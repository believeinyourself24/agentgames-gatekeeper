// Proof Gatekeeper agent endpoint — zkVerify Agent Games Season 01.
//
//   POST /gatekeeper  (alias: POST /agent) — Proof Gatekeeper tasks + preflight
//   GET  /health                           — readiness for the dashboard check
//   GET  /                                 — service info
//
// Protocol (from the official Build guide / Rules / event page, cross-checked
// against live platform-accepted agents):
//   * Every inbound POST is HMAC-SHA256 verified over the RAW body against
//     the `x-agent-games-signature` header BEFORE any parsing (401 on
//     mismatch, no work done).
//   * Preflight {"type":"agent-games.preflight.v1"} is answered with the
//     signed JSON {"ok":true,"protocolVersion":"v1"}.
//   * Every response is signed the same way (header over the raw body).
//   * Task ids are idempotency keys: a retried delivery returns the
//     byte-identical cached response.
//   * Fail closed: uncertainty => REJECT, never an unprovable APPROVE.
//
// Environment:
//   AGENT_GAMES_HMAC_SECRET  (required for live play; without it the server
//                             runs in local-test mode and skips verification)
//   AGENT_GAMES_HMAC_FORMAT  'hex' (default) or 'sha256='
//   GATEKEEPER_TASK_ID_MODE  'keccak' (default), 'numeric', or 'hex'
//   PORT                     listen port (default 8080)
//   STATE_FILE               seen-set/cache persistence file
//                            (default ./data/state.json; set to 'off' to disable)

const fs = require('fs');
const path = require('path');
const http = require('http');
const { verifySignature, signatureFor } = require('./lib/hmac');
const { decide } = require('./lib/decide');
const { proveTask, verifyLocally } = require('./lib/prove');
const { Store } = require('./lib/store');

// ---- tiny .env loader (no dependency) ----
(function loadEnv() {
  try {
    for (const line of fs.readFileSync(path.join(__dirname, '.env'), 'utf8').split('\n')) {
      const m = /^\s*([A-Z0-9_]+)\s*=\s*(.*)\s*$/.exec(line);
      if (m && !(m[1] in process.env)) process.env[m[1]] = m[2].replace(/^['"]|['"]$/g, '');
    }
  } catch { /* no .env file — env vars only */ }
})();

const PORT = Number(process.env.PORT || 8080);
const HOST = process.env.HOST || '0.0.0.0';
const HMAC_SECRET = process.env.AGENT_GAMES_HMAC_SECRET || '';
const HMAC_FORMAT = process.env.AGENT_GAMES_HMAC_FORMAT || 'hex';
const TASK_ID_MODE = process.env.GATEKEEPER_TASK_ID_MODE || 'keccak';
const STATE_FILE =
  process.env.STATE_FILE === 'off'
    ? null
    : process.env.STATE_FILE || path.join(__dirname, 'data', 'state.json');

const store = new Store(STATE_FILE);
const inFlight = new Map(); // task_id -> Promise<rawBody> (dedupe concurrent retries)

let selfTest = 'pending';

// ---- helpers ----

function sendRaw(res, status, rawBody, sign) {
  const headers = { 'Content-Type': 'application/json' };
  if (sign && HMAC_SECRET) {
    headers['x-agent-games-signature'] = signatureFor(HMAC_SECRET, rawBody, HMAC_FORMAT);
  }
  res.writeHead(status, headers);
  res.end(rawBody);
}

function sendJson(res, status, obj, sign) {
  sendRaw(res, status, JSON.stringify(obj), sign);
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    req.on('data', (c) => {
      size += c.length;
      if (size > 1_000_000) {
        reject(new Error('body too large'));
        req.destroy();
        return;
      }
      chunks.push(c);
    });
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

function verifyInbound(req, rawBody) {
  if (!HMAC_SECRET) return true; // local-test mode only; never live without a secret
  return verifySignature(HMAC_SECRET, rawBody, req.headers['x-agent-games-signature'], HMAC_FORMAT);
}

// ---- Gatekeeper task handling ----

async function processTask(envelope) {
  const task = (envelope && envelope.input) || envelope || {};
  // The envelope carries task_id/mode at top level; circuit + seen-set need
  // them alongside the input fields.
  const t = { ...task, task_id: envelope && envelope.task_id !== undefined ? envelope.task_id : task.task_id };

  const { decision, reason_code } = decide(t, store);
  const proofTx = String(t.proof_tx || '');

  // PROOF_REUSED and INVALID_TASK carry no proof: reused tasks are excluded
  // from the proof requirement by the scoring rules, and a malformed task
  // has no well-defined circuit input.
  if (reason_code === 'PROOF_REUSED' || reason_code === 'INVALID_TASK') {
    return JSON.stringify({ decision, reason_code, proof_tx: proofTx });
  }

  try {
    const { proof, publicSignals } = await proveTask(t, decision, TASK_ID_MODE);
    return JSON.stringify({ decision, reason_code, proof_tx: proofTx, proof, public_signals: publicSignals });
  } catch (e) {
    // The decision is still returned (a correct decision without a proof
    // beats a timeout). This path should never trigger if decide() mirrors
    // the circuit — it is logged loudly when it does.
    console.error('[gatekeeper] proof generation failed, returning decision without proof:', e.message);
    return JSON.stringify({ decision, reason_code, proof_tx: proofTx });
  }
}

async function handleGatekeeper(envelope) {
  const taskId = envelope && envelope.task_id !== undefined ? String(envelope.task_id) : null;

  if (taskId) {
    const cached = store.cachedResponse(taskId);
    if (cached) return { status: 200, rawBody: cached };
    if (inFlight.has(taskId)) return { status: 200, rawBody: await inFlight.get(taskId) };
  }

  const promise = processTask(envelope);
  if (taskId) {
    inFlight.set(taskId, promise);
    try {
      const rawBody = await promise;
      store.cacheResponse(taskId, rawBody);
      return { status: 200, rawBody };
    } finally {
      inFlight.delete(taskId);
    }
  }
  return { status: 200, rawBody: await promise };
}

// ---- startup self-test: prove + verify the official sample scenario ----

async function runSelfTest() {
  try {
    const { Store: FreshStore } = require('./lib/store');
    const fresh = new FreshStore(null);
    const task = {
      task_id: 'gk_selftest_1',
      registered_vk: '0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0',
      proof_vk: '0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0',
      minimum: '1000',
      public_balance: '1460',
      expiry_block: 8430000,
      current_block: 8420000,
      recipient: '0x1111111111111111111111111111111111111111',
      condition_recipient: '0x1111111111111111111111111111111111111111',
      amount: '500',
      max_transfer: '1000',
      proof_tx: '0xselftest',
    };
    const { decision } = decide(task, fresh);
    const { proof, publicSignals } = await proveTask(task, decision, TASK_ID_MODE);
    const ok = await verifyLocally(proof, publicSignals);
    selfTest = ok && decision === 'APPROVE' ? 'PASS' : 'FAIL (unexpected decision or proof did not verify)';
  } catch (e) {
    selfTest = 'FAIL: ' + e.message;
  }
  console.log('[server] gatekeeper self-test:', selfTest);
}

// ---- HTTP server ----

const server = http.createServer(async (req, res) => {
  try {
    const url = (req.url || '').split('?')[0];

    if (req.method === 'GET' && url === '/health') {
      return sendJson(res, 200, {
        ok: true,
        service: 'proof-gatekeeper',
        hmacConfigured: !!HMAC_SECRET,
        taskIdMode: TASK_ID_MODE,
        selfTest,
        uptimeSec: Math.floor(process.uptime()),
      });
    }

    if (req.method === 'GET' && url === '/') {
      return sendJson(res, 200, {
        service: 'agent-games-proof-gatekeeper',
        endpoints: ['POST /gatekeeper', 'POST /agent', 'GET /health'],
      });
    }

    if (req.method !== 'POST' || (url !== '/gatekeeper' && url !== '/agent')) {
      return sendJson(res, 404, { error: 'not found' });
    }

    const rawBody = await readBody(req);

    if (!verifyInbound(req, rawBody)) {
      console.warn('[warn] HMAC mismatch on', url);
      return sendJson(res, 401, { error: 'bad signature' });
    }

    let obj;
    try {
      obj = JSON.parse(rawBody.toString('utf8'));
    } catch {
      return sendJson(res, 400, { error: 'invalid JSON' });
    }

    if (obj && obj.type === 'agent-games.preflight.v1') {
      return sendJson(res, 200, { ok: true, protocolVersion: 'v1' }, true);
    }

    const result = await handleGatekeeper(obj);
    return sendRaw(res, result.status, result.rawBody, true);
  } catch (e) {
    console.error('[server] unhandled error:', e);
    return sendJson(res, 500, { error: 'internal error' });
  }
});

if (require.main === module) {
  server.listen(PORT, HOST, () => {
    console.log(`[server] proof-gatekeeper listening on ${HOST}:${PORT}`);
    console.log(`[server] HMAC secret: ${HMAC_SECRET ? 'configured' : 'NOT SET — local-test mode, inbound verification skipped'}`);
    console.log(`[server] taskId mode: ${TASK_ID_MODE}`);
    runSelfTest();
  });
}

// Serverless (Vercel) entry: export a request handler instead of listening.
module.exports = (req, res) => server.emit('request', req, res);
