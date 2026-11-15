// Local end-to-end test harness for the Proof Gatekeeper endpoint.
//
// Boots the real server (child process) with a placeholder HMAC secret, then
// acts as the platform: signs envelopes, POSTs them, and checks decisions,
// reason codes, response signatures, Groth16 proofs (verified locally
// against the official VK exported from the official zkey), public-signal
// encodings, idempotent replays, and latency.
//
//   node test/harness.js
//
// Exits non-zero if any check fails.

const { spawn } = require('child_process');
const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');
const snarkjs = require('snarkjs');
const { toField, taskIdToField } = require('../lib/field');
const { buildInput } = require('../lib/prove');

const PORT = 18741;
const BASE = `http://127.0.0.1:${PORT}`;
const SECRET = 'local-test-secret-not-the-platform-secret';
const VK = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'circuits', 'verification_key.json'), 'utf8'));
const OFFICIAL_VK = '0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0';
const RECIPIENT = '0xDe42bEd3a91C4f5A6b7C8d9E0f1A2b3C4d5e9f01'.slice(0, 42);

let passed = 0;
let failed = 0;
const latencies = [];

function check(name, cond, extra) {
  if (cond) {
    passed++;
    console.log(`  PASS  ${name}`);
  } else {
    failed++;
    console.log(`  FAIL  ${name}${extra ? ' — ' + extra : ''}`);
  }
}

function sign(rawBody, secret) {
  return crypto.createHmac('sha256', secret || SECRET).update(rawBody).digest('hex');
}

async function post(obj, opts = {}) {
  const rawBody = typeof obj === 'string' ? obj : JSON.stringify(obj);
  const headers = { 'Content-Type': 'application/json' };
  if (!opts.unsigned) headers['x-agent-games-signature'] = sign(rawBody, opts.secret);
  const t0 = Date.now();
  const res = await fetch(BASE + (opts.path || '/gatekeeper'), {
    method: 'POST',
    headers,
    body: rawBody,
    signal: AbortSignal.timeout(30000),
  });
  const text = await res.text();
  const ms = Date.now() - t0;
  let json = null;
  try { json = JSON.parse(text); } catch { /* leave null */ }
  return { status: res.status, text, json, ms, sigHeader: res.headers.get('x-agent-games-signature') };
}

function responseSigOk(r) {
  return r.sigHeader === sign(r.text);
}

async function proofOk(r) {
  if (!r.json || !r.json.proof || !Array.isArray(r.json.public_signals)) return false;
  try {
    return await snarkjs.groth16.verify(VK, r.json.public_signals, r.json.proof);
  } catch {
    return false;
  }
}

// Expected public signals [1..12] for a task + decision (signal [0] is the
// salt-dependent binding hash and cannot be predicted).
function expectedSignals(task, decisionWord) {
  return [
    toField(task.registered_vk).toString(),
    toField(task.proof_vk).toString(),
    String(BigInt(task.minimum)),
    String(BigInt(task.public_balance)),
    String(BigInt(task.expiry_block)),
    String(BigInt(task.current_block)),
    toField(task.recipient).toString(),
    toField(task.condition_recipient).toString(),
    String(BigInt(task.amount)),
    String(BigInt(task.max_transfer)),
    decisionWord === 'APPROVE' ? '1' : '0',
    taskIdToField(task.task_id, 'keccak').toString(),
  ];
}

function signalsOk(r, task, decisionWord) {
  if (!r.json || !Array.isArray(r.json.public_signals)) return false;
  const got = r.json.public_signals;
  if (got.length !== 13) return false;
  const exp = expectedSignals(task, decisionWord);
  return exp.every((v, i) => got[i + 1] === v);
}

function baseTask(overrides) {
  return {
    type: 'agent-games.proof-gatekeeper.v1',
    task_id: 'gk_t1',
    mode: 'practice',
    issued_at: new Date().toISOString(),
    deadline_at: new Date(Date.now() + 60000).toISOString(),
    input: {
      registered_vk: OFFICIAL_VK,
      proof_vk: OFFICIAL_VK,
      minimum: '1000',
      public_balance: '1460',
      expiry_block: 8430000,
      current_block: 8420000,
      recipient: RECIPIENT,
      condition_recipient: RECIPIENT,
      amount: '500',
      max_transfer: '1000',
      proof_tx: '0xtx_t1',
    },
    ...overrides,
  };
}

function taskWith(id, proofTx, inputOverrides) {
  const t = baseTask({ task_id: id });
  t.input = { ...t.input, proof_tx: proofTx, ...inputOverrides };
  return t;
}

async function waitForServer(proc) {
  for (let i = 0; i < 60; i++) {
    try {
      const r = await fetch(BASE + '/health');
      if (r.ok) return true;
    } catch { /* not up yet */ }
    await new Promise((r) => setTimeout(r, 500));
  }
  throw new Error('server did not come up');
}

(async () => {
  const stateFile = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'gk-test-')), 'state.json');
  const proc = spawn('node', [path.join(__dirname, '..', 'server.js')], {
    env: {
      ...process.env,
      PORT: String(PORT),
      AGENT_GAMES_HMAC_SECRET: SECRET,
      STATE_FILE: stateFile,
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  proc.stderr.on('data', (d) => process.stderr.write('[server] ' + d));

  try {
    await waitForServer(proc);
    console.log('server up on port', PORT);

    // --- health ---
    {
      const r = await fetch(BASE + '/health');
      const j = await r.json();
      check('health: ok + hmacConfigured', j.ok === true && j.hmacConfigured === true);
    }

    // --- preflight ---
    {
      const r = await post({ type: 'agent-games.preflight.v1' });
      check('preflight: 200 + {ok:true, protocolVersion:"v1"}',
        r.status === 200 && r.json && r.json.ok === true && r.json.protocolVersion === 'v1');
      check('preflight: response is signed', responseSigOk(r));
    }

    // --- bad HMAC ---
    {
      const r = await post(baseTask(), { secret: 'wrong-secret' });
      check('bad HMAC: 401', r.status === 401, 'got ' + r.status);
    }

    // --- valid task -> APPROVE with verifiable proof ---
    const validTask = taskWith('gk_valid_1', '0xtx_valid_1', {});
    {
      const r = await post(validTask);
      latencies.push(r.ms);
      check('valid: decision APPROVE', r.json && r.json.decision === 'APPROVE');
      check('valid: reason_code VALID_CONDITION', r.json && r.json.reason_code === 'VALID_CONDITION');
      check('valid: proof_tx echoed', r.json && r.json.proof_tx === '0xtx_valid_1');
      check('valid: response signed', responseSigOk(r));
      check('valid: proof verifies against official VK', await proofOk(r));
      check('valid: 13 public signals encode the task + decision=1', signalsOk(r, { ...validTask.input, task_id: validTask.task_id }, 'APPROVE'));
      console.log(`        latency: ${r.ms} ms`);
    }

    // --- replay of the same task_id returns the byte-identical body ---
    {
      const r1 = await post(validTask);
      const r2 = await post(validTask);
      check('replay: byte-identical cached response', r1.text === r2.text);
      check('replay: same task_id + same proof_tx is NOT proof-reuse', r2.json && r2.json.decision === 'APPROVE');
    }

    // --- traps: each must REJECT with its reason_code and a verifying proof ---
    const traps = [
      ['VK_SUBSTITUTION', { proof_vk: '0x7d3af291f291f291f291f291f291f291f291f291f291f291f291f291f291' }],
      ['THRESHOLD_MISMATCH', { public_balance: '999' }],
      ['EXPIRED_CONDITION', { current_block: 8430000 }], // == expiry: strict boundary
      ['RECIPIENT_MISMATCH', { recipient: '0x0000000000000000000000000000000000000bad' }],
      ['AMOUNT_OVERFLOW', { amount: '1001' }],
    ];
    for (const [code, over] of traps) {
      const t = taskWith('gk_trap_' + code.toLowerCase(), '0xtx_' + code.toLowerCase(), over);
      const r = await post(t);
      latencies.push(r.ms);
      check(`trap ${code}: REJECT + reason_code`, r.json && r.json.decision === 'REJECT' && r.json.reason_code === code,
        r.json ? r.json.decision + '/' + r.json.reason_code : 'no json');
      check(`trap ${code}: proof verifies`, await proofOk(r));
      check(`trap ${code}: signals encode decision=0`, signalsOk(r, { ...t.input, task_id: t.task_id }, 'REJECT'));
      console.log(`        latency: ${r.ms} ms`);
    }

    // --- boundary-valid: balance == minimum, amount == cap, current == expiry-1 ---
    {
      const t = taskWith('gk_boundary_ok', '0xtx_boundary_ok', {
        public_balance: '1000', amount: '1000', current_block: 8429999,
      });
      const r = await post(t);
      latencies.push(r.ms);
      check('boundary-valid: APPROVE (inclusive threshold/cap, strict expiry)',
        r.json && r.json.decision === 'APPROVE' && r.json.reason_code === 'VALID_CONDITION');
      check('boundary-valid: proof verifies', await proofOk(r));
      console.log(`        latency: ${r.ms} ms`);
    }

    // --- PROOF_REUSED: same proof_tx under a new task_id, no proof attached ---
    {
      const t = taskWith('gk_reuse_2', '0xtx_valid_1', {}); // reuses valid task's proof_tx
      const r = await post(t);
      check('reused: REJECT + PROOF_REUSED', r.json && r.json.decision === 'REJECT' && r.json.reason_code === 'PROOF_REUSED');
      check('reused: no proof attached (excluded by scoring rules)', r.json && r.json.proof === undefined);
    }

    // --- malformed task fails closed without a proof ---
    {
      const t = taskWith('gk_bad_1', '0xtx_bad_1', {});
      delete t.input.amount;
      const r = await post(t);
      check('malformed: REJECT + INVALID_TASK, no proof',
        r.json && r.json.decision === 'REJECT' && r.json.reason_code === 'INVALID_TASK' && r.json.proof === undefined);
    }

    // --- circuit honesty: an APPROVE proof for trap inputs must be impossible ---
    {
      const trapInput = { ...validTask.input, proof_vk: '0x7d3af291f291f291f291f291f291f291f291f291f291f291f291f291f291', task_id: 'gk_lie_1' };
      let threw = false;
      try {
        await snarkjs.groth16.fullProve(
          buildInput(trapInput, 'APPROVE', 'keccak'),
          path.join(__dirname, '..', 'circuits', 'gatekeeper.wasm'),
          path.join(__dirname, '..', 'circuits', 'gatekeeper_final.zkey')
        );
      } catch {
        threw = true;
      }
      check('circuit honesty: fullProve(APPROVE) on VK-trap inputs fails witness generation', threw);
    }

    // --- latency summary ---
    latencies.sort((a, b) => a - b);
    const max = latencies[latencies.length - 1];
    const avg = Math.round(latencies.reduce((a, b) => a + b, 0) / latencies.length);
    console.log(`\nlatency over ${latencies.length} proved responses: avg ${avg} ms, max ${max} ms (deadline 60000 ms)`);
    check('latency: slowest proved response well under 60 s', max < 30000, 'max ' + max + ' ms');
  } finally {
    proc.kill('SIGTERM');
  }

  console.log(`\n${passed} passed, ${failed} failed`);
  process.exit(failed ? 1 : 0);
})().catch((e) => {
  console.error('harness error:', e);
  process.exit(2);
});
