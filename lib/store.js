// Persistent agent state: the proof_tx seen-set (reuse detection) and the
// per-task response cache (idempotency — the platform may retry a delivery
// after a network failure and must get the byte-identical response).
//
// State lives in memory and is mirrored to a JSON file (STATE_FILE env, or
// ./data/state.json by default) so a restart does not forget which proof
// references were already accepted. File errors are swallowed: on serverless
// hosts the filesystem may be read-only/ephemeral, in which case the
// in-memory maps still cover the lifetime of the process.

const fs = require('fs');
const path = require('path');

class Store {
  constructor(file) {
    this.file = file || null;
    this.seenProofTx = new Map(); // proof_tx (lowercased) -> task_id that first presented it
    this.responseCache = new Map(); // task_id -> raw response body string
    this.load();
  }

  load() {
    if (!this.file) return;
    try {
      const raw = JSON.parse(fs.readFileSync(this.file, 'utf8'));
      for (const [k, v] of Object.entries(raw.seenProofTx || {})) this.seenProofTx.set(k, v);
      for (const [k, v] of Object.entries(raw.responseCache || {})) this.responseCache.set(k, v);
    } catch {
      /* no state file yet — start clean */
    }
  }

  save() {
    if (!this.file) return;
    try {
      fs.mkdirSync(path.dirname(this.file), { recursive: true });
      const data = {
        seenProofTx: Object.fromEntries(this.seenProofTx),
        responseCache: Object.fromEntries(this.responseCache),
      };
      fs.writeFileSync(this.file, JSON.stringify(data));
    } catch {
      /* ephemeral filesystem — in-memory state still applies */
    }
  }

  // Returns the task_id that first presented this proof_tx, or undefined.
  seenBy(proofTx) {
    return this.seenProofTx.get(String(proofTx).toLowerCase());
  }

  recordSeen(proofTx, taskId) {
    const key = String(proofTx).toLowerCase();
    if (!this.seenProofTx.has(key)) {
      this.seenProofTx.set(key, String(taskId));
      this.save();
    }
  }

  cachedResponse(taskId) {
    return this.responseCache.get(String(taskId));
  }

  cacheResponse(taskId, rawBody) {
    const key = String(taskId);
    if (!this.responseCache.has(key)) {
      this.responseCache.set(key, rawBody);
      this.save();
    }
  }
}

module.exports = { Store };
