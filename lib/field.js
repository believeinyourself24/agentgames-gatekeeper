// Field-element helpers for the BN128 (alt_bn128) scalar field used by the
// gatekeeper circuit, plus the taskId -> field element mapping.

const { keccak_256 } = require('js-sha3');

const FIELD_PRIME = BigInt(
  '21888242871839275222246405745257275088548364400416034343698204186575808495617'
);

// Convert a hex string (0x..), decimal string, number, or BigInt into a
// field element (BigInt reduced mod p).
function toField(x) {
  let b;
  if (typeof x === 'bigint') b = x;
  else if (typeof x === 'number') b = BigInt(x);
  else b = BigInt(String(x));
  const r = b % FIELD_PRIME;
  return r < 0n ? r + FIELD_PRIME : r;
}

function keccak256ModP(buffers) {
  const hex = keccak_256(Buffer.concat(buffers));
  return toField(BigInt('0x' + hex));
}

// Map the envelope's string task_id (e.g. "gk_24_9d1") to a circuit field
// element. The platform does not publish this mapping; the default below is
// the one used by live agents that passed platform preflight + practice:
//   keccak:   keccak256(utf8(task_id)) mod p        (default)
//   numeric:  the decimal digits contained in the id, as a number
//   hex:      the hex characters contained in the id, as a number
// Switch with env GATEKEEPER_TASK_ID_MODE if a practice proof is rejected.
function taskIdToField(taskId, mode) {
  const id = String(taskId || '');
  if (mode === 'numeric') {
    const digits = id.replace(/\D/g, '');
    return digits ? toField(BigInt(digits)) : 0n;
  }
  if (mode === 'hex') {
    const hex = id.replace(/[^0-9a-fA-F]/g, '');
    return hex ? toField(BigInt('0x' + hex)) : 0n;
  }
  return keccak256ModP([Buffer.from(id, 'utf8')]);
}

module.exports = { FIELD_PRIME, toField, keccak256ModP, taskIdToField };
