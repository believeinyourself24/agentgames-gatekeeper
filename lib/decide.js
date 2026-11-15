// Proof Gatekeeper — deterministic decision engine for the 7 documented
// task varieties. This logic must mirror the gatekeeper circuit exactly:
// the circuit enforces decision == 1 (APPROVE) if and only if every check
// passes, so a decision the circuit disagrees with is unprovable.
//
// Checks run in a fixed order; the first failing trap wins and its name is
// the reason_code:
//
//   VK_SUBSTITUTION    proof_vk != registered_vk            (case-insensitive)
//   PROOF_REUSED       proof_tx already seen under a DIFFERENT task_id
//                      (a platform retry of the SAME task_id is not reuse)
//   THRESHOLD_MISMATCH public_balance < minimum             (== is valid)
//   EXPIRED_CONDITION  current_block >= expiry_block        (STRICT: the
//                      condition is valid only while current < expiry;
//                      == is expired — verified against the circuit)
//   RECIPIENT_MISMATCH recipient != condition_recipient     (case-insensitive)
//   AMOUNT_OVERFLOW    amount > max_transfer                (== is valid)
//   otherwise          APPROVE with reason_code VALID_CONDITION
//
// Malformed input (missing fields, non-numeric amounts) fails closed:
// REJECT with reason_code INVALID_TASK and no proof.

const REQUIRED_FIELDS = [
  'registered_vk',
  'proof_vk',
  'minimum',
  'public_balance',
  'expiry_block',
  'current_block',
  'recipient',
  'condition_recipient',
  'amount',
  'max_transfer',
];

function isMalformed(task) {
  if (!task || typeof task !== 'object') return true;
  for (const f of REQUIRED_FIELDS) {
    if (task[f] === undefined || task[f] === null || task[f] === '') return true;
  }
  try {
    BigInt(task.minimum);
    BigInt(task.public_balance);
    BigInt(task.expiry_block);
    BigInt(task.current_block);
    BigInt(task.amount);
    BigInt(task.max_transfer);
  } catch {
    return true;
  }
  return false;
}

// store: a lib/store Store instance (seen-set for reuse detection).
function decide(task, store) {
  if (isMalformed(task)) {
    return { decision: 'REJECT', reason_code: 'INVALID_TASK' };
  }

  const registeredVk = String(task.registered_vk).toLowerCase();
  const proofVk = String(task.proof_vk).toLowerCase();
  const minimum = BigInt(task.minimum);
  const publicBalance = BigInt(task.public_balance);
  const expiryBlock = BigInt(task.expiry_block);
  const currentBlock = BigInt(task.current_block);
  const recipient = String(task.recipient).toLowerCase();
  const conditionRecipient = String(task.condition_recipient).toLowerCase();
  const amount = BigInt(task.amount);
  const maxTransfer = BigInt(task.max_transfer);
  const proofTx = String(task.proof_tx || '').toLowerCase();
  const taskId = String(task.task_id || '');

  if (proofVk !== registeredVk) {
    return { decision: 'REJECT', reason_code: 'VK_SUBSTITUTION' };
  }

  if (proofTx) {
    const prevTask = store ? store.seenBy(proofTx) : undefined;
    if (prevTask !== undefined && prevTask !== taskId) {
      return { decision: 'REJECT', reason_code: 'PROOF_REUSED' };
    }
    if (store) store.recordSeen(proofTx, taskId);
  }

  if (publicBalance < minimum) {
    return { decision: 'REJECT', reason_code: 'THRESHOLD_MISMATCH' };
  }

  if (currentBlock >= expiryBlock) {
    return { decision: 'REJECT', reason_code: 'EXPIRED_CONDITION' };
  }

  if (recipient !== conditionRecipient) {
    return { decision: 'REJECT', reason_code: 'RECIPIENT_MISMATCH' };
  }

  if (amount > maxTransfer) {
    return { decision: 'REJECT', reason_code: 'AMOUNT_OVERFLOW' };
  }

  return { decision: 'APPROVE', reason_code: 'VALID_CONDITION' };
}

module.exports = { decide, isMalformed, REQUIRED_FIELDS };
