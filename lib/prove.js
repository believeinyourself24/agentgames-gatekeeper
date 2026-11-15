// Groth16 proof generation for the Proof Gatekeeper circuit.
//
// Circuit inputs (13 signals, recovered by participants probing the official
// WASM and cross-checked across multiple independent builds — see README):
//
//   registeredVkHash, proofVkHash, minimum, publicBalance, expiryBlock,
//   currentBlock, recipient, conditionRecipient, amount, maxTransfer,
//   decision (1 = APPROVE, 0 = REJECT), taskId, salt (private)
//
// Public signals returned by the circuit (13, in order):
//   [ bindingHash, registeredVkHash, proofVkHash, minimum, publicBalance,
//     expiryBlock, currentBlock, recipient, conditionRecipient, amount,
//     maxTransfer, decision, taskId ]
// The first signal is a salt-dependent binding hash; the remaining 12 are
// the task fields (vk hashes and addresses reduced mod p), which the
// platform checks against the envelope it sent.
//
// Task field values are passed to snarkjs exactly as they arrive (decimal
// strings stay decimal, 0x-hex strings stay hex — snarkjs parses both).
// The salt is a fresh random 32-byte value per proof; it never appears in
// the public signals except through the binding hash.

const crypto = require('crypto');
const path = require('path');
const snarkjs = require('snarkjs');
const { taskIdToField } = require('./field');

const WASM_PATH = path.join(__dirname, '..', 'circuits', 'gatekeeper.wasm');
const ZKEY_PATH = path.join(__dirname, '..', 'circuits', 'gatekeeper_final.zkey');
const VK_PATH = path.join(__dirname, '..', 'circuits', 'verification_key.json');

function buildInput(task, decision, taskIdMode) {
  return {
    registeredVkHash: String(task.registered_vk),
    proofVkHash: String(task.proof_vk),
    minimum: String(task.minimum),
    publicBalance: String(task.public_balance),
    expiryBlock: String(task.expiry_block),
    currentBlock: String(task.current_block),
    recipient: String(task.recipient),
    conditionRecipient: String(task.condition_recipient),
    amount: String(task.amount),
    maxTransfer: String(task.max_transfer),
    decision: decision === 'APPROVE' ? '1' : '0',
    taskId: taskIdToField(task.task_id, taskIdMode).toString(),
    salt: '0x' + crypto.randomBytes(32).toString('hex'),
  };
}

async function proveTask(task, decision, taskIdMode) {
  const input = buildInput(task, decision, taskIdMode);
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(input, WASM_PATH, ZKEY_PATH);
  return { proof, publicSignals };
}

let cachedVk = null;
async function verifyLocally(proof, publicSignals) {
  if (!cachedVk) {
    cachedVk = require(VK_PATH);
  }
  return snarkjs.groth16.verify(cachedVk, publicSignals, proof);
}

module.exports = { buildInput, proveTask, verifyLocally, WASM_PATH, ZKEY_PATH, VK_PATH };
