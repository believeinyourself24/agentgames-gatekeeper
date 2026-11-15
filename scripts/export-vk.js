// Export the Groth16 verification key from the official proving key so
// proofs can be verified locally:  node scripts/export-vk.js
// Writes circuits/verification_key.json (already run once; safe to re-run).

const path = require('path');
const snarkjs = require('snarkjs');

(async () => {
  const zkey = path.join(__dirname, '..', 'circuits', 'gatekeeper_final.zkey');
  const out = path.join(__dirname, '..', 'circuits', 'verification_key.json');
  const vk = await snarkjs.zKey.exportVerificationKey(zkey);
  require('fs').writeFileSync(out, JSON.stringify(vk, null, 2));
  console.log('verification key written to', out);
  console.log('protocol:', vk.protocol, '| curve:', vk.curve, '| nPublic:', vk.nPublic);
  process.exit(0);
})();
