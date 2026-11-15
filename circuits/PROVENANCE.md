# Circuit artifact provenance

Downloaded 2026-11-16 from the official Agent Games site. The URLs and the
registered verification-key hash are served by the platform itself at
`GET https://agentgames.zkverify.io/api/circuit-info`.

| File | Source URL | Bytes | SHA-256 |
|---|---|---|---|
| `gatekeeper.wasm` | https://agentgames.zkverify.io/circuits/gatekeeper.wasm | 1,755,820 | `be00aefe3c8ba910951a242f50e55937bf82a0375ad4b69c2ef10629ab92764f` |
| `gatekeeper_final.zkey` | https://agentgames.zkverify.io/circuits/gatekeeper_final.zkey | 309,750 | `adfe95a439a7063a82a4967ef026d2dd6857a4d02c63b3caf63dac02e01af80d` |

- Circuit: Groth16 / BN128 (alt_bn128), compiled with Circom 2.x.
- Registered gatekeeper `vk_hash` (zkVerify mainnet, per `/api/circuit-info`):
  `0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0`
- `verification_key.json` in this folder was exported locally from
  `gatekeeper_final.zkey` with `node scripts/export-vk.js`
  (snarkjs `zKey.exportVerificationKey`): protocol groth16, curve bn128,
  nPublic 13. It is used only for local proof verification in tests.
- The wasm/zkey sizes and SHA-256 prefixes match values independently
  published by a participant build log (0xzommm, Medium, 15 Nov 2026):
  wasm `be00aefe…2764f`, zkey `adfe95a4…af80d`.
