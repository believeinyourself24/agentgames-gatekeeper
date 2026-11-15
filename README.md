# Proof Gatekeeper — Agent Endpoint

An agent endpoint for the **Proof Gatekeeper** track of **zkVerify Agent
Games Season 01** (https://agentgames.zkverify.io/). The platform POSTs
signed payment-judgment tasks; this server verifies the signature, decides
APPROVE/REJECT with a deterministic rule engine, generates a Groth16 proof
of the decision with the official circuit, and returns a signed response —
in ~0.3–1.0 s against a 60 s deadline.

Status: **built and fully verified locally** (34/34 end-to-end checks,
2026-11-16). Not yet registered or deployed — see "What is still missing".

## Architecture

```
platform ──POST /gatekeeper──▶ server.js (Node built-in http, no framework)
                                 │ 1. HMAC-SHA256 verify over RAW body
                                 │    (x-agent-games-signature) → 401 on mismatch
                                 │ 2. preflight? → {ok:true, protocolVersion:"v1"}
                                 │ 3. response cache hit (task_id)? → replay bytes
                                 │ 4. lib/decide.js — 7-variety rule engine
                                 │ 5. lib/prove.js  — snarkjs groth16.fullProve
                                 │    (official gatekeeper.wasm + _final.zkey)
                                 │ 6. sign response body, return
                                 lib/store.js — proof_tx seen-set + response
                                 cache, persisted to data/state.json
```

| File | Role |
|---|---|
| `server.js` | HTTP server, routing, HMAC gate, preflight, idempotency, startup self-test |
| `lib/hmac.js` | HMAC-SHA256 sign/verify (constant-time compare) |
| `lib/decide.js` | Deterministic decision engine (mirrors the circuit) |
| `lib/prove.js` | Circuit input assembly + `snarkjs.groth16.fullProve` + local verify |
| `lib/field.js` | BN128 field helpers + `task_id` → field element mapping |
| `lib/store.js` | Seen-set / response-cache with JSON file persistence |
| `scripts/export-vk.js` | Export `circuits/verification_key.json` from the zkey |
| `test/harness.js` | Boots the real server and plays the platform against it |
| `circuits/` | Official artifacts + `PROVENANCE.md` (URLs, SHA-256, vk hash) |

Only two runtime dependencies: `snarkjs@0.7.6` and `js-sha3` (keccak).

## Protocol (as implemented)

- **Request**: `POST` JSON envelope
  `{type:"agent-games.proof-gatekeeper.v1", task_id, mode, issued_at,
  deadline_at, input:{registered_vk, proof_vk, minimum, public_balance,
  expiry_block, current_block, recipient, condition_recipient, amount,
  max_transfer, proof_tx}}`, header `x-agent-games-signature` =
  HMAC-SHA256 hex over the raw body with the agent's dashboard secret.
- **Preflight**: body `{"type":"agent-games.preflight.v1"}` →
  `{"ok":true,"protocolVersion":"v1"}`, signed.
- **Response** (signed the same way):
  ```json
  {"decision":"APPROVE","reason_code":"VALID_CONDITION","proof_tx":"0x…",
   "proof":{"pi_a":[…],"pi_b":[[…]],"pi_c":[…],"protocol":"groth16","curve":"bn128"},
   "public_signals":["…", "×13"]}
  ```
  `PROOF_REUSED` and `INVALID_TASK` responses omit `proof`/`public_signals`
  (reused-proof tasks are excluded from the proof requirement by the
  official scoring rules). If proof generation ever failed, the decision is
  still returned without a proof (better than a timeout) and the error is
  logged.
- **Idempotency**: task ids are idempotency keys — a retried delivery gets
  the byte-identical cached response; a repeated task id is never treated
  as proof reuse.
- **Health**: `GET /health` → `{ok, hmacConfigured, taskIdMode, selfTest}`.
  The startup self-test proves the official sample scenario and verifies
  the proof locally, so the dashboard health check sees `selfTest:"PASS"`.

## Decision rules (the 7 varieties)

Checks run in this order; the first failure wins and names the
`reason_code`. The order and boundary semantics mirror the circuit — the
circuit enforces `decision == 1` **iff** all checks pass, so any decision
the circuit disagrees with is unprovable (verified: `fullProve` with
decision=1 on trap inputs aborts in witness generation,
`GatekeeperEvaluation` line 102 — the same assert participants reported).

| # | Check | Fail → | Boundary |
|---|---|---|---|
| 1 | `proof_vk == registered_vk` (case-insensitive) | REJECT `VK_SUBSTITUTION` | — |
| 2 | `proof_tx` not seen under a different `task_id` | REJECT `PROOF_REUSED` (no proof attached) | same-task retry ≠ reuse |
| 3 | `public_balance >= minimum` | REJECT `THRESHOLD_MISMATCH` | balance == minimum is VALID |
| 4 | `current_block < expiry_block` | REJECT `EXPIRED_CONDITION` | current == expiry is EXPIRED (strict) |
| 5 | `recipient == condition_recipient` (case-insensitive) | REJECT `RECIPIENT_MISMATCH` | — |
| 6 | `amount <= max_transfer` | REJECT `AMOUNT_OVERFLOW` | amount == cap is VALID |
| — | all pass | APPROVE `VALID_CONDITION` | — |

Malformed envelopes (missing/non-numeric fields) fail closed:
REJECT `INVALID_TASK`, no proof. Scoring context: correct ±verified
decision +12, wrong APPROVE −6, wrong REJECT −3, timeout −2,
missing/invalid proof −2, reliability bonus +0…+5 per round.

## Circuit input schema (recovered)

The Build page does not publish the circuit's input names. They were
recovered by participants probing the WASM and are confirmed here by three
independent sources plus our own runs against the official artifacts
(VK export: groth16, bn128, **nPublic = 13**):

```
inputs (13):  registeredVkHash, proofVkHash, minimum, publicBalance,
              expiryBlock, currentBlock, recipient, conditionRecipient,
              amount, maxTransfer, decision, taskId, salt (private)

public signals (13, in order):
              [ bindingHash, registeredVkHash, proofVkHash, minimum,
                publicBalance, expiryBlock, currentBlock, recipient,
                conditionRecipient, amount, maxTransfer, decision, taskId ]
```

- Signal 0 is a salt-dependent binding hash (changes with the salt; the
  platform cannot recompute it). Signals 1–12 are the task fields with the
  vk hashes / addresses reduced mod p — the platform checks these against
  the envelope.
- Task values are passed to snarkjs exactly as received (decimal strings
  stay decimal, `0x…` hex stays hex). `decision` is `"1"` (APPROVE) or
  `"0"` (REJECT). `salt` is a fresh random 32-byte hex per proof.
- **`taskId` mapping — the one open question.** The envelope's `task_id`
  is a string like `"gk_24_9d1"`; the circuit needs a field element. This
  build defaults to `keccak256(utf8(task_id)) mod p` — the mapping used by
  a live agent that passed platform preflight and practice. Alternatives
  are one env var away (`GATEKEEPER_TASK_ID_MODE=numeric|hex`). **Confirm
  with a practice task after registration: if the practice proof is
  rejected, switch the mode and re-run practice.** Nothing else changes.

Sources: official pages — [/build](https://agentgames.zkverify.io/build),
[/events/proof-gatekeeper](https://agentgames.zkverify.io/events/proof-gatekeeper),
[/rules](https://agentgames.zkverify.io/rules),
[/api/circuit-info](https://agentgames.zkverify.io/api/circuit-info);
participant builds — @djarot (Medium, "Don't Trust the Agent. Verify It."),
0xzommm (Medium, "Before I trust an agent with payments…"), @jotri
(dev.to), noven.ai (dev.to, "Trust Nothing, Prove Everything"), and the
public, platform-healthy reference implementation of @rday98
(github.com/subastian1998/agent-games-season-01).

## Test results (2026-11-16, local, `node test/harness.js`)

**34 passed, 0 failed.** The harness boots the real server with a
placeholder secret and plays the platform:

- health, signed preflight, bad-HMAC → 401;
- valid task → APPROVE + proof **verifies against the official VK** +
  all 13 public signals encode the exact task fields and decision=1;
- all 5 provable traps (VK substitution, threshold, expiry at the
  `current == expiry` boundary, recipient, amount) → correct REJECT +
  reason code + verifying proof with decision=0 signals;
- boundary-valid task (balance == minimum, amount == cap,
  current == expiry − 1) → APPROVE + verifying proof;
- proof reuse under a new task id → REJECT `PROOF_REUSED`, no proof;
- same-task replay → byte-identical cached response, not flagged as reuse;
- malformed task → REJECT `INVALID_TASK`, no proof;
- circuit honesty: `fullProve(APPROVE)` on trap inputs fails witness
  generation, as the circuit design requires;
- **latency: avg 391 ms, max 836–963 ms per proved response** (deadline
  60,000 ms). Startup self-test: PASS.

## Deploy

**Recommended: Railway** (long-lived process, no cold starts, proven by
two live participants; the rules warn that hosts which sleep after
inactivity forfeit tasks). `railway.json` + `Procfile` are included:

1. Push this folder to a Git repo and create a Railway service from it
   (or `railway up`). Start command: `node server.js`; healthcheck `/health`.
2. Set env vars in Railway: `AGENT_GAMES_HMAC_SECRET` (from the dashboard,
   see below). `PORT` is injected by Railway.
3. Your endpoint URL is `https://<service>.up.railway.app/gatekeeper`.

**Vercel alternative**: `vercel.json` is included (routes all traffic to
`server.js` as a function, `maxDuration` 60). Caveats: cold starts eat
into the 60 s window (proof itself is ~0.3–1 s, so it fits), and the
filesystem is ephemeral — seen-set/response cache then live per instance
in memory (set `STATE_FILE=off`). Railway avoids both issues.

Run locally: `npm install && AGENT_GAMES_HMAC_SECRET=<any placeholder> npm start`,
then `npm test`.

## What is still missing (go-live checklist)

Code and local verification are complete. To enter Round 4+ (rounds start
17:30 WIB daily; Round 4 is 16 Nov) the following **account-side steps
remain — none of them can be done from this repo**:

1. **Register** at https://agentgames.zkverify.io/register (X account or
   wallet sign-in — a human step; prize eligibility also needs a connected
   GitHub account and a wallet address on the profile).
2. **Get the HMAC secret**: register the agent in the dashboard and copy
   the secret shown **exactly once** ("Rotate Secret"). Set it as
   `AGENT_GAMES_HMAC_SECRET` in the host env. Never commit it.
3. **Deploy** (Railway steps above) and **register the endpoint URL**
   (`https://…/gatekeeper`) in the dashboard.
4. **Pass the platform preflight + run practice tasks** from the
   dashboard. Practice is where the `taskId` mapping gets confirmed —
   if a practice proof is rejected, set `GATEKEEPER_TASK_ID_MODE` to
   `numeric` (then `hex`) and repeat practice before the scored round.
5. Keep the endpoint awake during round windows (17:30–03:30 WIB).

Explicitly NOT done by this build, by design: no account registration, no
wallet connection, no credentials handled, no Kurier API key (optional
on-chain finalization is unnecessary — Gatekeeper responses carry the
proof inline and the platform re-verifies it).
