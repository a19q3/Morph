# Morph RGB++ / Agent / Fiber Boundary Audit

Date: 2026-07-21

## Verdict

The sovereign architecture is sound only with this ownership split:

1. Morph Factory owns pooled liquidity, virtual rights, local exit, splice,
   and liquidity reuse.
2. Morph bilateral State/Vault owns CKB-enforceable signed state.
3. A provider-neutral Morph edge is derived from verified materialisation.
4. Fiber may mirror that edge for routing, MPP, invoices, and transport, but is
   not the source of truth.
5. Agent remains an application sidecar for x402, credentials, and fair
   exchange.

Batch settlement is an optimisation under Factory/Channel. It is not a
Factory replacement. Building a second Morph multi-hop network now would
duplicate Fiber's strongest layer without improving Morph sovereignty; the
correct investment is a replaceable routing-provider boundary and a minimal
external-edge hook.

The implementation in this commit is an experimental host-side boundary, not
a production-readiness claim. The on-chain Factory and bilateral model are
preserved.

## Security and correctness findings fixed

### A-01 — Post-payment payer self-assertion

Severity: critical.

The first Agent version accepted a payer public key only after a public Fiber
invoice had become paid. That proves ownership of an arbitrary key, not that
the signer is the intended claimant. Current Fiber `get_invoice` returns the
invoice and status but not final-hop custom records; `get_payment` does not
return the learned preimage. A third party could therefore race to mint the
first credential for someone else's paid invoice.

Fix:

- payer identity is committed when the Morph challenge is created;
- requirement ID commits that payer;
- the payment signature key must derive to the committed payer;
- the durable `settle_once` winner is rechecked after the atomic write, closing
  the concurrent first-writer window;
- retry still requires a valid payer signature.

### A-02 — Provider edge liquidity could be assigned to the wrong node

Severity: critical.

Settlement descriptors order balances by settlement lock, while the edge
descriptor preserves caller-supplied participant order. Copying descriptor
amounts positionally could reverse directional liquidity and make a router
send into unavailable capacity.

Fix: each directional amount is now mapped through the participant's exact
settlement lock. A reversed-participant regression test proves the mapping.

### A-03 — Outgoing wallet fee/timeout amplification

Severity: high.

The payer signature binds the invoice and amount, but caller-supplied Fiber
`max_fee_amount` and `timeout` were outside that signature. Once `/v1/pay` was
enabled, a replaying caller could enlarge operational spending parameters.

Fix:

- `/v1/pay` remains disabled by default;
- enabling it requires both an allowlisted payer and a deployment-level
  maximum fee;
- timeout has a bounded deployment cap;
- caller values can only reduce those caps.

### A-04 — Human-readable Fiber status was not receipt-bound

Severity: high.

`PaymentReceipt.fiber_status` could be changed without invalidating the signed
terminal receipt because only an opaque commitment was signed.

Fix: independent receipt validation now accepts only terminal success values
and recomputes the Fiber evidence commitment from requirement ID, payment
hash, and status. It also requires the exact Fiber provider ID and settlement
ID.

### A-05 — Gateway query was outside the paid resource

Severity: high.

The gateway credential committed the path but forwarded any query string. A
credential for one resource variant could therefore authorize another variant
whose security meaning was encoded in its query.

Fix: the canonical paid resource includes the exact raw query string when one
is present.

### A-06 — Adapter reconciliation omitted channel identity

Severity: high.

Restart reconciliation compared edge ID, funding context, and Morph
commitment, but not the provider's mirrored channel ID. A corrupted provider
association could survive reconciliation.

Fix: mirrored identifiers are parsed as canonical byte32 values and a channel
ID mismatch schedules an optimistic-revision update.

### A-07 — Unchecked amount aggregation and parsing panics

Severity: medium.

The bilateral backend used ordinary `u128` summation after parsing xUDT
balances, and the bridge used infallible conversions in production descriptor
parsing.

Fix: amount totals use checked arithmetic; descriptor lock conversion returns
typed errors; overflowing xUDT descriptors have a regression test.

### A-08 — Future-dated protocol objects

Severity: medium.

Payment intents and Factory reservations rejected expiry but did not reject a
verification time earlier than their creation/reservation time.

Fix: both objects now have an explicit not-yet-valid failure.

### A-09 — RGB++ admission and identity ambiguity

Severity: critical in the original model.

Ticker/decimal metadata is not an asset identity, and a caller-supplied hash is
not proof of an RGB++ binding.

Fix:

- canonical identity commits CKB genesis, xUDT Type Script hash, Bitcoin
  network, and binding code hash;
- the Type Script JSON is hashed and matched;
- binding evidence commits the Bitcoin seal/block, CKB Cell, proof program,
  proof Cell, amount, and proof payload;
- policy allowlists both binding and proof-program identities and checks
  confirmations/freshness;
- Agent challenges accept only operator-admitted proof commitments.

Actual Bitcoin inclusion verification remains delegated to a pinned proof
program and is a release blocker until exercised against a real implementation.

## Implemented boundary

- `morph-core::rgbpp`: canonical RGB++ identity and proof evidence policy.
- `morph-core::agent`: provider-neutral intents and signed terminal receipts.
- `morph-core::backend`: native backend over the existing bilateral
  State/Authorization/settlement descriptor.
- `morph-core::bridge`: Factory-right reservation, materialisation validation,
  stable provider-edge lifecycle, and participant-aligned liquidity.
- `morph-agent`: Fiber RPC sidecar, x402 headers, payer authorization, Biscuit
  credentials, encrypted durable state, fixed-upstream gateway, and AES-GCM
  hash-locked data exchange.
- `morph-fiber-adapter`: isolated proposed external-edge RPC contract and
  Morph-authoritative restart reconciliation.
- TypeScript SDK: payer signing, x402 calls/header handling, and fair-exchange
  decryption.

No Fiber type is imported into Morph consensus code, and no fake Fiber funding
outpoint is created.

The expanded real-devnet matrix currently records 193 transactions and is
stable at roughly 1.533 billion aggregate estimated cycles across repeated
runs. The aggregate smoke/stateful budget is therefore 1.6 billion cycles.
This is a suite-size budget adjustment: the per-transaction 30 million cycle
limit, named transaction limits, proof/witness limits, and byte limits remain
active. The four reduced-exit fixtures measured at 10.17–10.21 million cycles,
so their stale 10 million named/proof limits are calibrated to 11 million;
their witness and transaction-size limits remain unchanged.

## Evidence collected

The repository CI gate covers:

- formatting and clippy with warnings denied;
- RustSec and cargo-deny supply-chain checks;
- full workspace tests and Factory fixture validation;
- TypeScript SDK typecheck/build/smoke test and npm audit;
- Hub UI typecheck/build and npm audit;
- release RISC-V contract builds;
- 89 ignored CKB-VM contract tests run serially.

The final command and exact result are recorded in the commit handoff. These
tests prove the local implementation and existing scripts; they do not replace
the missing cross-stack devnet evidence below.

## Open release blockers

1. Fiber has no implemented external-edge hook, so no Morph-backed edge has
   routed a real three-node/MPP payment.
2. Fiber RPC exposes neither the sender's learned preimage nor receiver-side
   final-hop custom records. Challenge-bound payer identity is safe for the
   current stateful flow, but a minimal proof hook is still desirable.
3. A live watcher does not yet match reservation roots to canonical CKB
   FactoryStateCells or handle CKB reorg rollback.
4. Real RGB++ Bitcoin SPV/proof-program/leap/reorg evidence is absent.
5. Pending TLC/HTLC force-close enforcement is absent; Batch Cell cannot stand
   in for it or for Factory.
6. The encrypted store assumes one writer and has no key-rotation/backup
   protocol.
7. TLS/mTLS, ingress rate limits, payment-index admin authorization,
   authenticated proof admission, metrics, and operational recovery are not
   wired.
8. On-chain deployment identity does not yet pin the complete trusted code-hash
   set.
9. No independent security review has been completed.

Until these gates pass, describe the new components as experimental and
unit-tested, not production-ready.
