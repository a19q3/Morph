# Implementation Notes

## Production Boundary

The implementation has three security boundaries:

1. State authority: participant signatures over the canonical state header.
2. Value authority: vault locks that accept only current-state settlement.
3. Fee authority: sponsor policies that can pay publication fees but cannot
   touch channel-owned value.

The core crate models those boundaries without assuming CKB mempool replacement
semantics. A publication transaction is a reconstructible carrier for state
evidence and sponsor authorisation.

The contract crates now implement the fixed-width V1 subset for devnet:

- State type: consumes exactly one State Cell and recreates exactly one newer
  settling State Cell under the same funding anchor and channel context; it can
  also close the state track after the configured relative `since` has matured.
- Vault lock: permits vault spend only when a unique settling State Cell with
  the expected funding anchor is present, its relative `since` has matured, and
  the settlement outputs match the descriptor commitment in the signed state.
- Sponsor lock: permits fee payment only within an explicit sponsor policy and
  counts only outputs returning to the authorised change lock as sponsor change;
  it also requires a matching settling StateHeader output whose channel and
  state number are admitted by the policy.

The state type script verifies the bilateral V1 participant witness: two sorted
compressed secp256k1 public keys, two ECDSA signatures over the canonical state
header digest, and a participant commitment that must match the signed header.
Sponsor inputs and fee selection remain outside that state-signature domain.

The draft Molecule schema in `schemas/morph.mol` now names every active
fixed-width V1 object used by the devnet contracts: `StateHeaderV1`,
`BilateralSignatureWitnessV1`, CKB and CKB+xUDT settlement descriptors, and
`SponsorPolicyV1`. The contracts still parse fixed-width bytes directly; the
schema is treated as the public wire-boundary record until generated Molecule
code is introduced.

The vault lock verifies the bilateral CKB settlement descriptor: two sorted
recipient lock hashes and exact output capacities. It also supports the devnet
CKB+xUDT descriptor, which binds the canonical xUDT type hash and exact token
amount for each recipient. The descriptor hash is bound inside
`settlement_descriptor_commitment`, so a finalisation transaction cannot change
the settlement recipients, capacities, asset type, or token amounts without
invalidating the signed state.

The sponsor lock is not a general wallet lock. It will pay only transactions
that produce a settling Morph State Cell for the policy's channel and authorised
state-number interval. This keeps sponsor capacity out of arbitrary transfers.

Factory mode is still host-side only, but the core crate now has a concrete
non-interference predicate. A factory-local update is described as changes to a
set of participant rights: balance, reserve claim, membership, exit path, and
sponsor budget claim. Any right outside the declared touched participant set
must be byte-for-byte unchanged, and every touched participant must appear in
the authorisation set. This is not yet an on-chain proof system; it is the
executable rule that a future proof bundle must satisfy.

The CLI can now serialise that predicate as a deterministic factory update
package. `print-factory-fixture` emits a sample package with a
`non_interference_digest`; `validate-factory-package` checks canonical roots,
canonical participant sets, digest consistency, and the host-side
non-interference predicate. This is intentionally a data-layer milestone before
any devnet factory script.

The watchtower scanner may also be bound by a small operator policy before it
reads blocks or publishes a transaction. The policy is a JSON object generated
by `print-watch-policy-fixture`; it can bind the channel id and constrain
confirmation depth, runtime window, polling interval, fee, explicit sponsor
usage, auto-funded sponsor rotation, auto-sponsor capacity, and devnet mining
requirements. This keeps deployment assumptions in an auditable file rather
than relying only on command-line convention.

## Current Non-Goals

- No routing, gossip, path finding, or liquidity discovery.
- No reduced-signature factory exits.
- No generic descriptor runtime.
- No base-layer CKB change.

## Devnet Acceptance Criteria

A devnet demonstration is acceptable only when it includes:

- at least one successful publish/supersede/finalise path;
- negative transactions for stale state, wrong funding anchor, sponsor drain,
  channel-paid fee leakage, and xUDT type mismatch;
- cycle and transaction-size measurements for each lifecycle transaction;
- a CKB+xUDT vault smoke that mints only under the devnet issuer lock and then
  settles by ordinary xUDT conservation;
- a CKB+xUDT negative smoke proving that unchanged total supply is not enough:
  the vault lock must reject a tampered recipient-level token distribution;
- a finalise-since negative smoke proving that an immature finalisation is
  rejected and that finalisation resumes after explicit maturity blocks;
- a competing-spend smoke proving that a newer state may need to be rebuilt
  against the currently live StateCell after an older publication confirms;
- a sponsor-budget negative smoke proving that a too-low fee cap is rejected
  on-chain and can be resolved by rotating to a fresh SponsorCell;
- reusable signed state packages that can be published without channel signing
  keys;
- a watchtower operator policy that bounds confirmation depth, fees, sponsor
  mode, and automatic sponsor capacity before publication;
- a smoke summary report that preserves cycle, size, status, and expected
  script-error evidence for review;
- a reproducible runbook with deployed script outpoints and transaction hashes.

## Offline Contract Tests

`make contract-tests` uses `ckb-testtool` to execute the compiled RISC-V scripts
inside transaction-shaped fixtures. These tests are not a substitute for a live
devnet run, but they catch script-group mistakes, occupied-capacity mistakes,
and missing finalisation paths before a node is involved.
