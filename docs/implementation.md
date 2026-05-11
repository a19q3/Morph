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
- a competing-spend smoke proving that a newer state may need to be rebuilt
  against the currently live StateCell after an older publication confirms;
- reusable signed state packages that can be published without channel signing
  keys;
- a reproducible runbook with deployed script outpoints and transaction hashes.

## Offline Contract Tests

`make contract-tests` uses `ckb-testtool` to execute the compiled RISC-V scripts
inside transaction-shaped fixtures. These tests are not a substitute for a live
devnet run, but they catch script-group mistakes, occupied-capacity mistakes,
and missing finalisation paths before a node is involved.
