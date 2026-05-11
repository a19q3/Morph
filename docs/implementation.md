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
  the expected funding anchor is present and its relative `since` has matured.
- Sponsor lock: permits fee payment only within an explicit sponsor policy and
  counts only outputs returning to the authorised change lock as sponsor change.

The state type script verifies the bilateral V1 participant witness: two sorted
compressed secp256k1 public keys, two ECDSA signatures over the canonical state
header digest, and a participant commitment that must match the signed header.
Sponsor inputs and fee selection remain outside that state-signature domain.

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
- cycle measurements for each script;
- a reproducible runbook with deployed script outpoints and transaction hashes.

## Offline Contract Tests

`make contract-tests` uses `ckb-testtool` to execute the compiled RISC-V scripts
inside transaction-shaped fixtures. These tests are not a substitute for a live
devnet run, but they catch script-group mistakes, occupied-capacity mistakes,
and missing finalisation paths before a node is involved.
