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
  settling State Cell under the same funding anchor and channel context.
- Vault lock: permits vault spend only when a unique settling State Cell with
  the expected funding anchor is present and its relative `since` has matured.
- Sponsor lock: permits fee payment only within an explicit sponsor policy and
  requires sponsor change to return to the authorised lock hash.

These scripts are intentionally structural. They enforce the Cell and accounting
boundaries first; participant signature verification is the next implementation
step, not a skipped concern.

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
