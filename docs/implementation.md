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

