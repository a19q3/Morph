# Publication controller patch contract

## Must hold

- The bytes parsed as `StateHeader` and the participant witness are immutable
  for every attempt belonging to one publication intent.
- Attempt `n + 1` may change only carrier dependencies, sponsor inputs/change,
  fee, and transaction hash.
- A replacement that conflicts with an earlier attempt must use the CKB node's
  `min_replace_fee` when available. A configured bump multiplier is only a lower
  bound and fallback.
- The chosen fee must be no larger than all applicable bounds: SponsorPolicy
  `max_fee_per_tx`, remaining SponsorPolicy total budget, operator maximum, and
  available capacity above occupied clean change.
- Unknown/rejected outcomes trigger canonical StateCell reconciliation. They are
  never interpreted as proof that the intended state failed to land.
- An advanced scan cursor cannot suppress retry: if its last observed StateCell
  remains canonical-live and its context has a newer retained package, startup
  resets the effective scan position to the configured channel floor.
- A canonical state number equal to or greater than the intent is success or
  obsolescence, not a reason to double-publish.
- Logs must not include participant or sponsor private keys.
- RPC RBF price discovery must key off CKB's structured `-1111` error code;
  changed or undecodable text fails closed.
- Only an incomplete final JSONL record may be repaired automatically, and its
  original bytes must first be retained as forensic evidence.
- Production measurement freshness applies to every sample, not merely the
  dataset wrapper timestamp; network, genesis, and CKB version must match the
  node used for assessment.

## Acceptance tests

- Initial fee is calculated with integer ceiling from serialized bytes.
- Node floor and estimator are multiplied and capped without overflow.
- RBF-disabled nodes are rejected by a production profile.
- A node-provided replacement fee overrides a lower local bump.
- Fee/script/operator cap conflicts fail before broadcast.
- Both watchtower operators can build from the same signed package with no Alice
  or Bob key material.
- Actual devnet RBF marks the old tx rejected and commits the replacement.
- Clearing the devnet pool without changing the canonical tip forces a
  cursor-floor rescan and deterministic rebroadcast.
- Rebroadcasting an already-pending deterministic carrier is reconciled as
  accepted instead of being treated as a terminal rejection.
- Actual devnet truncation invalidates a saved cursor hash and produces a reset
  and rescan report.
- A fake typed or SponsorCell cannot supply the deployed challenge window.
- A production dataset with diluted rare faults is judged by the worst required
  fault-family P99.9, not only the aggregate P99.9.
