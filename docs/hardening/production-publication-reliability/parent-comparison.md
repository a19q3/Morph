# Parent CKB and Fiber source comparison

This comparison is pinned to immutable local revisions:

- CKB: `82c0bb640f406c9f7d5395157073005c7e583c89`
- Fiber: `de9071a3601ea6a3b8853d53b9f2f67184cab9a7`
- Morph change base: `790bf1c18a55b1186669a3833c5fcf7dd17177c1`

Line numbers below refer to those revisions. The source repositories are sibling
directories of Morph, not copied or vendored code.

## CKB behaviour Morph relies on

| CKB source | Observed rule | Morph consequence |
| --- | --- | --- |
| `../ckb/tx-pool/src/pool.rs:80-83` | RBF is enabled only when `min_rbf_rate > min_fee_rate`. | A profile with `require_rbf=true` rejects a node that does not advertise that relationship. |
| `../ckb/tx-pool/src/pool.rs:85-103` | A pending transaction's replacement set includes descendants; the incremental amount is `min_rbf_rate.fee(new_size)`. | Morph does not implement a percentage-only bump. It takes the maximum of its configured bump and `old_fee + fee(min_rbf_rate, new_size)`. |
| `../ckb/tx-pool/src/pool.rs:101-115` | The minimum is the checked sum of all replaced fees plus the incremental RBF fee. | All Morph fee arithmetic is checked and the node value remains authoritative when available. |
| `../ckb/tx-pool/src/pool.rs:630-678` | Descendant-input and conflicting-cell-dep rules can reject a replacement; an insufficient fee is returned as `RBFRejected` with the exact required amount. | Carrier rebuilds retain independent contract deps and do not consume descendants. Cross-operator price discovery requires RPC code `-1111`; undecodable requirements fail closed. |
| `../ckb/tx-pool/src/service.rs:904-928` | `get_transaction` verbosity 2 exposes `min_replace_fee` for a pending entry, but not for a proposed entry. | Morph reads `min_replace_fee` for its known pending tx. Proposed/committed results are reconciled by status instead of inventing a floor. |
| `../ckb/tx-pool/src/service.rs:1076-1097` | `tx_pool_info` exposes both configured fee floors and current pool size/counts. | Every attempt records the complete pool observation used for its decision. |
| `../ckb/rpc/src/module/experiment.rs:215-220,301-314` | `estimate_fee_rate` supports an explicit fallback and returns the node's `FeeRate`. | Morph calls `no_priority` with fallback enabled, applies bounded headroom, and combines it with pool and confirmed-block signals. |
| `../ckb/rpc/src/module/test.rs:114-145,629-653` | IntegrationTest `truncate` selects a prior canonical hash, truncates chain/database, and resets pool state. | The devnet rehearsal orphans the committed publication, checks cursor canonicality loss, and requires retained-evidence republication on an alternate branch. |

### Exact replacement calculation

For a transaction of serialized size `s`, Morph mirrors the parent CKB unit and
rounding boundary:

```text
incremental_rbf_fee = ceil(min_rbf_rate * s / 1000)
minimum_replacement = sum(conflicting_fees) + incremental_rbf_fee
```

For its own known pending transaction, Morph uses CKB's returned
`min_replace_fee`. For an unknown competing operator transaction, the first
`-1111 PoolRejectedRBF` response supplies the aggregate conflict floor. This is
necessary because the StateCell outpoint identifies the conflict but does not
identify the complete tx-pool descendant set.

Sending is not assumed to be atomic with receiving the RPC response. After a
timeout or duplicate error, Morph queries its locally computed transaction hash;
pending, proposed, or committed means the submission succeeded. Otherwise the
attempt remains `submission_unknown` until reconciliation.

## Fiber behaviour that is not a Morph security control

| Fiber source | Observed behaviour | Why Morph cannot delegate the property |
| --- | --- | --- |
| `../fiber/crates/fiber-types/src/schema/fiber.mol:96-104,211-212` | `TxInitRBF` and `TxAckRBF` exist in the wire schema. | A message definition is not an implemented replacement state machine. |
| `../fiber/crates/fiber-lib/src/fiber/channel.rs:962-965` | The channel actor logs both RBF messages as unsupported and returns. | Fiber does not currently provide Morph's carrier replacement guarantee. |
| `../fiber/crates/fiber-lib/src/watchtower/actor.rs:457-460,1379-1382,1614-1617` | Reviewed watchtower transaction builders use `FeeCalculator::new(1000)`. | A fixed 1000 shannons/KW cannot satisfy a production fee-pressure gate. |
| `../fiber/crates/fiber-lib/src/fiber/config.rs:336-361` | Configuration has one optional standalone watchtower URL plus a switch for the built-in actor. | It does not model two independently administered Morph operators, RPC paths, budgets, stores, and receipts. |
| `../fiber/crates/fiber-bin/src/main.rs:233-291,340-353` | Events can be sent to the optional client and built-in actor; standalone forwarding failure is logged while processing continues. | Best-effort forwarding is useful integration behaviour but is not durable dual-operator delivery evidence. |

Fiber remains a peer/network integration option. It is deliberately outside the
Morph StateCell publication correctness boundary.

## Adopted, adapted, and rejected choices

| Choice | Decision | Reason |
| --- | --- | --- |
| CKB fee estimator and pool floors | Adopt | They are the authoritative policy of the node that will admit the carrier. |
| CKB `min_replace_fee` | Adopt | It accounts for the actual conflict/descendant set and exact replacement size. |
| CKB human-readable RBF text alone | Reject | Morph first requires structured RPC code `-1111`; changed text cannot silently authorize a guessed fee. |
| Fiber fixed fee | Reject | It does not track real pool pressure. |
| Fiber RBF messages as evidence of support | Reject | The reviewed actor explicitly treats them as unsupported. |
| One built-in plus one best-effort Fiber endpoint as operator independence | Reject | Production independence is administrative and infrastructural, not merely two in-process recipients. |
| Participant re-signing for every bump | Reject | Morph signatures bind immutable state evidence; the operator can rebuild only the fee carrier under SponsorPolicy caps. |

## Verification mapping

| Parent rule or gap | Morph implementation | Evidence |
| --- | --- | --- |
| Fee floors and estimator | `crates/morph-cli/src/rpc.rs`, `publication.rs` | `fee-market.json`; below-floor rejection in the reliability report |
| Exact pending replacement floor | `publication.rs::replacement_fee`, `devnet.rs::send_publication_attempts` | operator A becomes `RBFRejected`; operator B commits |
| Unknown competing transaction | structured `-1111` handling in `rpc.rs` and `publication.rs` | operator B's first rejected attempt records the node floor, then retries |
| Ambiguous send result / duplicate | hash reconciliation in `send_publication_attempts` | duplicate pending rebroadcast succeeds idempotently |
| Pool eviction without reorg | canonical-live cursor retry in `watch_latest_state_package` | pool clear, unchanged tip, floor rescan, and accepted rebroadcast |
| Canonical reorg | hash-bound cursor plus `truncate` | orphaned committed attempt becomes unknown, then republishes and commits |
| Fiber fixed-fee and watchtower limitations | Morph-owned profile, sponsor, cursor, and operator receipts | two operator scopes run without participant keys |

The reproducible command is `scripts/devnet-publication-reliability.sh`. Its
report is development evidence only; public-network measurement and independent
operator receipts remain release gates.
