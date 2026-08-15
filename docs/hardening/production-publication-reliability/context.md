# Production publication reliability context

Date: 2026-08-15
Morph baseline: `790bf1c18a55b1186669a3833c5fcf7dd17177c1`
CKB comparison baseline: `82c0bb640f406c9f7d5395157073005c7e583c89`
Fiber comparison baseline: `de9071a3601ea6a3b8853d53b9f2f67184cab9a7`

## Objective

Close the operational liveness gaps around fee pressure, CKB transaction-pool
replacement, challenge-window sizing, delayed observation, reorg recovery, and
two independent watchtower operators without changing Morph's signed state or
contract wire formats in this workstream. The encompassing `v1.10.0` tag also
contains the earlier withdrawal-destination wire update from `1cc830f`; see the
release boundary in `CHANGELOG.md`.

## Inputs reviewed

- `docs/mainnet-readiness.md`, `docs/roadmap.md`, the watchtower runbooks, and
  the 2026-08-15 swarm audit.
- Morph publication, sponsor, watch cursor, and devnet smoke implementations.
- CKB RPC and tx-pool source for `estimate_fee_rate`,
  `get_fee_rate_statistics`, `tx_pool_info`, `min_replace_fee`, RBF admission,
  and IntegrationTest `truncate`.
- Fiber v0.9.0-rc4-era channel/watchtower implementation, including fee-rate
  constants, unsupported `TxInitRBF` / `TxAckRBF` handlers, transaction tracer,
  and the single optional standalone-watchtower endpoint.
- Jan's 2026-06-13 review and Arthur's 2026-06-14 reply in
  <https://talk.nervos.org/t/morph-channel-explained-separating-value-state-evidence-and-fee-responsibility-on-ckb/10378/2>.

## Parent-source comparison anchors

The line-by-line mapping and implementation consequences are recorded in
[`parent-comparison.md`](parent-comparison.md).

These paths are relative to this repository and refer to the exact baselines
above:

| Conclusion | Parent source anchor |
| --- | --- |
| CKB enables RBF only when `min_rbf_rate > min_fee_rate`. | `../ckb/tx-pool/src/pool.rs` (`enable_rbf`) |
| CKB replacement floor is conflict fees plus `min_rbf_rate.fee(new_size)`. | `../ckb/tx-pool/src/pool.rs` (`calculate_min_replace_fee`) |
| Pending status exposes `min_replace_fee`; pool info exposes both fee floors. | `../ckb/tx-pool/src/service.rs`, `../ckb/util/types/src/core/tx_pool.rs` |
| CKB exposes estimator and deterministic IntegrationTest truncation. | `../ckb/rpc/src/module/experiment.rs`, `../ckb/rpc/src/module/test.rs` |
| Fiber declares RBF messages but its channel actor treats both as unsupported. | `../fiber/crates/fiber-types/src/schema/fiber.mol`, `../fiber/crates/fiber-lib/src/fiber/channel.rs` |
| Reviewed Fiber watchtower construction still uses a fixed rate of 1000. | `../fiber/crates/fiber-lib/src/watchtower/actor.rs` |
| Fiber permits built-in watchtower plus one optional standalone RPC endpoint, with forwarding failures logged. | `../fiber/crates/fiber-bin/src/main.rs`, `../fiber/crates/fiber-lib/src/fiber/config.rs` |

## Existing controls preserved

- State evidence and channel value are independent of carrier-transaction fee
  selection.
- Participant signatures authorize the State Header, not sponsor inputs or fee.
- Sponsor scripts enforce channel, state-number, per-transaction, total-budget,
  exact fee attribution, and clean-change boundaries.
- Watch cursors bind the scanned block hash and reset to the configured scan
  floor after a canonicality mismatch.
- A newer signed state supersedes an older state without slashing.

## Gaps at the Morph comparison baseline

- Watch publication uses a fixed absolute fee and does not consult node fee or
  replacement requirements.
- The competing-spend smoke proves conflict rejection and later rebuilding, but
  not successful higher-fee RBF.
- Challenge delay is a convenience constant, not a result derived from measured
  publication latency and explicit reorg/failover budgets.
- Reorg recovery is unit-tested but is not exercised by truncating and replacing
  a live devnet chain.
- Watchtower commands unnecessarily require Alice and Bob channel private keys
  even when publishing an already signed state package.
- Multi-operator evidence is local/single-environment and lacks operator-scoped
  attempt/health receipts.

## Production target trust and deployment assumptions

- Each operator has an independent process, RPC endpoint, cursor, package store,
  sponsor budget, alert sink, and failure domain.
- An operator may receive signed state packages and public settlement metadata,
  but must not receive participant signing keys.
- Sponsor-budget keys and automatic sponsor funding remain an operator policy
  concern. Explicit pre-funded SponsorCells can be spent under their bounded
  script policy without participant signatures.
- CKB RBF is an admission policy, not a consensus guarantee. The controller must
  continue to support rebroadcast, canonical-state reconciliation, and failover.
- Devnet fault injection proves code paths and evidence production; repeated
  public-network measurements are still required before a real-assets claim.
- The checked-in deterministic harness co-locates both operator processes and
  uses one loopback RPC. It is not evidence for independent hosts, providers,
  alerting, health supervision, or administrative control.
