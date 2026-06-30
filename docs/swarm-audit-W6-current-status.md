# Swarm Audit W6 Current Status

## 1. Metadata

| Field | Value |
| --- | --- |
| Date | 2026-06-30 |
| Current HEAD | `5072d81eddeb9a754d2a5a08f2e335fd7e12775f` |
| Worktree | Dirty; this status is based on the current worktree, not only committed HEAD |
| Supersedes | `docs/swarm-audit-W6-SYNTHESIS.md` from 2026-06-28 |
| Companion note | `docs/swarm-audit-W6-remediation.md` |
| Scope | W6 findings only; newer Hub backend/frontend audits remain separate live follow-ups |

## 2. Validity verdict

The old `swarm-audit-W6-SYNTHESIS.md` is **not valid as the current live risk
register**. It remains useful historical evidence for what W6 found on
2026-06-28, but the present code and docs have closed, refuted, or deliberately
bounded the findings that drove its `devnet-research-only` rating.

The current W6 status is:

| Area | Current W6 status |
| --- | --- |
| Bilateral on-chain profile | **devnet-acceptable after W6 remediation**, subject to ordinary devnet evidence gates |
| Factory profile | **devnet-acceptable for the implemented reduced/full paths**, with v2 proof-size simplification still future work |
| Morph Hub W6 items | **original W6 Hub P0/P1 issues are remediated or bounded** |
| Mainnet readiness | **not established by W6**; this document is not a mainnet readiness sign-off |

Important nuance: later documents such as `docs/hub-backend-ux-safety-audit.md`
raise newer Hub interaction risks. Those are not regressions in the W6 closure;
they are a later audit layer and should be tracked separately.

## 3. Why the old report is stale

| Old W6 claim | Current status | Evidence |
| --- | --- | --- |
| Host `SpliceTransition` lacks `next_state` (`W6-FIND-02`) | **Closed** | `SpliceTransition` now includes `next_state` and host validation checks it through `state_context_matches_splice_next`. See `crates/morph-core/src/types.rs:523-525` and `crates/morph-core/src/validation.rs:217-245`. |
| Splice successor payload/vault materialisation binding is only script-side | **Closed** | Host and script now both bind `new_vault_materialisation_root` during splice successor validation. See `crates/morph-core/src/validation.rs:311-335` and `contracts/morph-script-common/src/lib.rs:976-1001`. |
| `payload_commitment` is overloaded terminology (`REC-W6-16`) | **Closed by rename** | The wire/core name is now `vault_materialisation_root` / `new_vault_materialisation_root`, with JSON aliases for old saved packages. See `schemas/morph.mol:94-116` and `crates/morph-core/src/types.rs:509-512`. |
| Factory vault lock still leaks via `Box::leak` (`REC-W6-05`) | **Closed** | The old leak is absent; factory state data is parsed from owned cell data in the current path. See `contracts/morph-factory-vault-lock/src/main.rs:64-69` and `contracts/morph-factory-vault-lock/src/main.rs:150-173`. |
| Hub `PUT /api/state-file` is arbitrary full replacement (`W6-SAF-01`) | **Closed for the original W6 threat** | Restore is opt-in, restricted to empty bootstrap state, refuses settling/operational state, intersects restored `completed_flows`, keeps a backup, and emits a Critical `state_restored` event. See `crates/morph-cli/src/hub.rs:597-660`. |
| Hub SSE cannot be authenticated (`W6-SAF-02`) | **Bounded for current auth mode** | The UI does not open browser `EventSource` when an API token is present and falls back to authenticated polling. See `ui/morph-hub/src/api.ts:49-52` and `ui/morph-hub/src/App.tsx:312-341`. |
| Hub bearer token comparison is ordinary `==` (`W6-SAF-05`) | **Closed** | Token checks use the local `constant_time_eq` helper for both bearer and `x-morph-hub-token`. See `crates/morph-cli/src/hub.rs:1412-1420` and `crates/morph-cli/src/hub.rs:1634-1643`. |
| `completed_flows` can be injected through state restore (`W6-SAF-06`) | **Closed** | Restored flows are intersected with the live set before persistence. See `crates/morph-cli/src/hub.rs:626-638`. |
| Persisted Hub `Bytes32` zero checks can be bypassed (`W6-SAF-04`) | **Closed** | `parse_bytes32` rejects all-zero values, and restored node ids are derived from canonical pubkeys. See `crates/morph-cli/src/hub.rs:813-824`, `crates/morph-cli/src/hub.rs:1791-1794`, and `crates/morph-cli/src/hub.rs:1839-1853`. |
| Sponsor defaults are `0..u64::MAX` (`W6-SAF-03`) | **Closed** | Defaults are `1..2^20`; strict sponsor range validation rejects wider strict windows, and reports flag wider observed policies. See `crates/morph-cli/src/devnet.rs:90-91`, `crates/morph-cli/src/devnet.rs:11769-11781`, and `crates/morph-cli/src/stateful_report.rs:1003-1027`. |
| `SponsorPolicy::expiry` is a `u64::MAX` sentinel (`REC-W6-17`) | **Closed by deletion** | `SponsorPolicy` no longer has an expiry field in core or schema. See `crates/morph-core/src/types.rs:129-138`, `schemas/morph.mol:470-478`, and `docs/implementation.md:150-155`. |
| `ChannelOperation::CooperativeClose` is a dead variant (`REC-W6-18`) | **Closed** | The variant is gone; the docs say cooperative close is outside the current profile. See `crates/morph-core/src/types.rs:27-40` and `docs/implementation.md:141-149`. |
| `is_publication_or_challenge` is misleading (`REC-W6-21`) | **Closed** | The helper is now `is_publication_or_supersede`, and sponsor validation uses it. See `crates/morph-core/src/types.rs:37-40` and `crates/morph-core/src/validation.rs:375-404`. |
| Devnet command tree is exposed in default CLI builds (`REC-W6-24`) | **Closed** | The `devnet` command is behind the Cargo `devnet` feature and requires `--devnet-only`. See `crates/morph-cli/Cargo.toml:9-12` and `crates/morph-cli/src/main.rs:416-426`. |
| Funding anchor / factory id uniqueness is only first-input based (`REC-W6-12`) | **Closed** | State and factory type scripts now scan later inputs and reject duplicate derived anchors/ids. See `contracts/morph-state-type/src/main.rs:180-205` and `contracts/morph-factory-type/src/main.rs:331-353`. |
| Splice witness scans are unbounded (`REC-W6-13`) | **Closed** | State and vault scripts cap witness input scans with `MAX_WITNESS_INPUTS_PER_TX = 64`. See `contracts/morph-state-type/src/main.rs:27` and `contracts/morph-vault-lock/src/main.rs:29`. |

## 4. Refuted or bounded W6 findings

| Finding | Current position |
| --- | --- |
| `REC-W6-06 / W6-RIGOR-02` vault-lock should use `Source::GroupInput` for State lookup | Refuted for the current CKB grouping model. The vault lock group contains vault cells, so it scans transaction inputs and then requires the exact State header anchor plus type/lock binding and duplicate rejection. |
| `REC-W6-14 / REC-W6-15 / W6-RIGOR-03` factory reduced-exit state-root cross-check | Closed by call order and committed proof checks. The factory vault lock verifies the reduced-exit witness against on-chain old/new Factory State headers before reserve arithmetic. |
| `W6-RIGOR-09` factory local-exit participants commitment binding | Closed by committed evidence: local and reduced exits commit the exact child State header; later child states are governed by child-channel signatures. |
| `REC-W6-25` reduced proof body size | Fixed for patch scope through table-driven negative tests. The smaller proof-system redesign remains a v2 design item, not a W6 remediation blocker. |

## 5. Remaining caveats after W6

These are not reasons to keep the old W6 synthesis as the live register, but
they should remain visible:

| Caveat | Status |
| --- | --- |
| Hub state restore is still not chain-anchored | Acceptable only because restore is narrowed to empty bootstrap state. A future non-empty restore must be chain-anchored and reviewed separately. |
| Hub invoice private key can still be supplied as a CLI argument or environment variable | `hide_env_values` reduces accidental disclosure, but `--invoice-private-key-file` / stdin parity with auth tokens would be cleaner. Track this under the newer Hub backend audit, not W6. |
| Loopback Hub without auth | No longer the default. The Hub now requires a token unless the operator explicitly passes `--allow-unauthenticated-loopback` for local development. Per-action scopes and rate limits are tracked in `docs/hub-backend-ux-safety-remediation.md`. |
| W6 docs before this file are historical | `W6-rigor`, `W6-safety`, `W6-reasonable`, and the old synthesis should be read with this status document and `docs/swarm-audit-W6-remediation.md`. |

## 6. Updated conclusion

The answer to "is the old W6 synthesis still valid?" is **no, not as a current
report**. It was valid for the 2026-06-28 audit snapshot, but current worktree
evidence supersedes its live recommendations and most of its open-risk matrix.

Use this file plus `docs/swarm-audit-W6-remediation.md` as the W6 live status.
Use the newer Hub backend/frontend audit documents for current Hub product
hardening work.
