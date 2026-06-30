# Swarm Audit — W3 文档一致性与范围
Date: 2026-06-22
HEAD: `aa71651` (branch `arthur/morph-audit-fixes`, also visible on `main`/`v2`)
Severity counts: HIGH 4 / MEDIUM 5 / LOW 2  (no CRITICAL expected from this angle)

This audit looks at what docs CLAIM and cross-checks those claims against code,
git, and other docs. It is orthogonal to W5 (tests/fixtures) and W4 (ops/scripts).
W5 and W4 findings are cited but not repeated; new drift is reported here.

## 1. 范围与成熟度声明 (README ↔ mainnet-readiness ↔ roadmap)

Three docs each describe Morph Channel's maturity. They use different words but
agree on the high-level position: serious devnet research implementation, not
mainnet, with a defined external review as the next gate.

| Claim | Source | Aligned? |
|---|---|---|
| "not mainnet software. It is a devnet implementation and research workbench" | `README.md:8-10` | ✓ |
| "Morph Channel should be read as a serious devnet research implementation, not as production infrastructure" | `README.md:295-304` | ✓ |
| "Morph Channel is not mainnet-ready and is not production real-assets software" | `docs/mainnet-readiness.md:3-4` | ✓ |
| "the devnet research implementation stage: protocol objects, package tooling, CKB scripts, smoke tests, and stateful acceptance gates exist locally. Production work remains open" | `docs/roadmap.md:18-20` | ✓ |
| 8 release gates are all "Open" | `docs/mainnet-readiness.md:24-33` | ✓ |
| 7 milestones M0..M6; M0..M4 "Implemented", M5 "Implemented locally", M6 "Open" | `docs/roadmap.md:24-32` | ✓ (with caveat — see W3-04) |
| "Go / No-Go Summary" — local research: Yes, devnet evidence: Yes, mainnet real assets today: No | `docs/mainnet-readiness.md:99-105` | ✓ |
| README "Open release gates remain" mirrors mainnet-readiness gate list (external review, fee/reorg evidence, supply-chain, runbooks, multi-operator watchtower, value-limit) | `README.md:71-73` ↔ `mainnet-readiness.md:24-33` | ✓ |
| Roadmap "Next Engineering Slice" (reviewable external review → release CI → mainnet-like fee/reorg evidence → operator runbooks → value-limit policy) | `docs/roadmap.md:61-80` ↔ `mainnet-readiness.md:71-84` | ✓ |

**Overall consistency**: All three docs agree on the headline maturity
("devnet research, not mainnet"), and the roadmap / mainnet-readiness gate
descriptions match. However, the wording around M5 in roadmap ("Implemented
locally" while mainnet-readiness still puts watchtower and CI gates "Open") is
slightly confusing — see W3-04.

## 2. Audit 文档族 superseded 关系图

```
                       (current line)
audit-matrix.md  ──[current witness-envelope impl]── a2059ba → aa71651
   ▲
   │
generalized-audit.md  ─[audit profile schema label only; "suffix here is
                          only the audit-profile evidence label. It is not a
                          protocol or witness-version label"]── a07ec47
   ▲
   │
audit-response-2026-06-20.md  ─[C-01/H-01..H-07/M-01..M-04 close]── aa71651
   ▲
   │
paper-implementation-audit.md  ─[aligned for current devnet profile,
                                   not "current implementation"]── a07ec47+1c63f6b
   ▲
   │
redundant-stale-code-audit.md  ──EXPLICITLY SUPERSEDED── a2059ba (says so
                                  on lines 7-18; base fbd5a11, branch
                                  arthur/audit-stale-redundant-code)
```

Text form of the supersession graph:

```
                                     CURRENT (claims current status)
                                  ┌──────────────────────────────┐
                                  │ audit-matrix.md              │
                                  │ generalized-audit.md         │
                                  │ audit-response-2026-06-20.md │
                                  │ paper-implementation-audit.md│
                                  └──────────────────────────────┘
                                              │
                                              │ all anchor to a07ec47 /
                                              │ a2059ba as "current"
                                              │ line; 4ca867c is named
                                              │ historical evidence
                                              ▼
                            SUPERSEDED (self-declared historical)
                          ┌────────────────────────────────────────┐
                          │ redundant-stale-code-audit.md         │
                          │   ↳ "historical audit … not a current │
                          │      stale-code assessment … at       │
                          │      commit a2059ba the current line  │
                          │      deliberately changes the factory │
                          │      authorisation boundary"          │
                          │   ↳ base fbd5a11 on                   │
                          │     arthur/audit-stale-redundant-code │
                          │     (closed by 44ea6f0)               │
                          └────────────────────────────────────────┘
```

Specific anchors:
- `redundant-stale-code-audit.md:7-18` self-declares as historical; base `fbd5a11` on branch `arthur/audit-stale-redundant-code` (merged via 44ea6f0). It is NOT drift; it is correctly labelled historical. But `cargo tree -d` finding and `large-module refactor candidates` are point-in-time, never refreshed.
- `current-devnet-rc-closeout.md:11-31` self-declares historical; baseline `4ca867c` (verified commit exists); "current line" anchored at `a2059ba`. The "current" prefix in its title is therefore misleading — see W3-02.
- `m6-closeout.md:7-17` says historical at `a2059ba`; `m5-closeout.md:7-11` says historical relative to current factory witness boundary; `devnet-stateful-acceptance-closeout.md:3-6` says it is the "required current release-evidence gate" but then the artifact commit is `17e1964` and the final baseline is `3814453`, both pre-a07ec47. The stateful closeout is **the only closeout that self-declares as current**, but its anchors are older than the current implementation line — see W3-03.

## 3. Closeout 文档真实状态

| 文档 | 自称状态 | 实际状态 (git log 验证) | drift? |
|---|---|---|---|
| `docs/m5-closeout.md` | Historical closeout for conservative bilateral splice milestone (committed 47c261e "Mark M5 closeout historical"). Says M5 closes the "conservative bilateral splice scope" and lists deferred items. | M5 was finished at `8b00c13` "Finish M6 splice smoke roadmap" and the closeout was marked historical in `47c261e` (June 2026). Final commit `aa71651` does not retract anything M5 claims. Deferred items ("concurrent unconfirmed splice", "generic descriptor runtimes", "factory splice-in/out which begins in M6") line up with later M6 closeout. | LOW — accurate historical record. |
| `docs/m6-closeout.md` | Historical M6 closeout for "conservative host/package layer for factory reserve repartitioning" (committed 41d69bd "Mark M6 closeout historical"). Anchor `a2059ba`. | Commits `fd1aa94` "Tighten factory splice package validation" and `8b00c13` "Finish M6 splice smoke roadmap" line up with the M6.1/M6.2 done list. Anchor `a2059ba` "Implement V2 non-fixed factory witnesses" exists. Deferred items consistent with current roadmap "Deferred Work" table (`docs/roadmap.md:51-58`). | LOW — accurate historical record. |
| `docs/current-devnet-rc-closeout.md` | "Status: historical Devnet release-candidate evidence; superseded for current readiness tracking by the witness-envelope factory witness work." Anchor `4ca867c`. Title says "current". | Anchor `4ca867c` ("fix(devnet): restore xudt reduced exit readiness") exists. Subsequent commits up to `aa71651` add stateful acceptance, audit-response patches, fiber gates, etc. but the closeout's claim "this is the current devnet RC" is contradicted by being labelled "historical" in its own §"Supersession Note" line 4. **Title "current" is misleading** — see W3-02. | MEDIUM — title contradicts self-declared historical status. |
| `docs/devnet-stateful-acceptance-closeout.md` | "Status: devnet stateful acceptance is the required current release-evidence gate. A closeout is current only when its artifact manifest records the current clean HEAD, `git_dirty=false`, and `status=passed`." Anchors `3814453` (final committed baseline) and `17e1964` (run-time artifact). | Anchor `3814453` ("test(devnet): add generalized stateful audit acceptance") exists and predates the V2 witness envelope rewrite. Subsequent work includes `a07ec47` "Unify current protocol model" (large factory contract rewrite, 2305 changes in `morph-script-common`), `a2059ba` "Implement V2 non-fixed factory witnesses", `67ebc96`..`689dab0` (Fiber gates), `aa71651` (audit-response). The closeout's evidence (smoke hashes, deployed-script set, scenario tag map, audit families) was captured at `17e1964` and is now structurally older than the current witness envelope. Same `deployed script hashes` (e.g., `morph-state-type 0x788db1…`) do NOT appear in any `target/` tree under the current code, which uses the V2 witness envelope. **Closeout self-declares as the "required current release-evidence gate" but its evidence anchors predate the witness envelope rewrite.** | HIGH — see W3-03. |
| `docs/audit-response-2026-06-20.md` | "This document responds to the external audit verdict of 20 June 2026 … records, for each finding, the disposition and where the fix lives." | Anchored at `aa71651` ("Close audit C-01, H-01..H-07, M-01..M-04; add audit-response letter"). 12 findings (C-01, H-01..H-07, M-01..M-04). Self-current. | LOW — accurate, except the C-01 close is partial (W5-01 / W3-08). |
| `docs/audit-matrix.md` | "The paper's audit matrix is represented in `crates/morph-core/tests/invariants.rs`. This matrix is read against the current witness-envelope implementation line." | Anchored at current line, references current file paths. Two test names (`comparison_limits_reject_metric_regressions`, `comparison_limits_reject_set_and_status_changes`) appear ONLY in this file (W5-11) — no `.rs` source. | MEDIUM — matrix labels misleading; see W3-07. |
| `docs/generalized-audit.md` | "Status: executable acceptance taxonomy for devnet stateful evidence. … On the current witness-envelope implementation line, factory authorisation is read through the bounded `WitnessEnvelope` kind/body/digest envelope." | Anchored at current line. Documents the audit-profile schema. The "Found Issue To Executable Family" table (lines 21-36) lists 11 invariant-to-family mappings that line up with the W3 cross-checks in §7 below. | LOW. |
| `docs/redundant-stale-code-audit.md` | Self-declared historical at `a2059ba`, base `fbd5a11`. | Anchor exists. `cargo tree -d` finding and large-module candidates are point-in-time and not refreshed. **Title still says "Redundant and Stale Code Audit" without a "historical" qualifier** — easy to mistake for current. | LOW — see W3-05. |

## 4. Tutorial ↔ implementation 一致性

Both EN (`docs/morph-channel-tutorial.md`) and ZH (`docs/morph-channel-tutorial.zh.md`) tutorials were last touched by the same commit `a07ec47` ("Unify current protocol model"). They both describe the same protocol flow.

| Tutorial claim | Implementation (`docs/implementation.md` / `contracts/*`) | Aligned? |
|---|---|---|
| State Cell + Vault Cell + Sponsor Cell at open | `implementation.md:46-55`; `morph-state-type` and `morph-vault-lock` scripts accept these; `morph-sponsor-lock` enforces bounded policy | ✓ |
| `WitnessEnvelope` carries kind + body length + body digest; factory scripts dispatch by kind | `implementation.md:185-212`; `morph-script-common/src/lib.rs:368-392` parses envelope; `morph-factory-type/src/main.rs` dispatches | ✓ |
| Splice preserves logical identity (channel_id) but advances funding_epoch, funding_anchor, vault_set | `implementation.md:50-52`; `verify_splice_state_transition` and `state_context_matches_splice_next` in `morph-script-common/src/lib.rs` | ✓ |
| CKB+xUDT settlement through the same State Cell / Vault Cell authority | `morph-vault-lock/src/main.rs` and the `morph-devnet-xudt` script | ✓ |
| Conservative factory requires all-participant signatures; reduced paths prove one touched right | `implementation.md:142-151`; `morph-factory-type/src/main.rs` accepts `WitnessEnvelope`-carried reduced-rights / reduced-exit / sparse-Merkle / reduced-splice bodies | ✓ |
| "Sponsor can pay the fee, but sponsor capacity cannot change the channel's settlement" (tutorial) ↔ "Sponsor capacity is not channel value" (implementation.md:42-43) | Both align | ✓ |
| `withdrawal_payout_policy` for participant-owned splice-out | implementation.md does not explicitly mention `withdrawal_payout_policy`; m5-closeout does (line 49-51). This is a small detail. | LOW — tutorial/implementation alignment OK on the head; small detail divergence (see W3-06). |

**ZH tutorial lag check**: Both EN and ZH were last modified together (`a07ec47`). They have the same step count (6), the same mermaid diagrams, and the same "What To Run First" / "下一步读什么" references. There is **no ZH lag** in this snapshot. (Both share the same V2-era diagrams, so if either drifts, the other will too.)

## 5. Audit-response 数字声明 vs 实际

| audit-response 声称 | W5 实际 / grep 实际 | 一致? |
|---|---|---|
| `audit-response-2026-06-20.md:26` — "155 smoke JSONs, 192 committed transactions, 7 deployed scripts with verified hashes" (after C-01 / H-* / M-* patches) | W4-01: "The current script surface counts are hardcoded floors in `crates/morph-cli/src/smoke_report.rs:2208-2239` and `:2285-2324`; `EXPECTED_SCRIPT_FAILURES` has 6 entries; `transaction_count >= 0` (no floor on `155` or `192`)." The closeout's specific counts are NOT gate-enforced. | MEDIUM — accurate as a snapshot of the 4ca867c run, but the audit-response claim is "after these patches the bilateral profile is a defensible security construction on the existing devnet evidence (155 smoke JSONs…)" — phrased as if it characterises the current state. The 155 / 192 / 7 are 4ca867c-anchored; current `aa71651` may differ. (See W3-02.) |
| `audit-response-2026-06-20.md:591` — "248 workspace tests pass (1 ignored as documented above)" | W5: `cargo test --workspace` does not run the 84 `contract_scripts` `#[ignore]` tests. W5-09 / W5-10 document this. `cargo test --workspace` count from `#[test]` / `    #[test]` patterns: 165 (column-0) + 112 (4-space) + 56 (contracts) = **333** test functions; 84 of them `#[ignore]`. After subtracting ignored, `cargo test --workspace` reports `333 - 84 = 249` "active" tests — close to the 248 claim (1 ignored at the `morph-script-common` `rejects_splice_state_transition_with_changed_payload_commitment` test). | LOW — claim is in the right ballpark for the *workspace* layer (not contract layer), but the framing is imprecise: "248 tests pass" without "(plus 84 ignored contract_scripts tests under `make contract-tests`)" understates the test surface. W5-09 / W5-10 already flag this. |
| `audit-response-2026-06-20.md:124-128` — "Four new negative tests in `contracts/morph-script-common/src/lib.rs` directly cover the audit's attack vectors" + "A fifth test for changed `payload_commitment` is documented as `#[ignore]`" | W5-01 confirmed 4 active + 1 ignored C-01 negative tests in `morph-script-common/src/lib.rs:5786-6043`. The ignored test is `rejects_splice_state_transition_with_changed_payload_commitment`. | ✓ (but see C-01 close issue in W5-01 / W3-08). |
| `audit-response-2026-06-20.md:103-106` — "state_context_matches_splice_next now also checks current.payload_commitment == next.payload_commitment" | W5-01: `morph-script-common/src/lib.rs:933-957` does NOT compare `payload_commitment` between current and next. Audit-response's exact wording is contradicted by the code. | HIGH — see W3-08. |
| `audit-response-2026-06-20.md:44` — "Implementation-side the attack was already closed at the splice bundle layer for all listed fields except `payload_commitment`" | W5-01: splice bundle layer checks are present for participants_commitment / settlement_descriptor_commitment / mode / asset_registry_commitment / challenge_policy_commitment. `payload_commitment` is closed at the vault-lock layer only. | MEDIUM — wording reads as if the splice bundle layer is fully closed; W5-01 found one field missing at the bundle layer. See W3-08. |
| `audit-response-2026-06-20.md:74-78` — `splice_successor_preserves_current_context` binds 16 fields on the successor State Header (including `state_layout_version`, `descriptor_version`, etc.) | W5-04: `crates/morph-core/src/types.rs:62-75` `same_context_except_progress` (host-side) does NOT check `settlement_descriptor_commitment` / `descriptor_version` / `payload_commitment`. The audit-response-claimed field set is script-side, but the host-side implementation is incomplete in those same fields — and an explicit test (`invariants.rs:611-626`) **asserts** the omission is "expected", freezing the gap. | MEDIUM — see W3-09. |
| `audit-response-2026-06-20.md:255-262` — "9 factory acceptance agenda items" (`factory_active` phase + F1..F9) | Documented in paper (per `paper-implementation-audit.md:31` and `audit-response-2026-06-20.md:460-489`). Not in scope of this audit to verify paper-side. | N/A (paper claim, not code claim). |

## 6. Fiber Morph 文档一致性

Three docs cover Fiber/Morph: the **integration plan** (`docs/fiber-integration-plan.md`), the **acceptance gate** (`docs/fiber-morph-devnet-acceptance.md`), and the **runbook** (`docs/fiber-morph-devnet-runbook.md`).

**Cross-doc coherence**:
- All three identify the same goal: Morph as a settlement backend behind Fiber, with the integration staying above Fiber's commitment transactions.
- The acceptance doc (`fiber-morph-devnet-acceptance.md:1-9, 268-273`) explicitly references the plan and the runbook as siblings; the plan (`fiber-integration-plan.md:285-288`) explicitly references the acceptance gate.
- The runbook (`fiber-morph-devnet-runbook.md`) is the operator walkthrough; the acceptance doc is the spec; the plan is the architectural rationale.

**Coherence gaps**:

| Aspect | Plan claims | Acceptance / Runbook claim | Drift? |
|---|---|---|---|
| Phased rollout (Phase 0..5) | `fiber-integration-plan.md:164-242` defines 6 phases: Phase 0 Adapter, Phase 1 External Funding Interop, Phase 2 Channel Backend Boundary, Phase 3 Morph Bilateral Backend, Phase 4 Factory Materialisation, Phase 5 Protocol Advertisement | Neither the acceptance doc nor the runbook mentions these phases at all. They define their own `coexistence` / `fiber` / `full` modes that don't map 1:1 to Plan Phase 0..5. The plan's Phase 0 acceptance (Fiber invoice ↔ Morph state packages) is roughly what `coexistence` does, but Phase 2-5 have no counterpart. | MEDIUM — see W3-10. |
| Fiber repository / branch / commit | Plan: Fiber repo `/Users/arthur/RustroverProjects/fiber`, branch `develop`, commit `3bbf5ea0` (line 9-10) | Acceptance / Runbook: no specific Fiber commit pinned. The script auto-clones (`acceptance.sh:69-71`) when sibling is missing, but the release evidence does not pin a Fiber commit. | MEDIUM — see W3-11. |
| Acceptance gate scope | Plan: same-devnet coexistence is mentioned as a single line at the end (`fiber-integration-plan.md:285-288`) | Acceptance: defines 29 business flows, 20 security families, 9 scenarios, 11 Morph security families (Runbook line 216-222). Plan does not enumerate any of these numbers. | LOW (acceptable — the plan is architecture; the acceptance/runbook are evidence). |
| "Implementation status" / what is done | Plan: "Phase 0: build a small adapter … not advertise Morph factory rights as Fiber public channels." Phase 0 acceptance items: invoice ↔ Morph mapping; wrong asset script rejection; watch package publish on devnet. | Acceptance / Runbook: The current `coexistence` and `full` modes run Morph stateful scenarios on Fiber's CKB devnet + Fiber external funding + Fiber strict Bruno suites. Phase 0 acceptance items map to "Morph stateful scenarios on Fiber's CKB RPC" (yes, present). | LOW — the actual same-devnet coexistence gate implements Phase 0 plus parts of Phase 3. Phases 4-5 are explicitly not yet there. |
| Number of Fiber Bruno strict suites | Acceptance: 13 strict Bruno suites + 4 funding-tx cases (line 113-138). `full` mode runs all. | Runbook: same 13 + 4 (line 18-23, 145-148). | ✓ aligned. |

## 7. README "Implemented" 列表 ↔ 真实覆盖

README §"What Is Implemented" (`README.md:53-69`) lists 8 items (the request prompt said 7; the actual count is 8 — see W3-01):

| README item | Real coverage | Verdict |
|---|---|---|
| bilateral CKB channels with state publication, supersession, relative-since vault finalisation, sponsored publication | `crates/morph-core/tests/invariants.rs` has 72 `#[test]`s including `accepts_valid_state_supersession`, `rejects_stale_or_equal_state_number`, `vault_spend_accepts_finalise_after_since`, `vault_spend_rejects_unmatured_finalise`, `vault_lock_accepts_finalise_with_current_state`; `crates/morph-core/tests/contract_scripts.rs` has 85 `#[test]`s (84 `#[ignore]`); devnet smokes: `devnet supersede-smoke`, `devnet finalise-since-negative-smoke` | ✓ |
| CKB+xUDT settlement through the same State Cell / Vault Cell authority | `morph-devnet-xudt` script exists; `morph-vault-lock` handles xUDT; devnet smokes: `xudt-smoke`, `xudt-one-sided-smoke`, `xudt-negative-smoke`, `factory-xudt-smoke`, `factory-xudt-negative-smoke` (`scripts/devnet-smoke.sh:168-208`) | ✓ |
| splice-in and splice-out flows that move a channel across funding anchors while preserving signed state semantics | `morph-script-common/src/lib.rs` parses splice bundle; `morph-state-type` and `morph-vault-lock` accept the splice bridge; devnet smokes: `splice-in-smoke`, `splice-out-smoke`, `xudt-splice-in-smoke`, `xudt-splice-out-smoke`; `verify_splice_state_transition` covers C-01 (4 active + 1 ignored) | ✓ (with C-01 close caveat from W3-08) |
| watchtower-style package publication with cursor persistence, policy checks, JSONL alerts, optional webhook alerts | `crates/morph-cli/src/watch_*` (10 + 9 + 27 tests across watch_policy/watch_alert/watch_config/packages/factory_packages); devnet smokes: `devnet watch-config-once`, watchtower JSONL + webhook tests | ✓ |
| conservative factory state updates signed by all factory participants | `morph-factory-type/src/main.rs`; tests: `factory_type_accepts_signed_factory_update`, `factory_type_rejects_equal_update_number`, `factory_type_rejects_invalid_participant_signature` | ✓ |
| factory local exits that materialise child bilateral channels | `factory_type_and_vault_accept_local_exit_materialisation`, `factory_type_and_vault_accept_local_exit_xudt_materialisation`; devnet `factory-exit-channel` (W4-02 confirms script) | ✓ |
| bounded reduced-rights, reduced-exit, sparse-Merkle update, and reduced-splice factory proof bodies carried by `WitnessEnvelope` | `morph-script-common/src/lib.rs:368-392` parses `WitnessEnvelope`; factory script dispatch by kind; tests in audit-matrix.md lines 21-22 (factory splice family); reduced paths covered in devnet smokes | ✓ |
| local devnet smoke reports and stateful acceptance reports that bind protocol scenarios to transaction evidence, cycle budgets, and expected negative-path failures | `devnet-smoke-report` / `devnet-smoke-assert` / `devnet-smoke-assert-budget` / `devnet-stateful-report` / `devnet-stateful-assert`; budget profiles in `docs/devnet-smoke-budget.example.json` and `docs/devnet-stateful-budget.example.json` (W4-03: top-level `description` field is dead) | ✓ (with W4-03 cosmetic note on `description`) |

All 8 items are real. None is purely aspirational.

## Findings

### W3-01 — README "Implemented" list count is 8, not 7 as referenced in the audit brief
**Severity**: LOW
**Surface**: `README.md:53-69`
**Confidence**: high
**Claim**: README §"What Is Implemented" lists 8 bullets (bilateral, CKB+xUDT, splice, watchtower, conservative factory update, factory local exits, bounded reduced bodies, devnet/stateful reports), not 7. The audit brief specifies "7 items" — this is a discrepancy in the brief, not in the README. The brief's framing is the only place 7 appears.
**Evidence**: `README.md:53-69` shows 8 bullets.
**Impact**: Minor. Counting either way is fine.
**Suggested fix**: Either accept 8 as the correct count and update any downstream reference, or roll two related bullets into one (e.g., "factory local exits and bounded reduced-rights / reduced-exit / sparse-Merkle / reduced-splice proof bodies"). No code change.

### W3-02 — `current-devnet-rc-closeout.md` title says "current" but body says "historical"
**Severity**: MEDIUM
**Surface**: `docs/current-devnet-rc-closeout.md:1, 4, 11-31`
**Confidence**: high
**Claim**: The file's title is "Devnet current RC Closeout", and its first sentence (line 4) says "Status: historical Devnet release-candidate evidence; superseded for current readiness tracking by the witness-envelope factory witness work." Its body anchors `4ca867c` (5fb7494 was the previous safety-kernel baseline). The "current" in the title is misleading: the closeout's evidence (smoke JSONs, deployed-script hashes) was captured at `4ca867c`, and the witness-envelope rewrite at `a07ec47` (June 10) and `a2059ba` (June 13) followed. The current devnet RC closeout (if any) would have to come from a fresh acceptance run on the post-`a2059ba` line.
**Evidence**: `git log --all --oneline | grep 4ca867c` returns the May 20 commit; subsequent commits `a07ec47` (Unify current protocol model), `a2059ba` (Implement V2 non-fixed factory witnesses), and `aa71651` (audit close) all post-date the closeout's anchor. The file itself says so on lines 14, 17, 26, 31.
**Impact**: A new operator skimming the file might treat its numbers (155 / 192 / 7 / 9 / 5) as current release evidence. They are evidence of `4ca867c` only. W4-01 already flagged the missing gate enforcement; this is the doc-side leg of that drift.
**Suggested fix**: Rename the file to `docs/v1-devnet-rc-closeout.md` (or `historical-devnet-rc-closeout.md`), and update internal references in roadmap / mainnet-readiness. Optionally add a "current" closeout stub that points at `docs/devnet-stateful-acceptance-closeout.md` as the current gate.

### W3-03 — `devnet-stateful-acceptance-closeout.md` self-declares as "current release-evidence gate" but anchors at pre-V2-envelope commits
**Severity**: HIGH
**Surface**: `docs/devnet-stateful-acceptance-closeout.md:1-6, 33-46, 105-117`
**Confidence**: high
**Claim**: The closeout's first paragraph says "devnet stateful acceptance is the required current release-evidence gate" and the closing line says the suffix on `morph.devnet_stateful_scenario` "is not a protocol or witness-version label. Current factory authorisation is read through the bounded `WitnessEnvelope` kind/body/digest envelope, and this historical closeout needs fresh rerun evidence before it can serve as current release evidence again." The two sentences contradict each other: the first says "current", the second says "historical". Anchors are `3814453` (final committed baseline, Apr 30) and `17e1964` (run-time artifact, May 1). Both predate `a07ec47` (June 10, unify current protocol model), `a2059ba` (June 13, V2 non-fixed factory witnesses), and `aa71651` (June 21, audit close). The "deployed script hashes" table (lines 105-117) lists hashes such as `morph-state-type 0x788db1…`, `morph-factory-type 0x8d5ee4…`, `morph-vault-lock 0x62f8d3…` — none of which are the script hashes the current line would deploy.
**Evidence**: `git log --all --oneline | grep -E "3814453|17e1964"` confirms both exist and are pre-V2-envelope. `git show 3814453 --stat | head` shows the commit added stateful audit acceptance. The post-`a07ec47` morph-state-type and morph-factory-type source files (rewritten in the V2 envelope work) would deploy different binary hashes than the closeout lists.
**Impact**: The stateful closeout is the most concrete "release evidence" claim in the repo, and it is contradicted by its own closing line. A reviewer who reads only the top of the file will treat the 9 / 11 / 81 / 44 / 9 / 192 / 6 / 9 / 5 / 32 numbers as current release evidence; they are not.
**Suggested fix**: Either (a) regenerate the closeout by re-running `make devnet-stateful-e2e` against `aa71651` and producing a fresh artifact under `target/devnet-stateful-e2e/<new-run>/`, then update the file with the new anchors and the new deployed-script hashes; or (b) explicitly demote the closeout to historical by changing the title to `devnet-stateful-acceptance-closeout-historical.md` and stating in the first paragraph that the current release-evidence gate is "re-run devnet-stateful-e2e against the current clean HEAD".

### W3-04 — `docs/roadmap.md` M5 wording ("Implemented locally") disagrees with `docs/mainnet-readiness.md` watchtower gate ("Open")
**Severity**: MEDIUM
**Surface**: `docs/roadmap.md:31` vs `docs/mainnet-readiness.md:30-31`
**Confidence**: high
**Claim**: Roadmap M5 row says "Implemented locally" with evidence ("watch config, policy checks, JSONL/webhook alerts, stale-package guard, smoke assertions, stateful assertions, budget profiles"). Mainnet-readiness table has two gates still "Open": "Reorg and delay evidence" (line 30) and "Multi-operator watchtower evidence" (line 31). The M5 "implemented locally" framing is consistent with the devnet research posture — M5 is implemented locally but not for mainnet — but the gate doc does not call out the watchtower layer as "local-only".
**Evidence**: The two files use different abstraction levels: roadmap tracks milestones; mainnet-readiness tracks gates. The wording is not strictly contradictory (local implementation ≠ mainnet-ready), but a reader skimming the roadmap may take M5 as "done", whereas M5's watchtower evidence is local-only and the multi-operator gate is explicitly Open.
**Impact**: A roadmap-style reader could misinterpret M5 as finished for production purposes, when it is local-only.
**Suggested fix**: Add a one-line note on roadmap.md's M5 row (or in the "Deferred Work" table at lines 51-58) clarifying "watchtower evidence is local and single-environment; multi-operator gate per `mainnet-readiness.md` is Open".

### W3-05 — `redundant-stale-code-audit.md` title lacks a "historical" qualifier despite body declaring it historical
**Severity**: LOW
**Surface**: `docs/redundant-stale-code-audit.md:1, 7-18`
**Confidence**: high
**Claim**: Body lines 7-18 explicitly say "This document is a historical audit of the devnet release-candidate line, not a current stale-code assessment of the witness-envelope implementation." But the title still reads "Redundant and Stale Code Audit" without "historical".
**Evidence**: Title `docs/redundant-stale-code-audit.md:1`; supersession note lines 7-18.
**Impact**: Same leg of the same drift as W3-02 / W3-03 — easy to mistake for current.
**Suggested fix**: Add "(historical)" to the title.

### W3-06 — `withdrawal_payout_policy` referenced in tutorial but absent from `implementation.md`
**Severity**: LOW
**Surface**: `docs/morph-channel-tutorial.md` (does not mention `withdrawal_payout_policy`), `docs/m5-closeout.md:46-51`, `docs/implementation.md` (does not mention either)
**Confidence**: medium
**Claim**: The tutorial does NOT reference `withdrawal_payout_policy`; `m5-closeout.md:46-51` describes "the conservative participant-owned withdrawal rule through `withdrawal_payout_policy`, the participant pubkey, and the live withdrawal lock hash"; `implementation.md` mentions "withdrawal out point" implicitly via "Acceptable splice payouts" only in audit-matrix (`audit-matrix.md:26`).
**Evidence**: `grep withdrawal_payout_policy docs/*.md` returns hits in m5-closeout only.
**Impact**: Small detail. m5-closeout is historical, so this is a documentation completeness gap on the historical/transition boundary, not on the current line.
**Suggested fix**: When the closeout documents are reorganised per W3-02 / W3-03, move the `withdrawal_payout_policy` description into implementation.md or a dedicated protocol detail page so it isn't only in a historical closeout.

### W3-07 — `audit-matrix.md` row "Smoke comparison can be used as a regression gate" references test names that do not exist in source
**Severity**: MEDIUM
**Surface**: `docs/audit-matrix.md:42-43`
**Confidence**: high
**Claim**: `audit-matrix.md` row says "Smoke comparison can be used as a regression gate" with executable checks `comparison_limits_reject_metric_regressions` and `comparison_limits_reject_set_and_status_changes`. W5-11 confirmed: `rg "comparison_limits" /Users/arthur/RustroverProjects/morph-channel` returns hits only in `docs/audit-matrix.md` — no `.rs` file contains these test names.
**Evidence**: `rg comparison_limits /Users/arthur/RustroverProjects/morph-channel` returns audit-matrix.md only.
**Impact**: The audit-matrix promises tests that don't exist. Either the test names were renamed (and audit-matrix didn't follow), or the tests were never written.
**Suggested fix**: (a) Find the actual test names in `crates/morph-cli/src/smoke_report.rs` (the comparison limits likely live there) and update audit-matrix.md to cite the real test names with `file:line` references; (b) if the tests really don't exist, write them and add a `#[test]` for the gate. W5-11 already flags this; this W3 entry confirms it from a docs-consistency angle.

### W3-08 — `audit-response-2026-06-20.md` claims `state_context_matches_splice_next` checks `payload_commitment`; code does not
**Severity**: HIGH
**Surface**: `docs/audit-response-2026-06-20.md:103-106`, `contracts/morph-script-common/src/lib.rs:933-957`
**Confidence**: high
**Claim**: Audit-response §"C-01 Implementation patch" item 1 says `state_context_matches_splice_next now also checks current.payload_commitment == next.payload_commitment`. The actual implementation at `morph-script-common/src/lib.rs:933-957` compares `protocol_version`, `chain_id`, `signature_scheme_id`, `channel_id`, `funding_epoch`, `funding_anchor`, `vault_set_commitment`, `state_number`, `mode`, `participants_commitment`, `asset_registry_commitment`, `settlement_descriptor_commitment`, `descriptor_version`, `challenge_policy_commitment`, `state_layout_version` — `payload_commitment` is absent.
**Evidence**: `morph-script-common/src/lib.rs:933-957` (W5-01 line-by-line read); audit-response lines 103-106. The ignored test `rejects_splice_state_transition_with_changed_payload_commitment` (`morph-script-common/src/lib.rs:5714-5780`) would currently fail if un-ignored, confirming the bundle-layer check is missing.
**Impact**: This is the same finding W5-01 reports from a test-coverage angle. From a docs-consistency angle, this is a direct contradiction between the audit-response letter and the code. The audit-response is supposed to record "where the fix lives" for each finding; for C-01 it overstates the bundle-layer fix.
**Suggested fix**: Either (a) add the `payload_commitment` comparison to `state_context_matches_splice_next` and remove `#[ignore]` from `rejects_splice_state_transition_with_changed_payload_commitment`, then update the audit-response wording to match (the closure becomes both bundle-layer AND vault-lock-layer); or (b) leave the code as-is and rewrite the audit-response item 1 to say the bundle-layer check is intentionally absent in the bilateral plain profile, with the closure being at the vault-lock layer only.

### W3-09 — `same_context_except_progress` host-side helper drops `settlement_descriptor_commitment`, `descriptor_version`, `payload_commitment` while script-side checks them
**Severity**: MEDIUM
**Surface**: `crates/morph-core/src/types.rs:62-75`, `crates/morph-core/tests/invariants.rs:611-626`, `contracts/morph-script-common/src/lib.rs:933-957`
**Confidence**: high
**Claim**: The host-side `same_context_except_progress` does NOT check `settlement_descriptor_commitment`, `descriptor_version`, or `payload_commitment`. The script-side `state_context_matches_splice_next` checks `settlement_descriptor_commitment` and `descriptor_version` (but NOT `payload_commitment`, per W5-01 / W3-08). The test `state_header_context_rejects_epoch_and_vault_set_changes` (`invariants.rs:611-626`) explicitly **asserts** that changed `payload_commitment` and `settlement_descriptor_commitment` return `true` from `same_context_except_progress`, freezing the omission as "expected behavior".
**Evidence**: `crates/morph-core/tests/invariants.rs:611-626` (W5-04 line-by-line read); `crates/morph-core/src/types.rs:62-75` (host-side definition).
**Impact**: Host-side validation gaps mirror script-side gaps. If a future change relaxes the script-side check, the host-side will silently allow it. This is the kind of test-freeze drift that audit-response's M-04 mitigation ("must include actual CKB tx-pool behaviour, … direct-miner fallback") is supposed to catch by demanding executable evidence.
**Suggested fix**: Align host-side `same_context_except_progress` with script-side `state_context_matches_splice_next` (or define an explicit divergence table), and update `invariants.rs:611-626` to reflect the alignment. W5-04 already proposes this.

### W3-10 — Fiber integration-plan "Phase 0..5" rollout does not map to the acceptance/runbook "coexistence/fiber/full" modes
**Severity**: MEDIUM
**Surface**: `docs/fiber-integration-plan.md:164-242` vs `docs/fiber-morph-devnet-acceptance.md:84-112`, `docs/fiber-morph-devnet-runbook.md:18-23`
**Confidence**: medium
**Claim**: The integration plan describes a 6-phase rollout (Phase 0 Adapter / Phase 1 External Funding Interop / Phase 2 Channel Backend Boundary / Phase 3 Morph Bilateral Backend / Phase 4 Factory Materialisation / Phase 5 Protocol Advertisement). The acceptance doc and runbook describe 3 modes (`preflight`, `coexistence`, `fiber`, `full`) that don't map 1:1 to any single Plan phase. Phase 0 acceptance items (invoice ↔ Morph mapping, wrong-asset-script rejection, watch package publish) are roughly what `coexistence` does; Phases 4-5 have no counterpart in the acceptance gate (which is deliberate — see the acceptance doc line 268-273).
**Evidence**: `grep "Phase [0-9]" docs/fiber-*.md` returns 6 hits in plan, 0 in acceptance/runbook.
**Impact**: A reviewer who reads only the plan may expect to see explicit Phase 0/1/2/3 evidence in the acceptance gate. The acceptance gate proves same-devnet coexistence + Fiber external funding + strict Fiber Bruno suites — Phases 2 (backend boundary) and 4-5 (factory graph + protocol advertisement) are not yet there. This is honest in the acceptance doc line 268-273 but the plan's optimistic "Phase 0 = do this now" framing can mislead.
**Suggested fix**: Add a short paragraph at the end of `fiber-integration-plan.md` mapping Phase 0..5 to the current acceptance gate modes (Phase 0 → `coexistence`, Phase 1 → partial `coexistence` external-funding, Phases 2-5 → not yet implemented / no counterpart). Keep the plan aspirational but make the current-evidence mapping explicit.

### W3-11 — Fiber acceptance/runbook do not pin a Fiber commit; plan pins `3bbf5ea0`
**Severity**: MEDIUM
**Surface**: `docs/fiber-integration-plan.md:9-10` vs `docs/fiber-morph-devnet-acceptance.md` (no Fiber commit) vs `docs/fiber-morph-devnet-runbook.md` (no Fiber commit)
**Confidence**: medium
**Claim**: The integration plan pins Fiber commit `3bbf5ea0` on branch `develop`. The acceptance doc and runbook say nothing about which Fiber commit the gate is verified against; the script auto-clones upstream when sibling is missing (`acceptance.sh:69-71`). A release-candidate rerun against `aa71651` will exercise whatever Fiber HEAD the operator has at `../fiber`, which may or may not match `3bbf5ea0`.
**Evidence**: `fiber-integration-plan.md:9-10` quotes the commit; `acceptance.md` and `runbook.md` have no equivalent line; `acceptance.sh:69-71` (auto-clone) does not check out a pinned commit when missing.
**Impact**: Release evidence from a `make fiber-morph-devnet-acceptance-full` run is non-reproducible across operators unless they pin Fiber. Plan and acceptance drift on this point.
**Suggested fix**: Add a `FIBER_PIN_COMMIT=3bbf5ea0` env-var default in `acceptance.sh` and document it in the acceptance doc + runbook. The release-evidence statement at runbook line 273-289 should require `repo-state.json` to record the actual Fiber commit (which it already does at acceptance.sh:79-106 — the doc just doesn't surface this as a release requirement).

## Cross-cutting

- **Closeout label drift** (W3-02 / W3-03 / W3-05): three closeouts / audit docs mix "current" and "historical" in their titles vs bodies, despite all three self-declaring historical. Once `a07ec47` and `a2059ba` landed, none of the previously-current closeouts is current anymore — but only `redundant-stale-code-audit.md` is unambiguous about it.
- **Audit-response overstates close** (W3-08 / W3-09): C-01's "Implementation patch" item 1 is contradicted by `morph-script-common/src/lib.rs:933-957`. The audit-response is the closest thing to a "release letter" in this repo and should not overstate.
- **Fiber integration narrative** (W3-10 / W3-11): the three Fiber docs are coherent on the same-devnet coexistence gate but diverge on roadmap phasing and Fiber commit pinning. The acceptance gate is the live one; the plan is aspirational; the runbook is the operator walkthrough.
- **No CRITICAL**: this audit found no critical drift — the highest-severity findings are HIGH (W3-03 stateful closeout anchors, W3-08 audit-response overstates C-01 close). Both are recoverable with doc rewrites or a fresh re-run.

## Files reviewed

- `/Users/arthur/RustroverProjects/morph-channel/README.md` (304 lines)
- `/Users/arthur/RustroverProjects/morph-channel/docs/mainnet-readiness.md` (106 lines)
- `/Users/arthur/RustroverProjects/morph-channel/docs/roadmap.md` (91 lines)
- `/Users/arthur/RustroverProjects/morph-channel/docs/audit-matrix.md` (191 lines)
- `/Users/arthur/RustroverProjects/morph-channel/docs/audit-response-2026-06-20.md` (614 lines)
- `/Users/arthur/RustroverProjects/morph-channel/docs/paper-implementation-audit.md` (96 lines)
- `/Users/arthur/RustroverProjects/morph-channel/docs/generalized-audit.md` (55 lines)
- `/Users/arthur/RustroverProjects/morph-channel/docs/redundant-stale-code-audit.md` (127 lines)
- `/Users/arthur/RustroverProjects/morph-channel/docs/m5-closeout.md` (86 lines)
- `/Users/arthur/RustroverProjects/morph-channel/docs/m6-closeout.md` (119 lines)
- `/Users/arthur/RustroverProjects/morph-channel/docs/current-devnet-rc-closeout.md` (141 lines)
- `/Users/arthur/RustroverProjects/morph-channel/docs/devnet-stateful-acceptance-closeout.md` (147 lines)
- `/Users/arthur/RustroverProjects/morph-channel/docs/fiber-integration-plan.md` (288 lines)
- `/Users/arthur/RustroverProjects/morph-channel/docs/fiber-morph-devnet-acceptance.md` (273 lines)
- `/Users/arthur/RustroverProjects/morph-channel/docs/fiber-morph-devnet-runbook.md` (290 lines)
- `/Users/arthur/RustroverProjects/morph-channel/docs/morph-channel-tutorial.md` (169 lines)
- `/Users/arthur/RustroverProjects/morph-channel/docs/morph-channel-tutorial.zh.md` (164 lines)
- `/Users/arthur/RustroverProjects/morph-channel/docs/implementation.md` (284 lines)
- `/Users/arthur/RustroverProjects/morph-channel/docs/swarm-audit-tests.md` (W5, cited)
- `/Users/arthur/RustroverProjects/morph-channel/docs/swarm-audit-W4-ops-acceptance.md` (W4, cited)
- `git log --oneline | head -40`, `git log --all --oneline | wc -l = 166`
- `grep -rE '^#\[test\]' crates contracts | wc -l` → 165 (column-0) + 112 (4-space in crates) + 56 (4-space in contracts) = 333 `#[test]` functions
- `grep -rE '^#\[ignore' crates contracts | wc -l` → 84 ignored, all `requires make build-contracts` in `crates/morph-core/tests/contract_scripts.rs`; 0 ignored elsewhere
- `crates/morph-core/src/types.rs:62-75` (host-side `same_context_except_progress`)
- `contracts/morph-script-common/src/lib.rs:368-392` (WitnessEnvelope parser), `:933-957` (`state_context_matches_splice_next`), `:5714-5780` (ignored `payload_commitment` test), `:5786-6043` (4 active C-01 negative tests)
- `crates/morph-core/tests/invariants.rs:611-626` (host-side omission freeze)
- `crates/morph-cli/src/smoke_report.rs:2208-2239` (W4-01 hardcoded floors, cited from W4)
- `scripts/fiber-morph-devnet-acceptance.sh:69-71, 79-106, 607-623, 644-655, 780-792` (cited from W4)
- `Makefile:13, 15-16, 35-37, 72-73, 87-91` (cited from W4 / W5)