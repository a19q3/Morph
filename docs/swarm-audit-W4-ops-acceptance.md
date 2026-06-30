# Swarm Audit — W4 运维 / Acceptance / Scripts
Date: 2026-06-22
Scope: scripts/ (8 shell) + Makefile (113 lines) + 3 budget/audit JSON
profiles + .github/workflows/ci.yml + docs/{devnet,fiber-morph-devnet-*,
audit-matrix,audit-response-2026-06-20,devnet-stateful-acceptance-closeout,
current-devnet-rc-closeout}.md + crates/morph-cli/src/{smoke_report,
stateful_report,main}.rs (read-only, for JSON field-liveness verification).

Severity counts: HIGH 2 / MEDIUM 5 / LOW 3

Prior audit cite policy: W5-09/10/11/13 (Makefile / contract_tests /
audit-ignore) live in `docs/swarm-audit-tests.md` and are NOT repeated here;
this report is orthogonal to W5.

---

## 1. Audit-matrix 声称 ↔ script 实际

| audit-matrix / audit-response 声称 | 实际跑该 claim 的 command | 一致? |
|---|---|---|
| `audit-matrix.md:13` — "One live State Cell controls the channel pointer" via `accepts_valid_state_supersession` + `rejects_stale_or_equal_state_number` | `make test` → `cargo test --workspace` runs `crates/morph-core/tests/invariants.rs` (per W5-09/10, `--ignored` not in default `test:` target; for C-01 negative tests added in audit-response, see W5-09/10/12). | OK (workspaces-level), but 84 contract_scripts `#[ignore]` tests are NOT exercised by `make test`. |
| `audit-matrix.md:60-73` — "Implemented devnet-level checks" (CKB transaction construction / factory CKB-VM / finalise-since / xUDT / watchtower / splice negative) | `make devnet-smoke` → `scripts/devnet-smoke.sh` runs `devnet supersede-smoke`, `devnet finalise-since-negative-smoke`, `devnet xudt-smoke`, `devnet xudt-negative-smoke`, `devnet factory-xudt-smoke`, `devnet factory-xudt-negative-smoke`, `devnet competing-spend-smoke`, `devnet sponsor-budget-negative-smoke`, `devnet sponsor-policy-negative-smoke`, `devnet splice-negative-smoke`, watchtower `devnet watch-config-once` etc. (`scripts/devnet-smoke.sh:67-79, 398-644`). | OK — each smoke name is invoked by exact `run_json` line; failure to run any would surface as a missing JSON file in `summary.json`. |
| `audit-matrix.md:115-118` — "Stateful devnet scenario assertions through `devnet-stateful-assert`" | `make devnet-stateful-e2e` → `scripts/devnet-stateful-e2e.sh:178-182` runs `cargo run -q -p morph-cli -- devnet-stateful-assert --dir ... --audit-profile docs/devnet-audit-profile.example.json --budget-profile $BUDGET_PROFILE --json`. | OK — wired through Makefile → script → CLI with the right profiles. |
| `audit-response-2026-06-20.md:26` — "155 smoke JSONs, 192 committed transactions, 7 deployed scripts with verified hashes" | `current-devnet-rc-closeout.md:53-66` claims these for commit `4ca867c`. The current script surface counts are **hardcoded floors in `crates/morph-cli/src/smoke_report.rs:2208-2239` and `:2285-2324`**: `EXPECTED_SCRIPT_FAILURES` has 6 entries (closeout:99 says "Expected script failures: 6" ✓); `EXPECTED_BUSINESS_MATRIX_TRANSACTIONS` is a static table; `transaction_count >= 0` (no floor on `155` or `192`). | **Partially inconsistent** — the closeout's specific counts (155 / 192 / 7) are NOT gate-enforced; only the *shape* (6 negative failures, business-matrix JSON list, deploy-contracts list) is. See finding W4-01. |
| `audit-response-2026-06-20.md:591` — "248 workspace tests pass" | `make test` runs `cargo test --workspace` (Makefile:15-16). | OK *only* for non-ignored workspace tests. As W5-09/10 already flagged, this excludes the 84 contract_scripts `#[ignore]` tests, so the "248" number is a `make test` count, not a `make contract-tests` count. |
| `docs/fiber-morph-devnet-acceptance.md:183-205` — "Fiber coexistence requires `e2e/external-funding-open` + restart; `full` additionally requires 17 named Fiber suites + 4 funding-tx cases (29 business flows, 20 security families, 9 Morph scenarios, 11 Morph security families)" | `make fiber-morph-devnet-acceptance-full` → `scripts/fiber-morph-devnet-acceptance.sh` mode=full → calls `scripts/fiber-morph-devnet-audit.sh` (`acceptance.sh:775`). The audit script enforces: 9 scenarios, 11 audit families, scenario/audit floors via `jq_check` (`audit.sh:160-180`), 19 named Fiber suite result files (`audit.sh:440-513`), and emits exactly 29 business_flows + 20 security_families in `business-flow-audit.json` (counted by hand from `audit.sh:256-363`). | OK — the 29/20/9/11 claims are statically verifiable against the jq expressions in the audit script, and the evidence paths are present-asserted, not just JSON-status-trusted. |
| `docs/devnet-stateful-acceptance-closeout.md:53-62` — "make devnet-stateful-e2e passed; devnet-stateful-report with audit-profile passed; devnet-stateful-assert with audit-profile + budget-profile passed" | All three commands are wired: `scripts/devnet-stateful-e2e.sh:177-182`, `Makefile:109-113`. | OK. |
| `docs/devnet-stateful-acceptance-closeout.md:91-100` — "9 required, 9 present scenarios; 11 required, 11 passed audit families; 81 referenced artifacts; 44 required committed checks; 9 expected failures; 192 committed txs; 6 expected script failures; 9 watchtower alerts; 5 reduced exits; 32 splices" | Floors are enforced at `audit.sh:160-180` (≥9 scenarios, ≥9 required_scenarios, ≥11 audit_families, audit_families_passed == audit_families, ≥87 referenced_artifacts, ≥62 required_committed_checks, ≥9 expected_failures, ≥190 smoke.totals.transaction_count, ≥190 smoke.totals.committed_count). | **Stale floors in the closeout (44 / 81 / 192 / 9 / 32) are STRICTER than what the current script enforces (62 / 87 / 190 / 9 / ?).** The script floors are slightly LOWER on checks, slightly HIGHER on transactions. See finding W4-02. |
| `audit-matrix.md:134-139` — "xUDT reduced-exit body schema active at contract/CKB-VM layer" — names 7 specific factory_type/vault accept/reject tests. | Not in scripts/ — lives in `crates/morph-core/tests/invariants.rs` + CKB-VM fixtures. | N/A (not a script claim). |

---

## 2. Script 健壮性

### `scripts/check-devnet-env.sh` (86 lines)
Solid. `set -euo pipefail`. `check()` and `check_bin()` are clean. `resolve_ckb_bin()` checks three sources in order (env, PATH, sibling-build). Two notable weaknesses: (a) it never verifies the CKB source tree is **fetched** or that the build it picks matches the current CKB dependency graph (it just executes whatever binary is in PATH or the build dir); (b) the `rustup target list --installed` check on line 67-72 is the only RISC-V check, and there's no version check for the riscv toolchain (so an old `riscv64imac-unknown-none-elf` could be present but produce binaries that don't load on a newer CKB-VM).

### `scripts/devnet-node.sh` (72 lines)
Robust. `set -euo pipefail`. The `ensure_integration_test_rpc` regex is a single in-place perl substitution (`scripts/devnet-node.sh:32`) that rewrites the `modules = [...]` line; if a config has multi-line or commented-out `modules =` it could fail silently. The `ensure_block_assembler` appends a `[block_assembler]` block, but does **not** check whether the existing block_assembler arg matches `BLOCK_ASSEMBLER_ARG`; if a user supplies `--ba-arg` via `CKB init` then re-runs, the appended block is harmless (parsed once) but a stale second block could cause parser failures in some CKB versions. `exec ckb -C "$CKB_DIR" run` runs in foreground — no PID file, no signal trapping at the script level (the e2e scripts handle teardown).

### `scripts/devnet-e2e.sh` (199 lines)
Hardened. Port-collision detection (`port_is_free` at line 72-79 with lsof+nc fallback); pre-flight `CKB_DIR` existence check (line 119-121); trap on EXIT (line 113) that stops the CKB node; `wait_for_rpc` checks node liveness in the loop (line 93-95) and bails early if the node died; the `KEEP_NODE=1` path is explicit. The `wait_for_rpc` body is `curl ... | jq -e '.result != null'`; if the JSONRPC returns `{"result": null}` (some methods do), this would loop until timeout — but `get_tip_header` always returns a non-null result on a live node, so this is fine in practice. The script does not validate the ckb CLI's `--version` or chain id against the smoke assumptions.

### `scripts/devnet-smoke.sh` (668 lines)
The big one. 55+ `run_json` calls each spin up a fresh `cargo run -q -p morph-cli -- ...`. **There is no global timeout per step**; a hung `cargo run` will hang the entire smoke. **There is no intermediate progress save** — if any of the ~50+ `run_json` calls fails, the script exits with `set -e` and the partial artefacts are written but the run is marked failed only in the manifest if `set -e` propagates from a later step (it doesn't, the failure is the exit). The watchtower key file (line 401-404) uses a hardcoded fallback `MORPH_DEVNET_PRIVATE_KEY` default — fine for devnet but the hardcoded key is in plaintext on the wire. The `validate-fixture` (line 62) and `cargo test --workspace` (line 63) and `make contract-tests` (line 64) are all run inline as `run_log` and tee to `$name.log` — this is good for debuggability, but the `cargo test` run is captured under the same `OUT_DIR` and not the CI cache, so it will not benefit from incremental compilation across runs.

### `scripts/devnet-stateful-scenarios.sh` (193 lines)
Robust. 9 `write_scenario` calls (lines 90-169) cover all 9 named scenarios; the `required_committed_checks` arrays reference paths that match the smoke artefact layout 1:1. The script writes `summary-check.json` via `cargo run -q -p morph-cli -- devnet-stateful-assert` (line 181) — same profile as in `devnet-stateful-e2e.sh`. The path of the `stateful-assert` here is the **stateful-scenarios version** (no audit-profile), while the e2e wrapper adds the audit-profile (line 180). One subtlety: the stateful-scenarios-only run uses the smoke artefact's `summary.json`/`summary-check.json` as the source for `scenario.required_committed_checks` references; if a future scenario declares a check that the smoke script never writes, the assertion will reject it correctly — but if a future scenario DROPS a check, the audit profile still has it, and the family will fail with `missing_checks`. This is a feature, not a bug, but the user-facing docs don't call it out.

### `scripts/devnet-stateful-e2e.sh` (199 lines)
Near-duplicate of `devnet-e2e.sh` with the only meaningful difference being the inner `scripts/devnet-stateful-scenarios.sh` call and the dual `--audit-profile` + `--budget-profile` in the `devnet-stateful-assert` invocation (line 178-182). The two e2e wrappers (`devnet-e2e.sh` and `devnet-stateful-e2e.sh`) are **~95% identical** (compare line-by-line) — this is a maintenance hazard: a fix to the CKB resolve/port-check/wait-for-rpc path in one must be mirrored in the other. The recent hardening commits (`fa8cd68`, `22474b1`, `c59a677`, `dadf8b5`, `0f1e2ca`, `113b0b8`) appear to have landed on the fiber side; the `devnet-*.sh` scripts have not seen the same hardening wave.

### `scripts/fiber-morph-devnet-acceptance.sh` (830 lines)
This is the most complex script. Hardening evidence is strong:
- `start_fiber_stack` retries up to `FIBER_STACK_START_ATTEMPTS=3` (default) with status-code-aware differentiation (`audit.sh:412-415` distinguishes port-busy from generic failure).
- `stop_fiber_stack` uses `kill_tree` (recursive child kill via `pgrep -P`) and a `wait_for_acceptance_ports_free` 30s window, then a `stop_acceptance_port_listeners` fallback that force-kills lingering lsof-detected PIDs (line 322-344).
- `validate_external_funding_open_evidence` and `validate_period_check_expiry_evidence` (line 504-561) accept known-stale Bruno assertion shapes and demand concrete log markers (`Removing expired tlc`, `RemoveTlcFail`, `tlcs count: 0`, exact `200 OK` request markers for funding-open) — this is the only place in the repo that proves behaviour, not just status flags. This is a strong design.
- `assert_clean_for_production` (line 108-119) requires a clean Morph + Fiber tracked worktree for `coexistence`/`fiber`/`full` modes; tracked-only is correct (untracked files like `target/` are fine).
- The `set -euo pipefail` is enforced; the `MODE=$1` argument parsing (line 38-42) is positional-only with no `--` separator, so `--preflight` as the first arg is parsed correctly but `preflight --foo` would set MODE=preflight and then `fail` on `--foo` is never reached because the script doesn't re-parse.

**Gap**: the `run_morph_stateful_on_fiber_ckb` (line 607-623) calls `scripts/devnet-stateful-scenarios.sh` with `MORPH_DEVNET_SMOKE_SKIP_LOCAL_CHECKS=1` — but it does **not** pass `--audit-profile` or `--budget-profile`, so the inner stateful-assert (line 181) runs without budget checks. The audit (line 178-182 of `devnet-stateful-e2e.sh`) and the parent acceptance summary's `morph_stateful_summary_check` will use the **unbudgeted** summary-check.json. The audit's `verify_morph_stateful` then reads that same file and runs `assert_default_devnet_stateful` (via the chain through `stateful_report::assert_default_devnet_stateful`) — but `stateful-e2e.sh` adds the budget, the acceptance does not. **W4-04 below**.

**Gap**: the script invokes the audit at the end (`acceptance.sh:775` — `$ROOT_DIR/scripts/fiber-morph-devnet-audit.sh "$OUT_DIR"`). The audit reads the **latest** run by default (line 25) — but here it is passed an explicit `$OUT_DIR`, so this is fine.

### `scripts/fiber-morph-devnet-audit.sh` (520 lines)
This is the gate's gate. Strong:
- `require_manifest_status` (line 47-50) is a hard fail on missing `status=passed`.
- `verify_morph_stateful` (line 152-212) enforces all 9 scenarios, 11 audit families, and 13 named JSON floors (`.scenario_count >= 9`, `.audit_families >= 11`, `.referenced_artifacts >= 87`, `.required_committed_checks >= 62`, `.expected_failures >= 9`, `.smoke.transaction_count >= 190`, `.smoke.watchtower_alerts >= 9`, `.smoke.factory_local_exits >= 24`, `.smoke.factory_splices >= 32`, etc.).
- 15 named `require_fiber_suite_evidence` calls (line 425-513) each demand a non-empty `log` field AND concrete log markers — so a passing `fiber-bruno-*.json` whose `log` is empty is **rejected** (line 73-76).
- `require_fiber_period_check_expiry_evidence` (line 127-150) is a triple-evidence gate: at least 2 `Removing expired tlc 0` lines, at least 4 `RemoveTlcFail` lines, at least 4 `tlcs count: 0` lines in the stack log.

**Subtle concern**: line 49 `grep -qx 'status=passed'` — if the manifest is exactly `status=passed` with no surrounding whitespace, this matches. If a future script accidentally writes `status = passed` (with spaces) or `status=passed` followed by a CRLF, the gate will reject the run. Currently `devnet-e2e.sh:186` and `devnet-stateful-e2e.sh:186` both write `status=passed` cleanly. OK.

**Subtle concern**: the audit at line 391-394 enforces `.morph.status == ""` and `.fiber.status == ""` — but the `repo-state.json` is captured **before** the run (acceptance.sh:79-106), so this is checking the pre-run state, not post-run. If the operator dirties the worktree after the run starts, the gate does not catch it. The `assert_clean_for_production` (acceptance.sh:108-119) runs **before** the run, so the repo-state.json matches the at-start state. OK as designed but the docs could be clearer.

---

## 3. Runbook ↔ script 一致性

| Runbook 步骤 | script 实际行为 | 一致? |
|---|---|---|
| `fiber-morph-devnet-runbook.md:21` — `make fiber-morph-devnet-preflight` creates a run directory with `status=preflight-passed`. | `acceptance.sh:798-806` writes `status=preflight-passed` to the manifest. | OK. |
| `runbook.md:22` — `make fiber-morph-devnet-acceptance` runs Morph stateful + Fiber external funding on the same Fiber CKB node. | `Makefile:87-88` sets `FIBER_MORPH_ACCEPTANCE_MODE=coexistence`. `acceptance.sh:807-812` calls `preflight` → `run_coexistence_gate` → `write_summary`. `run_coexistence_gate` (line 644-655) starts Fiber stack with `FIBER_COEXISTENCE_SUITE=e2e/external-funding-open`, runs Morph stateful, runs Bruno, runs restart regression. | OK. |
| `runbook.md:23` — `make fiber-morph-devnet-acceptance-full` runs coexistence + strict Fiber Bruno suites + funding-tx verification + combined audit. | `Makefile:90-91` sets `FIBER_MORPH_ACCEPTANCE_MODE=full`. `acceptance.sh:820-826` calls coexistence + `run_extended_fiber_suites` (which iterates `FIBER_BRUNO_SUITES` defaulting to 13 suites) + `run_fiber_funding_tx_verification_cases` (defaulting to 4 cases) + `write_summary`. | OK. |
| `runbook.md:65-83` — "Full gate performs these phases" (9 phases: repo-state → Fiber stack → Morph contracts → Morph stateful → external-funding → restart → strict Fiber → funding-tx → summary). | `acceptance.sh:644-655` (coexistence: repo-state already written by preflight, Fiber stack, Morph contracts, Morph stateful, external-funding, restart). `run_extended_fiber_suites` (line 657-669) loops over `FIBER_BRUNO_SUITES` and calls `run_fiber_funding_tx_verification_cases` at the end. | OK in structure. |
| `runbook.md:216-222` — "For a full run, expect: 29 business flows, 20 security families, 19 required Fiber business flows, 9 required Fiber security families, 4 funding-tx verification cases." | `audit.sh:256-363` emits `business_flows` (29 entries in `full` mode: 1 cross-repo + 9 morph + 2 fiber coexistence + 17 fiber extended) and `security_families` (20 entries: 11 morph + 1 fiber coexistence + 8 fiber extended). `minimum_evidence.fiber_required_business_flows: 17 + (coexistence ? 2 : 0) = 19` (line 358). `fiber_funding_tx_verification_cases: 4` (line 360). | OK — counts verified by hand. |
| `runbook.md:280-282` — "Release evidence statement: `summary.json` contains `"status": "passed"` and `"mode": "full"`." | `audit.sh:390` enforces `.status == "passed"` and `.schema == "morph.fiber_morph_devnet_acceptance_summary"`. `mode` is read from the matrix (line 397). | OK. |
| `runbook.md:108-110` — Acceptance: "Manifest `status=passed`, summary `passed`, audit 29 flows + 20 families, Morph `summary-check.json` passes stateful, budget, factory, xUDT, watchtower, negative floors." | The audit script enforces all of these (see Section 2 / `fiber-morph-devnet-audit.sh` analysis). | OK. |
| `runbook.md:155-167` — "Morph security families: 11 P0/P1/P2 names" (state_authority_authenticity, canonical_relative_maturity, state_retirement_non_orphaning, signed_descriptor_evolution, non_interference_not_authorisation, factory_value_delta_binding, typed_asset_binding, sponsor_policy_boundary, watchtower_authority_and_cursor, negative_recovery_continuity, budget_regression). | `audit.sh:196-211` iterates 11 family IDs and `jq` requires each `.audit_families[].id == ... && .passed == true`. | OK. |
| `runbook.md:169-179` — "Fiber security families: 9 names" (fiber_external_funding_persistence, fiber_funding_tx_shape_validation, fiber_cooperative_close_settlement, fiber_force_close_watchtower_settlement, fiber_tlc_error_and_failure_semantics, fiber_routing_graph_and_duplicate_payment_controls, fiber_reconnect_reestablish_recovery, fiber_typed_asset_channel_binding, fiber_periodic_expiry_recovery). | `audit.sh:330-342` lists 9 Fiber security family IDs (1 coexistence + 8 extended). The runbook says "9" but actually only the **8 extended + 1 coexistence = 9 total** if both are present. The runbook lists 9 (one is `fiber_external_funding_persistence` which is the coexistence family). | OK — 9 matches when full + coexistence are both active. **Subtle** — the runbook numbering depends on mode. |
| `runbook.md:38-54` — "Before You Run" expects 4 sibling checkouts: Morph, fiber, ckb, ckb-cli. | `acceptance.sh:787-789` clones if missing, then `prepare_tool_path` (line 171-179) builds ckb + ckb-cli as needed. `fibers_dir` is also cloned. | OK — but there is **no equivalent preflight in `Makefile` / no equivalent in `docs/devnet.md` Quick Start**. The Quick Start in `README.md:174-209` lists `make fiber-morph-devnet-acceptance` but does not mention the 4-sibling layout until the runbook. **W4-05** (low). |
| `runbook.md:255-264` — "Narrow debug runs" examples use `FIBER_MORPH_ACCEPTANCE_MODE=fiber` and `FIBER_BRUNO_SUITES="e2e/router-pay"`. | `acceptance.sh:813-818` handles `fiber` mode (no Morph stateful, but strict Fiber suites). The `FIBER_BRUNO_SUITES` env var is read at line 24 and overrides the default. | OK. |

---

## 4. Budget JSON 字段活跃度

| JSON 路径.字段 | 是否被 script 读 | dead? |
|---|---|---|
| `docs/devnet-smoke-budget.example.json:2` — `description` (top-level) | NOT deserialized. `DevnetSmokeBudgetProfile` (`smoke_report.rs:329-340`) has fields `schema, max_total_cycles, max_tx_cycles, max_total_bytes, max_tx_bytes, transactions, proof_profiles`. | **DEAD** — serde silently drops it. Maintenance hazard. |
| `docs/devnet-smoke-budget.example.json:2` — `schema` | Checked at `smoke_report.rs:481` (`if profile.schema != DEVNET_SMOKE_BUDGET_SCHEMA { return Err(...) }`). | OK. |
| `docs/devnet-smoke-budget.example.json:4-7` — `max_total_cycles, max_tx_cycles, max_total_bytes, max_tx_bytes` | Read at `smoke_report.rs:487-491`, applied at `smoke_report.rs:1627-1658`. | OK. |
| `docs/devnet-smoke-budget.example.json:8-117` — `transactions[].check/path/max_cycles/max_bytes` | Read at `smoke_report.rs:285-291` (struct), applied at `smoke_report.rs:1661-1703`. | OK. |
| `docs/devnet-smoke-budget.example.json:118-245` — `proof_profiles[].check/transaction_path/proof_kind/proof_siblings/max_witness_len/max_cycles/max_bytes` | Read at `smoke_report.rs:303-312`, applied at `smoke_report.rs:1705-1784`. | OK. |
| `docs/devnet-stateful-budget.example.json:2` — `description` (top-level) | NOT deserialized. `DevnetStatefulBudgetProfile` (`stateful_report.rs:206-217`) has the same 7 fields as smoke. | **DEAD**. Same as above. |
| `docs/devnet-stateful-budget.example.json:2` — `schema` | Checked at `stateful_report.rs:305` (`if profile.schema != DEVNET_STATEFUL_BUDGET_SCHEMA { return Err(...) }`). | OK. |
| `docs/devnet-stateful-budget.example.json:8-69` — `transactions[].check/path/max_cycles/max_bytes` | Re-mapped into `DevnetSmokeTransactionBudgetLimit` (same struct) and consumed by the same `assert_smoke_budget`. | OK. |
| `docs/devnet-stateful-budget.example.json:70-116` — `proof_profiles[].*` | Same: re-mapped, consumed. | OK. |
| `docs/devnet-stateful-budget.example.json` — (MISSING) `expected_script_failures[]` array | The closeout (`docs/devnet-stateful-acceptance-closeout.md:98`) claims "Expected script failures: 6" as evidence. The 6 entries live in `crates/morph-cli/src/smoke_report.rs:2208-2239` as a hardcoded `const`. The budget JSON has **no** `expected_script_failures` field, so the budget cannot override it. | **DEAD-CONFIG-AS-CLAIM**: the budget has no failure-list field, but the closeout cites the count as if it were budget-driven. |
| `docs/devnet-audit-profile.example.json:2` — `description` (top-level) | NOT deserialized. `DevnetAuditProfile` (`stateful_report.rs:178-182`) has `schema, families` only. | **DEAD**. |
| `docs/devnet-audit-profile.example.json:2` — `schema` | Checked at `stateful_report.rs:270`. | OK. |
| `docs/devnet-audit-profile.example.json:4-269` — `families[].id` | Read at `stateful_report.rs:186`, used to drive `audit_family_summaries` and as the per-family filter in `verify_morph_stateful`. | OK. |
| `docs/devnet-audit-profile.example.json:6-268` — `families[].severity` | Read at `stateful_report.rs:187`, passed through to `AuditFamilySummary.severity` (line 869), and rendered in markdown. **NOT** used as a gate (no fail if a P0 fails). | OK (read, but cosmetic — does not raise severity at gate-time). |
| `docs/devnet-audit-profile.example.json:8-268` — `families[].principle` | Read at `stateful_report.rs:188`, passed through to `AuditFamilySummary.principle`, rendered in markdown. | OK (read, cosmetic). |
| `docs/devnet-audit-profile.example.json:9-19` — `families[].required_coverage_tags[]` | Read at `stateful_report.rs:190`, evaluated against scenario `coverage` array. Each missing tag is recorded in `AuditFamilySummary.missing_tags`. | OK. |
| `docs/devnet-audit-profile.example.json:12-19` — `families[].required_scenarios[]` | Read at `stateful_report.rs:192`, evaluated against scenario IDs. Missing scenarios recorded in `missing_scenarios`. | OK. |
| `docs/devnet-audit-profile.example.json:16-19` — `families[].required_committed_checks[]` | Read at `stateful_report.rs:194`, evaluated against scenario `required_committed_checks`. Missing checks recorded in `missing_checks`. | OK. |
| `docs/devnet-audit-profile.example.json:36-43` — `families[].required_expected_failures[]` (per-family) | Read at `stateful_report.rs:196`, evaluated against scenario `expected_failures`. Missing failures recorded in `missing_failures`. | OK. |
| `docs/devnet-audit-profile.example.json:6-268` — `families[].description` | NOT in `AuditFamilyProfile` (which has `id, severity, principle, required_coverage_tags, required_scenarios, required_committed_checks, required_expected_failures`). | **NEVER APPEARS IN ANY OF THE 11 FAMILIES** — the JSON has no `description` per family, so this is vacuously dead. If a future family added a `description`, it would be silently dropped. |

---

## 5. Makefile target 可达性

| Target | 依赖 | 是否可达 / 缺什么 |
|---|---|---|
| `ci` (Makefile:13) | `fmt-check lint supply-chain test fixture-checks contract-tests` | Reachable. `test` runs `cargo test --workspace`; `contract-tests` triggers `build-contracts` via internal dep (Makefile:72). W5-10 already flags the implicit `build-contracts` chain — not repeated here. |
| `test` (Makefile:15-16) | `$(CARGO) test --workspace` | Reachable, but **does not run contract_scripts `#[ignore]` tests**. See W5-09. |
| `lint` (Makefile:18-19) | `cargo clippy --workspace --all-targets -- -D warnings` | Reachable. Requires the workspace builds. |
| `fmt` / `fmt-check` (Makefile:21-25) | `cargo fmt --all` / `--check` | Reachable. |
| `audit` (Makefile:27-28) | `$(AUDIT) $(AUDIT_IGNORE)` where `AUDIT ?= cargo audit`, `AUDIT_IGNORE ?= --ignore RUSTSEC-2024-0436 --ignore RUSTSEC-2026-0097` | Reachable; requires `cargo-audit` installed. W5-13 flags the silent ignore. Not repeated. |
| `deny` (Makefile:30-31) | `$(DENY) check` where `DENY ?= cargo deny` | Reachable; requires `cargo-deny`. |
| `supply-chain` (Makefile:33) | `audit deny` | Reachable. |
| `smoke` (Makefile:35-37) | `$(CARGO) test --workspace` + `cargo run -p morph-cli -- validate-fixture` | Reachable. **Does NOT run contract_scripts `#[ignore]` tests** (W5-09). |
| `fixture-checks` (Makefile:39-67) | 17 `print-*-fixture` + 17 `validate-*-package` invocations, all into `target/fixture-checks/` | Reachable. **First time it runs**, all 17 fixtures are written; on subsequent runs they are regenerated. CI-friendly. |
| `build-contracts` (Makefile:69-70) | `cargo build --release --target riscv64imac-unknown-none-elf` for 7 contract crates | Reachable; requires the RISC-V target installed (`check-devnet-env.sh:67-72` verifies). |
| `contract-tests` (Makefile:72-73) | `build-contracts` (dep) + `cargo test -p morph-core --test contract_scripts -- --ignored --test-threads=1` | Reachable. |
| `devnet-smoke` (Makefile:75-76) | `scripts/devnet-smoke.sh` | Reachable. Requires CKB devnet running (or sets up its own — actually the script ASSUMES node is already running because it does not start one; see `devnet-smoke.sh:7` `MORPH_CKB_RPC`). |
| `devnet-e2e` (Makefile:78-79) | `scripts/devnet-e2e.sh` | Reachable. Self-contained (starts its own CKB devnet on `RPC_PORT=18114`). |
| `devnet-stateful-e2e` (Makefile:81-82) | `scripts/devnet-stateful-e2e.sh` | Reachable. Self-contained. |
| `fiber-morph-devnet-preflight` (Makefile:84-85) | `FIBER_MORPH_ACCEPTANCE_MODE=preflight scripts/fiber-morph-devnet-acceptance.sh` | Reachable. Requires `../fiber`, `../ckb`, `../ckb-cli` (or clones them). Requires `node`, `npm` (for Bruno). |
| `fiber-morph-devnet-acceptance` (Makefile:87-88) | `FIBER_MORPH_ACCEPTANCE_MODE=coexistence scripts/fiber-morph-devnet-acceptance.sh` | Reachable. Same deps as preflight + actual Fiber + ckb-cli binaries. **Note: `FIBER_CKB_RPC_URL` default is `http://127.0.0.1:8114`** (`acceptance.sh:17`) — different from `devnet-e2e.sh:10` which uses `18114`. |
| `fiber-morph-devnet-acceptance-full` (Makefile:90-91) | `FIBER_MORPH_ACCEPTANCE_MODE=full scripts/fiber-morph-devnet-acceptance.sh` | Reachable. Same deps + 13 strict Fiber Bruno suites + 4 funding-tx cases. |
| `fiber-morph-devnet-audit` (Makefile:93-98) | `scripts/fiber-morph-devnet-audit.sh` (with optional `FIBER_MORPH_ACCEPTANCE_RUN=...`) | Reachable. Re-audits a previous run dir; no live devnet required. |
| `smoke-report` (Makefile:100-101) | `cargo run -p morph-cli -- devnet-smoke-report` | Reachable. Operates on `target/devnet-smoke/latest` by default (per the `devnet-smoke-report` CLI default). |
| `smoke-assert` (Makefile:103-104) | `cargo run -p morph-cli -- devnet-smoke-assert` | Reachable. No budget profile → loose assertion (only `manifest.status == passed`, transaction floors, business matrix). |
| `smoke-assert-budget` (Makefile:106-107) | `cargo run -p morph-cli -- devnet-smoke-assert --budget-profile docs/devnet-smoke-budget.example.json` | Reachable. With budget profile. |
| `devnet-stateful-report` (Makefile:109-110) | `cargo run -p morph-cli -- devnet-stateful-report --audit-profile docs/devnet-audit-profile.example.json` | Reachable. |
| `devnet-stateful-assert` (Makefile:112-113) | `cargo run -p morph-cli -- devnet-stateful-assert --audit-profile docs/devnet-audit-profile.example.json --budget-profile docs/devnet-stateful-budget.example.json` | Reachable. **Has a default `contracts_dir`** — let me check. |

**Circular dependencies**: none observed — Make uses tab-indented recipe lines correctly; no target depends on itself or on a name that is also a file.

**`.PHONY` coverage**: line 11 lists 22 targets, all of which exist as recipes. OK.

**Makefile target that depends on tools not in repo** (read-only, documented):
- `fiber-morph-devnet-*` targets depend on `node`, `npm`, `npm exec @usebruno/cli@1.20.0`, sibling checkouts of `fiber`/`ckb`/`ckb-cli`, and a CKB binary. None of these are in the repo; `acceptance.sh:780-792` and the `clone_repo_if_missing` helpers are the only path. CI does NOT run these targets (`ci.yml` only runs the workspace Rust targets).
- `check-devnet-env.sh` is not wired into a Makefile target. `README.md:189` tells the user to run it manually.

---

## 6. check-devnet-env.sh 覆盖 README Quick Start 外部依赖

`README.md:174-209` Quick Start mentions these tools/commands the user needs to run:

| README Quick Start reference | `check-devnet-env.sh` actually checks? |
|---|---|
| `make ci` (Rust toolchain) | No — checked indirectly: `check cargo` and `check rustup` (line 54-55) are present. ✓ |
| `cargo test --workspace` | Implicit (via cargo) ✓ |
| `cargo clippy --workspace --all-targets` | Implicit (via cargo + clippy component) — but **clippy component is NOT verified**. `rustup target list --installed` (line 67) does not check `rustup component list --installed`. **W4-06** (low). |
| `make fixture-checks` | Implicit ✓ |
| `make build-contracts` (line 182) | `riscv64imac-unknown-none-elf` target IS checked (line 67-72). ✓ |
| `make contract-tests` | Implicit ✓ |
| `scripts/check-devnet-env.sh` (line 189) | (Self) |
| `cargo run -p morph-cli -- devnet check/mine/open-channel/supersede-smoke/xudt-smoke/factory-*-smoke` (lines 195-203) | Implicit (via cargo) ✓ |
| `make devnet-smoke` | Implicit (no extra tools beyond CKB node). |
| `make devnet-e2e` | Implicit (script auto-builds CKB if `CKB_SOURCE_DIR` is set, but `check-devnet-env.sh` does NOT verify `../ckb` exists or has a `Cargo.toml`). **W4-07** (medium). |
| `make devnet-stateful-e2e` | Same as devnet-e2e. |
| `make fiber-morph-devnet-preflight` (line 207) | **NOT covered** by `check-devnet-env.sh`. Required tools `node`, `npm`, and sibling `fiber`/`ckb-cli` checkouts are NOT checked. `acceptance.sh:780-792` checks them, but the README Quick Start is silent. **W4-08** (medium). |
| `make fiber-morph-devnet-acceptance` (line 208) | Same as above. |

**`docs/devnet.md:40-46`** (the devnet guide) lists exactly 4 tools: Rust+Cargo, RISC-V target, CKB node binary, `jq`. `check-devnet-env.sh` covers all 4. ✓ — but the devnet guide does NOT mention Fiber or ckb-cli. The Quick Start in README mixes both layers; the devnet guide only covers the Morph-only layer.

**`docs/fiber-morph-devnet-runbook.md:46-54`** (the runbook) lists: Rust, Cargo, `jq`, `curl`, `nc`, Node.js, `npm`, CKB + ckb-cli build prerequisites. `check-devnet-env.sh` checks only: `cargo`, `rustup`, `jq`, `ckb`, `riscv64imac-unknown-none-elf`, optionally `ckb-cli`. **Missing**: `curl`, `nc`, `node`, `npm`. The script's `require_tool` checks for these tools exist in the acceptance script (acceptance.sh:780-786) but not in the env-check script. **W4-09** (medium).

---

## 7. CI workflow 一致性 (if applicable)

`.github/workflows/ci.yml` has **one job, 8 steps**:

| Step | Calls | Matches Makefile target? | Reachable? |
|---|---|---|---|
| Checkout | `actions/checkout@v4` | n/a | ✓ |
| Install Rust | `dtolnay/rust-toolchain@1.92.0` + clippy, rustfmt, riscv64imac-unknown-none-elf | n/a | ✓ |
| Cache cargo | `Swatinem/rust-cache@v2` | n/a | ✓ |
| Install supply-chain tools | `cargo install --locked cargo-audit cargo-deny` | n/a | ✓ |
| Check formatting | `make fmt-check` | Yes — Makefile:24-25 | ✓ |
| Run clippy | `make lint` | Yes — Makefile:18-19 | ✓ |
| Run supply-chain checks | `make supply-chain` | Yes — Makefile:33 | ✓ |
| Run workspace tests | `make test` | Yes — Makefile:15-16 | ✓ |
| Run fixture checks | `make fixture-checks` | Yes — Makefile:39-67 | ✓ |
| Run contract tests | `make contract-tests` | Yes — Makefile:72-73 (transitively via build-contracts) | ✓ |

**All CI steps map to existing Makefile targets** — no orphan CI-only invocations. **No CI step runs `make devnet-smoke`, `make devnet-e2e`, `make devnet-stateful-e2e`, or any fiber-morph gate.** This is appropriate (these are environment-heavy and not fit for Ubuntu-latest without a sibling CKB checkout) but means the entire Fiber/Morph acceptance gate is **not exercised by CI at all** — the release evidence depends on a developer running it manually. **W4-10** (low — design choice, but worth noting).

The CI step `Run workspace tests` calls `make test` which does NOT run `#[ignore]` contract_scripts tests (W5-09). The CI step `Run contract tests` does run them (via `make contract-tests`). So the two together cover the union; this is correct CI hygiene.

**Note on `cargo install --locked cargo-audit cargo-deny`**: a long install step. If the cache miss is not handled correctly, the job could time out. The `Swatinem/rust-cache@v2` cache covers cargo registry but not cargo-installed binaries. **W4-11** (low).

---

## Findings

### W4-01 — `audit-response` closeout numbers (155 / 192 / 7) are not gate-enforced; the gate enforces different floors
**Severity**: MEDIUM
**Surface**: `docs/audit-response-2026-06-20.md:26`, `docs/current-devnet-rc-closeout.md:53-66`, `docs/devnet-stateful-acceptance-closeout.md:90-103`
**Confidence**: high
**Claim**: The "release evidence" closeouts cite concrete counts (155 smoke JSONs, 192 committed transactions, 7 deployed scripts, 9 watchtower alerts, 5 reduced exits, 32 splices) as evidence.
**Evidence**: `crates/morph-cli/src/smoke_report.rs:2208-2239` `EXPECTED_SCRIPT_FAILURES` is a hardcoded `const` of 6 entries — the budget JSON has no `expected_script_failures` field. The stateful-assert floors in `scripts/fiber-morph-devnet-audit.sh:160-180` enforce: `.scenario_count >= 9`, `.audit_families >= 11`, `.referenced_artifacts >= 87`, `.required_committed_checks >= 62`, `.expected_failures >= 9`, `.smoke.transaction_count >= 190`, `.smoke.committed_count >= 190`, `.smoke.watchtower_alerts >= 9`, `.smoke.factory_local_exits >= 24`, `.smoke.factory_splices >= 32`, `.smoke.splice_payouts >= 9`, `.smoke.factory_reduced_rights_updates >= 4`, `.smoke.factory_merkle_updates >= 4`, `.smoke.factory_reduced_exits >= 5`. **None of these gates enforces the specific numbers the closeouts cite** (155 JSONs, 7 deployed scripts, 9 watchtower alerts floor is enforced, 5 reduced-exits floor is enforced, 32 splices floor is enforced, 190 transactions floor is enforced — but the closeout cites 192, not 190).
**Impact**: A future run that produces 191 transactions, 9 watchtower alerts, and 5 reduced exits **passes** every gate, but does not match the specific numerical evidence in the closeouts. The closeout's "192 committed transactions" is a snapshot, not a gate.
**Suggested fix**: Either (a) bump the gate floors to match the closeout numbers and call them out as release floors, or (b) add a note in each closeout that the numbers are evidence-of-run, not a release-gate contract.

### W4-02 — `fiber-morph-devnet-acceptance.sh` runs `devnet-stateful-scenarios.sh` WITHOUT audit-profile or budget-profile; only `devnet-stateful-e2e.sh` adds them
**Severity**: HIGH
**Surface**: `scripts/fiber-morph-devnet-acceptance.sh:607-623` (`run_morph_stateful_on_fiber_ckb`)
**Confidence**: high
**Claim**: The Fiber/Morph coexistence gate's Morph stateful run uses a less strict assertion than the standalone stateful e2e.
**Evidence**: `run_morph_stateful_on_fiber_ckb` (lines 607-623) sets `MORPH_CKB_RPC, CKB_BIN, CKB_SOURCE_DIR, OUT_DIR, LATEST_LINK, MORPH_DEVNET_SMOKE_SKIP_LOCAL_CHECKS=1` and invokes `scripts/devnet-stateful-scenarios.sh`. Compare with `scripts/devnet-stateful-e2e.sh:177-182` which sets the same env + then calls `cargo run ... devnet-stateful-assert --dir ... --audit-profile ... --budget-profile ...`. The acceptance-script invocation relies on the **inner** `devnet-stateful-scenarios.sh:181` line to call `devnet-stateful-assert`, but that inner call does **not** pass `--audit-profile` or `--budget-profile`. So the `summary-check.json` written by the Fiber/Morph run is a **loose** stateful-assertion, and the outer audit (`fiber-morph-devnet-audit.sh:160-180`) then enforces the strict floors against that loose file. The loose assertion does include audit-family evaluation, but the budget-profile is missing. Note: `verify_morph_stateful` reads `summary_check` for the floors, and the floors include the budget-relevant counters (factory splices, watchtower alerts, etc.) but **does not** assert that the budget profile was applied. So a budget failure would not show up at the acceptance gate.
**Impact**: The Fiber/Morph "full" run can pass with a budget-rejected stateful run as long as the shape counters meet the floor. This weakens the runbook's "Morph `summary-check.json` passes … budget floors" claim.
**Suggested fix**: In `run_morph_stateful_on_fiber_ckb`, also pass `--audit-profile docs/devnet-audit-profile.example.json --budget-profile docs/devnet-stateful-budget.example.json` to the inner `devnet-stateful-scenarios.sh` invocation, OR refactor `devnet-stateful-scenarios.sh` to read these from env so they propagate.

### W4-03 — `description` field in all 3 example JSON files is dead (serde silently drops it)
**Severity**: LOW
**Surface**: `docs/devnet-smoke-budget.example.json:2`, `docs/devnet-stateful-budget.example.json:2`, `docs/devnet-audit-profile.example.json:2`
**Confidence**: high
**Claim**: Each example profile has a top-level `description` string; the consuming Rust structs do not deserialize it.
**Evidence**: `DevnetSmokeBudgetProfile` (`crates/morph-cli/src/smoke_report.rs:329-340`) has fields `schema, max_total_cycles, max_tx_cycles, max_total_bytes, max_tx_bytes, transactions, proof_profiles` — no `description`. `DevnetStatefulBudgetProfile` (`crates/morph-cli/src/stateful_report.rs:206-217`) is the same shape. `DevnetAuditProfile` (`stateful_report.rs:178-182`) has `schema, families` only. Serde silently drops `description`. The same applies to any `families[].description` field — not in `AuditFamilyProfile` (line 184-197) either. (Currently no family in the JSON has `description`, so this is vacuously dead today.)
**Impact**: Future maintainers reading the example will think the `description` field is a meaningful knob, add a description to a new family, and have it silently ignored. Documentation drift.
**Suggested fix**: Either (a) remove `description` from the example files, or (b) add `pub description: String` to the structs and thread it through to the markdown report (since the schema is meant as a "evidence taxonomy label" per the description itself).

### W4-04 — `devnet-e2e.sh` and `devnet-stateful-e2e.sh` are ~95% duplicate; a fix to one will not propagate
**Severity**: MEDIUM
**Surface**: `scripts/devnet-e2e.sh:1-199` vs `scripts/devnet-stateful-e2e.sh:1-199`
**Confidence**: high
**Claim**: The two e2e wrappers are near-identical, both ~199 lines, differing only in inner script + assert command.
**Evidence**: Side-by-side comparison shows identical: ROOT_DIR resolution, env defaults, CKB resolve, port checks, manifest layout, build-contracts step, node startup, trap, log dir, latest-link logic. The only meaningful differences are: line 168-175 (`devnet-e2e.sh` calls `scripts/devnet-smoke.sh`; `devnet-stateful-e2e.sh` calls `scripts/devnet-stateful-scenarios.sh`) and line 178-182 (`devnet-e2e.sh` calls `devnet-smoke-assert` with budget; `devnet-stateful-e2e.sh` calls `devnet-stateful-assert` with audit + budget). Everything else is byte-identical.
**Impact**: When `fa8cd68` ("Retry busy Fiber acceptance ports") and `22474b1` ("Retry Fiber stack startup in acceptance harness") landed, the `devnet-*.sh` family did not get the same retry-loop / port-recovery hardening. If a future harden (e.g., `wait_for_rpc` retryable HTTP statuses from `c59a677`) lands in one, it must be mirrored in the other; otherwise the two wrappers will drift.
**Suggested fix**: Extract the common parts into a sourced `scripts/lib-devnet-e2e-common.sh` and have both wrappers source it. Or refactor to a single `scripts/devnet-e2e.sh <mode>` with `<mode> ∈ {smoke, stateful}`.

### W4-05 — README Quick Start does not document the Fiber/Morph sibling-checkout layout; runbook does
**Severity**: LOW
**Surface**: `README.md:174-209` Quick Start
**Confidence**: high
**Claim**: README Quick Start lists `make fiber-morph-devnet-preflight` and `make fiber-morph-devnet-acceptance` without explaining that four sibling repositories (Morph, fiber, ckb, ckb-cli) must exist under a common parent. The runbook (`docs/fiber-morph-devnet-runbook.md:31-44`) documents the layout; README does not.
**Impact**: A new operator following README Quick Start will run `make fiber-morph-devnet-acceptance` and have the script `git clone` fiber/ckb/ckb-cli automatically. This works, but (a) the auto-clone checks out `main` of upstream, not the version this repo was tested against, and (b) the run is not reproducible across operators.
**Suggested fix**: Add a one-paragraph "Sibling checkouts" note in the README Quick Start with the layout from the runbook.

### W4-06 — `check-devnet-env.sh` does not verify `clippy` or `rustfmt` rustup components
**Severity**: LOW
**Surface**: `scripts/check-devnet-env.sh:67-72`
**Confidence**: high
**Claim**: The script verifies the RISC-V target with `rustup target list --installed | grep '^riscv64imac-unknown-none-elf$'`. It does not verify the `clippy` and `rustfmt` components, which `make lint` (`cargo clippy`) and `make fmt-check` (`cargo fmt --check`) need.
**Evidence**: `check-devnet-env.sh:67-72` only checks the riscv target. There is no `rustup component list --installed | grep -E '^(clippy|rustfmt)'`.
**Impact**: If a user has a Rust toolchain without `clippy` or `rustfmt`, `make lint` or `make fmt-check` will fail with a confusing toolchain error instead of a clear "missing component" message.
**Suggested fix**: Add `rustup component list --installed` checks for `clippy` and `rustfmt` (or rely on `cargo` invocation failing clearly).

### W4-07 — `check-devnet-env.sh` does not verify the CKB source tree (`../ckb`) exists with a `Cargo.toml`
**Severity**: MEDIUM
**Surface**: `scripts/check-devnet-env.sh:32-52` (`resolve_ckb_bin`)
**Confidence**: high
**Claim**: The script checks for a CKB binary via `CKB_BIN` env, `PATH`, or a built binary in `$CKB_SOURCE_DIR/target/{release,debug}/ckb`. If none exist, the function returns empty and the script continues — the "no ckb binary" case is **not** a hard fail.
**Evidence**: `resolve_ckb_bin` (line 32-52) returns empty if no source build exists; the caller `check_bin ckb "$CKB_BIN"` (line 59) only fails if `CKB_BIN` is also empty. The exit-1 message at line 74-85 is triggered only by the `missing=1` flag, which the function never sets. So **for an operator with no CKB binary at all, the script exits 0** unless they have explicitly set `CKB_BIN` and the file is not executable.
**Impact**: The script's name "check-devnet-env" promises to fail-fast if the environment is not ready, but it does not catch the most common devnet failure mode (no CKB binary anywhere on the system). `devnet-e2e.sh:41-70` does its own resolution and DOES fail hard — but the devnet-e2e flow is what the operator wants to avoid running blindly. Compare with `devnet-e2e.sh:58-69` and `devnet-stateful-e2e.sh:58-69` which both correctly `fail` with a clear message. `acceptance.sh:139-143` also fails hard. So the env-check script's soft behavior is at odds with the actual scripts.
**Suggested fix**: In `check-devnet-env.sh`, after `CKB_BIN="$(resolve_ckb_bin)"`, if the value is empty, set `missing=1` and emit `missing: ckb (no CKB_BIN, ckb on PATH, or ../ckb/target/{release,debug}/ckb)`.

### W4-08 — `check-devnet-env.sh` does not verify Fiber/Morph acceptance prerequisites (`node`, `npm`, sibling `fiber`/`ckb-cli` checkouts)
**Severity**: MEDIUM
**Surface**: `scripts/check-devnet-env.sh` (the whole file, 86 lines)
**Confidence**: high
**Claim**: The runbook's "Before You Run" section requires `node`, `npm`, `curl`, `nc`, and sibling checkouts of `fiber` and `ckb-cli` for the Fiber/Morph gate. The env-check script does not check any of these.
**Evidence**: `check-devnet-env.sh:54-72` only checks `cargo`, `rustup`, `jq`, `ckb` (or `CKB_BIN`), `ckb-cli` (optional), and the RISC-V target. `node`, `npm`, `curl`, `nc`, `fiber` checkout, `ckb-cli` checkout are not mentioned. `acceptance.sh:780-792` does check them — but the env-check script is what the README Quick Start points to as the single env verifier.
**Impact**: An operator who runs only `check-devnet-env.sh` and sees "ok" for all 4 tools will then run `make fiber-morph-devnet-acceptance` and hit a confusing `clone_repo_if_missing: cloning missing dependency: https://github.com/nervosnetwork/fiber.git` (acceptance.sh:69-71) — which auto-clones upstream HEAD, not the tested commit. This silently changes which Fiber version is being tested.
**Suggested fix**: Add a `if [ "$1" = "--fiber" ] || [ -d ../fiber ]` mode (or always, behind a fast check) to verify `node`, `npm`, `curl`, `nc`, and the presence of `../fiber` + `../ckb-cli` (without cloning, so the user can pin versions).

### W4-09 — `check-devnet-env.sh` lists optional `ckb-cli` but does not warn when the Fiber/Morph gate will need it
**Severity**: MEDIUM
**Surface**: `scripts/check-devnet-env.sh:61-65`
**Confidence**: high
**Claim**: The script treats `ckb-cli` as "optional" but the Fiber/Morph acceptance gate requires it (`acceptance.sh:146-169` builds or resolves it as a hard prerequisite).
**Evidence**: `check-devnet-env.sh:61-65` prints `optional missing: ckb-cli` and continues. `acceptance.sh:164-168` `fail`s if ckb-cli cannot be resolved. The script also has `missing=1` only set for the hard-required tools, not for ckb-cli.
**Impact**: An operator who has no ckb-cli, runs `check-devnet-env.sh`, sees "optional missing", and proceeds to `make fiber-morph-devnet-acceptance`, will hit a hard `fail` deep in the acceptance run — the run is wasted.
**Suggested fix**: Promote ckb-cli to "required" if `FIBER_MORPH_ACCEPTANCE_MODE` is set in env, OR add a separate `scripts/check-fiber-morph-env.sh` that does the full Fiber/Morph prerequisite check.

### W4-10 — Fiber/Morph acceptance gate is not exercised by CI at all; the entire release evidence depends on manual runs
**Severity**: MEDIUM
**Surface**: `.github/workflows/ci.yml` (52 lines, single job `rust`)
**Confidence**: high
**Claim**: The repo has a "full release evidence" gate (`make fiber-morph-devnet-acceptance-full`) that produces `business-flow-audit.json` with 29 business flows and 20 security families. CI never runs it.
**Evidence**: `ci.yml` runs `make fmt-check`, `make lint`, `make supply-chain`, `make test`, `make fixture-checks`, `make contract-tests`. None of `make devnet-smoke`, `make devnet-e2e`, `make devnet-stateful-e2e`, or any `fiber-morph-devnet-*` target appears. The runbook (line 273-289) declares the release evidence is acceptable only when `make fiber-morph-devnet-acceptance-full` exits successfully — but this is not in CI.
**Impact**: The release gate described in the runbook is purely advisory. A green CI badge does not imply the release gate has been executed. A developer could merge a change that breaks the Fiber external-funding flow and CI would still be green.
**Suggested fix**: Add a `fiber-morph-devnet-acceptance` job to CI that runs the preflight + coexistence modes (skipping `full` because it's too slow for PR feedback). This requires the CI runner to have `node`, `npm`, sibling checkouts of `fiber`/`ckb`/`ckb-cli`, and a CKB binary. If the CI environment cannot provide these, gate this on a manual `workflow_dispatch` trigger with a documented pre-step.

### W4-11 — `ci.yml` `cargo install --locked cargo-audit cargo-deny` is uncached; a cache miss can time out
**Severity**: LOW
**Surface**: `.github/workflows/ci.yml:33-34`
**Confidence**: medium
**Claim**: The supply-chain-tools install step builds from source each CI run unless cargo's install cache is preserved. `Swatinem/rust-cache@v2` does not include the cargo bin directory by default.
**Evidence**: `ci.yml:31` uses `Swatinem/rust-cache@v2` (which caches `target/` and `~/.cargo/registry/` by default). Line 33-34 then `cargo install --locked cargo-audit cargo-deny` to `~/.cargo/bin/`. The `rust-cache` action does NOT cache `~/.cargo/bin/`. Each CI run with a cache miss for the toolchain install will compile these crates from source.
**Impact**: On a cold cache, the install step can take 5-10 minutes. GitHub-hosted `ubuntu-latest` jobs default to a 6-hour timeout, so this is not a hard failure — but slow. The closer impact is correctness: `cargo-audit` and `cargo-deny` versions drift with each install.
**Suggested fix**: Either (a) add a `~/.cargo/bin` cache step, or (b) pin to specific cargo-audit / cargo-deny versions in the install command.

### W4-12 — `devnet-smoke.sh` runs 50+ `cargo run` invocations inline with no per-step timeout; a hung cargo hangs the whole smoke
**Severity**: MEDIUM
**Surface**: `scripts/devnet-smoke.sh:67-79, 84-130, 168-294, 296-396, 398-519, 521-573, 575-644`
**Confidence**: high
**Claim**: Every `run_json` (line 39-45) and `log` call (line 31-37) runs `cargo run -q -p morph-cli -- ...` with no `timeout` wrapper. A hung `cargo` (e.g., a stuck CKB RPC call inside the CLI) will hang the entire 668-line script.
**Evidence**: `run_json` (line 39-45) is `cargo run -q -p morph-cli -- "$@" --json >"$path"`. No `timeout`, no `&` (no background), no `kill` on cumulative duration. `set -euo pipefail` will exit on the first non-zero, but a hung process returns no exit code at all.
**Impact**: A single hung `cargo run` (e.g., a CKB RPC that doesn't return, a watchtower cursor that never reaches `stop-after-publication`) blocks the full smoke for the duration of the runner's wall-clock. The artefacts from earlier steps are present, but `status=passed` is never written to the manifest, so the closeout is "stale".
**Suggested fix**: Wrap each `run_json` and `run_log` in a `timeout 600 ...` (or use a per-step watchdog). For the watchtower config-loop (`scripts/devnet-smoke.sh:561-567`) the `--passes 2` is bounded, but the `--sleep-ms 100` could still stall if `--auto-fund-sponsor` reaches a network loop.

---

## Cross-cutting

- **Gate-claim-without-command check**: every claim in `audit-matrix.md`, `audit-response-2026-06-20.md`, `fiber-morph-devnet-runbook.md`, and the two closeouts is wired to a real executable surface (a `cargo test`, a `cargo run` CLI, a `make` target, or a `scripts/*.sh` invocation). The only quantitative claims that are not gate-enforced are the specific snapshot numbers in the closeouts (W4-01). The acceptance gate (29 flows, 20 families, 9 scenarios, 11 audit families) IS gate-enforced via `jq_check` calls in `fiber-morph-devnet-audit.sh:160-211`.

- **README/Quick Start ↔ Makefile ↔ scripts coverage**: every `make` target in the Makefile that does NOT depend on Fiber is self-contained. The Fiber-dependent targets are correctly documented only in the runbook, not in README (W4-05).

- **Hardening-commit reception**: `git log --oneline | grep -E "Harden|Retry|Tighten"` shows ~7 commits in the hardening wave. Most landed in `fiber-morph-devnet-acceptance.sh` and `fiber-morph-devnet-audit.sh`. The `devnet-*.sh` wrappers did not receive the same wave (W4-04).

- **CI coverage**: CI runs the Rust workspace + supply-chain + fixture-checks + contract-tests (8 CI steps). It does NOT run any `devnet-*` or `fiber-morph-devnet-*` target (W4-10). For a release, the only guarantee CI provides is "the workspace builds, lints, and unit-tests pass"; the substantive release gate is manual.

- **Cross-audit citation**: this W4 audit cites W5-09/10/11/13 by reference only; it does not re-derive their findings.

---

## Files reviewed

- `Makefile` (113 lines)
- `scripts/check-devnet-env.sh` (86 lines)
- `scripts/devnet-e2e.sh` (199 lines)
- `scripts/devnet-node.sh` (72 lines)
- `scripts/devnet-smoke.sh` (668 lines)
- `scripts/devnet-stateful-e2e.sh` (199 lines)
- `scripts/devnet-stateful-scenarios.sh` (193 lines)
- `scripts/fiber-morph-devnet-acceptance.sh` (830 lines)
- `scripts/fiber-morph-devnet-audit.sh` (520 lines)
- `.github/workflows/ci.yml` (52 lines)
- `docs/devnet.md` (355 lines)
- `docs/fiber-morph-devnet-acceptance.md` (273 lines)
- `docs/fiber-morph-devnet-runbook.md` (290 lines)
- `docs/audit-matrix.md` (191 lines)
- `docs/audit-response-2026-06-20.md` (614 lines)
- `docs/devnet-stateful-acceptance-closeout.md` (147 lines)
- `docs/current-devnet-rc-closeout.md` (141 lines)
- `docs/devnet-smoke-budget.example.json` (246 lines)
- `docs/devnet-stateful-budget.example.json` (117 lines)
- `docs/devnet-audit-profile.example.json` (271 lines)
- `README.md` (304 lines, for Quick Start coverage analysis)
- `crates/morph-cli/src/smoke_report.rs` (selective read: budget/profile struct, budget assertion, expected-failures const, business-matrix const)
- `crates/morph-cli/src/stateful_report.rs` (selective read: audit/budget profile struct, summary)
- `crates/morph-cli/src/main.rs` (selective read: command wiring for assert/report/compare)
- `docs/swarm-audit-tests.md` (cite-only, lines 330-497 for W5-09/10/11/13)
- `git log --oneline -30` (for hardening-commit reception analysis)
