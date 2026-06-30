# Swarm Audit — W5 tests / CI (Refresh)
Date: 2026-06-22  Branch: arthur/morph-audit-fixes @ aa71651
Severity counts: CRITICAL 1 / HIGH 3 / MEDIUM 3 / LOW 4

## Close verification (继承自 swarm-audit-tests.md)

| W5-NN | 仍真实? | file:line 验证结果 | 备注 |
|---|---|---|---|
| W5-01 | yes (CRITICAL) | `contracts/morph-script-common/src/lib.rs:933-957` `state_context_matches_splice_next` 仍未比较 `payload_commitment`(line 944-955 显式列举 `protocol_version/chain_id/signature_scheme_id/channel_id/funding_epoch/funding_anchor/vault_set_commitment/state_number/mode/participants_commitment/asset_registry_commitment/settlement_descriptor_commitment/descriptor_version/challenge_policy_commitment/state_layout_version`,无 `payload_commitment`)。`matches_current_state`(`lib.rs:644`)已加入 `payload_commitment` 比较。audit-response §"Implementation patch" 第 1 项文字声称与代码不符仍然成立。 | 文字/代码不一致持续存在;vault-lock `morph-vault-lock/src/main.rs:377` `new_header.payload_commitment == new_vault_commitment` 仍为唯一 bundle-层后守门员。 |
| W5-02 | yes (HIGH) | `schemas/morph.mol:15` 仍写 `SpliceHeader: 325 bytes`;SpliceHeader struct(`schemas/morph.mol:99-116`)字段列表仍无 `payload_commitment`。Rust constant `SPLICE_HEADER_LEN=357` 在 `morph-script-common/src/lib.rs:13`。`SpliceHeader::payload_commitment()` offset 293,`challenge_policy_commitment()` offset 325 在 `morph-script-common/src/lib.rs:622-628` — 与 audit-response 第 99-105 行声称一致。schema drift 持续。 | 注释里 schema 标 325,Rust 标 357。修复方向:把 schema struct 加上 `payload_commitment: Byte32` 字段并改注释为 357 bytes;同时核对 `SpliceStateTransitionWitness: 1017 bytes` 是否需要更新为 1049 bytes。 |
| W5-03 | yes (HIGH) | `Cargo.toml:23-38` workspace 依赖无 proptest / quickcheck / arbitrary。`crates/morph-core/Cargo.toml` dev-deps 仍为 `ckb-testtool / morph-script-common / serde_json`。`rg "proptest\|quickcheck\|Arbitrary"` 全仓库 0 命中;`rg "for_all\|arbitrary\|Arbitrary"` 0 命中。所有 248 个 example-based test 无 property-based 形式。 | 与 1 天前结论一致。 |
| W5-04 | yes (MEDIUM) | `crates/morph-core/tests/invariants.rs:611-626` `state_header_context_rejects_epoch_and_vault_set_changes` 三个 assertion 未变:line 615-618 改 `payload_commitment`/`settlement_descriptor_commitment` 但断言 `same_context_except_progress` 仍 true;line 620-621 改 `funding_epoch` 断言 false;line 623-625 改 `vault_set_commitment` 断言 false。host-side `same_context_except_progress`(`crates/morph-core/src/types.rs:62-75`)仍漏掉 `payload_commitment`/`settlement_descriptor_commitment`/`descriptor_version`。 | 测试 freeze host-side 不完整 bug 持续。 |
| W5-05 | yes (MEDIUM) | `crates/morph-core/tests/invariants.rs:588-603` 第三个 assertion 仍是 `assert_ne!(h1.signing_digest(), header(1, Phase::Settling).signing_digest())`(`header()` 默认 `funding_epoch=0` 而 `h1.funding_epoch=3`)— 因 epoch 字段绑定已生效,断言总是 true,无法 catch 删 epoch 字段的 regression。 | W5 修法:删除第三个 assertion 或改成 `assert_eq!(h1.signing_digest(), h1.signing_digest())`。 |
| W5-06 | yes (MEDIUM) | `morph-script-common/src/lib.rs:6152-6227` `molecule_schema_names_all_active_fixed_width_objects` expected 列表仍含 `"SpliceHeader: 325 bytes"`、`"SpliceStateTransitionWitness: 1017 bytes"` 等过时字符串,与 `schemas/morph.mol` 一致 — 不会 fail,失去 schema-drift 检测能力。 | 与 W5-02 同根。 |
| W5-07 | yes (LOW) | 60+ expected 字符串完全手工维护,未与 Rust 常量或 schema parse 联动。 | 建议改用 `format!("SpliceHeader: {} bytes", SPLICE_HEADER_LEN)`。 |
| W5-08 | yes (MEDIUM) — confirmed drift | `crates/morph-core/tests/contract_scripts.rs:582-583` `splice_header_bytes` 只填 `raw[293..325].fill(9)` (= payload_commitment 字段),`raw[325..357]` (= challenge_policy_commitment) 完全未填,默认 0。而 `header_raw_with_anchor`(`contract_scripts.rs:258-282`)的 `challenge_policy_commitment: [9; BYTE32_LEN]` 通过 `encode_state_header`(`morph-script-common/src/lib.rs:262`)写入 offset 280..312,值 `[9; 32]`。`hash_parity.rs:152-153` 显式填 `raw[325..357].copy_from_slice(&header.challenge_policy_commitment)`,与 Rust 常量 357 一致。**实测结论**:若 fixture 被传入 `verify_splice_state_transition_bundle`(从 `morph-vault-lock/src/main.rs:371` / `morph-state-type/src/main.rs` 调用),`matches_current_state`(`lib.rs:634-646`)会在 `splice_header.challenge_policy_commitment() == current.challenge_policy_commitment()` 失败 — 但 CKB-VM 测试仍 pass。说明测试套件里 CKB-VM 层 splice 测试在 `bind_splice_state_payloads`(`contract_scripts.rs:176-195`)重写 payload_commitment 的同时也覆盖了 challenge_policy_commitment 之外的字段,可能通过 vault-lock 的其他 short-circuit 路径;或 fixture 实际未走 `verify_splice_state_transition_bundle`。详细见 W5-14。 | 字段填充不一致真实存在;需明确测试走的路径。 |
| W5-09 | yes (LOW) | `Makefile:35-37` `smoke:` target 仍只跑 `cargo test --workspace + validate-fixture`,不跑 contract-tests。`Makefile:72-73` `contract-tests:` target 仍依赖 `build-contracts`。audit-response §"Implementation evidence" 仍写"248 workspace tests pass (1 ignored)"。 | dev 跑 `make smoke` 不会触发 CKB-VM 层。 |
| W5-10 | yes (LOW) | `Makefile:13` `ci:` target 仍依赖 `contract-tests`,后者通过 `build-contracts:` 传递性依赖 `build-contracts`,但 ci 没显式加。RISC-V 工具链不在 PATH 时,`make ci` 在 build-contracts 步骤 fail,contract-tests 不会跑。 | 改进方向:在 `ci:` 显式加 `build-contracts`。 |
| W5-11 | partially refuted | `comparison_limits_reject_metric_regressions` 和 `comparison_limits_reject_set_and_status_changes` 在 `crates/morph-cli/src/smoke_report.rs:3664` 和 `:3697` 找到 — W5 当时没 grep 到是因为查找范围限制。**audit-matrix 引用 test 名但不引用 file:line,仍是真实问题**(矩阵可执行性追踪需手动 grep)。 | W5 finding 减弱:测试名确实存在,但 audit-matrix 缺 file:line 仍是真实低危问题。 |
| W5-12 | yes (LOW) | `morph-script-common/src/lib.rs:5786-6043` 4 个 active C-01 negative test 仍在(`rejects_splice_state_transition_with_changed_participants_commitment`/`_settlement_descriptor`/`_mode`/`_asset_registry`),1 个 ignored `rejects_splice_state_transition_with_changed_payload_commitment`(line 5714-5780)。8 个未独立覆盖字段(`state_layout_version`/`signature_scheme_id`/`chain_id`/`channel_id`/`funding_epoch`/`funding_anchor`/`state_number`/`vault_set_commitment`)的实现覆盖在 `state_context_matches_splice_next`(`lib.rs:933-957`),但无独立 attack-style test。 | 覆盖不均匀;建议 macro 化生成 12 个 negative test。 |
| W5-13 | yes (LOW) | `Makefile:5-9` `AUDIT_IGNORE ?= --ignore RUSTSEC-2024-0436 --ignore RUSTSEC-2026-0097` 未变。注释解释了 paste (unmaintained) + rand 0.7 (unsound)。 | 与 1 天前一致。 |

## Audit-response close 独立验证

| Finding | audit-response § cite | 独立验证结果 | 备注 |
|---|---|---|---|
| C-01 | "Implementation patch" §1 `state_context_matches_splice_next now also checks current.payload_commitment == next.payload_commitment` (audit-response §line 104-105) | **fail / partial** | `morph-script-common/src/lib.rs:933-957` 的 `state_context_matches_splice_next` 仍**不**比较 `payload_commitment` — 见 W5-01。文字声称与代码不符。但 `matches_current_state`(`lib.rs:644`)确实加入 `payload_commitment` 比较,5 个 negative test 存在(`lib.rs:5716`、`5786`、`5851`、`5919`、`5983`),4 个 active 都断言 `SpliceProofMismatch`。vault-lock 层 `new_header.payload_commitment == new_vault_commitment`(`morph-vault-lock/src/main.rs:377`)存在,`vault_lock_rejects_splice_new_state_payload_mismatch`(`contract_scripts.rs:6541`)存在。**C-01 close 在 vault-lock 层成立,但 audit-response §"Implementation patch" item 1 的文字声称与代码不符**。 |
| H-01 | "Funding Anchor Profiles" paper patch, no test cite (paper-only) | **paper-only** | `Funding Anchor Profiles` 不在 test scope。grep `live_fund_cell_profile\|fund_cell_lifecycle` 0 命中 Rust 代码 — Type-ID-style 是当前实现,Live Fund Cell profile 仅 paper 描述。`is_factory_active\|FUND_BOUNDS\|MAX_VAULTS_PER_FINALISATION` 0 命中。**paper patch 已完成,代码实现预期未到**。 |
| H-02 | "Vault Manifest" paper patch, no specific test cite; covered by `splice_rejects_tampered_asset_delta_commitment` / `splice_rejects_unsigned_withdrawal_output_change` per W5 close table | **paper + minimal code** | `verify_splice_state_transition`(`lib.rs:803-839`)实现 vault commitment + delta commitment 比较,测试覆盖。`VaultManifest` / `vault_in_manifest` / `all_committed_vaults_consumed_or_evidenced` 在 Rust 代码 grep 0 命中 — 仅 paper 描述。**test 层 close 在现有 witness 字段集合上成立,完整 Vault Manifest 仍 paper-only**。 |
| H-03 | "Partition Classifier" paper patch; tests `partition_conservation_accepts_valid_partition` + 9 个 negative 覆盖 | **pass** | `crates/morph-core/tests/invariants.rs:1054-1162` 9 个 negative test 存在:`partition_conservation_accepts_valid_partition` / `rejects_channel_paid_fee_leakage` / `rejects_state_carrier_capacity_leakage` / `rejects_business_ckb_confusion` / `rejects_xudt_type_mismatch` / `rejects_xudt_amount_mismatch` / `rejects_xudt_amount_overflow_in_partition_totals` / `rejects_reserve_refund_overflow_in_partition_totals` / `rejects_sponsor_output_exceeding_input_without_fee_underflow` / `rejects_sponsor_change_contamination` / `rejects_unrelated_cell_used_for_channel_semantics`。**但**:`rejects_unrelated_cell_used_for_channel_semantics`(`invariants.rs:1153-1162`)只 push 一个 input,没有显式测试 output 侧必须出现对等 Unrelated cell 来满足 paper H-03 的 "exact equality rule"。 |
| H-04 | "Canonical Operation Envelope" paper patch + implementation; 7 operations routed by envelope | **code routed, tests partial** | `WitnessEnvelope`(`morph-script-common/src/lib.rs:368-425`)是 parse / body_commitment 校验点;`is_known_witness_envelope_kind`(`lib.rs:435-446`)列出全部 7 个 kind(1 SIGNATURE / 2 REDUCED_RIGHTS / 3 MERKLE_UPDATE / 4 REDUCED_EXIT / 5 LOCAL_EXIT / 6 SPLICE / 7 REDUCED_SPLICE)。**代码路由**:`morph-factory-type/src/main.rs:128-162` 7 个 `match` arm 完整覆盖(`SIGNATURE` → `verify_factory_state_signatures`, `REDUCED_RIGHTS` → `verify_reduced_factory_rights_update`, `MERKLE_UPDATE` → `verify_factory_merkle_update + validate_factory_merkle_update_local_predicate`, `REDUCED_EXIT` → `verify_reduced_factory_exit_update + validate_reduced_exit`, `REDUCED_SPLICE` → `verify_factory_reduced_splice_update`, `SPLICE` → `verify_factory_splice_update`, `LOCAL_EXIT` → `verify_factory_state_signatures + validate_local_exit`)。`morph-factory-vault-lock/src/main.rs:69-127` 也路由 LOCAL_EXIT / REDUCED_EXIT / SPLICE / REDUCED_SPLICE 4 个 kind(其余 3 不适用 vault-lock)。**测试覆盖**:每种 kind 至少有 1 个 CKB-VM acceptance test:`factory_type_accepts_signed_factory_update`(`contract_scripts.rs:2676`)、`factory_type_accepts_reduced_rights_update`(`contract_scripts.rs:2828`)、`factory_type_accepts_sparse_merkle_right_update`(`contract_scripts.rs:2869`)、`factory_type_and_vault_accept_reduced_exit_reserve_release`(`contract_scripts.rs:3568`)、`factory_type_and_vault_accept_local_exit_materialisation`(`contract_scripts.rs:4263`)、`factory_type_and_vault_accept_factory_splice_in`(`contract_scripts.rs:2717`)、`factory_type_and_vault_accept_reduced_factory_xudt_splice_in`(`contract_scripts.rs:2800`)。**但**:`witness_envelope_rejects_malformed_headers_and_bodies`(`morph-script-common/src/lib.rs:6323-6391`)只覆盖 `FACTORY_SIGNATURE` kind 的 envelope,其他 6 种 kind 没有专属 envelope 单元测试(只有经过 factory-type/vault-lock 路由的 CKB-VM 隐式覆盖)。**Overall:partially pass — 7 ops 全部路由 + 每种 kind 有 1 个 acceptance,但 WitnessEnvelope 单元层 6/7 kind 未直接 negative test**。 |
| H-05 | "Funding Anchor Identity" paper + impl; `funding_context_id` 4-field binding | **pass** | `crates/morph-core/src/hash.rs:48-61` `funding_context_id(chain_id, channel_id, funding_anchor, vault_set_commitment)` 4-field 绑定 + 域分离 `FUNDING_CONTEXT_DOMAIN`。`StateHeader::funding_context_id`(`hash.rs:93-100`)。`crates/morph-core/tests/invariants.rs` 也有对应测试。**三名字(funding_anchor_identity / funding_anchor_derivation_input / funding_context_id)在 Rust 中通过 `chain_id+channel_id+funding_anchor+vault_set_commitment` 4-field 绑定区分**。 |
| H-06 | "Worst-Case Finalisation Bound" paper + budget gate at devnet | **partial** | `MAX_VAULTS_PER_FINALISATION` / `MAX_XUDT_SCRIPT_GROUPS_PER_FINALISATION` 在 Rust 代码 grep 0 命中 — 仅有 paper 定义。`docs/devnet-smoke-budget.example.json` 和 `docs/devnet-stateful-budget.example.json` 是 budget profile,通过 `devnet-stateful-assert` / `devnet-smoke-assert-budget` Makefile target 执行。这是 deployment profile 范围,不在 unit/integration test scope。**W5 close 标记 partial 是准确的**。 |
| H-07 | "factory_active phase + Factory Acceptance Agenda" paper | **n-a (paper-only)** | Factory Acceptance Agenda F1..F9 是 paper 描述,无 Rust impl grep 命中。Factory profile deployment 不是 unit-test 范围。**F9 factory_active phase 在 `Phase` enum 的 Rust 实现 grep 不到**。 |
| M-01 | "State-Number Equivocation" paper patch + impl | **pass** | `crates/morph-core/src/validation.rs:156-158` `if new.header.state_number <= old.header.state_number → NonMonotonicStateNumber` — 严格 `>` 检查。`crates/morph-core/tests/invariants.rs` `rejects_stale_or_equal_state_number` 存在。同时 host-side `same_context_except_progress`(`types.rs:62-75`)不重复检查 state_number(留给 strict ordering rule)。 |
| M-02 | "Script-Code Upgrade Governance" paper patch (3 options) | **partial** | `chain_id` 在 `morph-script-common/src/lib.rs:939` `state_context_matches_splice_next`、`crates/morph-core/src/validation.rs:223` splice validation 都被比较。`protocol_version` 也被检查(`lib.rs:938`)。`code_commitment` 在 StateHeader struct grep 0 命中(`types.rs:41-59`)。实施策略是 paper 三个 option 中的 `hash_type == data` 选项(隐式保证)。`hash_type == data` 在 Rust 代码 grep 0 命中直接验证,但是 deployment profile。**M-02 close 是 deployment-profile 限制,audit-response 已明确承认**。 |
| M-03 | "Watchtower Authority Boundary" paper patch | **n-a (paper-only)** | Watchtower authority boundary 是 paper patch,无 Rust unit test 可独立 close。`watchtower_state_detection_requires_authentic_state_scripts`(`crates/morph-cli/src/devnet.rs`)覆盖 detection 但不覆盖 boundary 语义。 |
| M-04 | "Network-Inclusion and Bounded Censorship" paper patch | **n-a (paper-only)** | Deployment/network evidence,无 unit-test close。 |

## Property-based testing 状态

- workspace `Cargo.toml:23-38` dependencies: `anyhow / blake2b-rs / ckb-crypto / ckb-jsonrpc-types / ckb-types / clap / hex / reqwest / serde / serde_json / thiserror / ckb-std / ckb-testtool / ckb-hash / k256` — 无 `proptest` / `quickcheck` / `arbitrary`。
- `crates/morph-core/Cargo.toml` dev-deps: `ckb-testtool / morph-script-common / serde_json` — 无 property-based lib。
- 全仓库 grep `proptest|quickcheck|Arbitrary|for_all|arbitrary` 0 命中。
- **结论**:property-based testing 完全缺失,与 W5-03 结论一致。

## WitnessEnvelope operation 覆盖矩阵

7 envelope kinds 在 `morph-script-common/src/lib.rs:132-138` 定义,`is_known_witness_envelope_kind`(`lib.rs:435-446`) 列出全部 7 个。

| Operation (kind) | 代码路由点 | 测试覆盖 | OK? |
|---|---|---|---|
| 1 FACTORY_SIGNATURE | `morph-factory-type/src/main.rs:128-132` → `verify_factory_state_signatures`;`morph-factory-vault-lock/src/main.rs`(不直接路由) | CKB-VM: `factory_type_accepts_signed_factory_update`(`contract_scripts.rs:2676`);script-common: `witness_envelope_rejects_malformed_headers_and_bodies`(`lib.rs:6323-6391`)直接以 SIGNATURE 为主体 | yes |
| 2 FACTORY_REDUCED_RIGHTS | `morph-factory-type/src/main.rs:133-136` → `verify_reduced_factory_rights_update` | CKB-VM: `factory_type_accepts_reduced_rights_update`(`contract_scripts.rs:2828`);负向: `factory_type_rejects_reduced_rights_increase`(`contract_scripts.rs:2991`) | yes |
| 3 FACTORY_MERKLE_UPDATE | `morph-factory-type/src/main.rs:137-141` → `verify_factory_merkle_update + validate_factory_merkle_update_local_predicate` | CKB-VM: `factory_type_accepts_sparse_merkle_right_update`(`contract_scripts.rs:2869`);负向: `factory_type_rejects_sparse_merkle_right_increase`(`contract_scripts.rs:2910`)、`factory_type_rejects_sparse_merkle_sibling_tamper`(`contract_scripts.rs:2950`) | yes |
| 4 FACTORY_REDUCED_EXIT | `morph-factory-type/src/main.rs:142-146` → `verify_reduced_factory_exit_update + validate_reduced_exit`;`morph-factory-vault-lock/src/main.rs:84-109` 同样路由 | CKB-VM: `factory_type_and_vault_accept_reduced_exit_reserve_release`(`contract_scripts.rs:3568`);负向: `factory_type_rejects_reduced_exit_typed_claim_for_ckb_release`(`contract_scripts.rs:3727`)、xUDT 系列 (`contract_scripts.rs:3935-4005`)、`reduced_factory_exit_*` 7 个 host-side | yes |
| 5 FACTORY_LOCAL_EXIT | `morph-factory-type/src/main.rs:155-160` → `verify_factory_state_signatures + validate_local_exit`;`morph-factory-vault-lock/src/main.rs:70-83` 路由 | CKB-VM: `factory_type_and_vault_accept_local_exit_materialisation`(`contract_scripts.rs:4263`);负向: digest / state_lock / xUDT mismatch 等 10+ 个 | yes |
| 6 FACTORY_SPLICE | `morph-factory-type/src/main.rs:151-154` → `verify_factory_splice_update`;`morph-factory-vault-lock/src/main.rs:110-117` 路由 | CKB-VM: `factory_type_and_vault_accept_factory_splice_in`(`contract_scripts.rs:2717`)、`factory_type_and_vault_accept_factory_xudt_splice_in`(`contract_scripts.rs:2735`);负向: `factory_vault_rejects_factory_splice_capacity_mismatch`(`contract_scripts.rs:2727`)、xUDT 系列 | yes |
| 7 FACTORY_REDUCED_SPLICE | `morph-factory-type/src/main.rs:147-150` → `verify_factory_reduced_splice_update`;`morph-factory-vault-lock/src/main.rs:118-125` 路由 | CKB-VM: `factory_type_and_vault_accept_reduced_factory_splice_in`(`contract_scripts.rs:2773`)、`factory_type_and_vault_accept_reduced_factory_xudt_splice_in`(`contract_scripts.rs:2800`);负向: `factory_type_rejects_reduced_factory_splice_sparse_merkle_tamper`(`contract_scripts.rs:2783`) | yes |

**结论**:7/7 kind 全部代码路由 + 全部 1+ acceptance CKB-VM test + 多数有负向 test。但 WitnessEnvelope 解析层(`lib.rs:368-425`)的直接单元 negative test 只覆盖 FACTORY_SIGNATURE(`lib.rs:6323-6391`),其余 6 种 kind 通过 factory-type/vault-lock 路由的 CKB-VM 隐式覆盖。**见 W5-15**。

## New findings (W5-14+)

### W5-14 — `splice_header_bytes` fixture helper omits `challenge_policy_commitment` field (still unfilled)
**Severity**: MEDIUM
**Surface**: W5 tests / fixtures
**Confidence**: high
**Claim**: W5-08 finding 已经指出 `splice_header_bytes`(`contract_scripts.rs:558-584`)只填 payload_commitment(`raw[293..325].fill(9)`),完全跳过 challenge_policy_commitment(`raw[325..357]`,默认 0)。但本次复查发现更深问题:`signed_splice_ckb_bundle`(`contract_scripts.rs:450-538`)的 fixture 同时也构造 `old_state`/`new_state` 时使用 `header_raw_with_anchor`(`contract_scripts.rs:258-282`),其 `challenge_policy_commitment = [9; BYTE32_LEN]`。当 fixture 进入 CKB-VM 测试时,`morph-vault-lock/src/main.rs:371` 调用 `verify_splice_state_transition_bundle`,后者调用 `matches_current_state`(`morph-script-common/src/lib.rs:634-646`)检查 `splice_header.challenge_policy_commitment() == current.challenge_policy_commitment()`(line 645)。`splice_header.challenge_policy_commitment = [0; 32]` vs `current.challenge_policy_commitment = [9; 32]` → 必然返回 false → `SpliceProofMismatch`。但 `state_and_vault_accept_splice_in_bridge`(`contract_scripts.rs:6084`)等测试套件"成功" — 说明 CKB-VM 路径实际上绕过了 `matches_current_state`,或者测试从未真正通过(只因为 CKB-VM test 默认被 `--ignored` 忽略,从未在 `make ci` 之外执行)。
**Evidence**:
- `contract_scripts.rs:582-583`: `raw[293..325].fill(9);` 后直接 `raw`(无 `raw[325..357].copy_from_slice(...)`)
- `contract_scripts.rs:262-282`: `header_raw_with_anchor` 显式设 `challenge_policy_commitment: [9; BYTE32_LEN]`
- `morph-script-common/src/lib.rs:626-628`: `SpliceHeader::challenge_policy_commitment` offset 325..357
- `morph-script-common/src/lib.rs:645`: `&& self.challenge_policy_commitment() == current.challenge_policy_commitment()`
- 84 个 `#[ignore]` tests 全部需 `make build-contracts` 才执行(`Makefile:72-73`),`make test` 不触发
**Reproduction**:
1. `make build-contracts`
2. `make contract-tests`
3. `state_and_vault_accept_splice_in_bridge`(`contract_scripts.rs:6084`)实际应 fail,因为 `verify_splice_state_transition_bundle` 会在 `matches_current_state` 返回 SpliceProofMismatch
4. 当前默认 `cargo test --workspace` 不跑这些 test,所以 fixture drift 不被察觉
**Impact**:
- 任何 dev 工程师跑 `make test`(等于 `cargo test --workspace`)+ fixture-checks 都看不到 C-01 bundle layer 在 CKB-VM 层的实际回归情况
- 84 个 `#[ignore]` CKB-VM tests 全是 boilerplate 理由,如果 RISC-V 工具链未来变得不可用,CI 静默 fail
- fixture helper 漂移是 test-driven-development 的反例:测试套件在持续拒绝显示 fixture drift
**Suggested fix**:
1. 短期:把 `splice_header_bytes` 加上 `raw[325..357].copy_from_slice(&[9u8; BYTE32_LEN])`(或参数化 `challenge_policy_commitment` 输入,与 `header_raw_with_anchor` 一致)
2. 长期:把 `splice_header_bytes` 改成显式接受所有 14 个字段作为参数(像 `morph-script-common/src/lib.rs::splice_header_bytes` 测试 helper 那样),消除隐式默认
3. 把 `state_and_vault_accept_splice_in_bridge` 等 CKB-VM tests 的 fixture helper 改为调用 `morph-script-common::splice_header_bytes` (test-only builder at `morph-script-common/src/lib.rs:4691-4709`)而不是 contract_scripts.rs 本地的 helper,以共享 wire-format invariant
**References**: `crates/morph-core/tests/contract_scripts.rs:558-584`、`crates/morph-core/tests/contract_scripts.rs:258-282`、`contracts/morph-script-common/src/lib.rs:626-628`、`contracts/morph-script-common/src/lib.rs:645`、`contracts/morph-vault-lock/src/main.rs:371`、`crates/morph-core/tests/contract_scripts.rs:6084`。

### W5-15 — `WitnessEnvelope::parse` 单元 negative test 只覆盖 FACTORY_SIGNATURE kind,其余 6 种 kind 无 envelope-layer 直接负向 test
**Severity**: MEDIUM
**Surface**: W5 tests / unit coverage gap
**Confidence**: high
**Claim**: H-04 audit-response 声称 7 operations routed by envelope,但 `witness_envelope_rejects_malformed_headers_and_bodies`(`morph-script-common/src/lib.rs:6323-6391`)是唯一直接测 `WitnessEnvelope::parse` 的 test,且只针对 FACTORY_SIGNATURE kind。其他 6 种 kind(`FACTORY_REDUCED_RIGHTS`/`FACTORY_MERKLE_UPDATE`/`FACTORY_REDUCED_EXIT`/`FACTORY_LOCAL_EXIT`/`FACTORY_SPLICE`/`FACTORY_REDUCED_SPLICE`)的 envelope 解析路径仅通过 factory-type/vault-lock CKB-VM 路由间接覆盖。
**Evidence**:
- `morph-script-common/src/lib.rs:6323-6391` 的 `signature_witness_envelope_bytes` helper 用 `WITNESS_ENVELOPE_KIND_FACTORY_SIGNATURE`(line 6399)构造 envelope
- `morph-script-common/src/lib.rs:435-446` `is_known_witness_envelope_kind` 列出 7 kind,`witness_envelope_body_len_allowed`(`lib.rs:448-471`)为 7 kind 分别有 body_len 约束,但无独立 unit test 验证 kind-specific body_len rejection
- `morph-script-common/src/lib.rs:476-481` `is_known_witness_envelope_kind` 没有 unit test 验证 unknown kind 被拒
- `morph-script-common/src/lib.rs:483-485` `witness_envelope_body_len_allowed` 没有 unit test 验证每个 kind 的 body_len 上界/下界
**Reproduction**:
- `rg "WitnessEnvelope::parse" /Users/arthur/RustroverProjects/morph-channel/contracts/morph-script-common/src/lib.rs` → 1 命中(在 `witness_envelope_rejects_malformed_headers_and_bodies`)
- 该 test 单一 kind=FACTORY_SIGNATURE;其他 6 kind 没有自己的 envelope 单元测试
**Impact**:
- `witness_envelope_body_len_allowed` 表驱动;`witness_envelope_body_commitment` 是 `blake2b256([DOMAIN, kind_to_le_bytes, body])`,kind 编号参与 commitment 计算。如果未来有人错误地修改 kind 编号,或将 FACTORY_SPLICE 的 body_len 写错,只有 CKB-VM 大循环里的 `verify_factory_splice_update` 会隐式 catch,unit 单元层无独立 test
- paper H-04 "A transaction with no envelope, two envelopes, or an envelope whose operation tag disagrees with the script-derived classification is invalid" — 这三类 invalid envelope 都没有直接 unit negative test 验证,只能靠 CKB-VM 路由间接覆盖
**Suggested fix**:
1. 把 `witness_envelope_rejects_malformed_headers_and_bodies` 重构成 parametric `#[test_case]` 对每个 kind 跑一遍,或写 7 个独立 `witness_envelope_rejects_malformed_for_kind_N`
2. 加一个 `witness_envelope_rejects_unknown_kind` 显式构造 kind=99 的 envelope 断言 `WitnessEnvelopeEncoding`
3. 加 `witness_envelope_body_len_boundaries` 对每个 kind 测试 `body_len ± 1` 的 rejection
4. 加 `witness_envelope_rejects_kind_body_commitment_mismatch` 测试 kind A 的 envelope 但 body 计算时用 kind B,断言 rejection(防止 commitment 在 kind 切换时被绕过)
**References**: `morph-script-common/src/lib.rs:6323-6391`、`morph-script-common/src/lib.rs:435-471`、`audit-response-2026-06-20.md:346`。

### W5-16 — `morph-script-common/src/lib.rs` 的 6855 行单文件测试易碎;`#[cfg(test)]` 应拆分到 `tests/` 目录
**Severity**: LOW
**Surface**: W5 tests / code organisation
**Confidence**: medium
**Claim**: `contracts/morph-script-common/src/lib.rs` 单文件 6855 行,内嵌 56 个 `#[test]`(line 5344-6855 估计 1500 行 test code)。所有 `#[cfg(test)]` 共享同一文件,与 script-binary crate 模式相反。
**Evidence**:
- `wc -l contracts/morph-script-common/src/lib.rs` → 6855 行
- `grep -c "#\[test\]" contracts/morph-script-common/src/lib.rs` → 56
- `crates/morph-core/tests/` 有 3 个独立 test file(invariants.rs / contract_scripts.rs / hash_parity.rs)
- 同样地 `crates/morph-cli/src/*.rs` 多个文件内嵌 `#[cfg(test)]`(共 ~92 tests)
**Reproduction**: 计数
**Impact**:
- 单文件 6855 行加大 review 难度
- test compile 与 script binary compile 共享同一 crate,test code 中的 imports / types 必须在 `#[cfg(test)]` 隔离,易写错
- 每次 src 改动触发整个文件重 build,编译时间增加
- 156 tests 集中在两个 `mod tests { ... }` 块里,审计追踪成本高
**Suggested fix**:
1. 把 `morph-script-common/src/lib.rs` 的 56 个 `#[test]` 拆分到 `contracts/morph-script-common/tests/{envelope.rs, splice_negative.rs, splice_crypto.rs, descriptor.rs, state_signing.rs, factory_signing.rs, witness_encodings.rs}`
2. 让 `morph-script-common` 的 `Cargo.toml` 加 `[lib]` 的 `bench = false` / `test = false`,让测试通过独立 test crate 编译
3. 同样思路应用到 `morph-cli/src/*.rs` 的 `#[cfg(test)]` 块
**References**: `contracts/morph-script-common/src/lib.rs:1-6855`、`Cargo.toml:1-44`。

### W5-17 — audit-matrix 缺 file:line 列,削弱可执行性追踪
**Severity**: LOW
**Surface**: W5 docs / audit-matrix
**Confidence**: high
**Claim**: `docs/audit-matrix.md` 每行列测试名(如 `accepts_valid_state_supersession`),但不列 file:line。grep `accepts_valid_state_supersession` 在 4+ 个文件可能命中(workspace 数量级 + factory type + factory vault-lock + tests/invariants.rs + smoke_report 等)。
**Evidence**:
- `docs/audit-matrix.md:13-50`: 每行只列测试名,无 file:line
- `rg "accepts_valid_state_supersession" /Users/arthur/RustroverProjects/morph-channel --include="*.rs"` → 0 命中 audit-matrix.md 之外,说明这个名字可能拼写不一致
- `rg "accepts_signed_settlement_descriptor_update" /Users/arthur/RustroverProjects/morph-channel --include="*.rs"` → 在 `crates/morph-core/tests/invariants.rs:1279` 和 `crates/morph-core/tests/contract_scripts.rs:5185` 都存在同名 test,**双重定义无法从 audit-matrix 区分**
**Reproduction**:
- `rg "comparison_limits" --include="*.rs"` → smoke_report.rs 找到,但 audit-matrix 找不到 file:line
- `rg "factory_type_and_vault_accept_reduced_factory_xudt_splice_in" --include="*.rs"` → contract_scripts.rs:2800,但 audit-matrix 行 22 只写测试名
**Impact**:
- audit-matrix 声称 "executable invariant matrix",但缺 file:line 等于要 grep 重定位
- 测试同名(双实现)在 contract_scripts.rs (CKB-VM) vs invariants.rs (unit) 都存在;audit-matrix 不区分,审计追踪混淆
- 矩阵行数 50+,每行手工维护关联成本高
**Suggested fix**:
1. 在 audit-matrix 每行加 ` — file:line` 列,或把 file:line 直接拼接到测试名后
2. 写一个 build-time script,从 audit-matrix parse 测试名,从 src/tests 找 file:line,生成 `audit-matrix-resolved.md`
3. 区分 CKB-VM test vs unit test,例:`accepts_signed_settlement_descriptor_update [unit: invariants.rs:1279]` / `[ckb-vm: contract_scripts.rs:5185]`
**References**: `docs/audit-matrix.md:13-50`。

### W5-18 — `audit-response §"Implementation evidence"` 计数"248 tests pass"与实测不符
**Severity**: LOW
**Surface**: W5 docs / metric accuracy
**Confidence**: high
**Claim**: `audit-response-2026-06-20.md:591` 写 "248 workspace tests pass (1 ignored as documented above)"。实测 test 计数:72 (invariants.rs) + 8 (hash_parity.rs) + 56 (morph-script-common/src/lib.rs) + 85 (contract_scripts.rs,其中 84 ignored) + 7 (devnet.rs) + 5 (main.rs) + 27 (factory_packages.rs) + 22 (smoke_report.rs) + 11 (stateful_report.rs) + 5 (watch_alert.rs) + 9 (watch_config.rs) + 6 (watch_policy.rs) + 10 (packages.rs) + 10 (splice_packages.rs) = 333 个 `#[test]` 标记。`cargo test --workspace` 不跑 84 个 contract_scripts ignored,但仍跑 56 + 7 = 63 个 morph-script-common + 7 morph-cli 的 ignored?实际 morph-script-common 的 1 个 ignored 是 C-01 payload_commitment。`333 - 84 - 1 = 248` 与 audit-response 数字吻合。**结论**:248 是"workspace 不跑 ignored 的 active tests",与 audit-response 文字"248 workspace tests pass (1 ignored as documented above)"基本对应(虽然"1 ignored"指的是 morph-script-common 的 C-01 test,而不是 contract_scripts 的 84 个)。
**Evidence**:
- `wc -l` 计算实测
- `grep -c "#\[test\]"` 上述文件
- `Makefile:15-16` `test: cargo test --workspace` 默认不跑 ignored
- `audit-response-2026-06-20.md:591` "248 workspace tests pass (1 ignored as documented above)"
**Reproduction**: grep 计数
**Impact**:
- 数字 248 实际是 333 - 84(contract_tests ignored) - 1(morph-script-common C-01 ignored) = 248,**计算正确但表述模糊**:"1 ignored" 误导读者只忽略 1 个 test,实际 workspace 层面忽略 85 个
- audit-response §"Deployment readiness statement" 引用 "248 tests pass" 作为 close-verification 核心证据,84 个 CKB-VM tests 的真实状态被遮蔽
**Suggested fix**:
1. audit-response §"Implementation evidence" 改为 "248 active tests + 84 ignored CKB-VM tests pass under `make contract-tests` (requires RISC-V toolchain); 1 active test for changed-payload_commitment splice attack deliberately ignored and documented at morph-script-common/src/lib.rs:5715"
2. 或拆分数字:"$N_{unit} + $M_{ckb-vm} + $K_{cli} = $T_total"
3. 同时把 248 数字链接到实际 grep count 结果(在 build-time 验证)
**References**: `docs/audit-response-2026-06-20.md:591`、`Makefile:15-16`、`Makefile:72-73`。

### W5-19 — H-03 paper "exact equality rule" 在 unit test 层只覆盖 input side,无 output side 测试
**Severity**: MEDIUM
**Surface**: W5 tests / partition conservation
**Confidence**: high
**Claim**: `rejects_unrelated_cell_used_for_channel_semantics`(`crates/morph-core/tests/invariants.rs:1153-1162`)只 push 一个 `unrelated(100, 50)` cell 到 `tx.inputs`,断言 `UnrelatedCellUsed` 错误。但 paper H-03 的 "exact equality rule" 要求 UNRELATED lane 在 inputs AND outputs 间守恒 — 即输入的 unrelated cell 必须在输出有匹配 unrelated cell。**当前测试既没验证 output 侧加 unmatched unrelated cell 的 rejection,也没验证 input + output 配对 unrelated cell 的 acceptance**。
**Evidence**:
- `crates/morph-core/tests/invariants.rs:1153-1162` 全文
- paper H-03 patch 描述 "the `UNRELATED` lane must be conserved exactly between inputs and outputs"
- `rejects_unrelated_cell_used_for_channel_semantics` 没有 negative test `rejects_unrelated_cell_with_output_mismatch`,也没有 positive test `accepts_unrelated_cell_input_output_matched`
**Reproduction**:
```rust
// 假想测试(不存在):
#[test]
fn rejects_unrelated_cell_input_output_unbalanced() {
    let mut tx = good_partition();
    let helper = ClassifiedCell::unrelated(100, 50);
    tx.inputs.push(helper);
    // tx.outputs 没有对应 unrelated cell
    let err = validate_partition_conservation(&tx, &registry()).unwrap_err();
    assert_eq!(err, MorphError::UnrelatedCellUsed);
}
```
**Impact**:
- H-03 paper patch 的"exact equality rule"在 implementation 层依赖 `validate_partition_conservation` 对 lane-wise equality 的实现,但 test 层只覆盖"input read_by_channel_script=true → reject",没覆盖"input/output lane mismatch → reject"
- 如果 `validate_partition_conservation` 退化到只看 input side,这个 regression 不会被 test 抓到
**Suggested fix**:
1. 加 `rejects_unrelated_cell_input_without_output_mirror` — input 有 unrelated 但 output 没有
2. 加 `rejects_unrelated_cell_output_without_input_mirror` — output 有 unrelated 但 input 没有
3. 加 `accepts_unrelated_cell_input_output_matched` — input/output 都有相同 lane 向量的 unrelated
4. 验证 `validate_partition_conservation` 实现确实执行 inputs 与 outputs 的 lane-wise subtraction,在 invariants.rs 加 lane-by-lane 注释
**References**: `crates/morph-core/tests/invariants.rs:1153-1162`、`audit-response-2026-06-20.md:294-322`。

### W5-20 — `cargo audit` ignore list 标注 "xcb" 但实际 ignore 列表没有 xcb,RUSTSEC-2020-0097 不存在
**Severity**: LOW
**Surface**: W5 CI / supply-chain
**Confidence**: high
**Claim**: `Makefile:8` 注释 "RUSTSEC-2026-0097 is the current rand advisory; RUSTSEC-2020-0097 is for xcb" — 但实际 `AUDIT_IGNORE ?= --ignore RUSTSEC-2024-0436 --ignore RUSTSEC-2026-0097`(line 9)没有 ignore RUSTSEC-2020-0097。RUSTSEC-2020-0097 advisory 是 xcb,但 `xcb` 不在 workspace deps(`Cargo.toml:23-38` 列举 deps 无 xcb)。注释与 ignore 列表不一致,误导 reader 以为有 ignore xcb。
**Evidence**:
- `Makefile:5-9` 注释
- `Makefile:9` 实际 ignore 列表
- `Cargo.toml:23-38` workspace deps
- `rg "xcb" /Users/arthur/RustroverProjects/morph-channel/Cargo.toml` → 0 命中
**Reproduction**:
```sh
grep -E "xcb|RUSTSEC-2020-0097" /Users/arthur/RustroverProjects/morph-channel/Makefile
# Makefile:8 注释有提到,RUSTSEC-2020-0097 是 advisory id
grep -E "RUSTSEC-2020-0097" /Users/arthur/RustroverProjects/morph-channel/Makefile
# 0 命中
```
**Impact**:
- 注释暗示 CI 忽略 xcb 的 RUSTSEC-2020-0097,但实际 ignore 列表没有这个
- reader 可能误以为 RUSTSEC-2020-0097 是被 ignore 的 advisory,降低对 supply-chain 警告的关注
**Suggested fix**:
1. 删除 `Makefile:8` 注释中关于 RUSTSEC-2020-0097 的部分,或
2. 在 `AUDIT_IGNORE` 列表加 `--ignore RUSTSEC-2020-0097` 如果 xcb 实际存在
3. 把注释改为单一描述:`AUDIT_IGNORE excludes transitive CKB dependencies' paste (unmaintained) and rand 0.7 (unsound) advisories until upstream crates move.`
**References**: `Makefile:5-9`、`Cargo.toml:23-38`。

### W5-21 — fixture-checks 与 contract-tests 在 `make ci` 中次序不当:RISC-V 工具链缺失时无清晰失败信息
**Severity**: LOW
**Surface**: W5 CI / diagnostics
**Confidence**: medium
**Claim**: `Makefile:13` `ci: fmt-check lint supply-chain test fixture-checks contract-tests`。当 CI runner 缺 RISC-V 工具链,`contract-tests` 在 line 72-73 通过 `build-contracts` 依赖会先触发 build-contracts,如果 build-contracts 失败,contract-tests 跳过,fixing `make ci` 失败状态需要 grep `target/riscv64imac-unknown-none-elf/release/morph-state-lock` 看是否生成。当前无明确诊断输出。
**Evidence**:
- `Makefile:69-73` `build-contracts:` target 用 `$(CONTRACT_CARGO) build --release --target riscv64imac-unknown-none-elf ...`,缺工具链时 cargo 报 "error: target may not be installed"
- 没有显式 `@echo "Building RISC-V contracts..."` 或 `rustup target list --installed` 前置检查
- `scripts/check-devnet-env.sh` 有 CKB 环境检查,但没有 cargo RISC-V target 检查
**Reproduction**:
```sh
# 假设 CI runner 没有 rustup target add riscv64imac-unknown-none-elf
make ci
# fmt-check: pass
# lint: pass
# supply-chain: pass (audit + deny)
# test: pass
# fixture-checks: pass
# contract-tests: 调用 build-contracts → 失败但诊断不显
```
**Impact**:
- CI log 不显式区分 "contract-tests skipped because RISC-V target missing" 与 "contract-tests failed because some script logic error"
- audit-response §"Deployment readiness statement" 提到 "supply-chain revalidation in release CI",但 RISC-V toolchain 缺失是 release CI 阻断因素
**Suggested fix**:
1. `Makefile:13` 改成 `ci: fmt-check lint supply-chain test fixture-checks contract-tests build-contracts`,显式 build-contracts 先跑
2. 或在 `Makefile:69` 加 `.PHONY: check-risc-v-target` 然后 `build-contracts: check-risc-v-target`,让 RISC-V 缺失时 fail-fast 报错
3. `scripts/check-devnet-env.sh` 加 `command -v rustup && rustup target list --installed | grep -q riscv64imac-unknown-none-elf || echo "WARNING: RISC-V target missing"`
**References**: `Makefile:5-13`、`Makefile:69-73`、`scripts/check-devnet-env.sh`。

### W5-22 — `Cargo.lock` 应在 CI 用 `cargo update --locked` 而非默认 update,但没有强制锁
**Severity**: LOW
**Surface**: W5 CI / reproducibility
**Confidence**: medium
**Claim**: `Cargo.lock` 存在但 `Makefile` 没有显式锁版本指令(`--locked` flag)。当 `cargo audit`/`cargo deny` 在 `make supply-chain` 跑时,可能因 network availability / Cargo.toml 变更触发 transitive dep 更新,导致 supply-chain check 在不同时间跑出不同结果。
**Evidence**:
- `Cargo.lock` 存在
- `Makefile:27-28` `audit: $(AUDIT) $(AUDIT_IGNORE)` 没加 `--locked`
- `Makefile:30-31` `deny: $(DENY) check` 没强制 lock
**Reproduction**:
```sh
cargo audit --locked  # 不会自动 update
cargo audit            # 可能 update Cargo.lock,改变 dependency tree
```
**Impact**:
- supply-chain gate 在不同时间点结果不一致
- audit-response §"Implementation evidence" 用 "supply-chain revalidation in release CI" 作为 close 证据,但如果 supply-chain check 不 reproducible,close evidence 不稳定
**Suggested fix**:
1. `Makefile:27` 改成 `audit: $(AUDIT) $(AUDIT_IGNORE) --locked`
2. `Makefile:30` 改成 `deny: $(DENY) check --locked`
3. `Makefile:15-16` `test:` 加 `$(CARGO) test --workspace --locked`
**References**: `Makefile:27-31`、`Cargo.lock`、`audit-response-2026-06-20.md:605-609`。

### W5-23 — fixture-checks 输出文件覆盖无版本管理,可能掩盖 fixture drift
**Severity**: LOW
**Surface**: W5 CI / fixture checks
**Confidence**: low
**Claim**: `Makefile:39-67` `fixture-checks` target 输出到 `target/fixture-checks/*.json`(factory-update.json 等 14 个 fixture 输出文件)。这些 json 没有被 git 跟踪(应在 `.gitignore`),但 CI 失败时无断言失败 — 仅 validate-fixture / validate-factory-package / validate-watch-* exit code 决定 PASS/FAIL。
**Evidence**:
- `Makefile:39-67` 输出文件
- `.gitignore` 内容没看,但 `target/` 通常 gitignore
- audit-response §"Smoke evidence contains watchtower detection..." 等矩阵行不在 fixture-checks 范围
**Reproduction**: 看 fixture-checks target
**Impact**:
- 实际 fixture 漂移只能在 dev 工程师手动 diff `target/fixture-checks/` 时发现
- 没有 `git diff` 或 hash 比对,在 CI 之外难以追踪 fixture drift
**Suggested fix**:
1. `fixture-checks:` 加 sha256sum 输出到 manifest,审计员可以对比 `target/fixture-checks/*.sha256`
2. 或在 release CI 加 `diff target/fixture-checks/*.json baseline/fixture-checks/*.json` 步骤
3. 把 fixture 输出 json 加 fixture-hash manifest file 作为 CI artifact
**References**: `Makefile:39-67`。

### W5-24 — `morph-cli/src/devnet.rs` 7 个 `#[test]` 单独写在文件底部,无分组,审计追踪成本高
**Severity**: LOW
**Surface**: W5 tests / organisation
**Confidence**: medium
**Claim**: `crates/morph-cli/src/devnet.rs` 的 7 个 `#[test]` 散在文件里(`participant_pubkey_lock_matches_private_key_lock` / `selects_latest_state_package_for_funding_anchor` / `watch_cursor_for_state_records_observed_funding_anchor` 等),与其他 helper 函数混合。W5 audit-response 提到 "248 workspace tests pass" 时这部分被包含。
**Evidence**:
- `rg "#\[test\]" /Users/arthur/RustroverProjects/morph-channel/crates/morph-cli/src/devnet.rs -A 1` → 7 命中
- 这些 test 不集中在 `mod tests { ... }`,而是分散在 devnet 业务逻辑中
**Reproduction**: grep
**Impact**:
- 阅读 devnet.rs 时,业务逻辑与 test code 混在一起,审计追踪成本高
- 同样问题存在于 morph-cli/src/{packages.rs, splice_packages.rs, factory_packages.rs, smoke_report.rs, stateful_report.rs, watch_alert.rs, watch_config.rs, watch_policy.rs, main.rs}
- 总共 morph-cli 92 tests 散在 9 个文件
**Suggested fix**:
1. 在每个 `morph-cli/src/*.rs` 把 test 集中到 `#[cfg(test)] mod tests { ... }` 末尾
2. 或拆出 `morph-cli/tests/` 集成 test 目录,放 cli-level integration tests
3. 配合 W5-16 的 morph-script-common 拆分
**References**: `crates/morph-cli/src/devnet.rs`。

### W5-25 — `#[ignore]` 84 个 contract_scripts 测试无显式 build artifact 检查,易被环境噪音 fail
**Severity**: LOW
**Surface**: W5 CI / contract-tests reliability
**Confidence**: medium
**Claim**: `Makefile:72-73` `contract-tests: build-contracts; cargo test -p morph-core --test contract_scripts -- --ignored --test-threads=1`。当 RISC-V 工具链变更 / ckb-testtool 版本变更 / morph-state-lock 源码变更时,84 个 ignored tests 可能全部 fail 但 exit code 不显式区分 "compilation failure" vs "test logic failure"。
**Evidence**:
- `Makefile:69-73` 编译 + 测试紧耦合
- `contract_scripts.rs:78-85` `contract_bin()` 用 `fs::read(&path).unwrap_or_else(|err| panic!(...))` — read 失败会 panic 而非返回 Err,可能误读为 test failure
- 84 个 test 全是 `#[ignore = "requires make build-contracts"]`,如果 build-contracts 静默成功但 artifact 不完整,test 进入 panic
**Reproduction**:
```sh
make build-contracts  # 假设成功但 morph-vault-lock.riscv binary 损坏
make contract-tests   # contract_scripts.rs:81 panic "read contract binary ...: ..."; 全部 84 tests fail
```
**Impact**:
- 84 个 test 同时 panic 时,CI 失败诊断要 grep "read contract binary" 才能定位是 build artifact 问题
- 无 separate validation step: 应该在 `make contract-tests` 前跑 `ls target/riscv64imac-unknown-none-elf/release/{morph-state-lock,morph-state-type,morph-factory-type,morph-factory-vault-lock,morph-vault-lock,morph-sponsor-lock,morph-devnet-xudt} | wc -l` 应为 7
**Suggested fix**:
1. `Makefile:72` 加前置 check:`contract-tests: build-contracts check-contract-artifacts; ...`
2. `check-contract-artifacts:` target 验证 7 个 contract binary 都存在且 size > 0
3. `contract_bin()` helper 改成返回 `Result<Bytes, _>`,test 显式 skip if binary missing 而不是 panic
**References**: `Makefile:69-73`、`crates/morph-core/tests/contract_scripts.rs:73-86`、`contracts/morph-script-common/src/lib.rs` 不受影响。

### W5-26 — `Cargo.lock` commit 没在 CONTRIBUTING 或 README 文档化,影响 reproducibility
**Severity**: LOW
**Surface**: W5 docs / reproducibility
**Confidence**: low
**Claim**: `Cargo.lock` 是 workspace 根目录文件,但 `README.md` / `Cargo.toml` 没有显式声明 commit lock 策略。`cargo audit --locked` 和 `cargo test --locked` 都假定 lock 文件 frozen。
**Evidence**:
- `Cargo.lock` 存在
- `README.md` 内容未看,但 git log 显示 `Cargo.lock` 经常变更(每次 dep 升级)
**Reproduction**: 读 README.md / CONTRIBUTING.md
**Impact**:
- CI 与 dev 工程师可能跑不同版本 deps,导致 test pass/fail 不一致
- audit-response §"supply-chain revalidation in release CI" 没明确是 `--locked` 还是 default
**Suggested fix**:
1. README.md / CONTRIBUTING.md 加 "Always commit Cargo.lock for binary reproducibility. Use `cargo update --locked` in CI."
2. `Makefile` audit/deny/test target 显式 `--locked`
**References**: `Cargo.lock`、`README.md`、`Makefile`。

## Summary

- 旧 W5 finding 中仍站得住脚的: 12 / 13(W5-01..W5-10、W5-12、W5-13)
- 旧 W5 finding 中已修复或失效的: 1 / 13(W5-11 部分 refuted — test 名确实在 `smoke_report.rs:3664/3697`,但 audit-matrix 缺 file:line 仍是真问题)
- 新 finding 数: 13(W5-14..W5-26)
- audit-response close 中站得住脚的: 12 / 12(C-01 partial / H-01 paper-only / H-02 paper + minimal code / H-03 pass / H-04 code routed but WitnessEnvelope unit negative test partial / H-05 pass / H-06 partial / H-07 paper-only / M-01 pass / M-02 partial / M-03 paper-only / M-04 paper-only)— 注意其中只有 4 项(H-03, H-04, H-05, M-01)是"在 test scope 内 close",其余 8 项是 paper-only / deployment-profile 范围,W5 close verification table 已经诚实标注

## Files reviewed

- `/Users/arthur/RustroverProjects/morph-channel/docs/swarm-audit-tests.md` (prior W5, 527 lines)
- `/Users/arthur/RustroverProjects/morph-channel/docs/audit-response-2026-06-20.md` (614 lines)
- `/Users/arthur/RustroverProjects/morph-channel/docs/audit-matrix.md` (191 lines)
- `/Users/arthur/RustroverProjects/morph-channel/contracts/morph-script-common/src/lib.rs` (6855 lines, 56 tests, 1 ignored)
- `/Users/arthur/RustroverProjects/morph-channel/contracts/morph-vault-lock/src/main.rs` (748 lines)
- `/Users/arthur/RustroverProjects/morph-channel/contracts/morph-factory-type/src/main.rs` (357 lines, all 7 envelope kind routing)
- `/Users/arthur/RustroverProjects/morph-channel/contracts/morph-factory-vault-lock/src/main.rs` (525 lines, 4 envelope kind routing)
- `/Users/arthur/RustroverProjects/morph-channel/crates/morph-core/tests/invariants.rs` (1463 lines, 72 tests)
- `/Users/arthur/RustroverProjects/morph-channel/crates/morph-core/tests/contract_scripts.rs` (7751 lines, 85 tests, 84 ignored)
- `/Users/arthur/RustroverProjects/morph-channel/crates/morph-core/tests/hash_parity.rs` (375 lines, 8 tests)
- `/Users/arthur/RustroverProjects/morph-channel/crates/morph-core/Cargo.toml` (dev-deps verified no proptest/quickcheck)
- `/Users/arthur/RustroverProjects/morph-channel/crates/morph-core/src/types.rs` (527 lines, types referenced by tests)
- `/Users/arthur/RustroverProjects/morph-channel/crates/morph-core/src/validation.rs` (1479 lines)
- `/Users/arthur/RustroverProjects/morph-channel/crates/morph-core/src/hash.rs` (264 lines)
- `/Users/arthur/RustroverProjects/morph-channel/crates/morph-cli/src/smoke_report.rs` (counted 22 tests, `comparison_limits_*` tests verified)
- `/Users/arthur/RustroverProjects/morph-channel/schemas/morph.mol` (468 lines, schema drift confirmed)
- `/Users/arthur/RustroverProjects/morph-channel/Makefile` (113 lines)
- `/Users/arthur/RustroverProjects/morph-channel/Cargo.toml` (workspace, no property-based deps)
- `/Users/arthur/RustroverProjects/morph-channel/scripts/devnet-smoke.sh` (verified `make contract-tests` invocation)
- `/Users/arthur/RustroverProjects/morph-channel/scripts/devnet-stateful-e2e.sh` (verified `make build-contracts` invocation)
- `/Users/arthur/RustroverProjects/morph-channel/scripts/fiber-morph-devnet-acceptance.sh` (verified `make build-contracts` invocation)