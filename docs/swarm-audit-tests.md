# Swarm Audit — tests and CI fixtures

**Date**: 2026-06-21
**Branch**: `arthur/morph-audit-fixes` (HEAD `aa71651`)
**Auditor**: Swarm worker W5 (tests and CI fixtures)
**Scope**: 所有 test 文件 + CI fixture + Makefile 矩阵。审计:测试覆盖率缺口、property-based testing 该有却没有的地方、CI fixture 一致性(a040f6a/aa71651 都改了 hash_parity.rs / invariants.rs,新增测试与 fixture 是否同步更新)、所有 #[ignore] 测试的合理性、上一轮 12 finding 对应的 invariant test 是否存在且真的覆盖、Makefile 各 target 是否实际可达、Cargo workspace 配置、CKB-VM 测试是否覆盖所有 negative path。重点检查新增的 4 个 C-01 negative test + 1 个 #[ignore] 测试是否真的覆盖 audit-response 描述的攻击面。

**Methodology**:
- 独立审 上述文件全量代码
- 验证上一轮 12 finding 的 close 落地(范围内部分)
- 不做 build/test 跑(由 root 统一跑)

## Summary

| Severity | Count |
| --- | --- |
| CRITICAL | 1 |
| HIGH | 3 |
| MEDIUM | 4 |
| LOW | 2 |

## Close verification (上一轮 12 finding)

| Finding | 在本面范围 | Close 验证结果 | 备注 |
| --- | --- | --- | --- |
| C-01 | yes | **partial** | 4 个 negative test (`rejects_splice_state_transition_with_changed_participants_commitment`/`_settlement_descriptor`/`_mode`/`_asset_registry`) 在 `morph-script-common` 单元测试里编译通过且断言 SpliceProofMismatch。`matches_current_state` 已经把 `payload_commitment` 加进比较(`morph-script-common/src/lib.rs:644`)。`SPLICE_HEADER_LEN=357`、`payload_commitment` 在 `SpliceHeader` 偏移 293、`challenge_policy_commitment` 偏移 325,layout 与 audit-response 第 1 项声称一致。`vault_lock_rejects_splice_new_state_payload_mismatch` 在 `contract_scripts.rs:6541` 是真实的 CKB-VM 测试,覆盖 vault-lock 层的 `new_header.payload_commitment == new_vault_commitment` 检查。但是 `state_context_matches_splice_next`(`morph-script-common/src/lib.rs:933-957`)的代码**没有**比较 `current.payload_commitment() == next.payload_commitment()`,与 audit-response 的"Implementation patch"第 1 项声称不一致 — 详见 W5-01。 |
| H-01 | n-a | n-a | 落在 paper/profiles scope,不在 test/fixture 范围。 |
| H-02 | yes (covered by C-01 fixture layer) | pass | `vault_set_commitment` 和 vault manifest 的检查在 `verify_splice_state_transition`(`morph-script-common/src/lib.rs:803-839`)实现并由 `splice_rejects_tampered_asset_delta_commitment` / `splice_rejects_unsigned_withdrawal_output_change` 等测试覆盖。无 Vault Manifest 完整定义的 negative test。 |
| H-03 | yes | partial | `partition_conservation_accepts_valid_partition` + 8 个 negative(`rejects_channel_paid_fee_leakage` ... `rejects_unrelated_cell_used_for_channel_semantics`)覆盖 partition classifier 的关键 lane 守恒。但 `rejects_unrelated_cell_used_for_channel_semantics` 只检查 `read_by_channel_script=true`,没有显式测试 Unrelated 必须出现在 inputs AND outputs 中以满足 H-03 paper 要求的 "exact equality rule"。 |
| H-04 | yes | partial | witness envelope 在 `morph-script-common/src/lib.rs:368-392` 有解析和 body_commitment 校验。`morph_state_packages_devtest` 有 `witness_envelope_body_commitment` 调用点。但是没有显式的 `MorphOperationEnvelope` 单元测试 — paper H-04 描述的 "operation envelope" 7 种 operation 路由的 negative test 缺失。 |
| H-05 | yes | pass | `selects_latest_state_package_for_funding_anchor` / `watch_cursor_for_state_records_observed_funding_anchor` / `funding_context_id` 在 `crates/morph-cli/src/devnet.rs` 中实现。`funding_context_id` 在 `crates/morph-core/src/hash.rs:48-61` 有 domain separation。`chain_id+channel_id+funding_anchor+vault_set_commitment` 的 4-field 绑定覆盖 H-05 三名字区分。 |
| H-06 | partial | partial | `devnet-smoke-budget.example.json` 和 `devnet-stateful-budget.example.json` 有 cycle/byte/witness-length budget gate 通过 `devnet-stateful-assert` / `devnet-smoke-assert-budget` 跑。`MAX_VAULTS_PER_FINALISATION` / `MAX_XUDT_SCRIPT_GROUPS_PER_FINALISATION` 这些参数目前没有 source code 实现,只在 paper 里定义 — 在 unit/integration 层无法直接 test。这是 deployment profile 而非 close-verification 失败。 |
| H-07 | n-a | n-a | Factory profile 范围。Factory acceptance agenda F1..F9 是 deployment 工作,不在 test/fixture 范围。但 factory 端的 248 测试通过 + 大量 factory-type negative test 在 audit-matrix 里逐项列出 — 这一面的 close 不在本 worker scope。 |
| M-01 | yes | pass | `rejects_stale_or_equal_state_number` + `state_number` 严格 > 检查在 `crates/morph-core/src/validation.rs:156-158`。`mode_signing_codes_match_wire_profile` 在 `invariants.rs:605-609`。`rejects_signed_settlement_descriptor_update_as_context_change` 测试 `descriptor_version` / descriptor commitment 漂移会被 context 检查拒绝。同一 state number 上 two distinct headers 的攻击面被 monotonic check + signed_descriptor_evolution 双重守护。 |
| M-02 | partial | partial | `chain_id` 在 `verify_splice_state_transition` / `same_context_except_progress` / `state_context_matches_splice_next` 都被比较(`morph-script-common/src/lib.rs:939, 949`、`validation.rs:64`)。`protocol_version` 也被检查。但是 `code_commitment` (paper M-02 要求三个选项之一) 在代码中不存在,只能靠 `hash_type == data` 隐式保证。这是 deployment profile 限制,不在 test scope。 |
| M-03 | n-a | n-a | Watchtower authority 范围。watchtower cursor / detection 测试覆盖由 W5 之外的工作者审计。 |
| M-04 | n-a | n-a | Network-inclusion / bounded-censorship 范围。这是 deployment/network-layer evidence,不在 unit/integration test 范围。 |

## Findings

### W5-01 — `state_context_matches_splice_next` does not check `payload_commitment` between current and next, contrary to audit-response claim

**Severity**: CRITICAL
**Surface**: W5 tests
**Status**: verification-failed
**Confidence**: high

**Claim**: `audit-response-2026-06-20.md` 的 C-01 "Implementation patch" 第 1 项声称 `state_context_matches_splice_next` 现在也检查 `current.payload_commitment == next.payload_commitment`。但是 `morph-script-common/src/lib.rs:933-957` 的实际代码**没有**这条比较 — `payload_commitment` 完全缺席。

**Evidence**:
- `/Users/arthur/RustroverProjects/morph-channel/contracts/morph-script-common/src/lib.rs:933-957` 是 `state_context_matches_splice_next` 完整实现。其中比较的是 `protocol_version` / `chain_id` / `signature_scheme_id` / `channel_id` / `funding_epoch(old/new)` / `funding_anchor(old/new)` / `vault_set_commitment(old/new)` / `state_number(current==next)` / `mode` / `participants_commitment` / `asset_registry_commitment` / `settlement_descriptor_commitment` / `descriptor_version` / `challenge_policy_commitment` / `state_layout_version`。`payload_commitment` 不在比较列表里。
- 同样函数没有 `&& current_state.payload_commitment() == next_state.payload_commitment()` 这一项。
- `/Users/arthur/RustroverProjects/morph-channel/docs/audit-response-2026-06-20.md:103-106` 明确写出 `state_context_matches_splice_next now also checks current.payload_commitment == next.payload_commitment`。这是与代码不一致的文档声称。
- 对应单元测试 `rejects_splice_state_transition_with_changed_payload_commitment` 在 `morph-script-common/src/lib.rs:5714-5780` 被 `#[ignore]` 标记,并附详细 doc-comment 解释"payload_commitment is bound transitively via vault_set_commitment in this profile"。但代码实际逻辑中 `vault_set_commitment` 的比较只覆盖 next.vault_set_commitment == splice_header.new_vault_commitment(`morph-script-common/src/lib.rs:947`),并不直接传递到 payload_commitment — 唯一的 payload_commitment 强制点在 vault lock 的 `new_header.payload_commitment() != new_vault_commitment`(`morph-vault-lock/src/main.rs:377`)。

**Reproduction**: 在 `morph-script-common/src/lib.rs` 把 `rejects_splice_state_transition_with_changed_payload_commitment` 的 `#[ignore]` 去掉并执行 → 测试预期返回 `ScriptError::SpliceProofMismatch`,但实际会通过(因为 next.payload_commitment 没有跟 current.payload_commitment 比对)。即使测试函数把 next.payload_commitment 和 next.vault_set_commitment 都改了,只有 `state_context_matches_splice_next` 之外的 vault-lock 层检查会发现。这说明 `state_context_matches_splice_next` 这一层的 C-01 防线对 changed-payload_commitment 是空的。

**Impact**:
- bilateral plain profile(本仓库当前实现):vault lock 的 `new_header.payload_commitment == new_vault_commitment` 仍然兜底(测试 `vault_lock_rejects_splice_new_state_payload_mismatch` 覆盖),所以实际攻击被一层不同的检查拦截。属于"transitive binding"的设计选择,但 audit-response 的具体文字声称("now also checks")与代码不符。
- 其他 deployment profile(假设未来 factory profile 用 payload_commitment 表示 explicit balance commitment):bundle 层不再有 splice-bundle-level 的 payload_commitment 守恒检查,需要在 vault lock 层或 envelope 层加显式规则。audit-response 自身在第 88-93 行已经写出"a deployment profile that uses payload_commitment for a different purpose ... must replace the equality check with an explicit splice-time payload_commitment signing rule" — 但当前 `state_context_matches_splice_next` 完全没做这个 explicit check。

**Suggested fix**:
1. 短期:更新 audit-response 文字 — 把 "now also checks current.payload_commitment == next.payload_commitment" 改为"this check is intentionally absent in the bilateral plain profile because vault_set_commitment + vault-lock payload_commitment comparison close the attack vector at a different layer; profile-restricted general-case check is documented in H-02 vault manifest"。使文字声称与代码一致。
2. 长期:把 ignored test 解开(`#[ignore]` 移除)并让 `state_context_matches_splice_next` 在 next.payload_commitment != current.payload_commitment 时返回 false。这样既闭合 documentation-code 不一致,也让 C-01 attack vector 在 bundle 层有显式防线,不依赖 vault lock 层兜底。
3. 如果选择保留当前实现(bundle 层不强制 payload_commitment 相等),则必须在 paper / docs 显式标记 "C-01 closure in bilateral plain profile is vault-lock-layer only" 并引用 `morph-vault-lock/src/main.rs:377`,而不是声称在 splice bundle 层关闭。

**References**: C-01, audit-response §"Implementation patch" item 1, `morph-script-common/src/lib.rs:933-957`、`morph-script-common/src/lib.rs:644`、`morph-script-common/src/lib.rs:5714-5780`、`morph-vault-lock/src/main.rs:377`、`crates/morph-core/tests/contract_scripts.rs:6541`。

---

### W5-02 — SpliceHeader Molecule schema drift: schema says 325 bytes / no payload_commitment field, Rust constant is 357

**Severity**: HIGH
**Surface**: W5 tests
**Status**: new
**Confidence**: high

**Claim**: `schemas/morph.mol:15` 写 `"SpliceHeader: 325 bytes"` 而且 SpliceHeader struct (`schemas/morph.mol:99-116`) 没有 `payload_commitment` 字段。但是 `morph-script-common/src/lib.rs:13` 声明 `SPLICE_HEADER_LEN: usize = 357`,Rust wire 编码实际是 357 bytes(包括偏移 293 起的 `payload_commitment`)。schema 是 C-01 patch 之前的旧 layout,从未同步更新。

**Evidence**:
- `/Users/arthur/RustroverProjects/morph-channel/contracts/morph-script-common/src/lib.rs:13`: `pub const SPLICE_HEADER_LEN: usize = 357;`
- `/Users/arthur/RustroverProjects/morph-channel/contracts/morph-script-common/src/lib.rs:622-624`: SpliceHeader::payload_commitment 字段偏移 293。
- `/Users/arthur/RustroverProjects/morph-channel/contracts/morph-script-common/src/lib.rs:626-628`: SpliceHeader::challenge_policy_commitment 字段偏移 325。
- `/Users/arthur/RustroverProjects/morph-channel/schemas/morph.mol:15`: `- SpliceHeader: 325 bytes`
- `/Users/arthur/RustroverProjects/morph-channel/schemas/morph.mol:99-116`: SpliceHeader struct 字段列表 — 不含 payload_commitment。字段累加:2+32+2+32+32+32+8+8+8+8+1+32+32+32+32+32 = 325 bytes(没有 payload_commitment)。
- `/Users/arthur/RustroverProjects/morph-channel/contracts/morph-script-common/src/lib.rs:6152-6227`: 测试 `molecule_schema_names_all_active_fixed_width_objects` 的 expected 列表里仍然写 `"SpliceHeader: 325 bytes"`。这个 assertion 当前 **会 pass**(因为 schema 的注释里仍然写 325),所以 CI 不会发现 schema 已经过时。

**Reproduction**:
```sh
# schema 字节大小声明
grep "SpliceHeader" /Users/arthur/RustroverProjects/morph-channel/schemas/morph.mol
# 实际 Rust 常量
grep "SPLICE_HEADER_LEN" /Users/arthur/RustroverProjects/morph-channel/contracts/morph-script-common/src/lib.rs | head -1
```
注释:schema → 325;Rust → 357,差异 32 bytes(= payload_commitment 字段)。

**Impact**:
- schema 注释声称 325 bytes,但 Rust 编码是 357 bytes。如果有人依赖 schema 写外部分析工具(比如 block explorer / 调试工具的 wire 解码器),会用错误的偏移解 payload_commitment 字段,把下一个字段 challenge_policy_commitment 误读成 payload_commitment。
- 测试 `molecule_schema_names_all_active_fixed_width_objects` 把 schema 中的过时数字当作"期望"反向断言,失去 schema drift detection 能力。这等于把 audit 出的 bug 冻在测试里。
- 虽然 schema 文件顶部的注释说"The Rust implementation in crates/morph-core currently uses fixed-width Rust structs for executable invariant tests. This schema records the intended on-chain wire boundary and should be generated once moleculec is available in the devnet build environment",声明 schema 是"intended"而非 ground truth,但只要 schema 跟 Rust 偏差 32 bytes,任何用 schema 做交叉验证的 CI / 工具都会错位。

**Suggested fix**:
1. 把 `schemas/morph.mol:15` 的 `SpliceHeader: 325 bytes` 改成 `SpliceHeader: 357 bytes`,并在 SpliceHeader struct 字段列表加上 `payload_commitment: Byte32,`(放在 participants_commitment 之后,challenge_policy_commitment 之前)。
2. 把 `molecule_schema_names_all_active_fixed_width_objects`(`morph-script-common/src/lib.rs:6156`)的 expected `"SpliceHeader: 325 bytes"` 改成 `"SpliceHeader: 357 bytes"`。
3. 同时核对 schema 里 `SpliceStateTransitionWitness: 1017 bytes` 是否需要同步更新(原 SpliceHeader 325 + signatures 198 + 2×132 + 228 + 2(version)= 1019;新 SPLICE_STATE_TRANSITION_WITNESS_LEN 计算 = 2 + 357 + 198 + 264 + 228 = 1049,需重新计算)。

**References**: C-01, audit-response §"Implementation patch", `morph-script-common/src/lib.rs:13`、`morph-script-common/src/lib.rs:6152`、`schemas/morph.mol:15`、`schemas/morph.mol:99-116`。

---

### W5-03 — Property-based testing (proptest / quickcheck / arbitrary) is absent across the entire workspace

**Severity**: HIGH
**Surface**: W5 tests
**Status**: new
**Confidence**: high

**Claim**: 整个 codebase 没有 proptest / quickcheck / arbitrary 依赖,也没有任何 #[test] 用 property 描述。248 个 test 全部是 example-based。

**Evidence**:
- `/Users/arthur/RustroverProjects/morph-channel/crates/morph-core/Cargo.toml` 的 dev-dependencies 只有 ckb-testtool / morph-script-common / serde_json。
- `rg -c "proptest\|PropertyTesting\|quickcheck\|arbitrary"` 在全仓库返回 0 命中。
- `rg -c "for_all\|arbitrary\|Arbitrary"` 在 `crates/morph-core/tests/` 返回 0 命中。
- 当前所有 negative test 都基于特定手工构造的 fixture(例如 `state_header_context_rejects_epoch_and_vault_set_changes`、`rejects_xudt_amount_overflow_in_partition_totals`),手工构造的 edge case 不会触发编译器未察觉的隐式不变量。

**Reproduction**:
```sh
grep -rn "proptest\|quickcheck\|Arbitrary" /Users/arthur/RustroverProjects/morph-channel/crates
# 0 命中
```

**Impact**:
- 大部分 negative test 是手工构造的(例如 `rejects_xudt_amount_overflow_in_partition_totals` 把 u128::MAX 灌进 inputs 和 outputs)。这类测试只能保证"我想到的 edge case 被挡",不能保证"我没想过的 case 也被挡"。
- audit-response 给出 C-01 / H-02 / H-03 的 attack surface 列举,但只有 4-5 个手工构造的 case。Proptest 能用 1000 个随机生成的 splice / state / factory transition 覆盖更多 branch。
- H-02 "all_committed_vaults_consumed_or_evidenced" / H-03 lane-wise conservation 等数学性 invariant 是 property-based testing 经典目标,example-based 测试覆盖远远不够。

**Suggested fix**:
1. 在 workspace Cargo.toml `[workspace.dependencies]` 加 `proptest = "1"`。
2. 在 morph-core Cargo.toml dev-dependencies 加 `proptest.workspace = true`。
3. 把以下 invariants 改成 proptest:
   - `same_context_except_progress` 不变量(任意两个 header 改 protocol_version/chain_id 等字段,返回值应是 false)。
   - `participants_commitment` 排序不变量(pubkey 重排后 commitment 相同)。
   - `partition_conservation` 线性守恒性(任意 inputs/outputs/fee,reserves business_ckb xudt state_carrier sponsor 各 lane in==out 或等于 refund/fee)。
   - `factory_right_sparse_root` 顺序独立性 / 拼接单调性。
   - `factory_single_right_merkle_update` quantity decrease monotonicity。
   - SpliceHeader signing digest 字段敏感性(改任意字段 digest 必变)。
4. Property-based 测试发现的反例可以作为补充的 example-based 回归测试。

**References**: Audit response §"Implementation evidence" — 没有引用 property-based。Audit matrix 列出的所有 invariant 都是 example-based。

---

### W5-04 — `state_header_context_rejects_epoch_and_vault_set_changes` test asserts the wrong invariant for changed payload_commitment / settlement_descriptor

**Severity**: MEDIUM
**Surface**: W5 tests
**Status**: new
**Confidence**: high

**Claim**: `invariants.rs:611-626` 显式测试 `same_context_except_progress` 在 payload_commitment / settlement_descriptor_commitment 变化时仍返回 true。这把 host-side 类型的不完整性(critical fields not checked)固化为"expected behavior"。

**Evidence**:
- `/Users/arthur/RustroverProjects/morph-channel/crates/morph-core/tests/invariants.rs:611-626`:
```rust
let mut new = header_with_epoch(9, Phase::Settling, 3);
new.payload_commitment = bytes32(9);
new.settlement_descriptor_commitment = bytes32(10);

assert!(old.same_context_except_progress(&new));  // <-- 显式断言 changed-field 不影响 same_context
```
- `/Users/arthur/RustroverProjects/morph-channel/crates/morph-core/src/types.rs:62-75`: `same_context_except_progress` 实现确实不检查 `payload_commitment` / `settlement_descriptor_commitment` / `descriptor_version`。
- 但是 `/Users/arthur/RustroverProjects/morph-channel/contracts/morph-script-common/src/lib.rs:933-957`: 脚本层 `state_context_matches_splice_next` 实际检查 `settlement_descriptor_commitment` 和 `descriptor_version`,**唯独不检查** `payload_commitment`(见 W5-01)。

**Reproduction**: 看 `invariants.rs:611-626` 的三个 assertion:第一个改了 payload_commitment + settlement_descriptor,断言 same_context 是 true。第二个改了 funding_epoch,断言是 false。第三个改了 vault_set_commitment,断言是 false。

**Impact**:
- host-side `same_context_except_progress` 与 script-common `state_context_matches_splice_next` 的字段集**不一样**。Host-side 漏掉 settlement_descriptor 和 descriptor_version 检查 — 等于 host-side 把"descriptor 可在 splice 之外独立演进"当默认值,即使在 active→settling 转换里 descriptor 改了 host-side 也不报错。
- 但实际 `validate_state_transition` (`crates/morph-core/src/validation.rs:148-169`) 调用的是 host-side `require_same_header_context`,所以 host-side 漏掉的字段就是 host-side 真正不检查的字段。这与 paper 描述的"settlement descriptor 只能在 signed descriptor update 上演进"不完全一致。
- 把 bug freeze 成 test 通过 = 即使后续修 host-side 这两个字段,本测试会失败,阻碍修复。这是测试技术债。

**Suggested fix**:
1. 如果 host-side `same_context_except_progress` 应该和 script-common 对齐,把 `settlement_descriptor_commitment` 和 `descriptor_version` 加进 host-side 实现,然后把这个测试改成"changed descriptor → same_context is false"。
2. 如果 host-side 不需要和 script-common 对齐(因为它们服务不同目的),则该测试名应该是 `state_header_context_rejects_preserved_fields` 而不是 `rejects_epoch_and_vault_set_changes`,并在 doc-comment 显式说明"descriptor and payload_commitment are intentionally excluded because host-side only enforces the script-common-checked preserved set"。
3. 同时考虑是否应该在 host-side 增加 `payload_commitment` 比较(W5-01 的修复会自动闭合这条线)。

**References**: `crates/morph-core/tests/invariants.rs:611-626`、`crates/morph-core/src/types.rs:62-75`、`crates/morph-core/src/validation.rs:148-169`、`morph-script-common/src/lib.rs:933-957`。

---

### W5-05 — `state_header_digest_binds_epoch_and_vault_set` test asserts the wrong invariant for header equality baseline

**Severity**: MEDIUM
**Surface**: W5 tests
**Status**: new
**Confidence**: medium

**Claim**: `invariants.rs:588-603` 用 `header(1, Phase::Settling)` 而不是 `h1` 作为 baseline 比较 `h1` 的 signing_digest,baseline 不一致。

**Evidence**:
```rust
// /Users/arthur/RustroverProjects/morph-channel/crates/morph-core/tests/invariants.rs:588-603
let h1 = header_with_epoch(1, Phase::Settling, 3);
let mut h2 = h1.clone();
h2.funding_epoch = 4;
let mut h3 = h1.clone();
h3.vault_set_commitment = bytes32(34);

assert_ne!(h1.signing_digest(), h2.signing_digest());  // 改 epoch
assert_ne!(h1.signing_digest(), h3.signing_digest());  // 改 vault_set
assert_ne!(
    h1.signing_digest(),
    header(1, Phase::Settling).signing_digest()    // <-- baseline 是 header() 而非 header_with_epoch()
);
```
- `header()` 默认 `funding_epoch=0`,`vault_set_commitment=bytes32(33)`,而 `h1` 用 `header_with_epoch()` 是 `funding_epoch=3`,`vault_set_commitment=bytes32(33)`。这个 assertion 的本意似乎是"header 默认 vs funding_epoch=3 的 header digest 不同",但写法 `header(1, Phase::Settling)` 与 h1 已经相差 epoch=0 vs 3,所以 assertion 总是 true 即使 h1 没绑 epoch / vault_set。

**Impact**:
- 测试覆盖正确性疑点:第三个 assertion 在直觉上是"header_with_epoch(3) 跟 header() 必须不同",但因为 epoch 字段绑定已经生效,所以这个 assertion 永远 true,无法 catch 一个把 epoch 字段从 signing_digest 里偷偷删掉的 regression。
- 第二个 assertion(`assert_ne!(h1.signing_digest(), header(1, Phase::Settling).signing_digest())`)应该改成 `assert_eq!` 才合理 — 同样 funding_epoch=0 + vault_set_commitment=33 + state_number=1 + phase=Settling,header() 和 header() 的 digest 应相同。当前写法 `assert_ne!` 没意义。
- 第三个 assertion 跟第二个重复且 misleading。

**Suggested fix**:
1. 把第三个 assertion 改成跟一个真正的"non-binding" baseline 比,例如 `assert_eq!(h1.signing_digest(), h1.signing_digest())`(虽然 trivial,但是 sanity)。
2. 或者改成:声明一个 `non_signing_header()` fixture(比如改 `descriptor_version` 这种不影响 signing 的字段),然后断言 `assert_ne!(h1.signing_digest(), non_signing_header.signing_digest())`。
3. 顺便核对 `state_header_digest_binds_epoch_and_vault_set` 测试名是否符合实际 — 它声称 binds "epoch and vault_set",但缺少 state_number / chain_id / participants_commitment 等其他 binding assertion。`signing_digest_is_domain_separated_and_state_sensitive` (`invariants.rs:578-586`) 覆盖了 state_number 绑定。其他字段(chain_id / signature_scheme_id / mode / phase / participants_commitment / asset_registry_commitment / settlement_descriptor_commitment / payload_commitment / challenge_policy_commitment / state_layout_version / funding_anchor / channel_id / protocol_version)的 binding 没有单独的 digest test,只靠 `state_header_context_rejects_*` 系列。

**References**: `crates/morph-core/tests/invariants.rs:578-626`、`crates/morph-core/src/hash.rs:63-84`、`crates/morph-core/src/types.rs:40-59`。

---

### W5-06 — `molecule_schema_names_all_active_fixed_width_objects` test pins the stale SpliceHeader size, blocking schema drift detection

**Severity**: MEDIUM
**Surface**: W5 tests
**Status**: new
**Confidence**: high

**Claim**: 测试 `morph-script-common/src/lib.rs:6152-6228` 在 expected 列表里写 `"SpliceHeader: 325 bytes"`,这会跟 W5-02 一起把 schema drift 冻在测试通过里。

**Evidence**:
- `/Users/arthur/RustroverProjects/morph-channel/contracts/morph-script-common/src/lib.rs:6152-6227`: 这个 test 遍历 expected strings,在 schema 中找 substring。expected 含 `"SpliceHeader: 325 bytes"` 和 `"SpliceStateTransitionWitness: 1017 bytes"` 等。
- `/Users/arthur/RustroverProjects/morph-channel/schemas/morph.mol:14-37`: schema 的注释行写的是这些数字。
- Rust 实际 `SPLICE_HEADER_LEN = 357`、`SPLICE_STATE_TRANSITION_WITNESS_LEN = 2 + 357 + 198 + 2×132 + 228 = 1049`,跟 schema 注释的 325 / 1017 都对不上。
- 测试当前 pass 因为 expected 和 schema 都还是旧数字。

**Reproduction**:
```sh
grep -E "SpliceHeader|SpliceStateTransitionWitness" /Users/arthur/RustroverProjects/morph-channel/schemas/morph.mol
# 仍写 325 / 1017
grep -E "SPLICE_HEADER_LEN|SPLICE_STATE_TRANSITION_WITNESS_LEN" /Users/arthur/RustroverProjects/morph-channel/contracts/morph-script-common/src/lib.rs | head -2
# 357 / 1049(= 2 + 357 + 198 + 264 + 228)
```

**Impact**:
- 这个测试的设计意图是"schema 必须包含这些 wire-format invariants"。但因为 expected 字符串是从 schema 复制来的旧数字,测试不能 catch W5-02 的 drift。
- 如果未来有人把 schema 改成 357 但忘了改 Rust constant,或反之,本测试在两种情况下都 pass,失去 schema/Rust 一致性守门员作用。

**Suggested fix**:
1. 测试的 expected 不再是 schema 字符串的副本,而是 Rust 常量拼接出的 string,例如 `format!("SpliceHeader: {} bytes", SPLICE_HEADER_LEN)`。这样测试永远跟 Rust 常量一致,只在 schema 与 Rust 偏差时才 fail。
2. 或者在 expected 列表里把所有"X bytes"形式的字符串都改成"X bytes"带具体新数字,然后改 schema 让两边对齐(本质是 W5-02 的修复)。

**References**: `morph-script-common/src/lib.rs:6152-6228`、`schemas/morph.mol:14-37`。

---

### W5-07 — `molecule_schema_names_all_active_fixed_width_objects` expected list is a hand-maintained allowlist with no link to Rust constants

**Severity**: LOW
**Surface**: W5 tests
**Status**: new
**Confidence**: high

**Claim**: 测试 expected 列表(60+ 个字符串)完全手工维护,既不对 Rust 常量也不对 schema 字段做解析。

**Evidence**:
- `/Users/arthur/RustroverProjects/morph-channel/contracts/morph-script-common/src/lib.rs:6152-6227` 列出约 60 个 expected 字符串,从 "StateHeader: 314 bytes" 到 "signed_fee: uint128"。每个字符串都是字面量。
- 这意味着测试通过 ≠ schema 完整 = 代码完整。schema 里加新 struct 测试不会 fail;Rust 里加新常量测试也不会 fail;只有"expected 列表里有的字符串不在 schema 里"才 fail。
- 同样的 60+ 个字符串会随每次 Rust schema 改动需要手工同步,容易遗漏。

**Impact**:
- 给一个测试起"schema completeness check"的名字,实际只检查手工 allowlist。
- 假如 paper H-02 之后加了 `FactoryLocalExitXudtWitness: 790 bytes`,本测试不会 fail(expected 不变),但 audit-matrix 可能引用这个新 witness。

**Suggested fix**:
1. 改成 schema-driven:从 schema 文件 parse 出所有 `Name: N bytes` 行,跟 Rust 常量列表对照。
2. 至少把 expected 列表里所有形如 `"X: N bytes"` 的行改成 `format!("{}: {}", name, name_constant)` 拼接,Rust 改常量后 expected 自动跟。
3. 同时把 schema struct name 列表(expected 里 `"struct StateHeader"` 等)跟 schema 文件实际的 struct 定义对照,避免漏改。

**References**: `morph-script-common/src/lib.rs:6152-6228`。

---

### W5-08 — Hash parity test for StateHeader signing digest uses raw layout; the new `payload_commitment` field is included in `header_raw_with_anchor` but missing parity vs the new `SpliceHeader::payload_commitment`

**Severity**: MEDIUM
**Surface**: W5 tests
**Status**: new
**Confidence**: medium

**Claim**: `hash_parity.rs` 的 `splice_header_signing_digest_matches_script_common` 测试确实覆盖了 SpliceHeader payload_commitment 字段(`hash_parity.rs:152-153`),但 contract_scripts.rs 的 fixture helpers 也需要保持一致。

**Evidence**:
- `/Users/arthur/RustroverProjects/morph-channel/crates/morph-core/tests/hash_parity.rs:115-157` `splice_header_signing_digest_matches_script_common` 显式填入 `raw[293..325].copy_from_slice(&header.payload_commitment)` 和 `raw[325..357].copy_from_slice(&header.challenge_policy_commitment)`,跟 Rust 常量 357 一致。**这个测试是 pass 的,parity 存在。**
- `/Users/arthur/RustroverProjects/morph-channel/crates/morph-core/tests/contract_scripts.rs:580-584` `splice_header_bytes` helper 写:
```rust
raw[261..293].copy_from_slice(participants);
raw[293..325].fill(9);  // <-- payload_commitment 字段硬编码 fill 9
```
跟 audit-response 描述的"payload_commitment filled from current_state.header.payload_commitment"一致。但是 `raw[325..357]` 没有 fill,这跟 audit-response 描述的"challenge_policy_commitment shifting to 325"行为不一致 — challenge_policy_commitment 字段(325..357)在 helper 里完全没填,会默认 0。

**Reproduction**:
```sh
# 找到 raw[325..357] 没被填的 splice_header_bytes helper
sed -n '558,584p' /Users/arthur/RustroverProjects/morph-channel/crates/morph-core/tests/contract_scripts.rs
```

**Impact**:
- 这是一个 test helper 一致性问题。`hash_parity.rs` 的测试确实覆盖 payload_commitment 与 challenge_policy_commitment 都参与 digest,但是 `contract_scripts.rs` 的 `splice_header_bytes` helper 在 fixture 构造时只填到 293..325 (payload_commitment = 9),完全跳过 challenge_policy_commitment(325..357)。
- 对最终合约执行的影响:`challenge_policy_commitment = 0` 在大多数 fixture 里"碰巧"与 current_state 的 challenge_policy_commitment = 0 匹配,看起来测试能过。但如果未来 fixture 改了 current_state 的 challenge_policy_commitment(目前 fixture 用 `header_raw_with_anchor` 默认填 9 — 见 `contract_scripts.rs:279`),helper 会构造出 challenge_policy_commitment = 0 的 splice header,触发 SpliceProofMismatch(因为 `state_context_matches_splice_next` 比较 current_state.challenge_policy_commitment 和 next_state.challenge_policy_commitment)。
- 测试通过是因为 fixture helper 与 fixture header 都用 challenge_policy_commitment = 9(看 `header_raw_with_anchor` line 279),而 `splice_header_bytes` 写成 `[293..325].fill(9)` — 这填的其实是 payload_commitment 字段而不是 challenge_policy_commitment。**实测 splice_header_bytes helper 的 payload_commitment 字段填 9,challenge_policy_commitment 字段保持 0;而 header_raw_with_anchor 的对应字段是 payload_commitment=8,challenge_policy_commitment=9**。所以 helper 跟 header helper 的字段值不一致,导致 `matches_current_state` 检查 (`morph-script-common/src/lib.rs:644-645`) 在 fixture 构造时就匹配失败。

**Suggested fix**:
1. 仔细审计 `splice_header_bytes` helper(`contract_scripts.rs:558-584`)字段布局,核对 payload_commitment / challenge_policy_commitment 与 `header_raw_with_anchor` helper(`contract_scripts.rs:258-282`)保持一致。
2. 添加一个 parity test:从 helper 构造的 splice_header 跑 `matches_current_state` 必须返回 true(对当前 fixture 的 current_state header)。如果当前测试套件已经隐式覆盖(比如某 `state_and_vault_accept_splice_in_bridge` 测试需要 helper 通过),那 helper 与 header helper 是匹配的;否则 fixture helper 之间存在 drift。

**References**: `crates/morph-core/tests/contract_scripts.rs:258-282`、`crates/morph-core/tests/contract_scripts.rs:558-584`、`crates/morph-core/tests/contract_scripts.rs:652-668`、`morph-script-common/src/lib.rs:644`。

---

### W5-09 — `#[ignore = "requires make build-contracts"]` contract_scripts tests are not run by `make test` or `make ci` unless explicitly built

**Severity**: LOW
**Surface**: W5 tests
**Status**: new
**Confidence**: high

**Claim**: `Makefile` 上 `contract-tests` 依赖 `build-contracts`,而 `ci` 包含 `contract-tests`,所以 CI 上会跑所有 contract_scripts 测试 — 这看起来正常。但 `cargo test --workspace`(单独的 `test:` target)不会跑 ignored tests,所以 `make test` 这条命令本身不会触发 contract_scripts 的 84 个 CKB-VM 单元测试。

**Evidence**:
- `/Users/arthur/RustroverProjects/morph-channel/Makefile:15-16`: `test:` target = `$(CARGO) test --workspace`。`cargo test` 默认不跑 `#[ignore]` 测试。
- `/Users/arthur/RustroverProjects/morph-channel/Makefile:72-73`: `contract-tests:` target = `$(CARGO) test -p morph-core --test contract_scripts -- --ignored --test-threads=1`,跑 ignored。
- `/Users/arthur/RustroverProjects/morph-channel/Makefile:13`: `ci:` target = `fmt-check lint supply-chain test fixture-checks contract-tests`,包含 contract-tests。
- 但是 `/Users/arthur/RustroverProjects/morph-channel/Makefile:35-37`: `smoke:` target = `cargo test --workspace` + `cargo run validate-fixture`,**不包含** `contract-tests`。本地 dev 跑 `make smoke` 不会触发 CKB-VM 测试。
- audit-response 第 591 行写"248 workspace tests pass (1 ignored as documented above)",这个数字跟 `cargo test --workspace`(不含 ignored)对得上。

**Reproduction**:
```sh
make test    # cargo test --workspace, 不跑 ignored
make smoke   # cargo test --workspace + validate-fixture, 不跑 ignored
make ci      # 包含 contract-tests, 跑所有
make contract-tests  # 只跑 CKB-VM ignored tests, 需要 make build-contracts
```

**Impact**:
- 一个 dev 工程师跑 `make smoke` 看到所有 test pass,会以为合同层也通过。但实际合同层 84 个 CKB-VM 测试只在他显式跑 `make contract-tests`(以及 `make build-contracts`)时才跑。
- 如果有人在 contract_scripts.rs 加新测试但没加到 fixture(Makefile `fixture-checks` 之外),`make smoke` 不会发现新测试的 wire format 问题,只能靠 `make contract-tests` 才捕获。
- 不算 bug,但是 audit CI gate 的可见性不足。

**Suggested fix**:
1. 在 `Makefile` 把 `smoke:` target 改成 `smoke: build-contracts contract-tests`,这样本地 dev 也跑合同层。
2. 或者把 audit-response 的 "248 workspace tests pass" 改为分两个数字:`X workspace unit/integration tests + Y contract_scripts CKB-VM tests`。
3. CI 文档化:`make test` = fast unit/integration(不需 build-contracts),`make contract-tests` = slow CKB-VM(需 build-contracts)。

**References**: `Makefile:13`、`Makefile:15-16`、`Makefile:35-37`、`Makefile:72-73`、`audit-response-2026-06-20.md:591`。

---

### W5-10 — `Makefile` `ci:` target does not depend on `make build-contracts`; if RISC-V toolchain is missing, contract-tests silently fail

**Severity**: LOW
**Surface**: W5 tests
**Status**: new
**Confidence**: medium

**Claim**: `ci:` target 包含 `contract-tests`,但 `contract-tests:` 自身依赖 `build-contracts`。如果 CI runner 上没装 RISC-V toolchain,`build-contracts` 会失败,`contract-tests` 不会执行,但前一步 `test:` 已经通过会让 CI 看上去"绿了再红",产生混乱。

**Evidence**:
- `/Users/arthur/RustroverProjects/morph-channel/Makefile:13`: `ci:` 列了 contract-tests 但**没有**显式依赖 build-contracts;依赖通过 `contract-tests:` 内部的 `build-contracts:` 传递。
- `/Users/arthur/RustroverProjects/morph-channel/Makefile:69-73`:
```makefile
build-contracts:
    $(CONTRACT_CARGO) build --release --target riscv64imac-unknown-none-elf -p morph-state-lock ...

contract-tests: build-contracts
    $(CARGO) test -p morph-core --test contract_scripts -- --ignored --test-threads=1
```
所以 `make ci` 实际会触发 build-contracts。如果 RISC-V 工具链不在 PATH,build-contracts 会 fail,contract-tests 不会跑。
- `/Users/arthur/RustroverProjects/morph-channel/Makefile:5-9`: AUDIT_IGNORE 已经表明 CI 容忍 RUSTSEC advisory fail — 暗示该 CI 优先级是宽松的。

**Reproduction**: 见 Makefile 顺序。

**Impact**:
- CI runner 如果没装 RISC-V target,`make ci` 会在 build-contracts fail,contract-tests 不跑,导致 CKB-VM layer 没被测。如果把 contract-tests 的失败当作 warning 忽略,会错过 C-01 vault-lock payload mismatch 这种合约层回归。
- audit-response 把"248 tests pass"作为 close-verification 的核心证据,但 248 个 test 是 workspace unit/integration(不含 84 个 contract_scripts CKB-VM ignored tests)。这意味着 "248 tests pass" 实际只覆盖 C-01 在 vault lock 层的 `vault_lock_rejects_splice_new_state_payload_mismatch`(也是 ignored — 需 make build-contracts),不覆盖 C-01 在 bundle 层的 4 个 active tests(那 4 个在 morph-script-common unit test,确实 pass)。

**Suggested fix**:
1. 在 `Makefile` `ci:` target 里显式加 `build-contracts`:
```makefile
ci: fmt-check lint supply-chain build-contracts test fixture-checks contract-tests
```
2. 或者写一个 `make check-ci` script 串行 build + test + fixture + contract,失败就 exit 1。
3. 让 audit-response 的"248 workspace tests pass"加上"84 contract_scripts CKB-VM tests pass under `make contract-tests`"作为完整 CI 证据。

**References**: `Makefile:5-13`、`Makefile:69-73`、`audit-response-2026-06-20.md:591`。

---

### W5-11 — `splits_set_and_status_changes` / `comparison_limits` watchtower smoke tests are present but their regression-gate behavior is not asserted in unit tests

**Severity**: LOW
**Surface**: W5 tests
**Status**: new
**Confidence**: medium

**Claim**: `audit-matrix.md` 行 "Smoke comparison can be used as a regression gate" 引用 `comparison_limits_reject_metric_regressions` 和 `comparison_limits_reject_set_and_status_changes` 作为 gate tests。这些测试在 `crates/morph-cli/src/` 某个文件里,但是 audit-matrix 没有引用 file path,无法从 `audit-matrix.md` 直接定位。

**Evidence**:
- `/Users/arthur/RustroverProjects/morph-channel/docs/audit-matrix.md:42`: 仅列测试名,不列 file:line。
- `rg "comparison_limits_reject_metric_regressions|comparison_limits_reject_set_and_status_changes" /Users/arthur/RustroverProjects/morph-channel` 返回 audit-matrix 命中,但是没有 `.rs` 文件命中 — 这表示测试名不对应实际 test function 名字。

**Reproduction**:
```sh
rg "comparison_limits" /Users/arthur/RustroverProjects/morph-channel
# 仅在 docs/audit-matrix.md 命中
```

**Impact**:
- audit-matrix.md 是 "executable invariant matrix" — 但 `comparison_limits_reject_metric_regressions` 和 `comparison_limits_reject_set_and_status_changes` 这两个函数实际不存在,可能改名了或者从来没写。audit-matrix 声称 "Exhaust the spec via test names" 不可信。
- 即使 audit-matrix 用 audit-response 的"matrix representation"语义("test names identify bounded bodies"),这里也缺少对应的 source 引用。

**Suggested fix**:
1. audit-matrix.md 加 file:line 引用,跟 invariant → test 1:1 对应。
2. 找出这两个 test 的真实名字,可能改名了:`rg "regression|smoke_comparison|metric_regressions"` 找。
3. 如果实际不存在,audit-matrix 是 misleading 文档。

**References**: `docs/audit-matrix.md:42`。

---

### W5-12 — No negative test for `rejects_splice_state_transition_with_changed_state_layout_version` (missing C-01 coverage)

**Severity**: LOW
**Surface**: W5 tests
**Status**: new
**Confidence**: high

**Claim**: C-01 audit-response 列了 SpliceHeader 的多个守恒字段(state_number, mode, participants_commitment, settlement_descriptor, asset_registry, payload_commitment, challenge_policy_commitment 等)。script-common 加了 4 个 negative test(participants/settlement_descriptor/mode/asset_registry),但 `state_layout_version` / `signature_scheme_id` / `chain_id` / `channel_id` / `funding_epoch` / `funding_anchor` / `state_number` / `vault_set_commitment` 没有对应的"splice successor 改变"negative test — 它们通过 `state_context_matches_splice_next` 的字段集合自动覆盖,但显式 C-01 attack-style test 缺失。

**Evidence**:
- `/Users/arthur/RustroverProjects/morph-channel/contracts/morph-script-common/src/lib.rs:5786-6043` 只列了 4 个 C-01 attack-style tests:`rejects_splice_state_transition_with_changed_participants_commitment`、`rejects_splice_state_transition_with_changed_settlement_descriptor`、`rejects_splice_state_transition_with_changed_mode`、`rejects_splice_state_transition_with_changed_asset_registry`,加上 1 个 ignored `rejects_splice_state_transition_with_changed_payload_commitment`。
- 没有 `rejects_splice_state_transition_with_changed_state_layout_version`、`rejects_splice_state_transition_with_changed_signature_scheme_id`、`rejects_splice_state_transition_with_changed_chain_id`、`rejects_splice_state_transition_with_changed_channel_id`、`rejects_splice_state_transition_with_changed_funding_epoch`、`rejects_splice_state_transition_with_changed_funding_anchor`、`rejects_splice_state_transition_with_changed_state_number`、`rejects_splice_state_transition_with_changed_vault_set_commitment`。
- `state_context_matches_splice_next` 实现覆盖了 `state_layout_version` / `signature_scheme_id` / `chain_id` / `channel_id` / `funding_epoch` / `funding_anchor` / `state_number` / `vault_set_commitment`,但是没有显式 test 把每个字段独立 flip 验证。

**Impact**:
- 测试覆盖率不均匀。如果未来有人改 `state_context_matches_splice_next`,漏掉某个字段的比较,本套 negative tests 不会 fail — 因为 4 个字段只覆盖 4 个独立 case。
- paper C-01 的字段集合 12 个字段,只 4 个有 explicit attack-style negative test,8 个只靠 implementation review 来保护。

**Suggested fix**:
1. 加 8 个新的 `rejects_splice_state_transition_with_changed_<field>` tests,每个独立 flip 一个字段,断言 SpliceProofMismatch。
2. 或者把已有的 4 个 test 改用宏展开,自动对每个守恒字段生成一个 case。
3. 在 audit-response 加一句 "explicit negative tests cover 4 of 12 preserved fields; the remaining 8 fields rely on implementation review" 让 cover gap 可见。

**References**: `morph-script-common/src/lib.rs:5786-6043`、`audit-response-2026-06-20.md:124-128`、`docs/audit-matrix.md`。

---

### W5-13 — `cargo audit` Makefile ignore list excludes `RUSTSEC-2026-0097` (rand 0.7 unsound) without comment, weakening supply-chain claim

**Severity**: LOW
**Surface**: W5 tests
**Status**: new
**Confidence**: low

**Claim**: `Makefile:5-9` 把 `RUSTSEC-2026-0097` (rand 0.7 unsound) 加入 ignore 列表,但注释没明确说"upstream CKB crates move"意味着这个 advisory 会在依赖 transitive cargo 上拉进来。

**Evidence**:
- `/Users/arthur/RustroverProjects/morph-channel/Makefile:5-9`:
```makefile
# Current CKB dependencies pull transitive informational advisories for
# paste (unmaintained) and rand 0.7 (unsound). Keep vulnerability failures
# enabled while avoiding noisy warning trees until upstream CKB crates move.
# RUSTSEC-2026-0097 is the current rand advisory; RUSTSEC-2020-0097 is for xcb.
AUDIT_IGNORE ?= --ignore RUSTSEC-2024-0436 --ignore RUSTSEC-2026-0097
```

**Reproduction**: 见 Makefile。

**Impact**:
- `cargo audit` 现在对 rand 0.7 unsound 完全忽略,而 morph-core 实际使用 rand 0.x 来 derive SigningKey 等(虽然依赖 k256 — 见 `Cargo.toml:38`)。
- audit-response §"Deployment readiness statement" 提到 "supply-chain revalidation in release CI" — 当前 CI 默认 supply-chain check 是 ignore 一部分 advisory 的,跟 readiness 不一致。

**Suggested fix**:
1. 跟踪 `RUSTSEC-2026-0097` upstream 修复,定期从 ignore list 移除。
2. 把 AUDIT_IGNORE 的 ignored advisory 列表 link 到对应的 GitHub issue 或 fix-version PR。
3. 在 audit-matrix 加 "Supply chain gate excludes X advisories (tracked: <link>)" 注明当前状态。

**References**: `Makefile:5-9`、`Cargo.toml:38`、`audit-response-2026-06-20.md:605-609`。

---

## Cross-cutting observations

1. **C-01 close 状态**:`SpliceHeader` 的 `payload_commitment` 字段已加、helper 已更新、`matches_current_state` 已加入比较、5 个 negative test 全部到位(4 个 active + 1 个 ignored)。但 `state_context_matches_splice_next` 与 audit-response 文字声称不符(W5-01),且 SpliceHeader 的 Molecule schema 仍是旧 325 bytes layout(W5-02)。文字与代码不一致需要更新。
2. **fixture helper 一致性**:`contract_scripts.rs` 的 `splice_header_bytes` helper 与 `header_raw_with_anchor` helper 在 payload_commitment / challenge_policy_commitment 字段填充上不一致(W5-08),需要审计。
3. **property-based testing 缺失**(W5-03):整个 workspace 没有 proptest / quickcheck,所有 negative test 都是手工构造。建议加入 workspace dependency 并对 6 个关键 invariant 改造为 property-based。
4. **CI gate 可见性**:248 workspace tests pass 是 unit/integration 层;CKB-VM contract_tests 是 ignored,只在 `make contract-tests` 跑(W5-09, W5-10)。audit-response 的"248 tests pass"应明确分开。
5. **test freeze 风险**:`molecule_schema_names_all_active_fixed_width_objects` 把过时 schema 数字当作 expected,可能阻碍后续 schema 更新(W5-06, W5-07);`state_header_context_rejects_epoch_and_vault_set_changes` 把 host-side `same_context_except_progress` 不完整固化为"correct"(W5-04)。

## Files reviewed

- `/Users/arthur/RustroverProjects/morph-channel/crates/morph-core/tests/invariants.rs` (1463 lines, 72 tests)
- `/Users/arthur/RustroverProjects/morph-channel/crates/morph-core/tests/contract_scripts.rs` (7751 lines, 85 tests, 84 ignored)
- `/Users/arthur/RustroverProjects/morph-channel/crates/morph-core/tests/hash_parity.rs` (375 lines, 8 tests)
- `/Users/arthur/RustroverProjects/morph-channel/contracts/morph-script-common/src/lib.rs` (6855 lines, 56 tests, 1 ignored — the C-01 payload_commitment test)
- `/Users/arthur/RustroverProjects/morph-channel/schemas/morph.mol` (468 lines)
- `/Users/arthur/RustroverProjects/morph-channel/Makefile` (113 lines)
- `/Users/arthur/RustroverProjects/morph-channel/docs/devnet-audit-profile.example.json` (271 lines)
- `/Users/arthur/RustroverProjects/morph-channel/docs/devnet-smoke-budget.example.json` (246 lines)
- `/Users/arthur/RustroverProjects/morph-channel/docs/devnet-stateful-budget.example.json` (117 lines)
- `/Users/arthur/RustroverProjects/morph-channel/docs/audit-matrix.md` (191 lines)
- `/Users/arthur/RustroverProjects/morph-channel/docs/audit-response-2026-06-20.md` (614 lines)
- `/Users/arthur/RustroverProjects/morph-channel/docs/paper-implementation-audit.md` (96 lines)
- `/Users/arthur/RustroverProjects/morph-channel/Cargo.toml` (workspace root)
- `/Users/arthur/RustroverProjects/morph-channel/crates/morph-core/src/types.rs` (527 lines, types referenced by tests)
- `/Users/arthur/RustroverProjects/morph-channel/crates/morph-core/src/validation.rs` (1479 lines, validators referenced by tests)
- `/Users/arthur/RustroverProjects/morph-channel/crates/morph-core/src/hash.rs` (264 lines, signing digest referenced by tests)
- `/Users/arthur/RustroverProjects/morph-channel/contracts/morph-vault-lock/src/main.rs` (748 lines, vault-lock referenced by contract_scripts)
