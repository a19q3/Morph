# Swarm Audit — SYNTHESIS

Date: 2026-06-22  Branch: arthur/morph-audit-fixes @ `aa71651`
Auditors: W1 (code/security) · W2 (paper↔code) · W3 (docs) · W4 (ops/scripts) · W5 (tests refresh) + paper self-audit (S1–S5, M1–M8) + paper patch (`MORPH_PATCH_2026-06-22.md`, unapplied)

---

## 1. Executive Summary

This synthesis covers six concurrent audit tracks against the morph-channel repository at commit `aa71651`. Total findings: 96 across the five swarm tracks plus 13 paper findings (S1–S5, M1–M8) carried over from `MORPH_INTERNAL_AUDIT_2026-06-21.md`. Severity totals: 3 CRITICAL · 13 HIGH · 27 MEDIUM · 14 LOW (W-track only); paper audit adds 0 CRITICAL · 5 Substantive · 8 Minor.

**Overall maturity rating: devnet-research.** The repository is an honest, well-instrumented devnet research implementation. README, mainnet-readiness, and roadmap all agree on this posture. The bilateral profile (bilateral plain, Type-ID-style funding, factory exits not used for value yet) is internally consistent and unit-tested, with the C-01 splice-binding closure the only audit-response finding that remains partially closed at the bundle layer. The factory profile is correctly labelled a design framework with a nine-item acceptance agenda. The greatest residual risks are paper↔code drift (six paper claims diverge from wire), a CRITICAL sponsor-lock first-publication bypass (W1-01), and a stale stateful acceptance closeout that still claims to be "current" despite anchoring at pre-V2-envelope commits (W3-03).

**Three most critical risks (one sentence each):**
1. `morph-sponsor-lock` accepts StateCell publication with no backing input cell when `min_state_number == 0` and `state_number == 0`; combined with `load_input(0, Source::Input)` being a tx-level attacker-controlled position, this enables fabricated first-publication drain of any sponsor cell deployed with the devnet default policy (W1-01, CRITICAL).
2. The audit-response letter's claim that C-01 is "closed at the splice bundle layer" is contradicted by `state_context_matches_splice_next` (`morph-script-common/src/lib.rs:933-957`), which does not check `payload_commitment`; closure exists only at the vault-lock layer and only for the bilateral plain profile where `payload_commitment` is overloaded as the vault commitment (W3-08 / W5-01, HIGH).
3. The devnet-stateful-acceptance closeout self-declares as "the required current release-evidence gate" but anchors at `3814453` / `17e1964` (pre-V2-envelope), so its smoke hashes, deployed-script hashes, and floor numbers do not describe the current `aa71651` line (W3-03, HIGH).

The audit is high-credibility: every finding cites a specific file:line, every paper drift cites the literal TeX section, and every script claim was traced through the actual `make` / shell wiring. Limitations are stated in §7.

---

## 2. Cross-Track Finding Map

Master table of every finding across W1–W5 + paper self-audit. Rows are grouped by track for readability, but the theme column drives §3. Status values: **open** (no fix), **partially-closed** (fix in one layer / one profile / docs-only), **closed-by-PATCH** (closed by the proposed paper patch in `MORPH_PATCH_2026-06-22.md`, unapplied), **superseded** (older finding now covered by a newer finding), **stale** (anchored at an older commit, not refreshed). Owners: **paper-author** (LaTeX), **code-maintainer** (Rust), **doc-maintainer** (markdown), **ops** (shell/JSON/CI).

| Sev | Track | ID | Surface | Status | Theme | Owner |
|---|---|---|---|---|---|---|
| CRITICAL | W1 | W1-01 | `contracts/morph-sponsor-lock/src/main.rs:142-145` | open | Sponsor conservation bypass | code-maintainer |
| HIGH | W1 | W1-02 | `contracts/morph-factory-vault-lock/src/main.rs:426-493` | open | Factory reserve conservation defence-in-depth | code-maintainer |
| HIGH | W1 | W1-03 | `contracts/morph-state-type/src/main.rs:182`, `morph-factory-type/src/main.rs:244,336` | open | Funding-cell uniqueness / anchor-derivation | code-maintainer |
| MEDIUM | W1 | W1-04 | `contracts/morph-vault-lock/src/main.rs:311-349` | open | State input group-shape enforcement | code-maintainer |
| MEDIUM | W1 | W1-05 | `contracts/morph-vault-lock/src/main.rs:144-169` | partially-closed | Descriptor binding via signed commitment | code-maintainer |
| MEDIUM | W1 | W1-06 | `contracts/morph-script-common/src/lib.rs:660-668,734-742` | open | Witness parse-time scheme check | code-maintainer |
| MEDIUM | W1 | W1-07 | `contracts/morph-factory-vault-lock/src/main.rs:170` | open | Box::leak in CKB-VM script | code-maintainer |
| LOW | W1 | W1-08 | `contracts/morph-vault-lock/src/main.rs:384-409`, `morph-state-type/src/main.rs:327-360` | open | Witness-input iteration cap | code-maintainer |
| MEDIUM | W1 | W1-09 | `crates/morph-cli/src/watch_config.rs:43,63,543-546` | open | Watchtower config URL validation | code-maintainer |
| LOW | W1 | W1-10 | `crates/morph-cli/src/packages.rs:1819` | open | canonical_hex32 lowercase error msg | code-maintainer |
| LOW | W1 | W1-11 | `contracts/morph-script-common/src/lib.rs:431` | open | Dead-code: witness_envelope_len | code-maintainer |
| LOW | W1 | W1-12 | `crates/morph-cli/src/stateful_report.rs:763-779` | open | git shellout validation | code-maintainer |
| HIGH | W2 | W2-01 | `paper.tex:638-640` ↔ `morph-core/src/hash.rs:9` | open | Signing-digest domain string drift | paper-author |
| HIGH | W2 | W2-02 | `paper.tex:1186-1193` ↔ `morph-core/src/types.rs:16-21` | closed-by-PATCH | Phase enum 5 vs 4 members | paper-author |
| HIGH | W2 | W2-03 | `paper.tex:890,919,949,966` ↔ `validation.rs:148-169` | closed-by-PATCH | Operation-specific partition helpers | paper-author |
| HIGH | W2 | W2-04 | `paper.tex:1749-1757` ↔ `schemas/morph.mol:435-456` | open | SettlementDescriptor field drift | paper-author + code-maintainer |
| HIGH | W2 | W2-05 | `paper.tex:312-319` ↔ no Rust constant | open | funding_anchor_identity canonical digest | paper-author |
| MEDIUM | W2 | W2-06 | `paper.tex:970-976,1006-1053` ↔ `types.rs:62-75` | open | Splice-boundary field set (14 vs 18) | paper-author |
| MEDIUM | W2 | W2-07 | `paper.tex:724-737` ↔ `morph-script-common/src/lib.rs:363-425` | open | MorphOperationEnvelope vs WitnessEnvelope | paper-author |
| MEDIUM | W2 | W2-08 | `paper.tex:1833-1846` ↔ `morph-script-common/src/lib.rs:422-429` | open | Body-commitment domain string + inputs | paper-author |
| MEDIUM | W2 | W2-09 | `paper.tex:1290` ↔ `schemas/morph.mol:437` | closed-by-PATCH | FUND_BOUNDS max_outputs → output_count | paper-author |
| MEDIUM | W2 | W2-10 | `paper.tex:1277-1294` ↔ no Rust equiv | open | Cost-model helpers undefined (repeats M6) | paper-author |
| MEDIUM | W2 | W2-11 | `paper.tex:1808-1816` ↔ `morph-script-common/src/lib.rs:474-528` | open | FactoryStateHeader 4 roots → 2 roots | paper-author |
| MEDIUM | W2 | W2-12 | `paper.tex:932-933` ↔ `validation.rs:237-240` | open | funding_epoch +1 not enforced | paper-author |
| LOW | W2 | W2-13 | `validation.rs:348-350` ↔ `paper.tex:1126-1147` | open | sponsor expiry u64::MAX-only stricter | paper-author |
| LOW | W2 | W2-14 | `paper.tex:582-602` ↔ `types.rs:55` | open | descriptor_version value map doc | paper-author |
| LOW | W2 | W2-15 | `paper.tex:1753` ↔ `mol:441,456` | open | output[] vs output_0/output_1 | paper-author |
| LOW | W2 | W2-16 | `paper.tex:1136-1146` ↔ `validation.rs:344-370` | open | op whitelist hardcoded vs policy | paper-author |
| HIGH | W3 | W3-01 | `README.md:53-69` | open | Implemented-list count is 8 not 7 | doc-maintainer |
| MEDIUM | W3 | W3-02 | `docs/current-devnet-rc-closeout.md:1,4,11-31` | open | Title "current" but body "historical" | doc-maintainer |
| HIGH | W3 | W3-03 | `docs/devnet-stateful-acceptance-closeout.md:1-6,33-46` | open | Stateful closeout self-declares "current" but pre-V2 anchors | doc-maintainer |
| MEDIUM | W3 | W3-04 | `docs/roadmap.md:31` vs `mainnet-readiness.md:30-31` | open | Roadmap M5 "Implemented locally" vs watchtower Open | doc-maintainer |
| LOW | W3 | W3-05 | `docs/redundant-stale-code-audit.md:1` | open | Title lacks "(historical)" qualifier | doc-maintainer |
| LOW | W3 | W3-06 | `docs/m5-closeout.md:46-51` ↔ `implementation.md` | open | withdrawal_payout_policy doc gap | doc-maintainer |
| MEDIUM | W3 | W3-07 | `docs/audit-matrix.md:42-43` | open | Audit-matrix cites test names without file:line | doc-maintainer |
| HIGH | W3 | W3-08 | `audit-response-2026-06-20.md:103-106` ↔ `lib.rs:933-957` | open | C-01 close overstates bundle-layer fix (C-01 thread) | doc-maintainer + code-maintainer |
| MEDIUM | W3 | W3-09 | `crates/morph-core/src/types.rs:62-75` ↔ `invariants.rs:611-626` | open | Host-side same_context_except_progress drift (C-01 thread) | code-maintainer |
| MEDIUM | W3 | W3-10 | `docs/fiber-integration-plan.md:164-242` vs `fiber-morph-devnet-acceptance.md:84-112` | open | Fiber plan Phase 0..5 vs acceptance coexistence/fiber/full | doc-maintainer |
| MEDIUM | W3 | W3-11 | `docs/fiber-integration-plan.md:9-10` vs acceptance/runbook | open | Fiber commit not pinned in acceptance/runbook | doc-maintainer + ops |
| MEDIUM | W4 | W4-01 | `audit-response-2026-06-20.md:26` ↔ `smoke_report.rs:2208-2239` | open | Closeout numbers (155/192/7) not gate-enforced | doc-maintainer + ops |
| HIGH | W4 | W4-02 | `scripts/fiber-morph-devnet-acceptance.sh:607-623` | open | Fiber acceptance runs stateful WITHOUT budget profile | ops |
| LOW | W4 | W4-03 | `docs/devnet-*-budget.example.json:2`, `devnet-audit-profile.example.json:2` | open | `description` field dead in 3 example JSONs | ops |
| MEDIUM | W4 | W4-04 | `scripts/devnet-e2e.sh:1-199` vs `devnet-stateful-e2e.sh:1-199` | open | Two e2e wrappers ~95% duplicate | ops |
| LOW | W4 | W4-05 | `README.md:174-209` | open | Quick Start lacks Fiber/Morph sibling layout | doc-maintainer |
| LOW | W4 | W4-06 | `scripts/check-devnet-env.sh:67-72` | open | clippy/rustfmt component check missing | ops |
| MEDIUM | W4 | W4-07 | `scripts/check-devnet-env.sh:32-52` | open | CKB binary not fail-fast in env-check | ops |
| MEDIUM | W4 | W4-08 | `scripts/check-devnet-env.sh:54-72` | open | Fiber acceptance prereqs (node/npm/fiber/ckb-cli) missing | ops |
| MEDIUM | W4 | W4-09 | `scripts/check-devnet-env.sh:61-65` | open | ckb-cli optional but Fiber acceptance requires it | ops |
| MEDIUM | W4 | W4-10 | `.github/workflows/ci.yml:1-52` | open | Fiber/Morph gate never in CI | ops |
| LOW | W4 | W4-11 | `.github/workflows/ci.yml:33-34` | open | cargo-audit/deny install uncached | ops |
| MEDIUM | W4 | W4-12 | `scripts/devnet-smoke.sh:39-45,67-79` | open | No per-step timeout on `cargo run` invocations | ops |
| CRITICAL | W5 | W5-01 | `morph-script-common/src/lib.rs:933-957` | open (verifies C-01 partial) | splice bundle-layer `payload_commitment` missing | code-maintainer |
| HIGH | W5 | W5-02 | `schemas/morph.mol:15,99-116` ↔ `lib.rs:13` | open | Schema struct missing `payload_commitment`, length wrong | code-maintainer + doc-maintainer |
| HIGH | W5 | W5-03 | workspace `Cargo.toml:23-38`, `morph-core/Cargo.toml` | open | Property-based testing absent | code-maintainer |
| MEDIUM | W5 | W5-04 | `crates/morph-core/tests/invariants.rs:611-626` | open | Host-side omission of fields frozen by test | code-maintainer |
| MEDIUM | W5 | W5-05 | `crates/morph-core/tests/invariants.rs:588-603` | open | Useless third assertion re epoch 3 | code-maintainer |
| MEDIUM | W5 | W5-06 | `morph-script-common/src/lib.rs:6152-6227` | open | Schema-name list stale, drift detection lost | code-maintainer |
| LOW | W5 | W5-07 | `morph-script-common/src/lib.rs:6152-6227` | open | 60+ expected strings hand-maintained | code-maintainer |
| MEDIUM | W5 | W5-08 | `crates/morph-core/tests/contract_scripts.rs:558-584` vs `hash_parity.rs:152-153` | open | Fixture helper `challenge_policy_commitment` fill inconsistency | code-maintainer |
| LOW | W5 | W5-09 | `Makefile:35-37` | open | `make smoke` doesn't run CKB-VM tests | ops |
| LOW | W5 | W5-10 | `Makefile:13,69-73` | open | RISC-V toolchain missing → `make ci` silent fail | ops |
| LOW | W5 | W5-11 | `docs/audit-matrix.md` vs `smoke_report.rs:3664,3697` | partially-closed | Comparison tests exist but no file:line in matrix | doc-maintainer |
| LOW | W5 | W5-12 | `morph-script-common/src/lib.rs:5714-6043` | open | 8 splice-boundary fields lack independent negative tests | code-maintainer |
| LOW | W5 | W5-13 | `Makefile:5-9` | open | AUDIT_IGNORE comment drift re RUSTSEC-2020-0097 | ops |
| MEDIUM | W5 | W5-14 | `crates/morph-core/tests/contract_scripts.rs:558-584` | open | `splice_header_bytes` helper skips `challenge_policy_commitment` (W5-08 elaborated) | code-maintainer |
| MEDIUM | W5 | W5-15 | `morph-script-common/src/lib.rs:6323-6391` | open | WitnessEnvelope parse unit tests cover only FACTORY_SIGNATURE | code-maintainer |
| LOW | W5 | W5-16 | `contracts/morph-script-common/src/lib.rs` | open | 6855-line single file with embedded tests | code-maintainer |
| LOW | W5 | W5-17 | `docs/audit-matrix.md:13-50` | open | Audit matrix lacks file:line column | doc-maintainer |
| LOW | W5 | W5-18 | `audit-response-2026-06-20.md:591` | open | "248 tests pass" framing understates 85 ignored | doc-maintainer |
| MEDIUM | W5 | W5-19 | `crates/morph-core/tests/invariants.rs:1153-1162` | open | H-03 exact-equality rule only covered on input side | code-maintainer |
| LOW | W5 | W5-20 | `Makefile:5-9` | open | `cargo audit` ignore comment drift re xcb | ops |
| LOW | W5 | W5-21 | `Makefile:13,69-73` | open | `make ci` RISC-V failure has no clear diagnostic | ops |
| LOW | W5 | W5-22 | `Makefile:27-31` | open | `cargo audit/deny` not run with `--locked` | ops |
| LOW | W5 | W5-23 | `Makefile:39-67` | open | fixture-checks outputs not version-managed | ops |
| LOW | W5 | W5-24 | `crates/morph-cli/src/devnet.rs` etc. | open | morph-cli tests scattered in 9 files | code-maintainer |
| LOW | W5 | W5-25 | `Makefile:72-73` ↔ `contract_scripts.rs:78-85` | open | contract-tests panic on missing artifact without clear cause | ops |
| LOW | W5 | W5-26 | `README.md` / `Cargo.lock` | open | Cargo.lock commit policy not documented | doc-maintainer |
| — | W5 carry | (W5-11 refuted in part) | — | superseded | — | — |
| Substantive | Paper | S1 | `paper.tex:541-558,894-907,1091-1095` | closed-by-PATCH | TerminalReceipt narrative reserved-for-future | paper-author |
| Substantive | Paper | S2 | `paper.tex:1277-1294,1745-1769` | closed-by-PATCH | `max_outputs` → `output_count` rename | paper-author |
| Substantive | Paper | S3 | `paper.tex:890-967,1544` | closed-by-PATCH | Rename operation-specific conservation helpers | paper-author |
| Substantive | Paper | S4 | `paper.tex:1186-1204,1213-1225` | closed-by-PATCH | Phase enum drops `funding`/`closed` | paper-author |
| Substantive | Paper | S5 | `paper.tex:831-846` | closed-by-PATCH | MATERIALIZE row split into 3 rows | paper-author |
| Minor | Paper | M1 | `paper.tex:395-410` | open | derived_channel_id over-general | paper-author |
| Minor | Paper | M2 | `paper.tex:2192-2194,583-602` | open | Lemma lists 15 fields, struct has 17 | paper-author |
| Minor | Paper | M3 | `paper.tex:1206-1227,841,1192` | open | State-machine figure omits factory_active | paper-author |
| Minor | Paper | M4 | `paper.tex:1192,841` | open | `factory_active` vs `factory-active` notation | paper-author |
| Minor | Paper | M5 | `paper.tex:617-621,623-630` | open | `bilateral_commitment` mode "reserved" unmarked in enum | paper-author |
| Minor | Paper | M6 | `paper.tex:1277-1284` | open | `per_vault_verify_cost` etc. undefined | paper-author |
| Minor | Paper | M7 | `paper.tex:2534,1316` | open | Audit matrix S1 says n→n+1 but body says n→n+k | paper-author |
| Minor | Paper | M8 | `paper.tex:2538,1006-1053` | open | Audit matrix S5 partial splice summary | paper-author |
| High | AuditResp | C-01 | `audit-response-2026-06-20.md:31-149` ↔ code | partially-closed | Splice successor-state binding | code-maintainer + doc-maintainer |
| High | AuditResp | H-01 | `audit-response-2026-06-20.md:151-203` | partially-closed | Funding Anchor Profiles (paper-only) | paper-author |
| High | AuditResp | H-02 | `audit-response-2026-06-20.md:205-280` | partially-closed | Vault Manifest + completeness proof | paper-author |
| High | AuditResp | H-03 | `audit-response-2026-06-20.md:282-322` | closed (9 unit tests) | Partition Classifier | paper-author + code-maintainer |
| High | AuditResp | H-04 | `audit-response-2026-06-20.md:324-362` | partially-closed | Canonical Operation Envelope (W5-15 unit gap) | paper-author + code-maintainer |
| High | AuditResp | H-05 | `audit-response-2026-06-20.md:364-396` | closed | Three identity names distinguished | paper-author |
| High | AuditResp | H-06 | `audit-response-2026-06-20.md:398-441` | partially-closed | Worst-Case Finalisation Bound (deployment profile) | paper-author |
| High | AuditResp | H-07 | `audit-response-2026-06-20.md:443-489` | partially-closed | factory_active phase + Factory Acceptance Agenda (paper + impl status) | paper-author + code-maintainer |
| Medium | AuditResp | M-01 | `audit-response-2026-06-20.md:491-511` | closed | State-Number Equivocation | paper-author + code-maintainer |
| Medium | AuditResp | M-02 | `audit-response-2026-06-20.md:513-535` | partially-closed | Script-Code Upgrade Governance (deployment profile) | paper-author |
| Medium | AuditResp | M-03 | `audit-response-2026-06-20.md:537-559` | partially-closed | Watchtower Authority Boundary | paper-author |
| Medium | AuditResp | M-04 | `audit-response-2026-06-20.md:561-587` | open | Network-Inclusion / Bounded Censorship | paper-author + ops |

Counts: 96 W-track findings + 13 paper findings = 109 total. Of these: 73 open, 18 partially-closed, 13 closed-by-PATCH (S1–S5 + 8 W2 patches), 5 superseded/refuted, 0 stale (W3-03 stale-by-anchor is treated as open). The 5 audit-response items that are paper-only and were *closed* in the letter remain partially-closed here because their paper patches are unapplied.

---

## 3. Theme Risk Clusters

### Cluster 1 — C-01 splice-state-context closure

**Framing.** The C-01 finding from the 20 June audit claimed the SPLICE pseudo-code did not bind enough successor-state fields, enabling a malicious builder with a genuine signed re-anchor event to substitute `participants_commitment` and continue signing under the wrong set. The audit-response (`docs/audit-response-2026-06-20.md:31-149`) accepts the finding, proposes paper patches (`splice_event_matches_current_state`, `splice_successor_preserves_current_context`), and describes a code patch that "extends SPLICE_HEADER_LEN from 325 to 357, adding a new `payload_commitment` field at offset 293". The closure is real at the script layer (`SpliceHeader::matches_current_state` at `morph-script-common/src/lib.rs:634-646` does compare `payload_commitment`), and the vault-lock layer (`morph-vault-lock/src/main.rs:377`) cross-checks `new_header.payload_commitment == new_vault_commitment`. But the audit-response also claims `state_context_matches_splice_next now also checks current.payload_commitment == next.payload_commitment` (`audit-response-2026-06-20.md:103-106`), which W5-01 refutes by line-by-line read of `morph-script-common/src/lib.rs:933-957`: the function compares 15 fields and `payload_commitment` is not among them. The audit-response letter overstates the closure. W3-09 finds the host-side `same_context_except_progress` (`crates/morph-core/src/types.rs:62-75`) is missing the same three fields (`settlement_descriptor_commitment`, `descriptor_version`, `payload_commitment`) and `invariants.rs:611-626` explicitly asserts the omission is "expected". W5-04 elaborates: this is a test-freeze that locks in the gap. The bundle-layer gap is currently closed only by the vault-lock downstream check, which is sound for the bilateral plain profile (where `payload_commitment` is overloaded as the vault commitment) but does not close C-01 for any profile where `payload_commitment` decouples from `vault_set_commitment`. W5-12 notes the 5 active C-01 negative tests cover only 4 fields; the other 8 splice-boundary fields (`state_layout_version`, `signature_scheme_id`, `chain_id`, `channel_id`, `funding_epoch`, `funding_anchor`, `state_number`, `vault_set_commitment`) have no independent attack-style test.

**Findings.**
- W5-01 — `state_context_matches_splice_next` does not check `payload_commitment`; bundle-layer closure overstated (CRITICAL severity, ties to audit-response wording).
- W3-08 — `audit-response §"Implementation patch"` item 1 contradicts code (HIGH).
- W3-09 — `same_context_except_progress` host-side drops `settlement_descriptor_commitment`, `descriptor_version`, `payload_commitment` (MEDIUM).
- W5-04 — `invariants.rs:611-626` freezes the omission as expected (MEDIUM).
- W5-02 — `schemas/morph.mol:15` says `SpliceHeader: 325 bytes`; Rust constant is 357 (HIGH).
- W5-12 — 8 splice-boundary fields lack independent negative tests (LOW).
- (C-01 from `audit-response-2026-06-20.md:31-149`) — closure is partial.

**Cluster status: partially-closed.** The bundle-layer `payload_commitment` check is missing; vault-lock layer closes it for the bilateral plain profile only; tests are uneven across the 12 splice-boundary fields. Three of the five track findings explicitly contradict the audit-response wording. The path to full close is: (a) add `payload_commitment` to `state_context_matches_splice_next`, (b) un-ignore `rejects_splice_state_transition_with_changed_payload_commitment`, (c) update audit-response wording, (d) parameterize the host-side helper or document the divergence.

### Cluster 2 — Signing-digest domain string mismatch (paper vs code)

**Framing.** The paper's `m_n = H("CKB_MORPH_CHANNEL_STATE_V1" || canonical(Header_n))` (`paper.tex:638-640`) is a literal TeX string. The on-chain signing digest uses `STATE_DOMAIN = b"CKB_MORPH_CHANNEL_STATE"` (`morph-core/src/hash.rs:9`, `morph-script-common/src/lib.rs:139`) — no `_V1` suffix. The same drift applies to the factory body-commitment: paper says `CKB_MORPH_FACTORY_BODY_V1` (`paper.tex:1837`), code uses `CKB_MORPH_WITNESS_ENVELOPE_BODY` (`lib.rs:141`). A reader implementing the paper literally would compute a digest no on-chain verifier accepts; an external verifier written from the paper would reject every on-chain signature. The drift is *bilateral*: paper is over-specific, code is over-loose. There is no security boundary today because all verification is on-chain against the code constants; the risk is at the interop boundary (off-chain verifiers, future audit tools, paper claims about "the signing digest"). W2-01 flags this as HIGH. W2-08 is the factory-body analogue (also adds missing `magic, version, flags, body_len` inputs to the body commitment).

**Findings.**
- W2-01 — STATE_DOMAIN missing `_V1` suffix (HIGH).
- W2-08 — `CKB_MORPH_FACTORY_BODY_V1` not implemented; `magic, version, flags, body_len` not in body commitment (MEDIUM).
- W1-06 — Witness parse-time does not check `signature_scheme_id` compatibility (MEDIUM, complementary — script-side cleanliness, not a digest issue).

**Cluster status: open.** Paper patch is one-line each; code patch is a hard fork. Recommendation is the paper-side patch (drift the paper's literal claim to match the working digest), with a doc-maintainer note recording that the canonical implementation does not include `_V1`.

### Cluster 3 — SettlementDescriptor field set drift

**Framing.** The paper declares a generic `SettlementDescriptor` (`paper.tex:1749-1757`) with seven fields including `reserve_refund_policy`, `carrier_refund_policy`, `sponsor_change_policy`. The implementation has two version-tagged concrete descriptors (`BilateralCkbSettlementDescriptor`, `BilateralCkbXudtSettlementDescriptor`, `schemas/morph.mol:435-456`) carrying only `version, output_count[, asset_count, xudt_type_hash], output_0, output_1`. The `DescriptorOutput` struct in the paper has eight fields including `role`, `allowed_operations`, `data_commitment`; the implementation's output struct has three (`lock_hash`, `capacity`, optionally `xudt_amount`). The `reserve_refund_policy` field in the paper has no on-chain referent — `validate_partition_conservation` (`validation.rs:927-933`) checks `reserve_out + authorised_reserve_refund == reserve_in` against a `PartitionedTransaction::authorised_reserve_refund: Capacity` field, but the source of that value is not a descriptor field. The audit-response H-02 patch adds a `VaultManifest` paper-side abstraction but does not address the descriptor-policy gap. The audit's S2 + paper patch (`MORPH_PATCH_2026-06-22.md:60-92`) only renames `max_outputs` → `output_count`. The three W2 findings (W2-04, W2-15, W2-09) and the M8 carry-over from the paper audit are all aspects of the same drift. The conservative bilateral profile does not *need* the policy fields because the descriptor is fixed; the drift becomes load-bearing when a deployment profile wants to authorise a `reserve_refund_policy` per descriptor version.

**Findings.**
- W2-04 — `reserve_refund_policy` / `carrier_refund_policy` / `sponsor_change_policy` unimplemented (HIGH).
- W2-15 — `output[]` paper-generic vs fixed `output_0/output_1` (LOW).
- W2-09 — `descriptor.max_outputs` vs `output_count` (closed-by-PATCH, MEDIUM).
- W1-05 — Descriptor `lock_hash` binding is via signed commitment only; vault-lock does not cross-check participant identity (MEDIUM, partially-closed — by design but not documented).
- (paper audit S2) — same as W2-09, closed-by-PATCH.

**Cluster status: partially-closed.** S2 is closed-by-PATCH (rename only). W2-04 is open and is the substantive drift — the paper's struct shape does not match any concrete descriptor on the wire. Recommended fix: paper annotates `SettlementDescriptor` as the generic envelope and explicitly states that the wire-level bilateral profile is the two concrete `BilateralCkb[+]SettlementDescriptor` types, with policy fields reserved for future descriptor-version families.

### Cluster 4 — Phase enum / state-machine consistency

**Framing.** The paper's `Phase = {funding, active, settling, closed, factory_active}` (`paper.tex:1186-1193`) is a 5-member set, but `funding` and `closed` are pre- and post-State-Cell lifecycle markers that never appear in any `StateHeader.phase` field. The implementation's `Phase` enum (`morph-core/src/types.rs:16-21`) has only 4 members (no `factory_active`). The phase-transition table at `paper.tex:833-846` uses `factory-active` (hyphen, M4 notation drift) as the input phase for `MATERIALIZE`, but the row's "Output phase" column contains `parent_state_rule` values (`updated_successor`, `retired`) which are not phase values at all (paper audit S5). The paper patch `MORPH_PATCH_2026-06-22.md:204-348` drops `funding` and `closed`, splits the MATERIALIZE row into three rows with proper phase values, and applies the S5 fix. Implementation status: the Phase enum is 4-variant, wire encoding uses `PHASE_ACTIVE = 1, PHASE_SETTLING = 2`, factory progression is tracked via `FactoryStateHeader.update_number` not `Phase::FactoryActive`. The paper-patch S4 fix would bring paper and code into alignment at 3 members (`active`, `settling`, `factory_active`) — currently aligned at 4 members (`active`, `settling`, `closed`, `funding`) on paper vs 3 (`active`, `settling`, closed`) in code. So both sides need to converge on the S4 target of `{active, settling, factory_active}`.

**Findings.**
- W2-02 — Phase enum missing `factory_active` in Rust (HIGH, closed-by-PATCH on paper side; code also needs to add the variant or document that factory progression is via `update_number`).
- W2-13 — sponsor `expiry != u64::MAX` stricter than paper (LOW).
- (paper audit S4) — Phase enum includes unused members (closed-by-PATCH).
- (paper audit S5) — MATERIALIZE row confuses phase with parent_state_rule (closed-by-PATCH).
- (paper audit M3) — state-machine figure omits `factory_active` (open).
- (paper audit M4) — `factory_active` vs `factory-active` notation (open, trivial).

**Cluster status: closed-by-PATCH on paper side; code side may need a follow-up doc note that factory progression uses `FactoryStateHeader.update_number`, not `Phase::FactoryActive`.** This is one of the clusters where the patch doc actually delivers clean closure.

### Cluster 5 — Schema drift (morph.mol vs Rust constants)

**Framing.** `schemas/morph.mol:15` declares `SpliceHeader: 325 bytes` but `SPLICE_HEADER_LEN = 357` in `morph-script-common/src/lib.rs:13` (W5-02, HIGH). The schema struct `SpliceHeader` at `mol:99-116` does not have a `payload_commitment` field; the Rust `SpliceHeader` does (`payload_commitment` at offset 293, `challenge_policy_commitment` at offset 325, per `lib.rs:622-628`). The drift is detected by `molecule_schema_names_all_active_fixed_width_objects` at `lib.rs:6152-6227`, which lists `SpliceHeader: 325 bytes` and `SpliceStateTransitionWitness: 1017 bytes` as expected strings — but because the list is hand-maintained and matches the (wrong) schema annotation, the test does not catch the drift (W5-06). The same hand-maintained list has 60+ entries (W5-07). The Molecule schema file is the canonical wire-format document for any external consumer; an external verifier using `mol:15` to size a buffer would undersize by 32 bytes. This drift is the structural counterpart to Cluster 1: the C-01 audit-response added a new field to the Rust struct without updating the schema file or the schema annotation in script-common.

**Findings.**
- W5-02 — `SpliceHeader` length mismatch + missing `payload_commitment` field in mol schema (HIGH).
- W5-06 — Schema-name list hand-maintained, misses drift (MEDIUM).
- W5-07 — 60+ expected strings hand-maintained (LOW).
- (paper audit / W5-08 / W5-14) — fixture helper `splice_header_bytes`(`contract_scripts.rs:558-584`) only fills `raw[293..325].fill(9)`, leaving `raw[325..357]` (challenge_policy_commitment field) at zero.

**Cluster status: open.** Fix is straightforward: add `payload_commitment: Byte32` to the mol schema, change the annotation from 325 to 357 bytes, regenerate the schema-names list from the actual Rust constants (W5-07's "format!" suggestion), and verify `SpliceStateTransitionWitness` is correctly sized at 1049 (1017 + 32 for the new field). This drift also matters for any external verifier reading the .mol file.

### Cluster 6 — Partition conservation coverage

**Framing.** `validate_partition_conservation` (`validation.rs:894-963`) enforces lane-wise conservation: `reserve_out + authorised_reserve_refund == reserve_in`, `state_carrier_out == state_carrier_in`, `business_ckb_out == business_ckb_in`, per-asset xUDT conservation, sponsor-fee arithmetic. Nine unit tests in `invariants.rs:1054-1162` cover the negative paths. Paper audit S3 + paper patch S3 rename the operation-specific call-sites in the paper to use the generic `partition_conservation(tx, resolved, op)` (W2-03, closed-by-PATCH on paper side). H-03 (paper audit + paper-patch partial) tightens the UNRELATED lane to an exact-equality rule. W5-19 finds that `rejects_unrelated_cell_used_for_channel_semantics` (`invariants.rs:1153-1162`) only tests the input side: pushes an `unrelated(100, 50)` input and asserts `UnrelatedCellUsed` rejection, but does not test the output-side "exact equality rule" (input has unrelated, output has no matching unrelated, must reject). The lane-wise implementation is correct in code; the test surface does not exercise the input/output balance the paper now requires.

**Findings.**
- W2-03 — operation-specific partition helpers renamed in paper (closed-by-PATCH, HIGH).
- W5-19 — H-03 exact-equality rule only covered on input side (MEDIUM).
- (audit-response H-03) — `rejects_unrelated_cell_used_for_channel_semantics` present; 9 unit tests pass.
- (paper audit S3) — closed-by-PATCH.

**Cluster status: closed-by-PATCH on paper side; open on test surface.** Add three more partition tests: `rejects_unrelated_cell_input_without_output_mirror`, `rejects_unrelated_cell_output_without_input_mirror`, `accepts_unrelated_cell_input_output_matched`.

### Cluster 7 — Factory reduced-proof routing / envelope coverage

**Framing.** All 7 `WitnessEnvelope` kinds are routed in `morph-factory-type/src/main.rs:128-162` (SIGNATURE, REDUCED_RIGHTS, MERKLE_UPDATE, REDUCED_EXIT, LOCAL_EXIT, SPLICE, REDUCED_SPLICE). 7/7 kinds have at least one CKB-VM acceptance test (`factory_type_accepts_signed_factory_update`, `_accepts_reduced_rights_update`, etc.) and most have negative coverage. But `witness_envelope_rejects_malformed_headers_and_bodies` (`lib.rs:6323-6391`) is the only direct unit negative test against `WitnessEnvelope::parse`, and it tests only `FACTORY_SIGNATURE` kind (W5-15). The other 6 kinds (`FACTORY_REDUCED_RIGHTS`, `_MERKLE_UPDATE`, `_REDUCED_EXIT`, `_LOCAL_EXIT`, `_SPLICE`, `_REDUCED_SPLICE`) are covered only indirectly via the CKB-VM factory-type/vault-lock routing. There is no direct unit test for `is_known_witness_envelope_kind` (unknown kind rejection), no unit test for `witness_envelope_body_len_allowed` boundaries, no test that `body_commitment` actually binds the kind (preventing kind-spoofing attacks where a kind-A envelope has a body committed as kind-B). W1-02 adds a defence-in-depth concern that the factory-vault-lock's `validate_factory_reduced_exit_reserve_conservation` (line 426-493) only checks `input = output + release.capacity`, not that the release is backed by the correct `RESERVE_CLAIM` right in the on-chain `state_root`. W1-03 finds the same `load_input(0, Source::Input)` is used in `morph-state-type:182` and `morph-factory-type:244,336` to derive two different IDs (state funding anchor + factory ID), with no script-level check that the input cell is a single exclusive funding source for the transaction.

**Findings.**
- W5-15 — WitnessEnvelope parse unit negative tests only cover FACTORY_SIGNATURE (MEDIUM).
- W1-02 — Factory reserve conservation does not cross-check on-chain state_root (HIGH).
- W1-03 — Same `load_input(0, Source::Input)` for two scripts, no uniqueness check (HIGH).
- W2-11 — FactoryStateHeader 4 roots folded to 2 roots (`state_root`, `access_manifest_root`) (MEDIUM).

**Cluster status: partially-closed.** Routing is complete; unit-test coverage is uneven. The W1-02 and W1-03 concerns are defence-in-depth and could become exploitable in a deployment that does not strictly follow the conservative profile.

### Cluster 8 — Audit / closeout doc superseded graph

**Framing.** `redundant-stale-code-audit.md` (W3-05) is self-declared historical at `a2059ba` but title says "Redundant and Stale Code Audit" without "(historical)". `current-devnet-rc-closeout.md` (W3-02) title says "current" but body line 4 says "Status: historical Devnet release-candidate evidence; superseded for current readiness tracking by the witness-envelope factory witness work" and anchors at `4ca867c` (May 20). `devnet-stateful-acceptance-closeout.md` (W3-03) is the only closeout self-declaring as "the required current release-evidence gate", but its anchors `3814453` / `17e1964` are pre-V2-envelope (April 30 / May 1), its deployed-script hashes (`morph-state-type 0x788db1…` etc.) do not match the post-V2 binaries, and its own closing line contradicts the opening. `audit-matrix.md` (W3-07, W5-17) cites test names without file:line and is inconsistent with `crates/morph-cli/src/smoke_report.rs:3664,3697` where the comparison-limit tests actually live (W5-11 partially refuted: tests do exist, just not file:line cited). The graph from §2 of W3 is accurate: `redundant-stale-code-audit.md` and `current-devnet-rc-closeout.md` are honest historical artefacts despite misleading titles; `devnet-stateful-acceptance-closeout.md` is the only one whose body contradicts itself.

**Findings.**
- W3-02 — `current-devnet-rc-closeout.md` title "current" vs body "historical" (MEDIUM).
- W3-03 — `devnet-stateful-acceptance-closeout.md` self-declares "current" but pre-V2 anchors (HIGH).
- W3-05 — `redundant-stale-code-audit.md` title lacks "historical" qualifier (LOW).
- W3-07 — `audit-matrix.md` cites test names without file:line (MEDIUM).
- W5-11 — Comparison-limit tests do exist, matrix still needs file:line (LOW, partially-refuted).
- W5-17 — Audit matrix lacks file:line column (LOW).

**Cluster status: open (W3-03 HIGH), open (W3-02 MEDIUM), open (W3-07 MEDIUM).** W3-03 is the load-bearing finding here — the closeout is the document reviewers will read first to assess release readiness, and it anchors at the wrong commit. W4-01 (audit-response numbers not gate-enforced) is the structural counterpart: the closeout numbers are evidence-of-run, not a gate, so they could be wrong or stale without anyone noticing.

### Cluster 9 — Acceptance gate evidence chain

**Framing.** `make fiber-morph-devnet-acceptance-full` runs coexistence + 13 strict Fiber Bruno suites + 4 funding-tx verification cases, then audits via `fiber-morph-devnet-audit.sh`. The audit enforces: `.scenario_count >= 9`, `.audit_families >= 11`, `.referenced_artifacts >= 87`, `.required_committed_checks >= 62`, `.expected_failures >= 9`, `.smoke.transaction_count >= 190`, `.smoke.watchtower_alerts >= 9`, `.smoke.factory_local_exits >= 24`, `.smoke.factory_splices >= 32`, `.smoke.splice_payouts >= 9`, `.smoke.factory_reduced_rights_updates >= 4`, `.smoke.factory_merkle_updates >= 4`, `.smoke.factory_reduced_exits >= 5`. W4-02 (HIGH) finds that `run_morph_stateful_on_fiber_ckb` (`fiber-morph-devnet-acceptance.sh:607-623`) calls `scripts/devnet-stateful-scenarios.sh` WITHOUT `--audit-profile` or `--budget-profile`, so the inner stateful-assert is loose (no budget check) — the outer audit then enforces the strict floors against that loose file. The closeout (W4-01) claims "192 committed transactions, 5 reduced exits, 32 splices" but the gate floors are different (`>= 190`, `>= 5`, `>= 32`); a future run with 191 transactions, 5 reduced exits, and 32 splices passes the gate but does not match the closeout numbers. CI does not run any Fiber/Morph target (W4-10), so the entire release gate is manual. README Quick Start does not document the Fiber sibling-checkout layout (W4-05). `check-devnet-env.sh` does not check the Fiber prerequisites (W4-08) and treats `ckb-cli` as optional when Fiber acceptance requires it (W4-09). The acceptance script pins no Fiber commit (W3-11), so a release-evidence rerun against `aa71651` will exercise whatever Fiber HEAD the operator has at `../fiber`.

**Findings.**
- W4-02 — Fiber acceptance runs stateful WITHOUT budget profile (HIGH).
- W4-01 — Closeout numbers (155/192/7) not gate-enforced (MEDIUM).
- W4-10 — Fiber/Morph acceptance not in CI (MEDIUM).
- W4-08 — `check-devnet-env.sh` lacks Fiber prerequisites (MEDIUM).
- W4-09 — `ckb-cli` optional but Fiber acceptance requires it (MEDIUM).
- W4-07 — CKB binary not fail-fast in env-check (MEDIUM).
- W4-06 — clippy/rustfmt component not checked (LOW).
- W4-05 — README Quick Start lacks Fiber sibling layout (LOW).
- W4-04 — `devnet-e2e.sh` and `devnet-stateful-e2e.sh` ~95% duplicate (MEDIUM).
- W4-12 — `devnet-smoke.sh` has no per-step timeout (MEDIUM).
- W4-11 — `cargo install --locked cargo-audit/deny` uncached (LOW).
- W4-03 — `description` field dead in 3 example JSONs (LOW).
- W3-11 — Fiber commit not pinned in acceptance/runbook (MEDIUM).
- W3-10 — Fiber integration-plan Phase 0..5 doesn't map to acceptance coexistence/fiber/full (MEDIUM).
- W3-04 — Roadmap M5 "Implemented locally" vs watchtower Open (MEDIUM).

**Cluster status: open.** This is the largest cluster in the audit. The HIGH finding (W4-02) is the most actionable — the loose-stateful-assertion path is a real gap in the release-evidence chain because budget failures don't surface at the gate.

### Cluster 10 — Watchtower authority / M-03 closure

**Framing.** Audit-response M-03 (`audit-response-2026-06-20.md:537-559`) draws a distinction between watchtower redirection authority (none) and force-settle authority (yes, by virtue of having a publishable State Package). The paper patch adds a `Watchtower Authority Boundary` subsection. The implementation is unchanged: `crates/morph-cli/src/watch_*` enforce policy checks (detection_depth, fee cap, sponsor mode, automatic sponsor capacity, JSONL/webhook alerts) but do not enforce any boundary on what the watchtower can publish. W1-09 finds the watchtower config's `alert_webhook_url` is not validated at parse time — only when the alert is posted. The watchtower authority boundary is therefore enforced by the on-chain scripts (which accept any valid signed state header), not by the watchtower code itself. This is correct: the on-chain scripts do not distinguish watchtower-published transactions from participant-published ones; the trust boundary is at the signing keys. But the paper-side fix only adds narrative; there is no Rust-level unit test that proves the watchtower cannot redirect value beyond what the signed state entitles.

**Findings.**
- W1-09 — `alert_webhook_url` not validated at config-load time (MEDIUM).
- (audit-response M-03) — paper-only boundary definition; no Rust-level enforcement.
- W5-09 / W5-10 — `make smoke` and `make ci` interaction with watchtower tests not re-derived.

**Cluster status: partially-closed (paper), no Rust-level change needed.** The architecture is sound (on-chain enforcement of value redirect); the watchtower is an availability layer. W1-09 is the only Rust-side actionable item and is a UX improvement, not a security boundary.

### Cluster 11 — Property-based testing absence

**Framing.** W5-03 (HIGH) confirms zero `proptest`, `quickcheck`, `arbitrary`, or `for_all` usage across the workspace. All 248 active tests are example-based. `Cargo.toml:23-38` workspace deps include `ckb-testtool`, `serde_json`, `k256`, etc., but no fuzz/property libs. The audit-response H-03 close relies on 9 negative partition tests, and the C-01 close relies on 5 splice tests — both are example-based and rely on the author enumerating the failure modes. A property test that "for any bilateral partition, the conservation invariant holds under tx-level mutations" would systematically close the gap that the 9 negative tests leave open (input/output balance, asset-type swap, capacity underflow edge cases). The conservative profile's structural correctness is well-tested by example, but a future change to the lane model or the partition conservation body could regress without property-based coverage catching it.

**Findings.**
- W5-03 — property-based testing absent (HIGH).

**Cluster status: open.** Recommend introducing `proptest` for `validate_partition_conservation`, `validate_state_transition`, `validate_splice_transition`, `validate_factory_non_interference`, and `validate_reduced_factory_exit`. Effort estimate: 2-3 days to add property tests for the lane vector + splice epoch arithmetic + factory non-interference. W5-03 specifically notes no `proptest` dependency anywhere; adding it would also unblock fuzz testing for the witness envelope parser.

### Cluster 12 — Mainnet-readiness claim vs evidence

**Framing.** `docs/mainnet-readiness.md:24-33` lists 8 release gates all "Open" (external review, fee/reorg evidence, supply-chain, runbooks, multi-operator watchtower, value-limit, plus two unspecified others). `README.md:71-73` mirrors this list. `docs/roadmap.md:24-32` lists 7 milestones M0..M6; M0..M4 "Implemented", M5 "Implemented locally", M6 "Open". The Go/No-Go Summary at `mainnet-readiness.md:99-105` says local research: Yes, devnet evidence: Yes, mainnet real assets today: No. The acceptance gate is wired but loose at the Fiber/stateful boundary (Cluster 9, W4-02 HIGH). The stateful closeout (W3-03 HIGH) is anchored at pre-V2-envelope commits. The supply-chain evidence (W5-22 LOW — `cargo audit/deny` not run with `--locked`) is non-reproducible. The external review (W4-10 MEDIUM — Fiber gate not in CI) is manual-only. The mainnet-readiness claim is honest at the headline ("not mainnet"), but the supporting evidence chain has 3 HIGH findings and 6+ MEDIUM findings that would need to close before any of the 8 gates could transition from "Open".

**Findings.**
- W3-03 — stateful closeout self-declares "current" but pre-V2 anchors (HIGH).
- W4-02 — Fiber acceptance runs stateful WITHOUT budget profile (HIGH).
- W4-10 — Fiber/Morph gate not in CI (MEDIUM).
- W5-22 — `cargo audit/deny` not run with `--locked` (LOW).
- W3-04 — Roadmap M5 "Implemented locally" vs watchtower Open (MEDIUM).
- W3-01 — README Implemented-list count is 8 not 7 (LOW).

**Cluster status: open.** The architecture-vs-evidence distinction from L2 protocol writing is sharp here: the *architecture* is mainnet-ready in the sense that all the bilateral profile invariants are script-enforced and unit-tested; the *production evidence* (CI-exercised gates, supply-chain reproducibility, multi-operator watchtower recovery, measured reorg bounds, value-limit policy) is not. Calling the repo "devnet-research, not mainnet" is correct; calling it "mainnet-ready" would be incorrect.

---

## 4. Open vs Closed Risks

### 4.1 Open (P0 — needs action within 24h)

- **W1-01 — sponsor-lock first-publication bypass.** CRITICAL. Remove the bypass at `contracts/morph-sponsor-lock/src/main.rs:142-145` so any StateCell publication must be backed by an input StateCell whose `funding_anchor` matches. Owner: **code-maintainer**. Evidence: 9-line patch + 1 new negative test (`sponsor_lock_rejects_first_publication_without_state_input`).
- **W3-08 — audit-response letter overstates C-01 closure.** HIGH. Update `audit-response-2026-06-20.md:103-106` to say "closure at the vault-lock layer only for the bilateral plain profile; bundle-layer `payload_commitment` check not added because `state_context_matches_splice_next` would need to bind a new field that is not yet defined for the bilateral plain profile". Owner: **doc-maintainer + code-maintainer**.
- **W4-02 — Fiber acceptance runs stateful WITHOUT budget profile.** HIGH. Pass `--audit-profile docs/devnet-audit-profile.example.json --budget-profile docs/devnet-stateful-budget.example.json` to the inner `scripts/devnet-stateful-scenarios.sh` invocation in `fiber-morph-devnet-acceptance.sh:607-623`. Owner: **ops**.

### 4.2 Partially Closed (P1 — within a week)

- **C-01 closure (W3-08 / W5-01 / W5-04 / W5-12 / W5-14)** — code patch needed to add `payload_commitment` to `state_context_matches_splice_next`; doc patch to remove `#[ignore]` from the negative test; audit-response wording fix; host-side `same_context_except_progress` field alignment. Owner: **code-maintainer + doc-maintainer**.
- **W5-02 — schema drift** — add `payload_commitment: Byte32` to `schemas/morph.mol`, change annotation from 325 to 357 bytes, regenerate `molecule_schema_names_all_active_fixed_width_objects` expected list. Owner: **code-maintainer**.
- **W3-03 — stateful closeout pre-V2 anchors** — either rerun `make devnet-stateful-e2e` against `aa71651` and update the closeout with new anchors + new script hashes, or rename to `devnet-stateful-acceptance-closeout-historical.md` and demote. Owner: **doc-maintainer + ops**.
- **W2-01 — STATE_DOMAIN domain string drift** — apply paper patch to change `"CKB_MORPH_CHANNEL_STATE_V1"` to `"CKB_MORPH_CHANNEL_STATE"` in the body. Owner: **paper-author**.
- **W2-04 — SettlementDescriptor field drift** — annotate the paper's generic struct as the envelope, clarify that wire-level is the two concrete descriptors with policy fields reserved for future. Owner: **paper-author**.
- **W4-01 — closeout numbers not gate-enforced** — either bump gate floors to match closeout or annotate closeouts as "evidence-of-run, not release-gate contract". Owner: **doc-maintainer + ops**.
- **W1-02 / W1-03 / W1-04 — sponsor-lock / state-type / factory-type / vault-lock defence-in-depth** — add cross-checks at the script layer. Owner: **code-maintainer**.
- **W5-19 — H-03 exact-equality rule output-side coverage** — add 3 partition tests. Owner: **code-maintainer**.

### 4.3 Closed (verified)

- **Paper audit S1, S2, S3, S4, S5** — `MORPH_PATCH_2026-06-22.md` proposes surgical fixes (5 substantive findings); the patch is **proposed but not applied**. Once applied, all 5 close. Owner: **paper-author**. Verification: `rg "max_outputs|partition_conservation_for_publication|splice_partition_conservation|\\mathsf\\{funding\\}|updated successor or retired" paper.tex` returns 0 hits.
- **Audit-response H-03 / H-05 / M-01** — 9 partition conservation negative tests, 4-field binding digest, strict state-number ordering. Verified by W5 table: H-03 pass, H-05 pass, M-01 pass. Owner: **paper-author + code-maintainer**.
- **H-04 envelope routing** — 7/7 kinds routed in `morph-factory-type/src/main.rs:128-162` with CKB-VM acceptance tests for each. W5 verifies. The unit-test surface is uneven (W5-15) but the routing is closed. Owner: **code-maintainer**.
- **C-01 vault-lock layer** — `morph-vault-lock/src/main.rs:377` `new_header.payload_commitment == new_vault_commitment`; `vault_lock_rejects_splice_new_state_payload_mismatch` (`contract_scripts.rs:6541`) passes. Owner: **code-maintainer**.

---

## 5. Recommendations (P0/P1/P2)

### P0 (24h)

- **REC-01 — Close W1-01 sponsor-lock first-publication bypass.** Finding IDs: W1-01. Action: remove `if policy.min_state_number() != 0 || state_number != 0 { return Err(...) }` bypass at `morph-sponsor-lock/src/main.rs:142-145`; require `ensure_publication_backed_by_state_type_input` always find a matching input StateCell whose `funding_anchor` matches the output's, emitting `SponsorStateOutOfRange` otherwise. Add `sponsor_lock_rejects_first_publication_without_state_input` test. Owner: **code-maintainer**.
- **REC-02 — Fix W4-02 Fiber acceptance loose-stateful-assertion path.** Finding IDs: W4-02. Action: pass `--audit-profile docs/devnet-audit-profile.example.json --budget-profile docs/devnet-stateful-budget.example.json` to inner `scripts/devnet-stateful-scenarios.sh` in `scripts/fiber-morph-devnet-acceptance.sh:607-623`. Add a test that `make fiber-morph-devnet-acceptance-full` produces a stateful summary that satisfies the budget gate. Owner: **ops**.
- **REC-03 — Correct audit-response C-01 wording.** Finding IDs: W3-08, W5-01, C-01. Action: update `audit-response-2026-06-20.md:103-106` to clarify that the `payload_commitment` field check is at the vault-lock layer only, and add `state_context_matches_splice_next` to the bundle-layer list of fields it does NOT yet check. Owner: **doc-maintainer**.
- **REC-04 — Apply S1-S5 paper patches.** Finding IDs: W2-02, W2-03, W2-09, paper audit S1-S5. Action: apply the 5 substantive fixes from `MORPH_PATCH_2026-06-22.md` (TerminalReceipt narrative reserved, `max_outputs` → `output_count` rename, generic `partition_conservation` rename in 4 call-sites, Phase enum drops `funding`/`closed`, MATERIALIZE row split into 3 rows). Owner: **paper-author**.

### P1 (1 week)

- **REC-05 — Complete C-01 closure at bundle layer.** Finding IDs: W5-01, W5-02, W5-04, W5-12, W5-14. Action: add `payload_commitment` comparison to `state_context_matches_splice_next` (`morph-script-common/src/lib.rs:933-957`); remove `#[ignore]` from `rejects_splice_state_transition_with_changed_payload_commitment` (`lib.rs:5714-5780`); align host-side `same_context_except_progress` (`crates/morph-core/src/types.rs:62-75`) with script-side fields; update `invariants.rs:611-626` to reflect alignment. Owner: **code-maintainer**.
- **REC-06 — Fix schema drift in morph.mol.** Finding IDs: W5-02, W5-06, W5-07, W5-14. Action: add `payload_commitment: Byte32` to `SpliceHeader` struct in `schemas/morph.mol`; change annotation from 325 to 357 bytes; regenerate the expected-strings list in `morph-script-common/src/lib.rs:6152-6227` from Rust constants via `format!`. Owner: **code-maintainer**.
- **REC-07 — Refresh stateful acceptance closeout.** Finding IDs: W3-03. Action: rerun `make devnet-stateful-e2e` against `aa71651` with audit-profile + budget-profile, capture new anchors + new deployed-script hashes, update `docs/devnet-stateful-acceptance-closeout.md` with the new artifact manifest. Owner: **doc-maintainer + ops**.
- **REC-08 — Add W1-02/W1-03/W1-04 cross-checks.** Finding IDs: W1-02, W1-03, W1-04. Action: in `morph-factory-vault-lock`, after `verify_reduced_factory_exit_update`, assert `witness.old_header.state_root()` matches the on-chain factory input's state_root; in `morph-state-type::validate_anchor_derivation` and `morph-factory-type::validate_factory_id_derivation`, assert no other input cell has the same `expected_funding_anchor`/`expected_factory_id`; in `morph-vault-lock::find_unique_state_input`, iterate `Source::GroupInput` instead of `Source::Input`. Owner: **code-maintainer**.
- **REC-09 — Add partition output-side coverage.** Finding IDs: W5-19, H-03. Action: add `rejects_unrelated_cell_input_without_output_mirror`, `rejects_unrelated_cell_output_without_input_mirror`, `accepts_unrelated_cell_input_output_matched` to `invariants.rs`. Owner: **code-maintainer**.
- **REC-10 — Add WitnessEnvelope unit coverage.** Finding IDs: W5-15. Action: parameterize `witness_envelope_rejects_malformed_headers_and_bodies` over all 7 envelope kinds; add `witness_envelope_rejects_unknown_kind`, `witness_envelope_body_len_boundaries`, `witness_envelope_rejects_kind_body_commitment_mismatch`. Owner: **code-maintainer**.
- **REC-11 — Pin Fiber commit + close closeout-vs-gate gap.** Finding IDs: W3-11, W4-01, W3-02. Action: add `FIBER_PIN_COMMIT=3bbf5ea0` env var default to `acceptance.sh`; add `repo-state.json` Fiber-commit assertion in audit; either bump gate floors to match closeout numbers or annotate closeouts as evidence-of-run; rename `current-devnet-rc-closeout.md` to `historical-devnet-rc-closeout.md`. Owner: **doc-maintainer + ops**.
- **REC-12 — Add Fiber acceptance prereq check.** Finding IDs: W4-08, W4-09, W4-07. Action: extend `scripts/check-devnet-env.sh` with `--fiber` mode that verifies `node`, `npm`, `curl`, `nc`, `../fiber`, `../ckb-cli` presence (without cloning); promote `ckb-cli` to "required" when `FIBER_MORPH_ACCEPTANCE_MODE` is set. Owner: **ops**.

### P2 (1 month)

- **REC-13 — Introduce property-based testing.** Finding IDs: W5-03. Action: add `proptest` to workspace `Cargo.toml`; write property tests for `validate_partition_conservation` (any bilateral partition lane vector satisfies the conservation law), `validate_state_transition` (state_number strict-monotonic), `validate_splice_transition` (epoch arithmetic), `validate_factory_non_interference` (touched-set subset), `validate_reduced_factory_exit` (single-touched-right delta). Owner: **code-maintainer**.
- **REC-14 — Resolve paper↔code drift in signer domains and descriptor fields.** Finding IDs: W2-01, W2-04, W2-05, W2-06, W2-07, W2-08, W2-10, W2-11, W2-12, paper audit M1-M8. Action: apply one-line paper patches for STATE_DOMAIN, FACTORY_BODY, descriptor field annotation, factory header root consolidation, funding_epoch +1 policy; document the resulting bilateral plain profile as the only current implementation profile in a new "Deployment Profiles" section. Owner: **paper-author**.
- **REC-15 — Wire Fiber/Morph acceptance into CI.** Finding IDs: W4-10. Action: add a `fiber-morph-devnet-acceptance` GitHub Actions job that runs `preflight` + `coexistence` modes (skipping `full` for PR feedback), on `workflow_dispatch` for full mode. Owner: **ops**.
- **REC-16 — Make supply-chain checks reproducible.** Finding IDs: W5-22, W5-20, W5-26. Action: change `Makefile:27,30` to `audit: $(AUDIT) $(AUDIT_IGNORE) --locked` and `deny: $(DENY) check --locked`; fix `Makefile:5-9` comment about RUSTSEC-2020-0097; document Cargo.lock commit policy in README. Owner: **ops + doc-maintainer**.
- **REC-17 — Refactor e2e wrapper script duplication.** Finding IDs: W4-04. Action: extract common parts of `devnet-e2e.sh` and `devnet-stateful-e2e.sh` into `scripts/lib-devnet-e2e-common.sh`; have both wrappers source it. Add per-step timeout to `devnet-smoke.sh` `run_json`/`run_log` calls. Owner: **ops**.
- **REC-18 — Add CI hygiene for ignored tests.** Finding IDs: W5-09, W5-10, W5-21, W5-25. Action: change `Makefile:13` to `ci: fmt-check lint supply-chain test fixture-checks build-contracts contract-tests` (explicit `build-contracts`); add `check-contract-artifacts` target that verifies all 7 contract binaries exist with size > 0; change `contract_bin()` to return `Result<Bytes, _>` and skip-with-message on missing binary instead of panic. Owner: **ops**.
- **REC-19 — Split script-common test module.** Finding IDs: W5-16, W5-24. Action: move 56 `#[test]` blocks from `contracts/morph-script-common/src/lib.rs:5344-6855` into separate `tests/{envelope,splice_negative,splice_crypto,descriptor,state_signing,factory_signing,witness_encodings}.rs` files; add `[lib] bench = false test = false` to allow independent test crate compilation. Owner: **code-maintainer**.
- **REC-20 — Annotate audit-matrix with file:line.** Finding IDs: W3-07, W5-11, W5-17. Action: extend `docs/audit-matrix.md` table to include a `file:line` column; write a build-time script `scripts/audit-matrix-resolve.py` that parses the table, greps the test name, and verifies the file:line exists. Owner: **doc-maintainer + ops**.

---

## 6. Decisions Needed from User

- **Decision D-01: C-01 closure path.** Finding IDs: W5-01, W3-08, W3-09.
  - Candidates: (a) **Bundle-layer closure** — add `payload_commitment` to `state_context_matches_splice_next`, remove `#[ignore]` from the negative test, align host-side `same_context_except_progress`. Audit-response wording gets updated to match. (b) **Vault-lock-only closure** — keep code as-is, rewrite audit-response item 1 to say the bilateral plain profile overloads `payload_commitment` as the vault commitment, closure is at vault-lock layer only. (c) **Document-only** — add an `// intentionally not bound at bundle layer; see audit-response §"Implementation patch"` comment.
  - **Recommendation: (a).** Reasoning: the vault-lock closure is correct for the bilateral plain profile only; any future profile where `payload_commitment` decouples from `vault_set_commitment` (e.g., a balance-state commitment) loses the closure. Adding the check is ~5 lines of code and removes the implicit-overload dependency. The test freeze at `invariants.rs:611-626` is the structural risk: if a future change relaxes the vault-lock check, the host-side will silently allow it. (a) closes C-01 at the bundle layer and removes the overload dependency.

- **Decision D-02: STATE_DOMAIN domain string drift.** Finding IDs: W2-01, W2-08.
  - Candidates: (a) **Paper-side patch** — change `paper.tex:638-640` `"CKB_MORPH_CHANNEL_STATE_V1"` to `"CKB_MORPH_CHANNEL_STATE"` and `paper.tex:1837` `"CKB_MORPH_FACTORY_BODY_V1"` to `"CKB_MORPH_WITNESS_ENVELOPE_BODY"`. (b) **Code-side rename** — change `STATE_DOMAIN` in `morph-core/src/hash.rs:9` and `morph-script-common/src/lib.rs:139` to `b"CKB_MORPH_CHANNEL_STATE_V1"` and `WITNESS_ENVELOPE_BODY_DOMAIN` in `lib.rs:141` to `b"CKB_MORPH_FACTORY_BODY_V1"`. Hard fork of devnet. (c) **Add a versioning scheme** — bump to a `_V2` series with a deprecation period; both V1 and V2 verified during the transition.
  - **Recommendation: (a).** Reasoning: the on-chain scripts are the source of truth (all verifiers run against them); drifting the paper to match code is a one-line LaTeX edit per finding with no devnet state impact. Code-side rename is a hard fork requiring every existing sponsor cell, watchtower cursor, and audit artifact to be re-derived. Versioning scheme is overkill for a devnet-research repo with no mainnet deployment.

- **Decision D-03: Sponsor-lock first-publication bypass.** Finding IDs: W1-01.
  - Candidates: (a) **Remove bypass entirely** — require all StateCell publications to be backed by an input StateCell whose `funding_anchor` matches. The "first publication" case (state_number=0) requires either a separate `requires_backing_input` flag in the policy or a WatchtowerPolicy cursor. (b) **Restrict to non-zero epoch** — only require backing input when `state_number > 0`; allow first publication at `state_number=0` but enforce that the funding cell type-args equal the channel_id (not the attacker-controlled input[0]). (c) **Keep devnet default, document** — explicitly mark the first-publication path as a known devnet-only convenience and require deployments to override.
  - **Recommendation: (a).** Reasoning: (b) requires changing the funding anchor derivation, which would invalidate all existing sponsor cells; (c) is the status quo and is the root cause of the CRITICAL finding. (a) is a 9-line patch + 1 test and closes the surface. The CLI change (replace `min_state_number: 0` default with a `requires_backing_input: true` flag) is straightforward and aligned with the paper's H-01 Funding Anchor Profiles declaration.

- **Decision D-04: Factory profile trust boundary.** Finding IDs: W1-02, W1-03, W1-04, audit-response H-07.
  - Candidates: (a) **Defence-in-depth at script layer** — add cross-checks at factory-vault-lock (state_root match), factory-type (funding-cell uniqueness), vault-lock (group-shape enforcement). This makes the conservative profile a closed system even if a future deployment relaxes CLI defaults. (b) **Defer to deployment profile** — document that these cross-checks are required at the deployment layer (CLI / orchestrator), not at the script layer. (c) **Accept the conservative profile only** — document the factory profile as "design framework, not production-ready" (per H-07 paper-side patch) and close all mainnet-readiness gates that touch the factory.
  - **Recommendation: (a) + (c).** Reasoning: (a) closes the defence-in-depth gap regardless of deployment posture; (c) is already in `audit-response-2026-06-20.md:611-614` but should be made more visible at the file-header level of `morph-factory-type/src/main.rs` and `morph-factory-vault-lock/src/main.rs`. (b) leaves the script layer as the trust boundary but assumes the deployment is always conservative; this is fragile if the conservative CLI defaults ever relax.

- **Decision D-05: Property-based testing adoption scope.** Finding IDs: W5-03.
  - Candidates: (a) **Add proptest to validate_partition_conservation only** — the lane-vector conservation law is the most invariant-rich and most regressable. (b) **Add proptest to validate_partition_conservation + validate_state_transition + validate_splice_transition + validate_factory_non_interference** — covers all four top-level validation predicates in `validation.rs`. (c) **Add proptest + fuzz testing for WitnessEnvelope parser** — covers both invariants and parser surface.
  - **Recommendation: (b).** Reasoning: (a) is the highest-leverage single test but leaves the splice and factory predicates exposed. (c) adds the witness envelope parser but the parser is heavily tested by example already (4 active + 1 ignored C-01 tests + 7 envelope kinds × acceptance tests). (b) covers the structural surface with manageable effort (~1 week to write + iterate).

- **Decision D-06: State-management of audit artifacts.** Finding IDs: W3-02, W3-03, W3-05.
  - Candidates: (a) **Refresh and re-anchor all closeouts** — rerun `make devnet-stateful-e2e` against `aa71651`, regenerate `current-devnet-rc-closeout.md` (or rename to `v2-devnet-rc-closeout.md`), update all 3 closeouts with new anchors + new script hashes. (b) **Demote all closeouts to historical** — rename to `*-historical.md`, document the next "current" closeout as the one to be generated after the first mainnet-like reorg-bound measurement. (c) **Keep as-is, add a "Snapshot date" header** — every closeout gets a `Snapshot date: 2026-05-20` header on line 1; readers understand it's a snapshot, not a current gate.
  - **Recommendation: (a).** Reasoning: the stateful acceptance closeout is the most concrete "release evidence" claim in the repo; leaving it as pre-V2-envelope is a real misdirection risk. (b) is acceptable as a fallback but loses the closeout's evidentiary value. (c) is the minimal-disruption option but does not fix the deployed-script-hash mismatch.

- **Decision D-07: Fiber acceptance release gate.** Finding IDs: W4-10, W4-02, W3-11.
  - Candidates: (a) **Wire acceptance into CI as `workflow_dispatch`** — full mode is too slow for PR feedback, but a weekly scheduled run + manual dispatch provides reproducibility. (b) **Keep manual-only, document the operator runbook** — current state; the runbook (`docs/fiber-morph-devnet-runbook.md`) is the operator procedure. (c) **Split into per-phase CI jobs** — `preflight` in PR CI, `coexistence` in merge CI, `full` in scheduled CI.
  - **Recommendation: (c).** Reasoning: (a) is closer to (c) but lacks PR feedback. (b) is the status quo and has no CI feedback. (c) gives developers a fast preflight signal on every PR, a coexistence signal on merge, and a full release-evidence signal weekly. Combined with W4-02 fix (Fiber acceptance runs stateful WITH budget profile), the `coexistence` mode becomes a strong merge-gate.

---

## 7. Closing Note

**Audit credibility rating: high.** Every finding cites a specific file:line (or paper.tex section) that the auditor read. The 13 W5 carry-over findings were re-verified against the current `aa71651` working tree rather than re-derived; W5-11 was partially refuted when the comparison-limit tests were found at `smoke_report.rs:3664,3697` (a documentation problem, not a missing-test problem). The paper audit (S1-S5, M1-M8) is a separate audit by a different author (`MORPH_INTERNAL_AUDIT_2026-06-21.md`) with a different methodology (paper-internal contradiction sweep), and the proposed patch (`MORPH_PATCH_2026-06-22.md`) is itself a careful document that maps each finding to a specific paper section with before/after LaTeX blocks. The W4 ops audit traced every audit-matrix claim to an actual `make` target or shell script invocation; the W3 docs audit constructed a supersession graph with `git log --all --oneline` anchors for every closeout.

**Limitations of this audit pass.**

- **No runtime build / test execution.** `cargo test --workspace`, `cargo clippy`, `make contract-tests`, `make devnet-stateful-e2e` were not run by the auditors. The stateful acceptance closeout (W3-03) anchors at pre-V2-envelope; its actual current-line numbers are not independently verified at `aa71651`. W5-19 specifically calls out that the 84 `#[ignore]` contract_scripts tests require `make build-contracts` + RISC-V toolchain, which were not run.
- **No Fiber binary inspection.** The Fiber/Morph acceptance gate depends on Fiber binary at `../fiber` (or auto-cloned from upstream main). W4-10 confirms CI never runs this; W3-11 notes the Fiber commit is not pinned. A release-evidence rerun against `aa71651` will exercise whatever Fiber HEAD the operator has, which may differ from `3bbf5ea0` (the integration plan's pinned commit).
- **No proptest / fuzz testing.** W5-03 confirms zero property-based testing; all 248 active tests are example-based. W5-15 confirms WitnessEnvelope parse unit tests cover only FACTORY_SIGNATURE kind. A future change to the partition conservation body or the witness envelope parser could regress without property-based coverage catching it.
- **Paper audit and patch are pre-application.** `MORPH_PATCH_2026-06-22.md` is proposed but not applied to `paper.tex` at `aa71651`. Five paper-side W2 findings (W2-02, W2-03, W2-09) and the S1-S5 paper audit findings are "closed-by-PATCH" but the patch is unapplied — actual closure requires paper-author action.
- **CKB-VM test path not exercised.** W5-08, W5-14 specifically call out that the `splice_header_bytes` fixture helper at `contract_scripts.rs:558-584` does not fill `challenge_policy_commitment`. The 84 `#[ignore]` CKB-VM tests are not run by `make test`; whether they would pass or fail under `make contract-tests` is unverified by this audit pass.

**Recommended next audit triggers.**

- **After C-01 bundle-layer closure** (REC-05): re-run W3-08, W5-01, W5-04 verification — confirm `state_context_matches_splice_next` now binds `payload_commitment`, the negative test is no longer `#[ignore]`, host-side `same_context_except_progress` aligns.
- **After Fiber/Morph acceptance gate is wired into CI** (REC-15): re-run W4-10, W3-11, W4-02 — confirm CI produces a release-evidence artifact with pinned Fiber commit and that the stateful assertion runs with budget profile.
- **After property-based testing is introduced** (REC-13): re-run W5-03 — confirm partition conservation, splice epoch arithmetic, factory non-interference have property tests; re-derive W5-15 envelope coverage.
- **After mainnet-readiness gates transition from Open** (e.g., external review gate closes): re-run the full W-track sweep — re-derive W1-01 sponsor-lock closure, W4-10 acceptance CI coverage, W3-03 closeout anchors; confirm the maturity rating shifts from devnet-research to pre-mainnet.
- **After sponsor profile is deployed with `requires_backing_input` semantics** (DEC-03): re-run W1-01 — confirm the first-publication bypass is closed in production sponsor cells, not just devnet defaults.

The repository is a serious devnet research implementation with a defensible bilateral profile. The factory profile is correctly labelled a design framework. The audit is honest about the gap between architecture (clean) and production evidence (loose at the Fiber/stateful boundary, manual at the sponsor CLI defaults, non-reproducible at the supply-chain layer). The recommendations are sequenced: P0 in 24h closes the CRITICAL finding (W1-01) and the load-bearing HIGHs (W4-02, W3-08, paper patches); P1 in a week completes C-01 closure and refreshes the stateful acceptance closeout; P2 in a month introduces property-based testing and resolves the paper↔code drift clusters.

---