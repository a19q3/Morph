# W5 tests and CI remediation status

Date: 2026-06-27

This note records the current remediation status for `docs/swarm-audit-tests.md`.
The original audit file is historical evidence; this file is the live follow-up.

| Finding | Status | Evidence |
| --- | --- | --- |
| W5-01 | Fixed for the bilateral plain profile | `rejects_splice_state_transition_with_changed_current_payload_commitment`; `state_context_matches_splice_next` now requires the successor `payload_commitment` to equal the signed `new_payload_commitment`, and the vault lock still repeats the materialisation check against the actual post-splice vault Cell. |
| W5-02 | Fixed | `schemas/morph.mol` declares `SpliceHeader: 389 bytes` and includes both `payload_commitment` and `new_payload_commitment`. |
| W5-03 | Fixed for the requested baseline | `proptest` is wired into `morph-core` tests and covers header context/digest properties. |
| W5-04 | Fixed | Descriptor changes remain allowed as signed state updates; `rejects_unsigned_settlement_descriptor_update` covers stale-signature mutation while splice tests still reject descriptor drift across splice. |
| W5-05 | Fixed | Digest tests now isolate field mutations and cover signed context fields. |
| W5-06 | Fixed | Schema size test is constant-driven; stale copied size literals were removed. |
| W5-07 | Fixed | Schema byte sizes are parsed from the schema and compared to Rust constants. |
| W5-08 | Fixed | Splice helpers write payload and challenge policy at the current offsets. |
| W5-09 | Fixed by explicit target | `make full-test` runs workspace tests, fixture checks, and CKB-VM contract tests. `make test` remains the fast non-ignored test target. |
| W5-10 | Refuted/kept explicit | `make ci` still reaches `contract-tests`, which depends on `build-contracts`; `make -n ci` shows the RISC-V build before ignored contract tests. |
| W5-11 | Fixed | `docs/audit-matrix.md` anchors the comparison-limit tests to `crates/morph-cli/src/smoke_report.rs`. |
| W5-12 | Fixed | `rejects_splice_state_transition_with_changed_preserved_context_fields` covers the preserved splice context field set, including successor `payload_commitment` against `new_payload_commitment`. |
| W5-13 | Managed | `Makefile` documents the `rand@0.7.3` waiver tracking command and removal condition; `Cargo.lock` was also updated to `quinn-proto 0.11.15` after `cargo audit` flagged `RUSTSEC-2026-0185` in `0.11.14`. |
