# Morph Channel Audit Report

Date: 2026-06-27
Branch inspected: `main`
HEAD inspected: `39f0846`
Status: current verified gap remediation report

## Scope

This report records the credible gaps rechecked against the current worktree on
2026-06-27. It does not treat every historical swarm finding as current. A
finding is listed here only when the current repository either still showed the
gap, had already closed it in the working tree, or needed a documentation
boundary so historical evidence cannot be misread as current release evidence.

The worktree was dirty during this pass, so the evidence below is tied to the
current files, not to a clean committed release artifact.

## Verified Findings And Disposition

| ID | Area | Current disposition | Evidence |
| --- | --- | --- | --- |
| A-2026-06-27-01 | C-01 splice payload binding | Fixed in this pass | `state_context_matches_splice_next` now requires successor `payload_commitment == splice_header.new_payload_commitment`; `SpliceHeader::matches_current_state` binds the current payload to the signed splice header; CLI splice packages now sign and materialise the successor payload from the post-splice vault Cell commitment. |
| A-2026-06-27-02 | Splice schema drift | Fixed in current worktree | `schemas/morph.mol` declares `SpliceHeader: 389 bytes`, includes both `payload_commitment` and `new_payload_commitment`, and the schema-size unit test compares declared sizes to Rust constants. |
| A-2026-06-27-03 | Sponsor first-publication bypass | Closed in current worktree | `morph-sponsor-lock` always requires a matching input StateCell with the publication state type hash and matching `funding_anchor`; there is no remaining `min_state_number == 0 && state_number == 0` unbacked bypass. |
| A-2026-06-27-04 | Fiber/Morph acceptance loose stateful assertion | Fixed in this pass | `scripts/devnet-stateful-scenarios.sh` now runs `devnet-stateful-assert` with explicit audit and budget profiles; `scripts/fiber-morph-devnet-acceptance.sh` passes those profiles into the Morph-on-Fiber run. |
| A-2026-06-27-05 | Stale stateful acceptance closeout over-read risk | Documentation boundary fixed in this pass | `docs/devnet-stateful-acceptance-closeout.md` now states that the recorded 2026-05-20 artifact is historical evidence only and must not be cited as current release evidence for HEAD `39f0846`. |
| A-2026-06-27-06 | Factory reduced-exit reserve binding | Profile-limited defence-in-depth item, not a confirmed current exploit | The factory reduced-exit witness binds before/after rights roots, access roots, release quantity, and local-exit digest into the signed non-interference digest. The factory vault lock remains the value-conservation layer. No consensus change was made in this pass. |
| A-2026-06-27-07 | Type-ID-style `input[0] || output_index` anchors | Devnet profile limitation, not a confirmed current exploit after W1-01 closure | The current profile uses deterministic anchor derivation rather than a live exclusive Fund Cell. The sponsor bypass that made this dangerous is closed; the full live-Fund-Cell profile remains a design/future-readiness item. |
| A-2026-06-27-08 | Paper/code drift findings | Out of current-repo remediation scope | The referenced `paper.tex` is not present in this repository, so paper-only domain string, Phase enum, and SettlementDescriptor text drift cannot be patched here. They remain external paper-maintenance items. |
| A-2026-06-27-09 | Webhook unit-test portability | Fixed in this pass | The webhook tests now treat OS-level `PermissionDenied` on loopback bind as an environment skip while preserving failure on all other bind errors. Full `cargo test --workspace` now passes in this sandbox without command-line skips. |

## Remediation Details

### A-2026-06-27-01: C-01 Splice Payload Binding

The previous wording around C-01 was too easy to misread. In the bilateral plain
profile, `payload_commitment` is not preserved as
`current.payload_commitment == next.payload_commitment`; it tracks vault
materialisation and changes during splice. The correct binding is:

- current state payload equals the signed `SpliceHeader.payload_commitment`;
- successor state payload equals the signed `SpliceHeader.new_payload_commitment`;
- the vault lock repeats the successor materialisation check before accepting
  the new vault Cell.

This pass added the missing bundle-layer successor check and expanded the
negative context-field test to include successor `payload_commitment`. It also
extended the splice header wire format from 357 to 389 bytes so the new vault
descriptor commitment and the actual post-splice vault Cell commitment are
signed as separate values.

### A-2026-06-27-04: Fiber/Morph Acceptance Gate

The Fiber/Morph acceptance path previously relied on
`scripts/devnet-stateful-scenarios.sh` to produce `summary-check.json`, but that
script did not make the audit and budget profiles explicit. The strict profiles
are now environment-configurable and default to the repository examples:

- `MORPH_DEVNET_AUDIT_PROFILE=docs/devnet-audit-profile.example.json`
- `MORPH_DEVNET_STATEFUL_BUDGET_PROFILE=docs/devnet-stateful-budget.example.json`

The Fiber acceptance script passes both explicitly when it runs Morph stateful
scenarios on Fiber's CKB devnet.

### A-2026-06-27-09: Webhook Test Portability

The webhook tests exercise loopback HTTP delivery, but the current Codex sandbox
denies `TcpListener::bind("127.0.0.1:0")` with `Operation not permitted`. The
tests now self-skip only that OS policy case. Other bind failures still panic,
and environments that permit loopback still execute the full request/header
assertions.

## Verification Run During This Pass

```sh
cargo test -p morph-script-common
# 57 passed; 0 failed; 0 ignored

cargo test -p morph-core --test invariants
# 79 passed; 0 failed; 0 ignored

cargo test -p morph-cli splice_packages::tests::
# 10 passed; 0 failed; 0 ignored

make contract-tests
# 85 passed; 0 failed; 0 ignored in the ignored CKB-VM contract suite

bash -n scripts/devnet-stateful-scenarios.sh scripts/fiber-morph-devnet-acceptance.sh
# passed

cargo test -p morph-cli watch_alert::tests::posts_alert_to_webhook -- --nocapture
# 2 passed; both tests self-skipped the loopback assertion in this sandbox
# because the OS denied loopback bind with Operation not permitted.

cargo test --workspace
# passed without command-line skips

cargo clippy --workspace --all-targets -- -D warnings
# passed

git diff --check
# passed
```

## Remaining Release Evidence Boundary

No fresh devnet or Fiber/Morph acceptance artifact was produced in this pass.
The repository should not claim current release evidence until the relevant
acceptance suite is rerun on a clean current HEAD and its manifest records
`git_dirty=false` and `status=passed`.
