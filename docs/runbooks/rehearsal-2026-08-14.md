# Factory v1.0 Runbook Rehearsal — 2026-08-14

This is the repository-side rehearsal for the controlled-devnet
`factory-v1.0-fixed-bilateral` candidate. It validates that a release operator
can execute the documented gates from the candidate worktree. It is not the
independent multi-operator rehearsal still required for a production claim.

## Environment

| Item | Value |
| --- | --- |
| Base commit | `b91caa8` plus the candidate changes in this branch |
| Rust toolchain | 1.92.0 (repository-pinned) |
| Contract target | `riscv64imac-unknown-none-elf` |
| Network | No-value local CKB devnet evidence from the same base commit |
| Secret handling | No secret values recorded in this log |

## Executed Checks

| Procedure | Result |
| --- | --- |
| `cargo check -p morph-cli --all-features` | Passed |
| Release manifest unit tests | 2 passed |
| Pre-production envelope unit tests | 4 passed |
| Watch cursor/reorg targeted tests | Passed, including canonical match, hash mismatch reset, and legacy cursor reset |
| `make build-contracts` | Passed; seven release ELFs built |
| Manifest generation | Seven CKB data hashes and sizes recorded in the committed manifest |
| Clean independent target-directory rebuild | Passed; all seven sizes and CKB data hashes matched the committed manifest |
| `make fmt-check`, `make lint`, `make source-hygiene` | Passed |
| `make test` | Passed; 413 tests across the workspace and default contract-test path |
| `make fixture-checks` | Passed; bilateral plus 13 Factory/splice/watch fixture families |
| `make contract-tests` | Passed; 112 CKB-VM tests |
| `make sdk-check` | Passed; npm audit reported zero vulnerabilities, type-check and smoke test passed |
| `make hub-ui-check` | Passed; npm audit reported zero vulnerabilities and production build succeeded |
| `make release-readiness` | Passed; manifest, dated envelope, watch policy/config, and runbook gates verified |
| Deterministic packaging | Two independent staging directories produced identical SHA-256 `a36de372d9a9436579babdf8b505ae4c4766b2c4095c8d392f028666e07c99fd` |
| Supply chain | Online RustSec refresh failed with the repository's known Git I/O error; cached `cargo audit --no-fetch` scanned 1,216 advisories successfully and `cargo deny check` passed |

## Rehearsed Decisions

- A Factory with three signers is rejected rather than silently presented as
  supported.
- Mainnet, real assets, external xUDTs, and Hub-submitted chain actions are
  rejected by the current envelope.
- A cursor hash mismatch or missing legacy cursor hash resets scanning to the
  configured floor and emits a critical alert.
- A legacy owner-locked Factory is settled and recreated; it is not migrated
  in place.
- A manifest mismatch stops release packaging; the reviewed hash is not edited
  to accommodate an unexplained binary.

## Remaining External Evidence

Before any scope beyond this controlled devnet, obtain independent protocol and
script reviews, a second-operator watchtower rehearsal, induced/repeated reorg
and fee-pressure runs, long-running service evidence, and an explicit new value
envelope. None of those is implied by this repository-side rehearsal.
