# Redundant and Stale Code Audit

This audit records a conservative sweep for redundant or stale code paths on
the V1 devnet release-candidate line. It intentionally avoids behavior changes,
wire-format changes, dependency upgrades, and historical evidence edits.

## Supersession Note

This document is a historical audit of the V1 devnet release-candidate line,
not a current stale-code assessment of the post-V1 implementation.

The current V2 line, commit `a2059ba` on
`arthur/v2-final-nonfixed-witness`, deliberately changes the factory
authorisation boundary from raw fixed-width witness-length dispatch to the
bounded `WitnessEnvelopeV2` kind/body/digest envelope. Consequently, the V1
scope classifications below remain valid only for that older audit baseline.
They should not be used to decide whether current V2 witness-envelope code,
documentation, fixtures, or release evidence are stale.

## Baseline

- Branch: `arthur/audit-stale-redundant-code`
- Base commit: `fbd5a11`
- Scope: repository documentation, scripts, Rust crates, and contract crates
- Goal: small cleanup PR for evidence-backed low-risk findings only

## Commands

```sh
rg -n 'TODO|FIXME|deferred|disabled|stale|legacy|placeholder|pending' README.md docs crates contracts scripts
rg -n 'allow\((dead_code|unused|unused_variables|unused_imports)\)|#\[ignore\]|todo!\(|unimplemented!\(|panic!\("TODO|dbg!\(' crates contracts
cargo tree -d
find . -maxdepth 4 -type f \( -name '*.tmp' -o -name '*.bak' -o -name '*.old' -o -name '*.orig' -o -name '*~' \) -print
find crates contracts -name '*.rs' -print0 | xargs -0 wc -l | sort -nr | head -12
```

`cargo machete` and `cargo udeps` were not installed locally. This audit did
not add new cargo subcommand dependencies.

## Findings

### Cleanups Performed

- Clarified that the implementation document's current non-goals are
  intentional V1 boundaries rather than stale implementation gaps.
- Added this audit report so deferred items, upstream dependency duplication,
  and large-module refactor candidates are tracked without changing protocol
  behavior.

No code or fixture deletion met the cleanup rule in this pass: the candidate
had to be unreferenced by `rg`, outside public CLI/API behavior, unrelated to
historical closeout evidence, and safe under the required checks.

### Active Status Checks

- No active documentation was found that still claims xUDT reduced-exit devnet
  smoke is disabled or deferred. Current non-historical docs describe xUDT
  reduced-exit as active at contract, CKB-VM, and devnet-smoke layers.
- No `todo!()`, `unimplemented!()`, `#[ignore]`, or
  `allow(dead_code/unused/unused_variables/unused_imports)` markers were found
  under `crates` or `contracts`.
- No `.tmp`, `.bak`, `.old`, `.orig`, or editor backup files were found within
  the scanned depth.

### Intentional Deferred Scope

These references are retained because they describe real V1 limits or future
protocol work:

- Multi-right and variable-depth reduced-signature proof bundles.
- Generic descriptor runtime.
- Concurrent unconfirmed splice/off-chain-update interleaving.
- Arbitrary splice-out payout-lock allowlists.
- Larger factory proof profiles beyond the fixed-width V1 smoke paths.

Historical closeout files such as `docs/m5-closeout.md`,
`docs/m6-closeout.md`, and `docs/v1-devnet-rc-closeout.md` are evidence
artifacts. Old run names, paths, baselines, and status wording inside those
files are not treated as stale code.

### Dependency Duplication

`cargo tree -d` reports duplicate dependency versions, but the visible causes
are upstream transitive dependency stacks rather than local direct dependency
drift. Examples include CKB crates, request/HTTP support crates, and older
transitive `rand`/`getrandom` lines. This PR does not upgrade or override CKB
dependencies.

Follow-up should happen in a dependency-readiness PR with supply-chain evidence,
not in this conservative stale-code cleanup.

### Large-Module Refactor Candidates

The largest Rust modules remain maintenance risks, but splitting them would be
a behavior-preserving refactor with its own review cost. They are not changed in
this pass.

Top candidates by line count:

- `crates/morph-cli/src/devnet.rs`
- `crates/morph-cli/src/main.rs`
- `contracts/morph-script-common/src/lib.rs`
- `crates/morph-core/tests/contract_scripts.rs`
- `crates/morph-cli/src/smoke_report.rs`
- `crates/morph-cli/src/factory_packages.rs`

Potential follow-up work:

- Split devnet orchestration by channel, factory, splice, and watchtower flows.
- Extract shared smoke report assertion helpers.
- Move contract-script test fixture assembly into smaller scenario builders.
- Introduce `cargo machete` or `cargo udeps` only in a separate tooling PR.

## Non-Changes

This audit intentionally does not:

- Change contract wire schema, witness layout, descriptor versions, or script
  error codes.
- Change active CLI command behavior or devnet smoke flows.
- Upgrade CKB dependencies or resolve upstream duplicate dependency versions.
- Delete M5, M6, or V1 devnet release-candidate closeout evidence.
- Reclassify mainnet readiness. At the time of this audit, the repository
  remained a Devnet V1 release candidate until the separate mainnet-readiness
  gates passed. Current readiness classification must be taken from the active
  V2 roadmap and readiness documents, not from this historical audit.
