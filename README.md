# Morph Channel

Morph Channel is an implementation workspace for a CKB Cell-native channel
construction based on stable funding identity, moving signed state evidence,
sponsored publication, and partition conservation.

This repository is intentionally conservative. The first milestone is a
devnet-testable bilateral channel path. Factory proof mode is represented in
the data model, package validation, and a conservative full-participant factory
type script. Conservative factory-local exit materialisation is implemented on
devnet; bounded reduced-signature factory exits now have fixed-width script
coverage in CKB-VM tests and devnet smoke for the reserve-claim path.

## Status

Current implementation stage:

- `morph-core`: protocol objects and validation invariants for state
  supersession, sponsor policy, vault settlement, and partition conservation.
  It also includes the first host-side bilateral splice model: signed funding
  epoch transitions, CKB/xUDT vault descriptors, asset-delta commitments, and
  splice-in/splice-out validation. The factory reserve repartition model now
  validates conservative factory splice-in/out transitions where one
  participant reserve claim changes exactly with the CKB or xUDT
  FactoryVaultCell delta.
- `morph-script-common`: shared fixed-width parsers and digest helpers for the
  current CKB script wire objects, now including the initial splice header,
  splice signature witness, vault descriptor, asset-delta shapes, the bundled
  splice state-transition witness, a shared splice verifier, and the initial
  fixed-width factory splice witness verifier.
- `morph-cli`: local smoke tooling for fixture generation, invariant checks,
  native CKB devnet JSON-RPC checks, contract deployment, channel opening,
  state publication, vault finalisation, and per-transaction cycle/size
  reporting from the node. It also stores reusable signed state packages for
  watchtower-style publication and validates optional watchtower operator
  policies before confirmed-block scanning. Watchtower runs can be driven from
  a multi-channel JSON config, either as one scan pass or as a bounded loop
  that reuses persisted cursors, while the signing key remains a runtime
  argument or environment variable. Watchtower alerts can be written to JSONL
  and posted to a policy-gated HTTP webhook. Factory local-exit reports include
  a reusable evidence package that can be independently validated. Splice
  fixture commands can print and validate reusable host-side splice-in,
  splice-out, and xUDT splice-out packages; devnet can now save and apply
  live-matching CKB splice packages plus xUDT splice-in/out packages against an
  active StateCell/VaultCell pair. Factory splice fixture commands print and
  validate signed all-participant CKB/xUDT reserve-repartition packages and
  export the fixed-width `FactorySpliceWitnessV1` bytes as
  `contract_witness_hex`.
- `contracts/morph-state-lock`: no-std CKB lock script that delegates StateCell
  spending to the expected state type script.
- `contracts/morph-state-type`: no-std CKB type script for one-live-State-Cell
  progression, funding-anchor binding, monotonic settling publication, and the
  StateCell side of the old/new funding-anchor splice bridge.
- `contracts/morph-factory-type`: no-std CKB type script for conservative
  one-live-FactoryStateCell progression with full-participant signatures and
  local-exit evidence checks. It also supports a bounded reduced-rights proof
  path where one authorised participant may reduce only their own committed
  factory rights while all other rights remain unchanged, plus a bounded
  reduced-exit proof for reserve-claim release into a materialised child
  channel.
- `contracts/morph-factory-vault-lock`: no-std CKB lock script for factory
  reserve conservation during conservative and reduced-exit child-channel
  materialisation, with initial factory splice vault-delta checks for touched
  CKB/xUDT FactoryVaultCells.
- `contracts/morph-vault-lock`: no-std CKB lock script for vault settlement
  gated by a unique current settling State Cell and relative `since`, plus the
  old/new vault side of the splice funding-anchor bridge.
- `contracts/morph-sponsor-lock`: no-std CKB lock script for bounded sponsor
  fee spending, state-number policy checks, and clean sponsor change.
- `contracts/morph-devnet-xudt`: no-std devnet xUDT script used to test
  token-bearing vault settlement without depending on an external issuer.

This is not mainnet software. The current baseline is a V1 safety-kernel audit
candidate: known local P0/P1 safety-boundary blockers are addressed, but value
limits still require external diff review, mainnet-like evidence, supply-chain
gates, and operational readiness sign-off. It is a production-oriented
implementation repository with tests that turn the paper's audit matrix into
executable checks. Participant state signatures are verified in both host-side
invariants and the `morph-state-type` CKB script; conservative factory state
signatures are verified by `morph-factory-type`. The current devnet path opens
a channel, publishes a signed settling state using sponsor capacity, supersedes
it with a higher signed state, and finalises the vault without modifying CKB
consensus.
It also opens a conservative factory, advances its state, materialises plain
CKB and CKB+xUDT child bilateral channels from the factory reserve, and then
publishes and finalises those child channels. The CKB+xUDT smoke paths mint a
local test asset into the vault and settle exact token balances through the
same StateCell and VaultCell authority model.
The reduced-signature factory work is deliberately narrow at this stage:
CKB-VM tests and devnet smoke cover a fixed-width proof for claim-reducing
rights updates and fixed-width CKB/xUDT reserve-claim reduced exits. The xUDT
reduced-exit smoke covers typed child-vault and FactoryVault change binding,
including partial, full, one-sided, and tampered child-token amount cases.
Sparse Merkle update packages and a fixed-width no-std
Merkle witness now cover the first general proof-bundle step for larger
factories, including a devnet smoke path that updates one right through the
256-sibling proof. Smoke summaries bind the current bounded reduced-rights,
sparse Merkle, CKB reduced-exit, and xUDT reduced-exit proof shapes to their
witness sizes and node-estimated transaction budgets. Larger, multi-right, and
variable-depth proof profiles are deferred beyond this roadmap slice.

## Repository Layout

```text
crates/morph-core      Protocol data model and deterministic validation.
crates/morph-cli       Local CLI for fixtures and smoke checks.
contracts/             CKB script crates and deployment plan.
schemas/               Molecule schema draft for the on-chain wire format.
docs/                  Devnet and implementation notes.
```

## Quick Start

```sh
make ci
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo run -p morph-cli -- validate-fixture
make fixture-checks
make build-contracts
make contract-tests
scripts/check-devnet-env.sh
```

With a local devnet node running through `scripts/devnet-node.sh`:

```sh
cargo run -p morph-cli -- devnet check
cargo run -p morph-cli -- devnet mine --blocks 1
cargo run -p morph-cli -- devnet deploy-contracts
cargo run -p morph-cli -- devnet open-channel
cargo run -p morph-cli -- devnet supersede-smoke
cargo run -p morph-cli -- devnet finalise-since-negative-smoke
cargo run -p morph-cli -- devnet sponsor-budget-negative-smoke
cargo run -p morph-cli -- devnet competing-spend-smoke
cargo run -p morph-cli -- devnet xudt-smoke
cargo run -p morph-cli -- devnet xudt-negative-smoke
cargo run -p morph-cli -- devnet factory-reduced-rights-smoke
cargo run -p morph-cli -- devnet factory-merkle-update-smoke
cargo run -p morph-cli -- devnet factory-reduced-exit-smoke
cargo run -p morph-cli -- devnet factory-xudt-negative-smoke
make devnet-smoke
make devnet-e2e
```

The devnet path is documented in [docs/devnet.md](docs/devnet.md). JSON reports
include CKB `estimate_cycles` output and serialized transaction size for each
deployment, open, publication, sponsor top-up, supersession, factory local
exit, splice, watchtower, and finalisation transaction, including
finalise-since, sponsor budget, competing-spend, asymmetric CKB, one-sided
xUDT, CKB+xUDT, factory splice, and factory CKB+xUDT negative smoke paths.
`scripts/devnet-smoke.sh` runs the real local checks and devnet smoke paths,
then writes the JSON, log, `summary.md`, and `summary.json` artefacts under
`target/devnet-smoke/`. After a successful run it refreshes
`target/devnet-smoke/latest` to point at the completed run, unless that path is
a real directory or file. Summary generation also validates any factory
local-exit evidence package and factory Merkle update evidence embedded in the
smoke JSON, extracts deployed script outpoints and data hashes, derives
proof-shape budget profiles, and records watchtower JSONL alerts, including
auto-sponsor, direct sponsor, config-loop, and stale pre-splice package guard
paths. The script
asserts that the expected negative-path failures, deployed scripts, local
contract binary hashes, watchtower alert events, and factory update/exit
evidence are present. `devnet-smoke-assert` can also enforce absolute
cycle/byte budgets for completed smoke runs, including per-transaction and
proof-profile budgets from
[docs/devnet-smoke-budget.example.json](docs/devnet-smoke-budget.example.json).
Factory splice apply transactions are included in those proof profiles, binding
`FactorySpliceWitnessV1` length to the recorded cycle and byte metrics.
For release closeout, `scripts/devnet-e2e.sh` starts a fresh real CKB devnet
from the parent `../ckb` tree, runs only the on-chain smoke path with local
`cargo test`/testtool checks skipped, and applies the smoke budget profile to
the resulting chain artefacts.
`scripts/devnet-stateful-e2e.sh` runs the production-scenario acceptance layer
on a fresh devnet. It writes scenario records under
`target/devnet-stateful-e2e/<run>/scenarios/`, keeps the underlying smoke tree
as `scenarios/smoke/`, and asserts long-lifecycle channel, splice, factory,
watchtower, sponsor, xUDT, and negative attack-shaped paths through
`devnet-stateful-assert`. The stateful assertion layer also loads the
generalized audit profile in
[docs/devnet-audit-profile.example.json](docs/devnet-audit-profile.example.json)
so each protocol risk family has required scenario tags, committed transaction
evidence, exact negative-path failures, and budget coverage.
To rebuild or assert a previous run:

```sh
cargo run -p morph-cli -- devnet-smoke-report --dir target/devnet-smoke/<run>
cargo run -p morph-cli -- devnet-smoke-assert --dir target/devnet-smoke/<run>
make smoke-report
make smoke-assert
make smoke-assert-budget
cargo run -p morph-cli -- devnet-smoke-compare \
  --baseline target/devnet-smoke/<old-run> \
  --candidate target/devnet-smoke/<new-run> \
  --fail-on-transaction-set-change \
  --fail-on-status-change \
  --max-abs-total-byte-delta 0 \
  --max-abs-tx-byte-delta 0
make devnet-stateful-e2e
cargo run -p morph-cli -- devnet-stateful-report \
  --dir target/devnet-stateful-e2e/latest/scenarios \
  --audit-profile docs/devnet-audit-profile.example.json
cargo run -p morph-cli -- devnet-stateful-assert \
  --dir target/devnet-stateful-e2e/latest/scenarios \
  --audit-profile docs/devnet-audit-profile.example.json \
  --budget-profile docs/devnet-stateful-budget.example.json
```

For community-facing explanations with diagrams and less protocol vocabulary,
see the [English tutorial](docs/morph-channel-tutorial.md) and
[Chinese tutorial](docs/morph-channel-tutorial.zh.md).
The release-blocking production checklist is tracked in
[docs/mainnet-readiness.md](docs/mainnet-readiness.md).

For watchtower-style deployments, generate an operator policy and pass it to
the scanner before it publishes any package:

```sh
cargo run -p morph-cli -- print-watch-policy-fixture > target/watch-policy.json
cargo run -p morph-cli -- validate-watch-policy target/watch-policy.json
cargo run -p morph-cli -- print-watch-config-fixture > target/watch-config.json
cargo run -p morph-cli -- validate-watch-config target/watch-config.json
cargo run -p morph-cli -- devnet watch-latest-package \
  --channel-id "$CHANNEL_ID" \
  --from-block "$OPEN_BLOCK_NUMBER" \
  --detection-depth 3 \
  --auto-fund-sponsor \
  --private-key-file target/watchtower-owner.key \
  --watch-policy target/watch-policy.json \
  --alert-file target/watch-alerts.jsonl \
  --alert-webhook-url http://127.0.0.1:9000/morph-alerts \
  --json
```

For multiple channels, use a watchtower config and run one bounded scan pass.
Relative paths inside the config are resolved relative to the config file, and
private keys are intentionally kept outside the config:

```sh
cargo run -p morph-cli -- devnet watch-config-once \
  --config target/watch-config.json \
  --private-key-file target/watchtower-owner.key \
  --json
cargo run -p morph-cli -- devnet watch-config-loop \
  --config target/watch-config.json \
  --private-key-file target/watchtower-owner.key \
  --passes 10 \
  --sleep-ms 1000 \
  --json
cargo run -p morph-cli -- devnet watch-config-service \
  --config target/watch-config.json \
  --private-key-file target/watchtower-owner.key \
  --health-file target/watchtower-health.json \
  --stop-file target/watchtower.stop \
  --json
```

The watchtower commands also accept `MORPH_DEVNET_PRIVATE_KEY_FILE`; this is
preferred over placing the sponsor key in shell history or a process list.
The service form runs in the foreground for process supervisors, updates a
JSON health file, backs off after failed passes, and stops cleanly when the
stop file appears. Watch cursors remember the last observed funding anchor, and
the scanner only publishes packages whose funding anchor matches the confirmed
StateCell, emitting splice-specific alerts when a saved package belongs to a
different anchor.
The sponsor lock's V1 script-enforced boundary is intentionally narrower than
the watchtower operator policy. On chain it checks state type, channel/state
number range, fee caps, clean sponsor change, and rejects finite script-level
expiry values. Runtime fields such as expiry windows, sponsor source, cadence,
and webhook policy are operator/watchtower policy until a future
script-verifiable design exists.

For the factory research track, the CLI can also print and validate a
host-side non-interference package, its conservative all-participant signed
state package, and a host-side authorised-participant reduced package. The
devnet CLI also includes `open-factory`,
`update-factory`, `factory-exit-channel`, and `factory-xudt-smoke` for the
conservative on-chain path, plus `factory-reduced-rights-smoke`,
`factory-reduced-exit-smoke`, and `factory-reduced-xudt-exit-smoke` for the
bounded one-signer proof paths. `devnet
save-factory-splice-package` captures a live
conservative FactoryStateCell/FactoryVaultCell pair as a signed
`morph.factory_splice_package.v1` artifact, and `devnet apply-factory-splice`
applies that package against the live factory state/vault pair.
`devnet factory-splice-in-smoke`, `devnet factory-splice-out-smoke`,
`devnet factory-xudt-splice-in-smoke`, and
`devnet factory-xudt-splice-out-smoke` wrap those paths through live package
capture, apply, and post-splice child-channel materialisation.
`factory-xudt-negative-smoke` proves that a child
xUDT vault amount must match the committed local-exit descriptor even when
overall xUDT supply is conserved:

```sh
cargo run -p morph-cli -- print-factory-fixture > target/factory-update.json
cargo run -p morph-cli -- validate-factory-package target/factory-update.json --json
cargo run -p morph-cli -- print-factory-state-fixture > target/factory-state.json
cargo run -p morph-cli -- validate-factory-state-package target/factory-state.json --json
cargo run -p morph-cli -- print-reduced-factory-state-fixture \
  > target/factory-state-reduced.json
cargo run -p morph-cli -- validate-factory-state-package \
  target/factory-state-reduced.json --json
cargo run -p morph-cli -- print-factory-reduced-rights-fixture \
  > target/factory-reduced-rights.json
cargo run -p morph-cli -- validate-factory-reduced-rights-package \
  target/factory-reduced-rights.json --json
cargo run -p morph-cli -- print-factory-reduced-exit-fixture \
  > target/factory-reduced-exit.json
cargo run -p morph-cli -- validate-factory-reduced-exit-package \
  target/factory-reduced-exit.json --json
cargo run -p morph-cli -- print-factory-merkle-update-fixture \
  > target/factory-merkle-update.json
cargo run -p morph-cli -- validate-factory-merkle-update-package \
  target/factory-merkle-update.json --json
cargo run -p morph-cli -- print-factory-local-exit-fixture \
  > target/factory-local-exit.json
cargo run -p morph-cli -- validate-factory-local-exit-package \
  target/factory-local-exit.json --json
cargo run -p morph-cli -- print-factory-splice-fixture --kind splice-in \
  > target/factory-splice-in.json
cargo run -p morph-cli -- validate-factory-splice-package \
  target/factory-splice-in.json --json
cargo run -p morph-cli -- print-factory-splice-fixture --kind xudt-splice-out \
  > target/factory-xudt-splice-out.json
cargo run -p morph-cli -- validate-factory-splice-package \
  target/factory-xudt-splice-out.json --json
cargo run -p morph-cli -- print-factory-reduced-splice-fixture --kind splice-in \
  > target/factory-reduced-splice-in.json
cargo run -p morph-cli -- validate-factory-reduced-splice-package \
  target/factory-reduced-splice-in.json --json
cargo run -p morph-cli -- print-factory-reduced-splice-fixture --kind xudt-splice-out \
  > target/factory-reduced-xudt-splice-out.json
cargo run -p morph-cli -- validate-factory-reduced-splice-package \
  target/factory-reduced-xudt-splice-out.json --json
cargo run -p morph-cli -- devnet factory-splice-in-smoke --json
cargo run -p morph-cli -- devnet factory-splice-out-smoke --json
cargo run -p morph-cli -- devnet factory-reduced-splice-in-smoke --json
cargo run -p morph-cli -- devnet factory-reduced-splice-out-smoke --json
cargo run -p morph-cli -- devnet factory-reduced-xudt-splice-in-smoke --json
cargo run -p morph-cli -- devnet factory-reduced-xudt-splice-out-smoke --json
cargo run -p morph-cli -- devnet factory-xudt-splice-in-smoke --json
cargo run -p morph-cli -- devnet factory-xudt-splice-out-smoke --json
cargo run -p morph-cli -- print-splice-fixture --kind splice-in > target/splice.json
cargo run -p morph-cli -- validate-splice-package target/splice.json --json
cargo run -p morph-cli -- print-splice-fixture --kind splice-out \
  > target/splice-out.json
cargo run -p morph-cli -- validate-splice-package target/splice-out.json --json
cargo run -p morph-cli -- print-splice-fixture --kind xudt-splice-in \
  > target/xudt-splice-in.json
cargo run -p morph-cli -- validate-splice-package \
  target/xudt-splice-in.json --json
cargo run -p morph-cli -- print-splice-fixture --kind xudt-splice-out \
  > target/xudt-splice-out.json
cargo run -p morph-cli -- validate-splice-package \
  target/xudt-splice-out.json --json
```

The splice package validator derives the fixed-width
`SpliceStateTransitionWitnessV1` bytes and reports them as
`contract_witness_hex`, alongside fixed-width current/next StateHeader bytes,
and the V1 withdrawal payout policy for transaction-builder integration.
The factory splice package validator likewise derives fixed-width
`FactorySpliceWitnessV1` bytes as `contract_witness_hex`, so transaction
builders can pass the validated package evidence directly into the factory
type/vault script parsers.
The reduced factory splice validator emits the sparse-Merkle host proof shape
and the fixed-width `FactoryReducedSpliceWitnessV1` as `contract_witness_hex`:
one reserve claim, 256 proof siblings, unchanged access roots, the full
participant key commitment, and one authorised participant signature over the
factory splice header.
Splice-out package summaries expose `withdrawal_payout_policy:
participant_signature_pubkey`, and live apply reports include the exact
participant pubkey and lock hash used for the withdrawal output. `devnet
save-splice-package` builds a live-matching CKB or xUDT splice-in/out package
from an active StateCell/VaultCell pair, and `devnet apply-splice
--splice-package <path>` consumes that package with a fresh owner fee input. The
`devnet splice-in-smoke`, `devnet splice-out-smoke`,
`devnet xudt-splice-in-smoke`, and `devnet xudt-splice-out-smoke` commands wrap
those paths through post-splice sponsor funding, descriptor-updated state
publication, and finalisation.
