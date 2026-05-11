# Morph Channel

Morph Channel is an implementation workspace for a CKB Cell-native channel
construction based on stable funding identity, moving signed state evidence,
sponsored publication, and partition conservation.

This repository is intentionally conservative. The first milestone is a
devnet-testable bilateral channel path. Factory proof mode is represented in
the data model, package validation, and a conservative full-participant factory
type script. Conservative factory-local exit materialisation is implemented on
devnet; reduced-signature factory exits remain behind an explicit proof-system
gate.

## Status

Current implementation stage:

- `morph-core`: protocol objects and validation invariants for state
  supersession, sponsor policy, vault settlement, and partition conservation.
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
  a reusable evidence package that can be independently validated.
- `contracts/morph-state-lock`: no-std CKB lock script that delegates StateCell
  spending to the expected state type script.
- `contracts/morph-state-type`: no-std CKB type script for one-live-State-Cell
  progression, funding-anchor binding, and monotonic settling publication.
- `contracts/morph-factory-type`: no-std CKB type script for conservative
  one-live-FactoryStateCell progression with full-participant signatures and
  local-exit evidence checks. It also supports a bounded reduced-rights proof
  path where one authorised participant may reduce only their own committed
  factory rights while all other rights remain unchanged.
- `contracts/morph-factory-vault-lock`: no-std CKB lock script for factory
  reserve conservation during child-channel materialisation.
- `contracts/morph-vault-lock`: no-std CKB lock script for vault settlement
  gated by a unique current settling State Cell and relative `since`.
- `contracts/morph-sponsor-lock`: no-std CKB lock script for bounded sponsor
  fee spending, state-number policy checks, and clean sponsor change.
- `contracts/morph-devnet-xudt`: no-std devnet xUDT script used to test
  token-bearing vault settlement without depending on an external issuer.

This is not mainnet software. It is a production-oriented implementation
repository with tests that turn the paper's audit matrix into executable
checks. Participant state signatures are verified in both host-side invariants
and the `morph-state-type` CKB script; conservative factory state signatures
are verified by `morph-factory-type`. The current devnet path opens a channel,
publishes a signed settling state using sponsor capacity, supersedes it with a
higher signed state, and finalises the vault without modifying CKB consensus.
It also opens a conservative factory, advances its state, materialises plain
CKB and CKB+xUDT child bilateral channels from the factory reserve, and then
publishes and finalises those child channels. The CKB+xUDT smoke paths mint a
local test asset into the vault and settle exact token balances through the
same StateCell and VaultCell authority model.
The reduced-signature factory work is deliberately narrow at this stage:
CKB-VM tests and devnet smoke cover a fixed-width proof for claim-reducing
rights updates, while reduced-signature factory exits remain behind the
proof-system gate.

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
cargo run -p morph-cli -- devnet factory-xudt-negative-smoke
make devnet-smoke
```

The devnet path is documented in [docs/devnet.md](docs/devnet.md). JSON reports
include CKB `estimate_cycles` output and serialized transaction size for each
deployment, open, publication, sponsor top-up, supersession, factory local
exit, and finalisation transaction, including finalise-since, sponsor budget,
competing-spend, CKB+xUDT, and factory CKB+xUDT negative smoke paths.
`scripts/devnet-smoke.sh` runs the real local checks and devnet smoke paths,
then writes the JSON, log, `summary.md`, and `summary.json` artefacts under
`target/devnet-smoke/`. After a successful run it refreshes
`target/devnet-smoke/latest` to point at the completed run, unless that path is
a real directory or file. Summary generation also validates any factory
local-exit evidence package embedded in the smoke JSON, extracts deployed
script outpoints and data hashes, and records watchtower JSONL alerts. The
script asserts that the expected negative-path failures, deployed scripts,
local contract binary hashes, watchtower alert events, and factory exit
evidence are present. `devnet-smoke-assert` can also enforce absolute
cycle/byte budgets for completed smoke runs. To rebuild or assert a previous
run:

```sh
cargo run -p morph-cli -- devnet-smoke-report --dir target/devnet-smoke/<run>
cargo run -p morph-cli -- devnet-smoke-assert --dir target/devnet-smoke/<run>
make smoke-report
make smoke-assert
cargo run -p morph-cli -- devnet-smoke-compare \
  --baseline target/devnet-smoke/<old-run> \
  --candidate target/devnet-smoke/<new-run> \
  --fail-on-transaction-set-change \
  --fail-on-status-change \
  --max-abs-total-byte-delta 0 \
  --max-abs-tx-byte-delta 0
```

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
stop file appears.

For the factory research track, the CLI can also print and validate a
host-side non-interference package, its conservative all-participant signed
state package, and a host-side authorised-participant reduced package. The
devnet CLI also includes `open-factory`,
`update-factory`, `factory-exit-channel`, and `factory-xudt-smoke` for the
conservative on-chain path. `factory-xudt-negative-smoke` proves that a child
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
cargo run -p morph-cli -- print-factory-local-exit-fixture \
  > target/factory-local-exit.json
cargo run -p morph-cli -- validate-factory-local-exit-package \
  target/factory-local-exit.json --json
```
