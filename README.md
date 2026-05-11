# Morph Channel

Morph Channel is an implementation workspace for a CKB Cell-native channel
construction based on stable funding identity, moving signed state evidence,
sponsored publication, and partition conservation.

This repository is intentionally conservative. The first milestone is a
devnet-testable bilateral channel path. Factory proof mode is represented in
the data model and negative tests, but reduced-signature factory exits remain
behind an explicit proof-system gate.

## Status

Current implementation stage:

- `morph-core`: protocol objects and validation invariants for state
  supersession, sponsor policy, vault settlement, and partition conservation.
- `morph-cli`: local smoke tooling for fixture generation, invariant checks,
  native CKB devnet JSON-RPC checks, contract deployment, channel opening,
  state publication, vault finalisation, and per-transaction cycle/size
  reporting from the node. It also stores reusable signed state packages for
  watchtower-style publication.
- `contracts/morph-state-lock`: no-std CKB lock script that delegates StateCell
  spending to the expected state type script.
- `contracts/morph-state-type`: no-std CKB type script for one-live-State-Cell
  progression, funding-anchor binding, and monotonic settling publication.
- `contracts/morph-vault-lock`: no-std CKB lock script for vault settlement
  gated by a unique current settling State Cell and relative `since`.
- `contracts/morph-sponsor-lock`: no-std CKB lock script for bounded sponsor
  fee spending, state-number policy checks, and clean sponsor change.
- `contracts/morph-devnet-xudt`: no-std devnet xUDT script used to test
  token-bearing vault settlement without depending on an external issuer.

This is not mainnet software. It is a production-oriented implementation
repository with tests that turn the paper's audit matrix into executable
checks. Participant state signatures are verified in both host-side invariants
and the `morph-state-type` CKB script; the current devnet path opens a channel,
publishes a signed settling state using sponsor capacity, supersedes it with a
higher signed state, and finalises the vault without modifying CKB consensus.
It also includes a devnet CKB+xUDT smoke path that mints a local test asset
into the vault and settles exact token balances through the same StateCell and
VaultCell authority model.

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
cargo test --workspace
cargo run -p morph-cli -- validate-fixture
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
scripts/devnet-smoke.sh
```

The devnet path is documented in [docs/devnet.md](docs/devnet.md). JSON reports
include CKB `estimate_cycles` output and serialized transaction size for each
deployment, open, publication, sponsor top-up, supersession, and finalisation
transaction, including finalise-since, sponsor budget, competing-spend, and
CKB+xUDT smoke paths.
`scripts/devnet-smoke.sh` runs the real local checks and devnet smoke paths,
then writes the JSON, log, `summary.md`, and `summary.json` artefacts under
`target/devnet-smoke/`. To rebuild the summary for a previous run:

```sh
cargo run -p morph-cli -- devnet-smoke-report --dir target/devnet-smoke/<run>
```

For the factory research track, the CLI can also print and validate a
host-side non-interference package:

```sh
cargo run -p morph-cli -- print-factory-fixture > target/factory-update.json
cargo run -p morph-cli -- validate-factory-package target/factory-update.json --json
```
