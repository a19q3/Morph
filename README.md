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
  and native CKB devnet JSON-RPC checks.
- `contracts/morph-state-type`: no-std CKB type script for one-live-State-Cell
  progression, funding-anchor binding, and monotonic settling publication.
- `contracts/morph-vault-lock`: no-std CKB lock script for vault settlement
  gated by a unique current settling State Cell and relative `since`.
- `contracts/morph-sponsor-lock`: no-std CKB lock script for bounded sponsor
  fee spending and clean sponsor change.

This is not mainnet software. It is a production-oriented implementation
repository with tests that turn the paper's audit matrix into executable
checks. Participant state signatures are verified in both host-side invariants
and the `morph-state-type` CKB script; live devnet transaction construction and
broadcast tooling is the next remaining milestone.

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
```

The devnet path is documented in [docs/devnet.md](docs/devnet.md).
