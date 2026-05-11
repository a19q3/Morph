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
- `morph-cli`: local smoke tooling for fixture generation and invariant checks.
- `contracts/`: CKB script entrypoint plan and error-code boundary. The first
  real devnet contract milestone is to port the fixed-width validation subset
  from `morph-core` into no-std scripts.

This is not mainnet software. It is a production-oriented implementation
repository with tests that turn the paper's audit matrix into executable
checks.

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
```

The devnet path is documented in [docs/devnet.md](docs/devnet.md).

