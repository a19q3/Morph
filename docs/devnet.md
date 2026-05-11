# Devnet Plan

The devnet milestone is a bilateral channel vertical slice:

1. Deploy three scripts:
   - `morph-state-type`
   - `morph-vault-lock`
   - `morph-sponsor-lock`
2. Create one funding identity Cell, one State Cell, and optional vault Cells.
3. Produce an off-chain state package with a strictly higher state number.
4. Publish the state package using sponsor capacity.
5. Supersede a stale settling state before its relative `since` delay matures.
6. Finalise the current settling state and materialise vault outputs.

## Tooling Requirements

The local environment used to create this repository has Rust and the CKB
RISC-V target installed, but no `ckb`, `ckb-cli`, `capsule`, or `moleculec`
binary on PATH. Until those tools are installed, this repository verifies the
protocol semantics locally and keeps devnet broadcast commands as a runbook.

Expected tools for full devnet execution:

```sh
ckb --version
ckb-cli --version
cargo --version
rustup target list --installed | grep riscv64imac-unknown-none-elf
```

## Current Smoke Checks

```sh
cargo test --workspace
cargo run -p morph-cli -- validate-fixture
```

These checks exercise the same invariants that the scripts must enforce:

- one live State Cell transition;
- monotonic state number;
- canonical funding anchor binding;
- no channel-paid publication fees;
- reserve/business CKB separation;
- per-xUDT conservation by canonical type hash;
- bounded sponsor policy;
- vault settlement gated by current settling state and `since`.

## First Contract Milestone

The contract implementation should not start from a generic VM-like descriptor.
The first devnet contract should use fixed-width headers and a narrow witness
format:

```text
StateHeaderV1
PlainBilateralPayloadV1
SponsorPolicyV1
SettlementDescriptorV1
```

Factory proof mode should not be enabled on devnet until a concrete
rights-dependency proof predicate exists.

