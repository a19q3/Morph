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
CKB_BIN=/path/to/ckb scripts/check-devnet-env.sh
cargo --version
rustup target list --installed | grep riscv64imac-unknown-none-elf
```

The local machine currently has a usable CKB node binary at
`/Users/arthur/RustroverProjects/ckb/target/debug/ckb`. `ckb-cli` is optional
for manual inspection; the implementation should use Morph-specific RPC tooling
for deploy, publish, supersede, and finalise transactions.

To start an isolated local dev node:

```sh
scripts/devnet-node.sh
```

By default this initialises `target/devnet/node`, listens on RPC port `18114`,
enables CKB's `IntegrationTest` RPC module for local block generation, configures
a secp256k1 block assembler, and uses the local CKB debug binary. Override with
`CKB_BIN`, `CKB_DIR`, `RPC_PORT`, `P2P_PORT`, `BLOCK_ASSEMBLER_CODE_HASH`, or
`BLOCK_ASSEMBLER_ARG` when needed.

The default dev block assembler arg is:

```text
0xc8328aabcd9b9e8e64fbc566c4385c3bdeb219d7
```

It is suitable for isolated local devnet mining only. Production deployments
must replace it with an operator-controlled lock.

## Current Smoke Checks

```sh
cargo test --workspace
cargo run -p morph-cli -- validate-fixture
make build-contracts
make contract-tests
```

With `scripts/devnet-node.sh` running in another shell:

```sh
cargo run -p morph-cli -- devnet check
cargo run -p morph-cli -- devnet mine --blocks 1
cargo run -p morph-cli -- devnet wait-tip 1 --timeout-secs 30
```

These checks exercise the same invariants that the scripts must enforce:

- one live State Cell transition;
- monotonic state number;
- secp256k1 ECDSA participant signatures over the canonical state header;
- canonical funding anchor binding;
- no channel-paid publication fees;
- reserve/business CKB separation;
- per-xUDT conservation by canonical type hash;
- bounded sponsor policy;
- vault settlement gated by current settling state and `since`.

`make build-contracts` currently produces these CKB RISC-V ELFs:

```text
target/riscv64imac-unknown-none-elf/release/morph-state-type
target/riscv64imac-unknown-none-elf/release/morph-vault-lock
target/riscv64imac-unknown-none-elf/release/morph-sponsor-lock
```

`make contract-tests` builds those ELFs and runs offline `ckb-testtool`
transactions for:

- newer-state publication accepted by `morph-state-type`;
- equal state number rejected by `morph-state-type`;
- invalid participant signature rejected by `morph-state-type`;
- vault finalisation accepted when a current settling State Cell is consumed;
- descriptor output mismatch rejected by `morph-vault-lock`;
- sponsor fee payment accepted when change returns to the authorised wallet lock.
- sponsor fee payment rejected when no matching settling StateHeader is produced.

The CLI speaks directly to CKB JSON-RPC and does not require `ckb-cli`:

```sh
cargo run -p morph-cli -- devnet check
cargo run -p morph-cli -- devnet tip --json
cargo run -p morph-cli -- devnet mine --blocks 1
cargo run -p morph-cli -- devnet wait-tip 1 --timeout-secs 30
```

Use `--rpc-url` or `MORPH_CKB_RPC` when the node is not listening on the
default local endpoint:

```sh
MORPH_CKB_RPC=http://127.0.0.1:18114 cargo run -p morph-cli -- devnet check
```

`devnet mine` calls CKB's `generate_block` integration-test RPC method. If the
node has not exposed that module, the command fails with the returned RPC
error. It does not fabricate block progress.

## Contract Milestone

The contract implementation uses fixed-width headers and a narrow witness
format. It deliberately does not start from a generic VM-like descriptor:

```text
StateHeaderV1
PlainBilateralPayloadV1
SponsorPolicyV1
SettlementDescriptorV1
```

Factory proof mode should not be enabled on devnet until a concrete
rights-dependency proof predicate exists.

## Remaining Devnet Gap

The local machine now has a CKB node binary and the repository has native
read/mine JSON-RPC tooling. The next missing part is Morph-specific transaction
construction and signing for deploying scripts, funding a channel, publishing a
state, superseding it, and finalising vault outputs against a live devnet node.
