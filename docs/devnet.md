# Devnet Plan

The devnet milestone is a bilateral channel vertical slice:

1. Deploy five scripts:
   - `morph-state-lock`
   - `morph-state-type`
   - `morph-vault-lock`
   - `morph-sponsor-lock`
   - `morph-devnet-xudt`
2. Create one canonical State Cell, one VaultCell, and one SponsorCell.
3. Produce an off-chain state package with a strictly higher state number.
4. Publish the state package using sponsor capacity.
5. Finalise the current settling state and materialise vault outputs.

## Tooling Requirements

The local environment used to create this repository has Rust, the CKB RISC-V
target, and a local CKB node binary. `ckb-cli`, `capsule`, and `moleculec` are
not required for the current devnet path.

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
cargo run -p morph-cli -- devnet deploy-contracts --json
cargo run -p morph-cli -- devnet open-channel --json
```

For a repeatable local regression run:

```sh
scripts/devnet-smoke.sh
```

This script runs the real workspace tests, RISC-V contract tests, devnet RPC
check, contract deployment, supersession smoke, sponsor-policy negative smoke,
finalise-since negative smoke, sponsor-budget negative smoke, competing-spend
smoke, CKB+xUDT settlement smoke, CKB+xUDT negative settlement smoke, and the
watchtower auto-sponsor path. It expects the node and `jq` to be available, and
writes logs plus JSON reports under
`target/devnet-smoke/<timestamp>/`. Override `MORPH_CKB_RPC`, `OUT_DIR`, or
`MINE_BLOCKS` when needed.

Devnet transaction reports include two measurement fields:

```text
metrics.estimated_cycles
metrics.tx_size_bytes
```

`estimated_cycles` is returned by the local CKB node through
`estimate_cycles` before broadcast. `tx_size_bytes` is the serialized
transaction size constructed by the CLI. These fields are intended as a
repeatable baseline for script and transaction-shape changes; they are not a
mainnet fee recommendation.

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
target/riscv64imac-unknown-none-elf/release/morph-state-lock
target/riscv64imac-unknown-none-elf/release/morph-state-type
target/riscv64imac-unknown-none-elf/release/morph-vault-lock
target/riscv64imac-unknown-none-elf/release/morph-sponsor-lock
target/riscv64imac-unknown-none-elf/release/morph-devnet-xudt
```

`make contract-tests` builds those ELFs and runs offline `ckb-testtool`
transactions for:

- newer-state publication accepted by `morph-state-type`;
- typed StateCell delegation accepted by `morph-state-lock`;
- untyped StateCell input rejected by `morph-state-lock`;
- equal state number rejected by `morph-state-type`;
- invalid participant signature rejected by `morph-state-type`;
- vault finalisation accepted when a current settling State Cell is consumed;
- descriptor output mismatch rejected by `morph-vault-lock`;
- sponsor fee payment accepted when change returns to the authorised wallet lock.
- sponsor fee payment rejected when no matching settling StateHeader is produced.
- sponsor fee payment rejected when the fee exceeds the per-transaction policy.
- sponsor fee payment rejected when the state number is outside the policy range.
- devnet xUDT mint, conservation, and vault finalisation accepted when the
  descriptor commits to the canonical xUDT type hash and exact token amounts.

The CLI speaks directly to CKB JSON-RPC and does not require `ckb-cli`:

```sh
cargo run -p morph-cli -- devnet check
cargo run -p morph-cli -- devnet tip --json
cargo run -p morph-cli -- devnet mine --blocks 1
cargo run -p morph-cli -- devnet wait-tip 1 --timeout-secs 30
cargo run -p morph-cli -- devnet deploy-contracts
cargo run -p morph-cli -- devnet open-channel
```

Use `--rpc-url` or `MORPH_CKB_RPC` when the node is not listening on the
default local endpoint:

```sh
MORPH_CKB_RPC=http://127.0.0.1:18114 cargo run -p morph-cli -- devnet check
```

`devnet mine` calls CKB's `generate_block` integration-test RPC method. If the
node has not exposed that module, the command fails with the returned RPC
error. It does not fabricate block progress.

`devnet deploy-contracts` builds and signs a real CKB transaction that deploys
the five Morph RISC-V binaries as data-hash script cells:

```text
morph-state-lock
morph-state-type
morph-vault-lock
morph-sponsor-lock
morph-devnet-xudt
```

It scans the local chain for a live cell controlled by the devnet key, uses the
genesis secp256k1 system cell as a dependency, broadcasts through
`send_transaction`, optionally mines blocks, and reports the deployed outpoints
and `data1` code hashes. The default key is the first generated private key in
the local `dev` chain spec and is suitable only for isolated devnet testing.

The minimal bilateral lifecycle is:

```sh
OPEN_JSON=$(cargo run -q -p morph-cli -- devnet open-channel --json)
STATE_OUT_POINT="$(echo "$OPEN_JSON" | jq -r '.cells[] | select(.role=="state") | "\(.out_point.tx_hash):\(.out_point.index)"')"
VAULT_OUT_POINT="$(echo "$OPEN_JSON" | jq -r '.cells[] | select(.role=="vault") | "\(.out_point.tx_hash):\(.out_point.index)"')"
SPONSOR_OUT_POINT="$(echo "$OPEN_JSON" | jq -r '.cells[] | select(.role=="sponsor") | "\(.out_point.tx_hash):\(.out_point.index)"')"

PUBLISH_JSON=$(cargo run -q -p morph-cli -- devnet publish-state \
  --state-out-point "$STATE_OUT_POINT" \
  --sponsor-out-point "$SPONSOR_OUT_POINT" \
  --json)
SETTLING_STATE_OUT_POINT="$(echo "$PUBLISH_JSON" | jq -r '"\(.state_out_point.tx_hash):\(.state_out_point.index)"')"

cargo run -q -p morph-cli -- devnet finalise-channel \
  --state-out-point "$SETTLING_STATE_OUT_POINT" \
  --vault-out-point "$VAULT_OUT_POINT" \
  --json
```

`publish-state` signs the new StateHeader with the default Alice and Bob devnet
keys, consumes the SponsorCell, and returns sponsor change to the opener's
wallet lock. `finalise-channel` consumes the settling StateCell and VaultCell,
materialises the descriptor outputs, and returns the StateCell carrier capacity
minus fee to the opener's wallet lock.

The CKB+xUDT smoke path exercises the same open, publish, and finalise shape,
but the vault carries a devnet-only xUDT type script. The xUDT script allows
minting only when the first input is controlled by the mint-authority lock, and
then enforces ordinary amount conservation on transfers. The vault descriptor
commits to both settlement capacities and token amounts:

```sh
cargo run -q -p morph-cli -- devnet xudt-smoke --json
```

The command deploys no shortcuts: it opens a real channel with an xUDT vault,
publishes a signed settling state through sponsor capacity, finalises through
the vault lock after the relative `since`, and produces Alice/Bob xUDT
settlement cells.

There is also a live xUDT negative smoke:

```sh
cargo run -q -p morph-cli -- devnet xudt-negative-smoke --json
```

It first opens and publishes the same CKB+xUDT channel shape, then attempts a
tampered finalisation where Alice receives one extra token and Bob receives one
fewer token. The total xUDT supply is unchanged, so the xUDT type script is not
the interesting boundary. The expected rejection is
`SettlementOutputMismatch` from the vault lock, proving that the signed
settlement descriptor binds the concrete token distribution.

## Sponsor Policy

`open-channel` and `fund-sponsor` both create a SponsorCell with an explicit
`SponsorPolicyV1`. The default policy is intentionally broad for local devnet
smoke tests:

```text
min_state_number = 0
max_state_number = u64::MAX
max_fee_per_tx   = sponsor_capacity / 2
max_total_fee    = sponsor_capacity
expiry           = u64::MAX
```

For watchtower-style runs, use tighter policy bounds:

```sh
cargo run -q -p morph-cli -- devnet fund-sponsor \
  --state-out-point "$SETTLING_STATE_OUT_POINT" \
  --sponsor-capacity 50000000000 \
  --sponsor-min-state-number 2 \
  --sponsor-max-state-number 2 \
  --sponsor-max-fee-per-tx 200000000 \
  --sponsor-max-total-fee 400000000 \
  --json
```

The CLI reports the policy in JSON and in the non-JSON output. The contract
checks the same fields on-chain: the publication must create a settling
StateHeader for the channel, its state number must fall inside the policy
range, the fee must not exceed `max_fee_per_tx`, and the remaining sponsor
capacity must return to the authorised change lock.

To exercise the newer-state-wins path, top up a fresh SponsorCell against the
currently live settling StateCell and publish a higher state number:

```sh
TOP_UP_JSON=$(cargo run -q -p morph-cli -- devnet fund-sponsor \
  --state-out-point "$SETTLING_STATE_OUT_POINT" \
  --json)
TOP_UP_SPONSOR_OUT_POINT="$(echo "$TOP_UP_JSON" | jq -r '"\(.sponsor_out_point.tx_hash):\(.sponsor_out_point.index)"')"

SUPERSEDE_JSON=$(cargo run -q -p morph-cli -- devnet publish-state \
  --state-out-point "$SETTLING_STATE_OUT_POINT" \
  --sponsor-out-point "$TOP_UP_SPONSOR_OUT_POINT" \
  --state-number 2 \
  --json)
NEWER_STATE_OUT_POINT="$(echo "$SUPERSEDE_JSON" | jq -r '"\(.state_out_point.tx_hash):\(.state_out_point.index)"')"
```

The complete reproducible smoke path is also available as one command:

```sh
cargo run -q -p morph-cli -- devnet supersede-smoke --json
```

It performs:

```text
open channel
publish state 1
fund a fresh SponsorCell
publish state 2 over state 1
finalise the vault using state 2
```

The non-JSON form prints a compact cycle summary for the full path:

```text
cycles=open:<n> stale_publish:<n> sponsor_top_up:<n> supersede_publish:<n> finalise:<n>
```

The JSON form keeps the same per-transaction `metrics` object on each step, so
benchmark scripts can compare open, stale publication, supersession, sponsor
top-up, and finalisation separately.

The finalise-since negative smoke checks the challenge-window guard:

```sh
cargo run -q -p morph-cli -- devnet finalise-since-negative-smoke --json
```

It opens a channel, publishes state `1`, then attempts to finalise with the
StateCell input `since` set to zero while the channel requires the configured
relative `since`. The expected rejection is Morph error `StateSinceNotMature`.
The smoke then mines the configured number of maturity blocks and finalises with
the required `since`. This keeps the devnet model explicitly block-confirmation
based.

The competing-spend smoke makes the mempool assumption explicit:

```sh
cargo run -q -p morph-cli -- devnet competing-spend-smoke --json
```

It opens a channel, creates a spare SponsorCell for state `2`, publishes state
`1` without mining it, then attempts to publish state `2` against the same old
active StateCell while state `1` is still pending. The expected result is a CKB
node rejection because the old StateCell is no longer live from the node's
tx-pool-aware view; it is not a successful replacement. The smoke then mines
state `1`, rebuilds the state `2` publication against the now live settling
StateCell, and finalises normally. This is the practical rule the paper
describes: a signed state package is reusable evidence, not a permanently fixed
transaction body.

There is also a live negative smoke for sponsor policy enforcement:

```sh
cargo run -q -p morph-cli -- devnet sponsor-policy-negative-smoke --json
```

It opens a channel whose initial SponsorCell may only pay for state `1`, asks
the node to verify a state `2` publication, expects that transaction to be
rejected by the sponsor lock, then publishes the allowed state `1` and
finalises the channel. This catches drift between the CLI's reported
SponsorPolicy and the actual script behaviour. The smoke also parses the CKB
script failure and requires Morph error `SponsorStateOutOfRange`, so an
unrelated transaction-construction failure does not count as a pass.

The sponsor-budget negative smoke checks fee bounds and rotation:

```sh
cargo run -q -p morph-cli -- devnet sponsor-budget-negative-smoke --json
```

It opens a channel whose initial SponsorCell is allowed to pay state `1`, but
with `max_fee_per_tx` one shannon below the attempted publication fee. The
expected rejection is Morph error `SponsorFeeTooHigh`. The smoke then funds a
fresh SponsorCell for the same state number with a sufficient fee cap, publishes
the same state, and finalises. This is deliberately a single-use SponsorCell
model: budget rotation means replacing the sponsor cell, not mutating a wallet
balance inside the old one.

## Signed State Packages

A published state should be treated as reusable channel evidence, not as a
fixed transaction body. The CLI therefore has a small state-package store for
the watchtower path. A package contains:

- the complete signed settling `StateHeader`;
- the bilateral participant signature witness;
- channel id, funding anchor, state number, and signing digest metadata;
- the source StateCell outpoint, when created from devnet.

The package reader validates the header length, witness length, participant
commitment, ECDSA signatures, channel metadata, and signing digest before it is
used.

Create a package without broadcasting it:

```sh
PACKAGE_JSON=$(cargo run -q -p morph-cli -- devnet save-state-package \
  --state-out-point "$STATE_OUT_POINT" \
  --state-number 1 \
  --json)
PACKAGE_PATH="$(echo "$PACKAGE_JSON" | jq -r '.path')"
```

List the local package store:

```sh
cargo run -q -p morph-cli -- devnet list-state-packages
cargo run -q -p morph-cli -- devnet latest-state-package \
  --channel-id "$(echo "$PACKAGE_JSON" | jq -r '.package.channel_id')"
```

Publish using the saved package:

```sh
cargo run -q -p morph-cli -- devnet publish-state \
  --state-out-point "$STATE_OUT_POINT" \
  --sponsor-out-point "$SPONSOR_OUT_POINT" \
  --state-package "$PACKAGE_PATH" \
  --json
```

Or let the CLI select the highest-numbered package for the channel:

```sh
cargo run -q -p morph-cli -- devnet publish-latest-package \
  --channel-id "$CHANNEL_ID" \
  --state-out-point "$STATE_OUT_POINT" \
  --sponsor-out-point "$SPONSOR_OUT_POINT" \
  --json
```

For a watchtower-style path, the CLI can scan confirmed blocks from a chosen
height, wait for a confirmation depth, and publish only if the observed
StateCell is older than the latest saved package:

```sh
cargo run -q -p morph-cli -- devnet watch-latest-package \
  --channel-id "$CHANNEL_ID" \
  --from-block "$OPEN_BLOCK_NUMBER" \
  --detection-depth 3 \
  --sponsor-out-point "$SPONSOR_OUT_POINT" \
  --json
```

If the watcher should create its own SponsorCell at detection time, omit
`--sponsor-out-point` and use:

```sh
cargo run -q -p morph-cli -- devnet watch-latest-package \
  --channel-id "$CHANNEL_ID" \
  --from-block "$OPEN_BLOCK_NUMBER" \
  --detection-depth 3 \
  --auto-fund-sponsor \
  --json
```

The automatically funded SponsorCell is deliberately narrow: it is bound to the
selected latest package's state number and carries a fee budget of twice the
requested publication fee. On devnet this mode requires `--mine-blocks` greater
than zero, because the freshly created SponsorCell must be confirmed before it
can pay for the publication transaction.

The watcher persists its next scan height in the package store:

```text
target/morph-state-packages/watch-cursor-<channel-id>.json
```

On the next run it resumes from the saved cursor, unless `--ignore-cursor` is
passed. Use `--cursor-file <path>` when a deployment keeps watchtower runtime
state somewhere other than the package directory. The report includes
`effective_from_block`, `scanned_to_block`, and `next_from_block` so an operator
can audit what was actually covered.

This scanner is intentionally confirmation-based. It does not assume mempool
replacement behaviour, and it does not scan with an indexer. It reads canonical
blocks through CKB JSON-RPC, recognises Morph `StateHeader` outputs for the
channel, and rebuilds a fresh publication transaction once an older confirmed
StateCell is actionable.

When `--state-package` is used, the publication transaction is rebuilt against
the currently live StateCell and SponsorCell. Alice and Bob do not need to sign
again, and their private keys are not needed by the publisher. The publisher
still needs authority over the sponsor change lock, because fee payment remains
separate from channel state authority.

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

The current vertical slice is bilateral and covers both CKB-only vaults and a
devnet CKB+xUDT vault. The remaining devnet work is richer watchtower operator
policy, emergency sponsor-budget rotation, and factory proof predicates.
