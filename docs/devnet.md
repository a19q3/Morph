# Devnet Plan

The devnet milestone is a bilateral channel vertical slice plus a conservative
factory-state script path:

1. Deploy seven scripts:
   - `morph-state-lock`
   - `morph-state-type`
   - `morph-factory-type`
   - `morph-factory-vault-lock`
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

Set `CKB_BIN` to a local CKB node binary, or put `ckb` on `PATH`. `ckb-cli` is
optional for manual inspection; the implementation uses Morph-specific RPC
tooling for deploy, publish, supersede, and finalise transactions.

To start an isolated local dev node:

```sh
scripts/devnet-node.sh
```

By default this initialises `target/devnet/node`, listens on RPC port `18114`,
enables CKB's `IntegrationTest` RPC module for local block generation, and
configures a secp256k1 block assembler. Override with `CKB_BIN`, `CKB_DIR`,
`RPC_PORT`, `P2P_PORT`, `BLOCK_ASSEMBLER_CODE_HASH`, or `BLOCK_ASSEMBLER_ARG`
when needed.

The default dev block assembler arg is:

```text
0xc8328aabcd9b9e8e64fbc566c4385c3bdeb219d7
```

It is suitable for isolated local devnet mining only. Production deployments
must replace it with an operator-controlled lock.

## Real Chain E2E

For release closeout, use the one-command real devnet runner instead of
`cargo test`:

```sh
scripts/devnet-e2e.sh
```

The runner expects the CKB source tree in the parent folder by default
(`../ckb`). It resolves `../ckb/target/release/ckb` or
`../ckb/target/debug/ckb`, builds CKB from `../ckb` if no binary exists,
starts a fresh isolated dev chain under `target/devnet-e2e/<timestamp>/node`,
builds the current RISC-V contract binaries, waits for JSON-RPC, runs the
on-chain smoke suite against that node, and then checks the resulting smoke
summary against
`docs/devnet-smoke-budget.example.json`. It sets
`MORPH_DEVNET_SMOKE_SKIP_LOCAL_CHECKS=1`, so this path does not use
workspace `cargo test` or offline `ckb-testtool` as evidence.

Useful overrides:

```sh
CKB_SOURCE_DIR=../ckb scripts/devnet-e2e.sh
CKB_BIN=../ckb/target/debug/ckb scripts/devnet-e2e.sh
RPC_PORT=18124 P2P_PORT=18125 RUN_ID=m6-closeout scripts/devnet-e2e.sh
BUILD_CONTRACTS=0 scripts/devnet-e2e.sh
KEEP_NODE=1 scripts/devnet-e2e.sh
```

The important artefacts are:

```text
target/devnet-e2e/<timestamp>/manifest.txt
target/devnet-e2e/<timestamp>/logs/ckb-node.log
target/devnet-e2e/<timestamp>/logs/build-contracts.log
target/devnet-e2e/<timestamp>/logs/devnet-smoke.log
target/devnet-e2e/<timestamp>/smoke/summary.json
target/devnet-e2e/<timestamp>/smoke/summary-budget-check.json
```

## Current Smoke Checks

```sh
cargo test --workspace
cargo run -p morph-cli -- validate-fixture
make build-contracts
make contract-tests
```

If the active Rust toolchain does not have the CKB RISC-V target installed,
run the contract build through another installed toolchain without changing the
Makefile:

```sh
make CONTRACT_CARGO='cargo +nightly' contract-tests
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
make devnet-smoke
```

This script runs the real workspace tests, RISC-V contract tests, devnet RPC
check, tip/wait-tip, contract deployment, supersession, finalise-since,
sponsor-policy, sponsor-budget, and competing-spend smoke paths. It also runs a
business matrix for manual state package list/latest/publish-latest,
independent fund-sponsor, CKB+xUDT settlement, asymmetric CKB splits, one-sided
xUDT splits, CKB and xUDT splice-in/splice-out, conservative and reduced
factory updates, factory local exits, reduced reserve exits, factory splice
in/out, factory xUDT splice in/out, watchtower auto-sponsor, direct sponsor
watching, config-loop watching, and the stale-package guard after splice. It
expects the node and `jq` to be
available, and writes logs plus JSON reports under
`target/devnet-smoke/<timestamp>/`. Override `MORPH_CKB_RPC`, `OUT_DIR`, or
`MINE_BLOCKS` when needed; the default is four blocks to avoid proposal-window
flakiness on local devnet. On success it also refreshes the
`target/devnet-smoke/latest` symlink to the completed run; set `LATEST_LINK` to
use a different pointer, or point it at an existing real directory/file to skip
the update. The manifest records the RPC endpoint, block-mining profile, git
commit, and whether tracked files were dirty when the run started.

At the end of a successful run, the script also writes:

```text
summary.md
summary.json
```

These summaries are generated from the smoke JSON files and include every
transaction's node-estimated cycles, transaction size, status, block number,
expected script failure, deployed script outpoint, and deployed script data
hash. They also read watchtower JSONL alert files and summarise the older-state
detection and publication-submitted events. During a full smoke run, the script
also asserts that the expected negative-path failures, deployed scripts, local
contract binary hashes, watchtower alert events, and factory local-exit
evidence packages are present and writes
`summary-check.json`. They can be regenerated or rechecked for an existing run:

```sh
cargo run -q -p morph-cli -- devnet-smoke-report \
  --dir target/devnet-smoke/<timestamp>
cargo run -q -p morph-cli -- devnet-smoke-assert \
  --dir target/devnet-smoke/<timestamp>
make smoke-report
make smoke-assert
```

`devnet-smoke-assert` compares deployed script data hashes with the local
RISC-V binaries in `target/riscv64imac-unknown-none-elf/release`. Use
`--contracts-dir` for another build directory. The same command can enforce
absolute smoke budgets:

```sh
cargo run -q -p morph-cli -- devnet-smoke-assert \
  --dir target/devnet-smoke/<timestamp> \
  --budget-profile docs/devnet-smoke-budget.example.json
make smoke-assert-budget
```

The profile can set global ceilings, per-transaction ceilings keyed by summary
`check` and JSON `path`, and factory proof-profile ceilings keyed by `check`,
`transaction_path`, and `proof_kind`. The generated `summary.md` and
`summary.json` also include factory proof profiles that bind a proof kind such as
`factory_reduced_rights_bounded_claim_decrease_v1`,
`factory_sparse_merkle_update_v1`,
`factory_reduced_exit_ckb_reserve_claim_v1`, or
`factory_reduced_exit_xudt_one_sided_reserve_claim_v1`. Factory splice apply
transactions are also budgeted with `factory_splice_all_participants_ckb_v1`
and `factory_splice_all_participants_xudt_v1`, binding
`FactorySpliceWitnessV1` length to node-estimated cycles and transaction bytes.
For
quick local experiments, the same limits can be supplied directly:

```sh
cargo run -q -p morph-cli -- devnet-smoke-assert \
  --dir target/devnet-smoke/<timestamp> \
  --max-total-cycles 50000000 \
  --max-tx-cycles 10000000 \
  --max-total-bytes 1000000 \
  --max-tx-bytes 10000
```

These are absolute ceilings for a completed smoke run. They complement
`devnet-smoke-compare`, which is a relative gate between two runs.

Two completed runs can be compared without replaying devnet:

```sh
cargo run -q -p morph-cli -- devnet-smoke-compare \
  --baseline target/devnet-smoke/<old-timestamp> \
  --candidate target/devnet-smoke/<new-timestamp> \
  --fail-on-transaction-set-change \
  --fail-on-status-change \
  --max-abs-total-byte-delta 0 \
  --max-abs-tx-byte-delta 0
```

The comparison is keyed by smoke file and JSON path, so it reports transaction
shape changes such as `$.publish` or `$.finalise` becoming larger or more
expensive.
When any `--fail-*` or `--max-*` option is supplied, the command still prints
the comparison report and then exits non-zero if the candidate breaches the
requested regression gate. This keeps exploratory comparisons readable while
making CI checks strict.

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
target/riscv64imac-unknown-none-elf/release/morph-factory-type
target/riscv64imac-unknown-none-elf/release/morph-vault-lock
target/riscv64imac-unknown-none-elf/release/morph-sponsor-lock
target/riscv64imac-unknown-none-elf/release/morph-devnet-xudt
```

`make contract-tests` builds those ELFs and runs offline `ckb-testtool`
transactions for:

- newer-state publication accepted by `morph-state-type`;
- conservative factory creation and signed monotonic update accepted by
  `morph-factory-type`;
- typed StateCell delegation accepted by `morph-state-lock`;
- untyped StateCell input rejected by `morph-state-lock`;
- equal state number rejected by `morph-state-type`;
- invalid participant signature rejected by `morph-state-type`;
- equal update number and invalid participant signature rejected by
  `morph-factory-type`;
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

The reduced-rights factory path has a dedicated smoke command. It opens a
FactoryStateCell whose roots match the bounded rights fixture, stores a
reusable reduced-rights package, validates that the old package header matches
the live factory cell, and publishes the update through the ordinary
`update-factory --factory-state-package` path:

```sh
cargo run -q -p morph-cli -- devnet factory-reduced-rights-smoke --json \
  > target/factory-reduced-rights-smoke.json
```

The sparse Merkle update path uses a larger rights tree and carries only the
single changed right plus the fixed 256-sibling proof. It stores the package
used by `update-factory`, validates the live old header, and publishes the
new FactoryStateCell with the Merkle witness:

```sh
cargo run -q -p morph-cli -- devnet factory-merkle-update-smoke --json \
  > target/factory-merkle-update-smoke.json
```

The reduced-exit factory path has a separate smoke command. It opens a factory
whose roots match the bounded reserve-claim fixture, uses Alice's one-signer
reduced-exit witness to release a child vault, publishes the child state, and
finalises the child channel:

```sh
cargo run -q -p morph-cli -- devnet factory-reduced-exit-smoke --json \
  > target/factory-reduced-exit-smoke.json
```

The typed xUDT reduced-exit smoke is active in the devnet CLI. It binds
`release_quantity` to the child token amount, keeps the ReserveClaim asset type
equal to the live FactoryVault xUDT type hash, and exercises typed FactoryVault
change handling:

```sh
cargo run -q -p morph-cli -- devnet factory-reduced-xudt-exit-smoke --json \
  > target/factory-reduced-xudt-exit-smoke.json
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
the seven Morph RISC-V binaries as data-hash script cells:

```text
morph-state-lock
morph-state-type
morph-factory-type
morph-factory-vault-lock
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

The first CKB splice flow saves a live-matching package from an active
StateCell/VaultCell pair, then applies it by recreating the StateCell and
VaultCell under the package's new funding anchor:

```sh
cargo run -q -p morph-cli -- devnet save-splice-package \
  --state-out-point "$STATE_OUT_POINT" \
  --vault-out-point "$VAULT_OUT_POINT" \
  --kind splice-in \
  --ckb-amount 1000000000 \
  --json

cargo run -q -p morph-cli -- devnet apply-splice \
  --state-out-point "$STATE_OUT_POINT" \
  --vault-out-point "$VAULT_OUT_POINT" \
  --splice-package "$SPLICE_PACKAGE" \
  --json
```

`save-splice-package` supports CKB splice-in/splice-out packages and live xUDT
splice-in/splice-out packages via `--asset xudt --xudt-amount <amount>`. It
records the live StateCell and VaultCell out points, signs the splice header
with Alice/Bob, and writes the package under `target/morph-splice-packages` by
default. `apply-splice` expects that package to match the live current
StateHeader bytes and old VaultCell capacity. It inserts the fixed-width
`SpliceStateTransitionWitnessV1`, pays CKB splice-in deltas, typed withdrawal
cell capacity, typed external-input carrier accounting, and transaction fees
from an opener-controlled fee cell. CKB splice-out withdrawals go to a
participant-derived secp256k1 lock, xUDT splice-out withdrawals go to a typed
participant-owned output, and xUDT splice-in uses `--xudt-input-out-point` to
consume an owner-controlled typed input.
`validate-splice-package --json` reports the package payout rule as
`withdrawal_payout_policy`; V1 splice-out packages use
`participant_signature_pubkey`. Live `apply-splice --json` reports the exact
`withdrawal_participant_pubkey_sec1` and `withdrawal_lock_hash` used for the
on-chain withdrawal output, so a smoke artifact can be audited without
reconstructing the transaction by hand. `make smoke-assert` requires this
evidence for splice apply artifacts and rejects splice-out reports that do not
use the V1 participant-signature payout rule.

For a one-command live path, use the splice smokes:

```sh
cargo run -q -p morph-cli -- devnet splice-in-smoke --json
cargo run -q -p morph-cli -- devnet splice-out-smoke --json
cargo run -q -p morph-cli -- devnet xudt-splice-in-smoke --json
cargo run -q -p morph-cli -- devnet xudt-splice-out-smoke --json
```

Each smoke opens a channel, saves a live splice package, applies it, funds a
new SponsorCell bound to the post-splice StateCell type hash, publishes a
descriptor-updated post-splice settling state, and finalises the post-splice
vault.

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
state_type_hash  = current Morph StateType hash
```

The sponsor script does not treat arbitrary output data as a publication. The
policy binds the expected Morph StateType hash, and the sponsor lock rejects a
fee spend unless the settling StateHeader appears in an output carrying that
exact type.
V1 does not have script-verifiable clock evidence for "not after" expiry
windows, so the sponsor lock rejects finite `expiry` values and only accepts the
unbounded sentinel `u64::MAX`. Operational expiry windows belong in the
watchtower policy.

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
capacity must return to the authorised change lock. Finite `expiry` values are
rejected rather than treated as script-enforced deadlines.

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
cargo run -q -p morph-cli -- print-watch-policy-fixture > target/watch-policy.json
cargo run -q -p morph-cli -- validate-watch-policy target/watch-policy.json
cargo run -q -p morph-cli -- print-watch-config-fixture > target/watch-config.json
cargo run -q -p morph-cli -- validate-watch-config target/watch-config.json

cargo run -q -p morph-cli -- devnet watch-latest-package \
  --channel-id "$CHANNEL_ID" \
  --from-block "$OPEN_BLOCK_NUMBER" \
  --detection-depth 3 \
  --sponsor-out-point "$SPONSOR_OUT_POINT" \
  --private-key-file target/watchtower-owner.key \
  --watch-policy target/watch-policy.json \
  --alert-file target/watch-alerts.jsonl \
  --alert-webhook-url http://127.0.0.1:9000/morph-alerts \
  --json
```

For a multi-channel watchtower process, place the channel list and operator
paths in a config file and run one bounded scan pass:

```sh
cargo run -q -p morph-cli -- devnet watch-config-once \
  --config target/watch-config.json \
  --private-key-file target/watchtower-owner.key \
  --json
```

The same config can be used for several consecutive passes. Each pass reuses
the persisted cursor written by the previous pass:

```sh
cargo run -q -p morph-cli -- devnet watch-config-loop \
  --config target/watch-config.json \
  --private-key-file target/watchtower-owner.key \
  --passes 10 \
  --sleep-ms 1000 \
  --json
```

For a supervisor-managed process, use the foreground service form. It keeps the
same scanner semantics, writes a health file, backs off after errors, and stops
cleanly when the stop file appears:

```sh
cargo run -q -p morph-cli -- devnet watch-config-service \
  --config target/watch-config.json \
  --private-key-file target/watchtower-owner.key \
  --health-file target/watchtower-health.json \
  --stop-file target/watchtower.stop \
  --error-backoff-ms 5000 \
  --max-consecutive-errors 5 \
  --json
```

The config deliberately does not carry a private key; key material is supplied
through `--private-key-file`, `MORPH_DEVNET_PRIVATE_KEY_FILE`,
`--private-key`, or `MORPH_DEVNET_PRIVATE_KEY` at runtime. A key file should
contain exactly one hex-encoded private key. Relative paths inside the config
are resolved relative to the config file.

If the watcher should create its own SponsorCell at detection time, omit
`--sponsor-out-point` and use:

```sh
cargo run -q -p morph-cli -- devnet watch-latest-package \
  --channel-id "$CHANNEL_ID" \
  --from-block "$OPEN_BLOCK_NUMBER" \
  --detection-depth 3 \
  --auto-fund-sponsor \
  --private-key-file target/watchtower-owner.key \
  --watch-policy target/watch-policy.json \
  --alert-file target/watch-alerts.jsonl \
  --json
```

The watch policy is deliberately small. It bounds the operational assumptions
that matter to safety on a confirmation-based chain: minimum confirmation
depth, minimum runtime window, maximum polling interval, maximum fee, whether a
pre-existing SponsorCell may be used, whether auto-funded sponsor rotation is
required, the largest auto-sponsor capacity the watcher may lock, and whether
HTTP webhook alerts are allowed. It may also bind itself to one canonical
channel id. The policy is checked before the scanner reads blocks or publishes
a transaction.

When `--alert-file` is provided, the watcher appends JSON Lines events for
operator review. When `--alert-webhook-url` is provided, the same structured
event is also POSTed as JSON to that URL. Alerts record older-state detection
before sponsor work begins, successful publication after the transaction is
submitted, funding-anchor changes after a confirmed splice, stale saved
packages for the observed anchor, splice-aware publication, and idle scans that
reach the timeout without publishing.

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
state somewhere other than the package directory. The cursor also records the
last observed funding anchor, state number, and outpoint, which lets a watcher
notice confirmed splices and avoid replaying packages from the wrong funding
anchor. The report includes `effective_from_block`, `scanned_to_block`, and
`next_from_block` so an operator can audit what was actually covered.

This scanner is intentionally confirmation-based. It does not assume mempool
replacement behaviour, and it does not scan with an indexer. It reads canonical
blocks through CKB JSON-RPC, recognises Morph `StateHeader` outputs for the
channel, and rebuilds a fresh publication transaction once an older confirmed
StateCell is actionable. If multiple saved packages exist for the channel, it
publishes only the newest package whose funding anchor matches the confirmed
StateCell; a newer package for another anchor is reported as stale rather than
used.

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
FactoryStateHeaderV1
BilateralSignatureWitnessV1
FactorySignatureWitnessV1
FactoryReducedRightsWitnessV1
FactoryReducedExitWitnessV1
FactoryReducedExitXudtWitnessV1
FactoryLocalExitWitnessV1
FactoryLocalExitXudtWitnessV1
SponsorPolicyV1
BilateralCkbSettlementDescriptorV1
BilateralCkbXudtSettlementDescriptorV1
```

`FactoryReducedExitXudtWitnessV1` is the fixed-width xUDT descriptor variant of
the reduced-exit witness. It is active in contract/CKB-VM and devnet smoke
coverage.

The draft Molecule schema in `schemas/morph.mol` records these active wire
objects and their fixed byte lengths. The devnet contracts still parse the
bytes directly; generated Molecule code is a later hardening step, not a
consensus or node requirement.

The conservative factory path is now executable on devnet. It is deliberately
small: one FactoryStateCell, two named participants, all-participant signatures,
one FactoryVaultCell, and monotonic update numbers. It can materialise a
bilateral child channel under full factory-participant consent. A bounded
reduced-signature reserve-claim exit is covered in CKB-VM tests; wiring that
path into the devnet CLI remains open.

Open a factory state cell:

```sh
cargo run -q -p morph-cli -- devnet open-factory --json \
  > target/open-factory.json

FACTORY_OUT_POINT="$(
  jq -r '.cells[] | select(.role == "factory") |
    .out_point.tx_hash + ":" + (.out_point.index | tostring)' \
    target/open-factory.json
)"
FACTORY_VAULT_OUT_POINT="$(
  jq -r '.cells[] | select(.role == "factory-vault") |
    .out_point.tx_hash + ":" + (.out_point.index | tostring)' \
    target/open-factory.json
)"
FACTORY_ID="$(jq -r '.factory_id' target/open-factory.json)"
```

Save a reusable signed factory state package:

```sh
cargo run -q -p morph-cli -- devnet save-factory-state-package \
  --factory-out-point "$FACTORY_OUT_POINT" \
  --json > target/factory-state-package.json

FACTORY_PACKAGE_PATH="$(jq -r '.path' target/factory-state-package.json)"
```

List or select saved packages:

```sh
cargo run -q -p morph-cli -- devnet list-factory-state-packages \
  --factory-id "$FACTORY_ID"

cargo run -q -p morph-cli -- devnet latest-factory-state-package \
  --factory-id "$FACTORY_ID" \
  --json
```

Advance the factory by rebuilding a transaction around the signed evidence:

```sh
cargo run -q -p morph-cli -- devnet update-factory \
  --factory-out-point "$FACTORY_OUT_POINT" \
  --factory-state-package "$FACTORY_PACKAGE_PATH" \
  --json > target/update-factory.json

FACTORY_OUT_POINT="$(
  jq -r '.factory_out_point.tx_hash + ":" + (.factory_out_point.index | tostring)' \
    target/update-factory.json
)"
```

The update transaction keeps the FactoryStateCell capacity unchanged. A normal
owner-controlled cell pays the fee and receives change, so the state carrier is
not silently drained by routine factory updates.

The bounded reduced-rights path can be exercised with the same
`update-factory --factory-state-package` entry point. The current proof shape
uses a fixed rights set, so the factory must be opened with the matching old
rights roots:

```sh
cargo run -q -p morph-cli -- print-factory-reduced-rights-fixture \
  > target/factory-reduced-rights-fixture.json

REDUCED_OLD_STATE_ROOT="$(
  jq -r '.old_state_root' target/factory-reduced-rights-fixture.json
)"
REDUCED_OLD_ACCESS_ROOT="$(
  jq -r '.old_access_manifest_root' target/factory-reduced-rights-fixture.json
)"

cargo run -q -p morph-cli -- devnet open-factory \
  --state-root "$REDUCED_OLD_STATE_ROOT" \
  --access-manifest-root "$REDUCED_OLD_ACCESS_ROOT" \
  --json > target/open-reduced-factory.json

REDUCED_FACTORY_OUT_POINT="$(
  jq -r '.cells[] | select(.role == "factory") |
    .out_point.tx_hash + ":" + (.out_point.index | tostring)' \
    target/open-reduced-factory.json
)"

cargo run -q -p morph-cli -- devnet save-factory-reduced-rights-package \
  --factory-out-point "$REDUCED_FACTORY_OUT_POINT" \
  --touched-after-balance 90 \
  --json > target/factory-reduced-rights-package.json

REDUCED_PACKAGE_PATH="$(
  jq -r '.path' target/factory-reduced-rights-package.json
)"

cargo run -q -p morph-cli -- devnet update-factory \
  --factory-out-point "$REDUCED_FACTORY_OUT_POINT" \
  --factory-state-package "$REDUCED_PACKAGE_PATH" \
  --json > target/update-reduced-factory.json
```

This proves the narrow reduced-rights case on chain: Alice signs a claim-reducing
update, Bob's rights remain unchanged, and the script rejects inflation or root
mismatch. It is still not a reduced-signature factory exit.

Materialise a bilateral child channel from the factory reserve:

```sh
cargo run -q -p morph-cli -- devnet factory-exit-channel \
  --factory-out-point "$FACTORY_OUT_POINT" \
  --factory-vault-out-point "$FACTORY_VAULT_OUT_POINT" \
  --json > target/factory-exit-channel.json

CHILD_STATE_OUT_POINT="$(
  jq -r '.state_out_point.tx_hash + ":" + (.state_out_point.index | tostring)' \
    target/factory-exit-channel.json
)"
CHILD_VAULT_OUT_POINT="$(
  jq -r '.vault_out_point.tx_hash + ":" + (.vault_out_point.index | tostring)' \
    target/factory-exit-channel.json
)"
CHILD_SPONSOR_OUT_POINT="$(
  jq -r '.sponsor_out_point.tx_hash + ":" + (.sponsor_out_point.index | tostring)' \
    target/factory-exit-channel.json
)"
```

The exit transaction consumes the FactoryStateCell and FactoryVaultCell, creates
a child StateCell/VaultCell/SponsorCell, and returns the remaining factory
reserve to a new FactoryVaultCell. Its fee is paid by a normal owner cell, not
by the factory reserve.

The materialised child channel can then use the ordinary bilateral publication
and finalisation path:

```sh
cargo run -q -p morph-cli -- devnet publish-state \
  --state-out-point "$CHILD_STATE_OUT_POINT" \
  --sponsor-out-point "$CHILD_SPONSOR_OUT_POINT" \
  --json > target/factory-child-publish.json

CHILD_PUBLISHED_STATE_OUT_POINT="$(
  jq -r '.state_out_point.tx_hash + ":" + (.state_out_point.index | tostring)' \
    target/factory-child-publish.json
)"

cargo run -q -p morph-cli -- devnet finalise-channel \
  --state-out-point "$CHILD_PUBLISHED_STATE_OUT_POINT" \
  --vault-out-point "$CHILD_VAULT_OUT_POINT" \
  --json > target/factory-child-finalise.json
```

The open/package/update part is also available as a single smoke command:

```sh
cargo run -q -p morph-cli -- devnet factory-smoke --json \
  > target/factory-smoke.json
```

The typed-reserve path is available as a single CKB+xUDT smoke. It opens a
FactoryVaultCell carrying the devnet xUDT type, exits into a child xUDT vault,
publishes the child state, and finalises through the ordinary xUDT vault path:

```sh
cargo run -q -p morph-cli -- devnet factory-xudt-smoke --json \
  > target/factory-xudt-smoke.json
```

The corresponding negative smoke first attempts a factory-local exit where the
child xUDT vault amount is one unit lower than the committed descriptor, while
the factory-vault change output keeps total xUDT supply conserved. The expected
rejection is `SettlementOutputMismatch`; the command then performs the valid
exit, publication, and finalisation path:

```sh
cargo run -q -p morph-cli -- devnet factory-xudt-negative-smoke --json \
  > target/factory-xudt-negative-smoke.json
```

Each `factory-exit-channel` and `factory-xudt-smoke` report includes
`local_exit_package`. To validate that package independently:

```sh
jq '.exit.local_exit_package' target/factory-xudt-smoke.json \
  > target/factory-local-exit.json
cargo run -q -p morph-cli -- validate-factory-local-exit-package \
  target/factory-local-exit.json \
  --json
```

The repository-level `scripts/devnet-smoke.sh` includes the additional
factory-local exit, reduced-exit, child publication, child finalisation, and
factory xUDT child-channel steps, including the factory xUDT negative path and
the active CKB reduced reserve-claim path.
`devnet-smoke-report` validates any embedded
`local_exit_package` while building the summary, so a malformed package fails
the report rather than being silently displayed. It also parses watchtower
JSONL alerts, and `devnet-smoke-assert` requires the default smoke run to show
`older_state_detected`, `publication_submitted`, `splice_detected`, and
`splice_package_stale` alerts.

For production-shaped devnet acceptance, run `make devnet-stateful-e2e`. This
starts a fresh local CKB devnet, runs the same on-chain smoke matrix, and then
records a stateful scenario layer under
`target/devnet-stateful-e2e/<run>/scenarios/`. The scenario layer groups the
chain evidence into bilateral lifecycle, sponsor pressure, splice lifecycle,
factory lifecycle, watchtower operations, extreme value cases, and negative
attack-shaped cases. It also evaluates the generalized audit profile in
`docs/devnet-audit-profile.example.json`, which requires each protocol risk
family to have scenario tags, committed checks, exact expected failures, and
budget evidence. Use `devnet-stateful-report`,
`devnet-stateful-assert --audit-profile docs/devnet-audit-profile.example.json --budget-profile docs/devnet-stateful-budget.example.json`,
and `devnet-stateful-compare --audit-profile docs/devnet-audit-profile.example.json`
to review, gate, or compare those artifacts.

## Remaining Devnet Gap

The current vertical slice covers bilateral CKB-only vaults, a devnet CKB+xUDT
vault, watchtower policy/alerts, a CKB-VM-tested conservative factory type
script, a factory reserve lock, devnet factory open/update transactions,
conservative factory-local exit materialisation into plain CKB and CKB+xUDT
child bilateral channels, a bounded reduced-rights proof for claim-reducing
factory updates, and bounded reduced-exit paths that release reserve claims into
child CKB and CKB+xUDT channels. xUDT reduced-exit V1 is covered at the
contract/CKB-VM and devnet smoke layers with typed child-vault and FactoryVault
change binding.
The current devnet roadmap covers the fixed-width reduced-rights,
sparse-Merkle, CKB reduced-exit, and xUDT reduced-exit smoke paths. General
proof paths for larger factories remain deferred beyond this slice.

The factory research track has a host-side package format that can be exercised
without a node:

```sh
cargo run -q -p morph-cli -- print-factory-fixture > target/factory-update.json
cargo run -q -p morph-cli -- validate-factory-package \
  target/factory-update.json \
  --json
cargo run -q -p morph-cli -- print-factory-state-fixture > target/factory-state.json
cargo run -q -p morph-cli -- validate-factory-state-package \
  target/factory-state.json \
  --json
cargo run -q -p morph-cli -- print-factory-reduced-rights-fixture \
  > target/factory-reduced-rights.json
cargo run -q -p morph-cli -- validate-factory-reduced-rights-package \
  target/factory-reduced-rights.json \
  --json
cargo run -q -p morph-cli -- print-factory-reduced-exit-fixture \
  > target/factory-reduced-exit.json
cargo run -q -p morph-cli -- validate-factory-reduced-exit-package \
  target/factory-reduced-exit.json \
  --json
cargo run -q -p morph-cli -- print-factory-merkle-update-fixture \
  > target/factory-merkle-update.json
cargo run -q -p morph-cli -- validate-factory-merkle-update-package \
  target/factory-merkle-update.json \
  --json
cargo run -q -p morph-cli -- print-factory-local-exit-fixture \
  > target/factory-local-exit.json
cargo run -q -p morph-cli -- validate-factory-local-exit-package \
  target/factory-local-exit.json \
  --json
cargo run -q -p morph-cli -- print-factory-splice-fixture --kind splice-in \
  > target/factory-splice-in.json
cargo run -q -p morph-cli -- validate-factory-splice-package \
  target/factory-splice-in.json \
  --json
cargo run -q -p morph-cli -- print-factory-splice-fixture --kind xudt-splice-out \
  > target/factory-xudt-splice-out.json
cargo run -q -p morph-cli -- validate-factory-splice-package \
  target/factory-xudt-splice-out.json \
  --json
cargo run -q -p morph-cli -- print-factory-reduced-splice-fixture --kind splice-in \
  > target/factory-reduced-splice-in.json
cargo run -q -p morph-cli -- validate-factory-reduced-splice-package \
  target/factory-reduced-splice-in.json \
  --json
cargo run -q -p morph-cli -- print-factory-reduced-splice-fixture --kind xudt-splice-out \
  > target/factory-reduced-xudt-splice-out.json
cargo run -q -p morph-cli -- validate-factory-reduced-splice-package \
  target/factory-reduced-xudt-splice-out.json \
  --json
```

Those host-side commands check canonical roots, canonical participant sets,
`non_interference_digest`, the rights-dependency predicate, and conservative
participant-id/public-key bindings with all-participant signatures over a
domain-separated factory-state digest. The Merkle update package proves a
single right transition inside an arbitrary sparse rights tree and requires the
same sibling frontier before and after, so the package can show a larger
factory root transition without carrying the full rights set. The local-exit
package validator checks the embedded factory signatures, child state number
and phase, settlement descriptor commitment, output indices, script hashes, and
the digest bound into the updated FactoryStateHeader. The factory-splice
package validator checks the M6 reserve-repartition rule: one participant
reserve claim must increase or decrease by exactly the CKB/xUDT factory-vault
delta signed into the package. `validate-factory-splice-package` also reports
the fixed-width `FactorySpliceWitnessV1` as `contract_witness_hex`.
The reduced factory-splice package validator keeps the same reserve/vault delta
rule but replaces the full rights set with one sparse-Merkle reserve-claim proof
and requires exactly the authorised participant signature over the factory
splice header. It also emits fixed-width `FactoryReducedSpliceWitnessV1` bytes
as `contract_witness_hex`; this reduced contract path keeps the access manifest
root unchanged because the sparse proof only proves the rights-root transition.

A live FactoryStateCell/FactoryVaultCell pair can now be captured into the same
package format and then applied with the contract-facing witness:

```sh
cargo run -q -p morph-cli -- devnet save-factory-splice-package \
  --factory-out-point <factory-tx>:0 \
  --factory-vault-out-point <factory-tx>:1 \
  --kind splice-in \
  --asset ckb \
  --ckb-amount 1000000000 \
  --store-dir target/morph-factory-splice-packages \
  --json

cargo run -q -p morph-cli -- devnet apply-factory-splice \
  --factory-out-point <factory-tx>:0 \
  --factory-vault-out-point <factory-tx>:1 \
  --factory-splice-package target/morph-factory-splice-packages/<package>.json \
  --json

cargo run -q -p morph-cli -- devnet save-factory-reduced-splice-package \
  --factory-out-point <factory-tx>:0 \
  --factory-vault-out-point <factory-tx>:1 \
  --kind splice-in \
  --asset ckb \
  --ckb-amount 1000000000 \
  --store-dir target/morph-factory-splice-packages \
  --json

cargo run -q -p morph-cli -- devnet apply-factory-reduced-splice \
  --factory-out-point <factory-tx>:0 \
  --factory-vault-out-point <factory-tx>:1 \
  --factory-reduced-splice-package target/morph-factory-splice-packages/<reduced-package>.json \
  --json

cargo run -q -p morph-cli -- devnet factory-splice-in-smoke --json
cargo run -q -p morph-cli -- devnet factory-splice-out-smoke --json
cargo run -q -p morph-cli -- devnet factory-reduced-splice-in-smoke --json
cargo run -q -p morph-cli -- devnet factory-reduced-splice-out-smoke --json
cargo run -q -p morph-cli -- devnet factory-reduced-xudt-splice-in-smoke --json
cargo run -q -p morph-cli -- devnet factory-reduced-xudt-splice-out-smoke --json
cargo run -q -p morph-cli -- devnet factory-xudt-splice-in-smoke --json
cargo run -q -p morph-cli -- devnet factory-xudt-splice-out-smoke --json
```

The live builder is deliberately narrow: the current FactoryStateCell root must
match the conservative V1 reserve-claim shape for Alice and Bob. The apply
command consumes the FactoryStateCell, FactoryVaultCell, an owner fee cell, and
an optional xUDT external input for xUDT splice-in. Splice-out withdrawal
outputs are derived from the touched participant's signed secp256k1 key. The
reduced save/apply commands use the same live transaction shape but feed
`FactoryReducedSpliceWitnessV1` to both factory scripts, keeping the access
manifest root unchanged and proving only the touched reserve claim through the
sparse Merkle witness.

The CKB and xUDT smoke wrappers open a factory, capture a live factory splice
package, apply the splice, and then materialise a child channel from the
post-splice FactoryVaultCell with full-participant authorisation. The reduced
CKB and xUDT smoke wrappers run the same lifecycle with the sparse-Merkle
splice witness.
The xUDT splice-in wrapper mints a participant-owned external xUDT cell before
applying the package, while xUDT splice-out derives the participant-owned
withdrawal output from the signed package participant key.

The `morph-factory-type` script executes in CKB-VM tests, accepts a canonical
initial FactoryStateCell, accepts a signed monotonic factory update, and
rejects equal update numbers or invalid participant signatures. It also accepts
a bounded reduced-rights witness that proves old/new rights roots, access
roots, non-interference digest, and one authorised signature for a
claim-reducing update; attempted claim inflation is rejected in CKB-VM tests.
For larger factories it accepts `FactoryMerkleUpdateWitnessV1`, a fixed
256-sibling sparse Merkle proof for one authorised right transition, and
rejects sibling tampering. In the conservative local-exit path it verifies the
child channel evidence committed by the factory header, including xUDT
child-vault type and amount checks, while `morph-factory-vault-lock` enforces
reserve conservation. The devnet CLI now also publishes the bounded
reduced-rights update witness in `factory-reduced-rights-smoke`, publishes the
reserve-claim reduced-exit witness in `factory-reduced-exit-smoke`, publishes
the sparse Merkle update witness in `factory-merkle-update-smoke`, publishes
reduced CKB/xUDT splice witnesses in `factory-reduced-splice-*-smoke` and
`factory-reduced-xudt-splice-*-smoke`, and records the reduced-rights, sparse
Merkle, reduced-exit, and reduced-splice proof shapes in the smoke summary's
factory proof profile table.
