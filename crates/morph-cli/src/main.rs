use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result, ensure};
use clap::{Parser, Subcommand};
use devnet::{
    CompetingSpendSmokeOptions, DEFAULT_ALICE_PRIVATE_KEY, DEFAULT_BOB_PRIVATE_KEY,
    DEFAULT_DEVNET_PRIVATE_KEY, DeployContractsOptions, FactoryExitChannelOptions,
    FactoryExitChannelTamper, FactoryReducedRightsSmokeOptions, FactorySmokeOptions,
    FactoryXudtNegativeSmokeOptions, FactoryXudtSmokeOptions, FinaliseChannelOptions,
    FinaliseSinceNegativeSmokeOptions, FundSponsorOptions, OpenChannelOptions, OpenFactoryOptions,
    PublishLatestStatePackageOptions, PublishStateOptions, SaveFactoryReducedRightsPackageOptions,
    SaveFactoryStatePackageOptions, SaveStatePackageOptions, SponsorBudgetNegativeSmokeOptions,
    SponsorPolicyNegativeSmokeOptions, SupersedeSmokeOptions, UpdateFactoryOptions,
    WatchLatestStatePackageOptions, XudtNegativeSmokeOptions, XudtSmokeOptions,
};
use k256::ecdsa::signature::hazmat::PrehashSigner;
use k256::ecdsa::{Signature, SigningKey};
use morph_core::*;
use rpc::{CkbRpcClient, HeaderView};

mod devnet;
mod factory_packages;
mod packages;
mod rpc;
mod smoke_report;
mod watch_alert;
mod watch_config;
mod watch_policy;

#[derive(Debug, Parser)]
#[command(name = "morph")]
#[command(about = "Morph Channel devnet and invariant tooling")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[allow(clippy::large_enum_variant)]
#[derive(Debug, Subcommand)]
enum Command {
    /// Validate the built-in bilateral-channel fixture.
    ValidateFixture,
    /// Print a JSON state header fixture and signing digest.
    PrintFixture,
    /// Print a valid host-side factory non-interference package fixture.
    PrintFactoryFixture,
    /// Print a conservative all-participant signed factory state package fixture.
    PrintFactoryStateFixture,
    /// Print a host-side authorised-participant signed factory state package fixture.
    PrintReducedFactoryStateFixture,
    /// Print an on-chain reduced-rights factory update package fixture.
    PrintFactoryReducedRightsFixture,
    /// Print a valid factory local-exit evidence package fixture.
    PrintFactoryLocalExitFixture,
    /// Print a sample watchtower operator policy.
    PrintWatchPolicyFixture,
    /// Print a sample multi-channel watchtower config.
    PrintWatchConfigFixture,
    /// Validate a watchtower operator policy.
    ValidateWatchPolicy {
        /// Path to the watchtower policy JSON.
        path: std::path::PathBuf,
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// Validate a multi-channel watchtower config.
    ValidateWatchConfig {
        /// Path to the watchtower config JSON.
        path: std::path::PathBuf,
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// Validate a host-side factory non-interference package.
    ValidateFactoryPackage {
        /// Path to the factory update package JSON.
        path: std::path::PathBuf,
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// Validate a conservative all-participant signed factory state package.
    ValidateFactoryStatePackage {
        /// Path to the factory state package JSON.
        path: std::path::PathBuf,
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// Validate an on-chain reduced-rights factory update package.
    ValidateFactoryReducedRightsPackage {
        /// Path to the factory reduced-rights package JSON.
        path: std::path::PathBuf,
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// Validate a factory local-exit evidence package.
    ValidateFactoryLocalExitPackage {
        /// Path to the factory local-exit package JSON.
        path: std::path::PathBuf,
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// Summarise a completed scripts/devnet-smoke.sh output directory.
    DevnetSmokeReport {
        /// Directory produced by scripts/devnet-smoke.sh.
        #[arg(long, default_value = "target/devnet-smoke/latest")]
        dir: std::path::PathBuf,
        /// Emit machine-readable JSON instead of Markdown.
        #[arg(long)]
        json: bool,
    },
    /// Assert that a completed devnet smoke directory covers required paths.
    DevnetSmokeAssert {
        /// Directory produced by scripts/devnet-smoke.sh.
        #[arg(long, default_value = "target/devnet-smoke/latest")]
        dir: std::path::PathBuf,
        /// Directory containing the built RISC-V contract binaries.
        #[arg(long, default_value = "target/riscv64imac-unknown-none-elf/release")]
        contracts_dir: std::path::PathBuf,
        /// Skip checking deployed script hashes against local contract binaries.
        #[arg(long)]
        skip_contract_hash_check: bool,
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// Compare two completed devnet smoke output directories.
    DevnetSmokeCompare {
        /// Baseline directory produced by scripts/devnet-smoke.sh.
        #[arg(long)]
        baseline: std::path::PathBuf,
        /// Candidate directory produced by scripts/devnet-smoke.sh.
        #[arg(long)]
        candidate: std::path::PathBuf,
        /// Fail if the candidate has added or missing transaction entries.
        #[arg(long)]
        fail_on_transaction_set_change: bool,
        /// Fail if any compared transaction status changed.
        #[arg(long)]
        fail_on_status_change: bool,
        /// Maximum allowed absolute total estimated-cycle delta.
        #[arg(long)]
        max_abs_total_cycle_delta: Option<u64>,
        /// Maximum allowed absolute per-transaction estimated-cycle delta.
        #[arg(long)]
        max_abs_tx_cycle_delta: Option<u64>,
        /// Maximum allowed absolute total transaction-size delta.
        #[arg(long)]
        max_abs_total_byte_delta: Option<u64>,
        /// Maximum allowed absolute per-transaction transaction-size delta.
        #[arg(long)]
        max_abs_tx_byte_delta: Option<u64>,
        /// Emit machine-readable JSON instead of Markdown.
        #[arg(long)]
        json: bool,
    },
    /// Talk to a local CKB devnet node without relying on ckb-cli.
    Devnet {
        /// CKB JSON-RPC endpoint.
        #[arg(long, env = "MORPH_CKB_RPC", default_value = "http://127.0.0.1:18114")]
        rpc_url: String,
        #[command(subcommand)]
        command: DevnetCommand,
    },
}

#[derive(Debug, Subcommand)]
enum DevnetCommand {
    /// Print chain, node, and tip status.
    Check {
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// Print the current canonical tip header.
    Tip {
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// Wait until the node reaches at least the requested block number.
    WaitTip {
        /// Minimum canonical block number.
        min_number: u64,
        /// Maximum time to wait.
        #[arg(long, default_value_t = 60)]
        timeout_secs: u64,
        /// Poll interval in milliseconds.
        #[arg(long, default_value_t = 1_000)]
        poll_ms: u64,
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// Generate one or more dev blocks through CKB integration-test RPC.
    Mine {
        /// Number of blocks to generate.
        #[arg(long, default_value_t = 1)]
        blocks: u64,
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// Deploy the Morph contract binaries to local devnet.
    DeployContracts {
        /// Directory containing the built RISC-V contract binaries.
        #[arg(long, default_value = "target/riscv64imac-unknown-none-elf/release")]
        contracts_dir: std::path::PathBuf,
        /// Secp256k1 private key that controls a funded local-devnet cell.
        #[arg(
            long,
            env = "MORPH_DEVNET_PRIVATE_KEY",
            default_value = DEFAULT_DEVNET_PRIVATE_KEY
        )]
        private_key: String,
        /// Absolute fee to reserve for the deployment transaction, in shannons.
        #[arg(long, default_value_t = 100_000_000)]
        fee: u64,
        /// Mine this many blocks after broadcasting. Use 0 to only submit to tx-pool.
        #[arg(long, default_value_t = 4)]
        mine_blocks: u64,
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// Open a bilateral Morph channel on local devnet using deployed Morph scripts.
    OpenChannel {
        /// Directory containing the built RISC-V contract binaries.
        #[arg(long, default_value = "target/riscv64imac-unknown-none-elf/release")]
        contracts_dir: std::path::PathBuf,
        /// Secp256k1 private key that controls a funded local-devnet cell.
        #[arg(
            long,
            env = "MORPH_DEVNET_PRIVATE_KEY",
            default_value = DEFAULT_DEVNET_PRIVATE_KEY
        )]
        private_key: String,
        /// Devnet Alice channel key.
        #[arg(long, env = "MORPH_ALICE_PRIVATE_KEY", default_value = DEFAULT_ALICE_PRIVATE_KEY)]
        alice_private_key: String,
        /// Devnet Bob channel key.
        #[arg(long, env = "MORPH_BOB_PRIVATE_KEY", default_value = DEFAULT_BOB_PRIVATE_KEY)]
        bob_private_key: String,
        /// Capacity placed under the channel vault lock, in shannons.
        #[arg(long, default_value_t = 20_000_000_000)]
        vault_capacity: u64,
        /// Alice's descriptor capacity, in shannons. Must be paired with --bob-capacity.
        #[arg(long)]
        alice_capacity: Option<u64>,
        /// Bob's descriptor capacity, in shannons. Must be paired with --alice-capacity.
        #[arg(long)]
        bob_capacity: Option<u64>,
        /// Capacity placed under the sponsor lock, in shannons.
        #[arg(long, default_value_t = 50_000_000_000)]
        sponsor_capacity: u64,
        /// Lowest state number the initial SponsorCell may pay for.
        #[arg(long, default_value_t = 0)]
        sponsor_min_state_number: u64,
        /// Highest state number the initial SponsorCell may pay for.
        #[arg(long, default_value_t = u64::MAX)]
        sponsor_max_state_number: u64,
        /// Maximum fee this SponsorCell may pay in one publication transaction.
        #[arg(long)]
        sponsor_max_fee_per_tx: Option<u64>,
        /// Maximum total fee this SponsorCell may pay.
        #[arg(long)]
        sponsor_max_total_fee: Option<u64>,
        /// Absolute fee to reserve for the open-channel transaction, in shannons.
        #[arg(long, default_value_t = 100_000_000)]
        fee: u64,
        /// Raw relative-since value required before finalisation.
        #[arg(long, default_value_t = 4)]
        finalise_since: u64,
        /// Mine this many blocks after broadcasting. Use 0 to only submit to tx-pool.
        #[arg(long, default_value_t = 4)]
        mine_blocks: u64,
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// Open a conservative two-party Morph factory state cell on local devnet.
    OpenFactory {
        /// Directory containing the built RISC-V contract binaries.
        #[arg(long, default_value = "target/riscv64imac-unknown-none-elf/release")]
        contracts_dir: std::path::PathBuf,
        /// Secp256k1 private key that controls a funded local-devnet cell.
        #[arg(
            long,
            env = "MORPH_DEVNET_PRIVATE_KEY",
            default_value = DEFAULT_DEVNET_PRIVATE_KEY
        )]
        private_key: String,
        /// Devnet Alice factory signing key.
        #[arg(long, env = "MORPH_ALICE_PRIVATE_KEY", default_value = DEFAULT_ALICE_PRIVATE_KEY)]
        alice_private_key: String,
        /// Devnet Bob factory signing key.
        #[arg(long, env = "MORPH_BOB_PRIVATE_KEY", default_value = DEFAULT_BOB_PRIVATE_KEY)]
        bob_private_key: String,
        /// Capacity placed under the FactoryStateCell, in shannons.
        #[arg(long, default_value_t = 50_000_000_000)]
        factory_capacity: u64,
        /// Reserve capacity placed under the FactoryVaultCell, in shannons.
        #[arg(long, default_value_t = 300_000_000_000)]
        factory_vault_capacity: u64,
        /// Optional devnet xUDT amount placed under the FactoryVaultCell.
        #[arg(long)]
        factory_vault_xudt_amount: Option<u128>,
        /// Optional 32-byte state root for the initial factory state.
        #[arg(long)]
        state_root: Option<String>,
        /// Optional 32-byte access-manifest root for the initial factory state.
        #[arg(long)]
        access_manifest_root: Option<String>,
        /// Optional 32-byte non-interference digest for the initial factory state.
        #[arg(long)]
        non_interference_digest: Option<String>,
        /// Absolute fee to reserve for the open-factory transaction, in shannons.
        #[arg(long, default_value_t = 100_000_000)]
        fee: u64,
        /// Mine this many blocks after broadcasting. Use 0 to only submit to tx-pool.
        #[arg(long, default_value_t = 4)]
        mine_blocks: u64,
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// Advance a Morph factory state cell using all-participant signatures.
    UpdateFactory {
        /// Directory containing the built RISC-V contract binaries.
        #[arg(long, default_value = "target/riscv64imac-unknown-none-elf/release")]
        contracts_dir: std::path::PathBuf,
        /// Secp256k1 private key that controls the FactoryStateCell and fee input.
        #[arg(
            long,
            env = "MORPH_DEVNET_PRIVATE_KEY",
            default_value = DEFAULT_DEVNET_PRIVATE_KEY
        )]
        private_key: String,
        /// Devnet Alice factory signing key.
        #[arg(long, env = "MORPH_ALICE_PRIVATE_KEY", default_value = DEFAULT_ALICE_PRIVATE_KEY)]
        alice_private_key: String,
        /// Devnet Bob factory signing key.
        #[arg(long, env = "MORPH_BOB_PRIVATE_KEY", default_value = DEFAULT_BOB_PRIVATE_KEY)]
        bob_private_key: String,
        /// Current FactoryStateCell out point, formatted as <tx-hash>:<index>.
        #[arg(long)]
        factory_out_point: String,
        /// New update number. Defaults to old_update_number + 1.
        #[arg(long)]
        update_number: Option<u64>,
        /// Optional 32-byte replacement state root.
        #[arg(long)]
        state_root: Option<String>,
        /// Optional 32-byte replacement access-manifest root.
        #[arg(long)]
        access_manifest_root: Option<String>,
        /// Optional 32-byte replacement non-interference digest.
        #[arg(long)]
        non_interference_digest: Option<String>,
        /// Signed factory state package JSON. When set, Alice/Bob keys and root overrides are not used.
        #[arg(
            long,
            conflicts_with_all = [
                "update_number",
                "state_root",
                "access_manifest_root",
                "non_interference_digest"
            ]
        )]
        factory_state_package: Option<std::path::PathBuf>,
        /// Absolute fee paid by a normal owner cell, in shannons.
        #[arg(long, default_value_t = 100_000_000)]
        fee: u64,
        /// Mine this many blocks after broadcasting. Use 0 to only submit to tx-pool.
        #[arg(long, default_value_t = 4)]
        mine_blocks: u64,
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// Save a signed factory state package without broadcasting it.
    SaveFactoryStatePackage {
        /// Devnet Alice factory signing key.
        #[arg(long, env = "MORPH_ALICE_PRIVATE_KEY", default_value = DEFAULT_ALICE_PRIVATE_KEY)]
        alice_private_key: String,
        /// Devnet Bob factory signing key.
        #[arg(long, env = "MORPH_BOB_PRIVATE_KEY", default_value = DEFAULT_BOB_PRIVATE_KEY)]
        bob_private_key: String,
        /// Current FactoryStateCell out point, formatted as <tx-hash>:<index>.
        #[arg(long)]
        factory_out_point: String,
        /// New update number. Defaults to old_update_number + 1.
        #[arg(long)]
        update_number: Option<u64>,
        /// Optional 32-byte replacement state root.
        #[arg(long)]
        state_root: Option<String>,
        /// Optional 32-byte replacement access-manifest root.
        #[arg(long)]
        access_manifest_root: Option<String>,
        /// Optional 32-byte replacement non-interference digest.
        #[arg(long)]
        non_interference_digest: Option<String>,
        /// Directory where signed factory state packages are stored.
        #[arg(long, default_value = "target/morph-factory-state-packages")]
        store_dir: std::path::PathBuf,
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// Save a reduced-rights factory update package without broadcasting it.
    SaveFactoryReducedRightsPackage {
        /// Devnet Alice factory signing key. Alice is the touched participant in the bounded V1 proof.
        #[arg(long, env = "MORPH_ALICE_PRIVATE_KEY", default_value = DEFAULT_ALICE_PRIVATE_KEY)]
        alice_private_key: String,
        /// Devnet Bob factory key used to prove full factory membership. Bob does not sign the reduced update.
        #[arg(long, env = "MORPH_BOB_PRIVATE_KEY", default_value = DEFAULT_BOB_PRIVATE_KEY)]
        bob_private_key: String,
        /// Current FactoryStateCell out point, formatted as <tx-hash>:<index>.
        #[arg(long)]
        factory_out_point: String,
        /// New update number. Defaults to old_update_number + 1.
        #[arg(long)]
        update_number: Option<u64>,
        /// New Alice balance quantity in the bounded rights fixture. Must be lower than 100.
        #[arg(long, default_value_t = 90)]
        touched_after_balance: u128,
        /// Directory where reduced-rights factory packages are stored.
        #[arg(long, default_value = "target/morph-factory-state-packages")]
        store_dir: std::path::PathBuf,
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// List saved signed factory state packages.
    ListFactoryStatePackages {
        /// Directory where signed factory state packages are stored.
        #[arg(long, default_value = "target/morph-factory-state-packages")]
        store_dir: std::path::PathBuf,
        /// Optional factory id filter.
        #[arg(long)]
        factory_id: Option<String>,
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// Select the highest-numbered saved factory state package.
    LatestFactoryStatePackage {
        /// Directory where signed factory state packages are stored.
        #[arg(long, default_value = "target/morph-factory-state-packages")]
        store_dir: std::path::PathBuf,
        /// Factory id to select.
        #[arg(long)]
        factory_id: String,
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// Run open -> save package -> package update for a conservative factory.
    FactorySmoke {
        /// Directory containing the built RISC-V contract binaries.
        #[arg(long, default_value = "target/riscv64imac-unknown-none-elf/release")]
        contracts_dir: std::path::PathBuf,
        /// Secp256k1 private key that controls funded local-devnet cells.
        #[arg(
            long,
            env = "MORPH_DEVNET_PRIVATE_KEY",
            default_value = DEFAULT_DEVNET_PRIVATE_KEY
        )]
        private_key: String,
        /// Devnet Alice factory signing key.
        #[arg(long, env = "MORPH_ALICE_PRIVATE_KEY", default_value = DEFAULT_ALICE_PRIVATE_KEY)]
        alice_private_key: String,
        /// Devnet Bob factory signing key.
        #[arg(long, env = "MORPH_BOB_PRIVATE_KEY", default_value = DEFAULT_BOB_PRIVATE_KEY)]
        bob_private_key: String,
        /// Capacity placed under the FactoryStateCell, in shannons.
        #[arg(long, default_value_t = 50_000_000_000)]
        factory_capacity: u64,
        /// Reserve capacity placed under the FactoryVaultCell, in shannons.
        #[arg(long, default_value_t = 300_000_000_000)]
        factory_vault_capacity: u64,
        /// Absolute fee paid by each transaction, in shannons.
        #[arg(long, default_value_t = 100_000_000)]
        fee: u64,
        /// Mine this many blocks after each broadcast. Use 0 to only submit to tx-pool.
        #[arg(long, default_value_t = 4)]
        mine_blocks: u64,
        /// Directory where signed factory state packages are stored.
        #[arg(long, default_value = "target/morph-factory-state-packages")]
        store_dir: std::path::PathBuf,
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// Run open -> save reduced-rights package -> package update for a bounded reduced factory proof.
    FactoryReducedRightsSmoke {
        /// Directory containing the built RISC-V contract binaries.
        #[arg(long, default_value = "target/riscv64imac-unknown-none-elf/release")]
        contracts_dir: std::path::PathBuf,
        /// Secp256k1 private key that controls funded local-devnet cells.
        #[arg(
            long,
            env = "MORPH_DEVNET_PRIVATE_KEY",
            default_value = DEFAULT_DEVNET_PRIVATE_KEY
        )]
        private_key: String,
        /// Devnet Alice factory signing key. Alice signs the reduced update.
        #[arg(long, env = "MORPH_ALICE_PRIVATE_KEY", default_value = DEFAULT_ALICE_PRIVATE_KEY)]
        alice_private_key: String,
        /// Devnet Bob factory key used to prove full membership.
        #[arg(long, env = "MORPH_BOB_PRIVATE_KEY", default_value = DEFAULT_BOB_PRIVATE_KEY)]
        bob_private_key: String,
        /// Capacity placed under the FactoryStateCell, in shannons.
        #[arg(long, default_value_t = 50_000_000_000)]
        factory_capacity: u64,
        /// Reserve capacity placed under the FactoryVaultCell, in shannons.
        #[arg(long, default_value_t = 300_000_000_000)]
        factory_vault_capacity: u64,
        /// New Alice balance quantity in the bounded rights fixture. Must be lower than 100.
        #[arg(long, default_value_t = 90)]
        touched_after_balance: u128,
        /// Absolute fee paid by each transaction, in shannons.
        #[arg(long, default_value_t = 100_000_000)]
        fee: u64,
        /// Mine this many blocks after each broadcast. Use 0 to only submit to tx-pool.
        #[arg(long, default_value_t = 4)]
        mine_blocks: u64,
        /// Directory where reduced-rights factory packages are stored.
        #[arg(long, default_value = "target/morph-factory-state-packages")]
        store_dir: std::path::PathBuf,
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// Run a conservative factory-local CKB+xUDT child-channel smoke.
    FactoryXudtSmoke {
        /// Directory containing the built RISC-V contract binaries.
        #[arg(long, default_value = "target/riscv64imac-unknown-none-elf/release")]
        contracts_dir: std::path::PathBuf,
        /// Secp256k1 private key that controls funded local-devnet cells.
        #[arg(
            long,
            env = "MORPH_DEVNET_PRIVATE_KEY",
            default_value = DEFAULT_DEVNET_PRIVATE_KEY
        )]
        private_key: String,
        /// Devnet Alice factory/channel signing key.
        #[arg(long, env = "MORPH_ALICE_PRIVATE_KEY", default_value = DEFAULT_ALICE_PRIVATE_KEY)]
        alice_private_key: String,
        /// Devnet Bob factory/channel signing key.
        #[arg(long, env = "MORPH_BOB_PRIVATE_KEY", default_value = DEFAULT_BOB_PRIVATE_KEY)]
        bob_private_key: String,
        /// Capacity placed under the FactoryStateCell, in shannons.
        #[arg(long, default_value_t = 50_000_000_000)]
        factory_capacity: u64,
        /// Reserve capacity placed under the FactoryVaultCell, in shannons.
        #[arg(long, default_value_t = 300_000_000_000)]
        factory_vault_capacity: u64,
        /// Capacity released from the factory reserve into the child xUDT vault.
        #[arg(long, default_value_t = 40_000_000_000)]
        child_vault_capacity: u64,
        /// Alice's child-channel descriptor capacity. Must be paired with --bob-capacity.
        #[arg(long)]
        alice_capacity: Option<u64>,
        /// Bob's child-channel descriptor capacity. Must be paired with --alice-capacity.
        #[arg(long)]
        bob_capacity: Option<u64>,
        /// Alice's final xUDT settlement amount.
        #[arg(long, default_value_t = 600_000u128)]
        alice_xudt_amount: u128,
        /// Bob's final xUDT settlement amount.
        #[arg(long, default_value_t = 400_000u128)]
        bob_xudt_amount: u128,
        /// Capacity placed under the child channel sponsor lock.
        #[arg(long, default_value_t = 50_000_000_000)]
        sponsor_capacity: u64,
        /// Absolute fee paid by each transaction, in shannons.
        #[arg(long, default_value_t = 100_000_000)]
        fee: u64,
        /// Raw relative-since value required before child-channel finalisation.
        #[arg(long, default_value_t = 4)]
        finalise_since: u64,
        /// Mine this many blocks after each broadcast. Use 0 to only submit to tx-pool.
        #[arg(long, default_value_t = 4)]
        mine_blocks: u64,
        /// Directory where signed factory state packages are stored.
        #[arg(long, default_value = "target/morph-factory-xudt-state-packages")]
        store_dir: std::path::PathBuf,
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// Prove devnet rejects a factory-local xUDT exit with a tampered child vault amount.
    FactoryXudtNegativeSmoke {
        /// Directory containing the built RISC-V contract binaries.
        #[arg(long, default_value = "target/riscv64imac-unknown-none-elf/release")]
        contracts_dir: std::path::PathBuf,
        /// Secp256k1 private key that controls funded local-devnet cells.
        #[arg(
            long,
            env = "MORPH_DEVNET_PRIVATE_KEY",
            default_value = DEFAULT_DEVNET_PRIVATE_KEY
        )]
        private_key: String,
        /// Devnet Alice factory/channel signing key.
        #[arg(long, env = "MORPH_ALICE_PRIVATE_KEY", default_value = DEFAULT_ALICE_PRIVATE_KEY)]
        alice_private_key: String,
        /// Devnet Bob factory/channel signing key.
        #[arg(long, env = "MORPH_BOB_PRIVATE_KEY", default_value = DEFAULT_BOB_PRIVATE_KEY)]
        bob_private_key: String,
        /// Capacity placed under the FactoryStateCell, in shannons.
        #[arg(long, default_value_t = 50_000_000_000)]
        factory_capacity: u64,
        /// Reserve capacity placed under the FactoryVaultCell, in shannons.
        #[arg(long, default_value_t = 300_000_000_000)]
        factory_vault_capacity: u64,
        /// Capacity released from the factory reserve into the child xUDT vault.
        #[arg(long, default_value_t = 40_000_000_000)]
        child_vault_capacity: u64,
        /// Alice's child-channel descriptor capacity. Must be paired with --bob-capacity.
        #[arg(long)]
        alice_capacity: Option<u64>,
        /// Bob's child-channel descriptor capacity. Must be paired with --alice-capacity.
        #[arg(long)]
        bob_capacity: Option<u64>,
        /// Alice's final xUDT settlement amount.
        #[arg(long, default_value_t = 600_000u128)]
        alice_xudt_amount: u128,
        /// Bob's final xUDT settlement amount.
        #[arg(long, default_value_t = 400_000u128)]
        bob_xudt_amount: u128,
        /// Capacity placed under the child channel sponsor lock.
        #[arg(long, default_value_t = 50_000_000_000)]
        sponsor_capacity: u64,
        /// Absolute fee paid by each transaction, in shannons.
        #[arg(long, default_value_t = 100_000_000)]
        fee: u64,
        /// Raw relative-since value required before child-channel finalisation.
        #[arg(long, default_value_t = 4)]
        finalise_since: u64,
        /// Mine this many blocks after each accepted broadcast. Use 0 to only submit to tx-pool.
        #[arg(long, default_value_t = 4)]
        mine_blocks: u64,
        /// Directory where signed factory state packages are stored.
        #[arg(
            long,
            default_value = "target/morph-factory-xudt-negative-state-packages"
        )]
        store_dir: std::path::PathBuf,
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// Materialise a bilateral child channel from a conservative factory reserve.
    FactoryExitChannel {
        /// Directory containing the built RISC-V contract binaries.
        #[arg(long, default_value = "target/riscv64imac-unknown-none-elf/release")]
        contracts_dir: std::path::PathBuf,
        /// Secp256k1 private key that controls the FactoryStateCell and fee input.
        #[arg(
            long,
            env = "MORPH_DEVNET_PRIVATE_KEY",
            default_value = DEFAULT_DEVNET_PRIVATE_KEY
        )]
        private_key: String,
        /// Devnet Alice factory/channel signing key.
        #[arg(long, env = "MORPH_ALICE_PRIVATE_KEY", default_value = DEFAULT_ALICE_PRIVATE_KEY)]
        alice_private_key: String,
        /// Devnet Bob factory/channel signing key.
        #[arg(long, env = "MORPH_BOB_PRIVATE_KEY", default_value = DEFAULT_BOB_PRIVATE_KEY)]
        bob_private_key: String,
        /// Current FactoryStateCell out point, formatted as <tx-hash>:<index>.
        #[arg(long)]
        factory_out_point: String,
        /// Current FactoryVaultCell out point, formatted as <tx-hash>:<index>.
        #[arg(long)]
        factory_vault_out_point: String,
        /// New factory update number. Defaults to old_update_number + 1.
        #[arg(long)]
        update_number: Option<u64>,
        /// Capacity released from the factory reserve into the child channel vault.
        #[arg(long, default_value_t = 20_000_000_000)]
        vault_capacity: u64,
        /// Alice's child-channel descriptor capacity. Must be paired with --bob-capacity.
        #[arg(long)]
        alice_capacity: Option<u64>,
        /// Bob's child-channel descriptor capacity. Must be paired with --alice-capacity.
        #[arg(long)]
        bob_capacity: Option<u64>,
        /// Alice's child-channel xUDT amount when the FactoryVaultCell carries xUDT.
        #[arg(long)]
        alice_xudt_amount: Option<u128>,
        /// Bob's child-channel xUDT amount when the FactoryVaultCell carries xUDT.
        #[arg(long)]
        bob_xudt_amount: Option<u128>,
        /// Capacity placed under the child channel sponsor lock.
        #[arg(long, default_value_t = 50_000_000_000)]
        sponsor_capacity: u64,
        /// Absolute fee paid by a normal owner cell, in shannons.
        #[arg(long, default_value_t = 100_000_000)]
        fee: u64,
        /// Raw relative-since value required before child-channel finalisation.
        #[arg(long, default_value_t = 4)]
        finalise_since: u64,
        /// Mine this many blocks after broadcasting. Use 0 to only submit to tx-pool.
        #[arg(long, default_value_t = 4)]
        mine_blocks: u64,
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// Publish a newer signed settling state, paid by a SponsorCell.
    PublishState {
        /// Directory containing the built RISC-V contract binaries.
        #[arg(long, default_value = "target/riscv64imac-unknown-none-elf/release")]
        contracts_dir: std::path::PathBuf,
        /// Secp256k1 private key that controls the sponsor change lock.
        #[arg(
            long,
            env = "MORPH_DEVNET_PRIVATE_KEY",
            default_value = DEFAULT_DEVNET_PRIVATE_KEY
        )]
        private_key: String,
        /// Devnet Alice channel signing key.
        #[arg(long, env = "MORPH_ALICE_PRIVATE_KEY", default_value = DEFAULT_ALICE_PRIVATE_KEY)]
        alice_private_key: String,
        /// Devnet Bob channel signing key.
        #[arg(long, env = "MORPH_BOB_PRIVATE_KEY", default_value = DEFAULT_BOB_PRIVATE_KEY)]
        bob_private_key: String,
        /// Current StateCell out point, formatted as <tx-hash>:<index>.
        #[arg(long)]
        state_out_point: String,
        /// SponsorCell out point, formatted as <tx-hash>:<index>.
        #[arg(long)]
        sponsor_out_point: String,
        /// New state number. Defaults to old_state_number + 1.
        #[arg(long)]
        state_number: Option<u64>,
        /// Signed state package JSON. When set, Alice/Bob keys are not used.
        #[arg(long, conflicts_with = "state_number")]
        state_package: Option<std::path::PathBuf>,
        /// Absolute fee paid by the SponsorCell, in shannons.
        #[arg(long, default_value_t = 100_000_000)]
        fee: u64,
        /// Mine this many blocks after broadcasting. Use 0 to only submit to tx-pool.
        #[arg(long, default_value_t = 4)]
        mine_blocks: u64,
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// Save a signed settling state package without broadcasting it.
    SaveStatePackage {
        /// Devnet Alice channel signing key.
        #[arg(long, env = "MORPH_ALICE_PRIVATE_KEY", default_value = DEFAULT_ALICE_PRIVATE_KEY)]
        alice_private_key: String,
        /// Devnet Bob channel signing key.
        #[arg(long, env = "MORPH_BOB_PRIVATE_KEY", default_value = DEFAULT_BOB_PRIVATE_KEY)]
        bob_private_key: String,
        /// Current StateCell out point, formatted as <tx-hash>:<index>.
        #[arg(long)]
        state_out_point: String,
        /// New state number. Defaults to old_state_number + 1.
        #[arg(long)]
        state_number: Option<u64>,
        /// Directory where signed state packages are stored.
        #[arg(long, default_value = "target/morph-state-packages")]
        store_dir: std::path::PathBuf,
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// List saved signed state packages.
    ListStatePackages {
        /// Directory where signed state packages are stored.
        #[arg(long, default_value = "target/morph-state-packages")]
        store_dir: std::path::PathBuf,
        /// Optional channel id filter.
        #[arg(long)]
        channel_id: Option<String>,
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// Select the highest-numbered saved state package for a channel.
    LatestStatePackage {
        /// Directory where signed state packages are stored.
        #[arg(long, default_value = "target/morph-state-packages")]
        store_dir: std::path::PathBuf,
        /// Channel id to select.
        #[arg(long)]
        channel_id: String,
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// Publish the highest-numbered saved state package for a channel.
    PublishLatestPackage {
        /// Directory containing the built RISC-V contract binaries.
        #[arg(long, default_value = "target/riscv64imac-unknown-none-elf/release")]
        contracts_dir: std::path::PathBuf,
        /// Secp256k1 private key that controls the sponsor change lock.
        #[arg(
            long,
            env = "MORPH_DEVNET_PRIVATE_KEY",
            default_value = DEFAULT_DEVNET_PRIVATE_KEY
        )]
        private_key: String,
        /// Current StateCell out point, formatted as <tx-hash>:<index>.
        #[arg(long)]
        state_out_point: String,
        /// SponsorCell out point, formatted as <tx-hash>:<index>.
        #[arg(long)]
        sponsor_out_point: String,
        /// Directory where signed state packages are stored.
        #[arg(long, default_value = "target/morph-state-packages")]
        store_dir: std::path::PathBuf,
        /// Channel id to select.
        #[arg(long)]
        channel_id: String,
        /// Absolute fee paid by the SponsorCell, in shannons.
        #[arg(long, default_value_t = 100_000_000)]
        fee: u64,
        /// Mine this many blocks after broadcasting. Use 0 to only submit to tx-pool.
        #[arg(long, default_value_t = 4)]
        mine_blocks: u64,
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// Scan confirmed blocks and publish the latest saved package when an older StateCell is seen.
    WatchLatestPackage {
        /// Directory containing the built RISC-V contract binaries.
        #[arg(long, default_value = "target/riscv64imac-unknown-none-elf/release")]
        contracts_dir: std::path::PathBuf,
        /// Secp256k1 private key that controls the sponsor change lock.
        #[arg(long, env = "MORPH_DEVNET_PRIVATE_KEY")]
        private_key: Option<String>,
        /// File containing the sponsor private key. Prefer this for watchtower processes.
        #[arg(long, env = "MORPH_DEVNET_PRIVATE_KEY_FILE")]
        private_key_file: Option<PathBuf>,
        /// SponsorCell out point, formatted as <tx-hash>:<index>.
        /// Required unless --auto-fund-sponsor is set.
        #[arg(long)]
        sponsor_out_point: Option<String>,
        /// Directory where signed state packages are stored.
        #[arg(long, default_value = "target/morph-state-packages")]
        store_dir: std::path::PathBuf,
        /// Channel id to watch.
        #[arg(long)]
        channel_id: String,
        /// First block number to scan.
        #[arg(long, default_value_t = 0)]
        from_block: u64,
        /// Cursor JSON path. Defaults to the state-package store for this channel.
        #[arg(long)]
        cursor_file: Option<std::path::PathBuf>,
        /// Optional watchtower policy JSON that bounds this run.
        #[arg(long)]
        watch_policy: Option<std::path::PathBuf>,
        /// Optional JSONL alert sink for watchtower events.
        #[arg(long)]
        alert_file: Option<std::path::PathBuf>,
        /// Optional HTTP webhook URL for watchtower alerts.
        #[arg(long)]
        alert_webhook_url: Option<String>,
        /// Start from --from-block even when a saved cursor exists.
        #[arg(long)]
        ignore_cursor: bool,
        /// Required confirmation depth before a StateCell is actionable.
        #[arg(long, default_value_t = 1)]
        detection_depth: u64,
        /// Maximum time to poll before returning without publication.
        #[arg(long, default_value_t = 60)]
        timeout_secs: u64,
        /// Poll interval in milliseconds.
        #[arg(long, default_value_t = 1_000)]
        poll_ms: u64,
        /// Absolute fee paid by the SponsorCell, in shannons.
        #[arg(long, default_value_t = 100_000_000)]
        fee: u64,
        /// Mine this many blocks after broadcasting. Use 0 to only submit to tx-pool.
        #[arg(long, default_value_t = 4)]
        mine_blocks: u64,
        /// Create a narrowly scoped SponsorCell when an older StateCell is observed.
        #[arg(long)]
        auto_fund_sponsor: bool,
        /// Capacity placed under an automatically created SponsorCell, in shannons.
        #[arg(long, default_value_t = 50_000_000_000)]
        auto_sponsor_capacity: u64,
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// Run one configured watchtower pass across multiple channels.
    WatchConfigOnce {
        /// Directory containing the built RISC-V contract binaries.
        #[arg(long, default_value = "target/riscv64imac-unknown-none-elf/release")]
        contracts_dir: std::path::PathBuf,
        /// Secp256k1 private key that controls sponsor funding and change.
        #[arg(long, env = "MORPH_DEVNET_PRIVATE_KEY")]
        private_key: Option<String>,
        /// File containing the sponsor private key. Prefer this for watchtower processes.
        #[arg(long, env = "MORPH_DEVNET_PRIVATE_KEY_FILE")]
        private_key_file: Option<PathBuf>,
        /// Watchtower config JSON path.
        #[arg(long)]
        config: std::path::PathBuf,
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// Run several configured watchtower passes, reusing persisted cursors.
    WatchConfigLoop {
        /// Directory containing the built RISC-V contract binaries.
        #[arg(long, default_value = "target/riscv64imac-unknown-none-elf/release")]
        contracts_dir: std::path::PathBuf,
        /// Secp256k1 private key that controls sponsor funding and change.
        #[arg(long, env = "MORPH_DEVNET_PRIVATE_KEY")]
        private_key: Option<String>,
        /// File containing the sponsor private key. Prefer this for watchtower processes.
        #[arg(long, env = "MORPH_DEVNET_PRIVATE_KEY_FILE")]
        private_key_file: Option<PathBuf>,
        /// Watchtower config JSON path.
        #[arg(long)]
        config: std::path::PathBuf,
        /// Number of passes to run.
        #[arg(long, default_value_t = 3)]
        passes: u64,
        /// Milliseconds to sleep between passes.
        #[arg(long, default_value_t = 1_000)]
        sleep_ms: u64,
        /// Return after the first pass that publishes any state.
        #[arg(long)]
        stop_after_publication: bool,
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// Run a supervised watchtower service with health output and error backoff.
    WatchConfigService {
        /// Directory containing the built RISC-V contract binaries.
        #[arg(long, default_value = "target/riscv64imac-unknown-none-elf/release")]
        contracts_dir: std::path::PathBuf,
        /// Secp256k1 private key that controls sponsor funding and change.
        #[arg(long, env = "MORPH_DEVNET_PRIVATE_KEY")]
        private_key: Option<String>,
        /// File containing the sponsor private key. Prefer this for watchtower processes.
        #[arg(long, env = "MORPH_DEVNET_PRIVATE_KEY_FILE")]
        private_key_file: Option<PathBuf>,
        /// Watchtower config JSON path.
        #[arg(long)]
        config: std::path::PathBuf,
        /// Maximum passes before returning. Omit to run until stopped or failed.
        #[arg(long)]
        max_passes: Option<u64>,
        /// Milliseconds to sleep after a successful pass.
        #[arg(long, default_value_t = 1_000)]
        sleep_ms: u64,
        /// Milliseconds to sleep after a failed pass.
        #[arg(long, default_value_t = 5_000)]
        error_backoff_ms: u64,
        /// Stop after this many consecutive failed passes.
        #[arg(long, default_value_t = 5)]
        max_consecutive_errors: u64,
        /// Return after the first pass that publishes any state.
        #[arg(long)]
        stop_after_publication: bool,
        /// Stop gracefully when this file exists.
        #[arg(long)]
        stop_file: Option<PathBuf>,
        /// JSON health file updated after start, pass, error, and stop events.
        #[arg(long)]
        health_file: Option<PathBuf>,
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// Create a fresh SponsorCell for an existing channel state.
    FundSponsor {
        /// Directory containing the built RISC-V contract binaries.
        #[arg(long, default_value = "target/riscv64imac-unknown-none-elf/release")]
        contracts_dir: std::path::PathBuf,
        /// Secp256k1 private key funding the SponsorCell and receiving change.
        #[arg(
            long,
            env = "MORPH_DEVNET_PRIVATE_KEY",
            default_value = DEFAULT_DEVNET_PRIVATE_KEY
        )]
        private_key: String,
        /// StateCell out point whose channel id should be sponsored.
        #[arg(long)]
        state_out_point: String,
        /// Capacity placed under the sponsor lock, in shannons.
        #[arg(long, default_value_t = 50_000_000_000)]
        sponsor_capacity: u64,
        /// Lowest state number the SponsorCell may pay for.
        #[arg(long, default_value_t = 0)]
        sponsor_min_state_number: u64,
        /// Highest state number the SponsorCell may pay for.
        #[arg(long, default_value_t = u64::MAX)]
        sponsor_max_state_number: u64,
        /// Maximum fee this SponsorCell may pay in one publication transaction.
        #[arg(long)]
        sponsor_max_fee_per_tx: Option<u64>,
        /// Maximum total fee this SponsorCell may pay.
        #[arg(long)]
        sponsor_max_total_fee: Option<u64>,
        /// Absolute fee for the funding transaction, in shannons.
        #[arg(long, default_value_t = 100_000_000)]
        fee: u64,
        /// Mine this many blocks after broadcasting. Use 0 to only submit to tx-pool.
        #[arg(long, default_value_t = 4)]
        mine_blocks: u64,
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// Finalise a settling channel and release the vault according to the descriptor.
    FinaliseChannel {
        /// Directory containing the built RISC-V contract binaries.
        #[arg(long, default_value = "target/riscv64imac-unknown-none-elf/release")]
        contracts_dir: std::path::PathBuf,
        /// Secp256k1 private key receiving the state-carrier refund.
        #[arg(
            long,
            env = "MORPH_DEVNET_PRIVATE_KEY",
            default_value = DEFAULT_DEVNET_PRIVATE_KEY
        )]
        private_key: String,
        /// Devnet Alice settlement key.
        #[arg(long, env = "MORPH_ALICE_PRIVATE_KEY", default_value = DEFAULT_ALICE_PRIVATE_KEY)]
        alice_private_key: String,
        /// Devnet Bob settlement key.
        #[arg(long, env = "MORPH_BOB_PRIVATE_KEY", default_value = DEFAULT_BOB_PRIVATE_KEY)]
        bob_private_key: String,
        /// Current settling StateCell out point, formatted as <tx-hash>:<index>.
        #[arg(long)]
        state_out_point: String,
        /// VaultCell out point, formatted as <tx-hash>:<index>.
        #[arg(long)]
        vault_out_point: String,
        /// Alice's descriptor capacity, in shannons. Must be paired with --bob-capacity.
        #[arg(long)]
        alice_capacity: Option<u64>,
        /// Bob's descriptor capacity, in shannons. Must be paired with --alice-capacity.
        #[arg(long)]
        bob_capacity: Option<u64>,
        /// Raw relative-since value placed on the StateCell input.
        #[arg(long, default_value_t = 4)]
        finalise_since: u64,
        /// Absolute fee paid from the state-carrier refund, in shannons.
        #[arg(long, default_value_t = 100_000_000)]
        fee: u64,
        /// Mine this many blocks after broadcasting. Use 0 to only submit to tx-pool.
        #[arg(long, default_value_t = 4)]
        mine_blocks: u64,
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// Run open -> stale publish -> sponsor top-up -> supersede -> finalise on devnet.
    SupersedeSmoke {
        /// Directory containing the built RISC-V contract binaries.
        #[arg(long, default_value = "target/riscv64imac-unknown-none-elf/release")]
        contracts_dir: std::path::PathBuf,
        /// Secp256k1 private key controlling devnet funding cells.
        #[arg(
            long,
            env = "MORPH_DEVNET_PRIVATE_KEY",
            default_value = DEFAULT_DEVNET_PRIVATE_KEY
        )]
        private_key: String,
        /// Devnet Alice channel key.
        #[arg(long, env = "MORPH_ALICE_PRIVATE_KEY", default_value = DEFAULT_ALICE_PRIVATE_KEY)]
        alice_private_key: String,
        /// Devnet Bob channel key.
        #[arg(long, env = "MORPH_BOB_PRIVATE_KEY", default_value = DEFAULT_BOB_PRIVATE_KEY)]
        bob_private_key: String,
        /// Capacity placed under the channel vault lock, in shannons.
        #[arg(long, default_value_t = 20_000_000_000)]
        vault_capacity: u64,
        /// Alice's descriptor capacity, in shannons. Must be paired with --bob-capacity.
        #[arg(long)]
        alice_capacity: Option<u64>,
        /// Bob's descriptor capacity, in shannons. Must be paired with --alice-capacity.
        #[arg(long)]
        bob_capacity: Option<u64>,
        /// Capacity placed under each sponsor lock, in shannons.
        #[arg(long, default_value_t = 50_000_000_000)]
        sponsor_capacity: u64,
        /// Absolute fee used for each transaction, in shannons.
        #[arg(long, default_value_t = 100_000_000)]
        fee: u64,
        /// Raw relative-since value used by channel finalisation.
        #[arg(long, default_value_t = 4)]
        finalise_since: u64,
        /// Mine this many blocks after each broadcast. Use 0 to only submit to tx-pool.
        #[arg(long, default_value_t = 4)]
        mine_blocks: u64,
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// Prove live devnet rejects finalisation when the StateCell input since is too low.
    FinaliseSinceNegativeSmoke {
        /// Directory containing the built RISC-V contract binaries.
        #[arg(long, default_value = "target/riscv64imac-unknown-none-elf/release")]
        contracts_dir: std::path::PathBuf,
        /// Secp256k1 private key controlling devnet funding cells.
        #[arg(
            long,
            env = "MORPH_DEVNET_PRIVATE_KEY",
            default_value = DEFAULT_DEVNET_PRIVATE_KEY
        )]
        private_key: String,
        /// Devnet Alice channel key.
        #[arg(long, env = "MORPH_ALICE_PRIVATE_KEY", default_value = DEFAULT_ALICE_PRIVATE_KEY)]
        alice_private_key: String,
        /// Devnet Bob channel key.
        #[arg(long, env = "MORPH_BOB_PRIVATE_KEY", default_value = DEFAULT_BOB_PRIVATE_KEY)]
        bob_private_key: String,
        /// Capacity placed under the channel vault lock, in shannons.
        #[arg(long, default_value_t = 20_000_000_000)]
        vault_capacity: u64,
        /// Alice's descriptor capacity, in shannons. Must be paired with --bob-capacity.
        #[arg(long)]
        alice_capacity: Option<u64>,
        /// Bob's descriptor capacity, in shannons. Must be paired with --alice-capacity.
        #[arg(long)]
        bob_capacity: Option<u64>,
        /// Capacity placed under each sponsor lock, in shannons.
        #[arg(long, default_value_t = 50_000_000_000)]
        sponsor_capacity: u64,
        /// Absolute fee used for each transaction, in shannons.
        #[arg(long, default_value_t = 100_000_000)]
        fee: u64,
        /// Raw relative-since value required by channel finalisation.
        #[arg(long, default_value_t = 4)]
        finalise_since: u64,
        /// Mine this many blocks after each accepted broadcast. Use 0 to only submit to tx-pool.
        #[arg(long, default_value_t = 4)]
        mine_blocks: u64,
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// Run open -> publish -> finalise for a CKB+xUDT channel on devnet.
    XudtSmoke {
        /// Directory containing the built RISC-V contract binaries.
        #[arg(long, default_value = "target/riscv64imac-unknown-none-elf/release")]
        contracts_dir: std::path::PathBuf,
        /// Secp256k1 private key controlling devnet funding cells and xUDT mint authority.
        #[arg(
            long,
            env = "MORPH_DEVNET_PRIVATE_KEY",
            default_value = DEFAULT_DEVNET_PRIVATE_KEY
        )]
        private_key: String,
        /// Devnet Alice channel key.
        #[arg(long, env = "MORPH_ALICE_PRIVATE_KEY", default_value = DEFAULT_ALICE_PRIVATE_KEY)]
        alice_private_key: String,
        /// Devnet Bob channel key.
        #[arg(long, env = "MORPH_BOB_PRIVATE_KEY", default_value = DEFAULT_BOB_PRIVATE_KEY)]
        bob_private_key: String,
        /// Capacity placed under the xUDT vault lock, in shannons.
        #[arg(long, default_value_t = 40_000_000_000)]
        vault_capacity: u64,
        /// Alice's descriptor capacity, in shannons. Must be paired with --bob-capacity.
        #[arg(long)]
        alice_capacity: Option<u64>,
        /// Bob's descriptor capacity, in shannons. Must be paired with --alice-capacity.
        #[arg(long)]
        bob_capacity: Option<u64>,
        /// Alice's final xUDT settlement amount.
        #[arg(long, default_value_t = 600_000u128)]
        alice_xudt_amount: u128,
        /// Bob's final xUDT settlement amount.
        #[arg(long, default_value_t = 400_000u128)]
        bob_xudt_amount: u128,
        /// Capacity placed under the sponsor lock, in shannons.
        #[arg(long, default_value_t = 50_000_000_000)]
        sponsor_capacity: u64,
        /// Absolute fee used for each transaction, in shannons.
        #[arg(long, default_value_t = 100_000_000)]
        fee: u64,
        /// Raw relative-since value used by channel finalisation.
        #[arg(long, default_value_t = 4)]
        finalise_since: u64,
        /// Mine this many blocks after each broadcast. Use 0 to only submit to tx-pool.
        #[arg(long, default_value_t = 4)]
        mine_blocks: u64,
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// Prove live devnet rejects tampered CKB+xUDT vault settlement.
    XudtNegativeSmoke {
        /// Directory containing the built RISC-V contract binaries.
        #[arg(long, default_value = "target/riscv64imac-unknown-none-elf/release")]
        contracts_dir: std::path::PathBuf,
        /// Secp256k1 private key controlling devnet funding cells and xUDT mint authority.
        #[arg(
            long,
            env = "MORPH_DEVNET_PRIVATE_KEY",
            default_value = DEFAULT_DEVNET_PRIVATE_KEY
        )]
        private_key: String,
        /// Devnet Alice channel key.
        #[arg(long, env = "MORPH_ALICE_PRIVATE_KEY", default_value = DEFAULT_ALICE_PRIVATE_KEY)]
        alice_private_key: String,
        /// Devnet Bob channel key.
        #[arg(long, env = "MORPH_BOB_PRIVATE_KEY", default_value = DEFAULT_BOB_PRIVATE_KEY)]
        bob_private_key: String,
        /// Capacity placed under the xUDT vault lock, in shannons.
        #[arg(long, default_value_t = 40_000_000_000)]
        vault_capacity: u64,
        /// Alice's descriptor capacity, in shannons. Must be paired with --bob-capacity.
        #[arg(long)]
        alice_capacity: Option<u64>,
        /// Bob's descriptor capacity, in shannons. Must be paired with --alice-capacity.
        #[arg(long)]
        bob_capacity: Option<u64>,
        /// Alice's final xUDT settlement amount.
        #[arg(long, default_value_t = 600_000u128)]
        alice_xudt_amount: u128,
        /// Bob's final xUDT settlement amount.
        #[arg(long, default_value_t = 400_000u128)]
        bob_xudt_amount: u128,
        /// Capacity placed under the sponsor lock, in shannons.
        #[arg(long, default_value_t = 50_000_000_000)]
        sponsor_capacity: u64,
        /// Absolute fee used for each transaction, in shannons.
        #[arg(long, default_value_t = 100_000_000)]
        fee: u64,
        /// Raw relative-since value used by channel finalisation.
        #[arg(long, default_value_t = 4)]
        finalise_since: u64,
        /// Mine this many blocks after each accepted broadcast. Use 0 to only submit to tx-pool.
        #[arg(long, default_value_t = 4)]
        mine_blocks: u64,
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// Prove live devnet rejects a SponsorCell outside its state-number policy.
    SponsorPolicyNegativeSmoke {
        /// Directory containing the built RISC-V contract binaries.
        #[arg(long, default_value = "target/riscv64imac-unknown-none-elf/release")]
        contracts_dir: std::path::PathBuf,
        /// Secp256k1 private key controlling devnet funding cells.
        #[arg(
            long,
            env = "MORPH_DEVNET_PRIVATE_KEY",
            default_value = DEFAULT_DEVNET_PRIVATE_KEY
        )]
        private_key: String,
        /// Devnet Alice channel key.
        #[arg(long, env = "MORPH_ALICE_PRIVATE_KEY", default_value = DEFAULT_ALICE_PRIVATE_KEY)]
        alice_private_key: String,
        /// Devnet Bob channel key.
        #[arg(long, env = "MORPH_BOB_PRIVATE_KEY", default_value = DEFAULT_BOB_PRIVATE_KEY)]
        bob_private_key: String,
        /// Capacity placed under the channel vault lock, in shannons.
        #[arg(long, default_value_t = 20_000_000_000)]
        vault_capacity: u64,
        /// Alice's descriptor capacity, in shannons. Must be paired with --bob-capacity.
        #[arg(long)]
        alice_capacity: Option<u64>,
        /// Bob's descriptor capacity, in shannons. Must be paired with --alice-capacity.
        #[arg(long)]
        bob_capacity: Option<u64>,
        /// Capacity placed under each sponsor lock, in shannons.
        #[arg(long, default_value_t = 50_000_000_000)]
        sponsor_capacity: u64,
        /// Absolute fee used for each transaction, in shannons.
        #[arg(long, default_value_t = 100_000_000)]
        fee: u64,
        /// Raw relative-since value used by channel finalisation.
        #[arg(long, default_value_t = 4)]
        finalise_since: u64,
        /// Mine this many blocks after each broadcast. Use 0 to only submit to tx-pool.
        #[arg(long, default_value_t = 4)]
        mine_blocks: u64,
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// Prove live devnet rejects a SponsorCell whose fee cap is too low.
    SponsorBudgetNegativeSmoke {
        /// Directory containing the built RISC-V contract binaries.
        #[arg(long, default_value = "target/riscv64imac-unknown-none-elf/release")]
        contracts_dir: std::path::PathBuf,
        /// Secp256k1 private key controlling devnet funding cells.
        #[arg(
            long,
            env = "MORPH_DEVNET_PRIVATE_KEY",
            default_value = DEFAULT_DEVNET_PRIVATE_KEY
        )]
        private_key: String,
        /// Devnet Alice channel key.
        #[arg(long, env = "MORPH_ALICE_PRIVATE_KEY", default_value = DEFAULT_ALICE_PRIVATE_KEY)]
        alice_private_key: String,
        /// Devnet Bob channel key.
        #[arg(long, env = "MORPH_BOB_PRIVATE_KEY", default_value = DEFAULT_BOB_PRIVATE_KEY)]
        bob_private_key: String,
        /// Capacity placed under the channel vault lock, in shannons.
        #[arg(long, default_value_t = 20_000_000_000)]
        vault_capacity: u64,
        /// Alice's descriptor capacity, in shannons. Must be paired with --bob-capacity.
        #[arg(long)]
        alice_capacity: Option<u64>,
        /// Bob's descriptor capacity, in shannons. Must be paired with --alice-capacity.
        #[arg(long)]
        bob_capacity: Option<u64>,
        /// Capacity placed under each sponsor lock, in shannons.
        #[arg(long, default_value_t = 50_000_000_000)]
        sponsor_capacity: u64,
        /// Absolute fee used for each transaction, in shannons.
        #[arg(long, default_value_t = 100_000_000)]
        fee: u64,
        /// Raw relative-since value used by channel finalisation.
        #[arg(long, default_value_t = 4)]
        finalise_since: u64,
        /// Mine this many blocks after each accepted broadcast. Use 0 to only submit to tx-pool.
        #[arg(long, default_value_t = 4)]
        mine_blocks: u64,
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// Prove competing mempool spends do not replace a live StateCell update.
    CompetingSpendSmoke {
        /// Directory containing the built RISC-V contract binaries.
        #[arg(long, default_value = "target/riscv64imac-unknown-none-elf/release")]
        contracts_dir: std::path::PathBuf,
        /// Secp256k1 private key controlling devnet funding cells.
        #[arg(
            long,
            env = "MORPH_DEVNET_PRIVATE_KEY",
            default_value = DEFAULT_DEVNET_PRIVATE_KEY
        )]
        private_key: String,
        /// Devnet Alice channel key.
        #[arg(long, env = "MORPH_ALICE_PRIVATE_KEY", default_value = DEFAULT_ALICE_PRIVATE_KEY)]
        alice_private_key: String,
        /// Devnet Bob channel key.
        #[arg(long, env = "MORPH_BOB_PRIVATE_KEY", default_value = DEFAULT_BOB_PRIVATE_KEY)]
        bob_private_key: String,
        /// Capacity placed under the channel vault lock, in shannons.
        #[arg(long, default_value_t = 20_000_000_000)]
        vault_capacity: u64,
        /// Alice's descriptor capacity, in shannons. Must be paired with --bob-capacity.
        #[arg(long)]
        alice_capacity: Option<u64>,
        /// Bob's descriptor capacity, in shannons. Must be paired with --alice-capacity.
        #[arg(long)]
        bob_capacity: Option<u64>,
        /// Capacity placed under each sponsor lock, in shannons.
        #[arg(long, default_value_t = 50_000_000_000)]
        sponsor_capacity: u64,
        /// Absolute fee used for each transaction, in shannons.
        #[arg(long, default_value_t = 100_000_000)]
        fee: u64,
        /// Raw relative-since value used by channel finalisation.
        #[arg(long, default_value_t = 4)]
        finalise_since: u64,
        /// Mine this many blocks after each accepted broadcast. Must be greater than zero.
        #[arg(long, default_value_t = 4)]
        mine_blocks: u64,
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::ValidateFixture => validate_fixture(),
        Command::PrintFixture => print_fixture(),
        Command::PrintFactoryFixture => {
            let package = factory_packages::fixture_package()?;
            println!("{}", serde_json::to_string_pretty(&package)?);
            Ok(())
        }
        Command::PrintFactoryStateFixture => {
            let package = factory_packages::fixture_state_package()?;
            println!("{}", serde_json::to_string_pretty(&package)?);
            Ok(())
        }
        Command::PrintReducedFactoryStateFixture => {
            let package = factory_packages::fixture_reduced_state_package()?;
            println!("{}", serde_json::to_string_pretty(&package)?);
            Ok(())
        }
        Command::PrintFactoryReducedRightsFixture => {
            let package = packages::fixture_factory_reduced_rights_package()?;
            println!("{}", serde_json::to_string_pretty(&package)?);
            Ok(())
        }
        Command::PrintFactoryLocalExitFixture => {
            let package = packages::fixture_factory_local_exit_package()?;
            println!("{}", serde_json::to_string_pretty(&package)?);
            Ok(())
        }
        Command::PrintWatchPolicyFixture => {
            let policy = watch_policy::fixture_policy();
            println!("{}", serde_json::to_string_pretty(&policy)?);
            Ok(())
        }
        Command::PrintWatchConfigFixture => {
            let config = watch_config::fixture_config();
            println!("{}", serde_json::to_string_pretty(&config)?);
            Ok(())
        }
        Command::ValidateWatchPolicy { path, json } => {
            let policy = watch_policy::read_watchtower_policy(&path)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&policy)?);
            } else {
                println!("watchtower policy ok");
                println!("schema={}", policy.schema);
                if let Some(channel_id) = &policy.channel_id {
                    println!("channel_id={channel_id}");
                }
                println!("min_detection_depth={}", policy.min_detection_depth);
                println!("max_fee={}", policy.max_fee);
                println!(
                    "max_auto_sponsor_capacity={}",
                    policy.max_auto_sponsor_capacity
                );
                println!("allow_explicit_sponsor={}", policy.allow_explicit_sponsor);
                println!(
                    "require_auto_fund_sponsor={}",
                    policy.require_auto_fund_sponsor
                );
                println!("allow_webhook_alerts={}", policy.allow_webhook_alerts);
            }
            Ok(())
        }
        Command::ValidateWatchConfig { path, json } => {
            let config = watch_config::read_watchtower_config(&path)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&config)?);
            } else {
                println!("watchtower config ok");
                println!("schema={}", config.schema);
                println!("channels={}", config.channels.len());
                for channel in &config.channels {
                    println!(
                        "channel={} from_block={}",
                        channel.channel_id, channel.from_block
                    );
                }
            }
            Ok(())
        }
        Command::ValidateFactoryPackage { path, json } => {
            let package = factory_packages::read_factory_update_package(&path)?;
            let summary = package.summary()?;
            if json {
                println!("{}", serde_json::to_string_pretty(&summary)?);
            } else {
                println!("factory package ok");
                println!("factory_id={}", summary.factory_id);
                println!("update_number={}", summary.update_number);
                println!("state_root_before={}", summary.state_root_before);
                println!("state_root_after={}", summary.state_root_after);
                println!("touched_participants={}", summary.touched_participants);
                println!(
                    "authorised_participants={}",
                    summary.authorised_participants
                );
                println!("rights_before={}", summary.rights_before);
                println!("rights_after={}", summary.rights_after);
                println!(
                    "non_interference_digest={}",
                    summary.non_interference_digest
                );
            }
            Ok(())
        }
        Command::ValidateFactoryStatePackage { path, json } => {
            let package = factory_packages::read_factory_state_package(&path)?;
            let summary = package.summary()?;
            if json {
                println!("{}", serde_json::to_string_pretty(&summary)?);
            } else {
                println!("factory state package ok");
                println!("factory_id={}", summary.factory_id);
                println!("update_number={}", summary.update_number);
                println!("state_root_before={}", summary.state_root_before);
                println!("state_root_after={}", summary.state_root_after);
                println!(
                    "non_interference_digest={}",
                    summary.non_interference_digest
                );
                println!("signature_mode={}", summary.signature_mode);
                println!("signature_threshold={}", summary.signature_threshold);
                println!("participants={}", summary.participants);
                println!("signatures={}", summary.signatures);
                println!("factory_state_digest={}", summary.factory_state_digest);
            }
            Ok(())
        }
        Command::ValidateFactoryReducedRightsPackage { path, json } => {
            let package = packages::read_factory_reduced_rights_package(&path)?;
            let summary = package.summary()?;
            if json {
                println!("{}", serde_json::to_string_pretty(&summary)?);
            } else {
                println!("factory reduced-rights package ok");
                println!("factory_id={}", summary.factory_id);
                println!("old_update_number={}", summary.old_update_number);
                println!("new_update_number={}", summary.new_update_number);
                println!("signing_digest={}", summary.signing_digest);
                println!("old_state_root={}", summary.old_state_root);
                println!("new_state_root={}", summary.new_state_root);
                println!(
                    "old_access_manifest_root={}",
                    summary.old_access_manifest_root
                );
                println!(
                    "new_access_manifest_root={}",
                    summary.new_access_manifest_root
                );
                println!(
                    "non_interference_digest={}",
                    summary.non_interference_digest
                );
            }
            Ok(())
        }
        Command::ValidateFactoryLocalExitPackage { path, json } => {
            let package = packages::read_factory_local_exit_package(&path)?;
            let summary = package.summary()?;
            if json {
                println!("{}", serde_json::to_string_pretty(&summary)?);
            } else {
                println!("factory local-exit package ok");
                println!("factory_id={}", summary.factory_id);
                println!("update_number={}", summary.update_number);
                println!("factory_signing_digest={}", summary.factory_signing_digest);
                println!("exit_digest={}", summary.exit_digest);
                println!("child_channel_id={}", summary.child_channel_id);
                println!("child_state_number={}", summary.child_state_number);
                println!("child_phase={}", summary.child_phase);
                println!("descriptor_version={}", summary.descriptor_version);
                println!("state_output_index={}", summary.state_output_index);
                println!("vault_output_index={}", summary.vault_output_index);
            }
            Ok(())
        }
        Command::DevnetSmokeReport { dir, json } => {
            let summary = smoke_report::summarize_devnet_smoke(&dir)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&summary)?);
            } else {
                print!("{}", smoke_report::render_markdown(&summary));
            }
            Ok(())
        }
        Command::DevnetSmokeAssert {
            dir,
            contracts_dir,
            skip_contract_hash_check,
            json,
        } => {
            let contracts_dir = (!skip_contract_hash_check).then_some(contracts_dir.as_path());
            let report = smoke_report::assert_default_devnet_smoke(&dir, contracts_dir)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!("devnet smoke assertions ok");
                println!("directory={}", report.directory);
                if let Some(git_commit) = &report.git_commit {
                    println!("git_commit={git_commit}");
                }
                if let Some(git_dirty) = &report.git_dirty {
                    println!("git_dirty={git_dirty}");
                }
                println!("transactions={}", report.transaction_count);
                println!("committed={}", report.committed_count);
                println!(
                    "expected_script_failures={}",
                    report.expected_script_failures
                );
                println!("deployed_scripts={}", report.deployed_scripts);
                println!(
                    "deployed_script_hashes_verified={}",
                    report.deployed_script_hashes_verified
                );
                println!("watchtower_alerts={}", report.watchtower_alerts);
                println!(
                    "watchtower_publication_alerts={}",
                    report.watchtower_publication_alerts
                );
                println!(
                    "watchtower_service_records={}",
                    report.watchtower_service_records
                );
                println!("factory_local_exits={}", report.factory_local_exits);
            }
            Ok(())
        }
        Command::DevnetSmokeCompare {
            baseline,
            candidate,
            fail_on_transaction_set_change,
            fail_on_status_change,
            max_abs_total_cycle_delta,
            max_abs_tx_cycle_delta,
            max_abs_total_byte_delta,
            max_abs_tx_byte_delta,
            json,
        } => {
            let comparison = smoke_report::compare_devnet_smoke(&baseline, &candidate)?;
            let limits = smoke_report::DevnetSmokeComparisonLimits {
                fail_on_transaction_set_change,
                fail_on_status_change,
                max_abs_total_cycle_delta,
                max_abs_tx_cycle_delta,
                max_abs_total_byte_delta,
                max_abs_tx_byte_delta,
            };
            if json {
                println!("{}", serde_json::to_string_pretty(&comparison)?);
            } else {
                print!("{}", smoke_report::render_comparison_markdown(&comparison));
            }
            smoke_report::assert_comparison_limits(&comparison, &limits)?;
            Ok(())
        }
        Command::Devnet { rpc_url, command } => run_devnet(&rpc_url, command),
    }
}

fn resolve_watchtower_private_key(
    private_key: Option<String>,
    private_key_file: Option<PathBuf>,
) -> Result<String> {
    ensure!(
        private_key.is_none() || private_key_file.is_none(),
        "pass either --private-key or --private-key-file, not both"
    );
    if let Some(private_key) = private_key {
        return canonical_private_key(&private_key, "--private-key");
    }
    if let Some(path) = private_key_file {
        let value = fs::read_to_string(&path)
            .with_context(|| format!("failed to read private key file {}", path.display()))?;
        return canonical_private_key(&value, &format!("private key file {}", path.display()));
    }
    canonical_private_key(
        DEFAULT_DEVNET_PRIVATE_KEY,
        "default local-devnet private key",
    )
}

fn canonical_private_key(value: &str, source: &str) -> Result<String> {
    let mut parts = value.split_whitespace();
    let Some(first) = parts.next() else {
        anyhow::bail!("{source} is empty");
    };
    ensure!(
        parts.next().is_none(),
        "{source} must contain exactly one hex private key"
    );
    let raw = first.strip_prefix("0x").unwrap_or(first);
    ensure!(raw.len() == 64, "{source} must be 32 bytes");
    let decoded = hex::decode(raw).with_context(|| format!("{source} must be hex encoded"))?;
    ensure!(decoded.len() == 32, "{source} must be 32 bytes");
    SigningKey::from_slice(&decoded)
        .map_err(|err| anyhow::anyhow!("{source} is not a valid secp256k1 private key: {err:?}"))?;
    Ok(format!("0x{}", raw.to_ascii_lowercase()))
}

fn run_devnet(rpc_url: &str, command: DevnetCommand) -> Result<()> {
    let rpc = CkbRpcClient::new(rpc_url)?;
    match command {
        DevnetCommand::Check { json } => {
            let status = rpc.status()?;
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "rpc_url": rpc_url,
                        "chain": status.chain.chain,
                        "initial_block_download": status.chain.is_initial_block_download,
                        "median_time": status.chain.median_time,
                        "median_time_number": status.chain.median_time_value()?,
                        "epoch": status.chain.epoch,
                        "node_active": status.node.active,
                        "node_id": status.node.node_id,
                        "connections": status.node.connections,
                        "connection_count": status.node.connection_count()?,
                        "tip": tip_json(&status.tip)?,
                    }))?
                );
            } else {
                println!("rpc_url={rpc_url}");
                println!("chain={}", status.chain.chain);
                println!(
                    "initial_block_download={}",
                    status.chain.is_initial_block_download
                );
                println!("node_active={}", status.node.active);
                println!("node_id={}", status.node.node_id);
                println!("connections={}", status.node.connection_count()?);
                print_tip(&status.tip)?;
            }
        }
        DevnetCommand::Tip { json } => {
            let tip = rpc.tip_header()?;
            if json {
                println!("{}", serde_json::to_string_pretty(&tip_json(&tip)?)?);
            } else {
                print_tip(&tip)?;
            }
        }
        DevnetCommand::WaitTip {
            min_number,
            timeout_secs,
            poll_ms,
            json,
        } => {
            let tip = rpc.wait_for_tip(
                min_number,
                Duration::from_secs(timeout_secs),
                Duration::from_millis(poll_ms),
            )?;
            if json {
                println!("{}", serde_json::to_string_pretty(&tip_json(&tip)?)?);
            } else {
                println!("target_tip={min_number}");
                print_tip(&tip)?;
            }
        }
        DevnetCommand::Mine { blocks, json } => {
            let mut hashes = Vec::new();
            for _ in 0..blocks {
                hashes.push(rpc.generate_block()?);
            }
            let tip = rpc.tip_header()?;
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "generated": hashes,
                        "tip": tip_json(&tip)?,
                    }))?
                );
            } else {
                for hash in hashes {
                    println!("generated_block={hash}");
                }
                print_tip(&tip)?;
            }
        }
        DevnetCommand::DeployContracts {
            contracts_dir,
            private_key,
            fee,
            mine_blocks,
            json,
        } => {
            let report = devnet::deploy_contracts(
                &rpc,
                DeployContractsOptions {
                    contracts_dir,
                    private_key,
                    fee,
                    mine_blocks,
                },
            )?;
            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!("tx_hash={}", report.tx_hash);
                println!("status={}", report.status);
                if let Some(block_number) = report.block_number {
                    println!("block_number={block_number}");
                }
                if let Some(block_hash) = &report.block_hash {
                    println!("block_hash={block_hash}");
                }
                println!("input_capacity={}", report.input_capacity);
                println!("deployed_capacity={}", report.deployed_capacity);
                println!("change_capacity={}", report.change_capacity);
                println!("fee={}", report.fee);
                print_metrics(&report.metrics);
                for hash in report.mined_blocks {
                    println!("mined_block={hash}");
                }
                for script in report.scripts {
                    println!(
                        "script={} out_point={}:{} data_hash={} hash_type={} data_len={} capacity={}",
                        script.name,
                        script.out_point.tx_hash,
                        script.out_point.index,
                        script.data_hash,
                        script.hash_type,
                        script.data_len,
                        script.capacity
                    );
                }
            }
        }
        DevnetCommand::OpenChannel {
            contracts_dir,
            private_key,
            alice_private_key,
            bob_private_key,
            vault_capacity,
            alice_capacity,
            bob_capacity,
            sponsor_capacity,
            sponsor_min_state_number,
            sponsor_max_state_number,
            sponsor_max_fee_per_tx,
            sponsor_max_total_fee,
            fee,
            finalise_since,
            mine_blocks,
            json,
        } => {
            let report = devnet::open_channel(
                &rpc,
                OpenChannelOptions {
                    contracts_dir,
                    private_key,
                    alice_private_key,
                    bob_private_key,
                    vault_capacity,
                    alice_capacity,
                    bob_capacity,
                    sponsor_capacity,
                    sponsor_min_state_number,
                    sponsor_max_state_number,
                    sponsor_max_fee_per_tx,
                    sponsor_max_total_fee,
                    fee,
                    finalise_since,
                    mine_blocks,
                },
            )?;
            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!("tx_hash={}", report.tx_hash);
                println!("status={}", report.status);
                if let Some(block_number) = report.block_number {
                    println!("block_number={block_number}");
                }
                if let Some(block_hash) = &report.block_hash {
                    println!("block_hash={block_hash}");
                }
                println!("channel_id={}", report.channel_id);
                println!("funding_anchor={}", report.funding_anchor);
                println!("finalise_since={}", report.finalise_since);
                println!("input_capacity={}", report.input_capacity);
                println!("state_capacity={}", report.state_capacity);
                println!("vault_capacity={}", report.vault_capacity);
                println!("sponsor_capacity={}", report.sponsor_capacity);
                print_sponsor_policy(&report.sponsor_policy);
                println!("change_capacity={}", report.change_capacity);
                println!("fee={}", report.fee);
                print_metrics(&report.metrics);
                for hash in report.mined_blocks {
                    println!("mined_block={hash}");
                }
                for participant in report.participants {
                    println!(
                        "participant={} lock_hash={} pubkey_sec1={} capacity={}",
                        participant.role,
                        participant.lock_hash,
                        participant.pubkey_sec1,
                        participant.capacity
                    );
                }
                for script in report.scripts {
                    println!(
                        "script={} out_point={}:{} data_hash={} hash_type={}",
                        script.name,
                        script.out_point.tx_hash,
                        script.out_point.index,
                        script.data_hash,
                        script.hash_type
                    );
                }
                for cell in report.cells {
                    println!(
                        "cell={} out_point={}:{} capacity={} lock_hash={} type_hash={} data_len={}",
                        cell.role,
                        cell.out_point.tx_hash,
                        cell.out_point.index,
                        cell.capacity,
                        cell.lock_hash,
                        cell.type_hash.as_deref().unwrap_or("none"),
                        cell.data_len
                    );
                }
            }
        }
        DevnetCommand::OpenFactory {
            contracts_dir,
            private_key,
            alice_private_key,
            bob_private_key,
            factory_capacity,
            factory_vault_capacity,
            factory_vault_xudt_amount,
            state_root,
            access_manifest_root,
            non_interference_digest,
            fee,
            mine_blocks,
            json,
        } => {
            let report = devnet::open_factory(
                &rpc,
                OpenFactoryOptions {
                    contracts_dir,
                    private_key,
                    alice_private_key,
                    bob_private_key,
                    factory_capacity,
                    factory_vault_capacity,
                    factory_vault_xudt_amount,
                    state_root,
                    access_manifest_root,
                    non_interference_digest,
                    fee,
                    mine_blocks,
                },
            )?;
            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!("tx_hash={}", report.tx_hash);
                println!("status={}", report.status);
                if let Some(block_number) = report.block_number {
                    println!("block_number={block_number}");
                }
                if let Some(block_hash) = &report.block_hash {
                    println!("block_hash={block_hash}");
                }
                println!("factory_id={}", report.factory_id);
                println!("input_capacity={}", report.input_capacity);
                println!("factory_capacity={}", report.factory_capacity);
                println!("factory_vault_capacity={}", report.factory_vault_capacity);
                if let Some(amount) = report.factory_vault_xudt_amount {
                    println!("factory_vault_xudt_amount={amount}");
                }
                if let Some(type_hash) = &report.xudt_type_hash {
                    println!("xudt_type_hash={type_hash}");
                }
                println!("change_capacity={}", report.change_capacity);
                println!("fee={}", report.fee);
                print_metrics(&report.metrics);
                for hash in report.mined_blocks {
                    println!("mined_block={hash}");
                }
                for participant in report.participants {
                    println!(
                        "participant={} participant_id={} pubkey_sec1={}",
                        participant.role, participant.participant_id, participant.pubkey_sec1
                    );
                }
                for script in report.scripts {
                    println!(
                        "script={} out_point={}:{} data_hash={} hash_type={}",
                        script.name,
                        script.out_point.tx_hash,
                        script.out_point.index,
                        script.data_hash,
                        script.hash_type
                    );
                }
                for cell in report.cells {
                    println!(
                        "cell={} out_point={}:{} capacity={} lock_hash={} type_hash={} data_len={}",
                        cell.role,
                        cell.out_point.tx_hash,
                        cell.out_point.index,
                        cell.capacity,
                        cell.lock_hash,
                        cell.type_hash.as_deref().unwrap_or("none"),
                        cell.data_len
                    );
                }
            }
        }
        DevnetCommand::UpdateFactory {
            contracts_dir,
            private_key,
            alice_private_key,
            bob_private_key,
            factory_out_point,
            update_number,
            state_root,
            access_manifest_root,
            non_interference_digest,
            factory_state_package,
            fee,
            mine_blocks,
            json,
        } => {
            let report = devnet::update_factory(
                &rpc,
                UpdateFactoryOptions {
                    contracts_dir,
                    private_key,
                    alice_private_key,
                    bob_private_key,
                    factory_out_point,
                    update_number,
                    state_root,
                    access_manifest_root,
                    non_interference_digest,
                    factory_state_package,
                    fee,
                    mine_blocks,
                },
            )?;
            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!("tx_hash={}", report.tx_hash);
                println!("status={}", report.status);
                if let Some(block_number) = report.block_number {
                    println!("block_number={block_number}");
                }
                if let Some(block_hash) = &report.block_hash {
                    println!("block_hash={block_hash}");
                }
                println!("factory_id={}", report.factory_id);
                println!("old_update_number={}", report.old_update_number);
                println!("new_update_number={}", report.new_update_number);
                println!(
                    "factory_out_point={}:{}",
                    report.factory_out_point.tx_hash, report.factory_out_point.index
                );
                println!("factory_capacity={}", report.factory_capacity);
                println!("fee_input_capacity={}", report.fee_input_capacity);
                println!("fee_change_capacity={}", report.fee_change_capacity);
                println!("fee={}", report.fee);
                println!("state_root={}", report.state_root);
                println!("access_manifest_root={}", report.access_manifest_root);
                println!("non_interference_digest={}", report.non_interference_digest);
                if let Some(path) = &report.factory_state_package {
                    println!("factory_state_package={path}");
                }
                print_metrics(&report.metrics);
                for hash in report.mined_blocks {
                    println!("mined_block={hash}");
                }
            }
        }
        DevnetCommand::SaveFactoryStatePackage {
            alice_private_key,
            bob_private_key,
            factory_out_point,
            update_number,
            state_root,
            access_manifest_root,
            non_interference_digest,
            store_dir,
            json,
        } => {
            let report = devnet::save_factory_state_package(
                &rpc,
                SaveFactoryStatePackageOptions {
                    alice_private_key,
                    bob_private_key,
                    factory_out_point,
                    update_number,
                    state_root,
                    access_manifest_root,
                    non_interference_digest,
                    store_dir,
                },
            )?;
            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!("path={}", report.path);
                println!("factory_id={}", report.package.factory_id);
                println!("update_number={}", report.package.update_number);
                println!("signing_digest={}", report.package.signing_digest);
                println!("state_root={}", report.package.state_root);
                println!(
                    "access_manifest_root={}",
                    report.package.access_manifest_root
                );
                println!(
                    "non_interference_digest={}",
                    report.package.non_interference_digest
                );
            }
        }
        DevnetCommand::SaveFactoryReducedRightsPackage {
            alice_private_key,
            bob_private_key,
            factory_out_point,
            update_number,
            touched_after_balance,
            store_dir,
            json,
        } => {
            let report = devnet::save_factory_reduced_rights_package(
                &rpc,
                SaveFactoryReducedRightsPackageOptions {
                    alice_private_key,
                    bob_private_key,
                    factory_out_point,
                    update_number,
                    touched_after_balance,
                    store_dir,
                },
            )?;
            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!("path={}", report.path);
                println!("factory_id={}", report.package.factory_id);
                println!("old_update_number={}", report.package.old_update_number);
                println!("new_update_number={}", report.package.new_update_number);
                println!("signing_digest={}", report.package.signing_digest);
                println!("old_state_root={}", report.package.old_state_root);
                println!("new_state_root={}", report.package.new_state_root);
                println!(
                    "old_access_manifest_root={}",
                    report.package.old_access_manifest_root
                );
                println!(
                    "new_access_manifest_root={}",
                    report.package.new_access_manifest_root
                );
                println!(
                    "non_interference_digest={}",
                    report.package.non_interference_digest
                );
            }
        }
        DevnetCommand::ListFactoryStatePackages {
            store_dir,
            factory_id,
            json,
        } => {
            let packages =
                packages::list_factory_state_cell_packages(&store_dir, factory_id.as_deref())?;
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "store_dir": store_dir,
                        "packages": packages,
                    }))?
                );
            } else {
                println!("package_count={}", packages.len());
                for record in packages {
                    println!(
                        "package={} factory_id={} update_number={} signing_digest={}",
                        record.path.display(),
                        record.package.factory_id,
                        record.package.update_number,
                        record.package.signing_digest
                    );
                }
            }
        }
        DevnetCommand::LatestFactoryStatePackage {
            store_dir,
            factory_id,
            json,
        } => {
            let record = packages::latest_factory_state_cell_package(&store_dir, &factory_id)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&record)?);
            } else {
                println!("path={}", record.path.display());
                println!("factory_id={}", record.package.factory_id);
                println!("update_number={}", record.package.update_number);
                println!("signing_digest={}", record.package.signing_digest);
            }
        }
        DevnetCommand::FactorySmoke {
            contracts_dir,
            private_key,
            alice_private_key,
            bob_private_key,
            factory_capacity,
            factory_vault_capacity,
            fee,
            mine_blocks,
            store_dir,
            json,
        } => {
            let report = devnet::factory_smoke(
                &rpc,
                FactorySmokeOptions {
                    contracts_dir,
                    private_key,
                    alice_private_key,
                    bob_private_key,
                    factory_capacity,
                    factory_vault_capacity,
                    fee,
                    mine_blocks,
                    store_dir,
                },
            )?;
            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!("factory_id={}", report.open.factory_id);
                println!("open_tx_hash={}", report.open.tx_hash);
                println!("package={}", report.saved_package.path);
                println!(
                    "package_update_number={}",
                    report.saved_package.package.update_number
                );
                println!(
                    "selected_package={}",
                    report.selected_package.path.display()
                );
                println!("update_tx_hash={}", report.update.tx_hash);
                println!("update_status={}", report.update.status);
                print_metrics(&report.open.metrics);
                print_metrics(&report.update.metrics);
            }
        }
        DevnetCommand::FactoryReducedRightsSmoke {
            contracts_dir,
            private_key,
            alice_private_key,
            bob_private_key,
            factory_capacity,
            factory_vault_capacity,
            touched_after_balance,
            fee,
            mine_blocks,
            store_dir,
            json,
        } => {
            let report = devnet::factory_reduced_rights_smoke(
                &rpc,
                FactoryReducedRightsSmokeOptions {
                    contracts_dir,
                    private_key,
                    alice_private_key,
                    bob_private_key,
                    factory_capacity,
                    factory_vault_capacity,
                    touched_after_balance,
                    fee,
                    mine_blocks,
                    store_dir,
                },
            )?;
            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!("factory_id={}", report.open.factory_id);
                println!("open_tx_hash={}", report.open.tx_hash);
                println!("package_path={}", report.package.path);
                println!(
                    "old_update_number={}",
                    report.package.package.old_update_number
                );
                println!(
                    "new_update_number={}",
                    report.package.package.new_update_number
                );
                println!("update_tx_hash={}", report.update.tx_hash);
                println!("update_status={}", report.update.status);
                println!(
                    "factory_out_point={}:{}",
                    report.update.factory_out_point.tx_hash, report.update.factory_out_point.index
                );
                println!(
                    "non_interference_digest={}",
                    report.update.non_interference_digest
                );
                print_metrics(&report.open.metrics);
                print_metrics(&report.update.metrics);
                for hash in report.update.mined_blocks {
                    println!("mined_block={hash}");
                }
            }
        }
        DevnetCommand::FactoryXudtSmoke {
            contracts_dir,
            private_key,
            alice_private_key,
            bob_private_key,
            factory_capacity,
            factory_vault_capacity,
            child_vault_capacity,
            alice_capacity,
            bob_capacity,
            alice_xudt_amount,
            bob_xudt_amount,
            sponsor_capacity,
            fee,
            finalise_since,
            mine_blocks,
            store_dir,
            json,
        } => {
            let report = devnet::factory_xudt_smoke(
                &rpc,
                FactoryXudtSmokeOptions {
                    contracts_dir,
                    private_key,
                    alice_private_key,
                    bob_private_key,
                    factory_capacity,
                    factory_vault_capacity,
                    child_vault_capacity,
                    alice_capacity,
                    bob_capacity,
                    alice_xudt_amount,
                    bob_xudt_amount,
                    sponsor_capacity,
                    fee,
                    finalise_since,
                    mine_blocks,
                    store_dir,
                },
            )?;
            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!("factory_id={}", report.open.factory_id);
                println!(
                    "xudt_type_hash={}",
                    report.exit.xudt_type_hash.unwrap_or_default()
                );
                println!("open_tx_hash={}", report.open.tx_hash);
                println!("update_tx_hash={}", report.update.tx_hash);
                println!("exit_tx_hash={}", report.exit.tx_hash);
                println!("publish_tx_hash={}", report.publish.tx_hash);
                println!("finalise_tx_hash={}", report.finalise.tx_hash);
                println!(
                    "child_xudt_amount={}",
                    report.exit.child_xudt_amount.unwrap_or(0)
                );
                print_metrics(&report.open.metrics);
                print_metrics(&report.exit.metrics);
                print_metrics(&report.finalise.metrics);
            }
        }
        DevnetCommand::FactoryXudtNegativeSmoke {
            contracts_dir,
            private_key,
            alice_private_key,
            bob_private_key,
            factory_capacity,
            factory_vault_capacity,
            child_vault_capacity,
            alice_capacity,
            bob_capacity,
            alice_xudt_amount,
            bob_xudt_amount,
            sponsor_capacity,
            fee,
            finalise_since,
            mine_blocks,
            store_dir,
            json,
        } => {
            let report = devnet::factory_xudt_negative_smoke(
                &rpc,
                FactoryXudtNegativeSmokeOptions {
                    contracts_dir,
                    private_key,
                    alice_private_key,
                    bob_private_key,
                    factory_capacity,
                    factory_vault_capacity,
                    child_vault_capacity,
                    alice_capacity,
                    bob_capacity,
                    alice_xudt_amount,
                    bob_xudt_amount,
                    sponsor_capacity,
                    fee,
                    finalise_since,
                    mine_blocks,
                    store_dir,
                },
            )?;
            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!("factory_id={}", report.open.factory_id);
                println!("open_tx_hash={}", report.open.tx_hash);
                println!("update_tx_hash={}", report.update.tx_hash);
                println!(
                    "rejected_child_xudt_amount={}",
                    report.rejected_child_xudt_amount
                );
                println!(
                    "script_failure={}",
                    report
                        .script_failure
                        .morph_error
                        .as_deref()
                        .unwrap_or("unknown")
                );
                println!("exit_tx_hash={}", report.exit.tx_hash);
                println!("publish_tx_hash={}", report.publish.tx_hash);
                println!("finalise_tx_hash={}", report.finalise.tx_hash);
                print_metrics(&report.open.metrics);
                print_metrics(&report.exit.metrics);
                print_metrics(&report.finalise.metrics);
            }
        }
        DevnetCommand::FactoryExitChannel {
            contracts_dir,
            private_key,
            alice_private_key,
            bob_private_key,
            factory_out_point,
            factory_vault_out_point,
            update_number,
            vault_capacity,
            alice_capacity,
            bob_capacity,
            alice_xudt_amount,
            bob_xudt_amount,
            sponsor_capacity,
            fee,
            finalise_since,
            mine_blocks,
            json,
        } => {
            let report = devnet::factory_exit_channel(
                &rpc,
                FactoryExitChannelOptions {
                    contracts_dir,
                    private_key,
                    alice_private_key,
                    bob_private_key,
                    factory_out_point,
                    factory_vault_out_point,
                    update_number,
                    vault_capacity,
                    alice_capacity,
                    bob_capacity,
                    alice_xudt_amount,
                    bob_xudt_amount,
                    sponsor_capacity,
                    fee,
                    finalise_since,
                    mine_blocks,
                    tamper: FactoryExitChannelTamper::None,
                },
            )?;
            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!("tx_hash={}", report.tx_hash);
                println!("status={}", report.status);
                if let Some(block_number) = report.block_number {
                    println!("block_number={block_number}");
                }
                if let Some(block_hash) = &report.block_hash {
                    println!("block_hash={block_hash}");
                }
                println!("factory_id={}", report.factory_id);
                println!("old_update_number={}", report.old_update_number);
                println!("new_update_number={}", report.new_update_number);
                println!("channel_id={}", report.channel_id);
                println!("funding_anchor={}", report.funding_anchor);
                println!("finalise_since={}", report.finalise_since);
                println!(
                    "factory_out_point={}:{}",
                    report.factory_out_point.tx_hash, report.factory_out_point.index
                );
                println!(
                    "state_out_point={}:{}",
                    report.state_out_point.tx_hash, report.state_out_point.index
                );
                println!(
                    "vault_out_point={}:{}",
                    report.vault_out_point.tx_hash, report.vault_out_point.index
                );
                println!(
                    "factory_vault_out_point={}:{}",
                    report.factory_vault_out_point.tx_hash, report.factory_vault_out_point.index
                );
                println!(
                    "sponsor_out_point={}:{}",
                    report.sponsor_out_point.tx_hash, report.sponsor_out_point.index
                );
                println!("state_capacity={}", report.state_capacity);
                println!("vault_capacity={}", report.vault_capacity);
                if let Some(amount) = report.child_xudt_amount {
                    println!("child_xudt_amount={amount}");
                }
                if let Some(type_hash) = &report.xudt_type_hash {
                    println!("xudt_type_hash={type_hash}");
                }
                println!(
                    "factory_vault_input_capacity={}",
                    report.factory_vault_input_capacity
                );
                println!(
                    "factory_vault_change_capacity={}",
                    report.factory_vault_change_capacity
                );
                if let Some(amount) = report.factory_vault_input_xudt_amount {
                    println!("factory_vault_input_xudt_amount={amount}");
                }
                if let Some(amount) = report.factory_vault_change_xudt_amount {
                    println!("factory_vault_change_xudt_amount={amount}");
                }
                println!("sponsor_capacity={}", report.sponsor_capacity);
                println!("fee_change_capacity={}", report.fee_change_capacity);
                println!("fee={}", report.fee);
                print_metrics(&report.metrics);
                for hash in report.mined_blocks {
                    println!("mined_block={hash}");
                }
                for participant in report.participants {
                    println!(
                        "participant={} lock_hash={} pubkey_sec1={} capacity={}",
                        participant.role,
                        participant.lock_hash,
                        participant.pubkey_sec1,
                        participant.capacity
                    );
                }
            }
        }
        DevnetCommand::PublishState {
            contracts_dir,
            private_key,
            alice_private_key,
            bob_private_key,
            state_out_point,
            sponsor_out_point,
            state_number,
            state_package,
            fee,
            mine_blocks,
            json,
        } => {
            let report = devnet::publish_state(
                &rpc,
                PublishStateOptions {
                    contracts_dir,
                    private_key,
                    alice_private_key,
                    bob_private_key,
                    state_out_point,
                    sponsor_out_point,
                    state_number,
                    state_package,
                    fee,
                    mine_blocks,
                },
            )?;
            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!("tx_hash={}", report.tx_hash);
                println!("status={}", report.status);
                if let Some(block_number) = report.block_number {
                    println!("block_number={block_number}");
                }
                if let Some(block_hash) = &report.block_hash {
                    println!("block_hash={block_hash}");
                }
                println!("channel_id={}", report.channel_id);
                println!("funding_anchor={}", report.funding_anchor);
                println!("old_state_number={}", report.old_state_number);
                println!("new_state_number={}", report.new_state_number);
                println!(
                    "state_out_point={}:{}",
                    report.state_out_point.tx_hash, report.state_out_point.index
                );
                println!("sponsor_change_capacity={}", report.sponsor_change_capacity);
                println!("fee={}", report.fee);
                if let Some(path) = &report.state_package {
                    println!("state_package={path}");
                }
                print_metrics(&report.metrics);
                for hash in report.mined_blocks {
                    println!("mined_block={hash}");
                }
            }
        }
        DevnetCommand::SaveStatePackage {
            alice_private_key,
            bob_private_key,
            state_out_point,
            state_number,
            store_dir,
            json,
        } => {
            let report = devnet::save_state_package(
                &rpc,
                SaveStatePackageOptions {
                    alice_private_key,
                    bob_private_key,
                    state_out_point,
                    state_number,
                    store_dir,
                },
            )?;
            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!("path={}", report.path);
                println!("channel_id={}", report.package.channel_id);
                println!("funding_anchor={}", report.package.funding_anchor);
                println!("state_number={}", report.package.state_number);
                println!("signing_digest={}", report.package.signing_digest);
            }
        }
        DevnetCommand::ListStatePackages {
            store_dir,
            channel_id,
            json,
        } => {
            let packages = packages::list_packages(&store_dir, channel_id.as_deref())?;
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "store_dir": store_dir,
                        "packages": packages,
                    }))?
                );
            } else {
                println!("package_count={}", packages.len());
                for record in packages {
                    println!(
                        "package={} channel_id={} state_number={} signing_digest={}",
                        record.path.display(),
                        record.package.channel_id,
                        record.package.state_number,
                        record.package.signing_digest
                    );
                }
            }
        }
        DevnetCommand::LatestStatePackage {
            store_dir,
            channel_id,
            json,
        } => {
            let record = packages::latest_package(&store_dir, &channel_id)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&record)?);
            } else {
                println!("path={}", record.path.display());
                println!("channel_id={}", record.package.channel_id);
                println!("funding_anchor={}", record.package.funding_anchor);
                println!("state_number={}", record.package.state_number);
                println!("signing_digest={}", record.package.signing_digest);
            }
        }
        DevnetCommand::PublishLatestPackage {
            contracts_dir,
            private_key,
            state_out_point,
            sponsor_out_point,
            store_dir,
            channel_id,
            fee,
            mine_blocks,
            json,
        } => {
            let report = devnet::publish_latest_state_package(
                &rpc,
                PublishLatestStatePackageOptions {
                    contracts_dir,
                    private_key,
                    state_out_point,
                    sponsor_out_point,
                    store_dir,
                    channel_id,
                    fee,
                    mine_blocks,
                },
            )?;
            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!("package={}", report.selected_package.path.display());
                println!(
                    "package_state_number={}",
                    report.selected_package.package.state_number
                );
                println!("tx_hash={}", report.publication.tx_hash);
                println!("status={}", report.publication.status);
                println!(
                    "state_out_point={}:{}",
                    report.publication.state_out_point.tx_hash,
                    report.publication.state_out_point.index
                );
                println!("fee={}", report.publication.fee);
                print_metrics(&report.publication.metrics);
            }
        }
        DevnetCommand::WatchLatestPackage {
            contracts_dir,
            private_key,
            private_key_file,
            sponsor_out_point,
            store_dir,
            channel_id,
            from_block,
            cursor_file,
            watch_policy,
            alert_file,
            alert_webhook_url,
            ignore_cursor,
            detection_depth,
            timeout_secs,
            poll_ms,
            fee,
            mine_blocks,
            auto_fund_sponsor,
            auto_sponsor_capacity,
            json,
        } => {
            let report = devnet::watch_latest_state_package(
                &rpc,
                WatchLatestStatePackageOptions {
                    contracts_dir,
                    private_key: resolve_watchtower_private_key(private_key, private_key_file)?,
                    sponsor_out_point,
                    store_dir,
                    channel_id,
                    from_block,
                    cursor_file,
                    watch_policy,
                    alert_file,
                    alert_webhook_url,
                    ignore_cursor,
                    detection_depth,
                    timeout_secs,
                    poll_ms,
                    fee,
                    mine_blocks,
                    auto_fund_sponsor,
                    auto_sponsor_capacity,
                },
            )?;
            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!("channel_id={}", report.channel_id);
                println!("from_block={}", report.from_block);
                println!("effective_from_block={}", report.effective_from_block);
                println!("scanned_to_block={}", report.scanned_to_block);
                println!("next_from_block={}", report.next_from_block);
                println!("detection_depth={}", report.detection_depth);
                if let Some(path) = &report.cursor_file {
                    println!("cursor_file={}", path.display());
                }
                if let Some(path) = &report.alert_file {
                    println!("alert_file={}", path.display());
                }
                if let Some(url) = &report.alert_webhook_url {
                    println!("alert_webhook_url={url}");
                }
                if let Some(cursor) = &report.loaded_cursor {
                    println!("loaded_cursor_next_block={}", cursor.next_block);
                }
                println!("package={}", report.selected_package.path.display());
                println!(
                    "package_state_number={}",
                    report.selected_package.package.state_number
                );
                if let Some(sponsor_top_up) = &report.sponsor_top_up {
                    println!("sponsor_top_up_tx={}", sponsor_top_up.tx_hash);
                    println!(
                        "sponsor_out_point={}:{}",
                        sponsor_top_up.sponsor_out_point.tx_hash,
                        sponsor_top_up.sponsor_out_point.index
                    );
                }
                if let Some(observed) = &report.observed {
                    println!("observed_out_point={}", observed.out_point);
                    println!("observed_state_number={}", observed.state_number);
                    println!("observed_confirmations={}", observed.confirmations);
                }
                if let Some(publication) = &report.publication {
                    println!("published=true");
                    println!("tx_hash={}", publication.tx_hash);
                    println!("status={}", publication.status);
                    print_metrics(&publication.metrics);
                } else {
                    println!("published=false");
                }
            }
        }
        DevnetCommand::WatchConfigOnce {
            contracts_dir,
            private_key,
            private_key_file,
            config,
            json,
        } => {
            let config_data = watch_config::read_watchtower_config(&config)?;
            let report = watch_config::run_watchtower_config_once(
                &rpc,
                &config,
                &config_data,
                watch_config::WatchtowerRuntimeOptions {
                    contracts_dir,
                    private_key: resolve_watchtower_private_key(private_key, private_key_file)?,
                },
            )?;
            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!("config={}", report.config_path);
                println!("channels={}", report.channel_count);
                println!("published={}", report.published_count);
                println!("idle={}", report.idle_count);
                for channel in &report.channels {
                    println!(
                        "channel={} scanned_to={} next_from={} published={}",
                        channel.channel_id,
                        channel.report.scanned_to_block,
                        channel.report.next_from_block,
                        channel.report.publication.is_some()
                    );
                }
            }
        }
        DevnetCommand::WatchConfigLoop {
            contracts_dir,
            private_key,
            private_key_file,
            config,
            passes,
            sleep_ms,
            stop_after_publication,
            json,
        } => {
            let config_data = watch_config::read_watchtower_config(&config)?;
            let report = watch_config::run_watchtower_config_loop(
                &rpc,
                &config,
                &config_data,
                watch_config::WatchtowerRuntimeOptions {
                    contracts_dir,
                    private_key: resolve_watchtower_private_key(private_key, private_key_file)?,
                },
                watch_config::WatchtowerConfigLoopOptions {
                    passes,
                    sleep_ms,
                    stop_after_publication,
                },
            )?;
            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!("config={}", report.config_path);
                println!("requested_passes={}", report.requested_passes);
                println!("completed_passes={}", report.completed_passes);
                println!("published={}", report.published_count);
                println!("idle={}", report.idle_count);
                println!(
                    "stopped_after_publication={}",
                    report.stopped_after_publication
                );
                for pass in &report.passes {
                    println!(
                        "pass={} channels={} published={} idle={}",
                        pass.pass_number,
                        pass.report.channel_count,
                        pass.report.published_count,
                        pass.report.idle_count
                    );
                }
            }
        }
        DevnetCommand::WatchConfigService {
            contracts_dir,
            private_key,
            private_key_file,
            config,
            max_passes,
            sleep_ms,
            error_backoff_ms,
            max_consecutive_errors,
            stop_after_publication,
            stop_file,
            health_file,
            json,
        } => {
            let config_data = watch_config::read_watchtower_config(&config)?;
            let report = watch_config::run_watchtower_config_service(
                &rpc,
                &config,
                &config_data,
                watch_config::WatchtowerRuntimeOptions {
                    contracts_dir,
                    private_key: resolve_watchtower_private_key(private_key, private_key_file)?,
                },
                watch_config::WatchtowerConfigServiceOptions {
                    max_passes,
                    sleep_ms,
                    error_backoff_ms,
                    max_consecutive_errors,
                    stop_after_publication,
                    stop_file,
                    health_file,
                },
            )?;
            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!("config={}", report.config_path);
                println!("completed_passes={}", report.completed_passes);
                println!("published={}", report.published_count);
                println!("idle={}", report.idle_count);
                println!("errors={}", report.error_count);
                println!("consecutive_errors={}", report.consecutive_errors);
                println!("stopped_reason={}", report.stopped_reason);
                if let Some(error) = &report.last_error {
                    println!("last_error={error}");
                }
                if let Some(path) = &report.stop_file {
                    println!("stop_file={}", path.display());
                }
                if let Some(path) = &report.health_file {
                    println!("health_file={}", path.display());
                }
            }
        }
        DevnetCommand::FundSponsor {
            contracts_dir,
            private_key,
            state_out_point,
            sponsor_capacity,
            sponsor_min_state_number,
            sponsor_max_state_number,
            sponsor_max_fee_per_tx,
            sponsor_max_total_fee,
            fee,
            mine_blocks,
            json,
        } => {
            let report = devnet::fund_sponsor(
                &rpc,
                FundSponsorOptions {
                    contracts_dir,
                    private_key,
                    state_out_point,
                    sponsor_capacity,
                    sponsor_min_state_number,
                    sponsor_max_state_number,
                    sponsor_max_fee_per_tx,
                    sponsor_max_total_fee,
                    fee,
                    mine_blocks,
                },
            )?;
            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!("tx_hash={}", report.tx_hash);
                println!("status={}", report.status);
                if let Some(block_number) = report.block_number {
                    println!("block_number={block_number}");
                }
                if let Some(block_hash) = &report.block_hash {
                    println!("block_hash={block_hash}");
                }
                println!("channel_id={}", report.channel_id);
                println!("state_number={}", report.state_number);
                println!(
                    "sponsor_out_point={}:{}",
                    report.sponsor_out_point.tx_hash, report.sponsor_out_point.index
                );
                println!("sponsor_capacity={}", report.sponsor_capacity);
                print_sponsor_policy(&report.sponsor_policy);
                println!("change_capacity={}", report.change_capacity);
                println!("fee={}", report.fee);
                print_metrics(&report.metrics);
                for hash in report.mined_blocks {
                    println!("mined_block={hash}");
                }
            }
        }
        DevnetCommand::FinaliseChannel {
            contracts_dir,
            private_key,
            alice_private_key,
            bob_private_key,
            state_out_point,
            vault_out_point,
            alice_capacity,
            bob_capacity,
            finalise_since,
            fee,
            mine_blocks,
            json,
        } => {
            let report = devnet::finalise_channel(
                &rpc,
                FinaliseChannelOptions {
                    contracts_dir,
                    private_key,
                    alice_private_key,
                    bob_private_key,
                    state_out_point,
                    vault_out_point,
                    alice_capacity,
                    bob_capacity,
                    finalise_since,
                    fee,
                    mine_blocks,
                },
            )?;
            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!("tx_hash={}", report.tx_hash);
                println!("status={}", report.status);
                if let Some(block_number) = report.block_number {
                    println!("block_number={block_number}");
                }
                if let Some(block_hash) = &report.block_hash {
                    println!("block_hash={block_hash}");
                }
                println!("channel_id={}", report.channel_id);
                println!("funding_anchor={}", report.funding_anchor);
                println!("state_number={}", report.state_number);
                println!("alice_capacity={}", report.alice_capacity);
                println!("bob_capacity={}", report.bob_capacity);
                println!("state_refund_capacity={}", report.state_refund_capacity);
                println!("fee={}", report.fee);
                print_metrics(&report.metrics);
                for hash in report.mined_blocks {
                    println!("mined_block={hash}");
                }
                for output in report.outputs {
                    println!(
                        "output={} out_point={}:{} capacity={} lock_hash={}",
                        output.role,
                        output.out_point.tx_hash,
                        output.out_point.index,
                        output.capacity,
                        output.lock_hash
                    );
                }
            }
        }
        DevnetCommand::SupersedeSmoke {
            contracts_dir,
            private_key,
            alice_private_key,
            bob_private_key,
            vault_capacity,
            alice_capacity,
            bob_capacity,
            sponsor_capacity,
            fee,
            finalise_since,
            mine_blocks,
            json,
        } => {
            let report = devnet::supersede_smoke(
                &rpc,
                SupersedeSmokeOptions {
                    contracts_dir,
                    private_key,
                    alice_private_key,
                    bob_private_key,
                    vault_capacity,
                    alice_capacity,
                    bob_capacity,
                    sponsor_capacity,
                    fee,
                    finalise_since,
                    mine_blocks,
                },
            )?;
            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!("open_tx={}", report.open.tx_hash);
                println!("stale_publish_tx={}", report.stale_publish.tx_hash);
                println!("sponsor_top_up_tx={}", report.sponsor_top_up.tx_hash);
                println!("supersede_publish_tx={}", report.supersede_publish.tx_hash);
                println!("finalise_tx={}", report.finalise.tx_hash);
                println!("channel_id={}", report.finalise.channel_id);
                println!(
                    "state_numbers={}->{}",
                    report.stale_publish.new_state_number,
                    report.supersede_publish.new_state_number
                );
                println!("final_state_number={}", report.finalise.state_number);
                println!("finalise_status={}", report.finalise.status);
                println!(
                    "cycles=open:{} stale_publish:{} sponsor_top_up:{} supersede_publish:{} finalise:{}",
                    report.open.metrics.estimated_cycles,
                    report.stale_publish.metrics.estimated_cycles,
                    report.sponsor_top_up.metrics.estimated_cycles,
                    report.supersede_publish.metrics.estimated_cycles,
                    report.finalise.metrics.estimated_cycles
                );
            }
        }
        DevnetCommand::FinaliseSinceNegativeSmoke {
            contracts_dir,
            private_key,
            alice_private_key,
            bob_private_key,
            vault_capacity,
            alice_capacity,
            bob_capacity,
            sponsor_capacity,
            fee,
            finalise_since,
            mine_blocks,
            json,
        } => {
            let report = devnet::finalise_since_negative_smoke(
                &rpc,
                FinaliseSinceNegativeSmokeOptions {
                    contracts_dir,
                    private_key,
                    alice_private_key,
                    bob_private_key,
                    vault_capacity,
                    alice_capacity,
                    bob_capacity,
                    sponsor_capacity,
                    fee,
                    finalise_since,
                    mine_blocks,
                },
            )?;
            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!("open_tx={}", report.open.tx_hash);
                println!("publish_tx={}", report.publish.tx_hash);
                println!("rejected_input_since={}", report.rejected_input_since);
                println!("required_finalise_since={}", report.required_finalise_since);
                println!("rejection={}", report.rejection);
                if let Some(source) = &report.script_failure.source {
                    println!("script_failure_source={source}");
                }
                if let Some(code) = report.script_failure.error_code {
                    println!("script_failure_error_code={code}");
                }
                if let Some(name) = &report.script_failure.morph_error {
                    println!("script_failure_morph_error={name}");
                }
                for hash in report.maturity_blocks {
                    println!("maturity_block={hash}");
                }
                println!("finalise_tx={}", report.finalise.tx_hash);
                println!("channel_id={}", report.finalise.channel_id);
                println!("finalise_status={}", report.finalise.status);
            }
        }
        DevnetCommand::XudtSmoke {
            contracts_dir,
            private_key,
            alice_private_key,
            bob_private_key,
            vault_capacity,
            alice_capacity,
            bob_capacity,
            alice_xudt_amount,
            bob_xudt_amount,
            sponsor_capacity,
            fee,
            finalise_since,
            mine_blocks,
            json,
        } => {
            let report = devnet::xudt_smoke(
                &rpc,
                XudtSmokeOptions {
                    contracts_dir,
                    private_key,
                    alice_private_key,
                    bob_private_key,
                    vault_capacity,
                    alice_capacity,
                    bob_capacity,
                    alice_xudt_amount,
                    bob_xudt_amount,
                    sponsor_capacity,
                    fee,
                    finalise_since,
                    mine_blocks,
                },
            )?;
            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!("open_tx={}", report.open.tx_hash);
                println!("publish_tx={}", report.publish.tx_hash);
                println!("finalise_tx={}", report.finalise.tx_hash);
                println!("channel_id={}", report.finalise.channel_id);
                println!("xudt_type_hash={}", report.finalise.xudt_type_hash);
                println!("alice_capacity={}", report.finalise.alice_capacity);
                println!("bob_capacity={}", report.finalise.bob_capacity);
                println!("alice_xudt_amount={}", report.finalise.alice_xudt_amount);
                println!("bob_xudt_amount={}", report.finalise.bob_xudt_amount);
                println!("finalise_status={}", report.finalise.status);
                println!(
                    "cycles=open:{} publish:{} finalise:{}",
                    report.open.metrics.estimated_cycles,
                    report.publish.metrics.estimated_cycles,
                    report.finalise.metrics.estimated_cycles
                );
            }
        }
        DevnetCommand::XudtNegativeSmoke {
            contracts_dir,
            private_key,
            alice_private_key,
            bob_private_key,
            vault_capacity,
            alice_capacity,
            bob_capacity,
            alice_xudt_amount,
            bob_xudt_amount,
            sponsor_capacity,
            fee,
            finalise_since,
            mine_blocks,
            json,
        } => {
            let report = devnet::xudt_negative_smoke(
                &rpc,
                XudtNegativeSmokeOptions {
                    contracts_dir,
                    private_key,
                    alice_private_key,
                    bob_private_key,
                    vault_capacity,
                    alice_capacity,
                    bob_capacity,
                    alice_xudt_amount,
                    bob_xudt_amount,
                    sponsor_capacity,
                    fee,
                    finalise_since,
                    mine_blocks,
                },
            )?;
            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!("open_tx={}", report.open.tx_hash);
                println!("publish_tx={}", report.publish.tx_hash);
                println!(
                    "rejected_xudt_amounts={}:{}",
                    report.rejected_alice_xudt_amount, report.rejected_bob_xudt_amount
                );
                println!("rejection={}", report.rejection);
                if let Some(source) = &report.script_failure.source {
                    println!("script_failure_source={source}");
                }
                if let Some(code) = report.script_failure.error_code {
                    println!("script_failure_error_code={code}");
                }
                if let Some(name) = &report.script_failure.morph_error {
                    println!("script_failure_morph_error={name}");
                }
                println!("finalise_tx={}", report.finalise.tx_hash);
                println!("xudt_type_hash={}", report.finalise.xudt_type_hash);
                println!("finalise_status={}", report.finalise.status);
            }
        }
        DevnetCommand::SponsorPolicyNegativeSmoke {
            contracts_dir,
            private_key,
            alice_private_key,
            bob_private_key,
            vault_capacity,
            alice_capacity,
            bob_capacity,
            sponsor_capacity,
            fee,
            finalise_since,
            mine_blocks,
            json,
        } => {
            let report = devnet::sponsor_policy_negative_smoke(
                &rpc,
                SponsorPolicyNegativeSmokeOptions {
                    contracts_dir,
                    private_key,
                    alice_private_key,
                    bob_private_key,
                    vault_capacity,
                    alice_capacity,
                    bob_capacity,
                    sponsor_capacity,
                    fee,
                    finalise_since,
                    mine_blocks,
                },
            )?;
            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!("open_tx={}", report.open.tx_hash);
                println!("rejected_state_number={}", report.rejected_state_number);
                println!("rejection={}", report.rejection);
                if let Some(source) = &report.script_failure.source {
                    println!("script_failure_source={source}");
                }
                if let Some(code) = report.script_failure.error_code {
                    println!("script_failure_error_code={code}");
                }
                if let Some(name) = &report.script_failure.morph_error {
                    println!("script_failure_morph_error={name}");
                }
                println!("allowed_publish_tx={}", report.allowed_publish.tx_hash);
                println!("finalise_tx={}", report.finalise.tx_hash);
                println!("channel_id={}", report.finalise.channel_id);
                println!("finalise_status={}", report.finalise.status);
            }
        }
        DevnetCommand::SponsorBudgetNegativeSmoke {
            contracts_dir,
            private_key,
            alice_private_key,
            bob_private_key,
            vault_capacity,
            alice_capacity,
            bob_capacity,
            sponsor_capacity,
            fee,
            finalise_since,
            mine_blocks,
            json,
        } => {
            let report = devnet::sponsor_budget_negative_smoke(
                &rpc,
                SponsorBudgetNegativeSmokeOptions {
                    contracts_dir,
                    private_key,
                    alice_private_key,
                    bob_private_key,
                    vault_capacity,
                    alice_capacity,
                    bob_capacity,
                    sponsor_capacity,
                    fee,
                    finalise_since,
                    mine_blocks,
                },
            )?;
            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!("open_tx={}", report.open.tx_hash);
                println!("rejected_fee={}", report.rejected_fee);
                println!("sponsor_max_fee_per_tx={}", report.sponsor_max_fee_per_tx);
                println!("rejection={}", report.rejection);
                if let Some(source) = &report.script_failure.source {
                    println!("script_failure_source={source}");
                }
                if let Some(code) = report.script_failure.error_code {
                    println!("script_failure_error_code={code}");
                }
                if let Some(name) = &report.script_failure.morph_error {
                    println!("script_failure_morph_error={name}");
                }
                println!(
                    "replacement_sponsor_tx={}",
                    report.replacement_sponsor.tx_hash
                );
                println!("allowed_publish_tx={}", report.allowed_publish.tx_hash);
                println!("finalise_tx={}", report.finalise.tx_hash);
                println!("channel_id={}", report.finalise.channel_id);
                println!("finalise_status={}", report.finalise.status);
            }
        }
        DevnetCommand::CompetingSpendSmoke {
            contracts_dir,
            private_key,
            alice_private_key,
            bob_private_key,
            vault_capacity,
            alice_capacity,
            bob_capacity,
            sponsor_capacity,
            fee,
            finalise_since,
            mine_blocks,
            json,
        } => {
            let report = devnet::competing_spend_smoke(
                &rpc,
                CompetingSpendSmokeOptions {
                    contracts_dir,
                    private_key,
                    alice_private_key,
                    bob_private_key,
                    vault_capacity,
                    alice_capacity,
                    bob_capacity,
                    sponsor_capacity,
                    fee,
                    finalise_since,
                    mine_blocks,
                },
            )?;
            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!("open_tx={}", report.open.tx_hash);
                println!("spare_sponsor_tx={}", report.spare_sponsor.tx_hash);
                println!("pending_publish_tx={}", report.pending_publish.tx_hash);
                println!("pending_publish_status={}", report.pending_publish.status);
                println!("pending_commit_status={}", report.pending_commit.status);
                println!("rejected_state_number={}", report.rejected_state_number);
                println!(
                    "rejected_against_state_out_point={}",
                    report.rejected_against_state_out_point
                );
                println!("rejection={}", report.rejection);
                println!("rebuilt_publish_tx={}", report.rebuilt_publish.tx_hash);
                println!("finalise_tx={}", report.finalise.tx_hash);
                println!("final_state_number={}", report.finalise.state_number);
                println!("finalise_status={}", report.finalise.status);
            }
        }
    }
    Ok(())
}

fn print_metrics(metrics: &devnet::TransactionMetrics) {
    println!("estimated_cycles={}", metrics.estimated_cycles);
    println!("tx_size_bytes={}", metrics.tx_size_bytes);
}

fn print_sponsor_policy(policy: &devnet::SponsorPolicyReport) {
    println!("sponsor_min_state_number={}", policy.min_state_number);
    println!("sponsor_max_state_number={}", policy.max_state_number);
    println!("sponsor_max_fee_per_tx={}", policy.max_fee_per_tx);
    println!("sponsor_max_total_fee={}", policy.max_total_fee);
    println!(
        "sponsor_publication_state_type_hash={}",
        policy.publication_state_type_hash
    );
    println!("sponsor_change_lock_hash={}", policy.change_lock_hash);
}

fn print_tip(tip: &HeaderView) -> Result<()> {
    println!("tip_number={}", tip.number_value()?);
    println!("tip_hash={}", tip.hash);
    println!("tip_parent_hash={}", tip.parent_hash);
    println!("tip_epoch={}", tip.epoch);
    println!("tip_timestamp={}", tip.timestamp_value()?);
    Ok(())
}

fn tip_json(tip: &HeaderView) -> Result<serde_json::Value> {
    Ok(serde_json::json!({
        "number": tip.number,
        "number_value": tip.number_value()?,
        "hash": tip.hash,
        "parent_hash": tip.parent_hash,
        "epoch": tip.epoch,
        "timestamp": tip.timestamp,
        "timestamp_value": tip.timestamp_value()?,
    }))
}

fn validate_fixture() -> Result<()> {
    let fixture = Fixture::new();
    validate_state_transition(&fixture.old_state, &fixture.new_state, &fixture.transition)?;
    validate_partition_conservation(
        &fixture.transition.partition,
        &fixture.transition.asset_registry,
    )?;
    validate_sponsor_policy(&fixture.sponsor_policy, &fixture.sponsor_spend)?;
    validate_vault_spend(&fixture.vault_spend)?;
    println!("fixture ok");
    println!(
        "state_digest={}",
        hex::encode(fixture.new_state.header.signing_digest())
    );
    Ok(())
}

fn print_fixture() -> Result<()> {
    let fixture = Fixture::new();
    let value = serde_json::json!({
        "old_state": fixture.old_state,
        "new_state": fixture.new_state,
        "new_state_signing_digest": hex::encode(fixture.new_state.header.signing_digest()),
        "sponsor_policy": fixture.sponsor_policy,
        "sponsor_spend": fixture.sponsor_spend,
    });
    println!("{}", serde_json::to_string_pretty(&value)?);
    Ok(())
}

struct Fixture {
    old_state: StateCell,
    new_state: StateCell,
    transition: StateTransitionContext,
    sponsor_policy: SponsorPolicy,
    sponsor_spend: SponsorSpend,
    vault_spend: VaultSpend,
}

impl Fixture {
    fn new() -> Self {
        let registry = AssetRegistry {
            xudt_types: BTreeSet::from([bytes32(42)]),
        };
        let partition = PartitionedTransaction {
            inputs: vec![
                ClassifiedCell::channel_reserve(1_000, 700),
                ClassifiedCell::business_ckb(1_500, 700, 800),
                ClassifiedCell::xudt(bytes32(42), 1_000, 700, 10),
                ClassifiedCell::state_carrier(10_000, 1_000),
                ClassifiedCell::sponsor(500, 100),
            ],
            outputs: vec![
                ClassifiedCell::channel_reserve(1_000, 700),
                ClassifiedCell::business_ckb(1_500, 700, 800),
                ClassifiedCell::xudt(bytes32(42), 1_000, 700, 10),
                ClassifiedCell::state_carrier(10_000, 1_000),
                ClassifiedCell::sponsor(400, 100),
            ],
            tx_fee: 100,
            authorised_reserve_refund: 0,
        };
        let mut old_state = StateCell {
            header: header(1, Phase::Active),
            capacity: 10_000,
            occupied_capacity: 1_000,
        };
        let mut new_state = StateCell {
            header: header(2, Phase::Settling),
            capacity: 10_000,
            occupied_capacity: 1_000,
        };
        let authorization = authorization_for(&mut new_state.header);
        old_state.header.participants_commitment = new_state.header.participants_commitment;
        let transition = StateTransitionContext {
            referenced_funding_anchor: bytes32(3),
            authorization,
            asset_registry: registry.clone(),
            partition: partition.clone(),
        };
        let sponsor_policy = SponsorPolicy {
            channel_id: bytes32(2),
            min_state_number: 1,
            max_state_number: 10,
            max_fee_per_tx: 200,
            max_total_fee: 1_000,
            already_spent: 100,
            expiry: 1_000,
            allowed_sponsor_source: bytes32(10),
            change_lock: bytes32(11),
        };
        let sponsor_spend = SponsorSpend {
            channel_id: bytes32(2),
            state_number: 2,
            fee: 100,
            now: 900,
            sponsor_source: bytes32(10),
            change_lock: bytes32(11),
            operation: ChannelOperation::Publish,
        };
        let vault_spend = VaultSpend {
            operation: ChannelOperation::Finalise,
            state_cell: new_state.clone(),
            signatures_or_phase_authorised: true,
            since_satisfied: true,
            expected_funding_anchor: bytes32(3),
            descriptor_outputs_match: true,
            asset_registry: registry,
            partition,
        };
        Self {
            old_state,
            new_state,
            transition,
            sponsor_policy,
            sponsor_spend,
            vault_spend,
        }
    }
}

fn signing_key(byte: u8) -> SigningKey {
    SigningKey::from_slice(&[byte; 32]).unwrap()
}

fn pubkey(key: &SigningKey) -> Vec<u8> {
    key.verifying_key()
        .to_encoded_point(true)
        .as_bytes()
        .to_vec()
}

fn signature(key: &SigningKey, digest: &[u8; 32]) -> Vec<u8> {
    let sig: Signature = key.sign_prehash(digest).unwrap();
    sig.to_bytes().as_slice().to_vec()
}

fn authorization_for(header: &mut StateHeader) -> StateAuthorization {
    let key0 = signing_key(1);
    let key1 = signing_key(2);
    let mut entries = [(pubkey(&key0), key0), (pubkey(&key1), key1)];
    entries.sort_by(|left, right| left.0.cmp(&right.0));

    let pubkeys = [entries[0].0.as_slice(), entries[1].0.as_slice()];
    header.participants_commitment = participants_commitment(2, &pubkeys);
    let digest = header.signing_digest();
    StateAuthorization {
        threshold: 2,
        signatures: entries
            .iter()
            .map(|(pubkey, key)| ParticipantSignature {
                pubkey_sec1: pubkey.clone(),
                signature: signature(key, &digest),
            })
            .collect(),
    }
}

fn header(n: u64, phase: Phase) -> StateHeader {
    StateHeader {
        protocol_version: 1,
        chain_id: bytes32(1),
        signature_scheme_id: 1,
        channel_id: bytes32(2),
        funding_anchor: bytes32(3),
        state_number: n,
        mode: Mode::BilateralPlain,
        phase,
        participants_commitment: bytes32(4),
        asset_registry_commitment: bytes32(5),
        settlement_descriptor_commitment: bytes32(6),
        descriptor_version: 1,
        payload_commitment: bytes32(7),
        challenge_policy_commitment: bytes32(8),
        state_layout_version: 1,
    }
}

#[cfg(test)]
mod cli_secret_tests {
    use super::*;

    #[test]
    fn resolves_private_key_from_file() {
        let path = std::env::temp_dir().join(format!(
            "morph-private-key-{}-{}.txt",
            std::process::id(),
            "file"
        ));
        fs::write(&path, format!("{}\n", DEFAULT_DEVNET_PRIVATE_KEY)).unwrap();
        let resolved = resolve_watchtower_private_key(None, Some(path.clone())).unwrap();
        fs::remove_file(path).unwrap();
        assert_eq!(resolved, DEFAULT_DEVNET_PRIVATE_KEY);
    }

    #[test]
    fn rejects_ambiguous_private_key_sources() {
        let err = resolve_watchtower_private_key(
            Some(DEFAULT_DEVNET_PRIVATE_KEY.to_string()),
            Some(PathBuf::from("key.txt")),
        )
        .unwrap_err();
        assert!(
            err.to_string()
                .contains("either --private-key or --private-key-file")
        );
    }

    #[test]
    fn rejects_multi_token_private_key_file() {
        let path = std::env::temp_dir().join(format!(
            "morph-private-key-{}-{}.txt",
            std::process::id(),
            "multi"
        ));
        fs::write(&path, format!("{} extra\n", DEFAULT_DEVNET_PRIVATE_KEY)).unwrap();
        let err = resolve_watchtower_private_key(None, Some(path.clone())).unwrap_err();
        fs::remove_file(path).unwrap();
        assert!(err.to_string().contains("exactly one hex private key"));
    }

    #[test]
    fn falls_back_to_devnet_key_for_local_watchers() {
        let resolved = resolve_watchtower_private_key(None, None).unwrap();
        assert_eq!(resolved, DEFAULT_DEVNET_PRIVATE_KEY);
    }
}
