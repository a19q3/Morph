use std::fs;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, ensure};
use ckb_crypto::secp::Privkey;
use ckb_hash::{blake2b_256, new_blake2b};
use ckb_jsonrpc_types::Status;
use ckb_types::{
    H256,
    bytes::Bytes,
    core::{Capacity, DepType, ScriptHashType, TransactionBuilder},
    packed::{CellDep, CellInput, CellOutput, OutPoint, OutPointVec, Script, WitnessArgs},
    prelude::*,
};
use k256::ecdsa::signature::hazmat::PrehashSigner;
use k256::ecdsa::{Signature, SigningKey};
use morph_script_common::{
    BILATERAL_CKB_DESCRIPTOR_OUTPUT_COUNT_V1, BILATERAL_CKB_DESCRIPTOR_V1_LEN,
    BILATERAL_CKB_DESCRIPTOR_VERSION_V1, BILATERAL_CKB_XUDT_DESCRIPTOR_ASSET_COUNT_V1,
    BILATERAL_CKB_XUDT_DESCRIPTOR_V1_LEN, BILATERAL_CKB_XUDT_DESCRIPTOR_VERSION_V1,
    BILATERAL_SIGNATURE_COUNT_V1, BILATERAL_SIGNATURE_THRESHOLD_V1,
    BILATERAL_SIGNATURE_WITNESS_V1_LEN, BILATERAL_SIGNATURE_WITNESS_VERSION_V1, BYTE32_LEN,
    COMPRESSED_SECP256K1_PUBKEY_LEN, ECDSA_SIGNATURE_LEN, FACTORY_LOCAL_EXIT_WITNESS_V1_LEN,
    FACTORY_LOCAL_EXIT_WITNESS_VERSION_V1, FACTORY_SIGNATURE_COUNT_V1,
    FACTORY_SIGNATURE_THRESHOLD_V1, FACTORY_SIGNATURE_WITNESS_V1_LEN,
    FACTORY_SIGNATURE_WITNESS_VERSION_V1, FACTORY_STATE_HEADER_V1_LEN, FactoryStateHeaderV1,
    PHASE_ACTIVE, PHASE_SETTLING, SIGNATURE_SCHEME_SECP256K1_ECDSA_BLAKE2B_V1,
    SPONSOR_POLICY_V1_LEN, STATE_HEADER_V1_LEN, ScriptError, StateHeaderV1,
    blake2b256 as script_blake2b256, factory_local_exit_digest_v1,
    factory_participants_commitment_v1, participants_commitment_v1,
    settlement_descriptor_commitment_v1,
};
use serde::Serialize;

use crate::packages::{
    FactoryStateCellPackageRecord, PackageOutPoint, StatePackageRecord,
    StoredFactoryLocalExitPackage, StoredFactoryReducedRightsPackage,
    StoredFactoryStateCellPackage, StoredStatePackage, WatchCursor, canonical_hex32,
    default_watch_cursor_path, fixture_factory_reduced_rights_package,
    latest_factory_state_cell_package, latest_package, read_factory_state_cell_update_package,
    read_package, read_watch_cursor, reduced_rights_package_from_factory_header,
    write_factory_reduced_rights_package, write_factory_state_cell_package, write_package,
    write_watch_cursor,
};
use crate::rpc::CkbRpcClient;
use crate::watch_alert::{
    WatchAlertEvent, WatchAlertSeverity, WatchtowerAlert, append_watchtower_alert,
    post_watchtower_alert_webhook,
};
use crate::watch_policy::{WatchPolicyRun, read_watchtower_policy};

const DEFAULT_SECP_TYPE_HASH: &str =
    "0x9bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8";
pub const DEFAULT_DEVNET_PRIVATE_KEY: &str =
    "0xd00c06bfd800d27397002dca6fb0993d5ba6399b4238b2f29ee9deb97593d2bc";
pub const DEFAULT_ALICE_PRIVATE_KEY: &str =
    "0x1111111111111111111111111111111111111111111111111111111111111111";
pub const DEFAULT_BOB_PRIVATE_KEY: &str =
    "0x2222222222222222222222222222222222222222222222222222222222222222";
const CONTRACTS: [(&str, &str); 7] = [
    ("morph-state-lock", "morph-state-lock"),
    ("morph-state-type", "morph-state-type"),
    ("morph-factory-type", "morph-factory-type"),
    ("morph-factory-vault-lock", "morph-factory-vault-lock"),
    ("morph-vault-lock", "morph-vault-lock"),
    ("morph-sponsor-lock", "morph-sponsor-lock"),
    ("morph-devnet-xudt", "morph-devnet-xudt"),
];

#[derive(Debug, Clone)]
pub struct DeployContractsOptions {
    pub contracts_dir: PathBuf,
    pub private_key: String,
    pub fee: u64,
    pub mine_blocks: u64,
}

#[derive(Debug, Clone)]
pub struct OpenChannelOptions {
    pub contracts_dir: PathBuf,
    pub private_key: String,
    pub alice_private_key: String,
    pub bob_private_key: String,
    pub vault_capacity: u64,
    pub alice_capacity: Option<u64>,
    pub bob_capacity: Option<u64>,
    pub sponsor_capacity: u64,
    pub sponsor_min_state_number: u64,
    pub sponsor_max_state_number: u64,
    pub sponsor_max_fee_per_tx: Option<u64>,
    pub sponsor_max_total_fee: Option<u64>,
    pub fee: u64,
    pub finalise_since: u64,
    pub mine_blocks: u64,
}

#[derive(Debug, Clone)]
pub struct OpenFactoryOptions {
    pub contracts_dir: PathBuf,
    pub private_key: String,
    pub alice_private_key: String,
    pub bob_private_key: String,
    pub factory_capacity: u64,
    pub factory_vault_capacity: u64,
    pub factory_vault_xudt_amount: Option<u128>,
    pub state_root: Option<String>,
    pub access_manifest_root: Option<String>,
    pub non_interference_digest: Option<String>,
    pub fee: u64,
    pub mine_blocks: u64,
}

#[derive(Debug, Clone)]
pub struct UpdateFactoryOptions {
    pub contracts_dir: PathBuf,
    pub private_key: String,
    pub alice_private_key: String,
    pub bob_private_key: String,
    pub factory_out_point: String,
    pub update_number: Option<u64>,
    pub state_root: Option<String>,
    pub access_manifest_root: Option<String>,
    pub non_interference_digest: Option<String>,
    pub factory_state_package: Option<PathBuf>,
    pub fee: u64,
    pub mine_blocks: u64,
}

#[derive(Debug, Clone)]
pub struct SaveFactoryStatePackageOptions {
    pub alice_private_key: String,
    pub bob_private_key: String,
    pub factory_out_point: String,
    pub update_number: Option<u64>,
    pub state_root: Option<String>,
    pub access_manifest_root: Option<String>,
    pub non_interference_digest: Option<String>,
    pub store_dir: PathBuf,
}

#[derive(Debug, Clone)]
pub struct SaveFactoryReducedRightsPackageOptions {
    pub alice_private_key: String,
    pub bob_private_key: String,
    pub factory_out_point: String,
    pub update_number: Option<u64>,
    pub touched_after_balance: u128,
    pub store_dir: PathBuf,
}

#[derive(Debug, Clone)]
pub struct FactorySmokeOptions {
    pub contracts_dir: PathBuf,
    pub private_key: String,
    pub alice_private_key: String,
    pub bob_private_key: String,
    pub factory_capacity: u64,
    pub factory_vault_capacity: u64,
    pub fee: u64,
    pub mine_blocks: u64,
    pub store_dir: PathBuf,
}

#[derive(Debug, Clone)]
pub struct FactoryReducedRightsSmokeOptions {
    pub contracts_dir: PathBuf,
    pub private_key: String,
    pub alice_private_key: String,
    pub bob_private_key: String,
    pub factory_capacity: u64,
    pub factory_vault_capacity: u64,
    pub touched_after_balance: u128,
    pub fee: u64,
    pub mine_blocks: u64,
    pub store_dir: PathBuf,
}

#[derive(Debug, Clone)]
pub struct FactoryXudtSmokeOptions {
    pub contracts_dir: PathBuf,
    pub private_key: String,
    pub alice_private_key: String,
    pub bob_private_key: String,
    pub factory_capacity: u64,
    pub factory_vault_capacity: u64,
    pub child_vault_capacity: u64,
    pub alice_capacity: Option<u64>,
    pub bob_capacity: Option<u64>,
    pub alice_xudt_amount: u128,
    pub bob_xudt_amount: u128,
    pub sponsor_capacity: u64,
    pub fee: u64,
    pub finalise_since: u64,
    pub mine_blocks: u64,
    pub store_dir: PathBuf,
}

#[derive(Debug, Clone)]
pub struct FactoryXudtNegativeSmokeOptions {
    pub contracts_dir: PathBuf,
    pub private_key: String,
    pub alice_private_key: String,
    pub bob_private_key: String,
    pub factory_capacity: u64,
    pub factory_vault_capacity: u64,
    pub child_vault_capacity: u64,
    pub alice_capacity: Option<u64>,
    pub bob_capacity: Option<u64>,
    pub alice_xudt_amount: u128,
    pub bob_xudt_amount: u128,
    pub sponsor_capacity: u64,
    pub fee: u64,
    pub finalise_since: u64,
    pub mine_blocks: u64,
    pub store_dir: PathBuf,
}

#[derive(Debug, Clone)]
pub struct FactoryExitChannelOptions {
    pub contracts_dir: PathBuf,
    pub private_key: String,
    pub alice_private_key: String,
    pub bob_private_key: String,
    pub factory_out_point: String,
    pub factory_vault_out_point: String,
    pub update_number: Option<u64>,
    pub vault_capacity: u64,
    pub alice_capacity: Option<u64>,
    pub bob_capacity: Option<u64>,
    pub alice_xudt_amount: Option<u128>,
    pub bob_xudt_amount: Option<u128>,
    pub sponsor_capacity: u64,
    pub fee: u64,
    pub finalise_since: u64,
    pub mine_blocks: u64,
    pub tamper: FactoryExitChannelTamper,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FactoryExitChannelTamper {
    None,
    ChildXudtAmountMinusOnePreserveFactoryChange,
}

#[derive(Debug, Clone)]
pub struct PublishStateOptions {
    pub contracts_dir: PathBuf,
    pub private_key: String,
    pub alice_private_key: String,
    pub bob_private_key: String,
    pub state_out_point: String,
    pub sponsor_out_point: String,
    pub state_number: Option<u64>,
    pub state_package: Option<PathBuf>,
    pub fee: u64,
    pub mine_blocks: u64,
}

#[derive(Debug, Clone)]
pub struct SaveStatePackageOptions {
    pub alice_private_key: String,
    pub bob_private_key: String,
    pub state_out_point: String,
    pub state_number: Option<u64>,
    pub store_dir: PathBuf,
}

#[derive(Debug, Clone)]
pub struct PublishLatestStatePackageOptions {
    pub contracts_dir: PathBuf,
    pub private_key: String,
    pub state_out_point: String,
    pub sponsor_out_point: String,
    pub store_dir: PathBuf,
    pub channel_id: String,
    pub fee: u64,
    pub mine_blocks: u64,
}

#[derive(Debug, Clone)]
pub struct WatchLatestStatePackageOptions {
    pub contracts_dir: PathBuf,
    pub private_key: String,
    pub sponsor_out_point: Option<String>,
    pub store_dir: PathBuf,
    pub channel_id: String,
    pub from_block: u64,
    pub cursor_file: Option<PathBuf>,
    pub watch_policy: Option<PathBuf>,
    pub alert_file: Option<PathBuf>,
    pub alert_webhook_url: Option<String>,
    pub ignore_cursor: bool,
    pub detection_depth: u64,
    pub timeout_secs: u64,
    pub poll_ms: u64,
    pub fee: u64,
    pub mine_blocks: u64,
    pub auto_fund_sponsor: bool,
    pub auto_sponsor_capacity: u64,
}

#[derive(Debug, Clone)]
pub struct FundSponsorOptions {
    pub contracts_dir: PathBuf,
    pub private_key: String,
    pub state_out_point: String,
    pub sponsor_capacity: u64,
    pub sponsor_min_state_number: u64,
    pub sponsor_max_state_number: u64,
    pub sponsor_max_fee_per_tx: Option<u64>,
    pub sponsor_max_total_fee: Option<u64>,
    pub fee: u64,
    pub mine_blocks: u64,
}

#[derive(Debug, Clone)]
pub struct FinaliseChannelOptions {
    pub contracts_dir: PathBuf,
    pub private_key: String,
    pub alice_private_key: String,
    pub bob_private_key: String,
    pub state_out_point: String,
    pub vault_out_point: String,
    pub alice_capacity: Option<u64>,
    pub bob_capacity: Option<u64>,
    pub finalise_since: u64,
    pub fee: u64,
    pub mine_blocks: u64,
}

#[derive(Debug, Clone)]
pub struct SupersedeSmokeOptions {
    pub contracts_dir: PathBuf,
    pub private_key: String,
    pub alice_private_key: String,
    pub bob_private_key: String,
    pub vault_capacity: u64,
    pub alice_capacity: Option<u64>,
    pub bob_capacity: Option<u64>,
    pub sponsor_capacity: u64,
    pub fee: u64,
    pub finalise_since: u64,
    pub mine_blocks: u64,
}

#[derive(Debug, Clone)]
pub struct FinaliseSinceNegativeSmokeOptions {
    pub contracts_dir: PathBuf,
    pub private_key: String,
    pub alice_private_key: String,
    pub bob_private_key: String,
    pub vault_capacity: u64,
    pub alice_capacity: Option<u64>,
    pub bob_capacity: Option<u64>,
    pub sponsor_capacity: u64,
    pub fee: u64,
    pub finalise_since: u64,
    pub mine_blocks: u64,
}

#[derive(Debug, Clone)]
pub struct SponsorPolicyNegativeSmokeOptions {
    pub contracts_dir: PathBuf,
    pub private_key: String,
    pub alice_private_key: String,
    pub bob_private_key: String,
    pub vault_capacity: u64,
    pub alice_capacity: Option<u64>,
    pub bob_capacity: Option<u64>,
    pub sponsor_capacity: u64,
    pub fee: u64,
    pub finalise_since: u64,
    pub mine_blocks: u64,
}

#[derive(Debug, Clone)]
pub struct SponsorBudgetNegativeSmokeOptions {
    pub contracts_dir: PathBuf,
    pub private_key: String,
    pub alice_private_key: String,
    pub bob_private_key: String,
    pub vault_capacity: u64,
    pub alice_capacity: Option<u64>,
    pub bob_capacity: Option<u64>,
    pub sponsor_capacity: u64,
    pub fee: u64,
    pub finalise_since: u64,
    pub mine_blocks: u64,
}

#[derive(Debug, Clone)]
pub struct CompetingSpendSmokeOptions {
    pub contracts_dir: PathBuf,
    pub private_key: String,
    pub alice_private_key: String,
    pub bob_private_key: String,
    pub vault_capacity: u64,
    pub alice_capacity: Option<u64>,
    pub bob_capacity: Option<u64>,
    pub sponsor_capacity: u64,
    pub fee: u64,
    pub finalise_since: u64,
    pub mine_blocks: u64,
}

#[derive(Debug, Clone)]
pub struct XudtSmokeOptions {
    pub contracts_dir: PathBuf,
    pub private_key: String,
    pub alice_private_key: String,
    pub bob_private_key: String,
    pub vault_capacity: u64,
    pub alice_capacity: Option<u64>,
    pub bob_capacity: Option<u64>,
    pub alice_xudt_amount: u128,
    pub bob_xudt_amount: u128,
    pub sponsor_capacity: u64,
    pub fee: u64,
    pub finalise_since: u64,
    pub mine_blocks: u64,
}

#[derive(Debug, Clone)]
pub struct XudtNegativeSmokeOptions {
    pub contracts_dir: PathBuf,
    pub private_key: String,
    pub alice_private_key: String,
    pub bob_private_key: String,
    pub vault_capacity: u64,
    pub alice_capacity: Option<u64>,
    pub bob_capacity: Option<u64>,
    pub alice_xudt_amount: u128,
    pub bob_xudt_amount: u128,
    pub sponsor_capacity: u64,
    pub fee: u64,
    pub finalise_since: u64,
    pub mine_blocks: u64,
}

#[derive(Debug, Clone, Copy)]
struct SponsorPolicySettings {
    min_state_number: u64,
    max_state_number: u64,
    max_fee_per_tx: u64,
    max_total_fee: u64,
}

#[derive(Debug, Serialize)]
pub struct TransactionMetrics {
    pub estimated_cycles: u64,
    pub tx_size_bytes: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct SponsorPolicyReport {
    pub min_state_number: u64,
    pub max_state_number: u64,
    pub max_fee_per_tx: u64,
    pub max_total_fee: u64,
    pub already_spent: u64,
    pub expiry: u64,
    pub publication_state_type_hash: String,
    pub change_lock_hash: String,
}

#[derive(Debug, Serialize)]
pub struct DeployContractsReport {
    pub tx_hash: String,
    pub input_capacity: u64,
    pub deployed_capacity: u64,
    pub change_capacity: u64,
    pub fee: u64,
    pub metrics: TransactionMetrics,
    pub mined_blocks: Vec<String>,
    pub status: String,
    pub block_number: Option<u64>,
    pub block_hash: Option<String>,
    pub scripts: Vec<DeployedScriptReport>,
}

#[derive(Debug, Serialize)]
pub struct DeployedScriptReport {
    pub name: String,
    pub out_point: PrintableOutPoint,
    pub data_hash: String,
    pub hash_type: String,
    pub data_len: usize,
    pub capacity: u64,
}

#[derive(Debug, Serialize)]
pub struct PrintableOutPoint {
    pub tx_hash: String,
    pub index: u32,
}

#[derive(Debug, Serialize)]
pub struct OpenChannelReport {
    pub tx_hash: String,
    pub status: String,
    pub block_number: Option<u64>,
    pub block_hash: Option<String>,
    pub channel_id: String,
    pub funding_anchor: String,
    pub finalise_since: u64,
    pub input_capacity: u64,
    pub state_capacity: u64,
    pub vault_capacity: u64,
    pub sponsor_capacity: u64,
    pub sponsor_policy: SponsorPolicyReport,
    pub change_capacity: u64,
    pub fee: u64,
    pub metrics: TransactionMetrics,
    pub mined_blocks: Vec<String>,
    pub participants: Vec<ParticipantReport>,
    pub scripts: Vec<ResolvedScriptReport>,
    pub cells: Vec<ChannelCellReport>,
}

#[derive(Debug, Serialize)]
pub struct OpenFactoryReport {
    pub tx_hash: String,
    pub status: String,
    pub block_number: Option<u64>,
    pub block_hash: Option<String>,
    pub factory_id: String,
    pub input_capacity: u64,
    pub factory_capacity: u64,
    pub factory_vault_capacity: u64,
    pub factory_vault_xudt_amount: Option<u128>,
    pub xudt_type_hash: Option<String>,
    pub change_capacity: u64,
    pub fee: u64,
    pub metrics: TransactionMetrics,
    pub mined_blocks: Vec<String>,
    pub participants: Vec<FactoryParticipantReport>,
    pub scripts: Vec<ResolvedScriptReport>,
    pub cells: Vec<ChannelCellReport>,
}

#[derive(Debug, Serialize)]
pub struct FactoryExitChannelReport {
    pub tx_hash: String,
    pub status: String,
    pub block_number: Option<u64>,
    pub block_hash: Option<String>,
    pub factory_id: String,
    pub old_update_number: u64,
    pub new_update_number: u64,
    pub channel_id: String,
    pub funding_anchor: String,
    pub finalise_since: u64,
    pub factory_out_point: PrintableOutPoint,
    pub state_out_point: PrintableOutPoint,
    pub vault_out_point: PrintableOutPoint,
    pub factory_vault_out_point: PrintableOutPoint,
    pub sponsor_out_point: PrintableOutPoint,
    pub state_capacity: u64,
    pub vault_capacity: u64,
    pub child_xudt_amount: Option<u128>,
    pub factory_vault_input_capacity: u64,
    pub factory_vault_change_capacity: u64,
    pub factory_vault_input_xudt_amount: Option<u128>,
    pub factory_vault_change_xudt_amount: Option<u128>,
    pub xudt_type_hash: Option<String>,
    pub local_exit_package: StoredFactoryLocalExitPackage,
    pub sponsor_capacity: u64,
    pub fee_change_capacity: u64,
    pub fee: u64,
    pub metrics: TransactionMetrics,
    pub mined_blocks: Vec<String>,
    pub participants: Vec<ParticipantReport>,
}

#[derive(Debug, Serialize)]
pub struct UpdateFactoryReport {
    pub tx_hash: String,
    pub status: String,
    pub block_number: Option<u64>,
    pub block_hash: Option<String>,
    pub factory_id: String,
    pub old_update_number: u64,
    pub new_update_number: u64,
    pub factory_out_point: PrintableOutPoint,
    pub factory_capacity: u64,
    pub fee_input_capacity: u64,
    pub fee_change_capacity: u64,
    pub fee: u64,
    pub state_root: String,
    pub access_manifest_root: String,
    pub non_interference_digest: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub factory_state_package: Option<String>,
    pub metrics: TransactionMetrics,
    pub mined_blocks: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct SaveFactoryStatePackageReport {
    pub path: String,
    pub package: StoredFactoryStateCellPackage,
}

#[derive(Debug, Serialize)]
pub struct SaveFactoryReducedRightsPackageReport {
    pub path: String,
    pub package: StoredFactoryReducedRightsPackage,
}

#[derive(Debug, Serialize)]
pub struct FactorySmokeReport {
    pub open: OpenFactoryReport,
    pub saved_package: SaveFactoryStatePackageReport,
    pub selected_package: FactoryStateCellPackageRecord,
    pub update: UpdateFactoryReport,
}

#[derive(Debug, Serialize)]
pub struct FactoryReducedRightsSmokeReport {
    pub open: OpenFactoryReport,
    pub package: SaveFactoryReducedRightsPackageReport,
    pub update: UpdateFactoryReport,
}

#[derive(Debug, Serialize)]
pub struct ParticipantReport {
    pub role: String,
    pub lock_hash: String,
    pub pubkey_sec1: String,
    pub capacity: u64,
}

#[derive(Debug, Serialize)]
pub struct FactoryParticipantReport {
    pub role: String,
    pub participant_id: String,
    pub pubkey_sec1: String,
}

#[derive(Debug, Serialize)]
pub struct ResolvedScriptReport {
    pub name: String,
    pub out_point: PrintableOutPoint,
    pub data_hash: String,
    pub hash_type: String,
}

#[derive(Debug, Serialize)]
pub struct ChannelCellReport {
    pub role: String,
    pub out_point: PrintableOutPoint,
    pub capacity: u64,
    pub lock_hash: String,
    pub type_hash: Option<String>,
    pub data_len: usize,
}

#[derive(Debug, Serialize)]
pub struct PublishStateReport {
    pub tx_hash: String,
    pub status: String,
    pub block_number: Option<u64>,
    pub block_hash: Option<String>,
    pub channel_id: String,
    pub funding_anchor: String,
    pub old_state_number: u64,
    pub new_state_number: u64,
    pub state_out_point: PrintableOutPoint,
    pub sponsor_change_capacity: u64,
    pub fee: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state_package: Option<String>,
    pub metrics: TransactionMetrics,
    pub mined_blocks: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct SaveStatePackageReport {
    pub path: String,
    pub package: StoredStatePackage,
}

#[derive(Debug, Serialize)]
pub struct PublishLatestStatePackageReport {
    pub selected_package: StatePackageRecord,
    pub publication: PublishStateReport,
}

#[derive(Debug, Clone, Serialize)]
pub struct ObservedStateCellReport {
    pub block_number: u64,
    pub block_hash: String,
    pub tx_hash: String,
    pub output_index: u32,
    pub out_point: String,
    pub state_number: u64,
    pub phase: String,
    pub confirmations: u64,
}

#[derive(Debug, Serialize)]
pub struct WatchLatestStatePackageReport {
    pub channel_id: String,
    pub from_block: u64,
    pub effective_from_block: u64,
    pub scanned_to_block: u64,
    pub next_from_block: u64,
    pub detection_depth: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cursor_file: Option<PathBuf>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alert_file: Option<PathBuf>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alert_webhook_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub loaded_cursor: Option<WatchCursor>,
    pub selected_package: StatePackageRecord,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sponsor_top_up: Option<FundSponsorReport>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub observed: Option<ObservedStateCellReport>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub publication: Option<PublishStateReport>,
}

#[derive(Debug, Serialize)]
pub struct FundSponsorReport {
    pub tx_hash: String,
    pub status: String,
    pub block_number: Option<u64>,
    pub block_hash: Option<String>,
    pub channel_id: String,
    pub state_number: u64,
    pub sponsor_out_point: PrintableOutPoint,
    pub sponsor_capacity: u64,
    pub sponsor_policy: SponsorPolicyReport,
    pub change_capacity: u64,
    pub fee: u64,
    pub metrics: TransactionMetrics,
    pub mined_blocks: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct FinaliseChannelReport {
    pub tx_hash: String,
    pub status: String,
    pub block_number: Option<u64>,
    pub block_hash: Option<String>,
    pub channel_id: String,
    pub funding_anchor: String,
    pub state_number: u64,
    pub alice_capacity: u64,
    pub bob_capacity: u64,
    pub state_refund_capacity: u64,
    pub fee: u64,
    pub metrics: TransactionMetrics,
    pub mined_blocks: Vec<String>,
    pub outputs: Vec<ChannelCellReport>,
}

#[derive(Debug, Serialize)]
pub struct XudtFinaliseReport {
    pub tx_hash: String,
    pub status: String,
    pub block_number: Option<u64>,
    pub block_hash: Option<String>,
    pub channel_id: String,
    pub funding_anchor: String,
    pub state_number: u64,
    pub xudt_type_hash: String,
    pub alice_capacity: u64,
    pub bob_capacity: u64,
    pub alice_xudt_amount: u128,
    pub bob_xudt_amount: u128,
    pub state_refund_capacity: u64,
    pub fee: u64,
    pub metrics: TransactionMetrics,
    pub mined_blocks: Vec<String>,
    pub outputs: Vec<ChannelCellReport>,
}

#[derive(Debug, Serialize)]
pub struct XudtSmokeReport {
    pub open: OpenChannelReport,
    pub publish: PublishStateReport,
    pub finalise: XudtFinaliseReport,
}

#[derive(Debug, Serialize)]
pub struct FactoryXudtSmokeReport {
    pub open: OpenFactoryReport,
    pub package: SaveFactoryStatePackageReport,
    pub latest_package: FactoryStateCellPackageRecord,
    pub update: UpdateFactoryReport,
    pub exit: FactoryExitChannelReport,
    pub publish: PublishStateReport,
    pub finalise: XudtFinaliseReport,
}

#[derive(Debug, Serialize)]
pub struct FactoryXudtNegativeSmokeReport {
    pub open: OpenFactoryReport,
    pub package: SaveFactoryStatePackageReport,
    pub latest_package: FactoryStateCellPackageRecord,
    pub update: UpdateFactoryReport,
    pub expected_child_xudt_amount: u128,
    pub rejected_child_xudt_amount: u128,
    pub rejection: String,
    pub script_failure: ScriptFailureReport,
    pub exit: FactoryExitChannelReport,
    pub publish: PublishStateReport,
    pub finalise: XudtFinaliseReport,
}

#[derive(Debug, Serialize)]
pub struct XudtNegativeSmokeReport {
    pub open: OpenChannelReport,
    pub publish: PublishStateReport,
    pub rejected_alice_xudt_amount: u128,
    pub rejected_bob_xudt_amount: u128,
    pub rejection: String,
    pub script_failure: ScriptFailureReport,
    pub finalise: XudtFinaliseReport,
}

#[derive(Debug, Serialize)]
pub struct SupersedeSmokeReport {
    pub open: OpenChannelReport,
    pub stale_publish: PublishStateReport,
    pub sponsor_top_up: FundSponsorReport,
    pub supersede_publish: PublishStateReport,
    pub finalise: FinaliseChannelReport,
}

#[derive(Debug, Serialize)]
pub struct FinaliseSinceNegativeSmokeReport {
    pub open: OpenChannelReport,
    pub publish: PublishStateReport,
    pub rejected_input_since: u64,
    pub required_finalise_since: u64,
    pub rejection: String,
    pub script_failure: ScriptFailureReport,
    pub maturity_blocks: Vec<String>,
    pub finalise: FinaliseChannelReport,
}

#[derive(Debug, Serialize)]
pub struct SponsorPolicyNegativeSmokeReport {
    pub open: OpenChannelReport,
    pub rejected_state_number: u64,
    pub rejection: String,
    pub script_failure: ScriptFailureReport,
    pub allowed_publish: PublishStateReport,
    pub finalise: FinaliseChannelReport,
}

#[derive(Debug, Serialize)]
pub struct SponsorBudgetNegativeSmokeReport {
    pub open: OpenChannelReport,
    pub rejected_fee: u64,
    pub sponsor_max_fee_per_tx: u64,
    pub rejection: String,
    pub script_failure: ScriptFailureReport,
    pub replacement_sponsor: FundSponsorReport,
    pub allowed_publish: PublishStateReport,
    pub finalise: FinaliseChannelReport,
}

#[derive(Debug, Serialize)]
pub struct PendingCommitReport {
    pub tx_hash: String,
    pub status: String,
    pub block_number: Option<u64>,
    pub block_hash: Option<String>,
    pub mined_blocks: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct CompetingSpendSmokeReport {
    pub open: OpenChannelReport,
    pub spare_sponsor: FundSponsorReport,
    pub pending_publish: PublishStateReport,
    pub pending_commit: PendingCommitReport,
    pub rejected_state_number: u64,
    pub rejected_against_state_out_point: String,
    pub rejection: String,
    pub rebuilt_publish: PublishStateReport,
    pub finalise: FinaliseChannelReport,
}

#[derive(Debug, Clone, Serialize)]
pub struct ScriptFailureReport {
    pub source: Option<String>,
    pub error_code: Option<i16>,
    pub morph_error: Option<String>,
    pub raw: String,
}

struct LiveCell {
    out_point: OutPoint,
    capacity: u64,
}

struct LiveCellDetails {
    output: CellOutput,
    data: Bytes,
    capacity: u64,
}

struct SentTransactionReport {
    tx_hash: String,
    status: String,
    block_number: Option<u64>,
    block_hash: Option<String>,
    metrics: TransactionMetrics,
    mined_blocks: Vec<String>,
}

struct ContractBinary {
    name: String,
    data: Bytes,
    data_hash: H256,
    capacity: u64,
    output: CellOutput,
}

struct ContractTarget {
    name: String,
    data_hash: H256,
}

#[derive(Debug, Clone)]
struct ResolvedContract {
    name: String,
    data_hash: H256,
    out_point: OutPoint,
    cell_dep: CellDep,
}

pub fn deploy_contracts(
    rpc: &CkbRpcClient,
    options: DeployContractsOptions,
) -> Result<DeployContractsReport> {
    ensure!(options.fee > 0, "fee must be non-zero");

    let privkey = parse_privkey(&options.private_key)
        .with_context(|| "invalid secp256k1 private key for devnet deploy")?;
    let owner_lock = secp256k1_lock(&privkey)?;
    let tip = rpc.tip_header()?;
    let tip_number = tip.number_value()?;
    let funding_cell = find_largest_live_cell(rpc, &owner_lock, tip_number)?;
    let secp_dep = find_secp256k1_cell_dep(rpc)?;
    let contracts = load_contracts(&options.contracts_dir, &owner_lock)?;

    let deployed_capacity = contracts
        .iter()
        .try_fold(0u64, |acc, contract| acc.checked_add(contract.capacity))
        .ok_or_else(|| anyhow!("deployed capacity overflow"))?;
    let change_capacity = funding_cell
        .capacity
        .checked_sub(deployed_capacity)
        .and_then(|value| value.checked_sub(options.fee))
        .ok_or_else(|| {
            anyhow!(
                "funding cell capacity {} cannot cover deployed capacity {} and fee {}",
                funding_cell.capacity,
                deployed_capacity,
                options.fee
            )
        })?;
    ensure_change_capacity(&owner_lock, change_capacity)?;

    let unsigned = build_deploy_transaction(
        &funding_cell,
        secp_dep,
        &owner_lock,
        &contracts,
        change_capacity,
    );
    let signed = sign_single_secp_input(unsigned, &privkey)?;
    let sent = send_and_mine(rpc, signed, options.mine_blocks)?;

    let tx_hash_string = sent.tx_hash.clone();
    let scripts = contracts
        .into_iter()
        .enumerate()
        .map(|(index, contract)| DeployedScriptReport {
            name: contract.name,
            out_point: PrintableOutPoint {
                tx_hash: tx_hash_string.clone(),
                index: index as u32,
            },
            data_hash: format!("{:#x}", contract.data_hash),
            hash_type: "data1".to_string(),
            data_len: contract.data.len(),
            capacity: contract.capacity,
        })
        .collect();

    Ok(DeployContractsReport {
        tx_hash: tx_hash_string,
        input_capacity: funding_cell.capacity,
        deployed_capacity,
        change_capacity,
        fee: options.fee,
        metrics: sent.metrics,
        mined_blocks: sent.mined_blocks,
        status: sent.status,
        block_number: sent.block_number,
        block_hash: sent.block_hash,
        scripts,
    })
}

pub fn open_channel(rpc: &CkbRpcClient, options: OpenChannelOptions) -> Result<OpenChannelReport> {
    ensure!(options.fee > 0, "fee must be non-zero");
    ensure!(
        options.vault_capacity > 0,
        "vault capacity must be non-zero"
    );
    ensure!(
        options.sponsor_capacity > 0,
        "sponsor capacity must be non-zero"
    );

    let owner_key = parse_privkey(&options.private_key)
        .with_context(|| "invalid secp256k1 private key for devnet channel opener")?;
    let alice_key = parse_privkey(&options.alice_private_key)
        .with_context(|| "invalid Alice channel private key")?;
    let bob_key = parse_privkey(&options.bob_private_key)
        .with_context(|| "invalid Bob channel private key")?;

    let owner_lock = secp256k1_lock(&owner_key)?;
    let alice_lock = secp256k1_lock(&alice_key)?;
    let bob_lock = secp256k1_lock(&bob_key)?;
    let tip = rpc.tip_header()?;
    let tip_number = tip.number_value()?;
    let genesis = rpc
        .block_by_number(0)?
        .ok_or_else(|| anyhow!("genesis block is not available from CKB RPC"))?;
    let chain_id = genesis.header.hash.0;
    let funding_cell = find_largest_live_cell(rpc, &owner_lock, tip_number)?;
    let secp_dep = find_secp256k1_cell_dep(rpc)?;
    let contracts = find_deployed_contracts(rpc, &options.contracts_dir, tip_number)?;
    let state_lock_contract = contract_by_name(&contracts, "morph-state-lock")?;
    let state_contract = contract_by_name(&contracts, "morph-state-type")?;
    let vault_contract = contract_by_name(&contracts, "morph-vault-lock")?;
    let sponsor_contract = contract_by_name(&contracts, "morph-sponsor-lock")?;

    let channel_input = CellInput::new(funding_cell.out_point.clone(), 0);
    let funding_anchor = derive_funding_anchor(&channel_input, 0);
    let channel_id = script_blake2b256(&[b"CKB_MORPH_CHANNEL_ID_V1", &funding_anchor]);

    let mut script_args = funding_anchor.to_vec();
    script_args.extend_from_slice(&options.finalise_since.to_le_bytes());
    let state_type = data1_script(state_contract.data_hash.clone(), Bytes::from(script_args));
    let state_lock = data1_script(
        state_lock_contract.data_hash.clone(),
        Bytes::copy_from_slice(state_type.calc_script_hash().as_slice()),
    );

    let mut vault_args = funding_anchor.to_vec();
    vault_args.extend_from_slice(&options.finalise_since.to_le_bytes());
    let vault_lock = data1_script(vault_contract.data_hash.clone(), Bytes::from(vault_args));

    let change_lock_hash = owner_lock.calc_script_hash();
    let sponsor_policy_settings = sponsor_policy_settings(
        options.sponsor_capacity,
        options.sponsor_min_state_number,
        options.sponsor_max_state_number,
        options.sponsor_max_fee_per_tx,
        options.sponsor_max_total_fee,
    )?;
    let sponsor_policy = sponsor_policy_bytes(
        &channel_id,
        sponsor_policy_settings,
        state_type.calc_script_hash().unpack(),
        change_lock_hash.as_slice().try_into().unwrap(),
    );
    let sponsor_lock = data1_script(
        sponsor_contract.data_hash.clone(),
        Bytes::copy_from_slice(&sponsor_policy),
    );

    let alice_lock_hash: [u8; 32] = alice_lock.calc_script_hash().unpack();
    let bob_lock_hash: [u8; 32] = bob_lock.calc_script_hash().unpack();
    let (alice_capacity, bob_capacity) = settlement_split(
        options.vault_capacity,
        options.alice_capacity,
        options.bob_capacity,
    )?;
    ensure_output_capacity(
        "alice settlement",
        &CellOutput::new_builder()
            .capacity(alice_capacity)
            .lock(alice_lock.clone())
            .build(),
        0,
    )?;
    ensure_output_capacity(
        "bob settlement",
        &CellOutput::new_builder()
            .capacity(bob_capacity)
            .lock(bob_lock.clone())
            .build(),
        0,
    )?;
    let descriptor =
        bilateral_ckb_descriptor(alice_lock_hash, alice_capacity, bob_lock_hash, bob_capacity);
    let descriptor_commitment = settlement_descriptor_commitment_v1(&descriptor);

    let alice_pubkey = compressed_pubkey(&alice_key)?;
    let bob_pubkey = compressed_pubkey(&bob_key)?;
    let mut participant_pubkeys = [alice_pubkey, bob_pubkey];
    participant_pubkeys.sort();
    let participants_commitment =
        participants_commitment_v1(2, &[&participant_pubkeys[0], &participant_pubkeys[1]]);
    let challenge_policy_commitment = script_blake2b256(&[
        b"CKB_MORPH_CHALLENGE_POLICY_V1",
        &options.finalise_since.to_le_bytes(),
    ]);
    let state_header = initial_state_header(InitialStateHeader {
        chain_id,
        channel_id,
        funding_anchor,
        participants_commitment,
        settlement_descriptor_commitment: descriptor_commitment,
        descriptor_version: BILATERAL_CKB_DESCRIPTOR_VERSION_V1,
        challenge_policy_commitment,
    });

    let state_output_for_capacity = CellOutput::new_builder()
        .lock(state_lock.clone())
        .type_(Some(state_type.clone()).pack())
        .build();
    let state_capacity = occupied_capacity(&state_output_for_capacity, state_header.len())?;
    let state_output = CellOutput::new_builder()
        .capacity(state_capacity)
        .lock(state_lock.clone())
        .type_(Some(state_type.clone()).pack())
        .build();

    let vault_output = CellOutput::new_builder()
        .capacity(options.vault_capacity)
        .lock(vault_lock)
        .build();
    ensure_output_capacity("vault", &vault_output, 0)?;

    let sponsor_output = CellOutput::new_builder()
        .capacity(options.sponsor_capacity)
        .lock(sponsor_lock)
        .build();
    ensure_output_capacity("sponsor", &sponsor_output, 0)?;

    let fixed_output_capacity = state_capacity
        .checked_add(options.vault_capacity)
        .and_then(|value| value.checked_add(options.sponsor_capacity))
        .ok_or_else(|| anyhow!("channel output capacity overflow"))?;
    let change_capacity = funding_cell
        .capacity
        .checked_sub(fixed_output_capacity)
        .and_then(|value| value.checked_sub(options.fee))
        .ok_or_else(|| {
            anyhow!(
                "funding cell capacity {} cannot cover state {}, vault {}, sponsor {}, and fee {}",
                funding_cell.capacity,
                state_capacity,
                options.vault_capacity,
                options.sponsor_capacity,
                options.fee
            )
        })?;
    ensure_change_capacity(&owner_lock, change_capacity)?;

    let change_output = CellOutput::new_builder()
        .capacity(change_capacity)
        .lock(owner_lock.clone())
        .build();
    let unsigned = TransactionBuilder::default()
        .cell_dep(secp_dep)
        .cell_dep(state_lock_contract.cell_dep.clone())
        .cell_dep(state_contract.cell_dep.clone())
        .cell_dep(vault_contract.cell_dep.clone())
        .cell_dep(sponsor_contract.cell_dep.clone())
        .input(channel_input)
        .output(state_output.clone())
        .output(vault_output.clone())
        .output(sponsor_output.clone())
        .output(change_output.clone())
        .output_data(Bytes::copy_from_slice(&state_header).pack())
        .output_data(Bytes::new().pack())
        .output_data(Bytes::new().pack())
        .output_data(Bytes::new().pack())
        .build();
    let signed = sign_single_secp_input(unsigned, &owner_key)?;
    let sent = send_and_mine(rpc, signed, options.mine_blocks)?;

    let tx_hash_string = sent.tx_hash.clone();
    let cell =
        |role: &str, index: u32, output: &CellOutput, data_len: usize| -> ChannelCellReport {
            ChannelCellReport {
                role: role.to_string(),
                out_point: PrintableOutPoint {
                    tx_hash: tx_hash_string.clone(),
                    index,
                },
                capacity: output.capacity().unpack(),
                lock_hash: hex32(output.lock().calc_script_hash().as_slice()),
                type_hash: output
                    .type_()
                    .to_opt()
                    .map(|script| hex32(script.calc_script_hash().as_slice())),
                data_len,
            }
        };

    Ok(OpenChannelReport {
        tx_hash: tx_hash_string.clone(),
        status: sent.status,
        block_number: sent.block_number,
        block_hash: sent.block_hash,
        channel_id: hex32(&channel_id),
        funding_anchor: hex32(&funding_anchor),
        finalise_since: options.finalise_since,
        input_capacity: funding_cell.capacity,
        state_capacity,
        vault_capacity: options.vault_capacity,
        sponsor_capacity: options.sponsor_capacity,
        sponsor_policy: sponsor_policy_report(
            sponsor_policy_settings,
            state_type.calc_script_hash().unpack(),
            change_lock_hash.as_slice().try_into().unwrap(),
        ),
        change_capacity,
        fee: options.fee,
        metrics: sent.metrics,
        mined_blocks: sent.mined_blocks,
        participants: vec![
            ParticipantReport {
                role: "alice".to_string(),
                lock_hash: hex32(&alice_lock_hash),
                pubkey_sec1: hex_prefixed(&alice_pubkey),
                capacity: alice_capacity,
            },
            ParticipantReport {
                role: "bob".to_string(),
                lock_hash: hex32(&bob_lock_hash),
                pubkey_sec1: hex_prefixed(&bob_pubkey),
                capacity: bob_capacity,
            },
        ],
        scripts: contracts
            .into_iter()
            .map(|contract| ResolvedScriptReport {
                name: contract.name,
                out_point: printable_out_point(&contract.out_point),
                data_hash: format!("{:#x}", contract.data_hash),
                hash_type: "data1".to_string(),
            })
            .collect(),
        cells: vec![
            cell("state", 0, &state_output, state_header.len()),
            cell("vault", 1, &vault_output, 0),
            cell("sponsor", 2, &sponsor_output, 0),
            cell("change", 3, &change_output, 0),
        ],
    })
}

pub fn open_factory(rpc: &CkbRpcClient, options: OpenFactoryOptions) -> Result<OpenFactoryReport> {
    ensure!(options.fee > 0, "fee must be non-zero");
    ensure!(
        options.factory_capacity > 0,
        "factory capacity must be non-zero"
    );
    ensure!(
        options.factory_vault_capacity > 0,
        "factory vault capacity must be non-zero"
    );
    if let Some(amount) = options.factory_vault_xudt_amount {
        ensure!(amount > 0, "factory vault xUDT amount must be non-zero");
    }

    let owner_key = parse_privkey(&options.private_key)
        .with_context(|| "invalid secp256k1 private key for factory opener")?;
    let owner_lock = secp256k1_lock(&owner_key)?;
    let alice_key = k256_signing_key(&options.alice_private_key)
        .with_context(|| "invalid Alice factory private key")?;
    let bob_key = k256_signing_key(&options.bob_private_key)
        .with_context(|| "invalid Bob factory private key")?;
    let alice_pubkey = k256_pubkey(&alice_key);
    let bob_pubkey = k256_pubkey(&bob_key);

    let tip = rpc.tip_header()?;
    let tip_number = tip.number_value()?;
    let genesis = rpc
        .block_by_number(0)?
        .ok_or_else(|| anyhow!("genesis block is not available from CKB RPC"))?;
    let chain_id = genesis.header.hash.0;
    let funding_cell = find_largest_live_cell(rpc, &owner_lock, tip_number)?;
    let secp_dep = find_secp256k1_cell_dep(rpc)?;
    let contracts = find_deployed_contracts(rpc, &options.contracts_dir, tip_number)?;
    let factory_contract = contract_by_name(&contracts, "morph-factory-type")?;
    let factory_vault_contract = contract_by_name(&contracts, "morph-factory-vault-lock")?;
    let xudt_contract = if options.factory_vault_xudt_amount.is_some() {
        Some(contract_by_name(&contracts, "morph-devnet-xudt")?)
    } else {
        None
    };

    let factory_input = CellInput::new(funding_cell.out_point.clone(), 0);
    let factory_id = derive_funding_anchor(&factory_input, 0);
    let factory_type = data1_script(
        factory_contract.data_hash.clone(),
        Bytes::copy_from_slice(&factory_id),
    );
    let factory_type_hash: [u8; BYTE32_LEN] = factory_type.calc_script_hash().unpack();
    let mut factory_vault_args = factory_id.to_vec();
    factory_vault_args.extend_from_slice(&factory_type_hash);
    let factory_vault_lock = data1_script(
        factory_vault_contract.data_hash.clone(),
        Bytes::from(factory_vault_args),
    );
    let owner_lock_hash = owner_lock.calc_script_hash();
    let xudt_type = xudt_contract.as_ref().map(|contract| {
        data1_script(
            contract.data_hash.clone(),
            Bytes::copy_from_slice(owner_lock_hash.as_slice()),
        )
    });
    let xudt_type_hash = xudt_type
        .as_ref()
        .map(|script| hex32(script.calc_script_hash().as_slice()));

    let state_root = parse_optional_hex32("state root", options.state_root.as_deref())?
        .unwrap_or_else(|| script_blake2b256(&[b"CKB_MORPH_EMPTY_FACTORY_STATE_ROOT_V1"]));
    let access_manifest_root = parse_optional_hex32(
        "access manifest root",
        options.access_manifest_root.as_deref(),
    )?
    .unwrap_or_else(|| script_blake2b256(&[b"CKB_MORPH_EMPTY_FACTORY_ACCESS_MANIFEST_V1"]));
    let non_interference_digest = parse_optional_hex32(
        "non-interference digest",
        options.non_interference_digest.as_deref(),
    )?
    .unwrap_or_else(|| script_blake2b256(&[b"CKB_MORPH_INITIAL_FACTORY_NON_INTERFERENCE_V1"]));
    let participants_commitment =
        factory_participants_commitment_from_pubkeys(alice_pubkey, bob_pubkey);
    let challenge_policy_commitment =
        script_blake2b256(&[b"CKB_MORPH_FACTORY_CHALLENGE_POLICY_V1"]);
    let factory_header = factory_state_header(FactoryHeaderInput {
        chain_id,
        factory_id,
        update_number: 0,
        state_root,
        participants_commitment,
        access_manifest_root,
        non_interference_digest,
        challenge_policy_commitment,
    });

    let factory_output = CellOutput::new_builder()
        .capacity(options.factory_capacity)
        .lock(owner_lock.clone())
        .type_(Some(factory_type.clone()).pack())
        .build();
    ensure_output_capacity("factory", &factory_output, factory_header.len())?;

    let factory_vault_output = CellOutput::new_builder()
        .capacity(options.factory_vault_capacity)
        .lock(factory_vault_lock)
        .type_(xudt_type.clone().pack())
        .build();
    let factory_vault_data = options
        .factory_vault_xudt_amount
        .map(xudt_amount_bytes)
        .unwrap_or_default();
    ensure_output_capacity(
        "factory vault",
        &factory_vault_output,
        factory_vault_data.len(),
    )?;

    let fixed_output_capacity = options
        .factory_capacity
        .checked_add(options.factory_vault_capacity)
        .ok_or_else(|| anyhow!("factory output capacity overflow"))?;
    let change_capacity = funding_cell
        .capacity
        .checked_sub(fixed_output_capacity)
        .and_then(|value| value.checked_sub(options.fee))
        .ok_or_else(|| {
            anyhow!(
                "funding cell capacity {} cannot cover factory capacity {}, factory vault capacity {}, and fee {}",
                funding_cell.capacity,
                options.factory_capacity,
                options.factory_vault_capacity,
                options.fee
            )
        })?;
    ensure_change_capacity(&owner_lock, change_capacity)?;
    let change_output = CellOutput::new_builder()
        .capacity(change_capacity)
        .lock(owner_lock.clone())
        .build();

    let mut builder = TransactionBuilder::default()
        .cell_dep(secp_dep)
        .cell_dep(factory_contract.cell_dep.clone())
        .cell_dep(factory_vault_contract.cell_dep.clone());
    if let Some(contract) = xudt_contract.as_ref() {
        builder = builder.cell_dep(contract.cell_dep.clone());
    }
    let unsigned = builder
        .input(factory_input)
        .output(factory_output.clone())
        .output(factory_vault_output.clone())
        .output(change_output.clone())
        .output_data(Bytes::copy_from_slice(&factory_header).pack())
        .output_data(factory_vault_data.clone().pack())
        .output_data(Bytes::new().pack())
        .build();
    let signed = sign_single_secp_input(unsigned, &owner_key)?;
    let sent = send_and_mine(rpc, signed, options.mine_blocks)?;
    let tx_hash_string = sent.tx_hash.clone();

    let cell =
        |role: &str, index: u32, output: &CellOutput, data_len: usize| -> ChannelCellReport {
            ChannelCellReport {
                role: role.to_string(),
                out_point: PrintableOutPoint {
                    tx_hash: tx_hash_string.clone(),
                    index,
                },
                capacity: output.capacity().unpack(),
                lock_hash: hex32(output.lock().calc_script_hash().as_slice()),
                type_hash: output
                    .type_()
                    .to_opt()
                    .map(|script| hex32(script.calc_script_hash().as_slice())),
                data_len,
            }
        };

    Ok(OpenFactoryReport {
        tx_hash: tx_hash_string.clone(),
        status: sent.status,
        block_number: sent.block_number,
        block_hash: sent.block_hash,
        factory_id: hex32(&factory_id),
        input_capacity: funding_cell.capacity,
        factory_capacity: options.factory_capacity,
        factory_vault_capacity: options.factory_vault_capacity,
        factory_vault_xudt_amount: options.factory_vault_xudt_amount,
        xudt_type_hash,
        change_capacity,
        fee: options.fee,
        metrics: sent.metrics,
        mined_blocks: sent.mined_blocks,
        participants: factory_participant_reports(alice_pubkey, bob_pubkey),
        scripts: contracts
            .into_iter()
            .map(|contract| ResolvedScriptReport {
                name: contract.name,
                out_point: printable_out_point(&contract.out_point),
                data_hash: format!("{:#x}", contract.data_hash),
                hash_type: "data1".to_string(),
            })
            .collect(),
        cells: vec![
            cell("factory", 0, &factory_output, factory_header.len()),
            cell(
                "factory-vault",
                1,
                &factory_vault_output,
                factory_vault_data.len(),
            ),
            cell("change", 2, &change_output, 0),
        ],
    })
}

pub fn update_factory(
    rpc: &CkbRpcClient,
    options: UpdateFactoryOptions,
) -> Result<UpdateFactoryReport> {
    ensure!(options.fee > 0, "fee must be non-zero");

    let owner_key = parse_privkey(&options.private_key)
        .with_context(|| "invalid secp256k1 private key for factory updater")?;
    let owner_lock = secp256k1_lock(&owner_key)?;
    let factory_out_point = parse_out_point(&options.factory_out_point)?;
    let factory_cell = load_live_cell(rpc, factory_out_point.clone())?;
    ensure!(
        factory_cell.output.lock() == owner_lock,
        "private key does not control the FactoryStateCell lock"
    );
    let factory_type = factory_cell
        .output
        .type_()
        .to_opt()
        .ok_or_else(|| anyhow!("factory cell has no type script"))?;
    let old_header = FactoryStateHeaderV1::parse(factory_cell.data.as_ref()).map_err(|err| {
        anyhow!("factory cell does not contain a valid FactoryStateHeader: {err:?}")
    })?;
    ensure!(
        factory_type.args().raw_data().as_ref() == old_header.factory_id(),
        "factory type args do not match the factory id in cell data"
    );
    let old_update_number = old_header.update_number();
    let (
        new_factory_data,
        signature_witness,
        new_update_number,
        state_root,
        access_manifest_root,
        non_interference_digest,
        factory_state_package,
    ) = if let Some(path) = &options.factory_state_package {
        ensure!(
            options.update_number.is_none()
                && options.state_root.is_none()
                && options.access_manifest_root.is_none()
                && options.non_interference_digest.is_none(),
            "factory_state_package cannot be combined with update_number or root overrides"
        );
        let package = read_factory_state_cell_update_package(path)?;
        package.validate_against_current_header(&old_header)?;
        let header_bytes = package.new_header_bytes()?;
        let witness_bytes = package.witness_bytes()?;
        let package_header = FactoryStateHeaderV1::parse(&header_bytes)
            .map_err(|err| anyhow!("factory state package header is invalid: {err:?}"))?;
        ensure!(
            package.factory_id() == hex32(old_header.factory_id()),
            "factory state package is for factory {}, not {}",
            package.factory_id(),
            hex32(old_header.factory_id())
        );
        ensure!(
            old_header.same_context_except_progress(&package_header),
            "factory state package does not match the current factory context"
        );
        ensure!(
            package_header.update_number() > old_update_number,
            "factory state package number {} must be greater than old update number {}",
            package_header.update_number(),
            old_update_number
        );
        let package_update_number = package_header.update_number();
        ensure!(
            package.update_number() == package_update_number,
            "factory state package update number metadata does not match header"
        );
        let package_state_root =
            bytes32_from_slice("factory package state root", package_header.state_root())?;
        ensure!(
            package.state_root() == hex32(&package_state_root),
            "factory state package state root metadata does not match header"
        );
        let package_access_manifest_root = bytes32_from_slice(
            "factory package access manifest root",
            package_header.access_manifest_root(),
        )?;
        ensure!(
            package.access_manifest_root() == hex32(&package_access_manifest_root),
            "factory state package access manifest metadata does not match header"
        );
        let package_non_interference_digest = bytes32_from_slice(
            "factory package non-interference digest",
            package_header.non_interference_digest(),
        )?;
        ensure!(
            package.non_interference_digest() == hex32(&package_non_interference_digest),
            "factory state package non-interference metadata does not match header"
        );
        (
            header_bytes,
            witness_bytes,
            package_update_number,
            package_state_root,
            package_access_manifest_root,
            package_non_interference_digest,
            Some(path.display().to_string()),
        )
    } else {
        let new_update_number = options
            .update_number
            .unwrap_or_else(|| old_update_number.saturating_add(1));
        ensure!(
            new_update_number > old_update_number,
            "new update number must be greater than old update number {}",
            old_update_number
        );
        let state_root = parse_optional_hex32("state root", options.state_root.as_deref())?
            .unwrap_or_else(|| {
                derived_factory_update_digest(
                    b"CKB_MORPH_FACTORY_STATE_ROOT_UPDATE_V1",
                    old_header.state_root(),
                    new_update_number,
                )
            });
        let access_manifest_root = parse_optional_hex32(
            "access manifest root",
            options.access_manifest_root.as_deref(),
        )?
        .unwrap_or_else(|| {
            derived_factory_update_digest(
                b"CKB_MORPH_FACTORY_ACCESS_MANIFEST_UPDATE_V1",
                old_header.access_manifest_root(),
                new_update_number,
            )
        });
        let non_interference_digest = parse_optional_hex32(
            "non-interference digest",
            options.non_interference_digest.as_deref(),
        )?
        .unwrap_or_else(|| {
            derived_factory_update_digest(
                b"CKB_MORPH_FACTORY_NON_INTERFERENCE_UPDATE_V1",
                old_header.non_interference_digest(),
                new_update_number,
            )
        });

        let mut new_factory_data = factory_cell.data.to_vec();
        put_u64(&mut new_factory_data, 68, new_update_number);
        new_factory_data[76..108].copy_from_slice(&state_root);
        new_factory_data[140..172].copy_from_slice(&access_manifest_root);
        new_factory_data[172..204].copy_from_slice(&non_interference_digest);
        let signature_witness = factory_signature_witness(
            &new_factory_data,
            &options.alice_private_key,
            &options.bob_private_key,
        )?;
        (
            new_factory_data,
            signature_witness.to_vec(),
            new_update_number,
            state_root,
            access_manifest_root,
            non_interference_digest,
            None,
        )
    };

    let tip_number = rpc.tip_header()?.number_value()?;
    let secp_dep = find_secp256k1_cell_dep(rpc)?;
    let contracts = find_deployed_contracts(rpc, &options.contracts_dir, tip_number)?;
    let factory_contract = contract_by_name(&contracts, "morph-factory-type")?;
    ensure!(
        byte32_to_h256(factory_type.code_hash()) == factory_contract.data_hash,
        "factory cell type script does not use the deployed morph-factory-type code hash"
    );

    let fee_cell = find_largest_live_cell(rpc, &owner_lock, tip_number)?;
    ensure!(
        fee_cell.out_point != factory_out_point,
        "fee input cannot be the FactoryStateCell itself"
    );
    let fee_change_capacity = fee_cell
        .capacity
        .checked_sub(options.fee)
        .ok_or_else(|| anyhow!("fee input capacity cannot cover fee {}", options.fee))?;
    ensure_change_capacity(&owner_lock, fee_change_capacity)?;
    ensure_output_capacity("factory", &factory_cell.output, new_factory_data.len())?;
    let fee_change_output = CellOutput::new_builder()
        .capacity(fee_change_capacity)
        .lock(owner_lock)
        .build();

    let unsigned = TransactionBuilder::default()
        .cell_dep(secp_dep)
        .cell_dep(factory_contract.cell_dep)
        .input(CellInput::new(factory_out_point, 0))
        .input(CellInput::new(fee_cell.out_point.clone(), 0))
        .output(factory_cell.output.clone())
        .output(fee_change_output)
        .output_data(Bytes::from(new_factory_data).pack())
        .output_data(Bytes::new().pack())
        .build();
    let signed = sign_factory_update_transaction(
        unsigned,
        &owner_key,
        Bytes::copy_from_slice(&signature_witness),
    )?;
    let sent = send_and_mine(rpc, signed, options.mine_blocks)?;
    let new_factory_tx_hash = sent.tx_hash.clone();

    Ok(UpdateFactoryReport {
        tx_hash: sent.tx_hash,
        status: sent.status,
        block_number: sent.block_number,
        block_hash: sent.block_hash,
        factory_id: hex32(old_header.factory_id()),
        old_update_number,
        new_update_number,
        factory_out_point: PrintableOutPoint {
            tx_hash: new_factory_tx_hash,
            index: 0,
        },
        factory_capacity: factory_cell.capacity,
        fee_input_capacity: fee_cell.capacity,
        fee_change_capacity,
        fee: options.fee,
        state_root: hex32(&state_root),
        access_manifest_root: hex32(&access_manifest_root),
        non_interference_digest: hex32(&non_interference_digest),
        factory_state_package,
        metrics: sent.metrics,
        mined_blocks: sent.mined_blocks,
    })
}

pub fn save_factory_state_package(
    rpc: &CkbRpcClient,
    options: SaveFactoryStatePackageOptions,
) -> Result<SaveFactoryStatePackageReport> {
    let factory_out_point = parse_out_point(&options.factory_out_point)?;
    let factory_cell = load_live_cell(rpc, factory_out_point.clone())?;
    let old_header = FactoryStateHeaderV1::parse(factory_cell.data.as_ref()).map_err(|err| {
        anyhow!("factory cell does not contain a valid FactoryStateHeader: {err:?}")
    })?;
    let new_update_number = options
        .update_number
        .unwrap_or_else(|| old_header.update_number().saturating_add(1));
    ensure!(
        new_update_number > old_header.update_number(),
        "new update number must be greater than old update number {}",
        old_header.update_number()
    );
    let state_root = parse_optional_hex32("state root", options.state_root.as_deref())?
        .unwrap_or_else(|| {
            derived_factory_update_digest(
                b"CKB_MORPH_FACTORY_STATE_ROOT_UPDATE_V1",
                old_header.state_root(),
                new_update_number,
            )
        });
    let access_manifest_root = parse_optional_hex32(
        "access manifest root",
        options.access_manifest_root.as_deref(),
    )?
    .unwrap_or_else(|| {
        derived_factory_update_digest(
            b"CKB_MORPH_FACTORY_ACCESS_MANIFEST_UPDATE_V1",
            old_header.access_manifest_root(),
            new_update_number,
        )
    });
    let non_interference_digest = parse_optional_hex32(
        "non-interference digest",
        options.non_interference_digest.as_deref(),
    )?
    .unwrap_or_else(|| {
        derived_factory_update_digest(
            b"CKB_MORPH_FACTORY_NON_INTERFERENCE_UPDATE_V1",
            old_header.non_interference_digest(),
            new_update_number,
        )
    });

    let mut new_factory_data = factory_cell.data.to_vec();
    put_u64(&mut new_factory_data, 68, new_update_number);
    new_factory_data[76..108].copy_from_slice(&state_root);
    new_factory_data[140..172].copy_from_slice(&access_manifest_root);
    new_factory_data[172..204].copy_from_slice(&non_interference_digest);
    let signature_witness = factory_signature_witness(
        &new_factory_data,
        &options.alice_private_key,
        &options.bob_private_key,
    )?;

    let printable = printable_out_point(&factory_out_point);
    let package = StoredFactoryStateCellPackage::from_signed_factory_state(
        &new_factory_data,
        &signature_witness,
        Some(PackageOutPoint {
            tx_hash: printable.tx_hash,
            index: printable.index,
        }),
    )?;
    let path = write_factory_state_cell_package(&options.store_dir, &package)?;

    Ok(SaveFactoryStatePackageReport {
        path: path.display().to_string(),
        package,
    })
}

pub fn save_factory_reduced_rights_package(
    rpc: &CkbRpcClient,
    options: SaveFactoryReducedRightsPackageOptions,
) -> Result<SaveFactoryReducedRightsPackageReport> {
    ensure!(
        options.touched_after_balance < 100,
        "touched_after_balance must decrease the fixture balance below 100"
    );
    let alice_key = k256_signing_key(&options.alice_private_key)
        .with_context(|| "invalid Alice factory private key")?;
    let bob_key = k256_signing_key(&options.bob_private_key)
        .with_context(|| "invalid Bob factory private key")?;
    let factory_out_point = parse_out_point(&options.factory_out_point)?;
    let factory_cell = load_live_cell(rpc, factory_out_point.clone())?;
    let old_header = FactoryStateHeaderV1::parse(factory_cell.data.as_ref()).map_err(|err| {
        anyhow!("factory cell does not contain a valid FactoryStateHeader: {err:?}")
    })?;
    let printable = printable_out_point(&factory_out_point);
    let package = reduced_rights_package_from_factory_header(
        factory_cell.data.as_ref(),
        &alice_key,
        &bob_key,
        options.update_number,
        options.touched_after_balance,
        Some(PackageOutPoint {
            tx_hash: printable.tx_hash,
            index: printable.index,
        }),
    )
    .with_context(|| {
        format!(
            "factory {} at update {} is not compatible with the reduced-rights proof shape",
            hex32(old_header.factory_id()),
            old_header.update_number()
        )
    })?;
    let path = write_factory_reduced_rights_package(&options.store_dir, &package)?;

    Ok(SaveFactoryReducedRightsPackageReport {
        path: path.display().to_string(),
        package,
    })
}

pub fn factory_smoke(
    rpc: &CkbRpcClient,
    options: FactorySmokeOptions,
) -> Result<FactorySmokeReport> {
    let open = open_factory(
        rpc,
        OpenFactoryOptions {
            contracts_dir: options.contracts_dir.clone(),
            private_key: options.private_key.clone(),
            alice_private_key: options.alice_private_key.clone(),
            bob_private_key: options.bob_private_key.clone(),
            factory_capacity: options.factory_capacity,
            factory_vault_capacity: options.factory_vault_capacity,
            factory_vault_xudt_amount: None,
            state_root: None,
            access_manifest_root: None,
            non_interference_digest: None,
            fee: options.fee,
            mine_blocks: options.mine_blocks,
        },
    )?;
    let factory_out_point = factory_cell_out_point(&open, "factory")?;
    let saved_package = save_factory_state_package(
        rpc,
        SaveFactoryStatePackageOptions {
            alice_private_key: options.alice_private_key.clone(),
            bob_private_key: options.bob_private_key.clone(),
            factory_out_point: factory_out_point.clone(),
            update_number: None,
            state_root: None,
            access_manifest_root: None,
            non_interference_digest: None,
            store_dir: options.store_dir.clone(),
        },
    )?;
    let selected_package = latest_factory_state_cell_package(&options.store_dir, &open.factory_id)?;
    let update = update_factory(
        rpc,
        UpdateFactoryOptions {
            contracts_dir: options.contracts_dir,
            private_key: options.private_key,
            alice_private_key: options.alice_private_key,
            bob_private_key: options.bob_private_key,
            factory_out_point,
            update_number: None,
            state_root: None,
            access_manifest_root: None,
            non_interference_digest: None,
            factory_state_package: Some(selected_package.path.clone()),
            fee: options.fee,
            mine_blocks: options.mine_blocks,
        },
    )?;

    Ok(FactorySmokeReport {
        open,
        saved_package,
        selected_package,
        update,
    })
}

pub fn factory_reduced_rights_smoke(
    rpc: &CkbRpcClient,
    options: FactoryReducedRightsSmokeOptions,
) -> Result<FactoryReducedRightsSmokeReport> {
    let roots = fixture_factory_reduced_rights_package()?;
    let open = open_factory(
        rpc,
        OpenFactoryOptions {
            contracts_dir: options.contracts_dir.clone(),
            private_key: options.private_key.clone(),
            alice_private_key: options.alice_private_key.clone(),
            bob_private_key: options.bob_private_key.clone(),
            factory_capacity: options.factory_capacity,
            factory_vault_capacity: options.factory_vault_capacity,
            factory_vault_xudt_amount: None,
            state_root: Some(roots.old_state_root),
            access_manifest_root: Some(roots.old_access_manifest_root),
            non_interference_digest: None,
            fee: options.fee,
            mine_blocks: options.mine_blocks,
        },
    )?;
    let factory_out_point = factory_cell_out_point(&open, "factory")?;
    let package = save_factory_reduced_rights_package(
        rpc,
        SaveFactoryReducedRightsPackageOptions {
            alice_private_key: options.alice_private_key.clone(),
            bob_private_key: options.bob_private_key.clone(),
            factory_out_point: factory_out_point.clone(),
            update_number: None,
            touched_after_balance: options.touched_after_balance,
            store_dir: options.store_dir.clone(),
        },
    )?;
    let update = update_factory(
        rpc,
        UpdateFactoryOptions {
            contracts_dir: options.contracts_dir,
            private_key: options.private_key,
            alice_private_key: options.alice_private_key,
            bob_private_key: options.bob_private_key,
            factory_out_point,
            update_number: None,
            state_root: None,
            access_manifest_root: None,
            non_interference_digest: None,
            factory_state_package: Some(PathBuf::from(&package.path)),
            fee: options.fee,
            mine_blocks: options.mine_blocks,
        },
    )?;

    Ok(FactoryReducedRightsSmokeReport {
        open,
        package,
        update,
    })
}

pub fn factory_xudt_smoke(
    rpc: &CkbRpcClient,
    options: FactoryXudtSmokeOptions,
) -> Result<FactoryXudtSmokeReport> {
    let total_xudt_amount = options
        .alice_xudt_amount
        .checked_add(options.bob_xudt_amount)
        .ok_or_else(|| anyhow!("factory xUDT amount overflow"))?;
    ensure!(
        total_xudt_amount > 0,
        "factory xUDT amount must be non-zero"
    );

    let open = open_factory(
        rpc,
        OpenFactoryOptions {
            contracts_dir: options.contracts_dir.clone(),
            private_key: options.private_key.clone(),
            alice_private_key: options.alice_private_key.clone(),
            bob_private_key: options.bob_private_key.clone(),
            factory_capacity: options.factory_capacity,
            factory_vault_capacity: options.factory_vault_capacity,
            factory_vault_xudt_amount: Some(total_xudt_amount),
            state_root: None,
            access_manifest_root: None,
            non_interference_digest: None,
            fee: options.fee,
            mine_blocks: options.mine_blocks,
        },
    )?;
    let factory_out_point = factory_cell_out_point(&open, "factory")?;
    let factory_vault_out_point = factory_cell_out_point(&open, "factory-vault")?;
    let package = save_factory_state_package(
        rpc,
        SaveFactoryStatePackageOptions {
            alice_private_key: options.alice_private_key.clone(),
            bob_private_key: options.bob_private_key.clone(),
            factory_out_point: factory_out_point.clone(),
            update_number: None,
            state_root: None,
            access_manifest_root: None,
            non_interference_digest: None,
            store_dir: options.store_dir.clone(),
        },
    )?;
    let latest_package = latest_factory_state_cell_package(&options.store_dir, &open.factory_id)?;
    let update = update_factory(
        rpc,
        UpdateFactoryOptions {
            contracts_dir: options.contracts_dir.clone(),
            private_key: options.private_key.clone(),
            alice_private_key: options.alice_private_key.clone(),
            bob_private_key: options.bob_private_key.clone(),
            factory_out_point,
            update_number: None,
            state_root: None,
            access_manifest_root: None,
            non_interference_digest: None,
            factory_state_package: Some(latest_package.path.clone()),
            fee: options.fee,
            mine_blocks: options.mine_blocks,
        },
    )?;
    let exit = factory_exit_channel(
        rpc,
        FactoryExitChannelOptions {
            contracts_dir: options.contracts_dir.clone(),
            private_key: options.private_key.clone(),
            alice_private_key: options.alice_private_key.clone(),
            bob_private_key: options.bob_private_key.clone(),
            factory_out_point: printable_out_point_string(&update.factory_out_point),
            factory_vault_out_point,
            update_number: None,
            vault_capacity: options.child_vault_capacity,
            alice_capacity: options.alice_capacity,
            bob_capacity: options.bob_capacity,
            alice_xudt_amount: Some(options.alice_xudt_amount),
            bob_xudt_amount: Some(options.bob_xudt_amount),
            sponsor_capacity: options.sponsor_capacity,
            fee: options.fee,
            finalise_since: options.finalise_since,
            mine_blocks: options.mine_blocks,
            tamper: FactoryExitChannelTamper::None,
        },
    )?;
    let publish = publish_state(
        rpc,
        PublishStateOptions {
            contracts_dir: options.contracts_dir.clone(),
            private_key: options.private_key.clone(),
            alice_private_key: options.alice_private_key.clone(),
            bob_private_key: options.bob_private_key.clone(),
            state_out_point: printable_out_point_string(&exit.state_out_point),
            sponsor_out_point: printable_out_point_string(&exit.sponsor_out_point),
            state_number: Some(1),
            state_package: None,
            fee: options.fee,
            mine_blocks: options.mine_blocks,
        },
    )?;
    let finalise_options = XudtSmokeOptions {
        contracts_dir: options.contracts_dir,
        private_key: options.private_key,
        alice_private_key: options.alice_private_key,
        bob_private_key: options.bob_private_key,
        vault_capacity: options.child_vault_capacity,
        alice_capacity: options.alice_capacity,
        bob_capacity: options.bob_capacity,
        alice_xudt_amount: options.alice_xudt_amount,
        bob_xudt_amount: options.bob_xudt_amount,
        sponsor_capacity: options.sponsor_capacity,
        fee: options.fee,
        finalise_since: options.finalise_since,
        mine_blocks: options.mine_blocks,
    };
    let finalise = finalise_xudt_channel(
        rpc,
        &finalise_options,
        printable_out_point_string(&publish.state_out_point),
        printable_out_point_string(&exit.vault_out_point),
    )?;

    Ok(FactoryXudtSmokeReport {
        open,
        package,
        latest_package,
        update,
        exit,
        publish,
        finalise,
    })
}

pub fn factory_xudt_negative_smoke(
    rpc: &CkbRpcClient,
    options: FactoryXudtNegativeSmokeOptions,
) -> Result<FactoryXudtNegativeSmokeReport> {
    let total_xudt_amount = options
        .alice_xudt_amount
        .checked_add(options.bob_xudt_amount)
        .ok_or_else(|| anyhow!("factory xUDT amount overflow"))?;
    ensure!(
        total_xudt_amount > 0,
        "factory xUDT amount must be non-zero"
    );
    ensure!(
        total_xudt_amount > 1,
        "factory xUDT negative smoke needs at least two units"
    );

    let open = open_factory(
        rpc,
        OpenFactoryOptions {
            contracts_dir: options.contracts_dir.clone(),
            private_key: options.private_key.clone(),
            alice_private_key: options.alice_private_key.clone(),
            bob_private_key: options.bob_private_key.clone(),
            factory_capacity: options.factory_capacity,
            factory_vault_capacity: options.factory_vault_capacity,
            factory_vault_xudt_amount: Some(total_xudt_amount),
            state_root: None,
            access_manifest_root: None,
            non_interference_digest: None,
            fee: options.fee,
            mine_blocks: options.mine_blocks,
        },
    )?;
    let factory_out_point = factory_cell_out_point(&open, "factory")?;
    let factory_vault_out_point = factory_cell_out_point(&open, "factory-vault")?;
    let package = save_factory_state_package(
        rpc,
        SaveFactoryStatePackageOptions {
            alice_private_key: options.alice_private_key.clone(),
            bob_private_key: options.bob_private_key.clone(),
            factory_out_point: factory_out_point.clone(),
            update_number: None,
            state_root: None,
            access_manifest_root: None,
            non_interference_digest: None,
            store_dir: options.store_dir.clone(),
        },
    )?;
    let latest_package = latest_factory_state_cell_package(&options.store_dir, &open.factory_id)?;
    let update = update_factory(
        rpc,
        UpdateFactoryOptions {
            contracts_dir: options.contracts_dir.clone(),
            private_key: options.private_key.clone(),
            alice_private_key: options.alice_private_key.clone(),
            bob_private_key: options.bob_private_key.clone(),
            factory_out_point,
            update_number: None,
            state_root: None,
            access_manifest_root: None,
            non_interference_digest: None,
            factory_state_package: Some(latest_package.path.clone()),
            fee: options.fee,
            mine_blocks: options.mine_blocks,
        },
    )?;

    let live_factory_out_point = printable_out_point_string(&update.factory_out_point);
    let rejected_child_xudt_amount = total_xudt_amount
        .checked_sub(1)
        .ok_or_else(|| anyhow!("factory xUDT negative smoke underflow"))?;
    let rejection = match factory_exit_channel(
        rpc,
        FactoryExitChannelOptions {
            contracts_dir: options.contracts_dir.clone(),
            private_key: options.private_key.clone(),
            alice_private_key: options.alice_private_key.clone(),
            bob_private_key: options.bob_private_key.clone(),
            factory_out_point: live_factory_out_point.clone(),
            factory_vault_out_point: factory_vault_out_point.clone(),
            update_number: None,
            vault_capacity: options.child_vault_capacity,
            alice_capacity: options.alice_capacity,
            bob_capacity: options.bob_capacity,
            alice_xudt_amount: Some(options.alice_xudt_amount),
            bob_xudt_amount: Some(options.bob_xudt_amount),
            sponsor_capacity: options.sponsor_capacity,
            fee: options.fee,
            finalise_since: options.finalise_since,
            mine_blocks: 0,
            tamper: FactoryExitChannelTamper::ChildXudtAmountMinusOnePreserveFactoryChange,
        },
    ) {
        Ok(report) => {
            return Err(anyhow!(
                "factory xUDT local exit unexpectedly accepted tampered child vault amount in tx {}",
                report.tx_hash
            ));
        }
        Err(err) => err.to_string(),
    };
    let script_failure = parse_script_failure(&rejection);
    ensure!(
        script_failure.error_code == Some(ScriptError::SettlementOutputMismatch as i16),
        "expected SettlementOutputMismatch from factory xUDT local exit, got {:?}: {}",
        script_failure.error_code,
        rejection
    );

    let exit = factory_exit_channel(
        rpc,
        FactoryExitChannelOptions {
            contracts_dir: options.contracts_dir.clone(),
            private_key: options.private_key.clone(),
            alice_private_key: options.alice_private_key.clone(),
            bob_private_key: options.bob_private_key.clone(),
            factory_out_point: live_factory_out_point,
            factory_vault_out_point,
            update_number: None,
            vault_capacity: options.child_vault_capacity,
            alice_capacity: options.alice_capacity,
            bob_capacity: options.bob_capacity,
            alice_xudt_amount: Some(options.alice_xudt_amount),
            bob_xudt_amount: Some(options.bob_xudt_amount),
            sponsor_capacity: options.sponsor_capacity,
            fee: options.fee,
            finalise_since: options.finalise_since,
            mine_blocks: options.mine_blocks,
            tamper: FactoryExitChannelTamper::None,
        },
    )?;
    let publish = publish_state(
        rpc,
        PublishStateOptions {
            contracts_dir: options.contracts_dir.clone(),
            private_key: options.private_key.clone(),
            alice_private_key: options.alice_private_key.clone(),
            bob_private_key: options.bob_private_key.clone(),
            state_out_point: printable_out_point_string(&exit.state_out_point),
            sponsor_out_point: printable_out_point_string(&exit.sponsor_out_point),
            state_number: Some(1),
            state_package: None,
            fee: options.fee,
            mine_blocks: options.mine_blocks,
        },
    )?;
    let finalise_options = XudtSmokeOptions {
        contracts_dir: options.contracts_dir,
        private_key: options.private_key,
        alice_private_key: options.alice_private_key,
        bob_private_key: options.bob_private_key,
        vault_capacity: options.child_vault_capacity,
        alice_capacity: options.alice_capacity,
        bob_capacity: options.bob_capacity,
        alice_xudt_amount: options.alice_xudt_amount,
        bob_xudt_amount: options.bob_xudt_amount,
        sponsor_capacity: options.sponsor_capacity,
        fee: options.fee,
        finalise_since: options.finalise_since,
        mine_blocks: options.mine_blocks,
    };
    let finalise = finalise_xudt_channel(
        rpc,
        &finalise_options,
        printable_out_point_string(&publish.state_out_point),
        printable_out_point_string(&exit.vault_out_point),
    )?;

    Ok(FactoryXudtNegativeSmokeReport {
        open,
        package,
        latest_package,
        update,
        expected_child_xudt_amount: total_xudt_amount,
        rejected_child_xudt_amount,
        rejection,
        script_failure,
        exit,
        publish,
        finalise,
    })
}

pub fn factory_exit_channel(
    rpc: &CkbRpcClient,
    options: FactoryExitChannelOptions,
) -> Result<FactoryExitChannelReport> {
    ensure!(options.fee > 0, "fee must be non-zero");
    ensure!(
        options.vault_capacity > 0,
        "child channel vault capacity must be non-zero"
    );
    ensure!(
        options.sponsor_capacity > 0,
        "child channel sponsor capacity must be non-zero"
    );

    let owner_key = parse_privkey(&options.private_key)
        .with_context(|| "invalid secp256k1 private key for factory exit")?;
    let alice_key = parse_privkey(&options.alice_private_key)
        .with_context(|| "invalid Alice channel private key")?;
    let bob_key = parse_privkey(&options.bob_private_key)
        .with_context(|| "invalid Bob channel private key")?;
    let owner_lock = secp256k1_lock(&owner_key)?;
    let alice_lock = secp256k1_lock(&alice_key)?;
    let bob_lock = secp256k1_lock(&bob_key)?;

    let factory_out_point = parse_out_point(&options.factory_out_point)?;
    let factory_vault_out_point = parse_out_point(&options.factory_vault_out_point)?;
    let factory_cell = load_live_cell(rpc, factory_out_point.clone())?;
    let factory_vault_cell = load_live_cell(rpc, factory_vault_out_point.clone())?;
    ensure!(
        factory_cell.output.lock() == owner_lock,
        "private key does not control the FactoryStateCell lock"
    );
    let factory_type = factory_cell
        .output
        .type_()
        .to_opt()
        .ok_or_else(|| anyhow!("factory cell has no type script"))?;
    let old_header = FactoryStateHeaderV1::parse(factory_cell.data.as_ref()).map_err(|err| {
        anyhow!("factory cell does not contain a valid FactoryStateHeader: {err:?}")
    })?;
    ensure!(
        factory_type.args().raw_data().as_ref() == old_header.factory_id(),
        "factory type args do not match the factory id in cell data"
    );
    let old_update_number = old_header.update_number();
    let new_update_number = options
        .update_number
        .unwrap_or_else(|| old_update_number.saturating_add(1));
    ensure!(
        new_update_number > old_update_number,
        "new update number must be greater than old update number {}",
        old_update_number
    );

    let tip_number = rpc.tip_header()?.number_value()?;
    let genesis = rpc
        .block_by_number(0)?
        .ok_or_else(|| anyhow!("genesis block is not available from CKB RPC"))?;
    let chain_id = genesis.header.hash.0;
    let secp_dep = find_secp256k1_cell_dep(rpc)?;
    let contracts = find_deployed_contracts(rpc, &options.contracts_dir, tip_number)?;
    let state_lock_contract = contract_by_name(&contracts, "morph-state-lock")?;
    let state_contract = contract_by_name(&contracts, "morph-state-type")?;
    let factory_contract = contract_by_name(&contracts, "morph-factory-type")?;
    let factory_vault_contract = contract_by_name(&contracts, "morph-factory-vault-lock")?;
    let vault_contract = contract_by_name(&contracts, "morph-vault-lock")?;
    let sponsor_contract = contract_by_name(&contracts, "morph-sponsor-lock")?;
    ensure!(
        byte32_to_h256(factory_type.code_hash()) == factory_contract.data_hash,
        "factory cell type script does not use the deployed morph-factory-type code hash"
    );
    let factory_type_hash: [u8; BYTE32_LEN] = factory_type.calc_script_hash().unpack();
    let factory_vault_lock = factory_vault_cell.output.lock();
    ensure!(
        byte32_to_h256(factory_vault_lock.code_hash()) == factory_vault_contract.data_hash,
        "factory vault cell lock does not use the deployed morph-factory-vault-lock code hash"
    );
    let factory_vault_args = factory_vault_lock.args().raw_data();
    ensure!(
        factory_vault_args.len() == 2 * BYTE32_LEN,
        "factory vault lock args must be 64 bytes"
    );
    ensure!(
        &factory_vault_args.as_ref()[..BYTE32_LEN] == old_header.factory_id(),
        "factory vault lock is for a different factory id"
    );
    ensure!(
        &factory_vault_args.as_ref()[BYTE32_LEN..2 * BYTE32_LEN] == factory_type_hash.as_slice(),
        "factory vault lock is for a different factory type hash"
    );
    let factory_vault_type = factory_vault_cell.output.type_().to_opt();
    let factory_vault_xudt_amount = if factory_vault_type.is_some() {
        Some(xudt_amount_from_data(&factory_vault_cell.data)?)
    } else {
        ensure!(
            factory_vault_cell.data.is_empty(),
            "plain factory vault cell must not carry data"
        );
        None
    };
    let child_xudt = match factory_vault_xudt_amount {
        Some(total_amount) => {
            let alice_amount = options.alice_xudt_amount.ok_or_else(|| {
                anyhow!("--alice-xudt-amount is required when the FactoryVaultCell carries xUDT")
            })?;
            let bob_amount = options.bob_xudt_amount.ok_or_else(|| {
                anyhow!("--bob-xudt-amount is required when the FactoryVaultCell carries xUDT")
            })?;
            let child_amount = alice_amount
                .checked_add(bob_amount)
                .ok_or_else(|| anyhow!("child xUDT amount overflow"))?;
            ensure!(child_amount > 0, "child xUDT amount must be non-zero");
            ensure!(
                child_amount <= total_amount,
                "child xUDT amount {} exceeds factory vault amount {}",
                child_amount,
                total_amount
            );
            let xudt_type = factory_vault_type
                .clone()
                .ok_or_else(|| anyhow!("factory vault xUDT type script missing"))?;
            let xudt_type_hash: [u8; BYTE32_LEN] = xudt_type.calc_script_hash().unpack();
            Some((
                xudt_type,
                xudt_type_hash,
                total_amount,
                alice_amount,
                bob_amount,
                child_amount,
            ))
        }
        None => {
            ensure!(
                options.alice_xudt_amount.is_none() && options.bob_xudt_amount.is_none(),
                "xUDT settlement amounts require a typed FactoryVaultCell"
            );
            None
        }
    };
    let xudt_contract = if child_xudt.is_some() {
        Some(contract_by_name(&contracts, "morph-devnet-xudt")?)
    } else {
        None
    };

    let state_output_index = 1u32;
    let vault_output_index = 2u32;
    let channel_input = CellInput::new(factory_out_point.clone(), 0);
    let funding_anchor = derive_funding_anchor(&channel_input, state_output_index as u64);
    let channel_id = script_blake2b256(&[b"CKB_MORPH_CHANNEL_ID_V1", &funding_anchor]);

    let mut state_args = funding_anchor.to_vec();
    state_args.extend_from_slice(&options.finalise_since.to_le_bytes());
    let state_type = data1_script(state_contract.data_hash.clone(), Bytes::from(state_args));
    let state_type_hash: [u8; BYTE32_LEN] = state_type.calc_script_hash().unpack();
    let state_lock = data1_script(
        state_lock_contract.data_hash.clone(),
        Bytes::copy_from_slice(&state_type_hash),
    );
    let state_lock_hash: [u8; BYTE32_LEN] = state_lock.calc_script_hash().unpack();
    let mut vault_args = funding_anchor.to_vec();
    vault_args.extend_from_slice(&options.finalise_since.to_le_bytes());
    let vault_lock = data1_script(vault_contract.data_hash.clone(), Bytes::from(vault_args));
    let vault_lock_hash: [u8; BYTE32_LEN] = vault_lock.calc_script_hash().unpack();

    let owner_lock_hash = owner_lock.calc_script_hash();
    let sponsor_policy_settings =
        sponsor_policy_settings(options.sponsor_capacity, 0, u64::MAX, None, None)?;
    let sponsor_policy = sponsor_policy_bytes(
        &channel_id,
        sponsor_policy_settings,
        state_type_hash,
        owner_lock_hash.as_slice().try_into().unwrap(),
    );
    let sponsor_lock = data1_script(
        sponsor_contract.data_hash.clone(),
        Bytes::copy_from_slice(&sponsor_policy),
    );

    let alice_lock_hash: [u8; BYTE32_LEN] = alice_lock.calc_script_hash().unpack();
    let bob_lock_hash: [u8; BYTE32_LEN] = bob_lock.calc_script_hash().unpack();
    let (alice_capacity, bob_capacity) = settlement_split(
        options.vault_capacity,
        options.alice_capacity,
        options.bob_capacity,
    )?;
    let descriptor;
    let descriptor_version;
    if let Some((xudt_type, xudt_type_hash, _, alice_amount, bob_amount, _)) = &child_xudt {
        ensure_output_capacity(
            "alice xUDT settlement",
            &CellOutput::new_builder()
                .capacity(alice_capacity)
                .lock(alice_lock.clone())
                .type_(Some(xudt_type.clone()).pack())
                .build(),
            16,
        )?;
        ensure_output_capacity(
            "bob xUDT settlement",
            &CellOutput::new_builder()
                .capacity(bob_capacity)
                .lock(bob_lock.clone())
                .type_(Some(xudt_type.clone()).pack())
                .build(),
            16,
        )?;
        descriptor = bilateral_ckb_xudt_descriptor(
            *xudt_type_hash,
            alice_lock_hash,
            alice_capacity,
            *alice_amount,
            bob_lock_hash,
            bob_capacity,
            *bob_amount,
        )
        .to_vec();
        descriptor_version = BILATERAL_CKB_XUDT_DESCRIPTOR_VERSION_V1;
    } else {
        ensure_output_capacity(
            "alice settlement",
            &CellOutput::new_builder()
                .capacity(alice_capacity)
                .lock(alice_lock.clone())
                .build(),
            0,
        )?;
        ensure_output_capacity(
            "bob settlement",
            &CellOutput::new_builder()
                .capacity(bob_capacity)
                .lock(bob_lock.clone())
                .build(),
            0,
        )?;
        descriptor =
            bilateral_ckb_descriptor(alice_lock_hash, alice_capacity, bob_lock_hash, bob_capacity)
                .to_vec();
        descriptor_version = BILATERAL_CKB_DESCRIPTOR_VERSION_V1;
    }
    let descriptor_commitment = settlement_descriptor_commitment_v1(&descriptor);

    let alice_pubkey = compressed_pubkey(&alice_key)?;
    let bob_pubkey = compressed_pubkey(&bob_key)?;
    let mut participant_pubkeys = [alice_pubkey, bob_pubkey];
    participant_pubkeys.sort();
    let participants_commitment =
        participants_commitment_v1(2, &[&participant_pubkeys[0], &participant_pubkeys[1]]);
    let challenge_policy_commitment = script_blake2b256(&[
        b"CKB_MORPH_CHALLENGE_POLICY_V1",
        &options.finalise_since.to_le_bytes(),
    ]);
    let state_header = initial_state_header(InitialStateHeader {
        chain_id,
        channel_id,
        funding_anchor,
        participants_commitment,
        settlement_descriptor_commitment: descriptor_commitment,
        descriptor_version,
        challenge_policy_commitment,
    });

    let state_output_for_capacity = CellOutput::new_builder()
        .lock(state_lock.clone())
        .type_(Some(state_type.clone()).pack())
        .build();
    let state_capacity = occupied_capacity(&state_output_for_capacity, state_header.len())?;
    let state_output = CellOutput::new_builder()
        .capacity(state_capacity)
        .lock(state_lock)
        .type_(Some(state_type).pack())
        .build();
    let child_vault_type = child_xudt
        .as_ref()
        .map(|(xudt_type, _, _, _, _, _)| xudt_type.clone());
    let child_vault_xudt_amount = match (&child_xudt, options.tamper) {
        (
            Some((_, _, _, _, _, child_amount)),
            FactoryExitChannelTamper::ChildXudtAmountMinusOnePreserveFactoryChange,
        ) => {
            let tampered_amount = child_amount
                .checked_sub(1)
                .ok_or_else(|| anyhow!("tampered child xUDT amount underflow"))?;
            ensure!(
                tampered_amount > 0,
                "tampered child xUDT amount must remain non-zero"
            );
            Some(tampered_amount)
        }
        (Some((_, _, _, _, _, child_amount)), FactoryExitChannelTamper::None) => {
            Some(*child_amount)
        }
        (None, FactoryExitChannelTamper::None) => None,
        (None, FactoryExitChannelTamper::ChildXudtAmountMinusOnePreserveFactoryChange) => {
            return Err(anyhow!(
                "factory exit xUDT tamper requires a typed FactoryVaultCell"
            ));
        }
    };
    let child_vault_data = child_xudt
        .as_ref()
        .map(|_| xudt_amount_bytes(child_vault_xudt_amount.expect("child xUDT amount present")))
        .unwrap_or_default();
    let vault_output = CellOutput::new_builder()
        .capacity(options.vault_capacity)
        .lock(vault_lock)
        .type_(child_vault_type.pack())
        .build();
    ensure_output_capacity("child vault", &vault_output, child_vault_data.len())?;
    let sponsor_output = CellOutput::new_builder()
        .capacity(options.sponsor_capacity)
        .lock(sponsor_lock)
        .build();
    ensure_output_capacity("child sponsor", &sponsor_output, 0)?;

    let factory_vault_change_capacity = factory_vault_cell
        .capacity
        .checked_sub(options.vault_capacity)
        .ok_or_else(|| {
            anyhow!(
                "factory vault capacity {} cannot release child vault capacity {}",
                factory_vault_cell.capacity,
                options.vault_capacity
            )
        })?;
    let factory_vault_change_xudt_amount =
        child_xudt.as_ref().map(|(_, _, total_amount, _, _, _)| {
            total_amount - child_vault_xudt_amount.expect("child xUDT amount present")
        });
    let factory_vault_change_type = match (&factory_vault_type, factory_vault_change_xudt_amount) {
        (Some(xudt_type), Some(amount)) if amount > 0 => Some(xudt_type.clone()),
        _ => None,
    };
    let factory_vault_change_data = factory_vault_change_xudt_amount
        .filter(|amount| *amount > 0)
        .map(xudt_amount_bytes)
        .unwrap_or_default();
    let factory_vault_change_output = CellOutput::new_builder()
        .capacity(factory_vault_change_capacity)
        .lock(factory_vault_lock.clone())
        .type_(factory_vault_change_type.pack())
        .build();
    ensure_output_capacity(
        "factory vault change",
        &factory_vault_change_output,
        factory_vault_change_data.len(),
    )?;

    ensure_output_capacity("factory", &factory_cell.output, FACTORY_STATE_HEADER_V1_LEN)?;
    let exit_digest = factory_local_exit_digest_v1(
        state_output_index,
        vault_output_index,
        &state_type_hash,
        &vault_lock_hash,
        &state_lock_hash,
        &state_header,
        &descriptor,
    );
    let state_root = derived_factory_update_digest(
        b"CKB_MORPH_FACTORY_STATE_ROOT_EXIT_V1",
        old_header.state_root(),
        new_update_number,
    );
    let access_manifest_root = derived_factory_update_digest(
        b"CKB_MORPH_FACTORY_ACCESS_MANIFEST_EXIT_V1",
        old_header.access_manifest_root(),
        new_update_number,
    );
    let mut new_factory_data = factory_cell.data.to_vec();
    put_u64(&mut new_factory_data, 68, new_update_number);
    new_factory_data[76..108].copy_from_slice(&state_root);
    new_factory_data[140..172].copy_from_slice(&access_manifest_root);
    new_factory_data[172..204].copy_from_slice(&exit_digest);
    let factory_signature = factory_signature_witness(
        &new_factory_data,
        &options.alice_private_key,
        &options.bob_private_key,
    )?;
    let local_exit_witness = factory_local_exit_witness(
        &factory_signature,
        state_output_index,
        vault_output_index,
        &state_type_hash,
        &vault_lock_hash,
        &state_lock_hash,
        &state_header,
        &descriptor,
    )?;
    let local_exit_package = StoredFactoryLocalExitPackage::from_factory_local_exit(
        &new_factory_data,
        &local_exit_witness,
    )
    .context("constructed factory local-exit package is invalid")?;

    let fee_cell = find_largest_live_cell(rpc, &owner_lock, tip_number)?;
    ensure!(
        fee_cell.out_point != factory_out_point,
        "fee input cannot be the FactoryStateCell itself"
    );
    ensure!(
        fee_cell.out_point != factory_vault_out_point,
        "fee input cannot be the FactoryVaultCell itself"
    );
    let fixed_fee_cell_capacity = state_capacity
        .checked_add(options.sponsor_capacity)
        .and_then(|value| value.checked_add(options.fee))
        .ok_or_else(|| anyhow!("factory exit fee-side output capacity overflow"))?;
    let fee_change_capacity = fee_cell
        .capacity
        .checked_sub(fixed_fee_cell_capacity)
        .ok_or_else(|| {
            anyhow!(
                "fee input capacity {} cannot cover state {}, sponsor {}, and fee {}",
                fee_cell.capacity,
                state_capacity,
                options.sponsor_capacity,
                options.fee
            )
        })?;
    ensure_change_capacity(&owner_lock, fee_change_capacity)?;
    let fee_change_output = CellOutput::new_builder()
        .capacity(fee_change_capacity)
        .lock(owner_lock)
        .build();

    let mut builder = TransactionBuilder::default()
        .cell_dep(secp_dep)
        .cell_dep(state_lock_contract.cell_dep)
        .cell_dep(state_contract.cell_dep)
        .cell_dep(factory_contract.cell_dep)
        .cell_dep(factory_vault_contract.cell_dep)
        .cell_dep(vault_contract.cell_dep)
        .cell_dep(sponsor_contract.cell_dep);
    if let Some(contract) = xudt_contract {
        builder = builder.cell_dep(contract.cell_dep);
    }
    let unsigned = builder
        .input(channel_input)
        .input(CellInput::new(factory_vault_out_point.clone(), 0))
        .input(CellInput::new(fee_cell.out_point.clone(), 0))
        .output(factory_cell.output.clone())
        .output(state_output.clone())
        .output(vault_output.clone())
        .output(factory_vault_change_output.clone())
        .output(sponsor_output.clone())
        .output(fee_change_output)
        .output_data(Bytes::from(new_factory_data).pack())
        .output_data(Bytes::copy_from_slice(&state_header).pack())
        .output_data(child_vault_data.pack())
        .output_data(factory_vault_change_data.pack())
        .output_data(Bytes::new().pack())
        .output_data(Bytes::new().pack())
        .build();
    let signed = sign_factory_exit_transaction(
        unsigned,
        &owner_key,
        Bytes::copy_from_slice(&local_exit_witness),
    )?;
    let sent = send_and_mine(rpc, signed, options.mine_blocks)?;
    let tx_hash = sent.tx_hash.clone();

    Ok(FactoryExitChannelReport {
        tx_hash: sent.tx_hash,
        status: sent.status,
        block_number: sent.block_number,
        block_hash: sent.block_hash,
        factory_id: hex32(old_header.factory_id()),
        old_update_number,
        new_update_number,
        channel_id: hex32(&channel_id),
        funding_anchor: hex32(&funding_anchor),
        finalise_since: options.finalise_since,
        factory_out_point: PrintableOutPoint {
            tx_hash: tx_hash.clone(),
            index: 0,
        },
        state_out_point: PrintableOutPoint {
            tx_hash: tx_hash.clone(),
            index: state_output_index,
        },
        vault_out_point: PrintableOutPoint {
            tx_hash: tx_hash.clone(),
            index: vault_output_index,
        },
        factory_vault_out_point: PrintableOutPoint {
            tx_hash: tx_hash.clone(),
            index: 3,
        },
        sponsor_out_point: PrintableOutPoint { tx_hash, index: 4 },
        state_capacity,
        vault_capacity: options.vault_capacity,
        child_xudt_amount: child_xudt
            .as_ref()
            .map(|(_, _, _, _, _, child_amount)| *child_amount),
        factory_vault_input_capacity: factory_vault_cell.capacity,
        factory_vault_change_capacity,
        factory_vault_input_xudt_amount: factory_vault_xudt_amount,
        factory_vault_change_xudt_amount,
        xudt_type_hash: child_xudt
            .as_ref()
            .map(|(_, xudt_type_hash, _, _, _, _)| hex32(xudt_type_hash)),
        local_exit_package,
        sponsor_capacity: options.sponsor_capacity,
        fee_change_capacity,
        fee: options.fee,
        metrics: sent.metrics,
        mined_blocks: sent.mined_blocks,
        participants: vec![
            ParticipantReport {
                role: "alice".to_string(),
                lock_hash: hex32(&alice_lock_hash),
                pubkey_sec1: hex_prefixed(&alice_pubkey),
                capacity: alice_capacity,
            },
            ParticipantReport {
                role: "bob".to_string(),
                lock_hash: hex32(&bob_lock_hash),
                pubkey_sec1: hex_prefixed(&bob_pubkey),
                capacity: bob_capacity,
            },
        ],
    })
}

fn open_xudt_channel(rpc: &CkbRpcClient, options: &XudtSmokeOptions) -> Result<OpenChannelReport> {
    ensure!(options.fee > 0, "fee must be non-zero");
    ensure!(
        options.vault_capacity > 0,
        "vault capacity must be non-zero"
    );
    ensure!(
        options.sponsor_capacity > 0,
        "sponsor capacity must be non-zero"
    );
    let total_xudt_amount = options
        .alice_xudt_amount
        .checked_add(options.bob_xudt_amount)
        .ok_or_else(|| anyhow!("xUDT amount overflow"))?;
    ensure!(total_xudt_amount > 0, "xUDT amount must be non-zero");

    let owner_key = parse_privkey(&options.private_key)
        .with_context(|| "invalid secp256k1 private key for devnet xUDT channel opener")?;
    let alice_key = parse_privkey(&options.alice_private_key)
        .with_context(|| "invalid Alice channel private key")?;
    let bob_key = parse_privkey(&options.bob_private_key)
        .with_context(|| "invalid Bob channel private key")?;

    let owner_lock = secp256k1_lock(&owner_key)?;
    let alice_lock = secp256k1_lock(&alice_key)?;
    let bob_lock = secp256k1_lock(&bob_key)?;
    let tip = rpc.tip_header()?;
    let tip_number = tip.number_value()?;
    let genesis = rpc
        .block_by_number(0)?
        .ok_or_else(|| anyhow!("genesis block is not available from CKB RPC"))?;
    let chain_id = genesis.header.hash.0;
    let funding_cell = find_largest_live_cell(rpc, &owner_lock, tip_number)?;
    let secp_dep = find_secp256k1_cell_dep(rpc)?;
    let contracts = find_deployed_contracts(rpc, &options.contracts_dir, tip_number)?;
    let state_lock_contract = contract_by_name(&contracts, "morph-state-lock")?;
    let state_contract = contract_by_name(&contracts, "morph-state-type")?;
    let vault_contract = contract_by_name(&contracts, "morph-vault-lock")?;
    let sponsor_contract = contract_by_name(&contracts, "morph-sponsor-lock")?;
    let xudt_contract = contract_by_name(&contracts, "morph-devnet-xudt")?;

    let channel_input = CellInput::new(funding_cell.out_point.clone(), 0);
    let funding_anchor = derive_funding_anchor(&channel_input, 0);
    let channel_id = script_blake2b256(&[b"CKB_MORPH_CHANNEL_ID_V1", &funding_anchor]);

    let mut script_args = funding_anchor.to_vec();
    script_args.extend_from_slice(&options.finalise_since.to_le_bytes());
    let state_type = data1_script(state_contract.data_hash.clone(), Bytes::from(script_args));
    let state_lock = data1_script(
        state_lock_contract.data_hash.clone(),
        Bytes::copy_from_slice(state_type.calc_script_hash().as_slice()),
    );

    let mut vault_args = funding_anchor.to_vec();
    vault_args.extend_from_slice(&options.finalise_since.to_le_bytes());
    let vault_lock = data1_script(vault_contract.data_hash.clone(), Bytes::from(vault_args));

    let owner_lock_hash = owner_lock.calc_script_hash();
    let xudt_type = data1_script(
        xudt_contract.data_hash.clone(),
        Bytes::copy_from_slice(owner_lock_hash.as_slice()),
    );
    let xudt_type_hash: [u8; 32] = xudt_type.calc_script_hash().unpack();

    let sponsor_policy_settings =
        sponsor_policy_settings(options.sponsor_capacity, 0, u64::MAX, None, None)?;
    let sponsor_policy = sponsor_policy_bytes(
        &channel_id,
        sponsor_policy_settings,
        state_type.calc_script_hash().unpack(),
        owner_lock_hash.as_slice().try_into().unwrap(),
    );
    let sponsor_lock = data1_script(
        sponsor_contract.data_hash.clone(),
        Bytes::copy_from_slice(&sponsor_policy),
    );

    let alice_lock_hash: [u8; 32] = alice_lock.calc_script_hash().unpack();
    let bob_lock_hash: [u8; 32] = bob_lock.calc_script_hash().unpack();
    let (alice_capacity, bob_capacity) = settlement_split(
        options.vault_capacity,
        options.alice_capacity,
        options.bob_capacity,
    )?;
    ensure_output_capacity(
        "alice xUDT settlement",
        &CellOutput::new_builder()
            .capacity(alice_capacity)
            .lock(alice_lock.clone())
            .type_(Some(xudt_type.clone()).pack())
            .build(),
        16,
    )?;
    ensure_output_capacity(
        "bob xUDT settlement",
        &CellOutput::new_builder()
            .capacity(bob_capacity)
            .lock(bob_lock.clone())
            .type_(Some(xudt_type.clone()).pack())
            .build(),
        16,
    )?;
    let descriptor = bilateral_ckb_xudt_descriptor(
        xudt_type_hash,
        alice_lock_hash,
        alice_capacity,
        options.alice_xudt_amount,
        bob_lock_hash,
        bob_capacity,
        options.bob_xudt_amount,
    );
    let descriptor_commitment = settlement_descriptor_commitment_v1(&descriptor);

    let alice_pubkey = compressed_pubkey(&alice_key)?;
    let bob_pubkey = compressed_pubkey(&bob_key)?;
    let mut participant_pubkeys = [alice_pubkey, bob_pubkey];
    participant_pubkeys.sort();
    let participants_commitment =
        participants_commitment_v1(2, &[&participant_pubkeys[0], &participant_pubkeys[1]]);
    let challenge_policy_commitment = script_blake2b256(&[
        b"CKB_MORPH_CHALLENGE_POLICY_V1",
        &options.finalise_since.to_le_bytes(),
    ]);
    let state_header = initial_state_header(InitialStateHeader {
        chain_id,
        channel_id,
        funding_anchor,
        participants_commitment,
        settlement_descriptor_commitment: descriptor_commitment,
        descriptor_version: BILATERAL_CKB_XUDT_DESCRIPTOR_VERSION_V1,
        challenge_policy_commitment,
    });

    let state_output_for_capacity = CellOutput::new_builder()
        .lock(state_lock.clone())
        .type_(Some(state_type.clone()).pack())
        .build();
    let state_capacity = occupied_capacity(&state_output_for_capacity, state_header.len())?;
    let state_output = CellOutput::new_builder()
        .capacity(state_capacity)
        .lock(state_lock.clone())
        .type_(Some(state_type.clone()).pack())
        .build();

    let vault_output = CellOutput::new_builder()
        .capacity(options.vault_capacity)
        .lock(vault_lock)
        .type_(Some(xudt_type).pack())
        .build();
    ensure_output_capacity("xUDT vault", &vault_output, 16)?;

    let sponsor_output = CellOutput::new_builder()
        .capacity(options.sponsor_capacity)
        .lock(sponsor_lock)
        .build();
    ensure_output_capacity("sponsor", &sponsor_output, 0)?;

    let fixed_output_capacity = state_capacity
        .checked_add(options.vault_capacity)
        .and_then(|value| value.checked_add(options.sponsor_capacity))
        .ok_or_else(|| anyhow!("channel output capacity overflow"))?;
    let change_capacity = funding_cell
        .capacity
        .checked_sub(fixed_output_capacity)
        .and_then(|value| value.checked_sub(options.fee))
        .ok_or_else(|| {
            anyhow!(
                "funding cell capacity {} cannot cover state {}, vault {}, sponsor {}, and fee {}",
                funding_cell.capacity,
                state_capacity,
                options.vault_capacity,
                options.sponsor_capacity,
                options.fee
            )
        })?;
    ensure_change_capacity(&owner_lock, change_capacity)?;

    let change_output = CellOutput::new_builder()
        .capacity(change_capacity)
        .lock(owner_lock.clone())
        .build();
    let unsigned = TransactionBuilder::default()
        .cell_dep(secp_dep)
        .cell_dep(state_lock_contract.cell_dep.clone())
        .cell_dep(state_contract.cell_dep.clone())
        .cell_dep(vault_contract.cell_dep.clone())
        .cell_dep(sponsor_contract.cell_dep.clone())
        .cell_dep(xudt_contract.cell_dep.clone())
        .input(channel_input)
        .output(state_output.clone())
        .output(vault_output.clone())
        .output(sponsor_output.clone())
        .output(change_output.clone())
        .output_data(Bytes::copy_from_slice(&state_header).pack())
        .output_data(xudt_amount_bytes(total_xudt_amount).pack())
        .output_data(Bytes::new().pack())
        .output_data(Bytes::new().pack())
        .build();
    let signed = sign_single_secp_input(unsigned, &owner_key)?;
    let sent = send_and_mine(rpc, signed, options.mine_blocks)?;

    let tx_hash_string = sent.tx_hash.clone();
    let cell =
        |role: &str, index: u32, output: &CellOutput, data_len: usize| -> ChannelCellReport {
            ChannelCellReport {
                role: role.to_string(),
                out_point: PrintableOutPoint {
                    tx_hash: tx_hash_string.clone(),
                    index,
                },
                capacity: output.capacity().unpack(),
                lock_hash: hex32(output.lock().calc_script_hash().as_slice()),
                type_hash: output
                    .type_()
                    .to_opt()
                    .map(|script| hex32(script.calc_script_hash().as_slice())),
                data_len,
            }
        };

    Ok(OpenChannelReport {
        tx_hash: tx_hash_string.clone(),
        status: sent.status,
        block_number: sent.block_number,
        block_hash: sent.block_hash,
        channel_id: hex32(&channel_id),
        funding_anchor: hex32(&funding_anchor),
        finalise_since: options.finalise_since,
        input_capacity: funding_cell.capacity,
        state_capacity,
        vault_capacity: options.vault_capacity,
        sponsor_capacity: options.sponsor_capacity,
        sponsor_policy: sponsor_policy_report(
            sponsor_policy_settings,
            state_type.calc_script_hash().unpack(),
            owner_lock_hash.as_slice().try_into().unwrap(),
        ),
        change_capacity,
        fee: options.fee,
        metrics: sent.metrics,
        mined_blocks: sent.mined_blocks,
        participants: vec![
            ParticipantReport {
                role: "alice".to_string(),
                lock_hash: hex32(&alice_lock_hash),
                pubkey_sec1: hex_prefixed(&alice_pubkey),
                capacity: alice_capacity,
            },
            ParticipantReport {
                role: "bob".to_string(),
                lock_hash: hex32(&bob_lock_hash),
                pubkey_sec1: hex_prefixed(&bob_pubkey),
                capacity: bob_capacity,
            },
        ],
        scripts: contracts
            .into_iter()
            .map(|contract| ResolvedScriptReport {
                name: contract.name,
                out_point: printable_out_point(&contract.out_point),
                data_hash: format!("{:#x}", contract.data_hash),
                hash_type: "data1".to_string(),
            })
            .collect(),
        cells: vec![
            cell("state", 0, &state_output, state_header.len()),
            cell("xudt-vault", 1, &vault_output, 16),
            cell("sponsor", 2, &sponsor_output, 0),
            cell("change", 3, &change_output, 0),
        ],
    })
}

pub fn publish_state(
    rpc: &CkbRpcClient,
    options: PublishStateOptions,
) -> Result<PublishStateReport> {
    ensure!(options.fee > 0, "fee must be non-zero");

    let owner_key = parse_privkey(&options.private_key)
        .with_context(|| "invalid secp256k1 private key for sponsor change")?;
    let owner_lock = secp256k1_lock(&owner_key)?;
    let state_out_point = parse_out_point(&options.state_out_point)?;
    let sponsor_out_point = parse_out_point(&options.sponsor_out_point)?;
    let state_cell = load_live_cell(rpc, state_out_point.clone())?;
    let sponsor_cell = load_live_cell(rpc, sponsor_out_point.clone())?;
    let old_header = StateHeaderV1::parse(state_cell.data.as_ref())
        .map_err(|err| anyhow!("state cell does not contain a valid Morph StateHeader: {err:?}"))?;
    let new_state_number = options
        .state_number
        .unwrap_or_else(|| old_header.state_number().saturating_add(1));
    ensure!(
        new_state_number > old_header.state_number(),
        "new state number must be greater than old state number {}",
        old_header.state_number()
    );

    let sponsor_args = sponsor_cell.output.lock().args().raw_data();
    ensure!(
        sponsor_args.len() == SPONSOR_POLICY_V1_LEN,
        "sponsor lock args must be {} bytes",
        SPONSOR_POLICY_V1_LEN
    );
    ensure!(
        &sponsor_args[0..32] == old_header.channel_id(),
        "sponsor policy is for a different channel"
    );
    let expected_change_lock = &sponsor_args[112..144];
    ensure!(
        expected_change_lock == owner_lock.calc_script_hash().as_slice(),
        "private key does not control the sponsor change lock"
    );

    let (new_state_data, signature_witness, new_state_number, state_package) =
        if let Some(path) = &options.state_package {
            let package = read_package(path)?;
            let header_bytes = package.header_bytes()?;
            let witness_bytes = package.witness_bytes()?;
            let package_state_number = {
                let package_header = StateHeaderV1::parse(&header_bytes)
                    .map_err(|err| anyhow!("state package header is invalid: {err:?}"))?;
                ensure!(
                    old_header.same_context_except_progress(&package_header),
                    "state package does not match the current channel context"
                );
                ensure!(
                    package_header.state_number() > old_header.state_number(),
                    "state package number {} must be greater than old state number {}",
                    package_header.state_number(),
                    old_header.state_number()
                );
                ensure!(
                    package_header.phase() == PHASE_SETTLING,
                    "state package must publish a settling state"
                );
                package_header.state_number()
            };
            (
                header_bytes,
                witness_bytes,
                package_state_number,
                Some(path.display().to_string()),
            )
        } else {
            let mut new_state_data = state_cell.data.to_vec();
            put_u64(&mut new_state_data, 100, new_state_number);
            new_state_data[109] = PHASE_SETTLING;
            let signature_witness = bilateral_signature_witness(
                &new_state_data,
                &options.alice_private_key,
                &options.bob_private_key,
            )?;
            (
                new_state_data,
                signature_witness.to_vec(),
                new_state_number,
                None,
            )
        };

    let tip_number = rpc.tip_header()?.number_value()?;
    let contracts = find_deployed_contracts(rpc, &options.contracts_dir, tip_number)?;
    let state_lock_contract = contract_by_name(&contracts, "morph-state-lock")?;
    let state_contract = contract_by_name(&contracts, "morph-state-type")?;
    let sponsor_contract = contract_by_name(&contracts, "morph-sponsor-lock")?;

    ensure_output_capacity("state", &state_cell.output, new_state_data.len())?;
    let sponsor_change_capacity = sponsor_cell
        .capacity
        .checked_sub(options.fee)
        .ok_or_else(|| anyhow!("sponsor capacity cannot cover fee {}", options.fee))?;
    ensure_change_capacity(&owner_lock, sponsor_change_capacity)?;

    let tx = TransactionBuilder::default()
        .cell_dep(state_lock_contract.cell_dep)
        .cell_dep(state_contract.cell_dep)
        .cell_dep(sponsor_contract.cell_dep)
        .input(CellInput::new(state_out_point, 0))
        .input(CellInput::new(sponsor_out_point, 0))
        .output(state_cell.output.clone())
        .output(
            CellOutput::new_builder()
                .capacity(sponsor_change_capacity)
                .lock(owner_lock)
                .build(),
        )
        .output_data(Bytes::from(new_state_data).pack())
        .output_data(Bytes::new().pack())
        .witness(witness_with_input_type(Bytes::copy_from_slice(
            &signature_witness,
        )))
        .witness(empty_witness())
        .build();
    let sent_hash = send_and_mine(rpc, tx, options.mine_blocks)?;
    let new_state_tx_hash = sent_hash.tx_hash.clone();

    Ok(PublishStateReport {
        tx_hash: sent_hash.tx_hash,
        status: sent_hash.status,
        block_number: sent_hash.block_number,
        block_hash: sent_hash.block_hash,
        channel_id: hex32(old_header.channel_id()),
        funding_anchor: hex32(old_header.funding_anchor()),
        old_state_number: old_header.state_number(),
        new_state_number,
        state_out_point: PrintableOutPoint {
            tx_hash: new_state_tx_hash,
            index: 0,
        },
        sponsor_change_capacity,
        fee: options.fee,
        state_package,
        metrics: sent_hash.metrics,
        mined_blocks: sent_hash.mined_blocks,
    })
}

pub fn save_state_package(
    rpc: &CkbRpcClient,
    options: SaveStatePackageOptions,
) -> Result<SaveStatePackageReport> {
    let state_out_point = parse_out_point(&options.state_out_point)?;
    let state_cell = load_live_cell(rpc, state_out_point.clone())?;
    let old_header = StateHeaderV1::parse(state_cell.data.as_ref())
        .map_err(|err| anyhow!("state cell does not contain a valid Morph StateHeader: {err:?}"))?;
    let new_state_number = options
        .state_number
        .unwrap_or_else(|| old_header.state_number().saturating_add(1));
    ensure!(
        new_state_number > old_header.state_number(),
        "new state number must be greater than old state number {}",
        old_header.state_number()
    );

    let mut new_state_data = state_cell.data.to_vec();
    put_u64(&mut new_state_data, 100, new_state_number);
    new_state_data[109] = PHASE_SETTLING;
    let signature_witness = bilateral_signature_witness(
        &new_state_data,
        &options.alice_private_key,
        &options.bob_private_key,
    )?;

    let printable = printable_out_point(&state_out_point);
    let package = StoredStatePackage::from_signed_state(
        &new_state_data,
        &signature_witness,
        Some(PackageOutPoint {
            tx_hash: printable.tx_hash,
            index: printable.index,
        }),
    )?;
    let path = write_package(&options.store_dir, &package)?;

    Ok(SaveStatePackageReport {
        path: path.display().to_string(),
        package,
    })
}

pub fn publish_latest_state_package(
    rpc: &CkbRpcClient,
    options: PublishLatestStatePackageOptions,
) -> Result<PublishLatestStatePackageReport> {
    let selected_package = latest_package(&options.store_dir, &options.channel_id)?;
    let publication = publish_state(
        rpc,
        PublishStateOptions {
            contracts_dir: options.contracts_dir,
            private_key: options.private_key,
            alice_private_key: DEFAULT_ALICE_PRIVATE_KEY.to_string(),
            bob_private_key: DEFAULT_BOB_PRIVATE_KEY.to_string(),
            state_out_point: options.state_out_point,
            sponsor_out_point: options.sponsor_out_point,
            state_number: None,
            state_package: Some(selected_package.path.clone()),
            fee: options.fee,
            mine_blocks: options.mine_blocks,
        },
    )?;
    Ok(PublishLatestStatePackageReport {
        selected_package,
        publication,
    })
}

pub fn watch_latest_state_package(
    rpc: &CkbRpcClient,
    options: WatchLatestStatePackageOptions,
) -> Result<WatchLatestStatePackageReport> {
    ensure!(
        options.detection_depth > 0,
        "detection depth must be at least one block"
    );
    ensure!(
        options.sponsor_out_point.is_some() || options.auto_fund_sponsor,
        "watch-latest-package requires --sponsor-out-point unless --auto-fund-sponsor is set"
    );
    ensure!(
        options.sponsor_out_point.is_none() || !options.auto_fund_sponsor,
        "pass either --sponsor-out-point or --auto-fund-sponsor, not both"
    );
    ensure!(
        !options.auto_fund_sponsor || options.mine_blocks > 0,
        "auto sponsor funding requires --mine-blocks greater than zero on devnet"
    );
    if let Some(path) = &options.watch_policy {
        let policy = read_watchtower_policy(path)?;
        policy.validate_run(&WatchPolicyRun {
            channel_id: &options.channel_id,
            detection_depth: options.detection_depth,
            timeout_secs: options.timeout_secs,
            poll_ms: options.poll_ms,
            fee: options.fee,
            mine_blocks: options.mine_blocks,
            sponsor_out_point_present: options.sponsor_out_point.is_some(),
            auto_fund_sponsor: options.auto_fund_sponsor,
            auto_sponsor_capacity: options.auto_sponsor_capacity,
            alert_webhook_present: options.alert_webhook_url.is_some(),
        })?;
    }
    let channel_id = canonical_hex32(&options.channel_id)?;
    let selected_package = latest_package(&options.store_dir, &channel_id)?;
    let selected_state_number = selected_package.package.state_number;
    let cursor_file = options
        .cursor_file
        .clone()
        .map(Ok)
        .unwrap_or_else(|| default_watch_cursor_path(&options.store_dir, &channel_id))?;
    let loaded_cursor = if options.ignore_cursor {
        None
    } else {
        match read_watch_cursor(&cursor_file)? {
            Some(cursor) => {
                ensure!(
                    cursor.channel_id == channel_id,
                    "watch cursor {} belongs to channel {}, not {}",
                    cursor_file.display(),
                    cursor.channel_id,
                    channel_id
                );
                Some(cursor)
            }
            None => None,
        }
    };
    let effective_from_block = loaded_cursor
        .as_ref()
        .map(|cursor| options.from_block.max(cursor.next_block))
        .unwrap_or(options.from_block);
    let started = Instant::now();
    let timeout = Duration::from_secs(options.timeout_secs);
    let poll_interval = Duration::from_millis(options.poll_ms);
    let mut next_block = effective_from_block;
    let mut scanned_to_block = effective_from_block.saturating_sub(1);
    let mut last_observed = None;

    loop {
        let tip_number = rpc.tip_header()?.number_value()?;
        if tip_number.saturating_add(1) >= options.detection_depth {
            let mature_tip = tip_number + 1 - options.detection_depth;
            while next_block <= mature_tip {
                let current_block = next_block;
                if let Some(block) = rpc.block_by_number(next_block)? {
                    scanned_to_block = current_block;
                    for observed in observed_state_cells(&block, &channel_id, tip_number)? {
                        if observed.state_number < selected_state_number {
                            append_watch_alert_if_requested(
                                &options.alert_file,
                                &options.alert_webhook_url,
                                WatchtowerAlert::new(
                                    channel_id.clone(),
                                    WatchAlertSeverity::Warning,
                                    WatchAlertEvent::OlderStateDetected,
                                    format!(
                                        "confirmed StateCell {} is older than saved state {}",
                                        observed.state_number, selected_state_number
                                    ),
                                    selected_state_number,
                                    scanned_to_block,
                                    current_block.saturating_add(1),
                                )?
                                .with_observed(observed.state_number, observed.out_point.clone()),
                            )?;
                            let (sponsor_out_point, sponsor_top_up) =
                                sponsor_for_watch_publication(
                                    rpc,
                                    &options,
                                    &observed,
                                    selected_state_number,
                                )?;
                            let publication = publish_state(
                                rpc,
                                PublishStateOptions {
                                    contracts_dir: options.contracts_dir.clone(),
                                    private_key: options.private_key.clone(),
                                    alice_private_key: DEFAULT_ALICE_PRIVATE_KEY.to_string(),
                                    bob_private_key: DEFAULT_BOB_PRIVATE_KEY.to_string(),
                                    state_out_point: observed.out_point.clone(),
                                    sponsor_out_point,
                                    state_number: None,
                                    state_package: Some(selected_package.path.clone()),
                                    fee: options.fee,
                                    mine_blocks: options.mine_blocks,
                                },
                            )?;
                            append_watch_alert_if_requested(
                                &options.alert_file,
                                &options.alert_webhook_url,
                                WatchtowerAlert::new(
                                    channel_id.clone(),
                                    WatchAlertSeverity::Warning,
                                    WatchAlertEvent::PublicationSubmitted,
                                    format!(
                                        "published saved state {} against older StateCell {}",
                                        selected_state_number, observed.state_number
                                    ),
                                    selected_state_number,
                                    scanned_to_block,
                                    current_block.saturating_add(1),
                                )?
                                .with_observed(observed.state_number, observed.out_point.clone())
                                .with_publication(publication.tx_hash.clone()),
                            )?;
                            let next_from_block = current_block.saturating_add(1);
                            write_watch_cursor(
                                &cursor_file,
                                &WatchCursor::new(&channel_id, next_from_block, scanned_to_block)?,
                            )?;
                            return Ok(WatchLatestStatePackageReport {
                                channel_id,
                                from_block: options.from_block,
                                effective_from_block,
                                scanned_to_block,
                                next_from_block,
                                detection_depth: options.detection_depth,
                                cursor_file: Some(cursor_file),
                                alert_file: options.alert_file.clone(),
                                alert_webhook_url: options.alert_webhook_url.clone(),
                                loaded_cursor,
                                selected_package,
                                sponsor_top_up,
                                observed: Some(observed),
                                publication: Some(publication),
                            });
                        }
                        last_observed = Some(observed);
                    }
                }
                next_block = current_block.saturating_add(1);
                write_watch_cursor(
                    &cursor_file,
                    &WatchCursor::new(&channel_id, next_block, scanned_to_block)?,
                )?;
            }
        }

        if started.elapsed() >= timeout {
            write_watch_cursor(
                &cursor_file,
                &WatchCursor::new(&channel_id, next_block, scanned_to_block)?,
            )?;
            append_watch_alert_if_requested(
                &options.alert_file,
                &options.alert_webhook_url,
                WatchtowerAlert::new(
                    channel_id.clone(),
                    WatchAlertSeverity::Info,
                    WatchAlertEvent::ScanIdle,
                    "scan reached timeout without publishing a newer state".to_string(),
                    selected_state_number,
                    scanned_to_block,
                    next_block,
                )?,
            )?;
            return Ok(WatchLatestStatePackageReport {
                channel_id,
                from_block: options.from_block,
                effective_from_block,
                scanned_to_block,
                next_from_block: next_block,
                detection_depth: options.detection_depth,
                cursor_file: Some(cursor_file),
                alert_file: options.alert_file.clone(),
                alert_webhook_url: options.alert_webhook_url.clone(),
                loaded_cursor,
                selected_package,
                sponsor_top_up: None,
                observed: last_observed,
                publication: None,
            });
        }
        std::thread::sleep(poll_interval);
    }
}

fn append_watch_alert_if_requested(
    alert_file: &Option<PathBuf>,
    alert_webhook_url: &Option<String>,
    alert: WatchtowerAlert,
) -> Result<()> {
    if let Some(path) = alert_file {
        append_watchtower_alert(path, &alert)?;
    }
    if let Some(url) = alert_webhook_url {
        post_watchtower_alert_webhook(url, &alert)?;
    }
    Ok(())
}

fn sponsor_for_watch_publication(
    rpc: &CkbRpcClient,
    options: &WatchLatestStatePackageOptions,
    observed: &ObservedStateCellReport,
    selected_state_number: u64,
) -> Result<(String, Option<FundSponsorReport>)> {
    if let Some(out_point) = &options.sponsor_out_point {
        return Ok((out_point.clone(), None));
    }

    let policy_fee = options
        .fee
        .checked_mul(2)
        .ok_or_else(|| anyhow!("fee overflow while building auto sponsor policy"))?;
    ensure!(
        policy_fee <= options.auto_sponsor_capacity,
        "auto sponsor capacity must cover the emergency policy budget"
    );
    let sponsor_top_up = fund_sponsor(
        rpc,
        FundSponsorOptions {
            contracts_dir: options.contracts_dir.clone(),
            private_key: options.private_key.clone(),
            state_out_point: observed.out_point.clone(),
            sponsor_capacity: options.auto_sponsor_capacity,
            sponsor_min_state_number: selected_state_number,
            sponsor_max_state_number: selected_state_number,
            sponsor_max_fee_per_tx: Some(policy_fee),
            sponsor_max_total_fee: Some(policy_fee),
            fee: options.fee,
            mine_blocks: options.mine_blocks,
        },
    )?;
    let sponsor_out_point = printable_out_point_string(&sponsor_top_up.sponsor_out_point);
    Ok((sponsor_out_point, Some(sponsor_top_up)))
}

pub fn fund_sponsor(rpc: &CkbRpcClient, options: FundSponsorOptions) -> Result<FundSponsorReport> {
    ensure!(options.fee > 0, "fee must be non-zero");
    ensure!(
        options.sponsor_capacity > 0,
        "sponsor capacity must be non-zero"
    );

    let owner_key = parse_privkey(&options.private_key)
        .with_context(|| "invalid secp256k1 private key for sponsor funding")?;
    let owner_lock = secp256k1_lock(&owner_key)?;
    let state_out_point = parse_out_point(&options.state_out_point)?;
    let state_cell = load_live_cell(rpc, state_out_point)?;
    let header = StateHeaderV1::parse(state_cell.data.as_ref())
        .map_err(|err| anyhow!("state cell does not contain a valid Morph StateHeader: {err:?}"))?;
    let state_type_hash: [u8; 32] = state_cell
        .output
        .type_()
        .to_opt()
        .ok_or_else(|| anyhow!("state cell does not carry a type script"))?
        .calc_script_hash()
        .unpack();

    let tip_number = rpc.tip_header()?.number_value()?;
    let funding_cell = find_largest_live_cell(rpc, &owner_lock, tip_number)?;
    let secp_dep = find_secp256k1_cell_dep(rpc)?;
    let contracts = find_deployed_contracts(rpc, &options.contracts_dir, tip_number)?;
    let sponsor_contract = contract_by_name(&contracts, "morph-sponsor-lock")?;

    let change_lock_hash = owner_lock.calc_script_hash();
    let channel_id: &[u8; 32] = header
        .channel_id()
        .try_into()
        .map_err(|_| anyhow!("state header channel id is not 32 bytes"))?;
    let sponsor_policy_settings = sponsor_policy_settings(
        options.sponsor_capacity,
        options.sponsor_min_state_number,
        options.sponsor_max_state_number,
        options.sponsor_max_fee_per_tx,
        options.sponsor_max_total_fee,
    )?;
    let change_lock_hash_array: [u8; 32] = change_lock_hash.as_slice().try_into().unwrap();
    let sponsor_policy = sponsor_policy_bytes(
        channel_id,
        sponsor_policy_settings,
        state_type_hash,
        change_lock_hash_array,
    );
    let sponsor_lock = data1_script(
        sponsor_contract.data_hash.clone(),
        Bytes::copy_from_slice(&sponsor_policy),
    );
    let sponsor_output = CellOutput::new_builder()
        .capacity(options.sponsor_capacity)
        .lock(sponsor_lock)
        .build();
    ensure_output_capacity("sponsor", &sponsor_output, 0)?;

    let change_capacity = funding_cell
        .capacity
        .checked_sub(options.sponsor_capacity)
        .and_then(|value| value.checked_sub(options.fee))
        .ok_or_else(|| {
            anyhow!(
                "funding cell capacity {} cannot cover sponsor {} and fee {}",
                funding_cell.capacity,
                options.sponsor_capacity,
                options.fee
            )
        })?;
    ensure_change_capacity(&owner_lock, change_capacity)?;

    let unsigned = TransactionBuilder::default()
        .cell_dep(secp_dep)
        .input(CellInput::new(funding_cell.out_point.clone(), 0))
        .output(sponsor_output)
        .output(
            CellOutput::new_builder()
                .capacity(change_capacity)
                .lock(owner_lock.clone())
                .build(),
        )
        .output_data(Bytes::new().pack())
        .output_data(Bytes::new().pack())
        .build();
    let signed = sign_single_secp_input(unsigned, &owner_key)?;
    let sent = send_and_mine(rpc, signed, options.mine_blocks)?;

    Ok(FundSponsorReport {
        tx_hash: sent.tx_hash.clone(),
        status: sent.status,
        block_number: sent.block_number,
        block_hash: sent.block_hash,
        channel_id: hex32(header.channel_id()),
        state_number: header.state_number(),
        sponsor_out_point: PrintableOutPoint {
            tx_hash: sent.tx_hash,
            index: 0,
        },
        sponsor_capacity: options.sponsor_capacity,
        sponsor_policy: sponsor_policy_report(
            sponsor_policy_settings,
            state_type_hash,
            change_lock_hash_array,
        ),
        change_capacity,
        fee: options.fee,
        metrics: sent.metrics,
        mined_blocks: sent.mined_blocks,
    })
}

pub fn finalise_channel(
    rpc: &CkbRpcClient,
    options: FinaliseChannelOptions,
) -> Result<FinaliseChannelReport> {
    ensure!(options.fee > 0, "fee must be non-zero");

    let owner_key = parse_privkey(&options.private_key)
        .with_context(|| "invalid secp256k1 private key for state refund")?;
    let owner_lock = secp256k1_lock(&owner_key)?;
    let alice_key = parse_privkey(&options.alice_private_key)
        .with_context(|| "invalid Alice channel private key")?;
    let bob_key = parse_privkey(&options.bob_private_key)
        .with_context(|| "invalid Bob channel private key")?;
    let alice_lock = secp256k1_lock(&alice_key)?;
    let bob_lock = secp256k1_lock(&bob_key)?;
    let alice_lock_hash: [u8; 32] = alice_lock.calc_script_hash().unpack();
    let bob_lock_hash: [u8; 32] = bob_lock.calc_script_hash().unpack();

    let state_out_point = parse_out_point(&options.state_out_point)?;
    let vault_out_point = parse_out_point(&options.vault_out_point)?;
    let state_cell = load_live_cell(rpc, state_out_point.clone())?;
    let vault_cell = load_live_cell(rpc, vault_out_point.clone())?;
    let header = StateHeaderV1::parse(state_cell.data.as_ref())
        .map_err(|err| anyhow!("state cell does not contain a valid Morph StateHeader: {err:?}"))?;
    ensure!(
        header.phase() == PHASE_SETTLING,
        "only a settling state can be finalised"
    );

    let (alice_capacity, bob_capacity) = settlement_split(
        vault_cell.capacity,
        options.alice_capacity,
        options.bob_capacity,
    )?;
    ensure_output_capacity(
        "alice settlement",
        &CellOutput::new_builder()
            .capacity(alice_capacity)
            .lock(alice_lock.clone())
            .build(),
        0,
    )?;
    ensure_output_capacity(
        "bob settlement",
        &CellOutput::new_builder()
            .capacity(bob_capacity)
            .lock(bob_lock.clone())
            .build(),
        0,
    )?;
    let descriptor =
        bilateral_ckb_descriptor(alice_lock_hash, alice_capacity, bob_lock_hash, bob_capacity);
    ensure!(
        settlement_descriptor_commitment_v1(&descriptor).as_slice()
            == header.settlement_descriptor_commitment(),
        "reconstructed settlement descriptor does not match the state commitment"
    );

    let state_refund_capacity = state_cell
        .capacity
        .checked_sub(options.fee)
        .ok_or_else(|| anyhow!("state carrier capacity cannot cover fee {}", options.fee))?;
    ensure_change_capacity(&owner_lock, state_refund_capacity)?;

    let tip_number = rpc.tip_header()?.number_value()?;
    let contracts = find_deployed_contracts(rpc, &options.contracts_dir, tip_number)?;
    let state_lock_contract = contract_by_name(&contracts, "morph-state-lock")?;
    let state_contract = contract_by_name(&contracts, "morph-state-type")?;
    let vault_contract = contract_by_name(&contracts, "morph-vault-lock")?;

    let refund_output = CellOutput::new_builder()
        .capacity(state_refund_capacity)
        .lock(owner_lock)
        .build();
    let tx = TransactionBuilder::default()
        .cell_dep(state_lock_contract.cell_dep)
        .cell_dep(state_contract.cell_dep)
        .cell_dep(vault_contract.cell_dep)
        .input(CellInput::new(state_out_point, options.finalise_since))
        .input(CellInput::new(vault_out_point, 0))
        .output(
            CellOutput::new_builder()
                .capacity(alice_capacity)
                .lock(alice_lock)
                .build(),
        )
        .output(
            CellOutput::new_builder()
                .capacity(bob_capacity)
                .lock(bob_lock)
                .build(),
        )
        .output(refund_output.clone())
        .output_data(Bytes::new().pack())
        .output_data(Bytes::new().pack())
        .output_data(Bytes::new().pack())
        .witness(empty_witness())
        .witness(witness_with_input_type(Bytes::copy_from_slice(&descriptor)))
        .build();
    let sent_hash = send_and_mine(rpc, tx, options.mine_blocks)?;
    let tx_hash = sent_hash.tx_hash.clone();

    let output_report = |role: &str, index: u32, lock: Script, capacity: u64| ChannelCellReport {
        role: role.to_string(),
        out_point: PrintableOutPoint {
            tx_hash: tx_hash.clone(),
            index,
        },
        capacity,
        lock_hash: hex32(lock.calc_script_hash().as_slice()),
        type_hash: None,
        data_len: 0,
    };

    Ok(FinaliseChannelReport {
        tx_hash: sent_hash.tx_hash,
        status: sent_hash.status,
        block_number: sent_hash.block_number,
        block_hash: sent_hash.block_hash,
        channel_id: hex32(header.channel_id()),
        funding_anchor: hex32(header.funding_anchor()),
        state_number: header.state_number(),
        alice_capacity,
        bob_capacity,
        state_refund_capacity,
        fee: options.fee,
        metrics: sent_hash.metrics,
        mined_blocks: sent_hash.mined_blocks,
        outputs: vec![
            output_report("alice", 0, secp256k1_lock(&alice_key)?, alice_capacity),
            output_report("bob", 1, secp256k1_lock(&bob_key)?, bob_capacity),
            output_report(
                "state-refund",
                2,
                refund_output.lock(),
                state_refund_capacity,
            ),
        ],
    })
}

fn finalise_xudt_channel(
    rpc: &CkbRpcClient,
    options: &XudtSmokeOptions,
    state_out_point: String,
    vault_out_point: String,
) -> Result<XudtFinaliseReport> {
    let build = build_xudt_finalise_transaction(
        rpc,
        options,
        state_out_point,
        vault_out_point,
        (options.alice_xudt_amount, options.bob_xudt_amount),
    )?;
    let sent = send_and_mine(rpc, build.tx.clone(), options.mine_blocks)?;
    Ok(xudt_finalise_report(build, sent))
}

struct BuiltXudtFinalise {
    tx: ckb_types::core::TransactionView,
    channel_id: String,
    funding_anchor: String,
    state_number: u64,
    xudt_type_hash: String,
    alice_capacity: u64,
    bob_capacity: u64,
    alice_xudt_amount: u128,
    bob_xudt_amount: u128,
    state_refund_capacity: u64,
    fee: u64,
    alice_output: CellOutput,
    bob_output: CellOutput,
    refund_output: CellOutput,
}

fn build_xudt_finalise_transaction(
    rpc: &CkbRpcClient,
    options: &XudtSmokeOptions,
    state_out_point: String,
    vault_out_point: String,
    output_amounts: (u128, u128),
) -> Result<BuiltXudtFinalise> {
    ensure!(options.fee > 0, "fee must be non-zero");
    let total_xudt_amount = options
        .alice_xudt_amount
        .checked_add(options.bob_xudt_amount)
        .ok_or_else(|| anyhow!("xUDT amount overflow"))?;
    output_amounts
        .0
        .checked_add(output_amounts.1)
        .ok_or_else(|| anyhow!("xUDT output amount overflow"))?;

    let owner_key = parse_privkey(&options.private_key)
        .with_context(|| "invalid secp256k1 private key for state refund")?;
    let owner_lock = secp256k1_lock(&owner_key)?;
    let alice_key = parse_privkey(&options.alice_private_key)
        .with_context(|| "invalid Alice channel private key")?;
    let bob_key = parse_privkey(&options.bob_private_key)
        .with_context(|| "invalid Bob channel private key")?;
    let alice_lock = secp256k1_lock(&alice_key)?;
    let bob_lock = secp256k1_lock(&bob_key)?;
    let alice_lock_hash: [u8; 32] = alice_lock.calc_script_hash().unpack();
    let bob_lock_hash: [u8; 32] = bob_lock.calc_script_hash().unpack();

    let state_out_point = parse_out_point(&state_out_point)?;
    let vault_out_point = parse_out_point(&vault_out_point)?;
    let state_cell = load_live_cell(rpc, state_out_point.clone())?;
    let vault_cell = load_live_cell(rpc, vault_out_point.clone())?;
    let header = StateHeaderV1::parse(state_cell.data.as_ref())
        .map_err(|err| anyhow!("state cell does not contain a valid Morph StateHeader: {err:?}"))?;
    ensure!(
        header.phase() == PHASE_SETTLING,
        "only a settling state can be finalised"
    );
    ensure!(
        header.descriptor_version() == BILATERAL_CKB_XUDT_DESCRIPTOR_VERSION_V1,
        "state descriptor version is not xUDT-capable"
    );
    ensure!(
        xudt_amount_from_data(&vault_cell.data)? == total_xudt_amount,
        "vault xUDT amount does not match requested split"
    );
    let xudt_type = vault_cell
        .output
        .type_()
        .to_opt()
        .ok_or_else(|| anyhow!("xUDT vault cell has no type script"))?;
    let xudt_type_hash: [u8; 32] = xudt_type.calc_script_hash().unpack();

    let (alice_capacity, bob_capacity) = settlement_split(
        vault_cell.capacity,
        options.alice_capacity,
        options.bob_capacity,
    )?;
    ensure_output_capacity(
        "alice xUDT settlement",
        &CellOutput::new_builder()
            .capacity(alice_capacity)
            .lock(alice_lock.clone())
            .type_(Some(xudt_type.clone()).pack())
            .build(),
        16,
    )?;
    ensure_output_capacity(
        "bob xUDT settlement",
        &CellOutput::new_builder()
            .capacity(bob_capacity)
            .lock(bob_lock.clone())
            .type_(Some(xudt_type.clone()).pack())
            .build(),
        16,
    )?;
    let descriptor = bilateral_ckb_xudt_descriptor(
        xudt_type_hash,
        alice_lock_hash,
        alice_capacity,
        options.alice_xudt_amount,
        bob_lock_hash,
        bob_capacity,
        options.bob_xudt_amount,
    );
    ensure!(
        settlement_descriptor_commitment_v1(&descriptor).as_slice()
            == header.settlement_descriptor_commitment(),
        "reconstructed xUDT settlement descriptor does not match the state commitment"
    );

    let state_refund_capacity = state_cell
        .capacity
        .checked_sub(options.fee)
        .ok_or_else(|| anyhow!("state carrier capacity cannot cover fee {}", options.fee))?;
    ensure_change_capacity(&owner_lock, state_refund_capacity)?;

    let tip_number = rpc.tip_header()?.number_value()?;
    let contracts = find_deployed_contracts(rpc, &options.contracts_dir, tip_number)?;
    let state_lock_contract = contract_by_name(&contracts, "morph-state-lock")?;
    let state_contract = contract_by_name(&contracts, "morph-state-type")?;
    let vault_contract = contract_by_name(&contracts, "morph-vault-lock")?;
    let xudt_contract = contract_by_name(&contracts, "morph-devnet-xudt")?;

    let alice_output = CellOutput::new_builder()
        .capacity(alice_capacity)
        .lock(alice_lock)
        .type_(Some(xudt_type.clone()).pack())
        .build();
    let bob_output = CellOutput::new_builder()
        .capacity(bob_capacity)
        .lock(bob_lock)
        .type_(Some(xudt_type).pack())
        .build();
    let refund_output = CellOutput::new_builder()
        .capacity(state_refund_capacity)
        .lock(owner_lock)
        .build();
    let tx = TransactionBuilder::default()
        .cell_dep(state_lock_contract.cell_dep)
        .cell_dep(state_contract.cell_dep)
        .cell_dep(vault_contract.cell_dep)
        .cell_dep(xudt_contract.cell_dep)
        .input(CellInput::new(state_out_point, options.finalise_since))
        .input(CellInput::new(vault_out_point, 0))
        .output(alice_output.clone())
        .output(bob_output.clone())
        .output(refund_output.clone())
        .output_data(xudt_amount_bytes(output_amounts.0).pack())
        .output_data(xudt_amount_bytes(output_amounts.1).pack())
        .output_data(Bytes::new().pack())
        .witness(empty_witness())
        .witness(witness_with_input_type(Bytes::copy_from_slice(&descriptor)))
        .build();

    Ok(BuiltXudtFinalise {
        tx,
        channel_id: hex32(header.channel_id()),
        funding_anchor: hex32(header.funding_anchor()),
        state_number: header.state_number(),
        xudt_type_hash: hex32(&xudt_type_hash),
        alice_capacity,
        bob_capacity,
        alice_xudt_amount: output_amounts.0,
        bob_xudt_amount: output_amounts.1,
        state_refund_capacity,
        fee: options.fee,
        alice_output,
        bob_output,
        refund_output,
    })
}

fn xudt_finalise_report(
    build: BuiltXudtFinalise,
    sent_hash: SentTransactionReport,
) -> XudtFinaliseReport {
    let tx_hash = sent_hash.tx_hash.clone();
    let output_report =
        |role: &str, index: u32, output: &CellOutput, data_len: usize| -> ChannelCellReport {
            ChannelCellReport {
                role: role.to_string(),
                out_point: PrintableOutPoint {
                    tx_hash: tx_hash.clone(),
                    index,
                },
                capacity: output.capacity().unpack(),
                lock_hash: hex32(output.lock().calc_script_hash().as_slice()),
                type_hash: output
                    .type_()
                    .to_opt()
                    .map(|script| hex32(script.calc_script_hash().as_slice())),
                data_len,
            }
        };

    XudtFinaliseReport {
        tx_hash: sent_hash.tx_hash,
        status: sent_hash.status,
        block_number: sent_hash.block_number,
        block_hash: sent_hash.block_hash,
        channel_id: build.channel_id,
        funding_anchor: build.funding_anchor,
        state_number: build.state_number,
        xudt_type_hash: build.xudt_type_hash,
        alice_capacity: build.alice_capacity,
        bob_capacity: build.bob_capacity,
        alice_xudt_amount: build.alice_xudt_amount,
        bob_xudt_amount: build.bob_xudt_amount,
        state_refund_capacity: build.state_refund_capacity,
        fee: build.fee,
        metrics: sent_hash.metrics,
        mined_blocks: sent_hash.mined_blocks,
        outputs: vec![
            output_report("alice", 0, &build.alice_output, 16),
            output_report("bob", 1, &build.bob_output, 16),
            output_report("state-refund", 2, &build.refund_output, 0),
        ],
    }
}

pub fn xudt_smoke(rpc: &CkbRpcClient, options: XudtSmokeOptions) -> Result<XudtSmokeReport> {
    let open = open_xudt_channel(rpc, &options)?;
    let initial_state_out_point = channel_cell_out_point(&open, "state")?;
    let vault_out_point = channel_cell_out_point(&open, "xudt-vault")?;
    let sponsor_out_point = channel_cell_out_point(&open, "sponsor")?;
    let publish = publish_state(
        rpc,
        PublishStateOptions {
            contracts_dir: options.contracts_dir.clone(),
            private_key: options.private_key.clone(),
            alice_private_key: options.alice_private_key.clone(),
            bob_private_key: options.bob_private_key.clone(),
            state_out_point: initial_state_out_point,
            sponsor_out_point,
            state_number: Some(1),
            state_package: None,
            fee: options.fee,
            mine_blocks: options.mine_blocks,
        },
    )?;
    let settling_state_out_point = printable_out_point_string(&publish.state_out_point);
    let finalise = finalise_xudt_channel(rpc, &options, settling_state_out_point, vault_out_point)?;

    Ok(XudtSmokeReport {
        open,
        publish,
        finalise,
    })
}

pub fn xudt_negative_smoke(
    rpc: &CkbRpcClient,
    options: XudtNegativeSmokeOptions,
) -> Result<XudtNegativeSmokeReport> {
    ensure!(
        options.bob_xudt_amount > 0,
        "Bob xUDT amount must be non-zero so the negative smoke can preserve total supply"
    );
    let smoke_options = XudtSmokeOptions {
        contracts_dir: options.contracts_dir,
        private_key: options.private_key,
        alice_private_key: options.alice_private_key,
        bob_private_key: options.bob_private_key,
        vault_capacity: options.vault_capacity,
        alice_capacity: options.alice_capacity,
        bob_capacity: options.bob_capacity,
        alice_xudt_amount: options.alice_xudt_amount,
        bob_xudt_amount: options.bob_xudt_amount,
        sponsor_capacity: options.sponsor_capacity,
        fee: options.fee,
        finalise_since: options.finalise_since,
        mine_blocks: options.mine_blocks,
    };

    let open = open_xudt_channel(rpc, &smoke_options)?;
    let initial_state_out_point = channel_cell_out_point(&open, "state")?;
    let vault_out_point = channel_cell_out_point(&open, "xudt-vault")?;
    let sponsor_out_point = channel_cell_out_point(&open, "sponsor")?;
    let publish = publish_state(
        rpc,
        PublishStateOptions {
            contracts_dir: smoke_options.contracts_dir.clone(),
            private_key: smoke_options.private_key.clone(),
            alice_private_key: smoke_options.alice_private_key.clone(),
            bob_private_key: smoke_options.bob_private_key.clone(),
            state_out_point: initial_state_out_point,
            sponsor_out_point,
            state_number: Some(1),
            state_package: None,
            fee: smoke_options.fee,
            mine_blocks: smoke_options.mine_blocks,
        },
    )?;
    let settling_state_out_point = printable_out_point_string(&publish.state_out_point);

    let rejected_alice_xudt_amount = smoke_options
        .alice_xudt_amount
        .checked_add(1)
        .ok_or_else(|| anyhow!("Alice xUDT amount overflow in negative smoke"))?;
    let rejected_bob_xudt_amount = smoke_options
        .bob_xudt_amount
        .checked_sub(1)
        .ok_or_else(|| anyhow!("Bob xUDT amount underflow in negative smoke"))?;
    let rejected_build = build_xudt_finalise_transaction(
        rpc,
        &smoke_options,
        settling_state_out_point.clone(),
        vault_out_point.clone(),
        (rejected_alice_xudt_amount, rejected_bob_xudt_amount),
    )?;
    let rejection = match send_and_mine(rpc, rejected_build.tx, 0) {
        Ok(report) => {
            return Err(anyhow!(
                "xUDT descriptor unexpectedly accepted tampered settlement in tx {}",
                report.tx_hash
            ));
        }
        Err(err) => err.to_string(),
    };
    let script_failure = parse_script_failure(&rejection);
    ensure!(
        script_failure.error_code == Some(ScriptError::SettlementOutputMismatch as i16),
        "expected SettlementOutputMismatch from vault lock, got {:?}: {}",
        script_failure.error_code,
        rejection
    );

    let finalise = finalise_xudt_channel(
        rpc,
        &smoke_options,
        settling_state_out_point,
        vault_out_point,
    )?;

    Ok(XudtNegativeSmokeReport {
        open,
        publish,
        rejected_alice_xudt_amount,
        rejected_bob_xudt_amount,
        rejection,
        script_failure,
        finalise,
    })
}

pub fn supersede_smoke(
    rpc: &CkbRpcClient,
    options: SupersedeSmokeOptions,
) -> Result<SupersedeSmokeReport> {
    let open = open_channel(
        rpc,
        OpenChannelOptions {
            contracts_dir: options.contracts_dir.clone(),
            private_key: options.private_key.clone(),
            alice_private_key: options.alice_private_key.clone(),
            bob_private_key: options.bob_private_key.clone(),
            vault_capacity: options.vault_capacity,
            alice_capacity: options.alice_capacity,
            bob_capacity: options.bob_capacity,
            sponsor_capacity: options.sponsor_capacity,
            sponsor_min_state_number: 0,
            sponsor_max_state_number: u64::MAX,
            sponsor_max_fee_per_tx: None,
            sponsor_max_total_fee: None,
            fee: options.fee,
            finalise_since: options.finalise_since,
            mine_blocks: options.mine_blocks,
        },
    )?;
    let initial_state_out_point = channel_cell_out_point(&open, "state")?;
    let vault_out_point = channel_cell_out_point(&open, "vault")?;
    let initial_sponsor_out_point = channel_cell_out_point(&open, "sponsor")?;

    let stale_publish = publish_state(
        rpc,
        PublishStateOptions {
            contracts_dir: options.contracts_dir.clone(),
            private_key: options.private_key.clone(),
            alice_private_key: options.alice_private_key.clone(),
            bob_private_key: options.bob_private_key.clone(),
            state_out_point: initial_state_out_point,
            sponsor_out_point: initial_sponsor_out_point,
            state_number: Some(1),
            state_package: None,
            fee: options.fee,
            mine_blocks: options.mine_blocks,
        },
    )?;
    let stale_state_out_point = printable_out_point_string(&stale_publish.state_out_point);

    let sponsor_top_up = fund_sponsor(
        rpc,
        FundSponsorOptions {
            contracts_dir: options.contracts_dir.clone(),
            private_key: options.private_key.clone(),
            state_out_point: stale_state_out_point.clone(),
            sponsor_capacity: options.sponsor_capacity,
            sponsor_min_state_number: 0,
            sponsor_max_state_number: u64::MAX,
            sponsor_max_fee_per_tx: None,
            sponsor_max_total_fee: None,
            fee: options.fee,
            mine_blocks: options.mine_blocks,
        },
    )?;
    let top_up_sponsor_out_point = printable_out_point_string(&sponsor_top_up.sponsor_out_point);

    let supersede_publish = publish_state(
        rpc,
        PublishStateOptions {
            contracts_dir: options.contracts_dir.clone(),
            private_key: options.private_key.clone(),
            alice_private_key: options.alice_private_key.clone(),
            bob_private_key: options.bob_private_key.clone(),
            state_out_point: stale_state_out_point,
            sponsor_out_point: top_up_sponsor_out_point,
            state_number: Some(2),
            state_package: None,
            fee: options.fee,
            mine_blocks: options.mine_blocks,
        },
    )?;
    let newer_state_out_point = printable_out_point_string(&supersede_publish.state_out_point);

    let finalise = finalise_channel(
        rpc,
        FinaliseChannelOptions {
            contracts_dir: options.contracts_dir,
            private_key: options.private_key,
            alice_private_key: options.alice_private_key,
            bob_private_key: options.bob_private_key,
            state_out_point: newer_state_out_point,
            vault_out_point,
            alice_capacity: options.alice_capacity,
            bob_capacity: options.bob_capacity,
            finalise_since: options.finalise_since,
            fee: options.fee,
            mine_blocks: options.mine_blocks,
        },
    )?;

    Ok(SupersedeSmokeReport {
        open,
        stale_publish,
        sponsor_top_up,
        supersede_publish,
        finalise,
    })
}

pub fn finalise_since_negative_smoke(
    rpc: &CkbRpcClient,
    options: FinaliseSinceNegativeSmokeOptions,
) -> Result<FinaliseSinceNegativeSmokeReport> {
    ensure!(
        options.finalise_since > 0,
        "finalise-since negative smoke needs a non-zero finalise since"
    );
    let policy_fee = options
        .fee
        .checked_mul(2)
        .ok_or_else(|| anyhow!("fee overflow while building sponsor policy"))?;
    ensure!(
        policy_fee <= options.sponsor_capacity,
        "sponsor capacity must cover the smoke policy budget"
    );

    let open = open_channel(
        rpc,
        OpenChannelOptions {
            contracts_dir: options.contracts_dir.clone(),
            private_key: options.private_key.clone(),
            alice_private_key: options.alice_private_key.clone(),
            bob_private_key: options.bob_private_key.clone(),
            vault_capacity: options.vault_capacity,
            alice_capacity: options.alice_capacity,
            bob_capacity: options.bob_capacity,
            sponsor_capacity: options.sponsor_capacity,
            sponsor_min_state_number: 1,
            sponsor_max_state_number: 1,
            sponsor_max_fee_per_tx: Some(policy_fee),
            sponsor_max_total_fee: Some(policy_fee),
            fee: options.fee,
            finalise_since: options.finalise_since,
            mine_blocks: options.mine_blocks,
        },
    )?;
    let initial_state_out_point = channel_cell_out_point(&open, "state")?;
    let vault_out_point = channel_cell_out_point(&open, "vault")?;
    let sponsor_out_point = channel_cell_out_point(&open, "sponsor")?;

    let publish = publish_state(
        rpc,
        PublishStateOptions {
            contracts_dir: options.contracts_dir.clone(),
            private_key: options.private_key.clone(),
            alice_private_key: options.alice_private_key.clone(),
            bob_private_key: options.bob_private_key.clone(),
            state_out_point: initial_state_out_point,
            sponsor_out_point,
            state_number: Some(1),
            state_package: None,
            fee: options.fee,
            mine_blocks: options.mine_blocks,
        },
    )?;
    let settling_state_out_point = printable_out_point_string(&publish.state_out_point);

    let rejected_input_since = 0;
    let rejection = match finalise_channel(
        rpc,
        FinaliseChannelOptions {
            contracts_dir: options.contracts_dir.clone(),
            private_key: options.private_key.clone(),
            alice_private_key: options.alice_private_key.clone(),
            bob_private_key: options.bob_private_key.clone(),
            state_out_point: settling_state_out_point.clone(),
            vault_out_point: vault_out_point.clone(),
            alice_capacity: options.alice_capacity,
            bob_capacity: options.bob_capacity,
            finalise_since: rejected_input_since,
            fee: options.fee,
            mine_blocks: 0,
        },
    ) {
        Ok(report) => {
            return Err(anyhow!(
                "finalise unexpectedly accepted input since {} in tx {}",
                rejected_input_since,
                report.tx_hash
            ));
        }
        Err(err) => err.to_string(),
    };
    let script_failure = parse_script_failure(&rejection);
    ensure!(
        script_failure.error_code == Some(ScriptError::StateSinceNotMature as i16),
        "expected StateSinceNotMature from finalise path, got {:?}: {}",
        script_failure.error_code,
        rejection
    );

    let mut maturity_blocks = Vec::new();
    for _ in 0..options.finalise_since {
        maturity_blocks.push(rpc.generate_block()?);
    }

    let finalise = finalise_channel(
        rpc,
        FinaliseChannelOptions {
            contracts_dir: options.contracts_dir,
            private_key: options.private_key,
            alice_private_key: options.alice_private_key,
            bob_private_key: options.bob_private_key,
            state_out_point: settling_state_out_point,
            vault_out_point,
            alice_capacity: options.alice_capacity,
            bob_capacity: options.bob_capacity,
            finalise_since: options.finalise_since,
            fee: options.fee,
            mine_blocks: options.mine_blocks,
        },
    )?;

    Ok(FinaliseSinceNegativeSmokeReport {
        open,
        publish,
        rejected_input_since,
        required_finalise_since: options.finalise_since,
        rejection,
        script_failure,
        maturity_blocks,
        finalise,
    })
}

pub fn sponsor_policy_negative_smoke(
    rpc: &CkbRpcClient,
    options: SponsorPolicyNegativeSmokeOptions,
) -> Result<SponsorPolicyNegativeSmokeReport> {
    let policy_fee = options
        .fee
        .checked_mul(2)
        .ok_or_else(|| anyhow!("fee overflow while building sponsor policy"))?;
    ensure!(
        policy_fee <= options.sponsor_capacity,
        "sponsor capacity must cover the negative-smoke policy budget"
    );

    let open = open_channel(
        rpc,
        OpenChannelOptions {
            contracts_dir: options.contracts_dir.clone(),
            private_key: options.private_key.clone(),
            alice_private_key: options.alice_private_key.clone(),
            bob_private_key: options.bob_private_key.clone(),
            vault_capacity: options.vault_capacity,
            alice_capacity: options.alice_capacity,
            bob_capacity: options.bob_capacity,
            sponsor_capacity: options.sponsor_capacity,
            sponsor_min_state_number: 1,
            sponsor_max_state_number: 1,
            sponsor_max_fee_per_tx: Some(policy_fee),
            sponsor_max_total_fee: Some(policy_fee),
            fee: options.fee,
            finalise_since: options.finalise_since,
            mine_blocks: options.mine_blocks,
        },
    )?;
    let initial_state_out_point = channel_cell_out_point(&open, "state")?;
    let vault_out_point = channel_cell_out_point(&open, "vault")?;
    let sponsor_out_point = channel_cell_out_point(&open, "sponsor")?;

    let rejection = match publish_state(
        rpc,
        PublishStateOptions {
            contracts_dir: options.contracts_dir.clone(),
            private_key: options.private_key.clone(),
            alice_private_key: options.alice_private_key.clone(),
            bob_private_key: options.bob_private_key.clone(),
            state_out_point: initial_state_out_point.clone(),
            sponsor_out_point: sponsor_out_point.clone(),
            state_number: Some(2),
            state_package: None,
            fee: options.fee,
            mine_blocks: 0,
        },
    ) {
        Ok(report) => {
            return Err(anyhow!(
                "sponsor policy unexpectedly accepted out-of-range state in tx {}",
                report.tx_hash
            ));
        }
        Err(err) => err.to_string(),
    };
    let script_failure = parse_script_failure(&rejection);
    ensure!(
        script_failure.error_code == Some(ScriptError::SponsorStateOutOfRange as i16),
        "expected SponsorStateOutOfRange from sponsor lock, got {:?}: {}",
        script_failure.error_code,
        rejection
    );

    let allowed_publish = publish_state(
        rpc,
        PublishStateOptions {
            contracts_dir: options.contracts_dir.clone(),
            private_key: options.private_key.clone(),
            alice_private_key: options.alice_private_key.clone(),
            bob_private_key: options.bob_private_key.clone(),
            state_out_point: initial_state_out_point,
            sponsor_out_point,
            state_number: Some(1),
            state_package: None,
            fee: options.fee,
            mine_blocks: options.mine_blocks,
        },
    )?;
    let settling_state_out_point = printable_out_point_string(&allowed_publish.state_out_point);

    let finalise = finalise_channel(
        rpc,
        FinaliseChannelOptions {
            contracts_dir: options.contracts_dir,
            private_key: options.private_key,
            alice_private_key: options.alice_private_key,
            bob_private_key: options.bob_private_key,
            state_out_point: settling_state_out_point,
            vault_out_point,
            alice_capacity: options.alice_capacity,
            bob_capacity: options.bob_capacity,
            finalise_since: options.finalise_since,
            fee: options.fee,
            mine_blocks: options.mine_blocks,
        },
    )?;

    Ok(SponsorPolicyNegativeSmokeReport {
        open,
        rejected_state_number: 2,
        rejection,
        script_failure,
        allowed_publish,
        finalise,
    })
}

pub fn sponsor_budget_negative_smoke(
    rpc: &CkbRpcClient,
    options: SponsorBudgetNegativeSmokeOptions,
) -> Result<SponsorBudgetNegativeSmokeReport> {
    ensure!(
        options.fee > 1,
        "sponsor-budget negative smoke needs a fee greater than one shannon"
    );
    let rejected_max_fee = options.fee - 1;
    let replacement_policy_fee = options
        .fee
        .checked_mul(2)
        .ok_or_else(|| anyhow!("fee overflow while building replacement sponsor policy"))?;
    ensure!(
        replacement_policy_fee <= options.sponsor_capacity,
        "sponsor capacity must cover the replacement sponsor policy budget"
    );

    let open = open_channel(
        rpc,
        OpenChannelOptions {
            contracts_dir: options.contracts_dir.clone(),
            private_key: options.private_key.clone(),
            alice_private_key: options.alice_private_key.clone(),
            bob_private_key: options.bob_private_key.clone(),
            vault_capacity: options.vault_capacity,
            alice_capacity: options.alice_capacity,
            bob_capacity: options.bob_capacity,
            sponsor_capacity: options.sponsor_capacity,
            sponsor_min_state_number: 1,
            sponsor_max_state_number: 1,
            sponsor_max_fee_per_tx: Some(rejected_max_fee),
            sponsor_max_total_fee: Some(rejected_max_fee),
            fee: options.fee,
            finalise_since: options.finalise_since,
            mine_blocks: options.mine_blocks,
        },
    )?;
    let initial_state_out_point = channel_cell_out_point(&open, "state")?;
    let vault_out_point = channel_cell_out_point(&open, "vault")?;
    let underfunded_sponsor_out_point = channel_cell_out_point(&open, "sponsor")?;

    let rejection = match publish_state(
        rpc,
        PublishStateOptions {
            contracts_dir: options.contracts_dir.clone(),
            private_key: options.private_key.clone(),
            alice_private_key: options.alice_private_key.clone(),
            bob_private_key: options.bob_private_key.clone(),
            state_out_point: initial_state_out_point.clone(),
            sponsor_out_point: underfunded_sponsor_out_point,
            state_number: Some(1),
            state_package: None,
            fee: options.fee,
            mine_blocks: 0,
        },
    ) {
        Ok(report) => {
            return Err(anyhow!(
                "sponsor budget unexpectedly accepted fee {} in tx {}",
                options.fee,
                report.tx_hash
            ));
        }
        Err(err) => err.to_string(),
    };
    let script_failure = parse_script_failure(&rejection);
    ensure!(
        script_failure.error_code == Some(ScriptError::SponsorFeeTooHigh as i16),
        "expected SponsorFeeTooHigh from sponsor lock, got {:?}: {}",
        script_failure.error_code,
        rejection
    );

    let replacement_sponsor = fund_sponsor(
        rpc,
        FundSponsorOptions {
            contracts_dir: options.contracts_dir.clone(),
            private_key: options.private_key.clone(),
            state_out_point: initial_state_out_point.clone(),
            sponsor_capacity: options.sponsor_capacity,
            sponsor_min_state_number: 1,
            sponsor_max_state_number: 1,
            sponsor_max_fee_per_tx: Some(replacement_policy_fee),
            sponsor_max_total_fee: Some(replacement_policy_fee),
            fee: options.fee,
            mine_blocks: options.mine_blocks,
        },
    )?;
    let replacement_sponsor_out_point =
        printable_out_point_string(&replacement_sponsor.sponsor_out_point);
    let allowed_publish = publish_state(
        rpc,
        PublishStateOptions {
            contracts_dir: options.contracts_dir.clone(),
            private_key: options.private_key.clone(),
            alice_private_key: options.alice_private_key.clone(),
            bob_private_key: options.bob_private_key.clone(),
            state_out_point: initial_state_out_point,
            sponsor_out_point: replacement_sponsor_out_point,
            state_number: Some(1),
            state_package: None,
            fee: options.fee,
            mine_blocks: options.mine_blocks,
        },
    )?;
    let settling_state_out_point = printable_out_point_string(&allowed_publish.state_out_point);

    let finalise = finalise_channel(
        rpc,
        FinaliseChannelOptions {
            contracts_dir: options.contracts_dir,
            private_key: options.private_key,
            alice_private_key: options.alice_private_key,
            bob_private_key: options.bob_private_key,
            state_out_point: settling_state_out_point,
            vault_out_point,
            alice_capacity: options.alice_capacity,
            bob_capacity: options.bob_capacity,
            finalise_since: options.finalise_since,
            fee: options.fee,
            mine_blocks: options.mine_blocks,
        },
    )?;

    Ok(SponsorBudgetNegativeSmokeReport {
        open,
        rejected_fee: options.fee,
        sponsor_max_fee_per_tx: rejected_max_fee,
        rejection,
        script_failure,
        replacement_sponsor,
        allowed_publish,
        finalise,
    })
}

pub fn competing_spend_smoke(
    rpc: &CkbRpcClient,
    options: CompetingSpendSmokeOptions,
) -> Result<CompetingSpendSmokeReport> {
    ensure!(
        options.mine_blocks > 0,
        "competing-spend smoke needs --mine-blocks greater than zero to commit the pending tx"
    );
    let policy_fee = options
        .fee
        .checked_mul(2)
        .ok_or_else(|| anyhow!("fee overflow while building spare sponsor policy"))?;
    ensure!(
        policy_fee <= options.sponsor_capacity,
        "sponsor capacity must cover the spare sponsor policy budget"
    );

    let open = open_channel(
        rpc,
        OpenChannelOptions {
            contracts_dir: options.contracts_dir.clone(),
            private_key: options.private_key.clone(),
            alice_private_key: options.alice_private_key.clone(),
            bob_private_key: options.bob_private_key.clone(),
            vault_capacity: options.vault_capacity,
            alice_capacity: options.alice_capacity,
            bob_capacity: options.bob_capacity,
            sponsor_capacity: options.sponsor_capacity,
            sponsor_min_state_number: 1,
            sponsor_max_state_number: 1,
            sponsor_max_fee_per_tx: Some(policy_fee),
            sponsor_max_total_fee: Some(policy_fee),
            fee: options.fee,
            finalise_since: options.finalise_since,
            mine_blocks: options.mine_blocks,
        },
    )?;
    let initial_state_out_point = channel_cell_out_point(&open, "state")?;
    let vault_out_point = channel_cell_out_point(&open, "vault")?;
    let initial_sponsor_out_point = channel_cell_out_point(&open, "sponsor")?;

    let spare_sponsor = fund_sponsor(
        rpc,
        FundSponsorOptions {
            contracts_dir: options.contracts_dir.clone(),
            private_key: options.private_key.clone(),
            state_out_point: initial_state_out_point.clone(),
            sponsor_capacity: options.sponsor_capacity,
            sponsor_min_state_number: 2,
            sponsor_max_state_number: 2,
            sponsor_max_fee_per_tx: Some(policy_fee),
            sponsor_max_total_fee: Some(policy_fee),
            fee: options.fee,
            mine_blocks: options.mine_blocks,
        },
    )?;
    let spare_sponsor_out_point = printable_out_point_string(&spare_sponsor.sponsor_out_point);

    let pending_publish = publish_state(
        rpc,
        PublishStateOptions {
            contracts_dir: options.contracts_dir.clone(),
            private_key: options.private_key.clone(),
            alice_private_key: options.alice_private_key.clone(),
            bob_private_key: options.bob_private_key.clone(),
            state_out_point: initial_state_out_point.clone(),
            sponsor_out_point: initial_sponsor_out_point,
            state_number: Some(1),
            state_package: None,
            fee: options.fee,
            mine_blocks: 0,
        },
    )?;
    ensure!(
        pending_publish.status != "Committed",
        "pending publication unexpectedly committed before a block was generated"
    );

    let rejection = match publish_state(
        rpc,
        PublishStateOptions {
            contracts_dir: options.contracts_dir.clone(),
            private_key: options.private_key.clone(),
            alice_private_key: options.alice_private_key.clone(),
            bob_private_key: options.bob_private_key.clone(),
            state_out_point: initial_state_out_point.clone(),
            sponsor_out_point: spare_sponsor_out_point.clone(),
            state_number: Some(2),
            state_package: None,
            fee: options.fee,
            mine_blocks: 0,
        },
    ) {
        Ok(report) => {
            return Err(anyhow!(
                "competing state publication unexpectedly entered tx-pool in tx {}",
                report.tx_hash
            ));
        }
        Err(err) => err.to_string(),
    };

    let pending_commit =
        mine_pending_transaction(rpc, &pending_publish.tx_hash, options.mine_blocks)?;
    let live_settling_state_out_point =
        printable_out_point_string(&pending_publish.state_out_point);
    let rebuilt_publish = publish_state(
        rpc,
        PublishStateOptions {
            contracts_dir: options.contracts_dir.clone(),
            private_key: options.private_key.clone(),
            alice_private_key: options.alice_private_key.clone(),
            bob_private_key: options.bob_private_key.clone(),
            state_out_point: live_settling_state_out_point.clone(),
            sponsor_out_point: spare_sponsor_out_point,
            state_number: Some(2),
            state_package: None,
            fee: options.fee,
            mine_blocks: options.mine_blocks,
        },
    )?;
    let finalise_state_out_point = printable_out_point_string(&rebuilt_publish.state_out_point);
    let finalise = finalise_channel(
        rpc,
        FinaliseChannelOptions {
            contracts_dir: options.contracts_dir,
            private_key: options.private_key,
            alice_private_key: options.alice_private_key,
            bob_private_key: options.bob_private_key,
            state_out_point: finalise_state_out_point,
            vault_out_point,
            alice_capacity: options.alice_capacity,
            bob_capacity: options.bob_capacity,
            finalise_since: options.finalise_since,
            fee: options.fee,
            mine_blocks: options.mine_blocks,
        },
    )?;

    Ok(CompetingSpendSmokeReport {
        open,
        spare_sponsor,
        pending_publish,
        pending_commit,
        rejected_state_number: 2,
        rejected_against_state_out_point: initial_state_out_point,
        rejection,
        rebuilt_publish,
        finalise,
    })
}

fn build_deploy_transaction(
    funding_cell: &LiveCell,
    secp_dep: CellDep,
    owner_lock: &Script,
    contracts: &[ContractBinary],
    change_capacity: u64,
) -> ckb_types::core::TransactionView {
    let mut builder = TransactionBuilder::default()
        .cell_dep(secp_dep)
        .input(CellInput::new(funding_cell.out_point.clone(), 0));

    for contract in contracts {
        builder = builder
            .output(contract.output.clone())
            .output_data(contract.data.clone().pack());
    }

    let change_output = CellOutput::new_builder()
        .capacity(change_capacity)
        .lock(owner_lock.clone())
        .build();

    builder
        .output(change_output)
        .output_data(Bytes::new().pack())
        .build()
}

fn sign_single_secp_input(
    tx: ckb_types::core::TransactionView,
    privkey: &Privkey,
) -> Result<ckb_types::core::TransactionView> {
    let placeholder = WitnessArgs::new_builder()
        .lock(Some(Bytes::from(vec![0u8; 65])))
        .build();
    let message = sighash_all_message(tx.hash(), &[placeholder.as_bytes()]);
    let signature = privkey
        .sign_recoverable(&message)
        .context("failed to sign CKB transaction")?;
    let witness = WitnessArgs::new_builder()
        .lock(Some(Bytes::from(signature.serialize())))
        .build();
    Ok(tx.as_advanced_builder().witness(witness.as_bytes()).build())
}

fn sign_factory_update_transaction(
    tx: ckb_types::core::TransactionView,
    privkey: &Privkey,
    input_type: Bytes,
) -> Result<ckb_types::core::TransactionView> {
    let placeholder_factory_witness = WitnessArgs::new_builder()
        .lock(Some(Bytes::from(vec![0u8; 65])))
        .input_type(Some(input_type.clone()).pack())
        .build();
    let placeholder_fee_witness = WitnessArgs::default();
    let message = sighash_all_message(
        tx.hash(),
        &[
            placeholder_factory_witness.as_bytes(),
            placeholder_fee_witness.as_bytes(),
        ],
    );
    let signature = privkey
        .sign_recoverable(&message)
        .context("failed to sign CKB factory update transaction")?;
    let factory_witness = WitnessArgs::new_builder()
        .lock(Some(Bytes::from(signature.serialize())))
        .input_type(Some(input_type).pack())
        .build();
    Ok(tx
        .as_advanced_builder()
        .witness(factory_witness.as_bytes())
        .witness(placeholder_fee_witness.as_bytes())
        .build())
}

fn sign_factory_exit_transaction(
    tx: ckb_types::core::TransactionView,
    privkey: &Privkey,
    input_type: Bytes,
) -> Result<ckb_types::core::TransactionView> {
    let placeholder_factory_witness = WitnessArgs::new_builder()
        .lock(Some(Bytes::from(vec![0u8; 65])))
        .input_type(Some(input_type.clone()).pack())
        .build();
    let factory_vault_witness = WitnessArgs::new_builder()
        .input_type(Some(input_type.clone()).pack())
        .build();
    let placeholder_fee_witness = WitnessArgs::default();
    let message = sighash_all_message(
        tx.hash(),
        &[
            placeholder_factory_witness.as_bytes(),
            placeholder_fee_witness.as_bytes(),
        ],
    );
    let signature = privkey
        .sign_recoverable(&message)
        .context("failed to sign CKB factory exit transaction")?;
    let factory_witness = WitnessArgs::new_builder()
        .lock(Some(Bytes::from(signature.serialize())))
        .input_type(Some(input_type).pack())
        .build();
    Ok(tx
        .as_advanced_builder()
        .witness(factory_witness.as_bytes())
        .witness(factory_vault_witness.as_bytes())
        .witness(placeholder_fee_witness.as_bytes())
        .build())
}

fn send_and_mine(
    rpc: &CkbRpcClient,
    tx: ckb_types::core::TransactionView,
    mine_blocks: u64,
) -> Result<SentTransactionReport> {
    let metrics = transaction_metrics(rpc, &tx)?;
    let tx_hash = tx.hash();
    let json_tx: ckb_jsonrpc_types::Transaction = tx.data().into();
    let sent_hash = rpc.send_transaction(json_tx)?;
    ensure!(
        sent_hash == tx_hash.clone().into(),
        "node returned tx hash {sent_hash:#x}, but locally built {:#x}",
        H256::from(tx_hash)
    );

    let mut mined_blocks = Vec::new();
    for _ in 0..mine_blocks {
        mined_blocks.push(rpc.generate_block()?);
        let status = rpc.transaction(sent_hash.clone())?;
        if status.tx_status.status == Status::Committed {
            break;
        }
    }
    let status = if mine_blocks > 0 {
        rpc.wait_transaction_committed(
            sent_hash.clone(),
            Duration::from_secs(30),
            Duration::from_millis(500),
        )?
    } else {
        rpc.transaction(sent_hash.clone())?
    };

    Ok(SentTransactionReport {
        tx_hash: format!("{sent_hash:#x}"),
        status: format!("{:?}", status.tx_status.status),
        block_number: status.tx_status.block_number.map(|number| number.value()),
        block_hash: status.tx_status.block_hash.map(|hash| format!("{hash:#x}")),
        metrics,
        mined_blocks,
    })
}

fn mine_pending_transaction(
    rpc: &CkbRpcClient,
    tx_hash: &str,
    mine_blocks: u64,
) -> Result<PendingCommitReport> {
    let parsed = parse_h256(tx_hash)?;
    let mut mined_blocks = Vec::new();
    for _ in 0..mine_blocks {
        mined_blocks.push(rpc.generate_block()?);
        let status = rpc.transaction(parsed.clone())?;
        if status.tx_status.status == Status::Committed {
            break;
        }
    }
    let status = rpc.wait_transaction_committed(
        parsed,
        Duration::from_secs(30),
        Duration::from_millis(500),
    )?;
    Ok(PendingCommitReport {
        tx_hash: tx_hash.to_string(),
        status: format!("{:?}", status.tx_status.status),
        block_number: status.tx_status.block_number.map(|number| number.value()),
        block_hash: status.tx_status.block_hash.map(|hash| format!("{hash:#x}")),
        mined_blocks,
    })
}

fn transaction_metrics(
    rpc: &CkbRpcClient,
    tx: &ckb_types::core::TransactionView,
) -> Result<TransactionMetrics> {
    let json_tx: ckb_jsonrpc_types::Transaction = tx.data().into();
    let estimate = rpc.estimate_cycles(json_tx)?;
    Ok(TransactionMetrics {
        estimated_cycles: estimate.cycles.value(),
        tx_size_bytes: tx.data().as_slice().len(),
    })
}

fn observed_state_cells(
    block: &ckb_jsonrpc_types::BlockView,
    channel_id: &str,
    tip_number: u64,
) -> Result<Vec<ObservedStateCellReport>> {
    let block_number = block.header.inner.number.value();
    let block_hash = format!("{:#x}", block.header.hash);
    let confirmations = tip_number.saturating_sub(block_number).saturating_add(1);
    let mut observed = Vec::new();
    for tx in &block.transactions {
        for (index, data) in tx.inner.outputs_data.iter().enumerate() {
            let Ok(header) = StateHeaderV1::parse(data.as_bytes()) else {
                continue;
            };
            if hex32(header.channel_id()) != channel_id {
                continue;
            }
            let tx_hash = format!("{:#x}", tx.hash);
            observed.push(ObservedStateCellReport {
                block_number,
                block_hash: block_hash.clone(),
                tx_hash: tx_hash.clone(),
                output_index: index as u32,
                out_point: format!("{tx_hash}:{index}"),
                state_number: header.state_number(),
                phase: phase_label(header.phase()).to_string(),
                confirmations,
            });
        }
    }
    Ok(observed)
}

fn phase_label(phase: u8) -> &'static str {
    match phase {
        PHASE_ACTIVE => "active",
        PHASE_SETTLING => "settling",
        _ => "unknown",
    }
}

fn sighash_all_message(
    tx_hash: ckb_types::packed::Byte32,
    witnesses: &[Bytes],
) -> ckb_crypto::secp::Message {
    let mut hasher = new_blake2b();
    hasher.update(tx_hash.as_slice());
    for witness in witnesses {
        let witness = witness.as_ref();
        let witness_len = witness.len() as u64;
        hasher.update(&witness_len.to_le_bytes());
        hasher.update(witness);
    }
    let mut digest = [0u8; 32];
    hasher.finalize(&mut digest);
    digest.into()
}

fn load_contracts(contracts_dir: &Path, owner_lock: &Script) -> Result<Vec<ContractBinary>> {
    CONTRACTS
        .iter()
        .map(|(name, file_name)| {
            let path = contracts_dir.join(file_name);
            let data = fs::read(&path)
                .with_context(|| format!("failed to read contract binary {}", path.display()))?;
            ensure!(
                !data.is_empty(),
                "contract binary {} is empty",
                path.display()
            );
            let data_hash = H256::from(blake2b_256(&data));
            let data = Bytes::from(data);
            let output_for_capacity = CellOutput::new_builder().lock(owner_lock.clone()).build();
            let capacity = output_for_capacity
                .occupied_capacity(Capacity::bytes(data.len())?)?
                .as_u64();
            let output = CellOutput::new_builder()
                .capacity(capacity)
                .lock(owner_lock.clone())
                .build();
            Ok(ContractBinary {
                name: (*name).to_string(),
                data,
                data_hash,
                capacity,
                output,
            })
        })
        .collect()
}

fn load_contract_targets(contracts_dir: &Path) -> Result<Vec<ContractTarget>> {
    CONTRACTS
        .iter()
        .map(|(name, file_name)| {
            let path = contracts_dir.join(file_name);
            let data = fs::read(&path)
                .with_context(|| format!("failed to read contract binary {}", path.display()))?;
            ensure!(
                !data.is_empty(),
                "contract binary {} is empty",
                path.display()
            );
            Ok(ContractTarget {
                name: (*name).to_string(),
                data_hash: H256::from(blake2b_256(&data)),
            })
        })
        .collect()
}

fn find_deployed_contracts(
    rpc: &CkbRpcClient,
    contracts_dir: &Path,
    tip_number: u64,
) -> Result<Vec<ResolvedContract>> {
    let targets = load_contract_targets(contracts_dir)?;
    let mut found: Vec<Option<OutPoint>> = vec![None; targets.len()];

    for number in 0..=tip_number {
        let Some(block) = rpc.block_by_number(number)? else {
            continue;
        };
        for tx in block.transactions {
            for (index, data) in tx.inner.outputs_data.iter().enumerate() {
                let data_hash = H256::from(blake2b_256(data.as_bytes()));
                for (target_index, target) in targets.iter().enumerate() {
                    if data_hash != target.data_hash {
                        continue;
                    }
                    let out_point = OutPoint::new(tx.hash.pack(), index as u32);
                    let live = rpc.live_cell(out_point.clone().into(), false)?;
                    if live.status == "live" {
                        found[target_index] = Some(out_point);
                    }
                }
            }
        }
    }

    targets
        .into_iter()
        .zip(found)
        .map(|(target, out_point)| {
            let out_point = out_point.ok_or_else(|| {
                anyhow!(
                    "contract {} with data hash {:#x} is not deployed as a live cell; run `morph devnet deploy-contracts` first",
                    target.name,
                    target.data_hash
                )
            })?;
            Ok(ResolvedContract {
                name: target.name,
                data_hash: target.data_hash,
                cell_dep: CellDep::new_builder()
                    .out_point(out_point.clone())
                    .dep_type(DepType::Code)
                    .build(),
                out_point,
            })
        })
        .collect()
}

fn contract_by_name(contracts: &[ResolvedContract], name: &str) -> Result<ResolvedContract> {
    contracts
        .iter()
        .find(|contract| contract.name == name)
        .cloned()
        .ok_or_else(|| anyhow!("resolved contract {name} is missing"))
}

fn ensure_change_capacity(owner_lock: &Script, change_capacity: u64) -> Result<()> {
    let output = CellOutput::new_builder()
        .capacity(change_capacity)
        .lock(owner_lock.clone())
        .build();
    let occupied = output.occupied_capacity(Capacity::zero())?.as_u64();
    ensure!(
        change_capacity >= occupied,
        "change capacity {} is below occupied capacity {}",
        change_capacity,
        occupied
    );
    Ok(())
}

fn find_largest_live_cell(
    rpc: &CkbRpcClient,
    owner_lock: &Script,
    tip_number: u64,
) -> Result<LiveCell> {
    let mut best: Option<LiveCell> = None;

    for number in 0..=tip_number {
        let Some(block) = rpc.block_by_number(number)? else {
            continue;
        };
        for tx in block.transactions {
            for (index, output) in tx.inner.outputs.iter().enumerate() {
                let packed_output: CellOutput = output.clone().into();
                if packed_output.lock() != *owner_lock {
                    continue;
                }
                if packed_output.type_().to_opt().is_some() {
                    continue;
                }
                let out_point = OutPoint::new(tx.hash.pack(), index as u32);
                let live = rpc.live_cell(out_point.clone().into(), true)?;
                if live.status != "live" {
                    continue;
                }
                let Some(cell) = &live.cell else {
                    continue;
                };
                if cell
                    .data
                    .as_ref()
                    .is_some_and(|data| !data.content.is_empty())
                {
                    continue;
                }
                let capacity = output.capacity.value();
                if best.as_ref().is_none_or(|cell| capacity > cell.capacity) {
                    best = Some(LiveCell {
                        out_point,
                        capacity,
                    });
                }
            }
        }
    }

    best.ok_or_else(|| anyhow!("no live devnet funding cell found for the derived secp256k1 lock"))
}

fn load_live_cell(rpc: &CkbRpcClient, out_point: OutPoint) -> Result<LiveCellDetails> {
    let live = rpc.live_cell(out_point.clone().into(), true)?;
    ensure!(
        live.status == "live",
        "cell {} is not live; status={}",
        format_out_point(&out_point),
        live.status
    );
    let cell = live.cell.ok_or_else(|| {
        anyhow!(
            "RPC did not return live cell data for {}",
            format_out_point(&out_point)
        )
    })?;
    let output: CellOutput = cell.output.into();
    let data = cell
        .data
        .map(|data| data.content.into_bytes())
        .unwrap_or_default();
    let capacity = output.capacity().unpack();
    Ok(LiveCellDetails {
        output,
        data,
        capacity,
    })
}

fn find_secp256k1_cell_dep(rpc: &CkbRpcClient) -> Result<CellDep> {
    let secp_type_hash = parse_h256(DEFAULT_SECP_TYPE_HASH)?;
    let genesis = rpc
        .block_by_number(0)?
        .ok_or_else(|| anyhow!("genesis block is not available from CKB RPC"))?;

    let mut secp_code_out_point = None;
    for tx in &genesis.transactions {
        for (index, output) in tx.inner.outputs.iter().enumerate() {
            let packed_output: CellOutput = output.clone().into();
            let Some(type_script) = packed_output.type_().to_opt() else {
                continue;
            };
            let type_hash = byte32_to_h256(type_script.calc_script_hash());
            if type_hash == secp_type_hash {
                secp_code_out_point = Some(OutPoint::new(tx.hash.pack(), index as u32));
                break;
            }
        }
    }

    let secp_code_out_point = secp_code_out_point
        .ok_or_else(|| anyhow!("could not find secp256k1_blake160_sighash_all system cell"))?;

    for tx in genesis.transactions {
        for (index, data) in tx.inner.outputs_data.iter().enumerate() {
            let raw = data.clone().into_bytes();
            let Ok(group) = OutPointVec::from_slice(raw.as_ref()) else {
                continue;
            };
            if group
                .into_iter()
                .any(|out_point| out_point == secp_code_out_point)
            {
                return Ok(CellDep::new_builder()
                    .out_point(OutPoint::new(tx.hash.pack(), index as u32))
                    .dep_type(DepType::DepGroup)
                    .build());
            }
        }
    }

    Ok(CellDep::new_builder()
        .out_point(secp_code_out_point)
        .dep_type(DepType::Code)
        .build())
}

fn secp256k1_lock(privkey: &Privkey) -> Result<Script> {
    let pubkey = privkey.pubkey().context("failed to derive public key")?;
    let args = blake160(&pubkey.serialize());
    Ok(Script::new_builder()
        .code_hash(parse_h256(DEFAULT_SECP_TYPE_HASH)?.pack())
        .hash_type(ScriptHashType::Type)
        .args(Bytes::copy_from_slice(&args).pack())
        .build())
}

fn compressed_pubkey(privkey: &Privkey) -> Result<[u8; 33]> {
    let pubkey = privkey.pubkey().context("failed to derive public key")?;
    let serialized = pubkey.serialize();
    let mut out = [0u8; 33];
    out.copy_from_slice(&serialized);
    Ok(out)
}

fn k256_signing_key(value: &str) -> Result<SigningKey> {
    let raw = hex::decode(value.strip_prefix("0x").unwrap_or(value))
        .with_context(|| "private key must be hex encoded")?;
    ensure!(raw.len() == 32, "private key must be 32 bytes");
    SigningKey::from_slice(&raw).map_err(|err| anyhow!("invalid secp256k1 private key: {err:?}"))
}

fn k256_pubkey(key: &SigningKey) -> [u8; COMPRESSED_SECP256K1_PUBKEY_LEN] {
    let encoded = key.verifying_key().to_encoded_point(true);
    let mut out = [0u8; COMPRESSED_SECP256K1_PUBKEY_LEN];
    out.copy_from_slice(encoded.as_bytes());
    out
}

fn ecdsa_signature(key: &SigningKey, digest: &[u8; 32]) -> Result<[u8; ECDSA_SIGNATURE_LEN]> {
    let sig: Signature = key
        .sign_prehash(digest)
        .map_err(|err| anyhow!("failed to sign state digest: {err:?}"))?;
    let mut out = [0u8; ECDSA_SIGNATURE_LEN];
    out.copy_from_slice(sig.to_bytes().as_slice());
    Ok(out)
}

fn bilateral_signature_witness(
    state_header: &[u8],
    alice_private_key: &str,
    bob_private_key: &str,
) -> Result<[u8; BILATERAL_SIGNATURE_WITNESS_V1_LEN]> {
    let header = StateHeaderV1::parse(state_header)
        .map_err(|err| anyhow!("new state header is invalid: {err:?}"))?;
    let alice_key = k256_signing_key(alice_private_key)?;
    let bob_key = k256_signing_key(bob_private_key)?;
    let mut entries = [
        (k256_pubkey(&alice_key), alice_key),
        (k256_pubkey(&bob_key), bob_key),
    ];
    entries.sort_by(|left, right| left.0.cmp(&right.0));

    let digest = header.signing_digest();
    let mut witness = [0u8; BILATERAL_SIGNATURE_WITNESS_V1_LEN];
    put_u16(&mut witness, 0, BILATERAL_SIGNATURE_WITNESS_VERSION_V1);
    witness[2] = BILATERAL_SIGNATURE_THRESHOLD_V1;
    witness[3] = BILATERAL_SIGNATURE_COUNT_V1;
    for (index, (pubkey, key)) in entries.iter().enumerate() {
        let offset = 4 + index * (COMPRESSED_SECP256K1_PUBKEY_LEN + ECDSA_SIGNATURE_LEN);
        witness[offset..offset + COMPRESSED_SECP256K1_PUBKEY_LEN].copy_from_slice(pubkey);
        witness[offset + COMPRESSED_SECP256K1_PUBKEY_LEN
            ..offset + COMPRESSED_SECP256K1_PUBKEY_LEN + ECDSA_SIGNATURE_LEN]
            .copy_from_slice(&ecdsa_signature(key, &digest)?);
    }
    Ok(witness)
}

fn factory_signature_witness(
    factory_header: &[u8],
    alice_private_key: &str,
    bob_private_key: &str,
) -> Result<[u8; FACTORY_SIGNATURE_WITNESS_V1_LEN]> {
    let header = FactoryStateHeaderV1::parse(factory_header)
        .map_err(|err| anyhow!("new factory header is invalid: {err:?}"))?;
    let alice_key = k256_signing_key(alice_private_key)?;
    let bob_key = k256_signing_key(bob_private_key)?;
    let mut entries = [
        ([1u8; BYTE32_LEN], k256_pubkey(&alice_key), alice_key),
        ([2u8; BYTE32_LEN], k256_pubkey(&bob_key), bob_key),
    ];
    entries.sort_by(|left, right| left.0.cmp(&right.0));

    let digest = header.signing_digest();
    let mut witness = [0u8; FACTORY_SIGNATURE_WITNESS_V1_LEN];
    put_u16(&mut witness, 0, FACTORY_SIGNATURE_WITNESS_VERSION_V1);
    witness[2] = FACTORY_SIGNATURE_THRESHOLD_V1;
    witness[3] = FACTORY_SIGNATURE_COUNT_V1;
    for (index, (participant, pubkey, key)) in entries.iter().enumerate() {
        let offset =
            4 + index * (BYTE32_LEN + COMPRESSED_SECP256K1_PUBKEY_LEN + ECDSA_SIGNATURE_LEN);
        witness[offset..offset + BYTE32_LEN].copy_from_slice(participant);
        witness[offset + BYTE32_LEN..offset + BYTE32_LEN + COMPRESSED_SECP256K1_PUBKEY_LEN]
            .copy_from_slice(pubkey);
        witness[offset + BYTE32_LEN + COMPRESSED_SECP256K1_PUBKEY_LEN
            ..offset + BYTE32_LEN + COMPRESSED_SECP256K1_PUBKEY_LEN + ECDSA_SIGNATURE_LEN]
            .copy_from_slice(&ecdsa_signature(key, &digest)?);
    }
    Ok(witness)
}

#[allow(clippy::too_many_arguments)]
fn factory_local_exit_witness(
    factory_signature: &[u8],
    state_output_index: u32,
    vault_output_index: u32,
    state_type_hash: &[u8],
    vault_lock_hash: &[u8],
    state_lock_hash: &[u8],
    state_header: &[u8],
    descriptor: &[u8],
) -> Result<Vec<u8>> {
    ensure!(
        factory_signature.len() == FACTORY_SIGNATURE_WITNESS_V1_LEN,
        "factory signature witness must be {} bytes",
        FACTORY_SIGNATURE_WITNESS_V1_LEN
    );
    ensure!(
        state_type_hash.len() == BYTE32_LEN,
        "state type hash must be 32 bytes"
    );
    ensure!(
        vault_lock_hash.len() == BYTE32_LEN,
        "vault lock hash must be 32 bytes"
    );
    ensure!(
        state_lock_hash.len() == BYTE32_LEN,
        "state lock hash must be 32 bytes"
    );
    ensure!(
        state_header.len() == STATE_HEADER_V1_LEN,
        "exit state header must be {} bytes",
        STATE_HEADER_V1_LEN
    );
    ensure!(
        descriptor.len() == BILATERAL_CKB_DESCRIPTOR_V1_LEN
            || descriptor.len() == BILATERAL_CKB_XUDT_DESCRIPTOR_V1_LEN,
        "settlement descriptor must be {} or {} bytes",
        BILATERAL_CKB_DESCRIPTOR_V1_LEN,
        BILATERAL_CKB_XUDT_DESCRIPTOR_V1_LEN
    );

    let mut witness = vec![
        0u8;
        FACTORY_LOCAL_EXIT_WITNESS_V1_LEN - BILATERAL_CKB_DESCRIPTOR_V1_LEN
            + descriptor.len()
    ];
    put_u16(&mut witness, 0, FACTORY_LOCAL_EXIT_WITNESS_VERSION_V1);
    let mut offset = 2;
    witness[offset..offset + FACTORY_SIGNATURE_WITNESS_V1_LEN].copy_from_slice(factory_signature);
    offset += FACTORY_SIGNATURE_WITNESS_V1_LEN;
    put_u32(&mut witness, offset, state_output_index);
    offset += 4;
    put_u32(&mut witness, offset, vault_output_index);
    offset += 4;
    witness[offset..offset + BYTE32_LEN].copy_from_slice(state_type_hash);
    offset += BYTE32_LEN;
    witness[offset..offset + BYTE32_LEN].copy_from_slice(vault_lock_hash);
    offset += BYTE32_LEN;
    witness[offset..offset + BYTE32_LEN].copy_from_slice(state_lock_hash);
    offset += BYTE32_LEN;
    witness[offset..offset + STATE_HEADER_V1_LEN].copy_from_slice(state_header);
    offset += STATE_HEADER_V1_LEN;
    witness[offset..offset + descriptor.len()].copy_from_slice(descriptor);
    Ok(witness)
}

fn witness_with_input_type(input_type: Bytes) -> ckb_types::packed::Bytes {
    WitnessArgs::new_builder()
        .input_type(Some(input_type).pack())
        .build()
        .as_bytes()
        .pack()
}

fn empty_witness() -> ckb_types::packed::Bytes {
    WitnessArgs::default().as_bytes().pack()
}

fn data1_script(code_hash: H256, args: Bytes) -> Script {
    Script::new_builder()
        .code_hash(code_hash.pack())
        .hash_type(ScriptHashType::Data1)
        .args(args.pack())
        .build()
}

fn derive_funding_anchor(input: &CellInput, output_index: u64) -> [u8; 32] {
    script_blake2b256(&[input.as_slice(), &output_index.to_le_bytes()])
}

fn sponsor_policy_settings(
    sponsor_capacity: u64,
    min_state_number: u64,
    max_state_number: u64,
    max_fee_per_tx: Option<u64>,
    max_total_fee: Option<u64>,
) -> Result<SponsorPolicySettings> {
    ensure!(
        min_state_number <= max_state_number,
        "sponsor min state number must be <= max state number"
    );
    let max_total_fee = max_total_fee.unwrap_or(sponsor_capacity);
    let default_max_fee_per_tx = (sponsor_capacity / 2).max(1);
    let max_fee_per_tx = max_fee_per_tx.unwrap_or(default_max_fee_per_tx);
    ensure!(
        max_fee_per_tx > 0,
        "sponsor max fee per tx must be non-zero"
    );
    ensure!(max_total_fee > 0, "sponsor max total fee must be non-zero");
    ensure!(
        max_fee_per_tx <= max_total_fee,
        "sponsor max fee per tx cannot exceed max total fee"
    );
    ensure!(
        max_total_fee <= sponsor_capacity,
        "sponsor max total fee cannot exceed sponsor capacity"
    );
    Ok(SponsorPolicySettings {
        min_state_number,
        max_state_number,
        max_fee_per_tx,
        max_total_fee,
    })
}

fn sponsor_policy_bytes(
    channel_id: &[u8; 32],
    settings: SponsorPolicySettings,
    publication_state_type_hash: [u8; 32],
    change_lock_hash: [u8; 32],
) -> [u8; SPONSOR_POLICY_V1_LEN] {
    let mut raw = [0u8; SPONSOR_POLICY_V1_LEN];
    raw[0..32].copy_from_slice(channel_id);
    put_u64(&mut raw, 32, settings.min_state_number);
    put_u64(&mut raw, 40, settings.max_state_number);
    put_u64(&mut raw, 48, settings.max_fee_per_tx);
    put_u64(&mut raw, 56, settings.max_total_fee);
    put_u64(&mut raw, 64, 0);
    put_u64(&mut raw, 72, u64::MAX);
    raw[80..112].copy_from_slice(&publication_state_type_hash);
    raw[112..144].copy_from_slice(&change_lock_hash);
    raw
}

fn sponsor_policy_report(
    settings: SponsorPolicySettings,
    publication_state_type_hash: [u8; 32],
    change_lock_hash: [u8; 32],
) -> SponsorPolicyReport {
    SponsorPolicyReport {
        min_state_number: settings.min_state_number,
        max_state_number: settings.max_state_number,
        max_fee_per_tx: settings.max_fee_per_tx,
        max_total_fee: settings.max_total_fee,
        already_spent: 0,
        expiry: u64::MAX,
        publication_state_type_hash: hex32(&publication_state_type_hash),
        change_lock_hash: hex32(&change_lock_hash),
    }
}

fn bilateral_ckb_descriptor(
    left_lock_hash: [u8; 32],
    left_capacity: u64,
    right_lock_hash: [u8; 32],
    right_capacity: u64,
) -> [u8; BILATERAL_CKB_DESCRIPTOR_V1_LEN] {
    let mut entries = [
        (left_lock_hash, left_capacity),
        (right_lock_hash, right_capacity),
    ];
    entries.sort_by(|left, right| left.0.cmp(&right.0));

    let mut raw = [0u8; BILATERAL_CKB_DESCRIPTOR_V1_LEN];
    put_u16(&mut raw, 0, BILATERAL_CKB_DESCRIPTOR_VERSION_V1);
    raw[2] = BILATERAL_CKB_DESCRIPTOR_OUTPUT_COUNT_V1;
    raw[3] = 0;
    for (index, (lock_hash, capacity)) in entries.iter().enumerate() {
        let offset = 4 + index * (BYTE32_LEN + 8);
        raw[offset..offset + BYTE32_LEN].copy_from_slice(lock_hash);
        put_u64(&mut raw, offset + BYTE32_LEN, *capacity);
    }
    raw
}

fn bilateral_ckb_xudt_descriptor(
    xudt_type_hash: [u8; 32],
    left_lock_hash: [u8; 32],
    left_capacity: u64,
    left_amount: u128,
    right_lock_hash: [u8; 32],
    right_capacity: u64,
    right_amount: u128,
) -> [u8; BILATERAL_CKB_XUDT_DESCRIPTOR_V1_LEN] {
    let mut entries = [
        (left_lock_hash, left_capacity, left_amount),
        (right_lock_hash, right_capacity, right_amount),
    ];
    entries.sort_by(|left, right| left.0.cmp(&right.0));

    let mut raw = [0u8; BILATERAL_CKB_XUDT_DESCRIPTOR_V1_LEN];
    put_u16(&mut raw, 0, BILATERAL_CKB_XUDT_DESCRIPTOR_VERSION_V1);
    raw[2] = BILATERAL_CKB_DESCRIPTOR_OUTPUT_COUNT_V1;
    raw[3] = BILATERAL_CKB_XUDT_DESCRIPTOR_ASSET_COUNT_V1;
    raw[4..36].copy_from_slice(&xudt_type_hash);
    for (index, (lock_hash, capacity, amount)) in entries.iter().enumerate() {
        let offset = 36 + index * (BYTE32_LEN + 8 + 16);
        raw[offset..offset + BYTE32_LEN].copy_from_slice(lock_hash);
        put_u64(&mut raw, offset + BYTE32_LEN, *capacity);
        put_u128(&mut raw, offset + BYTE32_LEN + 8, *amount);
    }
    raw
}

fn xudt_amount_bytes(amount: u128) -> Bytes {
    Bytes::copy_from_slice(&amount.to_le_bytes())
}

fn xudt_amount_from_data(data: &Bytes) -> Result<u128> {
    ensure!(data.len() == 16, "xUDT cell data must be exactly 16 bytes");
    let mut raw = [0u8; 16];
    raw.copy_from_slice(data.as_ref());
    Ok(u128::from_le_bytes(raw))
}

fn settlement_split(
    vault_capacity: u64,
    alice_capacity: Option<u64>,
    bob_capacity: Option<u64>,
) -> Result<(u64, u64)> {
    match (alice_capacity, bob_capacity) {
        (None, None) => {
            let alice = vault_capacity.saturating_mul(6) / 10;
            let bob = vault_capacity
                .checked_sub(alice)
                .ok_or_else(|| anyhow!("vault capacity split underflow"))?;
            Ok((alice, bob))
        }
        (Some(alice), Some(bob)) => {
            ensure!(
                alice.checked_add(bob) == Some(vault_capacity),
                "alice capacity plus bob capacity must equal vault capacity"
            );
            Ok((alice, bob))
        }
        _ => Err(anyhow!(
            "alice and bob capacities must either both be provided or both be omitted"
        )),
    }
}

struct InitialStateHeader {
    chain_id: [u8; 32],
    channel_id: [u8; 32],
    funding_anchor: [u8; 32],
    participants_commitment: [u8; 32],
    settlement_descriptor_commitment: [u8; 32],
    descriptor_version: u16,
    challenge_policy_commitment: [u8; 32],
}

struct FactoryHeaderInput {
    chain_id: [u8; 32],
    factory_id: [u8; 32],
    update_number: u64,
    state_root: [u8; 32],
    participants_commitment: [u8; 32],
    access_manifest_root: [u8; 32],
    non_interference_digest: [u8; 32],
    challenge_policy_commitment: [u8; 32],
}

fn initial_state_header(input: InitialStateHeader) -> [u8; STATE_HEADER_V1_LEN] {
    let mut raw = [0u8; STATE_HEADER_V1_LEN];
    put_u16(&mut raw, 0, 1);
    raw[2..34].copy_from_slice(&input.chain_id);
    put_u16(&mut raw, 34, SIGNATURE_SCHEME_SECP256K1_ECDSA_BLAKE2B_V1);
    raw[36..68].copy_from_slice(&input.channel_id);
    raw[68..100].copy_from_slice(&input.funding_anchor);
    put_u64(&mut raw, 100, 0);
    raw[108] = 0;
    raw[109] = PHASE_ACTIVE;
    raw[110..142].copy_from_slice(&input.participants_commitment);
    raw[142..174].copy_from_slice(&script_blake2b256(&[b"CKB_MORPH_EMPTY_ASSET_REGISTRY_V1"]));
    raw[174..206].copy_from_slice(&input.settlement_descriptor_commitment);
    put_u16(&mut raw, 206, input.descriptor_version);
    raw[208..240].copy_from_slice(&script_blake2b256(&[
        b"CKB_MORPH_EMPTY_BILATERAL_PAYLOAD_V1",
    ]));
    raw[240..272].copy_from_slice(&input.challenge_policy_commitment);
    put_u16(&mut raw, 272, 1);
    raw
}

fn factory_state_header(input: FactoryHeaderInput) -> [u8; FACTORY_STATE_HEADER_V1_LEN] {
    let mut raw = [0u8; FACTORY_STATE_HEADER_V1_LEN];
    put_u16(&mut raw, 0, 1);
    raw[2..34].copy_from_slice(&input.chain_id);
    put_u16(&mut raw, 34, SIGNATURE_SCHEME_SECP256K1_ECDSA_BLAKE2B_V1);
    raw[36..68].copy_from_slice(&input.factory_id);
    put_u64(&mut raw, 68, input.update_number);
    raw[76..108].copy_from_slice(&input.state_root);
    raw[108..140].copy_from_slice(&input.participants_commitment);
    raw[140..172].copy_from_slice(&input.access_manifest_root);
    raw[172..204].copy_from_slice(&input.non_interference_digest);
    raw[204..236].copy_from_slice(&input.challenge_policy_commitment);
    put_u16(&mut raw, 236, 1);
    raw
}

fn factory_participants_commitment_from_pubkeys(
    alice_pubkey: [u8; COMPRESSED_SECP256K1_PUBKEY_LEN],
    bob_pubkey: [u8; COMPRESSED_SECP256K1_PUBKEY_LEN],
) -> [u8; 32] {
    let mut entries = [
        ([1u8; BYTE32_LEN], alice_pubkey),
        ([2u8; BYTE32_LEN], bob_pubkey),
    ];
    entries.sort_by(|left, right| left.0.cmp(&right.0));
    factory_participants_commitment_v1(
        FACTORY_SIGNATURE_THRESHOLD_V1,
        &[
            (entries[0].0.as_slice(), entries[0].1.as_slice()),
            (entries[1].0.as_slice(), entries[1].1.as_slice()),
        ],
    )
}

fn factory_participant_reports(
    alice_pubkey: [u8; COMPRESSED_SECP256K1_PUBKEY_LEN],
    bob_pubkey: [u8; COMPRESSED_SECP256K1_PUBKEY_LEN],
) -> Vec<FactoryParticipantReport> {
    let mut entries = [
        ("alice", [1u8; BYTE32_LEN], alice_pubkey),
        ("bob", [2u8; BYTE32_LEN], bob_pubkey),
    ];
    entries.sort_by(|left, right| left.1.cmp(&right.1));
    entries
        .into_iter()
        .map(|(role, participant_id, pubkey)| FactoryParticipantReport {
            role: role.to_string(),
            participant_id: hex32(&participant_id),
            pubkey_sec1: hex_prefixed(&pubkey),
        })
        .collect()
}

fn derived_factory_update_digest(
    domain: &[u8],
    previous_value: &[u8],
    update_number: u64,
) -> [u8; 32] {
    script_blake2b256(&[domain, previous_value, &update_number.to_le_bytes()])
}

fn occupied_capacity(output: &CellOutput, data_len: usize) -> Result<u64> {
    Ok(output
        .occupied_capacity(Capacity::bytes(data_len)?)?
        .as_u64())
}

fn ensure_output_capacity(name: &str, output: &CellOutput, data_len: usize) -> Result<()> {
    let capacity: u64 = output.capacity().unpack();
    let occupied = occupied_capacity(output, data_len)?;
    ensure!(
        capacity >= occupied,
        "{name} capacity {} is below occupied capacity {}",
        capacity,
        occupied
    );
    Ok(())
}

fn put_u16(raw: &mut [u8], offset: usize, value: u16) {
    raw[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn put_u32(raw: &mut [u8], offset: usize, value: u32) {
    raw[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn put_u64(raw: &mut [u8], offset: usize, value: u64) {
    raw[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn put_u128(raw: &mut [u8], offset: usize, value: u128) {
    raw[offset..offset + 16].copy_from_slice(&value.to_le_bytes());
}

fn printable_out_point(out_point: &OutPoint) -> PrintableOutPoint {
    PrintableOutPoint {
        tx_hash: format!("{:#x}", byte32_to_h256(out_point.tx_hash())),
        index: out_point.index().unpack(),
    }
}

fn channel_cell_out_point(report: &OpenChannelReport, role: &str) -> Result<String> {
    report
        .cells
        .iter()
        .find(|cell| cell.role == role)
        .map(|cell| printable_out_point_string(&cell.out_point))
        .ok_or_else(|| anyhow!("open-channel report does not contain {role} cell"))
}

fn factory_cell_out_point(report: &OpenFactoryReport, role: &str) -> Result<String> {
    report
        .cells
        .iter()
        .find(|cell| cell.role == role)
        .map(|cell| printable_out_point_string(&cell.out_point))
        .ok_or_else(|| anyhow!("open-factory report does not contain {role} cell"))
}

fn printable_out_point_string(out_point: &PrintableOutPoint) -> String {
    format!("{}:{}", out_point.tx_hash, out_point.index)
}

fn parse_out_point(value: &str) -> Result<OutPoint> {
    let (tx_hash, index) = value
        .split_once(':')
        .ok_or_else(|| anyhow!("out point must be formatted as <tx-hash>:<index>"))?;
    let tx_hash = parse_h256(tx_hash)?;
    let index = if let Some(hex) = index.strip_prefix("0x") {
        u32::from_str_radix(hex, 16).with_context(|| format!("invalid out point index {index}"))?
    } else {
        index
            .parse::<u32>()
            .with_context(|| format!("invalid out point index {index}"))?
    };
    Ok(OutPoint::new(tx_hash.pack(), index))
}

fn format_out_point(out_point: &OutPoint) -> String {
    format!(
        "{}:{}",
        printable_out_point(out_point).tx_hash,
        printable_out_point(out_point).index
    )
}

fn hex32(raw: &[u8]) -> String {
    hex_prefixed(raw)
}

fn hex_prefixed(raw: &[u8]) -> String {
    format!("0x{}", hex::encode(raw))
}

fn parse_script_failure(raw: &str) -> ScriptFailureReport {
    let error_code = extract_error_code(raw);
    ScriptFailureReport {
        source: extract_between(raw, "source: ", ", cause:").map(str::to_string),
        error_code,
        morph_error: error_code
            .and_then(morph_script_error_name)
            .map(str::to_string),
        raw: raw.to_string(),
    }
}

fn extract_error_code(raw: &str) -> Option<i16> {
    let (_, tail) = raw.split_once("error code ")?;
    let digits: String = tail
        .chars()
        .take_while(|character| character.is_ascii_digit() || *character == '-')
        .collect();
    if digits.is_empty() {
        return None;
    }
    digits.parse().ok()
}

fn extract_between<'a>(raw: &'a str, start: &str, end: &str) -> Option<&'a str> {
    let (_, tail) = raw.split_once(start)?;
    let (value, _) = tail.split_once(end)?;
    Some(value)
}

fn morph_script_error_name(code: i16) -> Option<&'static str> {
    match code {
        value if value == ScriptError::IndexOutOfBounds as i16 => Some("IndexOutOfBounds"),
        value if value == ScriptError::Encoding as i16 => Some("Encoding"),
        value if value == ScriptError::WrongArgsLength as i16 => Some("WrongArgsLength"),
        value if value == ScriptError::WrongGroupShape as i16 => Some("WrongGroupShape"),
        value if value == ScriptError::FundingAnchorMismatch as i16 => {
            Some("FundingAnchorMismatch")
        }
        value if value == ScriptError::NonMonotonicStateNumber as i16 => {
            Some("NonMonotonicStateNumber")
        }
        value if value == ScriptError::NewStateNotSettling as i16 => Some("NewStateNotSettling"),
        value if value == ScriptError::HeaderContextChanged as i16 => Some("HeaderContextChanged"),
        value if value == ScriptError::OutputBelowOccupiedCapacity as i16 => {
            Some("OutputBelowOccupiedCapacity")
        }
        value if value == ScriptError::StateCellMissing as i16 => Some("StateCellMissing"),
        value if value == ScriptError::StateCellAmbiguous as i16 => Some("StateCellAmbiguous"),
        value if value == ScriptError::StateSinceNotMature as i16 => Some("StateSinceNotMature"),
        value if value == ScriptError::SponsorFeeTooHigh as i16 => Some("SponsorFeeTooHigh"),
        value if value == ScriptError::SponsorBudgetExceeded as i16 => {
            Some("SponsorBudgetExceeded")
        }
        value if value == ScriptError::SponsorChangeLockMismatch as i16 => {
            Some("SponsorChangeLockMismatch")
        }
        value if value == ScriptError::CapacityUnderflow as i16 => Some("CapacityUnderflow"),
        value if value == ScriptError::ParticipantWitnessMissing as i16 => {
            Some("ParticipantWitnessMissing")
        }
        value if value == ScriptError::ParticipantWitnessEncoding as i16 => {
            Some("ParticipantWitnessEncoding")
        }
        value if value == ScriptError::ParticipantCommitmentMismatch as i16 => {
            Some("ParticipantCommitmentMismatch")
        }
        value if value == ScriptError::InvalidParticipantSignature as i16 => {
            Some("InvalidParticipantSignature")
        }
        value if value == ScriptError::SettlementWitnessMissing as i16 => {
            Some("SettlementWitnessMissing")
        }
        value if value == ScriptError::SettlementDescriptorEncoding as i16 => {
            Some("SettlementDescriptorEncoding")
        }
        value if value == ScriptError::SettlementDescriptorMismatch as i16 => {
            Some("SettlementDescriptorMismatch")
        }
        value if value == ScriptError::SettlementOutputMismatch as i16 => {
            Some("SettlementOutputMismatch")
        }
        value if value == ScriptError::SponsorStateOutOfRange as i16 => {
            Some("SponsorStateOutOfRange")
        }
        value if value == ScriptError::XudtAmountEncoding as i16 => Some("XudtAmountEncoding"),
        value if value == ScriptError::XudtMintUnauthorised as i16 => Some("XudtMintUnauthorised"),
        value if value == ScriptError::XudtConservationMismatch as i16 => {
            Some("XudtConservationMismatch")
        }
        value if value == ScriptError::XudtTypeMismatch as i16 => Some("XudtTypeMismatch"),
        value if value == ScriptError::FactoryIdMismatch as i16 => Some("FactoryIdMismatch"),
        value if value == ScriptError::FactoryLocalExitMismatch as i16 => {
            Some("FactoryLocalExitMismatch")
        }
        value if value == ScriptError::FactoryReserveMismatch as i16 => {
            Some("FactoryReserveMismatch")
        }
        value if value == ScriptError::StateTypeMismatch as i16 => Some("StateTypeMismatch"),
        value if value == ScriptError::FactoryReducedProofEncoding as i16 => {
            Some("FactoryReducedProofEncoding")
        }
        value if value == ScriptError::FactoryReducedProofMismatch as i16 => {
            Some("FactoryReducedProofMismatch")
        }
        _ => None,
    }
}

fn parse_optional_hex32(label: &str, value: Option<&str>) -> Result<Option<[u8; 32]>> {
    value
        .map(|value| parse_hex32_array(label, value))
        .transpose()
}

fn parse_hex32_array(label: &str, value: &str) -> Result<[u8; 32]> {
    let stripped = value.strip_prefix("0x").unwrap_or(value);
    ensure!(
        stripped.len() == 64,
        "{label} must be a 32-byte hex string, got {} hex characters",
        stripped.len()
    );
    let decoded = hex::decode(stripped).with_context(|| format!("{label} is not valid hex"))?;
    let mut out = [0u8; 32];
    out.copy_from_slice(&decoded);
    Ok(out)
}

fn bytes32_from_slice(label: &str, value: &[u8]) -> Result<[u8; 32]> {
    ensure!(
        value.len() == 32,
        "{label} must be 32 bytes, got {}",
        value.len()
    );
    let mut out = [0u8; 32];
    out.copy_from_slice(value);
    Ok(out)
}

fn parse_h256(value: &str) -> Result<H256> {
    H256::from_str(value.strip_prefix("0x").unwrap_or(value))
        .map_err(|err| anyhow!("invalid H256 {value}: {err:?}"))
}

fn parse_privkey(value: &str) -> Result<Privkey, ckb_crypto::secp::Error> {
    Privkey::from_str(value.strip_prefix("0x").unwrap_or(value))
}

fn blake160(data: &[u8]) -> [u8; 20] {
    let hash = blake2b_256(data);
    let mut out = [0u8; 20];
    out.copy_from_slice(&hash[..20]);
    out
}

fn byte32_to_h256(value: ckb_types::packed::Byte32) -> H256 {
    (&value).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_ckb_script_failure() {
        let raw = "CKB RPC error -302 on estimate_cycles: TransactionFailedToVerify: Script(TransactionScriptError { source: Inputs[1].Lock, cause: ValidationFailure: see error code 29 on page https://example.invalid#29 })";

        let parsed = parse_script_failure(raw);

        assert_eq!(parsed.source.as_deref(), Some("Inputs[1].Lock"));
        assert_eq!(
            parsed.error_code,
            Some(ScriptError::SponsorStateOutOfRange as i16)
        );
        assert_eq!(
            parsed.morph_error.as_deref(),
            Some("SponsorStateOutOfRange")
        );
        assert_eq!(parsed.raw, raw);
    }
}
