use std::fs;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::Duration;

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
    BILATERAL_CKB_DESCRIPTOR_VERSION_V1, BILATERAL_SIGNATURE_COUNT_V1,
    BILATERAL_SIGNATURE_THRESHOLD_V1, BILATERAL_SIGNATURE_WITNESS_V1_LEN,
    BILATERAL_SIGNATURE_WITNESS_VERSION_V1, BYTE32_LEN, COMPRESSED_SECP256K1_PUBKEY_LEN,
    ECDSA_SIGNATURE_LEN, PHASE_ACTIVE, PHASE_SETTLING, SIGNATURE_SCHEME_SECP256K1_ECDSA_BLAKE2B_V1,
    SPONSOR_POLICY_V1_LEN, STATE_HEADER_V1_LEN, StateHeaderV1, blake2b256 as script_blake2b256,
    participants_commitment_v1, settlement_descriptor_commitment_v1,
};
use serde::Serialize;

use crate::packages::{PackageOutPoint, StoredStatePackage, read_package, write_package};
use crate::rpc::CkbRpcClient;

const DEFAULT_SECP_TYPE_HASH: &str =
    "0x9bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8";
pub const DEFAULT_DEVNET_PRIVATE_KEY: &str =
    "0xd00c06bfd800d27397002dca6fb0993d5ba6399b4238b2f29ee9deb97593d2bc";
pub const DEFAULT_ALICE_PRIVATE_KEY: &str =
    "0x1111111111111111111111111111111111111111111111111111111111111111";
pub const DEFAULT_BOB_PRIVATE_KEY: &str =
    "0x2222222222222222222222222222222222222222222222222222222222222222";
const CONTRACTS: [(&str, &str); 4] = [
    ("morph-state-lock", "morph-state-lock"),
    ("morph-state-type", "morph-state-type"),
    ("morph-vault-lock", "morph-vault-lock"),
    ("morph-sponsor-lock", "morph-sponsor-lock"),
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
    pub fee: u64,
    pub finalise_since: u64,
    pub mine_blocks: u64,
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
pub struct FundSponsorOptions {
    pub contracts_dir: PathBuf,
    pub private_key: String,
    pub state_out_point: String,
    pub sponsor_capacity: u64,
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

#[derive(Debug, Serialize)]
pub struct TransactionMetrics {
    pub estimated_cycles: u64,
    pub tx_size_bytes: usize,
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
    pub change_capacity: u64,
    pub fee: u64,
    pub metrics: TransactionMetrics,
    pub mined_blocks: Vec<String>,
    pub participants: Vec<ParticipantReport>,
    pub scripts: Vec<ResolvedScriptReport>,
    pub cells: Vec<ChannelCellReport>,
}

#[derive(Debug, Serialize)]
pub struct ParticipantReport {
    pub role: String,
    pub lock_hash: String,
    pub pubkey_sec1: String,
    pub capacity: u64,
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
pub struct FundSponsorReport {
    pub tx_hash: String,
    pub status: String,
    pub block_number: Option<u64>,
    pub block_hash: Option<String>,
    pub channel_id: String,
    pub state_number: u64,
    pub sponsor_out_point: PrintableOutPoint,
    pub sponsor_capacity: u64,
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
pub struct SupersedeSmokeReport {
    pub open: OpenChannelReport,
    pub stale_publish: PublishStateReport,
    pub sponsor_top_up: FundSponsorReport,
    pub supersede_publish: PublishStateReport,
    pub finalise: FinaliseChannelReport,
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
    let sponsor_policy = sponsor_policy_bytes(
        &channel_id,
        options.sponsor_capacity / 2,
        options.sponsor_capacity,
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
    let sponsor_policy = sponsor_policy_bytes(
        channel_id,
        options.sponsor_capacity / 2,
        options.sponsor_capacity,
        change_lock_hash.as_slice().try_into().unwrap(),
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

fn sponsor_policy_bytes(
    channel_id: &[u8; 32],
    max_fee_per_tx: u64,
    max_total_fee: u64,
    change_lock_hash: [u8; 32],
) -> [u8; SPONSOR_POLICY_V1_LEN] {
    let mut raw = [0u8; SPONSOR_POLICY_V1_LEN];
    raw[0..32].copy_from_slice(channel_id);
    put_u64(&mut raw, 32, 0);
    put_u64(&mut raw, 40, u64::MAX);
    put_u64(&mut raw, 48, max_fee_per_tx);
    put_u64(&mut raw, 56, max_total_fee);
    put_u64(&mut raw, 64, 0);
    put_u64(&mut raw, 72, u64::MAX);
    raw[80..112].copy_from_slice(channel_id);
    raw[112..144].copy_from_slice(&change_lock_hash);
    raw
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
    put_u16(&mut raw, 206, BILATERAL_CKB_DESCRIPTOR_VERSION_V1);
    raw[208..240].copy_from_slice(&script_blake2b256(&[
        b"CKB_MORPH_EMPTY_BILATERAL_PAYLOAD_V1",
    ]));
    raw[240..272].copy_from_slice(&input.challenge_policy_commitment);
    put_u16(&mut raw, 272, 1);
    raw
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

fn put_u64(raw: &mut [u8], offset: usize, value: u64) {
    raw[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
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
