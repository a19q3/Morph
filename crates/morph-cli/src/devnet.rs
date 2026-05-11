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
use serde::Serialize;

use crate::rpc::CkbRpcClient;

const DEFAULT_SECP_TYPE_HASH: &str =
    "0x9bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8";
pub const DEFAULT_DEVNET_PRIVATE_KEY: &str =
    "0xd00c06bfd800d27397002dca6fb0993d5ba6399b4238b2f29ee9deb97593d2bc";
const CONTRACTS: [(&str, &str); 3] = [
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

#[derive(Debug, Serialize)]
pub struct DeployContractsReport {
    pub tx_hash: String,
    pub input_capacity: u64,
    pub deployed_capacity: u64,
    pub change_capacity: u64,
    pub fee: u64,
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

struct LiveCell {
    out_point: OutPoint,
    capacity: u64,
}

struct ContractBinary {
    name: String,
    data: Bytes,
    data_hash: H256,
    capacity: u64,
    output: CellOutput,
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
    let tx_hash = signed.hash();
    let json_tx: ckb_jsonrpc_types::Transaction = signed.data().into();
    let sent_hash = rpc.send_transaction(json_tx)?;
    ensure!(
        sent_hash == tx_hash.clone().into(),
        "node returned tx hash {sent_hash:#x}, but locally built {:#x}",
        H256::from(tx_hash)
    );

    let mut mined_blocks = Vec::new();
    for _ in 0..options.mine_blocks {
        mined_blocks.push(rpc.generate_block()?);
        let status = rpc.transaction(sent_hash.clone())?;
        if status.tx_status.status == Status::Committed {
            break;
        }
    }

    let status = if options.mine_blocks > 0 {
        rpc.wait_transaction_committed(
            sent_hash.clone(),
            Duration::from_secs(30),
            Duration::from_millis(500),
        )?
    } else {
        rpc.transaction(sent_hash.clone())?
    };

    let tx_hash_string = format!("{sent_hash:#x}");
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
        mined_blocks,
        status: format!("{:?}", status.tx_status.status),
        block_number: status.tx_status.block_number.map(|number| number.value()),
        block_hash: status.tx_status.block_hash.map(|hash| format!("{hash:#x}")),
        scripts,
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
                let out_point = OutPoint::new(tx.hash.pack(), index as u32);
                let live = rpc.live_cell(out_point.clone().into(), true)?;
                if live.status != "live" {
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
