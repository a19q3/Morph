use ckb_testtool::builtin::ALWAYS_SUCCESS;
use ckb_testtool::ckb_types::{
    bytes::Bytes,
    core::{ScriptHashType, TransactionBuilder},
    packed::{CellInput, CellOutput},
    prelude::*,
};
use ckb_testtool::context::Context;
use morph_script_common::{PHASE_SETTLING, SPONSOR_POLICY_V1_LEN, STATE_HEADER_V1_LEN};
use std::fs;
use std::path::PathBuf;

const MAX_CYCLES: u64 = 50_000_000;
const CELL_CAPACITY: u64 = 100_000_000_000;
const FUNDING_ANCHOR: [u8; 32] = [4u8; 32];

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("workspace crates dir")
        .parent()
        .expect("repository root")
        .to_path_buf()
}

fn contract_bin(name: &str) -> Bytes {
    let path = repo_root()
        .join("target/riscv64imac-unknown-none-elf/release")
        .join(name);
    fs::read(&path)
        .unwrap_or_else(|err| {
            panic!(
                "read contract binary {}: {}; run `make build-contracts` first",
                path.display(),
                err
            )
        })
        .into()
}

fn deploy_always_success(context: &mut Context) -> ckb_testtool::ckb_types::packed::Script {
    let out_point = context.deploy_cell(ALWAYS_SUCCESS.clone());
    context
        .build_script_with_hash_type(&out_point, ScriptHashType::Data1, Bytes::new())
        .expect("always-success script")
}

fn deploy_contract(
    context: &mut Context,
    name: &str,
    args: Vec<u8>,
) -> ckb_testtool::ckb_types::packed::Script {
    let out_point = context.deploy_cell(contract_bin(name));
    context
        .build_script(&out_point, args.into())
        .expect("contract script")
}

fn put_u16(raw: &mut [u8], offset: usize, value: u16) {
    raw[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn put_u64(raw: &mut [u8], offset: usize, value: u64) {
    raw[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn state_args(finalise_since: u64) -> Vec<u8> {
    let mut args = FUNDING_ANCHOR.to_vec();
    args.extend_from_slice(&finalise_since.to_le_bytes());
    args
}

fn header_bytes(state_number: u64, phase: u8) -> Bytes {
    let mut raw = [0u8; STATE_HEADER_V1_LEN];
    put_u16(&mut raw, 0, 1);
    raw[2..34].fill(2);
    put_u16(&mut raw, 34, 1);
    raw[36..68].fill(3);
    raw[68..100].copy_from_slice(&FUNDING_ANCHOR);
    put_u64(&mut raw, 100, state_number);
    raw[108] = 1;
    raw[109] = phase;
    raw[110..142].fill(5);
    raw[142..174].fill(6);
    raw[174..206].fill(7);
    put_u16(&mut raw, 206, 1);
    raw[208..240].fill(8);
    raw[240..272].fill(9);
    put_u16(&mut raw, 272, 1);
    raw.to_vec().into()
}

fn sponsor_policy(change_lock_hash: &[u8; 32], max_fee: u64) -> Vec<u8> {
    let mut raw = [0u8; SPONSOR_POLICY_V1_LEN];
    raw[0..32].fill(3);
    put_u64(&mut raw, 32, 0);
    put_u64(&mut raw, 40, u64::MAX);
    put_u64(&mut raw, 48, max_fee);
    put_u64(&mut raw, 56, max_fee);
    put_u64(&mut raw, 64, 0);
    put_u64(&mut raw, 72, u64::MAX);
    raw[80..112].fill(9);
    raw[112..144].copy_from_slice(change_lock_hash);
    raw.to_vec()
}

#[ignore = "requires `make build-contracts`"]
#[test]
fn state_type_accepts_newer_settling_state() {
    let mut context = Context::default();
    let lock = deploy_always_success(&mut context);
    let state_type = deploy_contract(&mut context, "morph-state-type", state_args(0));

    let input_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(CELL_CAPACITY)
            .lock(lock.clone())
            .type_(Some(state_type.clone()).pack())
            .build(),
        header_bytes(1, 1),
    );
    let input = CellInput::new_builder()
        .previous_output(input_out_point)
        .build();

    let output = CellOutput::new_builder()
        .capacity(CELL_CAPACITY)
        .lock(lock)
        .type_(Some(state_type).pack())
        .build();
    let tx = TransactionBuilder::default()
        .input(input)
        .output(output)
        .output_data(header_bytes(2, PHASE_SETTLING).pack())
        .build();
    let tx = context.complete_tx(tx);

    context
        .verify_tx(&tx, MAX_CYCLES)
        .expect("newer state should verify");
}

#[ignore = "requires `make build-contracts`"]
#[test]
fn state_type_rejects_equal_state_number() {
    let mut context = Context::default();
    let lock = deploy_always_success(&mut context);
    let state_type = deploy_contract(&mut context, "morph-state-type", state_args(0));

    let input_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(CELL_CAPACITY)
            .lock(lock.clone())
            .type_(Some(state_type.clone()).pack())
            .build(),
        header_bytes(2, 1),
    );
    let input = CellInput::new_builder()
        .previous_output(input_out_point)
        .build();
    let output = CellOutput::new_builder()
        .capacity(CELL_CAPACITY)
        .lock(lock)
        .type_(Some(state_type).pack())
        .build();
    let tx = TransactionBuilder::default()
        .input(input)
        .output(output)
        .output_data(header_bytes(2, PHASE_SETTLING).pack())
        .build();
    let tx = context.complete_tx(tx);

    assert!(context.verify_tx(&tx, MAX_CYCLES).is_err());
}

#[ignore = "requires `make build-contracts`"]
#[test]
fn vault_lock_accepts_finalise_with_current_state() {
    let mut context = Context::default();
    let settlement_lock = deploy_always_success(&mut context);
    let state_type = deploy_contract(&mut context, "morph-state-type", state_args(0));
    let mut vault_args = FUNDING_ANCHOR.to_vec();
    vault_args.extend_from_slice(&0u64.to_le_bytes());
    let vault_lock = deploy_contract(&mut context, "morph-vault-lock", vault_args);

    let state_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(CELL_CAPACITY)
            .lock(settlement_lock.clone())
            .type_(Some(state_type).pack())
            .build(),
        header_bytes(3, PHASE_SETTLING),
    );
    let vault_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(CELL_CAPACITY)
            .lock(vault_lock)
            .build(),
        Bytes::new(),
    );

    let tx = TransactionBuilder::default()
        .input(
            CellInput::new_builder()
                .previous_output(state_out_point)
                .build(),
        )
        .input(
            CellInput::new_builder()
                .previous_output(vault_out_point)
                .build(),
        )
        .output(
            CellOutput::new_builder()
                .capacity(CELL_CAPACITY * 2)
                .lock(settlement_lock)
                .build(),
        )
        .output_data(Bytes::new().pack())
        .build();
    let tx = context.complete_tx(tx);

    context
        .verify_tx(&tx, MAX_CYCLES)
        .expect("vault finalise should verify");
}

#[ignore = "requires `make build-contracts`"]
#[test]
fn sponsor_lock_accepts_bounded_fee_with_wallet_change() {
    let mut context = Context::default();
    let wallet_lock = deploy_always_success(&mut context);
    let change_hash = wallet_lock.calc_script_hash();
    let sponsor_lock = deploy_contract(
        &mut context,
        "morph-sponsor-lock",
        sponsor_policy(change_hash.as_slice().try_into().unwrap(), 1_000),
    );

    let input_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(CELL_CAPACITY)
            .lock(sponsor_lock)
            .build(),
        Bytes::new(),
    );
    let tx = TransactionBuilder::default()
        .input(
            CellInput::new_builder()
                .previous_output(input_out_point)
                .build(),
        )
        .output(
            CellOutput::new_builder()
                .capacity(CELL_CAPACITY - 100)
                .lock(wallet_lock)
                .build(),
        )
        .output_data(Bytes::new().pack())
        .build();
    let tx = context.complete_tx(tx);

    context
        .verify_tx(&tx, MAX_CYCLES)
        .expect("bounded sponsor fee should verify");
}
