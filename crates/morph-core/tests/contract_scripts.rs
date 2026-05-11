use ckb_testtool::builtin::ALWAYS_SUCCESS;
use ckb_testtool::ckb_types::{
    bytes::Bytes,
    core::{ScriptHashType, TransactionBuilder},
    packed::{CellInput, CellOutput, WitnessArgs},
    prelude::*,
};
use ckb_testtool::context::Context;
use k256::ecdsa::signature::hazmat::PrehashSigner;
use k256::ecdsa::{Signature, SigningKey};
use morph_script_common::{
    BILATERAL_SIGNATURE_COUNT_V1, BILATERAL_SIGNATURE_THRESHOLD_V1,
    BILATERAL_SIGNATURE_WITNESS_V1_LEN, BILATERAL_SIGNATURE_WITNESS_VERSION_V1,
    COMPRESSED_SECP256K1_PUBKEY_LEN, ECDSA_SIGNATURE_LEN, PHASE_SETTLING, SPONSOR_POLICY_V1_LEN,
    STATE_HEADER_V1_LEN, StateHeaderV1, participants_commitment_v1,
};
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

fn signing_key(byte: u8) -> SigningKey {
    SigningKey::from_slice(&[byte; 32]).unwrap()
}

fn pubkey(key: &SigningKey) -> [u8; COMPRESSED_SECP256K1_PUBKEY_LEN] {
    let encoded = key.verifying_key().to_encoded_point(true);
    let mut out = [0u8; COMPRESSED_SECP256K1_PUBKEY_LEN];
    out.copy_from_slice(encoded.as_bytes());
    out
}

fn signature(key: &SigningKey, digest: &[u8; 32]) -> [u8; ECDSA_SIGNATURE_LEN] {
    let sig: Signature = key.sign_prehash(digest).unwrap();
    let mut out = [0u8; ECDSA_SIGNATURE_LEN];
    out.copy_from_slice(sig.to_bytes().as_slice());
    out
}

fn header_raw(state_number: u64, phase: u8) -> [u8; STATE_HEADER_V1_LEN] {
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
    raw
}

fn signed_state_pair(
    old_number: u64,
    old_phase: u8,
    new_number: u64,
    new_phase: u8,
) -> (Bytes, Bytes, Bytes) {
    let key0 = signing_key(1);
    let key1 = signing_key(2);
    let mut entries = [(pubkey(&key0), key0), (pubkey(&key1), key1)];
    entries.sort_by(|left, right| left.0.cmp(&right.0));

    let commitment = participants_commitment_v1(2, &[&entries[0].0, &entries[1].0]);
    let mut old = header_raw(old_number, old_phase);
    old[110..142].copy_from_slice(&commitment);
    let mut new = header_raw(new_number, new_phase);
    new[110..142].copy_from_slice(&commitment);

    let header = StateHeaderV1::parse(&new).unwrap();
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
            .copy_from_slice(&signature(key, &digest));
    }

    (
        old.to_vec().into(),
        new.to_vec().into(),
        witness.to_vec().into(),
    )
}

fn header_bytes(state_number: u64, phase: u8) -> Bytes {
    header_raw(state_number, phase).to_vec().into()
}

fn witness_with_input_type(input_type: Bytes) -> ckb_testtool::ckb_types::packed::Bytes {
    WitnessArgs::new_builder()
        .input_type(Some(input_type).pack())
        .build()
        .as_bytes()
        .pack()
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
    let (old_data, new_data, sig_witness) = signed_state_pair(1, 1, 2, PHASE_SETTLING);

    let input_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(CELL_CAPACITY)
            .lock(lock.clone())
            .type_(Some(state_type.clone()).pack())
            .build(),
        old_data,
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
        .output_data(new_data.pack())
        .witness(witness_with_input_type(sig_witness))
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
    let (old_data, new_data, sig_witness) = signed_state_pair(2, 1, 2, PHASE_SETTLING);

    let input_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(CELL_CAPACITY)
            .lock(lock.clone())
            .type_(Some(state_type.clone()).pack())
            .build(),
        old_data,
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
        .output_data(new_data.pack())
        .witness(witness_with_input_type(sig_witness))
        .build();
    let tx = context.complete_tx(tx);

    assert!(context.verify_tx(&tx, MAX_CYCLES).is_err());
}

#[ignore = "requires `make build-contracts`"]
#[test]
fn state_type_rejects_invalid_participant_signature() {
    let mut context = Context::default();
    let lock = deploy_always_success(&mut context);
    let state_type = deploy_contract(&mut context, "morph-state-type", state_args(0));
    let (old_data, new_data, sig_witness) = signed_state_pair(1, 1, 2, PHASE_SETTLING);
    let mut sig_witness = sig_witness.to_vec();
    let last = sig_witness.len() - 1;
    sig_witness[last] ^= 1;

    let input_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(CELL_CAPACITY)
            .lock(lock.clone())
            .type_(Some(state_type.clone()).pack())
            .build(),
        old_data,
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
        .output_data(new_data.pack())
        .witness(witness_with_input_type(sig_witness.into()))
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
