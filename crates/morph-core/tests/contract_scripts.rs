use ckb_testtool::builtin::ALWAYS_SUCCESS;
use ckb_testtool::ckb_types::{
    bytes::Bytes,
    core::{ScriptHashType, TransactionBuilder, TransactionView},
    packed::{CellInput, CellOutput, WitnessArgs},
    prelude::*,
};
use ckb_testtool::context::Context;
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
    PHASE_ACTIVE, PHASE_SETTLING, SPONSOR_POLICY_V1_LEN, STATE_HEADER_V1_LEN, StateHeaderV1,
    blake2b256, factory_local_exit_digest_v1, factory_participants_commitment_v1,
    participants_commitment_v1, settlement_descriptor_commitment_v1,
};
use std::fs;
use std::path::PathBuf;

const MAX_CYCLES: u64 = 50_000_000;
const CELL_CAPACITY: u64 = 100_000_000_000;
const ALICE_CAPACITY: u64 = 60_000_000_000;
const BOB_CAPACITY: u64 = 40_000_000_000;
const FUNDING_ANCHOR: [u8; 32] = [4u8; 32];
const FACTORY_ID: [u8; 32] = [7u8; 32];
const ALICE_XUDT_AMOUNT: u128 = 70;
const BOB_XUDT_AMOUNT: u128 = 30;

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
    deploy_always_success_with_args(context, Bytes::new())
}

fn deploy_always_success_with_args(
    context: &mut Context,
    args: Bytes,
) -> ckb_testtool::ckb_types::packed::Script {
    let out_point = context.deploy_cell(ALWAYS_SUCCESS.clone());
    context
        .build_script_with_hash_type(&out_point, ScriptHashType::Data1, args)
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

fn put_u128(raw: &mut [u8], offset: usize, value: u128) {
    raw[offset..offset + 16].copy_from_slice(&value.to_le_bytes());
}

fn state_args(finalise_since: u64) -> Vec<u8> {
    state_args_with_anchor(FUNDING_ANCHOR, finalise_since)
}

fn state_args_with_anchor(anchor: [u8; 32], finalise_since: u64) -> Vec<u8> {
    let mut args = anchor.to_vec();
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
    header_raw_with_anchor(state_number, phase, FUNDING_ANCHOR)
}

fn header_raw_with_anchor(
    state_number: u64,
    phase: u8,
    funding_anchor: [u8; 32],
) -> [u8; STATE_HEADER_V1_LEN] {
    let mut raw = [0u8; STATE_HEADER_V1_LEN];
    put_u16(&mut raw, 0, 1);
    raw[2..34].fill(2);
    put_u16(&mut raw, 34, 1);
    raw[36..68].fill(3);
    raw[68..100].copy_from_slice(&funding_anchor);
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

fn factory_header_raw(update_number: u64) -> [u8; FACTORY_STATE_HEADER_V1_LEN] {
    factory_header_raw_with_id(update_number, FACTORY_ID)
}

fn factory_header_raw_with_id(
    update_number: u64,
    factory_id: [u8; 32],
) -> [u8; FACTORY_STATE_HEADER_V1_LEN] {
    let mut raw = [0u8; FACTORY_STATE_HEADER_V1_LEN];
    put_u16(&mut raw, 0, 1);
    raw[2..34].fill(2);
    put_u16(&mut raw, 34, 1);
    raw[36..68].copy_from_slice(&factory_id);
    put_u64(&mut raw, 68, update_number);
    raw[76..108].fill(4);
    raw[108..140].fill(5);
    raw[140..172].fill(6);
    raw[172..204].fill(7);
    raw[204..236].fill(8);
    put_u16(&mut raw, 236, 1);
    raw
}

fn derived_funding_anchor(input: &CellInput, output_index: u64) -> [u8; 32] {
    blake2b256(&[input.as_slice(), &output_index.to_le_bytes()])
}

fn derived_factory_id(input: &CellInput, output_index: u64) -> [u8; 32] {
    blake2b256(&[input.as_slice(), &output_index.to_le_bytes()])
}

fn header_with_descriptor(state_number: u64, phase: u8, descriptor_commitment: [u8; 32]) -> Bytes {
    let mut raw = header_raw(state_number, phase);
    raw[174..206].copy_from_slice(&descriptor_commitment);
    raw.to_vec().into()
}

fn header_with_descriptor_version(
    state_number: u64,
    phase: u8,
    descriptor_commitment: [u8; 32],
    descriptor_version: u16,
) -> Bytes {
    let mut raw = header_raw(state_number, phase);
    raw[174..206].copy_from_slice(&descriptor_commitment);
    put_u16(&mut raw, 206, descriptor_version);
    raw.to_vec().into()
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

fn signed_factory_pair(old_number: u64, new_number: u64) -> (Bytes, Bytes, Bytes) {
    let key0 = signing_key(1);
    let key1 = signing_key(2);
    let mut entries = [
        ([1u8; BYTE32_LEN], pubkey(&key0), key0),
        ([2u8; BYTE32_LEN], pubkey(&key1), key1),
    ];
    entries.sort_by(|left, right| left.0.cmp(&right.0));

    let commitment = factory_participants_commitment_v1(
        2,
        &[
            (entries[0].0.as_slice(), entries[0].1.as_slice()),
            (entries[1].0.as_slice(), entries[1].1.as_slice()),
        ],
    );
    let mut old = factory_header_raw(old_number);
    old[108..140].copy_from_slice(&commitment);
    let mut new = factory_header_raw(new_number);
    new[108..140].copy_from_slice(&commitment);
    new[76..108].fill(9);
    new[140..172].fill(10);
    new[172..204].fill(11);

    let header = FactoryStateHeaderV1::parse(&new).unwrap();
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
            .copy_from_slice(&signature(key, &digest));
    }

    (
        old.to_vec().into(),
        new.to_vec().into(),
        witness.to_vec().into(),
    )
}

fn signed_factory_pair_with_exit_digest(
    old_number: u64,
    new_number: u64,
    exit_digest: [u8; 32],
) -> (Bytes, Bytes, Bytes) {
    let key0 = signing_key(1);
    let key1 = signing_key(2);
    let mut entries = [
        ([1u8; BYTE32_LEN], pubkey(&key0), key0),
        ([2u8; BYTE32_LEN], pubkey(&key1), key1),
    ];
    entries.sort_by(|left, right| left.0.cmp(&right.0));

    let commitment = factory_participants_commitment_v1(
        2,
        &[
            (entries[0].0.as_slice(), entries[0].1.as_slice()),
            (entries[1].0.as_slice(), entries[1].1.as_slice()),
        ],
    );
    let mut old = factory_header_raw(old_number);
    old[108..140].copy_from_slice(&commitment);
    let mut new = factory_header_raw(new_number);
    new[108..140].copy_from_slice(&commitment);
    new[76..108].fill(9);
    new[140..172].fill(10);
    new[172..204].copy_from_slice(&exit_digest);

    let header = FactoryStateHeaderV1::parse(&new).unwrap();
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
            .copy_from_slice(&signature(key, &digest));
    }

    (
        old.to_vec().into(),
        new.to_vec().into(),
        witness.to_vec().into(),
    )
}

fn factory_local_exit_witness(
    factory_signature: &[u8],
    state_output_index: u32,
    vault_output_index: u32,
    state_type_hash: [u8; 32],
    vault_lock_hash: [u8; 32],
    state_lock_hash: [u8; 32],
    state_header: &[u8],
    descriptor: &[u8],
) -> Bytes {
    let mut witness = vec![
        0u8;
        FACTORY_LOCAL_EXIT_WITNESS_V1_LEN - BILATERAL_CKB_DESCRIPTOR_V1_LEN
            + descriptor.len()
    ];
    put_u16(&mut witness, 0, FACTORY_LOCAL_EXIT_WITNESS_VERSION_V1);
    witness[2..2 + FACTORY_SIGNATURE_WITNESS_V1_LEN].copy_from_slice(factory_signature);
    let offset = 2 + FACTORY_SIGNATURE_WITNESS_V1_LEN;
    witness[offset..offset + 4].copy_from_slice(&state_output_index.to_le_bytes());
    witness[offset + 4..offset + 8].copy_from_slice(&vault_output_index.to_le_bytes());
    witness[offset + 8..offset + 8 + BYTE32_LEN].copy_from_slice(&state_type_hash);
    witness[offset + 8 + BYTE32_LEN..offset + 8 + 2 * BYTE32_LEN].copy_from_slice(&vault_lock_hash);
    witness[offset + 8 + 2 * BYTE32_LEN..offset + 8 + 3 * BYTE32_LEN]
        .copy_from_slice(&state_lock_hash);
    witness[offset + 8 + 3 * BYTE32_LEN..offset + 8 + 3 * BYTE32_LEN + STATE_HEADER_V1_LEN]
        .copy_from_slice(state_header);
    witness[offset + 8 + 3 * BYTE32_LEN + STATE_HEADER_V1_LEN..].copy_from_slice(descriptor);
    witness.into()
}

fn witness_with_input_type(input_type: Bytes) -> ckb_testtool::ckb_types::packed::Bytes {
    WitnessArgs::new_builder()
        .input_type(Some(input_type).pack())
        .build()
        .as_bytes()
        .pack()
}

fn empty_witness() -> ckb_testtool::ckb_types::packed::Bytes {
    WitnessArgs::default().as_bytes().pack()
}

fn descriptor_bytes(
    left_lock_hash: [u8; 32],
    left_capacity: u64,
    right_lock_hash: [u8; 32],
    right_capacity: u64,
) -> Bytes {
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
    raw.to_vec().into()
}

fn ckb_xudt_descriptor_bytes(
    xudt_type_hash: [u8; 32],
    left_lock_hash: [u8; 32],
    left_capacity: u64,
    left_amount: u128,
    right_lock_hash: [u8; 32],
    right_capacity: u64,
    right_amount: u128,
) -> Bytes {
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
    raw.to_vec().into()
}

fn xudt_amount_data(amount: u128) -> Bytes {
    Bytes::copy_from_slice(&amount.to_le_bytes())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FactoryXudtExitTamper {
    None,
    ChildAmountMinusOneWithConservedSupply,
    ChildTypeMismatchWithAuthorisedMint,
}

fn sponsor_policy(change_lock_hash: &[u8; 32], max_fee: u64) -> Vec<u8> {
    sponsor_policy_with_bounds(change_lock_hash, 0, u64::MAX, max_fee, max_fee)
}

fn sponsor_policy_with_bounds(
    change_lock_hash: &[u8; 32],
    min_state_number: u64,
    max_state_number: u64,
    max_fee_per_tx: u64,
    max_total_fee: u64,
) -> Vec<u8> {
    let mut raw = [0u8; SPONSOR_POLICY_V1_LEN];
    raw[0..32].fill(3);
    put_u64(&mut raw, 32, min_state_number);
    put_u64(&mut raw, 40, max_state_number);
    put_u64(&mut raw, 48, max_fee_per_tx);
    put_u64(&mut raw, 56, max_total_fee);
    put_u64(&mut raw, 64, 0);
    put_u64(&mut raw, 72, u64::MAX);
    raw[80..112].fill(9);
    raw[112..144].copy_from_slice(change_lock_hash);
    raw.to_vec()
}

#[ignore = "requires `make build-contracts`"]
#[test]
fn state_lock_accepts_input_with_expected_state_type() {
    let mut context = Context::default();
    let state_type = deploy_always_success_with_args(&mut context, Bytes::from(vec![1]));
    let refund_lock = deploy_always_success_with_args(&mut context, Bytes::from(vec![2]));
    let state_lock = deploy_contract(
        &mut context,
        "morph-state-lock",
        state_type.calc_script_hash().as_slice().to_vec(),
    );
    let input_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(CELL_CAPACITY)
            .lock(state_lock)
            .type_(Some(state_type).pack())
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
                .capacity(CELL_CAPACITY)
                .lock(refund_lock)
                .build(),
        )
        .output_data(Bytes::new().pack())
        .build();
    let tx = context.complete_tx(tx);

    context
        .verify_tx(&tx, MAX_CYCLES)
        .expect("state lock should accept expected typed input");
}

#[ignore = "requires `make build-contracts`"]
#[test]
fn state_lock_rejects_untyped_input() {
    let mut context = Context::default();
    let state_type = deploy_always_success_with_args(&mut context, Bytes::from(vec![1]));
    let refund_lock = deploy_always_success_with_args(&mut context, Bytes::from(vec![2]));
    let state_lock = deploy_contract(
        &mut context,
        "morph-state-lock",
        state_type.calc_script_hash().as_slice().to_vec(),
    );
    let input_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(CELL_CAPACITY)
            .lock(state_lock)
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
                .capacity(CELL_CAPACITY)
                .lock(refund_lock)
                .build(),
        )
        .output_data(Bytes::new().pack())
        .build();
    let tx = context.complete_tx(tx);

    assert!(context.verify_tx(&tx, MAX_CYCLES).is_err());
}

#[ignore = "requires `make build-contracts`"]
#[test]
fn state_type_accepts_canonical_initial_state() {
    let mut context = Context::default();
    let lock = deploy_always_success(&mut context);

    let funding_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(CELL_CAPACITY)
            .lock(lock.clone())
            .build(),
        Bytes::new(),
    );
    let input = CellInput::new_builder()
        .previous_output(funding_out_point)
        .build();
    let funding_anchor = derived_funding_anchor(&input, 0);
    let state_type = deploy_contract(
        &mut context,
        "morph-state-type",
        state_args_with_anchor(funding_anchor, 0),
    );
    let initial_data =
        Bytes::from(header_raw_with_anchor(0, PHASE_ACTIVE, funding_anchor).to_vec());

    let output = CellOutput::new_builder()
        .capacity(CELL_CAPACITY)
        .lock(lock)
        .type_(Some(state_type).pack())
        .build();
    let tx = TransactionBuilder::default()
        .input(input)
        .output(output)
        .output_data(initial_data.pack())
        .build();
    let tx = context.complete_tx(tx);

    context
        .verify_tx(&tx, MAX_CYCLES)
        .expect("canonical initial state should verify");
}

#[ignore = "requires `make build-contracts`"]
#[test]
fn state_type_rejects_initial_state_with_non_canonical_anchor() {
    let mut context = Context::default();
    let lock = deploy_always_success(&mut context);

    let funding_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(CELL_CAPACITY)
            .lock(lock.clone())
            .build(),
        Bytes::new(),
    );
    let input = CellInput::new_builder()
        .previous_output(funding_out_point)
        .build();
    let mut wrong_anchor = derived_funding_anchor(&input, 0);
    wrong_anchor[0] ^= 1;
    let state_type = deploy_contract(
        &mut context,
        "morph-state-type",
        state_args_with_anchor(wrong_anchor, 0),
    );
    let initial_data = Bytes::from(header_raw_with_anchor(0, PHASE_ACTIVE, wrong_anchor).to_vec());

    let output = CellOutput::new_builder()
        .capacity(CELL_CAPACITY)
        .lock(lock)
        .type_(Some(state_type).pack())
        .build();
    let tx = TransactionBuilder::default()
        .input(input)
        .output(output)
        .output_data(initial_data.pack())
        .build();
    let tx = context.complete_tx(tx);

    assert!(context.verify_tx(&tx, MAX_CYCLES).is_err());
}

#[ignore = "requires `make build-contracts`"]
#[test]
fn factory_type_accepts_canonical_initial_factory_state() {
    let mut context = Context::default();
    let lock = deploy_always_success(&mut context);

    let funding_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(CELL_CAPACITY)
            .lock(lock.clone())
            .build(),
        Bytes::new(),
    );
    let input = CellInput::new_builder()
        .previous_output(funding_out_point)
        .build();
    let factory_id = derived_factory_id(&input, 0);
    let factory_type = deploy_contract(&mut context, "morph-factory-type", factory_id.to_vec());
    let initial_data = Bytes::from(factory_header_raw_with_id(0, factory_id).to_vec());

    let output = CellOutput::new_builder()
        .capacity(CELL_CAPACITY)
        .lock(lock)
        .type_(Some(factory_type).pack())
        .build();
    let tx = TransactionBuilder::default()
        .input(input)
        .output(output)
        .output_data(initial_data.pack())
        .build();
    let tx = context.complete_tx(tx);

    context
        .verify_tx(&tx, MAX_CYCLES)
        .expect("canonical initial factory state should verify");
}

#[ignore = "requires `make build-contracts`"]
#[test]
fn factory_type_accepts_signed_factory_update() {
    let mut context = Context::default();
    let lock = deploy_always_success(&mut context);
    let factory_type = deploy_contract(&mut context, "morph-factory-type", FACTORY_ID.to_vec());
    let (old_data, new_data, sig_witness) = signed_factory_pair(1, 2);

    let input_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(CELL_CAPACITY)
            .lock(lock.clone())
            .type_(Some(factory_type.clone()).pack())
            .build(),
        old_data,
    );
    let input = CellInput::new_builder()
        .previous_output(input_out_point)
        .build();

    let output = CellOutput::new_builder()
        .capacity(CELL_CAPACITY)
        .lock(lock)
        .type_(Some(factory_type).pack())
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
        .expect("factory update should verify");
}

#[ignore = "requires `make build-contracts`"]
#[test]
fn factory_type_rejects_equal_update_number() {
    let mut context = Context::default();
    let lock = deploy_always_success(&mut context);
    let factory_type = deploy_contract(&mut context, "morph-factory-type", FACTORY_ID.to_vec());
    let (old_data, new_data, sig_witness) = signed_factory_pair(2, 2);

    let input_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(CELL_CAPACITY)
            .lock(lock.clone())
            .type_(Some(factory_type.clone()).pack())
            .build(),
        old_data,
    );
    let input = CellInput::new_builder()
        .previous_output(input_out_point)
        .build();

    let output = CellOutput::new_builder()
        .capacity(CELL_CAPACITY)
        .lock(lock)
        .type_(Some(factory_type).pack())
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
fn factory_type_rejects_invalid_participant_signature() {
    let mut context = Context::default();
    let lock = deploy_always_success(&mut context);
    let factory_type = deploy_contract(&mut context, "morph-factory-type", FACTORY_ID.to_vec());
    let (old_data, new_data, sig_witness) = signed_factory_pair(1, 2);
    let mut sig_witness = sig_witness.to_vec();
    let last = sig_witness.len() - 1;
    sig_witness[last] ^= 1;

    let input_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(CELL_CAPACITY)
            .lock(lock.clone())
            .type_(Some(factory_type.clone()).pack())
            .build(),
        old_data,
    );
    let input = CellInput::new_builder()
        .previous_output(input_out_point)
        .build();

    let output = CellOutput::new_builder()
        .capacity(CELL_CAPACITY)
        .lock(lock)
        .type_(Some(factory_type).pack())
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
fn factory_type_and_vault_accept_local_exit_materialisation() {
    let mut context = Context::default();
    let factory_lock = deploy_always_success(&mut context);
    let reserve_lock_placeholder = deploy_always_success(&mut context);
    let alice_lock = deploy_always_success_with_args(&mut context, Bytes::from(vec![1]));
    let bob_lock = deploy_always_success_with_args(&mut context, Bytes::from(vec![2]));

    let factory_type = deploy_contract(&mut context, "morph-factory-type", FACTORY_ID.to_vec());
    let factory_type_hash: [u8; 32] = factory_type.calc_script_hash().unpack();
    let mut factory_vault_args = FACTORY_ID.to_vec();
    factory_vault_args.extend_from_slice(&factory_type_hash);
    let factory_vault_lock =
        deploy_contract(&mut context, "morph-factory-vault-lock", factory_vault_args);

    let descriptor = descriptor_bytes(
        alice_lock.calc_script_hash().unpack(),
        ALICE_CAPACITY,
        bob_lock.calc_script_hash().unpack(),
        BOB_CAPACITY,
    );
    let (old_factory_data, _, _) = signed_factory_pair_with_exit_digest(1, 2, [0u8; 32]);

    let factory_input_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(CELL_CAPACITY)
            .lock(factory_lock.clone())
            .type_(Some(factory_type.clone()).pack())
            .build(),
        old_factory_data,
    );
    let factory_input = CellInput::new_builder()
        .previous_output(factory_input_out_point)
        .build();
    let factory_vault_input_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(300_000_000_000u64)
            .lock(factory_vault_lock.clone())
            .build(),
        Bytes::new(),
    );
    let reserve_input = CellInput::new_builder()
        .previous_output(factory_vault_input_out_point)
        .build();
    let fee_input_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(CELL_CAPACITY)
            .lock(reserve_lock_placeholder)
            .build(),
        Bytes::new(),
    );

    let state_output_index = 1u32;
    let vault_output_index = 2u32;
    let child_anchor = derived_funding_anchor(&factory_input, state_output_index as u64);
    let state_type = deploy_contract(
        &mut context,
        "morph-state-type",
        state_args_with_anchor(child_anchor, 0),
    );
    let state_type_hash: [u8; 32] = state_type.calc_script_hash().unpack();
    let state_lock = deploy_contract(&mut context, "morph-state-lock", state_type_hash.to_vec());
    let state_lock_hash: [u8; 32] = state_lock.calc_script_hash().unpack();
    let mut vault_args = child_anchor.to_vec();
    vault_args.extend_from_slice(&0u64.to_le_bytes());
    let vault_lock = deploy_contract(&mut context, "morph-vault-lock", vault_args);
    let vault_lock_hash: [u8; 32] = vault_lock.calc_script_hash().unpack();

    let mut child_state = header_raw_with_anchor(0, PHASE_ACTIVE, child_anchor);
    child_state[174..206].copy_from_slice(&settlement_descriptor_commitment_v1(&descriptor));
    let key0 = signing_key(1);
    let key1 = signing_key(2);
    let mut child_pubkeys = [pubkey(&key0), pubkey(&key1)];
    child_pubkeys.sort();
    child_state[110..142].copy_from_slice(&participants_commitment_v1(
        2,
        &[&child_pubkeys[0], &child_pubkeys[1]],
    ));

    let exit_digest = factory_local_exit_digest_v1(
        state_output_index,
        vault_output_index,
        &state_type_hash,
        &vault_lock_hash,
        &state_lock_hash,
        &child_state,
        &descriptor,
    );
    let (_, new_data, factory_sig) = signed_factory_pair_with_exit_digest(1, 2, exit_digest);
    let exit_witness = factory_local_exit_witness(
        &factory_sig,
        state_output_index,
        vault_output_index,
        state_type_hash,
        vault_lock_hash,
        state_lock_hash,
        &child_state,
        &descriptor,
    );

    let tx = TransactionBuilder::default()
        .input(factory_input.clone())
        .input(reserve_input.clone())
        .input(
            CellInput::new_builder()
                .previous_output(fee_input_out_point)
                .build(),
        )
        .output(
            CellOutput::new_builder()
                .capacity(CELL_CAPACITY)
                .lock(factory_lock.clone())
                .type_(Some(factory_type.clone()).pack())
                .build(),
        )
        .output(
            CellOutput::new_builder()
                .capacity(CELL_CAPACITY)
                .lock(state_lock.clone())
                .type_(Some(state_type.clone()).pack())
                .build(),
        )
        .output(
            CellOutput::new_builder()
                .capacity(ALICE_CAPACITY + BOB_CAPACITY)
                .lock(vault_lock.clone())
                .build(),
        )
        .output(
            CellOutput::new_builder()
                .capacity(200_000_000_000u64)
                .lock(factory_vault_lock.clone())
                .build(),
        )
        .output_data(new_data.clone().pack())
        .output_data(Bytes::from(child_state.to_vec()).pack())
        .output_data(Bytes::new().pack())
        .output_data(Bytes::new().pack())
        .witness(witness_with_input_type(exit_witness.clone()))
        .witness(witness_with_input_type(exit_witness.clone()))
        .witness(empty_witness())
        .build();
    let tx = context.complete_tx(tx);

    context
        .verify_tx(&tx, MAX_CYCLES)
        .expect("factory local exit should verify");

    let split_fee_lock = deploy_always_success(&mut context);
    let split_fee_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(CELL_CAPACITY)
            .lock(split_fee_lock)
            .build(),
        Bytes::new(),
    );
    let split_reserve_tx = TransactionBuilder::default()
        .input(factory_input)
        .input(reserve_input)
        .input(
            CellInput::new_builder()
                .previous_output(split_fee_out_point)
                .build(),
        )
        .output(
            CellOutput::new_builder()
                .capacity(CELL_CAPACITY)
                .lock(factory_lock)
                .type_(Some(factory_type).pack())
                .build(),
        )
        .output(
            CellOutput::new_builder()
                .capacity(CELL_CAPACITY)
                .lock(state_lock)
                .type_(Some(state_type).pack())
                .build(),
        )
        .output(
            CellOutput::new_builder()
                .capacity(ALICE_CAPACITY + BOB_CAPACITY)
                .lock(vault_lock)
                .build(),
        )
        .output(
            CellOutput::new_builder()
                .capacity(100_000_000_000u64)
                .lock(factory_vault_lock.clone())
                .build(),
        )
        .output(
            CellOutput::new_builder()
                .capacity(100_000_000_000u64)
                .lock(factory_vault_lock)
                .build(),
        )
        .output_data(new_data.pack())
        .output_data(Bytes::from(child_state.to_vec()).pack())
        .output_data(Bytes::new().pack())
        .output_data(Bytes::new().pack())
        .output_data(Bytes::new().pack())
        .witness(witness_with_input_type(exit_witness.clone()))
        .witness(witness_with_input_type(exit_witness))
        .witness(empty_witness())
        .build();
    let split_reserve_tx = context.complete_tx(split_reserve_tx);
    assert!(context.verify_tx(&split_reserve_tx, MAX_CYCLES).is_err());
}

#[ignore = "requires `make build-contracts`"]
#[test]
fn factory_type_and_vault_accept_local_exit_xudt_materialisation() {
    let (context, tx) = factory_xudt_local_exit_tx(FactoryXudtExitTamper::None);

    context
        .verify_tx(&tx, MAX_CYCLES)
        .expect("factory xUDT local exit should verify");
}

#[ignore = "requires `make build-contracts`"]
#[test]
fn factory_type_rejects_local_exit_xudt_amount_mismatch() {
    let (context, tx) =
        factory_xudt_local_exit_tx(FactoryXudtExitTamper::ChildAmountMinusOneWithConservedSupply);
    assert!(context.verify_tx(&tx, MAX_CYCLES).is_err());
}

#[ignore = "requires `make build-contracts`"]
#[test]
fn factory_type_rejects_local_exit_xudt_type_mismatch() {
    let (context, tx) =
        factory_xudt_local_exit_tx(FactoryXudtExitTamper::ChildTypeMismatchWithAuthorisedMint);
    assert!(context.verify_tx(&tx, MAX_CYCLES).is_err());
}

fn factory_xudt_local_exit_tx(tamper: FactoryXudtExitTamper) -> (Context, TransactionView) {
    let mut context = Context::default();
    let factory_lock = deploy_always_success(&mut context);
    let reserve_lock_placeholder = deploy_always_success(&mut context);
    let xudt_owner_lock = deploy_always_success_with_args(&mut context, Bytes::from(vec![9]));
    let alice_lock = deploy_always_success_with_args(&mut context, Bytes::from(vec![1]));
    let bob_lock = deploy_always_success_with_args(&mut context, Bytes::from(vec![2]));

    let factory_type = deploy_contract(&mut context, "morph-factory-type", FACTORY_ID.to_vec());
    let factory_type_hash: [u8; 32] = factory_type.calc_script_hash().unpack();
    let mut factory_vault_args = FACTORY_ID.to_vec();
    factory_vault_args.extend_from_slice(&factory_type_hash);
    let factory_vault_lock =
        deploy_contract(&mut context, "morph-factory-vault-lock", factory_vault_args);
    let xudt_type = deploy_contract(
        &mut context,
        "morph-devnet-xudt",
        xudt_owner_lock.calc_script_hash().as_slice().to_vec(),
    );
    let xudt_type_hash: [u8; 32] = xudt_type.calc_script_hash().unpack();
    let wrong_xudt_type = deploy_contract(
        &mut context,
        "morph-devnet-xudt",
        factory_lock.calc_script_hash().as_slice().to_vec(),
    );

    let descriptor = ckb_xudt_descriptor_bytes(
        xudt_type_hash,
        alice_lock.calc_script_hash().unpack(),
        ALICE_CAPACITY,
        ALICE_XUDT_AMOUNT,
        bob_lock.calc_script_hash().unpack(),
        BOB_CAPACITY,
        BOB_XUDT_AMOUNT,
    );
    let (old_factory_data, _, _) = signed_factory_pair_with_exit_digest(1, 2, [0u8; 32]);

    let factory_input_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(CELL_CAPACITY)
            .lock(factory_lock.clone())
            .type_(Some(factory_type.clone()).pack())
            .build(),
        old_factory_data,
    );
    let factory_input = CellInput::new_builder()
        .previous_output(factory_input_out_point)
        .build();
    let factory_vault_input_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(300_000_000_000u64)
            .lock(factory_vault_lock.clone())
            .type_(Some(xudt_type.clone()).pack())
            .build(),
        xudt_amount_data(ALICE_XUDT_AMOUNT + BOB_XUDT_AMOUNT),
    );
    let reserve_input = CellInput::new_builder()
        .previous_output(factory_vault_input_out_point)
        .build();
    let fee_input_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(CELL_CAPACITY)
            .lock(reserve_lock_placeholder)
            .build(),
        Bytes::new(),
    );

    let state_output_index = 1u32;
    let vault_output_index = 2u32;
    let child_anchor = derived_funding_anchor(&factory_input, state_output_index as u64);
    let state_type = deploy_contract(
        &mut context,
        "morph-state-type",
        state_args_with_anchor(child_anchor, 0),
    );
    let state_type_hash: [u8; 32] = state_type.calc_script_hash().unpack();
    let state_lock = deploy_contract(&mut context, "morph-state-lock", state_type_hash.to_vec());
    let state_lock_hash: [u8; 32] = state_lock.calc_script_hash().unpack();
    let mut vault_args = child_anchor.to_vec();
    vault_args.extend_from_slice(&0u64.to_le_bytes());
    let vault_lock = deploy_contract(&mut context, "morph-vault-lock", vault_args);
    let vault_lock_hash: [u8; 32] = vault_lock.calc_script_hash().unpack();

    let mut child_state = header_raw_with_anchor(0, PHASE_ACTIVE, child_anchor);
    child_state[174..206].copy_from_slice(&settlement_descriptor_commitment_v1(&descriptor));
    put_u16(
        &mut child_state,
        206,
        BILATERAL_CKB_XUDT_DESCRIPTOR_VERSION_V1,
    );
    let key0 = signing_key(1);
    let key1 = signing_key(2);
    let mut child_pubkeys = [pubkey(&key0), pubkey(&key1)];
    child_pubkeys.sort();
    child_state[110..142].copy_from_slice(&participants_commitment_v1(
        2,
        &[&child_pubkeys[0], &child_pubkeys[1]],
    ));

    let exit_digest = factory_local_exit_digest_v1(
        state_output_index,
        vault_output_index,
        &state_type_hash,
        &vault_lock_hash,
        &state_lock_hash,
        &child_state,
        &descriptor,
    );
    let (_, new_data, factory_sig) = signed_factory_pair_with_exit_digest(1, 2, exit_digest);
    let exit_witness = factory_local_exit_witness(
        &factory_sig,
        state_output_index,
        vault_output_index,
        state_type_hash,
        vault_lock_hash,
        state_lock_hash,
        &child_state,
        &descriptor,
    );

    let child_vault_type = match tamper {
        FactoryXudtExitTamper::ChildTypeMismatchWithAuthorisedMint => wrong_xudt_type,
        _ => xudt_type.clone(),
    };
    let child_vault_amount = match tamper {
        FactoryXudtExitTamper::ChildAmountMinusOneWithConservedSupply => {
            ALICE_XUDT_AMOUNT + BOB_XUDT_AMOUNT - 1
        }
        _ => ALICE_XUDT_AMOUNT + BOB_XUDT_AMOUNT,
    };
    let factory_vault_change_type = match tamper {
        FactoryXudtExitTamper::ChildAmountMinusOneWithConservedSupply
        | FactoryXudtExitTamper::ChildTypeMismatchWithAuthorisedMint => Some(xudt_type),
        FactoryXudtExitTamper::None => None,
    };
    let factory_vault_change_data = match tamper {
        FactoryXudtExitTamper::ChildAmountMinusOneWithConservedSupply => xudt_amount_data(1),
        FactoryXudtExitTamper::ChildTypeMismatchWithAuthorisedMint => {
            xudt_amount_data(ALICE_XUDT_AMOUNT + BOB_XUDT_AMOUNT)
        }
        FactoryXudtExitTamper::None => Bytes::new(),
    };

    let tx = TransactionBuilder::default()
        .input(factory_input)
        .input(reserve_input)
        .input(
            CellInput::new_builder()
                .previous_output(fee_input_out_point)
                .build(),
        )
        .output(
            CellOutput::new_builder()
                .capacity(CELL_CAPACITY)
                .lock(factory_lock)
                .type_(Some(factory_type).pack())
                .build(),
        )
        .output(
            CellOutput::new_builder()
                .capacity(CELL_CAPACITY)
                .lock(state_lock)
                .type_(Some(state_type).pack())
                .build(),
        )
        .output(
            CellOutput::new_builder()
                .capacity(ALICE_CAPACITY + BOB_CAPACITY)
                .lock(vault_lock)
                .type_(Some(child_vault_type).pack())
                .build(),
        )
        .output(
            CellOutput::new_builder()
                .capacity(200_000_000_000u64)
                .lock(factory_vault_lock)
                .type_(factory_vault_change_type.pack())
                .build(),
        )
        .output_data(new_data.pack())
        .output_data(Bytes::from(child_state.to_vec()).pack())
        .output_data(xudt_amount_data(child_vault_amount).pack())
        .output_data(factory_vault_change_data.pack())
        .witness(witness_with_input_type(exit_witness.clone()))
        .witness(witness_with_input_type(exit_witness))
        .witness(empty_witness())
        .build();
    let tx = context.complete_tx(tx);
    (context, tx)
}

#[ignore = "requires `make build-contracts`"]
#[test]
fn factory_type_rejects_local_exit_digest_mismatch() {
    let mut context = Context::default();
    let factory_lock = deploy_always_success(&mut context);
    let factory_type = deploy_contract(&mut context, "morph-factory-type", FACTORY_ID.to_vec());
    let descriptor = descriptor_bytes([1u8; 32], ALICE_CAPACITY, [2u8; 32], BOB_CAPACITY);
    let state_output_index = 1u32;
    let vault_output_index = 2u32;
    let (old_factory_data, _, _) = signed_factory_pair_with_exit_digest(1, 2, [0u8; 32]);
    let input_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(CELL_CAPACITY)
            .lock(factory_lock.clone())
            .type_(Some(factory_type.clone()).pack())
            .build(),
        old_factory_data,
    );
    let factory_input = CellInput::new_builder()
        .previous_output(input_out_point)
        .build();
    let child_anchor = derived_funding_anchor(&factory_input, state_output_index as u64);
    let state_type = deploy_contract(
        &mut context,
        "morph-state-type",
        state_args_with_anchor(child_anchor, 0),
    );
    let state_type_hash: [u8; 32] = state_type.calc_script_hash().unpack();
    let state_lock = deploy_contract(&mut context, "morph-state-lock", state_type_hash.to_vec());
    let state_lock_hash: [u8; 32] = state_lock.calc_script_hash().unpack();
    let vault_lock = deploy_always_success_with_args(&mut context, Bytes::from(vec![3]));
    let vault_lock_hash: [u8; 32] = vault_lock.calc_script_hash().unpack();
    let mut child_state = header_raw_with_anchor(0, PHASE_ACTIVE, child_anchor);
    child_state[174..206].copy_from_slice(&settlement_descriptor_commitment_v1(&descriptor));

    let correct_digest = factory_local_exit_digest_v1(
        state_output_index,
        vault_output_index,
        &state_type_hash,
        &vault_lock_hash,
        &state_lock_hash,
        &child_state,
        &descriptor,
    );
    let mut wrong_digest = correct_digest;
    wrong_digest[0] ^= 1;
    let (_, new_data, factory_sig) = signed_factory_pair_with_exit_digest(1, 2, wrong_digest);
    let exit_witness = factory_local_exit_witness(
        &factory_sig,
        state_output_index,
        vault_output_index,
        state_type_hash,
        vault_lock_hash,
        state_lock_hash,
        &child_state,
        &descriptor,
    );

    let tx = TransactionBuilder::default()
        .input(factory_input)
        .output(
            CellOutput::new_builder()
                .capacity(CELL_CAPACITY)
                .lock(factory_lock)
                .type_(Some(factory_type).pack())
                .build(),
        )
        .output(
            CellOutput::new_builder()
                .capacity(CELL_CAPACITY)
                .lock(state_lock)
                .type_(Some(state_type).pack())
                .build(),
        )
        .output(
            CellOutput::new_builder()
                .capacity(ALICE_CAPACITY + BOB_CAPACITY)
                .lock(vault_lock)
                .build(),
        )
        .output_data(new_data.pack())
        .output_data(Bytes::from(child_state.to_vec()).pack())
        .output_data(Bytes::new().pack())
        .witness(witness_with_input_type(exit_witness))
        .build();
    let tx = context.complete_tx(tx);

    assert!(context.verify_tx(&tx, MAX_CYCLES).is_err());
}

#[ignore = "requires `make build-contracts`"]
#[test]
fn factory_type_rejects_local_exit_state_lock_mismatch() {
    let mut context = Context::default();
    let factory_lock = deploy_always_success(&mut context);
    let factory_type = deploy_contract(&mut context, "morph-factory-type", FACTORY_ID.to_vec());
    let descriptor = descriptor_bytes([1u8; 32], ALICE_CAPACITY, [2u8; 32], BOB_CAPACITY);
    let state_output_index = 1u32;
    let vault_output_index = 2u32;
    let (old_factory_data, _, _) = signed_factory_pair_with_exit_digest(1, 2, [0u8; 32]);
    let input_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(CELL_CAPACITY)
            .lock(factory_lock.clone())
            .type_(Some(factory_type.clone()).pack())
            .build(),
        old_factory_data,
    );
    let factory_input = CellInput::new_builder()
        .previous_output(input_out_point)
        .build();
    let child_anchor = derived_funding_anchor(&factory_input, state_output_index as u64);
    let state_type = deploy_contract(
        &mut context,
        "morph-state-type",
        state_args_with_anchor(child_anchor, 0),
    );
    let state_type_hash: [u8; 32] = state_type.calc_script_hash().unpack();
    let state_lock = deploy_contract(&mut context, "morph-state-lock", state_type_hash.to_vec());
    let state_lock_hash: [u8; 32] = state_lock.calc_script_hash().unpack();
    let wrong_state_lock = deploy_always_success_with_args(&mut context, Bytes::from(vec![4]));
    let vault_lock = deploy_always_success_with_args(&mut context, Bytes::from(vec![3]));
    let vault_lock_hash: [u8; 32] = vault_lock.calc_script_hash().unpack();
    let mut child_state = header_raw_with_anchor(0, PHASE_ACTIVE, child_anchor);
    child_state[174..206].copy_from_slice(&settlement_descriptor_commitment_v1(&descriptor));

    let exit_digest = factory_local_exit_digest_v1(
        state_output_index,
        vault_output_index,
        &state_type_hash,
        &vault_lock_hash,
        &state_lock_hash,
        &child_state,
        &descriptor,
    );
    let (_, new_data, factory_sig) = signed_factory_pair_with_exit_digest(1, 2, exit_digest);
    let exit_witness = factory_local_exit_witness(
        &factory_sig,
        state_output_index,
        vault_output_index,
        state_type_hash,
        vault_lock_hash,
        state_lock_hash,
        &child_state,
        &descriptor,
    );

    let tx = TransactionBuilder::default()
        .input(factory_input)
        .output(
            CellOutput::new_builder()
                .capacity(CELL_CAPACITY)
                .lock(factory_lock)
                .type_(Some(factory_type).pack())
                .build(),
        )
        .output(
            CellOutput::new_builder()
                .capacity(CELL_CAPACITY)
                .lock(wrong_state_lock)
                .type_(Some(state_type).pack())
                .build(),
        )
        .output(
            CellOutput::new_builder()
                .capacity(ALICE_CAPACITY + BOB_CAPACITY)
                .lock(vault_lock)
                .build(),
        )
        .output_data(new_data.pack())
        .output_data(Bytes::from(child_state.to_vec()).pack())
        .output_data(Bytes::new().pack())
        .witness(witness_with_input_type(exit_witness))
        .build();
    let tx = context.complete_tx(tx);

    assert!(context.verify_tx(&tx, MAX_CYCLES).is_err());
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
    let state_refund_lock = deploy_always_success(&mut context);
    let alice_lock = deploy_always_success_with_args(&mut context, Bytes::from(vec![1]));
    let bob_lock = deploy_always_success_with_args(&mut context, Bytes::from(vec![2]));
    let descriptor = descriptor_bytes(
        alice_lock.calc_script_hash().unpack(),
        ALICE_CAPACITY,
        bob_lock.calc_script_hash().unpack(),
        BOB_CAPACITY,
    );
    let descriptor_commitment = settlement_descriptor_commitment_v1(&descriptor);
    let state_type = deploy_contract(&mut context, "morph-state-type", state_args(0));
    let mut vault_args = FUNDING_ANCHOR.to_vec();
    vault_args.extend_from_slice(&0u64.to_le_bytes());
    let vault_lock = deploy_contract(&mut context, "morph-vault-lock", vault_args);

    let state_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(CELL_CAPACITY)
            .lock(state_refund_lock)
            .type_(Some(state_type).pack())
            .build(),
        header_with_descriptor(3, PHASE_SETTLING, descriptor_commitment),
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
                .capacity(ALICE_CAPACITY)
                .lock(alice_lock)
                .build(),
        )
        .output(
            CellOutput::new_builder()
                .capacity(BOB_CAPACITY)
                .lock(bob_lock)
                .build(),
        )
        .output_data(Bytes::new().pack())
        .output_data(Bytes::new().pack())
        .witness(empty_witness())
        .witness(witness_with_input_type(descriptor))
        .build();
    let tx = context.complete_tx(tx);

    context
        .verify_tx(&tx, MAX_CYCLES)
        .expect("vault finalise should verify");
}

#[ignore = "requires `make build-contracts`"]
#[test]
fn vault_lock_rejects_descriptor_output_mismatch() {
    let mut context = Context::default();
    let state_refund_lock = deploy_always_success(&mut context);
    let alice_lock = deploy_always_success_with_args(&mut context, Bytes::from(vec![1]));
    let bob_lock = deploy_always_success_with_args(&mut context, Bytes::from(vec![2]));
    let descriptor = descriptor_bytes(
        alice_lock.calc_script_hash().unpack(),
        ALICE_CAPACITY,
        bob_lock.calc_script_hash().unpack(),
        BOB_CAPACITY,
    );
    let descriptor_commitment = settlement_descriptor_commitment_v1(&descriptor);
    let state_type = deploy_contract(&mut context, "morph-state-type", state_args(0));
    let mut vault_args = FUNDING_ANCHOR.to_vec();
    vault_args.extend_from_slice(&0u64.to_le_bytes());
    let vault_lock = deploy_contract(&mut context, "morph-vault-lock", vault_args);

    let state_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(CELL_CAPACITY)
            .lock(state_refund_lock)
            .type_(Some(state_type).pack())
            .build(),
        header_with_descriptor(3, PHASE_SETTLING, descriptor_commitment),
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
                .capacity(ALICE_CAPACITY - 1)
                .lock(alice_lock)
                .build(),
        )
        .output(
            CellOutput::new_builder()
                .capacity(BOB_CAPACITY)
                .lock(bob_lock)
                .build(),
        )
        .output_data(Bytes::new().pack())
        .output_data(Bytes::new().pack())
        .witness(empty_witness())
        .witness(witness_with_input_type(descriptor))
        .build();
    let tx = context.complete_tx(tx);

    assert!(context.verify_tx(&tx, MAX_CYCLES).is_err());
}

#[ignore = "requires `make build-contracts`"]
#[test]
fn devnet_xudt_allows_owner_mint_and_conserves_transfer() {
    let mut context = Context::default();
    let owner_lock = deploy_always_success_with_args(&mut context, Bytes::from(vec![1]));
    let alice_lock = deploy_always_success_with_args(&mut context, Bytes::from(vec![2]));
    let bob_lock = deploy_always_success_with_args(&mut context, Bytes::from(vec![3]));
    let xudt_type = deploy_contract(
        &mut context,
        "morph-devnet-xudt",
        owner_lock.calc_script_hash().as_slice().to_vec(),
    );

    let owner_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(CELL_CAPACITY)
            .lock(owner_lock.clone())
            .build(),
        Bytes::new(),
    );
    let mint_tx = TransactionBuilder::default()
        .input(
            CellInput::new_builder()
                .previous_output(owner_out_point)
                .build(),
        )
        .output(
            CellOutput::new_builder()
                .capacity(CELL_CAPACITY)
                .lock(alice_lock.clone())
                .type_(Some(xudt_type.clone()).pack())
                .build(),
        )
        .output_data(xudt_amount_data(100).pack())
        .build();
    let mint_tx = context.complete_tx(mint_tx);
    context
        .verify_tx(&mint_tx, MAX_CYCLES)
        .expect("owner mint should verify");

    let xudt_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(CELL_CAPACITY)
            .lock(alice_lock.clone())
            .type_(Some(xudt_type.clone()).pack())
            .build(),
        xudt_amount_data(100),
    );
    let transfer_tx = TransactionBuilder::default()
        .input(
            CellInput::new_builder()
                .previous_output(xudt_out_point)
                .build(),
        )
        .output(
            CellOutput::new_builder()
                .capacity(ALICE_CAPACITY)
                .lock(alice_lock)
                .type_(Some(xudt_type.clone()).pack())
                .build(),
        )
        .output(
            CellOutput::new_builder()
                .capacity(BOB_CAPACITY)
                .lock(bob_lock)
                .type_(Some(xudt_type).pack())
                .build(),
        )
        .output_data(xudt_amount_data(ALICE_XUDT_AMOUNT).pack())
        .output_data(xudt_amount_data(BOB_XUDT_AMOUNT).pack())
        .build();
    let transfer_tx = context.complete_tx(transfer_tx);
    context
        .verify_tx(&transfer_tx, MAX_CYCLES)
        .expect("xUDT amount conservation should verify");
}

#[ignore = "requires `make build-contracts`"]
#[test]
fn vault_lock_accepts_xudt_finalise_with_descriptor_amounts() {
    let mut context = Context::default();
    let state_refund_lock = deploy_always_success(&mut context);
    let xudt_owner_lock = deploy_always_success_with_args(&mut context, Bytes::from(vec![9]));
    let alice_lock = deploy_always_success_with_args(&mut context, Bytes::from(vec![1]));
    let bob_lock = deploy_always_success_with_args(&mut context, Bytes::from(vec![2]));
    let xudt_type = deploy_contract(
        &mut context,
        "morph-devnet-xudt",
        xudt_owner_lock.calc_script_hash().as_slice().to_vec(),
    );
    let xudt_type_hash = xudt_type.calc_script_hash().unpack();
    let descriptor = ckb_xudt_descriptor_bytes(
        xudt_type_hash,
        alice_lock.calc_script_hash().unpack(),
        ALICE_CAPACITY,
        ALICE_XUDT_AMOUNT,
        bob_lock.calc_script_hash().unpack(),
        BOB_CAPACITY,
        BOB_XUDT_AMOUNT,
    );
    let descriptor_commitment = settlement_descriptor_commitment_v1(&descriptor);
    let state_type = deploy_contract(&mut context, "morph-state-type", state_args(0));
    let mut vault_args = FUNDING_ANCHOR.to_vec();
    vault_args.extend_from_slice(&0u64.to_le_bytes());
    let vault_lock = deploy_contract(&mut context, "morph-vault-lock", vault_args);

    let state_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(CELL_CAPACITY)
            .lock(state_refund_lock)
            .type_(Some(state_type).pack())
            .build(),
        header_with_descriptor_version(3, PHASE_SETTLING, descriptor_commitment, 2),
    );
    let vault_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(CELL_CAPACITY)
            .lock(vault_lock)
            .type_(Some(xudt_type.clone()).pack())
            .build(),
        xudt_amount_data(ALICE_XUDT_AMOUNT + BOB_XUDT_AMOUNT),
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
                .capacity(ALICE_CAPACITY)
                .lock(alice_lock)
                .type_(Some(xudt_type.clone()).pack())
                .build(),
        )
        .output(
            CellOutput::new_builder()
                .capacity(BOB_CAPACITY)
                .lock(bob_lock)
                .type_(Some(xudt_type).pack())
                .build(),
        )
        .output_data(xudt_amount_data(ALICE_XUDT_AMOUNT).pack())
        .output_data(xudt_amount_data(BOB_XUDT_AMOUNT).pack())
        .witness(empty_witness())
        .witness(witness_with_input_type(descriptor))
        .build();
    let tx = context.complete_tx(tx);

    context
        .verify_tx(&tx, MAX_CYCLES)
        .expect("xUDT vault finalise should verify");
}

#[ignore = "requires `make build-contracts`"]
#[test]
fn sponsor_lock_accepts_bounded_fee_with_wallet_change() {
    let mut context = Context::default();
    let wallet_lock = deploy_always_success(&mut context);
    let state_lock = deploy_always_success_with_args(&mut context, Bytes::from(vec![7]));
    let state_type = deploy_contract(&mut context, "morph-state-type", state_args(0));
    let (old_state_data, new_state_data, sig_witness) = signed_state_pair(1, 1, 2, PHASE_SETTLING);
    let change_hash = wallet_lock.calc_script_hash();
    let sponsor_lock = deploy_contract(
        &mut context,
        "morph-sponsor-lock",
        sponsor_policy(change_hash.as_slice().try_into().unwrap(), 1_000),
    );

    let state_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(CELL_CAPACITY)
            .lock(state_lock.clone())
            .type_(Some(state_type.clone()).pack())
            .build(),
        old_state_data,
    );
    let sponsor_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(CELL_CAPACITY)
            .lock(sponsor_lock)
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
                .previous_output(sponsor_out_point)
                .build(),
        )
        .output(
            CellOutput::new_builder()
                .capacity(CELL_CAPACITY)
                .lock(state_lock)
                .type_(Some(state_type).pack())
                .build(),
        )
        .output(
            CellOutput::new_builder()
                .capacity(CELL_CAPACITY - 100)
                .lock(wallet_lock)
                .build(),
        )
        .output_data(new_state_data.pack())
        .output_data(Bytes::new().pack())
        .witness(witness_with_input_type(sig_witness))
        .witness(empty_witness())
        .build();
    let tx = context.complete_tx(tx);

    context
        .verify_tx(&tx, MAX_CYCLES)
        .expect("bounded sponsor fee should verify");
}

#[ignore = "requires `make build-contracts`"]
#[test]
fn sponsor_lock_rejects_fee_above_per_tx_limit() {
    let mut context = Context::default();
    let wallet_lock = deploy_always_success(&mut context);
    let state_lock = deploy_always_success_with_args(&mut context, Bytes::from(vec![7]));
    let state_type = deploy_contract(&mut context, "morph-state-type", state_args(0));
    let (old_state_data, new_state_data, sig_witness) = signed_state_pair(1, 1, 2, PHASE_SETTLING);
    let change_hash = wallet_lock.calc_script_hash();
    let sponsor_lock = deploy_contract(
        &mut context,
        "morph-sponsor-lock",
        sponsor_policy(change_hash.as_slice().try_into().unwrap(), 50),
    );

    let state_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(CELL_CAPACITY)
            .lock(state_lock.clone())
            .type_(Some(state_type.clone()).pack())
            .build(),
        old_state_data,
    );
    let sponsor_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(CELL_CAPACITY)
            .lock(sponsor_lock)
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
                .previous_output(sponsor_out_point)
                .build(),
        )
        .output(
            CellOutput::new_builder()
                .capacity(CELL_CAPACITY)
                .lock(state_lock)
                .type_(Some(state_type).pack())
                .build(),
        )
        .output(
            CellOutput::new_builder()
                .capacity(CELL_CAPACITY - 100)
                .lock(wallet_lock)
                .build(),
        )
        .output_data(new_state_data.pack())
        .output_data(Bytes::new().pack())
        .witness(witness_with_input_type(sig_witness))
        .witness(empty_witness())
        .build();
    let tx = context.complete_tx(tx);

    assert!(context.verify_tx(&tx, MAX_CYCLES).is_err());
}

#[ignore = "requires `make build-contracts`"]
#[test]
fn sponsor_lock_rejects_state_number_outside_policy_range() {
    let mut context = Context::default();
    let wallet_lock = deploy_always_success(&mut context);
    let state_lock = deploy_always_success_with_args(&mut context, Bytes::from(vec![7]));
    let state_type = deploy_contract(&mut context, "morph-state-type", state_args(0));
    let (old_state_data, new_state_data, sig_witness) = signed_state_pair(1, 1, 2, PHASE_SETTLING);
    let change_hash = wallet_lock.calc_script_hash();
    let sponsor_lock = deploy_contract(
        &mut context,
        "morph-sponsor-lock",
        sponsor_policy_with_bounds(
            change_hash.as_slice().try_into().unwrap(),
            3,
            10,
            1_000,
            1_000,
        ),
    );

    let state_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(CELL_CAPACITY)
            .lock(state_lock.clone())
            .type_(Some(state_type.clone()).pack())
            .build(),
        old_state_data,
    );
    let sponsor_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(CELL_CAPACITY)
            .lock(sponsor_lock)
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
                .previous_output(sponsor_out_point)
                .build(),
        )
        .output(
            CellOutput::new_builder()
                .capacity(CELL_CAPACITY)
                .lock(state_lock)
                .type_(Some(state_type).pack())
                .build(),
        )
        .output(
            CellOutput::new_builder()
                .capacity(CELL_CAPACITY - 100)
                .lock(wallet_lock)
                .build(),
        )
        .output_data(new_state_data.pack())
        .output_data(Bytes::new().pack())
        .witness(witness_with_input_type(sig_witness))
        .witness(empty_witness())
        .build();
    let tx = context.complete_tx(tx);

    assert!(context.verify_tx(&tx, MAX_CYCLES).is_err());
}

#[ignore = "requires `make build-contracts`"]
#[test]
fn sponsor_lock_rejects_fee_without_state_publication() {
    let mut context = Context::default();
    let wallet_lock = deploy_always_success(&mut context);
    let change_hash = wallet_lock.calc_script_hash();
    let sponsor_lock = deploy_contract(
        &mut context,
        "morph-sponsor-lock",
        sponsor_policy(change_hash.as_slice().try_into().unwrap(), 1_000),
    );

    let sponsor_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(CELL_CAPACITY)
            .lock(sponsor_lock)
            .build(),
        Bytes::new(),
    );
    let tx = TransactionBuilder::default()
        .input(
            CellInput::new_builder()
                .previous_output(sponsor_out_point)
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

    assert!(context.verify_tx(&tx, MAX_CYCLES).is_err());
}
