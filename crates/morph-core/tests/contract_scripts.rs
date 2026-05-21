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
use morph_core::types::{FactoryMerkleSibling, FactoryRight, FactoryRightId, FactoryRightKind};
use morph_core::validation::{factory_right_sparse_proof, factory_right_sparse_root};
use morph_script_common::{
    BILATERAL_CKB_DESCRIPTOR_OUTPUT_COUNT_V1, BILATERAL_CKB_DESCRIPTOR_V1_LEN,
    BILATERAL_CKB_DESCRIPTOR_VERSION_V1, BILATERAL_CKB_XUDT_DESCRIPTOR_ASSET_COUNT_V1,
    BILATERAL_CKB_XUDT_DESCRIPTOR_V1_LEN, BILATERAL_CKB_XUDT_DESCRIPTOR_VERSION_V1,
    BILATERAL_SIGNATURE_COUNT_V1, BILATERAL_SIGNATURE_THRESHOLD_V1,
    BILATERAL_SIGNATURE_WITNESS_V1_LEN, BILATERAL_SIGNATURE_WITNESS_VERSION_V1, BYTE32_LEN,
    COMPRESSED_SECP256K1_PUBKEY_LEN, ECDSA_SIGNATURE_LEN, FACTORY_LOCAL_EXIT_WITNESS_V1_LEN,
    FACTORY_LOCAL_EXIT_WITNESS_VERSION_V1, FACTORY_MERKLE_UPDATE_RIGHT_COUNT_V1,
    FACTORY_MERKLE_UPDATE_WITNESS_V1_LEN, FACTORY_MERKLE_UPDATE_WITNESS_VERSION_V1,
    FACTORY_REDUCED_EXIT_WITNESS_V1_LEN, FACTORY_REDUCED_EXIT_WITNESS_VERSION_V1,
    FACTORY_REDUCED_EXIT_XUDT_WITNESS_V1_LEN, FACTORY_REDUCED_RIGHTS_AUTHORISED_COUNT_V1,
    FACTORY_REDUCED_RIGHTS_COUNT_V1, FACTORY_REDUCED_RIGHTS_PARTICIPANT_COUNT_V1,
    FACTORY_REDUCED_RIGHTS_PARTICIPANT_ENTRY_V1_LEN,
    FACTORY_REDUCED_RIGHTS_PARTICIPANT_THRESHOLD_V1, FACTORY_REDUCED_RIGHTS_WITNESS_V1_LEN,
    FACTORY_REDUCED_RIGHTS_WITNESS_VERSION_V1, FACTORY_REDUCED_SPLICE_WITNESS_V1_LEN,
    FACTORY_REDUCED_SPLICE_WITNESS_VERSION_V1, FACTORY_RIGHT_KIND_RESERVE_CLAIM,
    FACTORY_RIGHT_V1_LEN, FACTORY_SIGNATURE_COUNT_V1, FACTORY_SIGNATURE_THRESHOLD_V1,
    FACTORY_SIGNATURE_WITNESS_V1_LEN, FACTORY_SIGNATURE_WITNESS_VERSION_V1,
    FACTORY_SPARSE_MERKLE_DEPTH_V1, FACTORY_SPLICE_HEADER_V1_LEN, FACTORY_SPLICE_WITNESS_V1_LEN,
    FACTORY_SPLICE_WITNESS_VERSION_V1, FACTORY_STATE_HEADER_V1_LEN,
    FACTORY_VAULT_ASSET_AMOUNT_V1_LEN, FACTORY_VAULT_DELTA_V1_LEN, FACTORY_VAULT_DELTAS_V1_LEN,
    FACTORY_VAULT_DESCRIPTOR_V1_LEN, FactoryMerkleUpdateWitnessV1, FactoryReducedExitWitnessV1,
    FactoryReducedRightsWitnessV1, FactoryReducedSpliceWitnessV1, FactorySpliceHeaderV1,
    FactoryStateHeaderV1, FactoryVaultDeltasV1, PHASE_ACTIVE, PHASE_SETTLING,
    SPLICE_ASSET_DELTA_V1_LEN, SPLICE_ASSET_DELTAS_V1_LEN, SPLICE_HEADER_V1_LEN, SPLICE_KIND_IN_V1,
    SPLICE_KIND_OUT_V1, SPLICE_SIGNATURE_COUNT_V1, SPLICE_SIGNATURE_THRESHOLD_V1,
    SPLICE_SIGNATURE_WITNESS_V1_LEN, SPLICE_SIGNATURE_WITNESS_VERSION_V1,
    SPLICE_STATE_TRANSITION_WITNESS_V1_LEN, SPLICE_STATE_TRANSITION_WITNESS_VERSION_V1,
    SPLICE_VAULT_ASSET_AMOUNT_V2_LEN, SPLICE_VAULT_DESCRIPTOR_V2_LEN, SPONSOR_POLICY_V1_LEN,
    STATE_HEADER_V1_LEN, SpliceAssetDeltasV1, SpliceHeaderV1, SpliceStateTransitionWitnessV1,
    SpliceVaultDescriptorV2, StateHeaderV1, VAULT_ASSET_KIND_CKB_V1, blake2b256,
    factory_local_exit_digest_v1, factory_participants_commitment_v1, participants_commitment_v1,
    relative_block_since, settlement_descriptor_commitment_v1, vault_cell_commitment_v1,
};
use std::fs;
use std::path::PathBuf;

const MAX_CYCLES: u64 = 50_000_000;
const CELL_CAPACITY: u64 = 100_000_000_000;
const ALICE_CAPACITY: u64 = 60_000_000_000;
const BOB_CAPACITY: u64 = 40_000_000_000;
const FUNDING_ANCHOR: [u8; 32] = [4u8; 32];
const NEW_FUNDING_ANCHOR: [u8; 32] = [10u8; 32];
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

fn put_u32(raw: &mut [u8], offset: usize, value: u32) {
    raw[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
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

fn relative_since(value: u64) -> u64 {
    relative_block_since(value).expect("relative block since")
}

fn vault_args(
    anchor: [u8; 32],
    finalise_since: u64,
    state_type: &ckb_testtool::ckb_types::packed::Script,
    state_lock: &ckb_testtool::ckb_types::packed::Script,
) -> Vec<u8> {
    let mut args = anchor.to_vec();
    args.extend_from_slice(&finalise_since.to_le_bytes());
    args.extend_from_slice(state_type.code_hash().as_slice());
    args.push(state_type.hash_type().as_slice()[0]);
    args.extend_from_slice(state_lock.code_hash().as_slice());
    args.push(state_lock.hash_type().as_slice()[0]);
    args
}

fn set_state_payload_commitment(raw: &mut [u8], commitment: [u8; 32]) {
    raw[208..240].copy_from_slice(&commitment);
}

fn vault_commitment(
    lock: &ckb_testtool::ckb_types::packed::Script,
    capacity: u64,
    type_hash: Option<[u8; 32]>,
    data: &[u8],
) -> [u8; 32] {
    vault_cell_commitment_v1(
        lock.calc_script_hash().as_slice(),
        capacity,
        type_hash.as_ref().map(|hash| hash.as_slice()),
        data,
    )
}

fn bind_splice_state_payloads(
    old_state_data: Bytes,
    new_state_data: Bytes,
    old_vault_lock: &ckb_testtool::ckb_types::packed::Script,
    old_vault_capacity: u64,
    new_vault_lock: &ckb_testtool::ckb_types::packed::Script,
    new_vault_capacity: u64,
) -> (Bytes, Bytes) {
    let mut old_state = old_state_data.to_vec();
    set_state_payload_commitment(
        &mut old_state,
        vault_commitment(old_vault_lock, old_vault_capacity, None, &[]),
    );
    let mut new_state = new_state_data.to_vec();
    set_state_payload_commitment(
        &mut new_state,
        vault_commitment(new_vault_lock, new_vault_capacity, None, &[]),
    );
    (Bytes::from(old_state), Bytes::from(new_state))
}

fn build_state_type_from_code(
    context: &mut Context,
    code: &ckb_testtool::ckb_types::packed::OutPoint,
    anchor: [u8; 32],
    finalise_since: u64,
) -> ckb_testtool::ckb_types::packed::Script {
    context
        .build_script(code, state_args_with_anchor(anchor, finalise_since).into())
        .expect("state type script")
}

fn build_state_lock_from_code(
    context: &mut Context,
    code: &ckb_testtool::ckb_types::packed::OutPoint,
    state_type: &ckb_testtool::ckb_types::packed::Script,
) -> ckb_testtool::ckb_types::packed::Script {
    let state_type_hash: [u8; 32] = state_type.calc_script_hash().unpack();
    context
        .build_script(code, state_type_hash.to_vec().into())
        .expect("state lock script")
}

fn build_vault_lock_from_code(
    context: &mut Context,
    code: &ckb_testtool::ckb_types::packed::OutPoint,
    anchor: [u8; 32],
    finalise_since: u64,
    state_type: &ckb_testtool::ckb_types::packed::Script,
    state_lock: &ckb_testtool::ckb_types::packed::Script,
) -> ckb_testtool::ckb_types::packed::Script {
    context
        .build_script(
            code,
            vault_args(anchor, finalise_since, state_type, state_lock).into(),
        )
        .expect("vault lock script")
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

fn signed_state_pair_with_new_descriptor(
    old_number: u64,
    old_phase: u8,
    new_number: u64,
    new_phase: u8,
    descriptor_commitment: [u8; BYTE32_LEN],
    descriptor_version: u16,
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
    new[174..206].copy_from_slice(&descriptor_commitment);
    put_u16(&mut new, 206, descriptor_version);

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

fn signed_splice_out_bundle(
    old_anchor: [u8; BYTE32_LEN],
    new_anchor: [u8; BYTE32_LEN],
    state_number: u64,
    old_capacity: u64,
    new_capacity: u64,
) -> (Bytes, Bytes, Bytes) {
    signed_splice_ckb_bundle(
        SPLICE_KIND_OUT_V1,
        old_anchor,
        new_anchor,
        state_number,
        old_capacity,
        new_capacity,
        None,
    )
}

fn signed_splice_in_bundle(
    old_anchor: [u8; BYTE32_LEN],
    new_anchor: [u8; BYTE32_LEN],
    state_number: u64,
    old_capacity: u64,
    new_capacity: u64,
) -> (Bytes, Bytes, Bytes) {
    signed_splice_ckb_bundle(
        SPLICE_KIND_IN_V1,
        old_anchor,
        new_anchor,
        state_number,
        old_capacity,
        new_capacity,
        None,
    )
}

fn signed_splice_out_bundle_with_channel(
    old_anchor: [u8; BYTE32_LEN],
    new_anchor: [u8; BYTE32_LEN],
    state_number: u64,
    old_capacity: u64,
    new_capacity: u64,
    header_channel_id: [u8; BYTE32_LEN],
) -> (Bytes, Bytes, Bytes) {
    signed_splice_ckb_bundle(
        SPLICE_KIND_OUT_V1,
        old_anchor,
        new_anchor,
        state_number,
        old_capacity,
        new_capacity,
        Some(header_channel_id),
    )
}

fn signed_splice_ckb_bundle(
    kind: u8,
    old_anchor: [u8; BYTE32_LEN],
    new_anchor: [u8; BYTE32_LEN],
    state_number: u64,
    old_capacity: u64,
    new_capacity: u64,
    header_channel_id: Option<[u8; BYTE32_LEN]>,
) -> (Bytes, Bytes, Bytes) {
    let key0 = signing_key(1);
    let key1 = signing_key(2);
    let mut entries = [(pubkey(&key0), key0), (pubkey(&key1), key1)];
    entries.sort_by(|left, right| left.0.cmp(&right.0));
    let participants = participants_commitment_v1(2, &[&entries[0].0, &entries[1].0]);

    let old_asset = splice_vault_asset_bytes(
        VAULT_ASSET_KIND_CKB_V1,
        &[0u8; BYTE32_LEN],
        old_capacity as u128,
    );
    let old_vault_raw = splice_vault_descriptor_bytes(old_anchor, 1, &old_asset, None);
    let old_vault = SpliceVaultDescriptorV2::parse(&old_vault_raw).unwrap();

    let new_asset = splice_vault_asset_bytes(
        VAULT_ASSET_KIND_CKB_V1,
        &[0u8; BYTE32_LEN],
        new_capacity as u128,
    );
    let new_vault_raw = splice_vault_descriptor_bytes(new_anchor, 1, &new_asset, None);
    let new_vault = SpliceVaultDescriptorV2::parse(&new_vault_raw).unwrap();

    let (external_input, withdrawal) = match kind {
        SPLICE_KIND_IN_V1 => (new_capacity - old_capacity, 0),
        SPLICE_KIND_OUT_V1 => (0, old_capacity - new_capacity),
        _ => unreachable!("test fixture only builds known splice kinds"),
    };
    let delta = splice_asset_delta_bytes(
        VAULT_ASSET_KIND_CKB_V1,
        &[0u8; BYTE32_LEN],
        old_capacity as u128,
        new_capacity as u128,
        external_input as u128,
        withdrawal as u128,
        0,
    );
    let deltas_raw = splice_asset_deltas_bytes(1, &delta, None);
    let deltas = SpliceAssetDeltasV1::parse(&deltas_raw).unwrap();

    let mut splice_header_raw = splice_header_bytes(
        kind,
        old_anchor,
        new_anchor,
        state_number,
        &participants,
        (
            &old_vault.commitment().unwrap(),
            &new_vault.commitment().unwrap(),
            &deltas.commitment().unwrap(),
        ),
    );
    if let Some(channel_id) = header_channel_id {
        splice_header_raw[36..68].copy_from_slice(&channel_id);
    }
    let splice_header = SpliceHeaderV1::parse(&splice_header_raw).unwrap();
    let signature_witness =
        signed_splice_signature_witness(&entries, &splice_header.signing_digest());
    let bundle_raw = splice_state_transition_witness_bytes(
        &splice_header_raw,
        &signature_witness,
        &old_vault_raw,
        &new_vault_raw,
        &deltas_raw,
    );
    SpliceStateTransitionWitnessV1::parse(&bundle_raw).unwrap();

    let mut old_state = header_raw_with_anchor(state_number, PHASE_ACTIVE, old_anchor);
    old_state[110..142].copy_from_slice(&participants);
    let mut new_state = header_raw_with_anchor(state_number, PHASE_ACTIVE, new_anchor);
    new_state[110..142].copy_from_slice(&participants);

    (
        old_state.to_vec().into(),
        new_state.to_vec().into(),
        bundle_raw.to_vec().into(),
    )
}

fn signed_splice_signature_witness(
    entries: &[([u8; COMPRESSED_SECP256K1_PUBKEY_LEN], SigningKey); 2],
    digest: &[u8; BYTE32_LEN],
) -> [u8; SPLICE_SIGNATURE_WITNESS_V1_LEN] {
    let mut witness = [0u8; SPLICE_SIGNATURE_WITNESS_V1_LEN];
    put_u16(&mut witness, 0, SPLICE_SIGNATURE_WITNESS_VERSION_V1);
    witness[2] = SPLICE_SIGNATURE_THRESHOLD_V1;
    witness[3] = SPLICE_SIGNATURE_COUNT_V1;
    for (index, (pubkey, key)) in entries.iter().enumerate() {
        let offset = 4 + index * (COMPRESSED_SECP256K1_PUBKEY_LEN + ECDSA_SIGNATURE_LEN);
        witness[offset..offset + COMPRESSED_SECP256K1_PUBKEY_LEN].copy_from_slice(pubkey);
        witness[offset + COMPRESSED_SECP256K1_PUBKEY_LEN
            ..offset + COMPRESSED_SECP256K1_PUBKEY_LEN + ECDSA_SIGNATURE_LEN]
            .copy_from_slice(&signature(key, digest));
    }
    witness
}

fn splice_header_bytes(
    kind: u8,
    old_anchor: [u8; BYTE32_LEN],
    new_anchor: [u8; BYTE32_LEN],
    base_state_number: u64,
    participants: &[u8; BYTE32_LEN],
    commitments: (&[u8; BYTE32_LEN], &[u8; BYTE32_LEN], &[u8; BYTE32_LEN]),
) -> [u8; SPLICE_HEADER_V1_LEN] {
    let mut raw = [0u8; SPLICE_HEADER_V1_LEN];
    put_u16(&mut raw, 0, 1);
    raw[2..34].fill(2);
    put_u16(&mut raw, 34, 1);
    raw[36..68].fill(3);
    raw[68..100].copy_from_slice(&old_anchor);
    raw[100..132].copy_from_slice(&new_anchor);
    put_u64(&mut raw, 132, 0);
    put_u64(&mut raw, 140, 1);
    put_u64(&mut raw, 148, base_state_number);
    put_u64(&mut raw, 156, 1);
    raw[164] = kind;
    raw[165..197].copy_from_slice(commitments.0);
    raw[197..229].copy_from_slice(commitments.1);
    raw[229..261].copy_from_slice(commitments.2);
    raw[261..293].copy_from_slice(participants);
    raw[293..325].fill(9);
    raw
}

fn splice_vault_asset_bytes(
    kind: u8,
    type_hash: &[u8; BYTE32_LEN],
    amount: u128,
) -> [u8; SPLICE_VAULT_ASSET_AMOUNT_V2_LEN] {
    let mut raw = [0u8; SPLICE_VAULT_ASSET_AMOUNT_V2_LEN];
    raw[0] = kind;
    raw[1..33].copy_from_slice(type_hash);
    put_u128(&mut raw, 33, amount);
    raw
}

fn splice_vault_descriptor_bytes(
    funding_anchor: [u8; BYTE32_LEN],
    count: u16,
    asset_0: &[u8; SPLICE_VAULT_ASSET_AMOUNT_V2_LEN],
    asset_1: Option<&[u8; SPLICE_VAULT_ASSET_AMOUNT_V2_LEN]>,
) -> [u8; SPLICE_VAULT_DESCRIPTOR_V2_LEN] {
    let mut raw = [0u8; SPLICE_VAULT_DESCRIPTOR_V2_LEN];
    raw[0..32].copy_from_slice(&funding_anchor);
    put_u16(&mut raw, 32, count);
    raw[34..34 + SPLICE_VAULT_ASSET_AMOUNT_V2_LEN].copy_from_slice(asset_0);
    if let Some(asset) = asset_1 {
        let offset = 34 + SPLICE_VAULT_ASSET_AMOUNT_V2_LEN;
        raw[offset..offset + SPLICE_VAULT_ASSET_AMOUNT_V2_LEN].copy_from_slice(asset);
    }
    raw
}

fn splice_asset_delta_bytes(
    kind: u8,
    type_hash: &[u8; BYTE32_LEN],
    old_amount: u128,
    new_amount: u128,
    external_input: u128,
    withdrawal: u128,
    signed_fee: u128,
) -> [u8; SPLICE_ASSET_DELTA_V1_LEN] {
    let mut raw = [0u8; SPLICE_ASSET_DELTA_V1_LEN];
    raw[0] = kind;
    raw[1..33].copy_from_slice(type_hash);
    put_u128(&mut raw, 33, old_amount);
    put_u128(&mut raw, 49, new_amount);
    put_u128(&mut raw, 65, external_input);
    put_u128(&mut raw, 81, withdrawal);
    put_u128(&mut raw, 97, signed_fee);
    raw
}

fn splice_asset_deltas_bytes(
    count: u16,
    delta_0: &[u8; SPLICE_ASSET_DELTA_V1_LEN],
    delta_1: Option<&[u8; SPLICE_ASSET_DELTA_V1_LEN]>,
) -> [u8; SPLICE_ASSET_DELTAS_V1_LEN] {
    let mut raw = [0u8; SPLICE_ASSET_DELTAS_V1_LEN];
    put_u16(&mut raw, 0, count);
    raw[2..2 + SPLICE_ASSET_DELTA_V1_LEN].copy_from_slice(delta_0);
    if let Some(delta) = delta_1 {
        let offset = 2 + SPLICE_ASSET_DELTA_V1_LEN;
        raw[offset..offset + SPLICE_ASSET_DELTA_V1_LEN].copy_from_slice(delta);
    }
    raw
}

fn splice_state_transition_witness_bytes(
    header: &[u8; SPLICE_HEADER_V1_LEN],
    signatures: &[u8; SPLICE_SIGNATURE_WITNESS_V1_LEN],
    old_vault: &[u8; SPLICE_VAULT_DESCRIPTOR_V2_LEN],
    new_vault: &[u8; SPLICE_VAULT_DESCRIPTOR_V2_LEN],
    deltas: &[u8; SPLICE_ASSET_DELTAS_V1_LEN],
) -> [u8; SPLICE_STATE_TRANSITION_WITNESS_V1_LEN] {
    let mut raw = [0u8; SPLICE_STATE_TRANSITION_WITNESS_V1_LEN];
    put_u16(&mut raw, 0, SPLICE_STATE_TRANSITION_WITNESS_VERSION_V1);
    let mut offset = 2;
    raw[offset..offset + SPLICE_HEADER_V1_LEN].copy_from_slice(header);
    offset += SPLICE_HEADER_V1_LEN;
    raw[offset..offset + SPLICE_SIGNATURE_WITNESS_V1_LEN].copy_from_slice(signatures);
    offset += SPLICE_SIGNATURE_WITNESS_V1_LEN;
    raw[offset..offset + SPLICE_VAULT_DESCRIPTOR_V2_LEN].copy_from_slice(old_vault);
    offset += SPLICE_VAULT_DESCRIPTOR_V2_LEN;
    raw[offset..offset + SPLICE_VAULT_DESCRIPTOR_V2_LEN].copy_from_slice(new_vault);
    offset += SPLICE_VAULT_DESCRIPTOR_V2_LEN;
    raw[offset..offset + SPLICE_ASSET_DELTAS_V1_LEN].copy_from_slice(deltas);
    raw
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

fn factory_splice_signature_witness(
    key0: &SigningKey,
    key1: &SigningKey,
    digest: &[u8; 32],
) -> [u8; FACTORY_SIGNATURE_WITNESS_V1_LEN] {
    let mut entries = [
        ([1u8; BYTE32_LEN], pubkey(key0), signature(key0, digest)),
        ([2u8; BYTE32_LEN], pubkey(key1), signature(key1, digest)),
    ];
    entries.sort_by(|left, right| left.0.cmp(&right.0));

    let mut raw = [0u8; FACTORY_SIGNATURE_WITNESS_V1_LEN];
    put_u16(&mut raw, 0, FACTORY_SIGNATURE_WITNESS_VERSION_V1);
    raw[2] = FACTORY_SIGNATURE_THRESHOLD_V1;
    raw[3] = FACTORY_SIGNATURE_COUNT_V1;
    for (index, (participant, pubkey, sig)) in entries.iter().enumerate() {
        let offset =
            4 + index * (BYTE32_LEN + COMPRESSED_SECP256K1_PUBKEY_LEN + ECDSA_SIGNATURE_LEN);
        raw[offset..offset + BYTE32_LEN].copy_from_slice(participant);
        raw[offset + BYTE32_LEN..offset + BYTE32_LEN + COMPRESSED_SECP256K1_PUBKEY_LEN]
            .copy_from_slice(pubkey);
        raw[offset + BYTE32_LEN + COMPRESSED_SECP256K1_PUBKEY_LEN
            ..offset + BYTE32_LEN + COMPRESSED_SECP256K1_PUBKEY_LEN + ECDSA_SIGNATURE_LEN]
            .copy_from_slice(sig);
    }
    raw
}

fn factory_vault_asset_bytes(kind: u8, amount: u128) -> [u8; FACTORY_VAULT_ASSET_AMOUNT_V1_LEN] {
    let mut raw = [0u8; FACTORY_VAULT_ASSET_AMOUNT_V1_LEN];
    raw[0] = kind;
    put_u128(&mut raw, 1 + BYTE32_LEN, amount);
    raw
}

fn factory_vault_descriptor_bytes(
    factory_id: [u8; BYTE32_LEN],
    asset: &[u8; FACTORY_VAULT_ASSET_AMOUNT_V1_LEN],
) -> [u8; FACTORY_VAULT_DESCRIPTOR_V1_LEN] {
    let mut raw = [0u8; FACTORY_VAULT_DESCRIPTOR_V1_LEN];
    raw[0..BYTE32_LEN].copy_from_slice(&factory_id);
    put_u16(&mut raw, BYTE32_LEN, 1);
    raw[BYTE32_LEN + 2..BYTE32_LEN + 2 + FACTORY_VAULT_ASSET_AMOUNT_V1_LEN].copy_from_slice(asset);
    raw
}

fn factory_vault_delta_bytes(
    kind: u8,
    old_amount: u128,
    new_amount: u128,
    external_input: u128,
    withdrawal: u128,
) -> [u8; FACTORY_VAULT_DELTA_V1_LEN] {
    let mut raw = [0u8; FACTORY_VAULT_DELTA_V1_LEN];
    raw[0] = kind;
    put_u128(&mut raw, 1 + BYTE32_LEN, old_amount);
    put_u128(&mut raw, 1 + BYTE32_LEN + 16, new_amount);
    put_u128(&mut raw, 1 + BYTE32_LEN + 32, external_input);
    put_u128(&mut raw, 1 + BYTE32_LEN + 48, withdrawal);
    raw
}

fn factory_vault_deltas_bytes(
    delta: &[u8; FACTORY_VAULT_DELTA_V1_LEN],
) -> [u8; FACTORY_VAULT_DELTAS_V1_LEN] {
    let mut raw = [0u8; FACTORY_VAULT_DELTAS_V1_LEN];
    put_u16(&mut raw, 0, 1);
    raw[2..2 + FACTORY_VAULT_DELTA_V1_LEN].copy_from_slice(delta);
    raw
}

fn signed_factory_splice_pair(
    old_amount: u128,
    new_amount: u128,
    external_input: u128,
    withdrawal: u128,
) -> (Bytes, Bytes, Bytes) {
    let key0 = signing_key(1);
    let key1 = signing_key(2);
    let mut entries = [
        ([1u8; BYTE32_LEN], pubkey(&key0)),
        ([2u8; BYTE32_LEN], pubkey(&key1)),
    ];
    entries.sort_by(|left, right| left.0.cmp(&right.0));
    let factory_participants = factory_participants_commitment_v1(
        2,
        &[
            (entries[0].0.as_slice(), entries[0].1.as_slice()),
            (entries[1].0.as_slice(), entries[1].1.as_slice()),
        ],
    );
    let splice_participants =
        participants_commitment_v1(2, &[entries[0].1.as_slice(), entries[1].1.as_slice()]);

    let mut old = factory_header_raw(1);
    old[108..140].copy_from_slice(&factory_participants);
    let old_header = FactoryStateHeaderV1::parse(&old).unwrap();
    let mut new = factory_header_raw(2);
    new[76..108].fill(9);
    new[108..140].copy_from_slice(&factory_participants);
    new[140..172].fill(10);
    new[172..204].fill(11);
    let new_header = FactoryStateHeaderV1::parse(&new).unwrap();

    let old_asset = factory_vault_asset_bytes(VAULT_ASSET_KIND_CKB_V1, old_amount);
    let new_asset = factory_vault_asset_bytes(VAULT_ASSET_KIND_CKB_V1, new_amount);
    let old_vault = factory_vault_descriptor_bytes(FACTORY_ID, &old_asset);
    let new_vault = factory_vault_descriptor_bytes(FACTORY_ID, &new_asset);
    let delta = factory_vault_delta_bytes(
        VAULT_ASSET_KIND_CKB_V1,
        old_amount,
        new_amount,
        external_input,
        withdrawal,
    );
    let deltas = factory_vault_deltas_bytes(&delta);
    let vault_delta_commitment = FactoryVaultDeltasV1::parse(&deltas)
        .unwrap()
        .commitment()
        .unwrap();

    let kind = if external_input > 0 {
        SPLICE_KIND_IN_V1
    } else {
        SPLICE_KIND_OUT_V1
    };
    let mut header = [0u8; FACTORY_SPLICE_HEADER_V1_LEN];
    put_u16(&mut header, 0, 1);
    header[2..34].copy_from_slice(old_header.factory_id());
    put_u64(&mut header, 34, old_header.update_number());
    put_u64(&mut header, 42, new_header.update_number());
    header[50..82].copy_from_slice(old_header.state_root());
    header[82..114].copy_from_slice(new_header.state_root());
    header[114..146].copy_from_slice(old_header.access_manifest_root());
    header[146..178].copy_from_slice(new_header.access_manifest_root());
    header[178] = kind;
    header[179..211].copy_from_slice(&vault_delta_commitment);
    header[211..243].copy_from_slice(new_header.non_interference_digest());
    header[243..275].copy_from_slice(&splice_participants);
    let splice_header = FactorySpliceHeaderV1::parse(&header).unwrap();
    let signatures =
        factory_splice_signature_witness(&key0, &key1, &splice_header.signing_digest());

    let mut witness = [0u8; FACTORY_SPLICE_WITNESS_V1_LEN];
    put_u16(&mut witness, 0, FACTORY_SPLICE_WITNESS_VERSION_V1);
    let mut offset = 2;
    witness[offset..offset + FACTORY_SPLICE_HEADER_V1_LEN].copy_from_slice(&header);
    offset += FACTORY_SPLICE_HEADER_V1_LEN;
    witness[offset..offset + FACTORY_SIGNATURE_WITNESS_V1_LEN].copy_from_slice(&signatures);
    offset += FACTORY_SIGNATURE_WITNESS_V1_LEN;
    witness[offset..offset + FACTORY_VAULT_DESCRIPTOR_V1_LEN].copy_from_slice(&old_vault);
    offset += FACTORY_VAULT_DESCRIPTOR_V1_LEN;
    witness[offset..offset + FACTORY_VAULT_DESCRIPTOR_V1_LEN].copy_from_slice(&new_vault);
    offset += FACTORY_VAULT_DESCRIPTOR_V1_LEN;
    witness[offset..offset + FACTORY_VAULT_DELTAS_V1_LEN].copy_from_slice(&deltas);

    (
        old.to_vec().into(),
        new.to_vec().into(),
        witness.to_vec().into(),
    )
}

fn signed_factory_reduced_splice_pair(
    old_amount: u128,
    new_amount: u128,
    external_input: u128,
    withdrawal: u128,
) -> (Bytes, Bytes, Bytes) {
    let key0 = signing_key(1);
    let key1 = signing_key(2);
    let mut entries = [
        ([1u8; BYTE32_LEN], pubkey(&key0)),
        ([2u8; BYTE32_LEN], pubkey(&key1)),
    ];
    entries.sort_by(|left, right| left.0.cmp(&right.0));
    let factory_participants = factory_participants_commitment_v1(
        2,
        &[
            (entries[0].0.as_slice(), entries[0].1.as_slice()),
            (entries[1].0.as_slice(), entries[1].1.as_slice()),
        ],
    );
    let splice_participants =
        participants_commitment_v1(2, &[entries[0].1.as_slice(), entries[1].1.as_slice()]);

    let mut before = large_factory_rights();
    let mut after = before.clone();
    let changed_index = before
        .iter()
        .position(|right| {
            right.id.participant == [1u8; BYTE32_LEN]
                && right.id.subchannel == [10u8; BYTE32_LEN]
                && right.id.kind == FactoryRightKind::ReserveClaim
                && right.id.asset_type.is_none()
        })
        .expect("fixture reserve claim");
    before[changed_index].quantity = old_amount;
    after[changed_index].quantity = new_amount;
    let changed_id = before[changed_index].id.clone();
    let before_root = factory_right_sparse_root(&before).unwrap();
    let after_root = factory_right_sparse_root(&after).unwrap();
    let before_proof = factory_right_sparse_proof(&before, &changed_id).unwrap();
    let after_proof = factory_right_sparse_proof(&after, &changed_id).unwrap();
    assert_eq!(before_proof.siblings, after_proof.siblings);

    let (mut merkle_witness, _, _) = merkle_update_witness_raw(
        &before_proof.right,
        &after_proof.right,
        &before_proof.siblings,
    );
    let merkle = FactoryMerkleUpdateWitnessV1::parse(&merkle_witness).unwrap();
    assert_eq!(merkle.rights_root(false).unwrap(), before_root);
    assert_eq!(merkle.rights_root(true).unwrap(), after_root);

    let mut old = factory_header_raw(1);
    old[76..108].copy_from_slice(&before_root);
    old[108..140].copy_from_slice(&factory_participants);
    let old_header = FactoryStateHeaderV1::parse(&old).unwrap();

    let mut new = factory_header_raw(2);
    new[76..108].copy_from_slice(&after_root);
    new[108..140].copy_from_slice(&factory_participants);
    new[140..172].copy_from_slice(old_header.access_manifest_root());
    let preliminary_new = FactoryStateHeaderV1::parse(&new).unwrap();
    let digest = merkle
        .non_interference_digest(&old_header, &preliminary_new)
        .unwrap();
    new[172..204].copy_from_slice(&digest);
    let new_header = FactoryStateHeaderV1::parse(&new).unwrap();

    let old_asset = factory_vault_asset_bytes(VAULT_ASSET_KIND_CKB_V1, old_amount);
    let new_asset = factory_vault_asset_bytes(VAULT_ASSET_KIND_CKB_V1, new_amount);
    let old_vault = factory_vault_descriptor_bytes(FACTORY_ID, &old_asset);
    let new_vault = factory_vault_descriptor_bytes(FACTORY_ID, &new_asset);
    let delta = factory_vault_delta_bytes(
        VAULT_ASSET_KIND_CKB_V1,
        old_amount,
        new_amount,
        external_input,
        withdrawal,
    );
    let deltas = factory_vault_deltas_bytes(&delta);
    let vault_delta_commitment = FactoryVaultDeltasV1::parse(&deltas)
        .unwrap()
        .commitment()
        .unwrap();

    let kind = if external_input > 0 {
        SPLICE_KIND_IN_V1
    } else {
        SPLICE_KIND_OUT_V1
    };
    let mut header = [0u8; FACTORY_SPLICE_HEADER_V1_LEN];
    put_u16(&mut header, 0, 1);
    header[2..34].copy_from_slice(old_header.factory_id());
    put_u64(&mut header, 34, old_header.update_number());
    put_u64(&mut header, 42, new_header.update_number());
    header[50..82].copy_from_slice(old_header.state_root());
    header[82..114].copy_from_slice(new_header.state_root());
    header[114..146].copy_from_slice(old_header.access_manifest_root());
    header[146..178].copy_from_slice(new_header.access_manifest_root());
    header[178] = kind;
    header[179..211].copy_from_slice(&vault_delta_commitment);
    header[211..243].copy_from_slice(new_header.non_interference_digest());
    header[243..275].copy_from_slice(&splice_participants);
    let splice_header = FactorySpliceHeaderV1::parse(&header).unwrap();
    sign_merkle_update_witness(
        &mut merkle_witness,
        [1u8; BYTE32_LEN],
        &key0,
        &splice_header.signing_digest(),
    );

    let mut witness = [0u8; FACTORY_REDUCED_SPLICE_WITNESS_V1_LEN];
    put_u16(&mut witness, 0, FACTORY_REDUCED_SPLICE_WITNESS_VERSION_V1);
    let mut offset = 2;
    witness[offset..offset + FACTORY_SPLICE_HEADER_V1_LEN].copy_from_slice(&header);
    offset += FACTORY_SPLICE_HEADER_V1_LEN;
    witness[offset..offset + FACTORY_MERKLE_UPDATE_WITNESS_V1_LEN].copy_from_slice(&merkle_witness);
    offset += FACTORY_MERKLE_UPDATE_WITNESS_V1_LEN;
    witness[offset..offset + FACTORY_VAULT_DESCRIPTOR_V1_LEN].copy_from_slice(&old_vault);
    offset += FACTORY_VAULT_DESCRIPTOR_V1_LEN;
    witness[offset..offset + FACTORY_VAULT_DESCRIPTOR_V1_LEN].copy_from_slice(&new_vault);
    offset += FACTORY_VAULT_DESCRIPTOR_V1_LEN;
    witness[offset..offset + FACTORY_VAULT_DELTAS_V1_LEN].copy_from_slice(&deltas);
    FactoryReducedSpliceWitnessV1::parse(&witness).unwrap();

    (
        old.to_vec().into(),
        new.to_vec().into(),
        witness.to_vec().into(),
    )
}

fn reduced_splice_merkle_offset() -> usize {
    2 + FACTORY_SPLICE_HEADER_V1_LEN
}

fn reduced_participant_offset(index: usize) -> usize {
    8 + index * FACTORY_REDUCED_RIGHTS_PARTICIPANT_ENTRY_V1_LEN
}

fn reduced_touched_offset() -> usize {
    8 + FACTORY_REDUCED_RIGHTS_PARTICIPANT_COUNT_V1 as usize
        * FACTORY_REDUCED_RIGHTS_PARTICIPANT_ENTRY_V1_LEN
}

fn reduced_right_offset(after: bool, index: usize) -> usize {
    let before_offset = reduced_touched_offset() + BYTE32_LEN;
    if after {
        before_offset
            + FACTORY_REDUCED_RIGHTS_COUNT_V1 as usize * FACTORY_RIGHT_V1_LEN
            + index * FACTORY_RIGHT_V1_LEN
    } else {
        before_offset + index * FACTORY_RIGHT_V1_LEN
    }
}

fn merkle_participant_offset(index: usize) -> usize {
    8 + index * FACTORY_REDUCED_RIGHTS_PARTICIPANT_ENTRY_V1_LEN
}

fn merkle_touched_offset() -> usize {
    8 + FACTORY_REDUCED_RIGHTS_PARTICIPANT_COUNT_V1 as usize
        * FACTORY_REDUCED_RIGHTS_PARTICIPANT_ENTRY_V1_LEN
}

fn merkle_right_offset(after: bool) -> usize {
    let before_offset = merkle_touched_offset() + BYTE32_LEN;
    if after {
        before_offset + FACTORY_RIGHT_V1_LEN
    } else {
        before_offset
    }
}

fn merkle_sibling_offset(depth: usize) -> usize {
    merkle_right_offset(true) + FACTORY_RIGHT_V1_LEN + depth * BYTE32_LEN
}

fn factory_right_bytes(
    participant: u8,
    subchannel: u8,
    kind: u8,
    quantity: u128,
) -> [u8; FACTORY_RIGHT_V1_LEN] {
    factory_right_bytes_with_asset(participant, subchannel, kind, quantity, None)
}

fn factory_right_bytes_with_asset(
    participant: u8,
    subchannel: u8,
    kind: u8,
    quantity: u128,
    asset_type: Option<[u8; BYTE32_LEN]>,
) -> [u8; FACTORY_RIGHT_V1_LEN] {
    let mut raw = [0u8; FACTORY_RIGHT_V1_LEN];
    raw[0..BYTE32_LEN].fill(participant);
    raw[BYTE32_LEN..2 * BYTE32_LEN].fill(subchannel);
    raw[2 * BYTE32_LEN] = kind;
    if let Some(asset_type) = asset_type {
        raw[2 * BYTE32_LEN + 1] = 1;
        raw[2 * BYTE32_LEN + 2..2 * BYTE32_LEN + 2 + BYTE32_LEN].copy_from_slice(&asset_type);
    }
    put_u128(&mut raw, 2 * BYTE32_LEN + 2 + BYTE32_LEN, quantity);
    raw
}

fn factory_right_kind_byte(kind: FactoryRightKind) -> u8 {
    match kind {
        FactoryRightKind::Balance => 0,
        FactoryRightKind::ReserveClaim => 1,
        FactoryRightKind::Membership => 2,
        FactoryRightKind::ExitPath => 3,
        FactoryRightKind::SponsorBudgetClaim => 4,
    }
}

fn core_factory_right_bytes(right: &FactoryRight) -> [u8; FACTORY_RIGHT_V1_LEN] {
    let mut raw = [0u8; FACTORY_RIGHT_V1_LEN];
    raw[0..BYTE32_LEN].copy_from_slice(&right.id.participant);
    raw[BYTE32_LEN..2 * BYTE32_LEN].copy_from_slice(&right.id.subchannel);
    raw[2 * BYTE32_LEN] = factory_right_kind_byte(right.id.kind);
    match right.id.asset_type {
        Some(asset_type) => {
            raw[2 * BYTE32_LEN + 1] = 1;
            raw[2 * BYTE32_LEN + 2..2 * BYTE32_LEN + 2 + BYTE32_LEN].copy_from_slice(&asset_type);
        }
        None => {
            raw[2 * BYTE32_LEN + 1] = 0;
        }
    }
    put_u128(&mut raw, 2 * BYTE32_LEN + 2 + BYTE32_LEN, right.quantity);
    raw
}

fn large_factory_rights() -> Vec<FactoryRight> {
    let mut rights = Vec::new();
    for participant in 1u8..=8 {
        for subchannel in 10u8..=13 {
            for (kind, quantity) in [
                (FactoryRightKind::Balance, 1_000u128),
                (FactoryRightKind::ReserveClaim, 250u128),
                (FactoryRightKind::ExitPath, 1u128),
            ] {
                rights.push(FactoryRight {
                    id: FactoryRightId {
                        participant: [participant; BYTE32_LEN],
                        subchannel: [subchannel; BYTE32_LEN],
                        kind,
                        asset_type: None,
                    },
                    quantity,
                });
            }
        }
    }
    rights
}

fn reduced_rights_pair(
    touched_after_balance: u128,
) -> (
    [[u8; FACTORY_RIGHT_V1_LEN]; FACTORY_REDUCED_RIGHTS_COUNT_V1 as usize],
    [[u8; FACTORY_RIGHT_V1_LEN]; FACTORY_REDUCED_RIGHTS_COUNT_V1 as usize],
) {
    let before = [
        factory_right_bytes(1, 10, 0, 100),
        factory_right_bytes(1, 10, 1, 50),
        factory_right_bytes(1, 10, 2, 1),
        factory_right_bytes(1, 10, 3, 1),
        factory_right_bytes(1, 10, 4, 20),
        factory_right_bytes(2, 10, 0, 100),
        factory_right_bytes(2, 10, 1, 50),
        factory_right_bytes(2, 10, 2, 1),
        factory_right_bytes(2, 10, 3, 1),
        factory_right_bytes(2, 10, 4, 20),
    ];
    let mut after = before;
    after[0] = factory_right_bytes(1, 10, 0, touched_after_balance);
    (before, after)
}

fn reduced_rights_witness_raw(
    touched_after_balance: u128,
) -> (
    [u8; FACTORY_REDUCED_RIGHTS_WITNESS_V1_LEN],
    SigningKey,
    SigningKey,
) {
    let key0 = signing_key(1);
    let key1 = signing_key(2);
    let mut entries = [
        ([1u8; BYTE32_LEN], pubkey(&key0)),
        ([2u8; BYTE32_LEN], pubkey(&key1)),
    ];
    entries.sort_by(|left, right| left.0.cmp(&right.0));
    let (before, after) = reduced_rights_pair(touched_after_balance);

    let mut raw = [0u8; FACTORY_REDUCED_RIGHTS_WITNESS_V1_LEN];
    put_u16(&mut raw, 0, FACTORY_REDUCED_RIGHTS_WITNESS_VERSION_V1);
    raw[2] = FACTORY_REDUCED_RIGHTS_PARTICIPANT_THRESHOLD_V1;
    raw[3] = FACTORY_REDUCED_RIGHTS_PARTICIPANT_COUNT_V1;
    raw[4] = FACTORY_REDUCED_RIGHTS_AUTHORISED_COUNT_V1;
    raw[5] = FACTORY_REDUCED_RIGHTS_COUNT_V1;
    for (index, (participant, pubkey)) in entries.iter().enumerate() {
        let offset = reduced_participant_offset(index);
        raw[offset..offset + BYTE32_LEN].copy_from_slice(participant);
        raw[offset + BYTE32_LEN..offset + BYTE32_LEN + COMPRESSED_SECP256K1_PUBKEY_LEN]
            .copy_from_slice(pubkey);
        raw[offset + BYTE32_LEN + COMPRESSED_SECP256K1_PUBKEY_LEN] =
            u8::from(participant == &[1u8; BYTE32_LEN]);
    }
    raw[reduced_touched_offset()..reduced_touched_offset() + BYTE32_LEN]
        .copy_from_slice(&[1u8; BYTE32_LEN]);
    for index in 0..FACTORY_REDUCED_RIGHTS_COUNT_V1 as usize {
        let before_offset = reduced_right_offset(false, index);
        raw[before_offset..before_offset + FACTORY_RIGHT_V1_LEN].copy_from_slice(&before[index]);
        let after_offset = reduced_right_offset(true, index);
        raw[after_offset..after_offset + FACTORY_RIGHT_V1_LEN].copy_from_slice(&after[index]);
    }

    (raw, key0, key1)
}

fn signed_reduced_factory_rights_pair(
    old_number: u64,
    new_number: u64,
    touched_after_balance: u128,
) -> (Bytes, Bytes, Bytes) {
    let (mut witness_raw, key0, key1) = reduced_rights_witness_raw(touched_after_balance);
    let mut entries = [
        ([1u8; BYTE32_LEN], pubkey(&key0)),
        ([2u8; BYTE32_LEN], pubkey(&key1)),
    ];
    entries.sort_by(|left, right| left.0.cmp(&right.0));
    let participants_commitment = factory_participants_commitment_v1(
        2,
        &[
            (entries[0].0.as_slice(), entries[0].1.as_slice()),
            (entries[1].0.as_slice(), entries[1].1.as_slice()),
        ],
    );
    let witness = FactoryReducedRightsWitnessV1::parse(&witness_raw).unwrap();

    let mut old = factory_header_raw(old_number);
    old[76..108].copy_from_slice(&witness.rights_root(false).unwrap());
    old[108..140].copy_from_slice(&participants_commitment);
    old[140..172].copy_from_slice(&witness.access_manifest_root(false).unwrap());
    let old_header = FactoryStateHeaderV1::parse(&old).unwrap();

    let mut new = factory_header_raw(new_number);
    new[76..108].copy_from_slice(&witness.rights_root(true).unwrap());
    new[108..140].copy_from_slice(&participants_commitment);
    new[140..172].copy_from_slice(&witness.access_manifest_root(true).unwrap());
    let preliminary_new_header = FactoryStateHeaderV1::parse(&new).unwrap();
    let digest = witness
        .non_interference_digest(&old_header, &preliminary_new_header)
        .unwrap();
    new[172..204].copy_from_slice(&digest);
    let new_header = FactoryStateHeaderV1::parse(&new).unwrap();
    let sig = signature(&key0, &new_header.signing_digest());
    let signature_offset =
        reduced_participant_offset(0) + BYTE32_LEN + COMPRESSED_SECP256K1_PUBKEY_LEN + 1;
    witness_raw[signature_offset..signature_offset + ECDSA_SIGNATURE_LEN].copy_from_slice(&sig);

    (
        old.to_vec().into(),
        new.to_vec().into(),
        witness_raw.to_vec().into(),
    )
}

fn merkle_update_witness_raw(
    before_right: &FactoryRight,
    after_right: &FactoryRight,
    siblings: &[FactoryMerkleSibling],
) -> (Vec<u8>, SigningKey, SigningKey) {
    let key0 = signing_key(1);
    let key1 = signing_key(2);
    let touched = before_right.id.participant;
    let mut entries = [
        ([1u8; BYTE32_LEN], pubkey(&key0)),
        ([2u8; BYTE32_LEN], pubkey(&key1)),
    ];
    entries.sort_by(|left, right| left.0.cmp(&right.0));

    let mut raw = vec![0u8; FACTORY_MERKLE_UPDATE_WITNESS_V1_LEN];
    put_u16(&mut raw, 0, FACTORY_MERKLE_UPDATE_WITNESS_VERSION_V1);
    raw[2] = FACTORY_REDUCED_RIGHTS_PARTICIPANT_THRESHOLD_V1;
    raw[3] = FACTORY_REDUCED_RIGHTS_PARTICIPANT_COUNT_V1;
    raw[4] = FACTORY_REDUCED_RIGHTS_AUTHORISED_COUNT_V1;
    raw[5] = FACTORY_MERKLE_UPDATE_RIGHT_COUNT_V1;
    for (index, (participant, pubkey)) in entries.iter().enumerate() {
        let offset = merkle_participant_offset(index);
        raw[offset..offset + BYTE32_LEN].copy_from_slice(participant);
        raw[offset + BYTE32_LEN..offset + BYTE32_LEN + COMPRESSED_SECP256K1_PUBKEY_LEN]
            .copy_from_slice(pubkey);
        raw[offset + BYTE32_LEN + COMPRESSED_SECP256K1_PUBKEY_LEN] =
            u8::from(participant.as_slice() == touched.as_slice());
    }
    raw[merkle_touched_offset()..merkle_touched_offset() + BYTE32_LEN].copy_from_slice(&touched);
    raw[merkle_right_offset(false)..merkle_right_offset(false) + FACTORY_RIGHT_V1_LEN]
        .copy_from_slice(&core_factory_right_bytes(before_right));
    raw[merkle_right_offset(true)..merkle_right_offset(true) + FACTORY_RIGHT_V1_LEN]
        .copy_from_slice(&core_factory_right_bytes(after_right));
    assert_eq!(siblings.len(), FACTORY_SPARSE_MERKLE_DEPTH_V1);
    for (depth, sibling) in siblings.iter().enumerate() {
        let offset = merkle_sibling_offset(depth);
        raw[offset..offset + BYTE32_LEN].copy_from_slice(&sibling.hash);
    }

    (raw, key0, key1)
}

fn sign_merkle_update_witness(
    raw: &mut [u8],
    participant: [u8; BYTE32_LEN],
    key: &SigningKey,
    digest: &[u8; 32],
) {
    let sig = signature(key, digest);
    for index in 0..FACTORY_REDUCED_RIGHTS_PARTICIPANT_COUNT_V1 as usize {
        if &raw[merkle_participant_offset(index)..merkle_participant_offset(index) + BYTE32_LEN]
            == participant.as_slice()
        {
            let offset =
                merkle_participant_offset(index) + BYTE32_LEN + COMPRESSED_SECP256K1_PUBKEY_LEN + 1;
            raw[offset..offset + ECDSA_SIGNATURE_LEN].copy_from_slice(&sig);
        }
    }
}

fn signed_factory_merkle_update_pair(old_number: u64, new_number: u64) -> (Bytes, Bytes, Bytes) {
    signed_factory_merkle_update_pair_with_quantity(old_number, new_number, 900)
}

fn signed_factory_merkle_update_pair_with_quantity(
    old_number: u64,
    new_number: u64,
    after_quantity: u128,
) -> (Bytes, Bytes, Bytes) {
    let before = large_factory_rights();
    let mut after = before.clone();
    after[0].quantity = after_quantity;
    let changed_id = before[0].id.clone();
    let before_root = factory_right_sparse_root(&before).unwrap();
    let after_root = factory_right_sparse_root(&after).unwrap();
    let before_proof = factory_right_sparse_proof(&before, &changed_id).unwrap();
    let after_proof = factory_right_sparse_proof(&after, &changed_id).unwrap();
    assert_eq!(before_proof.siblings, after_proof.siblings);

    let (mut witness_raw, key0, key1) = merkle_update_witness_raw(
        &before_proof.right,
        &after_proof.right,
        &before_proof.siblings,
    );
    let mut entries = [
        ([1u8; BYTE32_LEN], pubkey(&key0)),
        ([2u8; BYTE32_LEN], pubkey(&key1)),
    ];
    entries.sort_by(|left, right| left.0.cmp(&right.0));
    let participants_commitment = factory_participants_commitment_v1(
        2,
        &[
            (entries[0].0.as_slice(), entries[0].1.as_slice()),
            (entries[1].0.as_slice(), entries[1].1.as_slice()),
        ],
    );
    let witness = FactoryMerkleUpdateWitnessV1::parse(&witness_raw).unwrap();
    assert_eq!(witness.rights_root(false).unwrap(), before_root);
    assert_eq!(witness.rights_root(true).unwrap(), after_root);

    let mut old = factory_header_raw(old_number);
    old[76..108].copy_from_slice(&before_root);
    old[108..140].copy_from_slice(&participants_commitment);
    let old_header = FactoryStateHeaderV1::parse(&old).unwrap();

    let mut new = factory_header_raw(new_number);
    new[76..108].copy_from_slice(&after_root);
    new[108..140].copy_from_slice(&participants_commitment);
    new[140..172].copy_from_slice(old_header.access_manifest_root());
    let preliminary_new_header = FactoryStateHeaderV1::parse(&new).unwrap();
    let digest = witness
        .non_interference_digest(&old_header, &preliminary_new_header)
        .unwrap();
    new[172..204].copy_from_slice(&digest);
    let new_header = FactoryStateHeaderV1::parse(&new).unwrap();
    sign_merkle_update_witness(
        &mut witness_raw,
        [1u8; BYTE32_LEN],
        &key0,
        &new_header.signing_digest(),
    );

    (old.to_vec().into(), new.to_vec().into(), witness_raw.into())
}

fn reduced_exit_participant_offset(index: usize) -> usize {
    8 + index * FACTORY_REDUCED_RIGHTS_PARTICIPANT_ENTRY_V1_LEN
}

fn reduced_exit_touched_offset() -> usize {
    8 + FACTORY_REDUCED_RIGHTS_PARTICIPANT_COUNT_V1 as usize
        * FACTORY_REDUCED_RIGHTS_PARTICIPANT_ENTRY_V1_LEN
}

fn reduced_exit_release_quantity_offset() -> usize {
    reduced_exit_touched_offset() + BYTE32_LEN
}

fn reduced_exit_state_output_index_offset() -> usize {
    reduced_exit_release_quantity_offset() + 16
}

fn reduced_exit_vault_output_index_offset() -> usize {
    reduced_exit_state_output_index_offset() + 4
}

fn reduced_exit_state_type_hash_offset() -> usize {
    reduced_exit_vault_output_index_offset() + 4
}

fn reduced_exit_vault_lock_hash_offset() -> usize {
    reduced_exit_state_type_hash_offset() + BYTE32_LEN
}

fn reduced_exit_state_lock_hash_offset() -> usize {
    reduced_exit_vault_lock_hash_offset() + BYTE32_LEN
}

fn reduced_exit_state_header_offset() -> usize {
    reduced_exit_state_lock_hash_offset() + BYTE32_LEN
}

fn reduced_exit_descriptor_offset() -> usize {
    reduced_exit_state_header_offset() + STATE_HEADER_V1_LEN
}

fn reduced_exit_right_offset(after: bool, descriptor_len: usize, index: usize) -> usize {
    let before_offset = reduced_exit_descriptor_offset() + descriptor_len;
    if after {
        before_offset
            + FACTORY_REDUCED_RIGHTS_COUNT_V1 as usize * FACTORY_RIGHT_V1_LEN
            + index * FACTORY_RIGHT_V1_LEN
    } else {
        before_offset + index * FACTORY_RIGHT_V1_LEN
    }
}

fn reduced_exit_rights_pair(
    reserve_claim_before_quantity: u128,
    reserve_claim_after_quantity: u128,
    reserve_asset_type: Option<[u8; BYTE32_LEN]>,
) -> (
    [[u8; FACTORY_RIGHT_V1_LEN]; FACTORY_REDUCED_RIGHTS_COUNT_V1 as usize],
    [[u8; FACTORY_RIGHT_V1_LEN]; FACTORY_REDUCED_RIGHTS_COUNT_V1 as usize],
) {
    let before = [
        factory_right_bytes(1, 10, 0, 100),
        factory_right_bytes_with_asset(
            1,
            10,
            FACTORY_RIGHT_KIND_RESERVE_CLAIM,
            reserve_claim_before_quantity,
            reserve_asset_type,
        ),
        factory_right_bytes(1, 10, 2, 1),
        factory_right_bytes(1, 10, 3, 1),
        factory_right_bytes(1, 10, 4, 20),
        factory_right_bytes(2, 10, 0, 100),
        factory_right_bytes(2, 10, FACTORY_RIGHT_KIND_RESERVE_CLAIM, 50),
        factory_right_bytes(2, 10, 2, 1),
        factory_right_bytes(2, 10, 3, 1),
        factory_right_bytes(2, 10, 4, 20),
    ];
    let mut after = before;
    after[1] = factory_right_bytes_with_asset(
        1,
        10,
        FACTORY_RIGHT_KIND_RESERVE_CLAIM,
        reserve_claim_after_quantity,
        reserve_asset_type,
    );
    (before, after)
}

#[allow(clippy::too_many_arguments)]
fn reduced_exit_witness_raw_with_reserve_asset(
    release_quantity: u128,
    reserve_claim_before_quantity: u128,
    reserve_claim_after_quantity: u128,
    state_output_index: u32,
    vault_output_index: u32,
    state_type_hash: [u8; 32],
    vault_lock_hash: [u8; 32],
    state_lock_hash: [u8; 32],
    state_header: &[u8],
    descriptor: &[u8],
    reserve_asset_type: Option<[u8; BYTE32_LEN]>,
) -> (Vec<u8>, SigningKey, SigningKey) {
    let key0 = signing_key(1);
    let key1 = signing_key(2);
    let touched = [1u8; BYTE32_LEN];
    let mut entries = [
        ([1u8; BYTE32_LEN], pubkey(&key0)),
        ([2u8; BYTE32_LEN], pubkey(&key1)),
    ];
    entries.sort_by(|left, right| left.0.cmp(&right.0));
    let (before, after) = reduced_exit_rights_pair(
        reserve_claim_before_quantity,
        reserve_claim_after_quantity,
        reserve_asset_type,
    );

    let mut raw = vec![
        0u8;
        FACTORY_REDUCED_EXIT_WITNESS_V1_LEN - BILATERAL_CKB_DESCRIPTOR_V1_LEN
            + descriptor.len()
    ];
    put_u16(&mut raw, 0, FACTORY_REDUCED_EXIT_WITNESS_VERSION_V1);
    raw[2] = FACTORY_REDUCED_RIGHTS_PARTICIPANT_THRESHOLD_V1;
    raw[3] = FACTORY_REDUCED_RIGHTS_PARTICIPANT_COUNT_V1;
    raw[4] = FACTORY_REDUCED_RIGHTS_AUTHORISED_COUNT_V1;
    raw[5] = FACTORY_REDUCED_RIGHTS_COUNT_V1;
    for (index, (participant, pubkey)) in entries.iter().enumerate() {
        let offset = reduced_exit_participant_offset(index);
        raw[offset..offset + BYTE32_LEN].copy_from_slice(participant);
        raw[offset + BYTE32_LEN..offset + BYTE32_LEN + COMPRESSED_SECP256K1_PUBKEY_LEN]
            .copy_from_slice(pubkey);
        raw[offset + BYTE32_LEN + COMPRESSED_SECP256K1_PUBKEY_LEN] =
            u8::from(participant.as_slice() == touched.as_slice());
    }
    raw[reduced_exit_touched_offset()..reduced_exit_touched_offset() + BYTE32_LEN]
        .copy_from_slice(&touched);
    put_u128(
        &mut raw,
        reduced_exit_release_quantity_offset(),
        release_quantity,
    );
    put_u32(
        &mut raw,
        reduced_exit_state_output_index_offset(),
        state_output_index,
    );
    put_u32(
        &mut raw,
        reduced_exit_vault_output_index_offset(),
        vault_output_index,
    );
    raw[reduced_exit_state_type_hash_offset()..reduced_exit_state_type_hash_offset() + BYTE32_LEN]
        .copy_from_slice(&state_type_hash);
    raw[reduced_exit_vault_lock_hash_offset()..reduced_exit_vault_lock_hash_offset() + BYTE32_LEN]
        .copy_from_slice(&vault_lock_hash);
    raw[reduced_exit_state_lock_hash_offset()..reduced_exit_state_lock_hash_offset() + BYTE32_LEN]
        .copy_from_slice(&state_lock_hash);
    raw[reduced_exit_state_header_offset()
        ..reduced_exit_state_header_offset() + STATE_HEADER_V1_LEN]
        .copy_from_slice(state_header);
    raw[reduced_exit_descriptor_offset()..reduced_exit_descriptor_offset() + descriptor.len()]
        .copy_from_slice(descriptor);
    for index in 0..FACTORY_REDUCED_RIGHTS_COUNT_V1 as usize {
        let before_offset = reduced_exit_right_offset(false, descriptor.len(), index);
        raw[before_offset..before_offset + FACTORY_RIGHT_V1_LEN].copy_from_slice(&before[index]);
        let after_offset = reduced_exit_right_offset(true, descriptor.len(), index);
        raw[after_offset..after_offset + FACTORY_RIGHT_V1_LEN].copy_from_slice(&after[index]);
    }

    (raw, key0, key1)
}

fn sign_reduced_exit_witness(
    raw: &mut [u8],
    participant: [u8; BYTE32_LEN],
    key: &SigningKey,
    digest: &[u8; 32],
) {
    let sig = signature(key, digest);
    for index in 0..FACTORY_REDUCED_RIGHTS_PARTICIPANT_COUNT_V1 as usize {
        if &raw[reduced_exit_participant_offset(index)
            ..reduced_exit_participant_offset(index) + BYTE32_LEN]
            == participant.as_slice()
        {
            let offset = reduced_exit_participant_offset(index)
                + BYTE32_LEN
                + COMPRESSED_SECP256K1_PUBKEY_LEN
                + 1;
            raw[offset..offset + ECDSA_SIGNATURE_LEN].copy_from_slice(&sig);
        }
    }
}

fn reduced_exit_old_factory_data(old_number: u64, reserve_claim_before_quantity: u128) -> Bytes {
    reduced_exit_old_factory_data_with_reserve_asset(
        old_number,
        reserve_claim_before_quantity,
        None,
    )
}

fn reduced_exit_old_factory_data_with_reserve_asset(
    old_number: u64,
    reserve_claim_before_quantity: u128,
    reserve_asset_type: Option<[u8; BYTE32_LEN]>,
) -> Bytes {
    let descriptor = descriptor_bytes([1u8; 32], 1, [2u8; 32], 2);
    let child_state = header_raw(0, PHASE_ACTIVE);
    let (witness_raw, key0, key1) = reduced_exit_witness_raw_with_reserve_asset(
        1,
        reserve_claim_before_quantity,
        reserve_claim_before_quantity - 1,
        1,
        2,
        [0u8; 32],
        [0u8; 32],
        [0u8; 32],
        &child_state,
        &descriptor,
        reserve_asset_type,
    );
    let mut entries = [
        ([1u8; BYTE32_LEN], pubkey(&key0)),
        ([2u8; BYTE32_LEN], pubkey(&key1)),
    ];
    entries.sort_by(|left, right| left.0.cmp(&right.0));
    let participants_commitment = factory_participants_commitment_v1(
        2,
        &[
            (entries[0].0.as_slice(), entries[0].1.as_slice()),
            (entries[1].0.as_slice(), entries[1].1.as_slice()),
        ],
    );
    let witness = FactoryReducedExitWitnessV1::parse(&witness_raw).unwrap();

    let mut old = factory_header_raw(old_number);
    old[76..108].copy_from_slice(&witness.rights_root(false).unwrap());
    old[108..140].copy_from_slice(&participants_commitment);
    old[140..172].copy_from_slice(&witness.access_manifest_root(false).unwrap());
    old.to_vec().into()
}

#[allow(clippy::too_many_arguments)]
fn signed_reduced_factory_exit_pair(
    old_number: u64,
    new_number: u64,
    release_quantity: u128,
    reserve_claim_before_quantity: u128,
    reserve_claim_after_quantity: u128,
    state_output_index: u32,
    vault_output_index: u32,
    state_type_hash: [u8; 32],
    vault_lock_hash: [u8; 32],
    state_lock_hash: [u8; 32],
    state_header: &[u8],
    descriptor: &[u8],
) -> (Bytes, Bytes, Bytes) {
    signed_reduced_factory_exit_pair_with_reserve_asset(
        old_number,
        new_number,
        release_quantity,
        reserve_claim_before_quantity,
        reserve_claim_after_quantity,
        state_output_index,
        vault_output_index,
        state_type_hash,
        vault_lock_hash,
        state_lock_hash,
        state_header,
        descriptor,
        None,
    )
}

#[allow(clippy::too_many_arguments)]
fn signed_reduced_factory_exit_pair_with_reserve_asset(
    old_number: u64,
    new_number: u64,
    release_quantity: u128,
    reserve_claim_before_quantity: u128,
    reserve_claim_after_quantity: u128,
    state_output_index: u32,
    vault_output_index: u32,
    state_type_hash: [u8; 32],
    vault_lock_hash: [u8; 32],
    state_lock_hash: [u8; 32],
    state_header: &[u8],
    descriptor: &[u8],
    reserve_asset_type: Option<[u8; BYTE32_LEN]>,
) -> (Bytes, Bytes, Bytes) {
    let (mut witness_raw, key0, key1) = reduced_exit_witness_raw_with_reserve_asset(
        release_quantity,
        reserve_claim_before_quantity,
        reserve_claim_after_quantity,
        state_output_index,
        vault_output_index,
        state_type_hash,
        vault_lock_hash,
        state_lock_hash,
        state_header,
        descriptor,
        reserve_asset_type,
    );
    let mut entries = [
        ([1u8; BYTE32_LEN], pubkey(&key0)),
        ([2u8; BYTE32_LEN], pubkey(&key1)),
    ];
    entries.sort_by(|left, right| left.0.cmp(&right.0));
    let participants_commitment = factory_participants_commitment_v1(
        2,
        &[
            (entries[0].0.as_slice(), entries[0].1.as_slice()),
            (entries[1].0.as_slice(), entries[1].1.as_slice()),
        ],
    );
    let witness = FactoryReducedExitWitnessV1::parse(&witness_raw).unwrap();

    let mut old = factory_header_raw(old_number);
    old[76..108].copy_from_slice(&witness.rights_root(false).unwrap());
    old[108..140].copy_from_slice(&participants_commitment);
    old[140..172].copy_from_slice(&witness.access_manifest_root(false).unwrap());
    let old_header = FactoryStateHeaderV1::parse(&old).unwrap();

    let mut new = factory_header_raw(new_number);
    new[76..108].copy_from_slice(&witness.rights_root(true).unwrap());
    new[108..140].copy_from_slice(&participants_commitment);
    new[140..172].copy_from_slice(&witness.access_manifest_root(true).unwrap());
    let preliminary_new_header = FactoryStateHeaderV1::parse(&new).unwrap();
    let digest = witness
        .non_interference_digest(&old_header, &preliminary_new_header)
        .unwrap();
    new[172..204].copy_from_slice(&digest);
    let new_header = FactoryStateHeaderV1::parse(&new).unwrap();
    sign_reduced_exit_witness(
        &mut witness_raw,
        [1u8; BYTE32_LEN],
        &key0,
        &new_header.signing_digest(),
    );

    (old.to_vec().into(), new.to_vec().into(), witness_raw.into())
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

#[allow(clippy::too_many_arguments)]
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
enum VaultCkbSettlementTamper {
    NonEmptyData,
    TypedOutput,
    SplitOutput,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum VaultXudtSettlementTamper {
    NonzeroWrongAmountData,
    ZeroRecipientTypedCell,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FactoryXudtExitTamper {
    None,
    ChildAmountMinusOneWithConservedSupply,
    ChildTypeMismatchWithAuthorisedMint,
    FactoryVaultInputTypeMismatch,
    FactoryVaultChangeAmountMismatch,
    FactoryVaultChangeMissingOnPartial,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FactoryReducedXudtExitTamper {
    None,
    FullReleaseNoTypedChange,
    ChildAmountMinusOneWithConservedSupply,
    ChildTypeMismatchWithAuthorisedMint,
    ClaimAssetTypeMismatch,
    FactoryVaultChangeAmountMismatch,
    FactoryVaultChangeMissing,
    CapacityMismatch,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReducedFactorySpliceTamper {
    None,
    VaultCapacity,
    SparseMerkleSibling,
}

fn sponsor_policy(
    change_lock_hash: &[u8; 32],
    publication_state_type_hash: &[u8; 32],
    max_fee: u64,
) -> Vec<u8> {
    sponsor_policy_with_bounds(
        change_lock_hash,
        publication_state_type_hash,
        0,
        u64::MAX,
        max_fee,
        max_fee,
    )
}

fn sponsor_policy_with_bounds(
    change_lock_hash: &[u8; 32],
    publication_state_type_hash: &[u8; 32],
    min_state_number: u64,
    max_state_number: u64,
    max_fee_per_tx: u64,
    max_total_fee: u64,
) -> Vec<u8> {
    sponsor_policy_with_bounds_and_expiry(
        change_lock_hash,
        publication_state_type_hash,
        min_state_number,
        max_state_number,
        max_fee_per_tx,
        max_total_fee,
        u64::MAX,
    )
}

fn sponsor_policy_with_bounds_and_expiry(
    change_lock_hash: &[u8; 32],
    publication_state_type_hash: &[u8; 32],
    min_state_number: u64,
    max_state_number: u64,
    max_fee_per_tx: u64,
    max_total_fee: u64,
    expiry: u64,
) -> Vec<u8> {
    let mut raw = [0u8; SPONSOR_POLICY_V1_LEN];
    raw[0..32].fill(3);
    put_u64(&mut raw, 32, min_state_number);
    put_u64(&mut raw, 40, max_state_number);
    put_u64(&mut raw, 48, max_fee_per_tx);
    put_u64(&mut raw, 56, max_total_fee);
    put_u64(&mut raw, 64, 0);
    put_u64(&mut raw, 72, expiry);
    raw[80..112].copy_from_slice(publication_state_type_hash);
    raw[112..144].copy_from_slice(change_lock_hash);
    raw.to_vec()
}

fn sponsor_policy_with_already_spent(
    change_lock_hash: &[u8; 32],
    publication_state_type_hash: &[u8; 32],
    max_fee_per_tx: u64,
    max_total_fee: u64,
    already_spent: u64,
) -> Vec<u8> {
    let mut raw = sponsor_policy_with_bounds(
        change_lock_hash,
        publication_state_type_hash,
        0,
        u64::MAX,
        max_fee_per_tx,
        max_total_fee,
    );
    put_u64(&mut raw, 64, already_spent);
    raw
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
    let funding_lock = deploy_always_success(&mut context);

    let funding_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(CELL_CAPACITY)
            .lock(funding_lock)
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
    let state_lock = deploy_always_success_with_args(
        &mut context,
        Bytes::from(state_type.calc_script_hash().as_slice().to_vec()),
    );
    let initial_data =
        Bytes::from(header_raw_with_anchor(0, PHASE_ACTIVE, funding_anchor).to_vec());

    let output = CellOutput::new_builder()
        .capacity(CELL_CAPACITY)
        .lock(state_lock)
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
    let funding_lock = deploy_always_success(&mut context);

    let funding_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(CELL_CAPACITY)
            .lock(funding_lock)
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
    let state_lock = deploy_always_success_with_args(
        &mut context,
        Bytes::from(state_type.calc_script_hash().as_slice().to_vec()),
    );
    let initial_data = Bytes::from(header_raw_with_anchor(0, PHASE_ACTIVE, wrong_anchor).to_vec());

    let output = CellOutput::new_builder()
        .capacity(CELL_CAPACITY)
        .lock(state_lock)
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
fn factory_type_and_vault_accept_factory_splice_in() {
    let (context, tx) = factory_splice_ckb_tx(false);

    context
        .verify_tx(&tx, MAX_CYCLES)
        .expect("factory splice-in should verify");
}

#[ignore = "requires `make build-contracts`"]
#[test]
fn factory_vault_rejects_factory_splice_capacity_mismatch() {
    let (context, tx) = factory_splice_ckb_tx(true);

    assert!(context.verify_tx(&tx, MAX_CYCLES).is_err());
}

#[ignore = "requires `make build-contracts`"]
#[test]
fn factory_type_and_vault_accept_reduced_factory_splice_in() {
    let (context, tx) = factory_reduced_splice_ckb_tx(ReducedFactorySpliceTamper::None);

    context
        .verify_tx(&tx, MAX_CYCLES)
        .expect("reduced factory splice-in should verify");
}

#[ignore = "requires `make build-contracts`"]
#[test]
fn factory_type_rejects_reduced_factory_splice_sparse_merkle_tamper() {
    let (context, tx) =
        factory_reduced_splice_ckb_tx(ReducedFactorySpliceTamper::SparseMerkleSibling);

    assert!(context.verify_tx(&tx, MAX_CYCLES).is_err());
}

#[ignore = "requires `make build-contracts`"]
#[test]
fn factory_vault_rejects_reduced_factory_splice_capacity_mismatch() {
    let (context, tx) = factory_reduced_splice_ckb_tx(ReducedFactorySpliceTamper::VaultCapacity);

    assert!(context.verify_tx(&tx, MAX_CYCLES).is_err());
}

#[ignore = "requires `make build-contracts`"]
#[test]
fn factory_type_accepts_reduced_rights_update() {
    let mut context = Context::default();
    let lock = deploy_always_success(&mut context);
    let factory_type = deploy_contract(&mut context, "morph-factory-type", FACTORY_ID.to_vec());
    let (old_data, new_data, reduced_witness) = signed_reduced_factory_rights_pair(1, 2, 90);

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
        .witness(witness_with_input_type(reduced_witness))
        .build();
    let tx = context.complete_tx(tx);

    context
        .verify_tx(&tx, MAX_CYCLES)
        .expect("reduced factory rights update should verify");
}

#[ignore = "requires `make build-contracts`"]
#[test]
fn factory_type_accepts_sparse_merkle_right_update() {
    let mut context = Context::default();
    let lock = deploy_always_success(&mut context);
    let factory_type = deploy_contract(&mut context, "morph-factory-type", FACTORY_ID.to_vec());
    let (old_data, new_data, merkle_witness) = signed_factory_merkle_update_pair(1, 2);

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
        .witness(witness_with_input_type(merkle_witness))
        .build();
    let tx = context.complete_tx(tx);

    context
        .verify_tx(&tx, MAX_CYCLES)
        .expect("sparse Merkle factory right update should verify");
}

#[ignore = "requires `make build-contracts`"]
#[test]
fn factory_type_rejects_sparse_merkle_right_increase() {
    let mut context = Context::default();
    let lock = deploy_always_success(&mut context);
    let factory_type = deploy_contract(&mut context, "morph-factory-type", FACTORY_ID.to_vec());
    let (old_data, new_data, merkle_witness) =
        signed_factory_merkle_update_pair_with_quantity(1, 2, 1_001);

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
        .witness(witness_with_input_type(merkle_witness))
        .build();
    let tx = context.complete_tx(tx);

    assert!(context.verify_tx(&tx, MAX_CYCLES).is_err());
}

#[ignore = "requires `make build-contracts`"]
#[test]
fn factory_type_rejects_sparse_merkle_sibling_tamper() {
    let mut context = Context::default();
    let lock = deploy_always_success(&mut context);
    let factory_type = deploy_contract(&mut context, "morph-factory-type", FACTORY_ID.to_vec());
    let (old_data, new_data, merkle_witness) = signed_factory_merkle_update_pair(1, 2);
    let mut merkle_witness = merkle_witness.to_vec();
    merkle_witness[merkle_sibling_offset(42)] ^= 1;

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
        .witness(witness_with_input_type(merkle_witness.into()))
        .build();
    let tx = context.complete_tx(tx);

    assert!(context.verify_tx(&tx, MAX_CYCLES).is_err());
}

#[ignore = "requires `make build-contracts`"]
#[test]
fn factory_type_rejects_reduced_rights_increase() {
    let mut context = Context::default();
    let lock = deploy_always_success(&mut context);
    let factory_type = deploy_contract(&mut context, "morph-factory-type", FACTORY_ID.to_vec());
    let (old_data, new_data, reduced_witness) = signed_reduced_factory_rights_pair(1, 2, 110);

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
        .witness(witness_with_input_type(reduced_witness))
        .build();
    let tx = context.complete_tx(tx);

    assert!(context.verify_tx(&tx, MAX_CYCLES).is_err());
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

fn factory_splice_ckb_tx(tamper_capacity: bool) -> (Context, TransactionView) {
    let mut context = Context::default();
    let factory_lock = deploy_always_success(&mut context);
    let external_input_lock = deploy_always_success_with_args(&mut context, Bytes::from(vec![9]));

    let factory_type = deploy_contract(&mut context, "morph-factory-type", FACTORY_ID.to_vec());
    let factory_type_hash: [u8; 32] = factory_type.calc_script_hash().unpack();
    let mut factory_vault_args = FACTORY_ID.to_vec();
    factory_vault_args.extend_from_slice(&factory_type_hash);
    let factory_vault_lock =
        deploy_contract(&mut context, "morph-factory-vault-lock", factory_vault_args);

    let old_reserve = 200_000_000_000u64;
    let splice_amount = 20_000_000_000u64;
    let new_reserve = old_reserve + splice_amount;
    let (old_factory_data, new_factory_data, splice_witness) = signed_factory_splice_pair(
        old_reserve as u128,
        new_reserve as u128,
        splice_amount as u128,
        0,
    );

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
            .capacity(old_reserve)
            .lock(factory_vault_lock.clone())
            .build(),
        Bytes::new(),
    );
    let reserve_input = CellInput::new_builder()
        .previous_output(factory_vault_input_out_point)
        .build();
    let external_input_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(CELL_CAPACITY)
            .lock(external_input_lock.clone())
            .build(),
        Bytes::new(),
    );

    let output_reserve = if tamper_capacity {
        new_reserve - 1
    } else {
        new_reserve
    };
    let change_capacity = CELL_CAPACITY - splice_amount;
    let tx = TransactionBuilder::default()
        .input(factory_input)
        .input(reserve_input)
        .input(
            CellInput::new_builder()
                .previous_output(external_input_out_point)
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
                .capacity(output_reserve)
                .lock(factory_vault_lock)
                .build(),
        )
        .output(
            CellOutput::new_builder()
                .capacity(change_capacity)
                .lock(external_input_lock)
                .build(),
        )
        .output_data(new_factory_data.pack())
        .output_data(Bytes::new().pack())
        .output_data(Bytes::new().pack())
        .witness(witness_with_input_type(splice_witness.clone()))
        .witness(witness_with_input_type(splice_witness))
        .witness(empty_witness())
        .build();
    let tx = context.complete_tx(tx);
    (context, tx)
}

fn factory_reduced_splice_ckb_tx(tamper: ReducedFactorySpliceTamper) -> (Context, TransactionView) {
    let mut context = Context::default();
    let factory_lock = deploy_always_success(&mut context);
    let external_input_lock = deploy_always_success_with_args(&mut context, Bytes::from(vec![9]));

    let factory_type = deploy_contract(&mut context, "morph-factory-type", FACTORY_ID.to_vec());
    let factory_type_hash: [u8; 32] = factory_type.calc_script_hash().unpack();
    let mut factory_vault_args = FACTORY_ID.to_vec();
    factory_vault_args.extend_from_slice(&factory_type_hash);
    let factory_vault_lock =
        deploy_contract(&mut context, "morph-factory-vault-lock", factory_vault_args);

    let old_reserve = 200_000_000_000u64;
    let splice_amount = 20_000_000_000u64;
    let new_reserve = old_reserve + splice_amount;
    let (old_factory_data, new_factory_data, splice_witness) = signed_factory_reduced_splice_pair(
        old_reserve as u128,
        new_reserve as u128,
        splice_amount as u128,
        0,
    );
    let mut splice_witness = splice_witness.to_vec();
    if tamper == ReducedFactorySpliceTamper::SparseMerkleSibling {
        splice_witness[reduced_splice_merkle_offset() + merkle_sibling_offset(42)] ^= 1;
    }
    let splice_witness: Bytes = splice_witness.into();

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
            .capacity(old_reserve)
            .lock(factory_vault_lock.clone())
            .build(),
        Bytes::new(),
    );
    let reserve_input = CellInput::new_builder()
        .previous_output(factory_vault_input_out_point)
        .build();
    let external_input_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(CELL_CAPACITY)
            .lock(external_input_lock.clone())
            .build(),
        Bytes::new(),
    );

    let output_reserve = if tamper == ReducedFactorySpliceTamper::VaultCapacity {
        new_reserve - 1
    } else {
        new_reserve
    };
    let change_capacity = CELL_CAPACITY - splice_amount;
    let tx = TransactionBuilder::default()
        .input(factory_input)
        .input(reserve_input)
        .input(
            CellInput::new_builder()
                .previous_output(external_input_out_point)
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
                .capacity(output_reserve)
                .lock(factory_vault_lock)
                .build(),
        )
        .output(
            CellOutput::new_builder()
                .capacity(change_capacity)
                .lock(external_input_lock)
                .build(),
        )
        .output_data(new_factory_data.pack())
        .output_data(Bytes::new().pack())
        .output_data(Bytes::new().pack())
        .witness(witness_with_input_type(splice_witness.clone()))
        .witness(witness_with_input_type(splice_witness))
        .witness(empty_witness())
        .build();
    let tx = context.complete_tx(tx);
    (context, tx)
}

#[ignore = "requires `make build-contracts`"]
#[test]
fn factory_type_and_vault_accept_reduced_exit_reserve_release() {
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

    let released_capacity = ALICE_CAPACITY + BOB_CAPACITY;
    let reserve_claim_before_quantity = released_capacity as u128;
    let old_factory_data = reduced_exit_old_factory_data(1, reserve_claim_before_quantity);

    let factory_input_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(CELL_CAPACITY)
            .lock(factory_lock.clone())
            .type_(Some(factory_type.clone()).pack())
            .build(),
        old_factory_data.clone(),
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
        state_args_with_anchor(child_anchor, relative_since(0)),
    );
    let state_type_hash: [u8; 32] = state_type.calc_script_hash().unpack();
    let state_lock = deploy_contract(&mut context, "morph-state-lock", state_type_hash.to_vec());
    let state_lock_hash: [u8; 32] = state_lock.calc_script_hash().unpack();
    let vault_lock = deploy_contract(
        &mut context,
        "morph-vault-lock",
        vault_args(child_anchor, relative_since(0), &state_type, &state_lock),
    );
    let vault_lock_hash: [u8; 32] = vault_lock.calc_script_hash().unpack();

    let descriptor = descriptor_bytes(
        alice_lock.calc_script_hash().unpack(),
        ALICE_CAPACITY,
        bob_lock.calc_script_hash().unpack(),
        BOB_CAPACITY,
    );
    let mut child_state = header_raw_with_anchor(0, PHASE_ACTIVE, child_anchor);
    child_state[174..206].copy_from_slice(&settlement_descriptor_commitment_v1(&descriptor));
    set_state_payload_commitment(
        &mut child_state,
        vault_commitment(&vault_lock, released_capacity, None, &[]),
    );
    let key0 = signing_key(1);
    let key1 = signing_key(2);
    let mut child_pubkeys = [pubkey(&key0), pubkey(&key1)];
    child_pubkeys.sort();
    child_state[110..142].copy_from_slice(&participants_commitment_v1(
        2,
        &[&child_pubkeys[0], &child_pubkeys[1]],
    ));

    let (expected_old_data, new_data, reduced_witness) = signed_reduced_factory_exit_pair(
        1,
        2,
        reserve_claim_before_quantity,
        reserve_claim_before_quantity,
        0,
        state_output_index,
        vault_output_index,
        state_type_hash,
        vault_lock_hash,
        state_lock_hash,
        &child_state,
        &descriptor,
    );
    assert_eq!(old_factory_data, expected_old_data);

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
                .capacity(released_capacity)
                .lock(vault_lock)
                .build(),
        )
        .output(
            CellOutput::new_builder()
                .capacity(200_000_000_000u64)
                .lock(factory_vault_lock)
                .build(),
        )
        .output_data(new_data.pack())
        .output_data(Bytes::from(child_state.to_vec()).pack())
        .output_data(Bytes::new().pack())
        .output_data(Bytes::new().pack())
        .witness(witness_with_input_type(reduced_witness.clone()))
        .witness(witness_with_input_type(reduced_witness))
        .witness(empty_witness())
        .build();
    let tx = context.complete_tx(tx);

    context
        .verify_tx(&tx, MAX_CYCLES)
        .expect("reduced factory exit should verify");
}

#[ignore = "requires `make build-contracts`"]
#[test]
fn factory_type_rejects_reduced_exit_typed_claim_for_ckb_release() {
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

    let released_capacity = ALICE_CAPACITY + BOB_CAPACITY;
    let reserve_asset_type = [7u8; BYTE32_LEN];
    let reserve_claim_before_quantity = released_capacity as u128;
    let old_factory_data = reduced_exit_old_factory_data_with_reserve_asset(
        1,
        reserve_claim_before_quantity,
        Some(reserve_asset_type),
    );

    let factory_input_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(CELL_CAPACITY)
            .lock(factory_lock.clone())
            .type_(Some(factory_type.clone()).pack())
            .build(),
        old_factory_data.clone(),
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
        state_args_with_anchor(child_anchor, relative_since(0)),
    );
    let state_type_hash: [u8; 32] = state_type.calc_script_hash().unpack();
    let state_lock = deploy_contract(&mut context, "morph-state-lock", state_type_hash.to_vec());
    let state_lock_hash: [u8; 32] = state_lock.calc_script_hash().unpack();
    let vault_lock = deploy_contract(
        &mut context,
        "morph-vault-lock",
        vault_args(child_anchor, relative_since(0), &state_type, &state_lock),
    );
    let vault_lock_hash: [u8; 32] = vault_lock.calc_script_hash().unpack();

    let descriptor = descriptor_bytes(
        alice_lock.calc_script_hash().unpack(),
        ALICE_CAPACITY,
        bob_lock.calc_script_hash().unpack(),
        BOB_CAPACITY,
    );
    let mut child_state = header_raw_with_anchor(0, PHASE_ACTIVE, child_anchor);
    child_state[174..206].copy_from_slice(&settlement_descriptor_commitment_v1(&descriptor));
    set_state_payload_commitment(
        &mut child_state,
        vault_commitment(&vault_lock, released_capacity, None, &[]),
    );
    let key0 = signing_key(1);
    let key1 = signing_key(2);
    let mut child_pubkeys = [pubkey(&key0), pubkey(&key1)];
    child_pubkeys.sort();
    child_state[110..142].copy_from_slice(&participants_commitment_v1(
        2,
        &[&child_pubkeys[0], &child_pubkeys[1]],
    ));

    let (expected_old_data, new_data, reduced_witness) =
        signed_reduced_factory_exit_pair_with_reserve_asset(
            1,
            2,
            reserve_claim_before_quantity,
            reserve_claim_before_quantity,
            0,
            state_output_index,
            vault_output_index,
            state_type_hash,
            vault_lock_hash,
            state_lock_hash,
            &child_state,
            &descriptor,
            Some(reserve_asset_type),
        );
    assert_eq!(old_factory_data, expected_old_data);

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
                .capacity(released_capacity)
                .lock(vault_lock)
                .build(),
        )
        .output(
            CellOutput::new_builder()
                .capacity(200_000_000_000u64)
                .lock(factory_vault_lock)
                .build(),
        )
        .output_data(new_data.pack())
        .output_data(Bytes::from(child_state.to_vec()).pack())
        .output_data(Bytes::new().pack())
        .output_data(Bytes::new().pack())
        .witness(witness_with_input_type(reduced_witness.clone()))
        .witness(witness_with_input_type(reduced_witness))
        .witness(empty_witness())
        .build();
    let tx = context.complete_tx(tx);

    assert!(context.verify_tx(&tx, MAX_CYCLES).is_err());
}

#[test]
fn reduced_exit_xudt_witness_parses_with_typed_claim() {
    let xudt_type_hash = [9u8; 32];
    let descriptor = ckb_xudt_descriptor_bytes(
        xudt_type_hash,
        [1u8; 32],
        ALICE_CAPACITY,
        ALICE_XUDT_AMOUNT,
        [2u8; 32],
        BOB_CAPACITY,
        BOB_XUDT_AMOUNT,
    );
    let release_quantity = ALICE_XUDT_AMOUNT + BOB_XUDT_AMOUNT;
    let mut child_state = header_raw(0, PHASE_ACTIVE);
    child_state[174..206].copy_from_slice(&settlement_descriptor_commitment_v1(&descriptor));
    put_u16(
        &mut child_state,
        206,
        BILATERAL_CKB_XUDT_DESCRIPTOR_VERSION_V1,
    );
    let (witness, _, _) = reduced_exit_witness_raw_with_reserve_asset(
        release_quantity,
        release_quantity + 1,
        1,
        1,
        2,
        [0u8; 32],
        [0u8; 32],
        [0u8; 32],
        &child_state,
        &descriptor,
        Some(xudt_type_hash),
    );
    assert_eq!(witness.len(), FACTORY_REDUCED_EXIT_XUDT_WITNESS_V1_LEN);
    let witness = FactoryReducedExitWitnessV1::parse(&witness).unwrap();
    assert_eq!(
        witness.settlement_descriptor().len(),
        BILATERAL_CKB_XUDT_DESCRIPTOR_V1_LEN
    );
    assert_eq!(witness.release_quantity(), release_quantity);
}

#[ignore = "requires `make build-contracts`"]
#[test]
fn factory_type_and_vault_accept_reduced_exit_xudt_reserve_release() {
    let (context, tx) = factory_reduced_xudt_exit_tx(FactoryReducedXudtExitTamper::None);
    context
        .verify_tx(&tx, MAX_CYCLES)
        .expect("xUDT reduced factory exit should verify");
}

#[ignore = "requires `make build-contracts`"]
#[test]
fn factory_type_and_vault_accept_reduced_exit_xudt_full_release_without_typed_change() {
    let (context, tx) =
        factory_reduced_xudt_exit_tx(FactoryReducedXudtExitTamper::FullReleaseNoTypedChange);
    context
        .verify_tx(&tx, MAX_CYCLES)
        .expect("full xUDT reduced factory exit should verify with CKB-only factory change");
}

#[ignore = "requires `make build-contracts`"]
#[test]
fn factory_type_rejects_reduced_exit_xudt_amount_mismatch() {
    let (context, tx) = factory_reduced_xudt_exit_tx(
        FactoryReducedXudtExitTamper::ChildAmountMinusOneWithConservedSupply,
    );
    assert!(context.verify_tx(&tx, MAX_CYCLES).is_err());
}

#[ignore = "requires `make build-contracts`"]
#[test]
fn factory_type_rejects_reduced_exit_xudt_type_mismatch() {
    let (context, tx) = factory_reduced_xudt_exit_tx(
        FactoryReducedXudtExitTamper::ChildTypeMismatchWithAuthorisedMint,
    );
    assert!(context.verify_tx(&tx, MAX_CYCLES).is_err());
}

#[ignore = "requires `make build-contracts`"]
#[test]
fn factory_type_rejects_reduced_exit_xudt_claim_asset_type_mismatch() {
    let (context, tx) =
        factory_reduced_xudt_exit_tx(FactoryReducedXudtExitTamper::ClaimAssetTypeMismatch);
    assert!(context.verify_tx(&tx, MAX_CYCLES).is_err());
}

#[ignore = "requires `make build-contracts`"]
#[test]
fn factory_vault_rejects_reduced_exit_xudt_change_amount_mismatch() {
    let (context, tx) = factory_reduced_xudt_exit_tx(
        FactoryReducedXudtExitTamper::FactoryVaultChangeAmountMismatch,
    );
    assert!(context.verify_tx(&tx, MAX_CYCLES).is_err());
}

#[ignore = "requires `make build-contracts`"]
#[test]
fn factory_vault_rejects_reduced_exit_xudt_missing_typed_change() {
    let (context, tx) =
        factory_reduced_xudt_exit_tx(FactoryReducedXudtExitTamper::FactoryVaultChangeMissing);
    assert!(context.verify_tx(&tx, MAX_CYCLES).is_err());
}

#[ignore = "requires `make build-contracts`"]
#[test]
fn factory_type_rejects_reduced_exit_xudt_capacity_mismatch() {
    let (context, tx) =
        factory_reduced_xudt_exit_tx(FactoryReducedXudtExitTamper::CapacityMismatch);
    assert!(context.verify_tx(&tx, MAX_CYCLES).is_err());
}

fn factory_reduced_xudt_exit_tx(
    tamper: FactoryReducedXudtExitTamper,
) -> (Context, TransactionView) {
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
    let released_xudt_amount = ALICE_XUDT_AMOUNT + BOB_XUDT_AMOUNT;
    let factory_vault_xudt_surplus = match tamper {
        FactoryReducedXudtExitTamper::FullReleaseNoTypedChange => 0,
        _ => 40u128,
    };
    let reserve_claim_before_quantity = released_xudt_amount + factory_vault_xudt_surplus;
    let reserve_claim_after_quantity = factory_vault_xudt_surplus;
    let reserve_asset_type = match tamper {
        FactoryReducedXudtExitTamper::ClaimAssetTypeMismatch => [8u8; BYTE32_LEN],
        _ => xudt_type_hash,
    };
    let old_factory_data = reduced_exit_old_factory_data_with_reserve_asset(
        1,
        reserve_claim_before_quantity,
        Some(reserve_asset_type),
    );

    let factory_input_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(CELL_CAPACITY)
            .lock(factory_lock.clone())
            .type_(Some(factory_type.clone()).pack())
            .build(),
        old_factory_data.clone(),
    );
    let factory_input = CellInput::new_builder()
        .previous_output(factory_input_out_point)
        .build();
    let factory_vault_input_capacity = 300_000_000_000u64;
    let factory_vault_input_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(factory_vault_input_capacity)
            .lock(factory_vault_lock.clone())
            .type_(Some(xudt_type.clone()).pack())
            .build(),
        xudt_amount_data(reserve_claim_before_quantity),
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
        state_args_with_anchor(child_anchor, relative_since(0)),
    );
    let state_type_hash: [u8; 32] = state_type.calc_script_hash().unpack();
    let state_lock = deploy_contract(&mut context, "morph-state-lock", state_type_hash.to_vec());
    let state_lock_hash: [u8; 32] = state_lock.calc_script_hash().unpack();
    let vault_lock = deploy_contract(
        &mut context,
        "morph-vault-lock",
        vault_args(child_anchor, relative_since(0), &state_type, &state_lock),
    );
    let vault_lock_hash: [u8; 32] = vault_lock.calc_script_hash().unpack();

    let child_vault_capacity = ALICE_CAPACITY + BOB_CAPACITY;
    let child_vault_data = xudt_amount_data(released_xudt_amount);
    let mut child_state = header_raw_with_anchor(0, PHASE_ACTIVE, child_anchor);
    child_state[174..206].copy_from_slice(&settlement_descriptor_commitment_v1(&descriptor));
    put_u16(
        &mut child_state,
        206,
        BILATERAL_CKB_XUDT_DESCRIPTOR_VERSION_V1,
    );
    set_state_payload_commitment(
        &mut child_state,
        vault_commitment(
            &vault_lock,
            child_vault_capacity,
            Some(xudt_type_hash),
            child_vault_data.as_ref(),
        ),
    );
    let key0 = signing_key(1);
    let key1 = signing_key(2);
    let mut child_pubkeys = [pubkey(&key0), pubkey(&key1)];
    child_pubkeys.sort();
    child_state[110..142].copy_from_slice(&participants_commitment_v1(
        2,
        &[&child_pubkeys[0], &child_pubkeys[1]],
    ));

    let (expected_old_data, new_data, reduced_witness) =
        signed_reduced_factory_exit_pair_with_reserve_asset(
            1,
            2,
            released_xudt_amount,
            reserve_claim_before_quantity,
            reserve_claim_after_quantity,
            state_output_index,
            vault_output_index,
            state_type_hash,
            vault_lock_hash,
            state_lock_hash,
            &child_state,
            &descriptor,
            Some(reserve_asset_type),
        );
    assert_eq!(old_factory_data, expected_old_data);

    let actual_child_vault_capacity = match tamper {
        FactoryReducedXudtExitTamper::CapacityMismatch => child_vault_capacity - 1,
        _ => child_vault_capacity,
    };
    let child_vault_amount = match tamper {
        FactoryReducedXudtExitTamper::ChildAmountMinusOneWithConservedSupply => {
            released_xudt_amount - 1
        }
        _ => released_xudt_amount,
    };
    let child_vault_type = match tamper {
        FactoryReducedXudtExitTamper::ChildTypeMismatchWithAuthorisedMint => wrong_xudt_type,
        _ => xudt_type.clone(),
    };
    let factory_vault_change_capacity = factory_vault_input_capacity - actual_child_vault_capacity;
    let factory_vault_change_type = match tamper {
        FactoryReducedXudtExitTamper::FullReleaseNoTypedChange
        | FactoryReducedXudtExitTamper::FactoryVaultChangeMissing => None,
        _ => Some(xudt_type),
    };
    let factory_vault_change_amount = match tamper {
        FactoryReducedXudtExitTamper::FullReleaseNoTypedChange => 0,
        FactoryReducedXudtExitTamper::ChildAmountMinusOneWithConservedSupply => {
            factory_vault_xudt_surplus + 1
        }
        FactoryReducedXudtExitTamper::ChildTypeMismatchWithAuthorisedMint => {
            reserve_claim_before_quantity
        }
        FactoryReducedXudtExitTamper::FactoryVaultChangeAmountMismatch => {
            factory_vault_xudt_surplus - 1
        }
        _ => factory_vault_xudt_surplus,
    };
    let factory_vault_change_data = if factory_vault_change_type.is_some() {
        xudt_amount_data(factory_vault_change_amount)
    } else {
        Bytes::new()
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
                .capacity(actual_child_vault_capacity)
                .lock(vault_lock)
                .type_(Some(child_vault_type).pack())
                .build(),
        )
        .output(
            CellOutput::new_builder()
                .capacity(factory_vault_change_capacity)
                .lock(factory_vault_lock)
                .type_(factory_vault_change_type.pack())
                .build(),
        )
        .output_data(new_data.pack())
        .output_data(Bytes::from(child_state.to_vec()).pack())
        .output_data(xudt_amount_data(child_vault_amount).pack())
        .output_data(factory_vault_change_data.pack())
        .witness(witness_with_input_type(reduced_witness.clone()))
        .witness(witness_with_input_type(reduced_witness))
        .witness(empty_witness())
        .build();
    let tx = context.complete_tx(tx);
    (context, tx)
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
        state_args_with_anchor(child_anchor, relative_since(0)),
    );
    let state_type_hash: [u8; 32] = state_type.calc_script_hash().unpack();
    let state_lock = deploy_contract(&mut context, "morph-state-lock", state_type_hash.to_vec());
    let state_lock_hash: [u8; 32] = state_lock.calc_script_hash().unpack();
    let vault_lock = deploy_contract(
        &mut context,
        "morph-vault-lock",
        vault_args(child_anchor, relative_since(0), &state_type, &state_lock),
    );
    let vault_lock_hash: [u8; 32] = vault_lock.calc_script_hash().unpack();

    let mut child_state = header_raw_with_anchor(0, PHASE_ACTIVE, child_anchor);
    child_state[174..206].copy_from_slice(&settlement_descriptor_commitment_v1(&descriptor));
    set_state_payload_commitment(
        &mut child_state,
        vault_commitment(&vault_lock, ALICE_CAPACITY + BOB_CAPACITY, None, &[]),
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
fn factory_vault_rejects_local_exit_ckb_typed_factory_vault_input() {
    let mut context = Context::default();
    let factory_lock = deploy_always_success(&mut context);
    let reserve_lock_placeholder = deploy_always_success(&mut context);
    let alice_lock = deploy_always_success_with_args(&mut context, Bytes::from(vec![1]));
    let bob_lock = deploy_always_success_with_args(&mut context, Bytes::from(vec![2]));
    let reserve_type = deploy_always_success_with_args(&mut context, Bytes::from(vec![77]));

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
            .type_(Some(reserve_type).pack())
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
        state_args_with_anchor(child_anchor, relative_since(0)),
    );
    let state_type_hash: [u8; 32] = state_type.calc_script_hash().unpack();
    let state_lock = deploy_contract(&mut context, "morph-state-lock", state_type_hash.to_vec());
    let state_lock_hash: [u8; 32] = state_lock.calc_script_hash().unpack();
    let vault_lock = deploy_contract(
        &mut context,
        "morph-vault-lock",
        vault_args(child_anchor, relative_since(0), &state_type, &state_lock),
    );
    let vault_lock_hash: [u8; 32] = vault_lock.calc_script_hash().unpack();

    let mut child_state = header_raw_with_anchor(0, PHASE_ACTIVE, child_anchor);
    child_state[174..206].copy_from_slice(&settlement_descriptor_commitment_v1(&descriptor));
    set_state_payload_commitment(
        &mut child_state,
        vault_commitment(&vault_lock, ALICE_CAPACITY + BOB_CAPACITY, None, &[]),
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
                .build(),
        )
        .output(
            CellOutput::new_builder()
                .capacity(200_000_000_000u64)
                .lock(factory_vault_lock)
                .build(),
        )
        .output_data(new_data.pack())
        .output_data(Bytes::from(child_state.to_vec()).pack())
        .output_data(Bytes::new().pack())
        .output_data(Bytes::new().pack())
        .witness(witness_with_input_type(exit_witness.clone()))
        .witness(witness_with_input_type(exit_witness))
        .witness(empty_witness())
        .build();
    let tx = context.complete_tx(tx);

    assert!(context.verify_tx(&tx, MAX_CYCLES).is_err());
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

#[ignore = "requires `make build-contracts`"]
#[test]
fn factory_vault_rejects_local_exit_xudt_input_type_mismatch() {
    let (context, tx) =
        factory_xudt_local_exit_tx(FactoryXudtExitTamper::FactoryVaultInputTypeMismatch);
    assert!(context.verify_tx(&tx, MAX_CYCLES).is_err());
}

#[ignore = "requires `make build-contracts`"]
#[test]
fn factory_vault_rejects_local_exit_xudt_change_amount_mismatch() {
    let (context, tx) =
        factory_xudt_local_exit_tx(FactoryXudtExitTamper::FactoryVaultChangeAmountMismatch);
    assert!(context.verify_tx(&tx, MAX_CYCLES).is_err());
}

#[ignore = "requires `make build-contracts`"]
#[test]
fn factory_vault_rejects_local_exit_xudt_missing_typed_change() {
    let (context, tx) =
        factory_xudt_local_exit_tx(FactoryXudtExitTamper::FactoryVaultChangeMissingOnPartial);
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
    let partial_release = matches!(
        tamper,
        FactoryXudtExitTamper::FactoryVaultChangeAmountMismatch
            | FactoryXudtExitTamper::FactoryVaultChangeMissingOnPartial
    );
    let factory_vault_input_type = match tamper {
        FactoryXudtExitTamper::FactoryVaultInputTypeMismatch => wrong_xudt_type.clone(),
        _ => xudt_type.clone(),
    };
    let factory_vault_input_amount =
        ALICE_XUDT_AMOUNT + BOB_XUDT_AMOUNT + if partial_release { 1 } else { 0 };
    let factory_vault_input_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(300_000_000_000u64)
            .lock(factory_vault_lock.clone())
            .type_(Some(factory_vault_input_type).pack())
            .build(),
        xudt_amount_data(factory_vault_input_amount),
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
        state_args_with_anchor(child_anchor, relative_since(0)),
    );
    let state_type_hash: [u8; 32] = state_type.calc_script_hash().unpack();
    let state_lock = deploy_contract(&mut context, "morph-state-lock", state_type_hash.to_vec());
    let state_lock_hash: [u8; 32] = state_lock.calc_script_hash().unpack();
    let vault_lock = deploy_contract(
        &mut context,
        "morph-vault-lock",
        vault_args(child_anchor, relative_since(0), &state_type, &state_lock),
    );
    let vault_lock_hash: [u8; 32] = vault_lock.calc_script_hash().unpack();

    let mut child_state = header_raw_with_anchor(0, PHASE_ACTIVE, child_anchor);
    child_state[174..206].copy_from_slice(&settlement_descriptor_commitment_v1(&descriptor));
    put_u16(
        &mut child_state,
        206,
        BILATERAL_CKB_XUDT_DESCRIPTOR_VERSION_V1,
    );
    let child_vault_data = xudt_amount_data(ALICE_XUDT_AMOUNT + BOB_XUDT_AMOUNT);
    set_state_payload_commitment(
        &mut child_state,
        vault_commitment(
            &vault_lock,
            ALICE_CAPACITY + BOB_CAPACITY,
            Some(xudt_type_hash),
            child_vault_data.as_ref(),
        ),
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
        | FactoryXudtExitTamper::ChildTypeMismatchWithAuthorisedMint
        | FactoryXudtExitTamper::FactoryVaultChangeAmountMismatch => Some(xudt_type),
        FactoryXudtExitTamper::FactoryVaultChangeMissingOnPartial
        | FactoryXudtExitTamper::FactoryVaultInputTypeMismatch
        | FactoryXudtExitTamper::None => None,
    };
    let factory_vault_change_data = match tamper {
        FactoryXudtExitTamper::ChildAmountMinusOneWithConservedSupply => xudt_amount_data(1),
        FactoryXudtExitTamper::ChildTypeMismatchWithAuthorisedMint => {
            xudt_amount_data(ALICE_XUDT_AMOUNT + BOB_XUDT_AMOUNT)
        }
        FactoryXudtExitTamper::FactoryVaultChangeAmountMismatch => xudt_amount_data(2),
        FactoryXudtExitTamper::FactoryVaultChangeMissingOnPartial
        | FactoryXudtExitTamper::FactoryVaultInputTypeMismatch
        | FactoryXudtExitTamper::None => Bytes::new(),
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
fn state_type_rejects_supersede_output_lock_drift() {
    let mut context = Context::default();
    let lock = deploy_always_success_with_args(&mut context, Bytes::from(vec![1]));
    let wrong_lock = deploy_always_success_with_args(&mut context, Bytes::from(vec![2]));
    let state_type = deploy_contract(&mut context, "morph-state-type", state_args(0));
    let (old_data, new_data, sig_witness) = signed_state_pair(1, 1, 2, PHASE_SETTLING);

    let input_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(CELL_CAPACITY)
            .lock(lock)
            .type_(Some(state_type.clone()).pack())
            .build(),
        old_data,
    );
    let input = CellInput::new_builder()
        .previous_output(input_out_point)
        .build();

    let output = CellOutput::new_builder()
        .capacity(CELL_CAPACITY)
        .lock(wrong_lock)
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
fn state_type_accepts_signed_descriptor_update() {
    let mut context = Context::default();
    let lock = deploy_always_success(&mut context);
    let state_type = deploy_contract(&mut context, "morph-state-type", state_args(0));
    let descriptor = descriptor_bytes([1u8; 32], ALICE_CAPACITY, [2u8; 32], BOB_CAPACITY);
    let descriptor_commitment = settlement_descriptor_commitment_v1(&descriptor);
    let (old_data, new_data, sig_witness) = signed_state_pair_with_new_descriptor(
        1,
        PHASE_ACTIVE,
        2,
        PHASE_SETTLING,
        descriptor_commitment,
        BILATERAL_CKB_DESCRIPTOR_VERSION_V1,
    );

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
        .expect("signed descriptor update should verify");
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
    let alice_lock = deploy_always_success_with_args(&mut context, Bytes::from(vec![1]));
    let bob_lock = deploy_always_success_with_args(&mut context, Bytes::from(vec![2]));
    let descriptor = descriptor_bytes(
        alice_lock.calc_script_hash().unpack(),
        ALICE_CAPACITY,
        bob_lock.calc_script_hash().unpack(),
        BOB_CAPACITY,
    );
    let descriptor_commitment = settlement_descriptor_commitment_v1(&descriptor);
    let finalise_since = relative_since(0);
    let state_type = deploy_contract(&mut context, "morph-state-type", state_args(finalise_since));
    let state_type_hash: [u8; 32] = state_type.calc_script_hash().unpack();
    let state_lock = deploy_contract(&mut context, "morph-state-lock", state_type_hash.to_vec());
    let vault_lock = deploy_contract(
        &mut context,
        "morph-vault-lock",
        vault_args(FUNDING_ANCHOR, finalise_since, &state_type, &state_lock),
    );
    let mut state_data = header_raw(3, PHASE_SETTLING);
    state_data[174..206].copy_from_slice(&descriptor_commitment);
    set_state_payload_commitment(
        &mut state_data,
        vault_commitment(&vault_lock, CELL_CAPACITY, None, &[]),
    );

    let state_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(CELL_CAPACITY)
            .lock(state_lock)
            .type_(Some(state_type).pack())
            .build(),
        Bytes::from(state_data.to_vec()),
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
                .since(finalise_since)
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
    let alice_lock = deploy_always_success_with_args(&mut context, Bytes::from(vec![1]));
    let bob_lock = deploy_always_success_with_args(&mut context, Bytes::from(vec![2]));
    let descriptor = descriptor_bytes(
        alice_lock.calc_script_hash().unpack(),
        ALICE_CAPACITY,
        bob_lock.calc_script_hash().unpack(),
        BOB_CAPACITY,
    );
    let descriptor_commitment = settlement_descriptor_commitment_v1(&descriptor);
    let finalise_since = relative_since(0);
    let state_type = deploy_contract(&mut context, "morph-state-type", state_args(finalise_since));
    let state_type_hash: [u8; 32] = state_type.calc_script_hash().unpack();
    let state_lock = deploy_contract(&mut context, "morph-state-lock", state_type_hash.to_vec());
    let vault_lock = deploy_contract(
        &mut context,
        "morph-vault-lock",
        vault_args(FUNDING_ANCHOR, finalise_since, &state_type, &state_lock),
    );
    let mut state_data = header_raw(3, PHASE_SETTLING);
    state_data[174..206].copy_from_slice(&descriptor_commitment);
    set_state_payload_commitment(
        &mut state_data,
        vault_commitment(&vault_lock, CELL_CAPACITY, None, &[]),
    );

    let state_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(CELL_CAPACITY)
            .lock(state_lock)
            .type_(Some(state_type).pack())
            .build(),
        Bytes::from(state_data.to_vec()),
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
                .since(finalise_since)
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

fn ckb_vault_finalise_tx_with_tamper(
    tamper: VaultCkbSettlementTamper,
) -> (Context, TransactionView) {
    let mut context = Context::default();
    let alice_lock = deploy_always_success_with_args(&mut context, Bytes::from(vec![1]));
    let bob_lock = deploy_always_success_with_args(&mut context, Bytes::from(vec![2]));
    let extra_type = deploy_always_success_with_args(&mut context, Bytes::from(vec![99]));
    let descriptor = descriptor_bytes(
        alice_lock.calc_script_hash().unpack(),
        ALICE_CAPACITY,
        bob_lock.calc_script_hash().unpack(),
        BOB_CAPACITY,
    );
    let descriptor_commitment = settlement_descriptor_commitment_v1(&descriptor);
    let finalise_since = relative_since(0);
    let state_type = deploy_contract(&mut context, "morph-state-type", state_args(finalise_since));
    let state_type_hash: [u8; 32] = state_type.calc_script_hash().unpack();
    let state_lock = deploy_contract(&mut context, "morph-state-lock", state_type_hash.to_vec());
    let vault_lock = deploy_contract(
        &mut context,
        "morph-vault-lock",
        vault_args(FUNDING_ANCHOR, finalise_since, &state_type, &state_lock),
    );
    let mut state_data = header_raw(3, PHASE_SETTLING);
    state_data[174..206].copy_from_slice(&descriptor_commitment);
    set_state_payload_commitment(
        &mut state_data,
        vault_commitment(&vault_lock, CELL_CAPACITY, None, &[]),
    );

    let state_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(CELL_CAPACITY)
            .lock(state_lock)
            .type_(Some(state_type).pack())
            .build(),
        Bytes::from(state_data.to_vec()),
    );
    let vault_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(CELL_CAPACITY)
            .lock(vault_lock)
            .build(),
        Bytes::new(),
    );

    let mut tx_builder = TransactionBuilder::default()
        .input(
            CellInput::new_builder()
                .previous_output(state_out_point)
                .since(finalise_since)
                .build(),
        )
        .input(
            CellInput::new_builder()
                .previous_output(vault_out_point)
                .build(),
        );

    let mut outputs = Vec::new();
    match tamper {
        VaultCkbSettlementTamper::NonEmptyData => {
            outputs.push((
                CellOutput::new_builder()
                    .capacity(ALICE_CAPACITY)
                    .lock(alice_lock)
                    .build(),
                Bytes::from(vec![1]),
            ));
            outputs.push((
                CellOutput::new_builder()
                    .capacity(BOB_CAPACITY)
                    .lock(bob_lock)
                    .build(),
                Bytes::new(),
            ));
        }
        VaultCkbSettlementTamper::TypedOutput => {
            outputs.push((
                CellOutput::new_builder()
                    .capacity(ALICE_CAPACITY)
                    .lock(alice_lock)
                    .type_(Some(extra_type).pack())
                    .build(),
                Bytes::new(),
            ));
            outputs.push((
                CellOutput::new_builder()
                    .capacity(BOB_CAPACITY)
                    .lock(bob_lock)
                    .build(),
                Bytes::new(),
            ));
        }
        VaultCkbSettlementTamper::SplitOutput => {
            outputs.push((
                CellOutput::new_builder()
                    .capacity(ALICE_CAPACITY / 2)
                    .lock(alice_lock.clone())
                    .build(),
                Bytes::new(),
            ));
            outputs.push((
                CellOutput::new_builder()
                    .capacity(ALICE_CAPACITY - ALICE_CAPACITY / 2)
                    .lock(alice_lock)
                    .build(),
                Bytes::new(),
            ));
            outputs.push((
                CellOutput::new_builder()
                    .capacity(BOB_CAPACITY)
                    .lock(bob_lock)
                    .build(),
                Bytes::new(),
            ));
        }
    }

    for (output, data) in outputs {
        tx_builder = tx_builder.output(output).output_data(data.pack());
    }
    let tx = tx_builder
        .witness(empty_witness())
        .witness(witness_with_input_type(descriptor))
        .build();
    let tx = context.complete_tx(tx);
    (context, tx)
}

#[ignore = "requires `make build-contracts`"]
#[test]
fn vault_lock_rejects_ckb_settlement_output_with_data() {
    let (context, tx) = ckb_vault_finalise_tx_with_tamper(VaultCkbSettlementTamper::NonEmptyData);
    assert!(context.verify_tx(&tx, MAX_CYCLES).is_err());
}

#[ignore = "requires `make build-contracts`"]
#[test]
fn vault_lock_rejects_ckb_settlement_output_with_type() {
    let (context, tx) = ckb_vault_finalise_tx_with_tamper(VaultCkbSettlementTamper::TypedOutput);
    assert!(context.verify_tx(&tx, MAX_CYCLES).is_err());
}

#[ignore = "requires `make build-contracts`"]
#[test]
fn vault_lock_rejects_split_settlement_outputs_for_same_lock() {
    let (context, tx) = ckb_vault_finalise_tx_with_tamper(VaultCkbSettlementTamper::SplitOutput);
    assert!(context.verify_tx(&tx, MAX_CYCLES).is_err());
}

#[ignore = "requires `make build-contracts`"]
#[test]
fn vault_lock_rejects_fake_state_header_without_state_type() {
    let mut context = Context::default();
    let fake_state_lock = deploy_always_success(&mut context);
    let alice_lock = deploy_always_success_with_args(&mut context, Bytes::from(vec![1]));
    let bob_lock = deploy_always_success_with_args(&mut context, Bytes::from(vec![2]));
    let descriptor = descriptor_bytes(
        alice_lock.calc_script_hash().unpack(),
        ALICE_CAPACITY,
        bob_lock.calc_script_hash().unpack(),
        BOB_CAPACITY,
    );
    let descriptor_commitment = settlement_descriptor_commitment_v1(&descriptor);
    let finalise_since = relative_since(0);
    let state_type = deploy_contract(&mut context, "morph-state-type", state_args(finalise_since));
    let state_type_hash: [u8; 32] = state_type.calc_script_hash().unpack();
    let state_lock = deploy_contract(&mut context, "morph-state-lock", state_type_hash.to_vec());
    let vault_lock = deploy_contract(
        &mut context,
        "morph-vault-lock",
        vault_args(FUNDING_ANCHOR, finalise_since, &state_type, &state_lock),
    );
    let mut fake_state_data = header_raw(3, PHASE_SETTLING);
    fake_state_data[174..206].copy_from_slice(&descriptor_commitment);
    set_state_payload_commitment(
        &mut fake_state_data,
        vault_commitment(&vault_lock, CELL_CAPACITY, None, &[]),
    );

    let fake_state_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(CELL_CAPACITY)
            .lock(fake_state_lock)
            .build(),
        Bytes::from(fake_state_data.to_vec()),
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
                .previous_output(fake_state_out_point)
                .since(finalise_since)
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

    assert!(context.verify_tx(&tx, MAX_CYCLES).is_err());
}

#[ignore = "requires `make build-contracts`"]
#[test]
fn vault_lock_rejects_state_type_since_args_mismatch() {
    let mut context = Context::default();
    let alice_lock = deploy_always_success_with_args(&mut context, Bytes::from(vec![1]));
    let bob_lock = deploy_always_success_with_args(&mut context, Bytes::from(vec![2]));
    let descriptor = descriptor_bytes(
        alice_lock.calc_script_hash().unpack(),
        ALICE_CAPACITY,
        bob_lock.calc_script_hash().unpack(),
        BOB_CAPACITY,
    );
    let descriptor_commitment = settlement_descriptor_commitment_v1(&descriptor);
    let finalise_since = relative_since(0);
    let mismatched_since = relative_since(1);
    let state_code = context.deploy_cell(contract_bin("morph-state-type"));
    let state_lock_code = context.deploy_cell(contract_bin("morph-state-lock"));
    let expected_state_type =
        build_state_type_from_code(&mut context, &state_code, FUNDING_ANCHOR, finalise_since);
    let mismatched_state_type =
        build_state_type_from_code(&mut context, &state_code, FUNDING_ANCHOR, mismatched_since);
    let expected_state_lock =
        build_state_lock_from_code(&mut context, &state_lock_code, &expected_state_type);
    let mismatched_state_lock =
        build_state_lock_from_code(&mut context, &state_lock_code, &mismatched_state_type);
    let vault_lock = deploy_contract(
        &mut context,
        "morph-vault-lock",
        vault_args(
            FUNDING_ANCHOR,
            finalise_since,
            &expected_state_type,
            &expected_state_lock,
        ),
    );
    let mut state_data = header_raw(3, PHASE_SETTLING);
    state_data[174..206].copy_from_slice(&descriptor_commitment);
    set_state_payload_commitment(
        &mut state_data,
        vault_commitment(&vault_lock, CELL_CAPACITY, None, &[]),
    );

    let state_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(CELL_CAPACITY)
            .lock(mismatched_state_lock)
            .type_(Some(mismatched_state_type).pack())
            .build(),
        Bytes::from(state_data.to_vec()),
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
                .since(finalise_since)
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

    assert!(context.verify_tx(&tx, MAX_CYCLES).is_err());
}

#[ignore = "requires `make build-contracts`"]
#[test]
fn vault_lock_rejects_raw_absolute_since() {
    let mut context = Context::default();
    let alice_lock = deploy_always_success_with_args(&mut context, Bytes::from(vec![1]));
    let bob_lock = deploy_always_success_with_args(&mut context, Bytes::from(vec![2]));
    let descriptor = descriptor_bytes(
        alice_lock.calc_script_hash().unpack(),
        ALICE_CAPACITY,
        bob_lock.calc_script_hash().unpack(),
        BOB_CAPACITY,
    );
    let descriptor_commitment = settlement_descriptor_commitment_v1(&descriptor);
    let finalise_since = relative_since(0);
    let state_type = deploy_contract(&mut context, "morph-state-type", state_args(finalise_since));
    let state_type_hash: [u8; 32] = state_type.calc_script_hash().unpack();
    let state_lock = deploy_contract(&mut context, "morph-state-lock", state_type_hash.to_vec());
    let vault_lock = deploy_contract(
        &mut context,
        "morph-vault-lock",
        vault_args(FUNDING_ANCHOR, finalise_since, &state_type, &state_lock),
    );
    let mut state_data = header_raw(3, PHASE_SETTLING);
    state_data[174..206].copy_from_slice(&descriptor_commitment);
    set_state_payload_commitment(
        &mut state_data,
        vault_commitment(&vault_lock, CELL_CAPACITY, None, &[]),
    );

    let state_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(CELL_CAPACITY)
            .lock(state_lock)
            .type_(Some(state_type).pack())
            .build(),
        Bytes::from(state_data.to_vec()),
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
                .since(0u64)
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

    assert!(context.verify_tx(&tx, MAX_CYCLES).is_err());
}

#[ignore = "requires `make build-contracts`"]
#[test]
fn state_type_rejects_standalone_settling_close_without_matching_vault() {
    let mut context = Context::default();
    let state_refund_lock = deploy_always_success(&mut context);
    let finalise_since = relative_since(0);
    let state_type = deploy_contract(&mut context, "morph-state-type", state_args(finalise_since));
    let state_type_hash: [u8; 32] = state_type.calc_script_hash().unpack();
    let state_lock = deploy_contract(&mut context, "morph-state-lock", state_type_hash.to_vec());
    let mut state_data = header_raw(3, PHASE_SETTLING);
    set_state_payload_commitment(&mut state_data, [99u8; 32]);

    let state_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(CELL_CAPACITY)
            .lock(state_lock)
            .type_(Some(state_type).pack())
            .build(),
        Bytes::from(state_data.to_vec()),
    );

    let tx = TransactionBuilder::default()
        .input(
            CellInput::new_builder()
                .previous_output(state_out_point)
                .since(finalise_since)
                .build(),
        )
        .output(
            CellOutput::new_builder()
                .capacity(CELL_CAPACITY)
                .lock(state_refund_lock)
                .build(),
        )
        .output_data(Bytes::new().pack())
        .witness(empty_witness())
        .build();
    let tx = context.complete_tx(tx);

    assert!(context.verify_tx(&tx, MAX_CYCLES).is_err());
}

#[ignore = "requires `make build-contracts`"]
#[test]
fn state_type_rejects_standalone_active_splice_retire_without_matching_vault() {
    let mut context = Context::default();
    let finalise_since = relative_since(0);

    let state_code = context.deploy_cell(contract_bin("morph-state-type"));
    let state_lock_code = context.deploy_cell(contract_bin("morph-state-lock"));
    let old_state_type =
        build_state_type_from_code(&mut context, &state_code, FUNDING_ANCHOR, finalise_since);
    let new_state_type = build_state_type_from_code(
        &mut context,
        &state_code,
        NEW_FUNDING_ANCHOR,
        finalise_since,
    );
    let old_state_lock =
        build_state_lock_from_code(&mut context, &state_lock_code, &old_state_type);
    let new_state_lock =
        build_state_lock_from_code(&mut context, &state_lock_code, &new_state_type);

    let (old_state_data, new_state_data, splice_witness) = signed_splice_out_bundle(
        FUNDING_ANCHOR,
        NEW_FUNDING_ANCHOR,
        7,
        CELL_CAPACITY,
        ALICE_CAPACITY,
    );
    let mut old_state_data = old_state_data.to_vec();
    set_state_payload_commitment(&mut old_state_data, [99u8; BYTE32_LEN]);

    let state_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(CELL_CAPACITY)
            .lock(old_state_lock)
            .type_(Some(old_state_type).pack())
            .build(),
        Bytes::from(old_state_data),
    );

    let tx = TransactionBuilder::default()
        .input(
            CellInput::new_builder()
                .previous_output(state_out_point)
                .build(),
        )
        .output(
            CellOutput::new_builder()
                .capacity(CELL_CAPACITY)
                .lock(new_state_lock)
                .type_(Some(new_state_type).pack())
                .build(),
        )
        .output_data(new_state_data.pack())
        .witness(witness_with_input_type(splice_witness))
        .build();
    let tx = context.complete_tx(tx);

    assert!(context.verify_tx(&tx, MAX_CYCLES).is_err());
}

#[ignore = "requires `make build-contracts`"]
#[test]
fn state_and_vault_accept_splice_out_bridge() {
    let mut context = Context::default();
    let withdrawal_lock = deploy_always_success_with_args(&mut context, Bytes::from(vec![9]));
    let finalise_since = relative_since(0);

    let state_code = context.deploy_cell(contract_bin("morph-state-type"));
    let state_lock_code = context.deploy_cell(contract_bin("morph-state-lock"));
    let old_state_type =
        build_state_type_from_code(&mut context, &state_code, FUNDING_ANCHOR, finalise_since);
    let new_state_type = build_state_type_from_code(
        &mut context,
        &state_code,
        NEW_FUNDING_ANCHOR,
        finalise_since,
    );
    let old_state_lock =
        build_state_lock_from_code(&mut context, &state_lock_code, &old_state_type);
    let new_state_lock =
        build_state_lock_from_code(&mut context, &state_lock_code, &new_state_type);

    let vault_code = context.deploy_cell(contract_bin("morph-vault-lock"));
    let old_vault_lock = build_vault_lock_from_code(
        &mut context,
        &vault_code,
        FUNDING_ANCHOR,
        finalise_since,
        &old_state_type,
        &old_state_lock,
    );
    let new_vault_lock = build_vault_lock_from_code(
        &mut context,
        &vault_code,
        NEW_FUNDING_ANCHOR,
        finalise_since,
        &new_state_type,
        &new_state_lock,
    );

    let (old_state_data, new_state_data, splice_witness) = signed_splice_out_bundle(
        FUNDING_ANCHOR,
        NEW_FUNDING_ANCHOR,
        7,
        CELL_CAPACITY,
        ALICE_CAPACITY,
    );
    let (old_state_data, new_state_data) = bind_splice_state_payloads(
        old_state_data,
        new_state_data,
        &old_vault_lock,
        CELL_CAPACITY,
        &new_vault_lock,
        ALICE_CAPACITY,
    );

    let state_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(CELL_CAPACITY)
            .lock(old_state_lock)
            .type_(Some(old_state_type).pack())
            .build(),
        old_state_data,
    );
    let vault_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(CELL_CAPACITY)
            .lock(old_vault_lock)
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
                .capacity(CELL_CAPACITY)
                .lock(new_state_lock)
                .type_(Some(new_state_type).pack())
                .build(),
        )
        .output(
            CellOutput::new_builder()
                .capacity(ALICE_CAPACITY)
                .lock(new_vault_lock)
                .build(),
        )
        .output(
            CellOutput::new_builder()
                .capacity(BOB_CAPACITY)
                .lock(withdrawal_lock)
                .build(),
        )
        .output_data(new_state_data.pack())
        .output_data(Bytes::new().pack())
        .output_data(Bytes::new().pack())
        .witness(witness_with_input_type(splice_witness))
        .witness(empty_witness())
        .build();
    let tx = context.complete_tx(tx);

    context
        .verify_tx(&tx, MAX_CYCLES)
        .expect("state and vault splice bridge should verify");
}

#[ignore = "requires `make build-contracts`"]
#[test]
fn state_and_vault_accept_splice_in_bridge() {
    let mut context = Context::default();
    let external_funding_lock = deploy_always_success_with_args(&mut context, Bytes::from(vec![8]));
    let finalise_since = relative_since(0);

    let state_code = context.deploy_cell(contract_bin("morph-state-type"));
    let state_lock_code = context.deploy_cell(contract_bin("morph-state-lock"));
    let old_state_type =
        build_state_type_from_code(&mut context, &state_code, FUNDING_ANCHOR, finalise_since);
    let new_state_type = build_state_type_from_code(
        &mut context,
        &state_code,
        NEW_FUNDING_ANCHOR,
        finalise_since,
    );
    let old_state_lock =
        build_state_lock_from_code(&mut context, &state_lock_code, &old_state_type);
    let new_state_lock =
        build_state_lock_from_code(&mut context, &state_lock_code, &new_state_type);

    let vault_code = context.deploy_cell(contract_bin("morph-vault-lock"));
    let old_vault_lock = build_vault_lock_from_code(
        &mut context,
        &vault_code,
        FUNDING_ANCHOR,
        finalise_since,
        &old_state_type,
        &old_state_lock,
    );
    let new_vault_lock = build_vault_lock_from_code(
        &mut context,
        &vault_code,
        NEW_FUNDING_ANCHOR,
        finalise_since,
        &new_state_type,
        &new_state_lock,
    );

    let new_vault_capacity = CELL_CAPACITY + BOB_CAPACITY;
    let (old_state_data, new_state_data, splice_witness) = signed_splice_in_bundle(
        FUNDING_ANCHOR,
        NEW_FUNDING_ANCHOR,
        7,
        CELL_CAPACITY,
        new_vault_capacity,
    );
    let (old_state_data, new_state_data) = bind_splice_state_payloads(
        old_state_data,
        new_state_data,
        &old_vault_lock,
        CELL_CAPACITY,
        &new_vault_lock,
        new_vault_capacity,
    );

    let state_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(CELL_CAPACITY)
            .lock(old_state_lock)
            .type_(Some(old_state_type).pack())
            .build(),
        old_state_data,
    );
    let vault_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(CELL_CAPACITY)
            .lock(old_vault_lock)
            .build(),
        Bytes::new(),
    );
    let external_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(BOB_CAPACITY)
            .lock(external_funding_lock)
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
        .input(
            CellInput::new_builder()
                .previous_output(external_out_point)
                .build(),
        )
        .output(
            CellOutput::new_builder()
                .capacity(CELL_CAPACITY)
                .lock(new_state_lock)
                .type_(Some(new_state_type).pack())
                .build(),
        )
        .output(
            CellOutput::new_builder()
                .capacity(new_vault_capacity)
                .lock(new_vault_lock)
                .build(),
        )
        .output_data(new_state_data.pack())
        .output_data(Bytes::new().pack())
        .witness(witness_with_input_type(splice_witness))
        .witness(empty_witness())
        .witness(empty_witness())
        .build();
    let tx = context.complete_tx(tx);

    context
        .verify_tx(&tx, MAX_CYCLES)
        .expect("state and vault splice-in bridge should verify");
}

#[ignore = "requires `make build-contracts`"]
#[test]
fn state_type_rejects_splice_new_state_lock_drift() {
    let mut context = Context::default();
    let external_funding_lock = deploy_always_success_with_args(&mut context, Bytes::from(vec![8]));
    let finalise_since = relative_since(0);

    let state_code = context.deploy_cell(contract_bin("morph-state-type"));
    let state_lock_code = context.deploy_cell(contract_bin("morph-state-lock"));
    let old_state_type =
        build_state_type_from_code(&mut context, &state_code, FUNDING_ANCHOR, finalise_since);
    let new_state_type = build_state_type_from_code(
        &mut context,
        &state_code,
        NEW_FUNDING_ANCHOR,
        finalise_since,
    );
    let old_state_lock =
        build_state_lock_from_code(&mut context, &state_lock_code, &old_state_type);
    let new_state_lock =
        build_state_lock_from_code(&mut context, &state_lock_code, &new_state_type);
    let wrong_new_state_lock = deploy_always_success_with_args(
        &mut context,
        Bytes::from(new_state_type.calc_script_hash().as_slice().to_vec()),
    );

    let vault_code = context.deploy_cell(contract_bin("morph-vault-lock"));
    let old_vault_lock = build_vault_lock_from_code(
        &mut context,
        &vault_code,
        FUNDING_ANCHOR,
        finalise_since,
        &old_state_type,
        &old_state_lock,
    );
    let new_vault_capacity = CELL_CAPACITY + BOB_CAPACITY;
    let new_vault_lock = build_vault_lock_from_code(
        &mut context,
        &vault_code,
        NEW_FUNDING_ANCHOR,
        finalise_since,
        &new_state_type,
        &new_state_lock,
    );

    let (old_state_data, new_state_data, splice_witness) = signed_splice_in_bundle(
        FUNDING_ANCHOR,
        NEW_FUNDING_ANCHOR,
        7,
        CELL_CAPACITY,
        new_vault_capacity,
    );
    let (old_state_data, new_state_data) = bind_splice_state_payloads(
        old_state_data,
        new_state_data,
        &old_vault_lock,
        CELL_CAPACITY,
        &new_vault_lock,
        new_vault_capacity,
    );

    let state_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(CELL_CAPACITY)
            .lock(old_state_lock)
            .type_(Some(old_state_type).pack())
            .build(),
        old_state_data,
    );
    let vault_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(CELL_CAPACITY)
            .lock(old_vault_lock)
            .build(),
        Bytes::new(),
    );
    let external_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(BOB_CAPACITY)
            .lock(external_funding_lock)
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
        .input(
            CellInput::new_builder()
                .previous_output(external_out_point)
                .build(),
        )
        .output(
            CellOutput::new_builder()
                .capacity(CELL_CAPACITY)
                .lock(wrong_new_state_lock)
                .type_(Some(new_state_type).pack())
                .build(),
        )
        .output(
            CellOutput::new_builder()
                .capacity(new_vault_capacity)
                .lock(new_vault_lock)
                .build(),
        )
        .output_data(new_state_data.pack())
        .output_data(Bytes::new().pack())
        .witness(witness_with_input_type(splice_witness))
        .witness(empty_witness())
        .witness(empty_witness())
        .build();
    let tx = context.complete_tx(tx);

    assert!(context.verify_tx(&tx, MAX_CYCLES).is_err());
}

#[ignore = "requires `make build-contracts`"]
#[test]
fn state_and_vault_reject_splice_wrong_channel_header() {
    let mut context = Context::default();
    let withdrawal_lock = deploy_always_success_with_args(&mut context, Bytes::from(vec![9]));
    let finalise_since = relative_since(0);

    let state_code = context.deploy_cell(contract_bin("morph-state-type"));
    let state_lock_code = context.deploy_cell(contract_bin("morph-state-lock"));
    let old_state_type =
        build_state_type_from_code(&mut context, &state_code, FUNDING_ANCHOR, finalise_since);
    let new_state_type = build_state_type_from_code(
        &mut context,
        &state_code,
        NEW_FUNDING_ANCHOR,
        finalise_since,
    );
    let old_state_lock =
        build_state_lock_from_code(&mut context, &state_lock_code, &old_state_type);
    let new_state_lock =
        build_state_lock_from_code(&mut context, &state_lock_code, &new_state_type);

    let vault_code = context.deploy_cell(contract_bin("morph-vault-lock"));
    let old_vault_lock = build_vault_lock_from_code(
        &mut context,
        &vault_code,
        FUNDING_ANCHOR,
        finalise_since,
        &old_state_type,
        &old_state_lock,
    );
    let new_vault_lock = build_vault_lock_from_code(
        &mut context,
        &vault_code,
        NEW_FUNDING_ANCHOR,
        finalise_since,
        &new_state_type,
        &new_state_lock,
    );

    let (old_state_data, new_state_data, splice_witness) = signed_splice_out_bundle_with_channel(
        FUNDING_ANCHOR,
        NEW_FUNDING_ANCHOR,
        7,
        CELL_CAPACITY,
        ALICE_CAPACITY,
        [99u8; BYTE32_LEN],
    );

    let state_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(CELL_CAPACITY)
            .lock(old_state_lock)
            .type_(Some(old_state_type).pack())
            .build(),
        old_state_data,
    );
    let vault_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(CELL_CAPACITY)
            .lock(old_vault_lock)
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
                .capacity(CELL_CAPACITY)
                .lock(new_state_lock)
                .type_(Some(new_state_type).pack())
                .build(),
        )
        .output(
            CellOutput::new_builder()
                .capacity(ALICE_CAPACITY)
                .lock(new_vault_lock)
                .build(),
        )
        .output(
            CellOutput::new_builder()
                .capacity(BOB_CAPACITY)
                .lock(withdrawal_lock)
                .build(),
        )
        .output_data(new_state_data.pack())
        .output_data(Bytes::new().pack())
        .output_data(Bytes::new().pack())
        .witness(witness_with_input_type(splice_witness))
        .witness(empty_witness())
        .build();
    let tx = context.complete_tx(tx);

    assert!(context.verify_tx(&tx, MAX_CYCLES).is_err());
}

#[ignore = "requires `make build-contracts`"]
#[test]
fn vault_lock_rejects_splice_new_vault_capacity_mismatch() {
    let mut context = Context::default();
    let withdrawal_lock = deploy_always_success_with_args(&mut context, Bytes::from(vec![9]));
    let finalise_since = relative_since(0);

    let state_code = context.deploy_cell(contract_bin("morph-state-type"));
    let state_lock_code = context.deploy_cell(contract_bin("morph-state-lock"));
    let old_state_type =
        build_state_type_from_code(&mut context, &state_code, FUNDING_ANCHOR, finalise_since);
    let new_state_type = build_state_type_from_code(
        &mut context,
        &state_code,
        NEW_FUNDING_ANCHOR,
        finalise_since,
    );
    let old_state_lock =
        build_state_lock_from_code(&mut context, &state_lock_code, &old_state_type);
    let new_state_lock =
        build_state_lock_from_code(&mut context, &state_lock_code, &new_state_type);

    let vault_code = context.deploy_cell(contract_bin("morph-vault-lock"));
    let old_vault_lock = build_vault_lock_from_code(
        &mut context,
        &vault_code,
        FUNDING_ANCHOR,
        finalise_since,
        &old_state_type,
        &old_state_lock,
    );
    let new_vault_lock = build_vault_lock_from_code(
        &mut context,
        &vault_code,
        NEW_FUNDING_ANCHOR,
        finalise_since,
        &new_state_type,
        &new_state_lock,
    );

    let (old_state_data, new_state_data, splice_witness) = signed_splice_out_bundle(
        FUNDING_ANCHOR,
        NEW_FUNDING_ANCHOR,
        7,
        CELL_CAPACITY,
        ALICE_CAPACITY,
    );

    let state_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(CELL_CAPACITY)
            .lock(old_state_lock)
            .type_(Some(old_state_type).pack())
            .build(),
        old_state_data,
    );
    let vault_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(CELL_CAPACITY)
            .lock(old_vault_lock)
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
                .capacity(CELL_CAPACITY)
                .lock(new_state_lock)
                .type_(Some(new_state_type).pack())
                .build(),
        )
        .output(
            CellOutput::new_builder()
                .capacity(ALICE_CAPACITY - 1)
                .lock(new_vault_lock)
                .build(),
        )
        .output(
            CellOutput::new_builder()
                .capacity(BOB_CAPACITY + 1)
                .lock(withdrawal_lock)
                .build(),
        )
        .output_data(new_state_data.pack())
        .output_data(Bytes::new().pack())
        .output_data(Bytes::new().pack())
        .witness(witness_with_input_type(splice_witness))
        .witness(empty_witness())
        .build();
    let tx = context.complete_tx(tx);

    assert!(context.verify_tx(&tx, MAX_CYCLES).is_err());
}

#[ignore = "requires `make build-contracts`"]
#[test]
fn vault_lock_rejects_splice_new_state_payload_mismatch() {
    let mut context = Context::default();
    let withdrawal_lock = deploy_always_success_with_args(&mut context, Bytes::from(vec![9]));
    let finalise_since = relative_since(0);

    let state_code = context.deploy_cell(contract_bin("morph-state-type"));
    let state_lock_code = context.deploy_cell(contract_bin("morph-state-lock"));
    let old_state_type =
        build_state_type_from_code(&mut context, &state_code, FUNDING_ANCHOR, finalise_since);
    let new_state_type = build_state_type_from_code(
        &mut context,
        &state_code,
        NEW_FUNDING_ANCHOR,
        finalise_since,
    );
    let old_state_lock =
        build_state_lock_from_code(&mut context, &state_lock_code, &old_state_type);
    let new_state_lock =
        build_state_lock_from_code(&mut context, &state_lock_code, &new_state_type);

    let vault_code = context.deploy_cell(contract_bin("morph-vault-lock"));
    let old_vault_lock = build_vault_lock_from_code(
        &mut context,
        &vault_code,
        FUNDING_ANCHOR,
        finalise_since,
        &old_state_type,
        &old_state_lock,
    );
    let new_vault_lock = build_vault_lock_from_code(
        &mut context,
        &vault_code,
        NEW_FUNDING_ANCHOR,
        finalise_since,
        &new_state_type,
        &new_state_lock,
    );

    let (old_state_data, new_state_data, splice_witness) = signed_splice_out_bundle(
        FUNDING_ANCHOR,
        NEW_FUNDING_ANCHOR,
        7,
        CELL_CAPACITY,
        ALICE_CAPACITY,
    );
    let (old_state_data, new_state_data) = bind_splice_state_payloads(
        old_state_data,
        new_state_data,
        &old_vault_lock,
        CELL_CAPACITY,
        &new_vault_lock,
        ALICE_CAPACITY,
    );
    let mut new_state_data = new_state_data.to_vec();
    set_state_payload_commitment(&mut new_state_data, [99u8; BYTE32_LEN]);

    let state_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(CELL_CAPACITY)
            .lock(old_state_lock)
            .type_(Some(old_state_type).pack())
            .build(),
        old_state_data,
    );
    let vault_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(CELL_CAPACITY)
            .lock(old_vault_lock)
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
                .capacity(CELL_CAPACITY)
                .lock(new_state_lock)
                .type_(Some(new_state_type).pack())
                .build(),
        )
        .output(
            CellOutput::new_builder()
                .capacity(ALICE_CAPACITY)
                .lock(new_vault_lock)
                .build(),
        )
        .output(
            CellOutput::new_builder()
                .capacity(BOB_CAPACITY)
                .lock(withdrawal_lock)
                .build(),
        )
        .output_data(Bytes::from(new_state_data).pack())
        .output_data(Bytes::new().pack())
        .output_data(Bytes::new().pack())
        .witness(witness_with_input_type(splice_witness))
        .witness(empty_witness())
        .build();
    let tx = context.complete_tx(tx);

    assert!(context.verify_tx(&tx, MAX_CYCLES).is_err());
}

#[ignore = "requires `make build-contracts`"]
#[test]
fn vault_lock_rejects_splice_split_new_vault_outputs() {
    let mut context = Context::default();
    let withdrawal_lock = deploy_always_success_with_args(&mut context, Bytes::from(vec![9]));
    let finalise_since = relative_since(0);

    let state_code = context.deploy_cell(contract_bin("morph-state-type"));
    let state_lock_code = context.deploy_cell(contract_bin("morph-state-lock"));
    let old_state_type =
        build_state_type_from_code(&mut context, &state_code, FUNDING_ANCHOR, finalise_since);
    let new_state_type = build_state_type_from_code(
        &mut context,
        &state_code,
        NEW_FUNDING_ANCHOR,
        finalise_since,
    );
    let old_state_lock =
        build_state_lock_from_code(&mut context, &state_lock_code, &old_state_type);
    let new_state_lock =
        build_state_lock_from_code(&mut context, &state_lock_code, &new_state_type);

    let vault_code = context.deploy_cell(contract_bin("morph-vault-lock"));
    let old_vault_lock = build_vault_lock_from_code(
        &mut context,
        &vault_code,
        FUNDING_ANCHOR,
        finalise_since,
        &old_state_type,
        &old_state_lock,
    );
    let new_vault_lock = build_vault_lock_from_code(
        &mut context,
        &vault_code,
        NEW_FUNDING_ANCHOR,
        finalise_since,
        &new_state_type,
        &new_state_lock,
    );

    let (old_state_data, new_state_data, splice_witness) = signed_splice_out_bundle(
        FUNDING_ANCHOR,
        NEW_FUNDING_ANCHOR,
        7,
        CELL_CAPACITY,
        ALICE_CAPACITY,
    );
    let (old_state_data, new_state_data) = bind_splice_state_payloads(
        old_state_data,
        new_state_data,
        &old_vault_lock,
        CELL_CAPACITY,
        &new_vault_lock,
        ALICE_CAPACITY,
    );

    let state_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(CELL_CAPACITY)
            .lock(old_state_lock)
            .type_(Some(old_state_type).pack())
            .build(),
        old_state_data,
    );
    let vault_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(CELL_CAPACITY)
            .lock(old_vault_lock)
            .build(),
        Bytes::new(),
    );
    let first_split = ALICE_CAPACITY / 2;
    let second_split = ALICE_CAPACITY - first_split;

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
                .capacity(CELL_CAPACITY)
                .lock(new_state_lock)
                .type_(Some(new_state_type).pack())
                .build(),
        )
        .output(
            CellOutput::new_builder()
                .capacity(first_split)
                .lock(new_vault_lock.clone())
                .build(),
        )
        .output(
            CellOutput::new_builder()
                .capacity(second_split)
                .lock(new_vault_lock)
                .build(),
        )
        .output(
            CellOutput::new_builder()
                .capacity(BOB_CAPACITY)
                .lock(withdrawal_lock)
                .build(),
        )
        .output_data(new_state_data.pack())
        .output_data(Bytes::new().pack())
        .output_data(Bytes::new().pack())
        .output_data(Bytes::new().pack())
        .witness(witness_with_input_type(splice_witness))
        .witness(empty_witness())
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
fn devnet_xudt_rejects_transfer_sum_overflow() {
    let mut context = Context::default();
    let owner_lock = deploy_always_success_with_args(&mut context, Bytes::from(vec![1]));
    let alice_lock = deploy_always_success_with_args(&mut context, Bytes::from(vec![2]));
    let bob_lock = deploy_always_success_with_args(&mut context, Bytes::from(vec![3]));
    let xudt_type = deploy_contract(
        &mut context,
        "morph-devnet-xudt",
        owner_lock.calc_script_hash().as_slice().to_vec(),
    );

    let xudt_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(CELL_CAPACITY)
            .lock(alice_lock.clone())
            .type_(Some(xudt_type.clone()).pack())
            .build(),
        xudt_amount_data(u128::MAX),
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
        .output_data(xudt_amount_data(u128::MAX).pack())
        .output_data(xudt_amount_data(1).pack())
        .build();
    let transfer_tx = context.complete_tx(transfer_tx);

    assert!(context.verify_tx(&transfer_tx, MAX_CYCLES).is_err());
}

#[ignore = "requires `make build-contracts`"]
#[test]
fn vault_lock_accepts_xudt_finalise_with_descriptor_amounts() {
    let mut context = Context::default();
    let xudt_owner_lock = deploy_always_success_with_args(&mut context, Bytes::from(vec![9]));
    let alice_lock = deploy_always_success_with_args(&mut context, Bytes::from(vec![1]));
    let bob_lock = deploy_always_success_with_args(&mut context, Bytes::from(vec![2]));
    let xudt_type = deploy_contract(
        &mut context,
        "morph-devnet-xudt",
        xudt_owner_lock.calc_script_hash().as_slice().to_vec(),
    );
    let xudt_type_hash: [u8; 32] = xudt_type.calc_script_hash().unpack();
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
    let finalise_since = relative_since(0);
    let state_type = deploy_contract(&mut context, "morph-state-type", state_args(finalise_since));
    let state_type_hash: [u8; 32] = state_type.calc_script_hash().unpack();
    let state_lock = deploy_contract(&mut context, "morph-state-lock", state_type_hash.to_vec());
    let vault_lock = deploy_contract(
        &mut context,
        "morph-vault-lock",
        vault_args(FUNDING_ANCHOR, finalise_since, &state_type, &state_lock),
    );
    let vault_data = xudt_amount_data(ALICE_XUDT_AMOUNT + BOB_XUDT_AMOUNT);
    let vault_commitment = vault_commitment(
        &vault_lock,
        CELL_CAPACITY,
        Some(xudt_type_hash),
        vault_data.as_ref(),
    );
    let mut state_data = header_raw(3, PHASE_SETTLING);
    state_data[174..206].copy_from_slice(&descriptor_commitment);
    put_u16(
        &mut state_data,
        206,
        BILATERAL_CKB_XUDT_DESCRIPTOR_VERSION_V1,
    );
    set_state_payload_commitment(&mut state_data, vault_commitment);

    let state_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(CELL_CAPACITY)
            .lock(state_lock)
            .type_(Some(state_type).pack())
            .build(),
        Bytes::from(state_data.to_vec()),
    );
    let vault_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(CELL_CAPACITY)
            .lock(vault_lock)
            .type_(Some(xudt_type.clone()).pack())
            .build(),
        vault_data,
    );

    let tx = TransactionBuilder::default()
        .input(
            CellInput::new_builder()
                .previous_output(state_out_point)
                .since(finalise_since)
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

fn xudt_vault_finalise_tx_with_tamper(
    tamper: VaultXudtSettlementTamper,
) -> (Context, TransactionView) {
    let mut context = Context::default();
    let xudt_owner_lock = deploy_always_success_with_args(&mut context, Bytes::from(vec![9]));
    let alice_lock = deploy_always_success_with_args(&mut context, Bytes::from(vec![1]));
    let bob_lock = deploy_always_success_with_args(&mut context, Bytes::from(vec![2]));
    let xudt_type = deploy_contract(
        &mut context,
        "morph-devnet-xudt",
        xudt_owner_lock.calc_script_hash().as_slice().to_vec(),
    );
    let xudt_type_hash: [u8; 32] = xudt_type.calc_script_hash().unpack();
    let (alice_descriptor_amount, bob_descriptor_amount) = match tamper {
        VaultXudtSettlementTamper::NonzeroWrongAmountData => (ALICE_XUDT_AMOUNT, BOB_XUDT_AMOUNT),
        VaultXudtSettlementTamper::ZeroRecipientTypedCell => {
            (ALICE_XUDT_AMOUNT + BOB_XUDT_AMOUNT, 0)
        }
    };
    let descriptor = ckb_xudt_descriptor_bytes(
        xudt_type_hash,
        alice_lock.calc_script_hash().unpack(),
        ALICE_CAPACITY,
        alice_descriptor_amount,
        bob_lock.calc_script_hash().unpack(),
        BOB_CAPACITY,
        bob_descriptor_amount,
    );
    let descriptor_commitment = settlement_descriptor_commitment_v1(&descriptor);
    let finalise_since = relative_since(0);
    let state_type = deploy_contract(&mut context, "morph-state-type", state_args(finalise_since));
    let state_type_hash: [u8; 32] = state_type.calc_script_hash().unpack();
    let state_lock = deploy_contract(&mut context, "morph-state-lock", state_type_hash.to_vec());
    let vault_lock = deploy_contract(
        &mut context,
        "morph-vault-lock",
        vault_args(FUNDING_ANCHOR, finalise_since, &state_type, &state_lock),
    );
    let total_amount = ALICE_XUDT_AMOUNT + BOB_XUDT_AMOUNT;
    let vault_data = xudt_amount_data(total_amount);
    let vault_commitment = vault_commitment(
        &vault_lock,
        CELL_CAPACITY,
        Some(xudt_type_hash),
        vault_data.as_ref(),
    );
    let mut state_data = header_raw(3, PHASE_SETTLING);
    state_data[174..206].copy_from_slice(&descriptor_commitment);
    put_u16(
        &mut state_data,
        206,
        BILATERAL_CKB_XUDT_DESCRIPTOR_VERSION_V1,
    );
    set_state_payload_commitment(&mut state_data, vault_commitment);

    let state_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(CELL_CAPACITY)
            .lock(state_lock)
            .type_(Some(state_type).pack())
            .build(),
        Bytes::from(state_data.to_vec()),
    );
    let vault_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(CELL_CAPACITY)
            .lock(vault_lock)
            .type_(Some(xudt_type.clone()).pack())
            .build(),
        vault_data,
    );

    let (alice_output_amount, bob_output_amount, bob_output_type) = match tamper {
        VaultXudtSettlementTamper::NonzeroWrongAmountData => (
            ALICE_XUDT_AMOUNT - 1,
            BOB_XUDT_AMOUNT + 1,
            Some(xudt_type.clone()),
        ),
        VaultXudtSettlementTamper::ZeroRecipientTypedCell => {
            (total_amount, 0, Some(xudt_type.clone()))
        }
    };
    let tx = TransactionBuilder::default()
        .input(
            CellInput::new_builder()
                .previous_output(state_out_point)
                .since(finalise_since)
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
                .type_(Some(xudt_type).pack())
                .build(),
        )
        .output(
            CellOutput::new_builder()
                .capacity(BOB_CAPACITY)
                .lock(bob_lock)
                .type_(bob_output_type.pack())
                .build(),
        )
        .output_data(xudt_amount_data(alice_output_amount).pack())
        .output_data(xudt_amount_data(bob_output_amount).pack())
        .witness(empty_witness())
        .witness(witness_with_input_type(descriptor))
        .build();
    let tx = context.complete_tx(tx);
    (context, tx)
}

#[ignore = "requires `make build-contracts`"]
#[test]
fn vault_lock_rejects_xudt_nonzero_wrong_amount_data() {
    let (context, tx) =
        xudt_vault_finalise_tx_with_tamper(VaultXudtSettlementTamper::NonzeroWrongAmountData);
    assert!(context.verify_tx(&tx, MAX_CYCLES).is_err());
}

#[ignore = "requires `make build-contracts`"]
#[test]
fn vault_lock_rejects_xudt_zero_recipient_typed_cell() {
    let (context, tx) =
        xudt_vault_finalise_tx_with_tamper(VaultXudtSettlementTamper::ZeroRecipientTypedCell);
    assert!(context.verify_tx(&tx, MAX_CYCLES).is_err());
}

#[ignore = "requires `make build-contracts`"]
#[test]
fn sponsor_lock_accepts_bounded_fee_with_wallet_change() {
    let mut context = Context::default();
    let wallet_lock = deploy_always_success(&mut context);
    let state_lock = deploy_always_success_with_args(&mut context, Bytes::from(vec![7]));
    let state_type = deploy_contract(&mut context, "morph-state-type", state_args(0));
    let state_type_hash: [u8; BYTE32_LEN] = state_type.calc_script_hash().unpack();
    let (old_state_data, new_state_data, sig_witness) = signed_state_pair(1, 1, 2, PHASE_SETTLING);
    let change_hash = wallet_lock.calc_script_hash();
    let sponsor_lock = deploy_contract(
        &mut context,
        "morph-sponsor-lock",
        sponsor_policy(
            change_hash.as_slice().try_into().unwrap(),
            &state_type_hash,
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

    context
        .verify_tx(&tx, MAX_CYCLES)
        .expect("bounded sponsor fee should verify");
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SponsorChangeTamper {
    TypedChange,
    DataChange,
    BudgetOverflow,
}

fn sponsor_change_tamper_tx(tamper: SponsorChangeTamper) -> (Context, TransactionView) {
    let mut context = Context::default();
    let wallet_lock = deploy_always_success(&mut context);
    let state_lock = deploy_always_success_with_args(&mut context, Bytes::from(vec![7]));
    let state_type = deploy_contract(&mut context, "morph-state-type", state_args(0));
    let state_type_hash: [u8; BYTE32_LEN] = state_type.calc_script_hash().unpack();
    let (old_state_data, new_state_data, sig_witness) = signed_state_pair(1, 1, 2, PHASE_SETTLING);
    let change_hash = wallet_lock.calc_script_hash();
    let policy = if tamper == SponsorChangeTamper::BudgetOverflow {
        sponsor_policy_with_already_spent(
            change_hash.as_slice().try_into().unwrap(),
            &state_type_hash,
            1_000,
            u64::MAX,
            u64::MAX - 50,
        )
    } else {
        sponsor_policy(
            change_hash.as_slice().try_into().unwrap(),
            &state_type_hash,
            1_000,
        )
    };
    let sponsor_lock = deploy_contract(&mut context, "morph-sponsor-lock", policy);
    let dirty_type = if tamper == SponsorChangeTamper::TypedChange {
        Some(deploy_always_success_with_args(
            &mut context,
            Bytes::from(vec![42]),
        ))
    } else {
        None
    };

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
    let mut change_output = CellOutput::new_builder()
        .capacity(CELL_CAPACITY - 100)
        .lock(wallet_lock)
        .build();
    if let Some(dirty_type) = dirty_type {
        change_output = change_output
            .as_builder()
            .type_(Some(dirty_type).pack())
            .build();
    }
    let change_data = if tamper == SponsorChangeTamper::DataChange {
        Bytes::from(vec![1])
    } else {
        Bytes::new()
    };

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
        .output(change_output)
        .output_data(new_state_data.pack())
        .output_data(change_data.pack())
        .witness(witness_with_input_type(sig_witness))
        .witness(empty_witness())
        .build();
    let tx = context.complete_tx(tx);
    (context, tx)
}

#[ignore = "requires `make build-contracts`"]
#[test]
fn sponsor_lock_rejects_typed_change_output() {
    let (context, tx) = sponsor_change_tamper_tx(SponsorChangeTamper::TypedChange);
    assert!(context.verify_tx(&tx, MAX_CYCLES).is_err());
}

#[ignore = "requires `make build-contracts`"]
#[test]
fn sponsor_lock_rejects_change_output_with_data() {
    let (context, tx) = sponsor_change_tamper_tx(SponsorChangeTamper::DataChange);
    assert!(context.verify_tx(&tx, MAX_CYCLES).is_err());
}

#[ignore = "requires `make build-contracts`"]
#[test]
fn sponsor_lock_rejects_budget_add_overflow() {
    let (context, tx) = sponsor_change_tamper_tx(SponsorChangeTamper::BudgetOverflow);
    assert!(context.verify_tx(&tx, MAX_CYCLES).is_err());
}

#[ignore = "requires `make build-contracts`"]
#[test]
fn sponsor_lock_does_not_mask_wrong_state_output_lock() {
    let mut context = Context::default();
    let wallet_lock = deploy_always_success(&mut context);
    let state_lock = deploy_always_success_with_args(&mut context, Bytes::from(vec![7]));
    let wrong_state_lock = deploy_always_success_with_args(&mut context, Bytes::from(vec![8]));
    let state_type = deploy_contract(&mut context, "morph-state-type", state_args(0));
    let state_type_hash: [u8; BYTE32_LEN] = state_type.calc_script_hash().unpack();
    let (old_state_data, new_state_data, sig_witness) = signed_state_pair(1, 1, 2, PHASE_SETTLING);
    let change_hash = wallet_lock.calc_script_hash();
    let sponsor_lock = deploy_contract(
        &mut context,
        "morph-sponsor-lock",
        sponsor_policy(
            change_hash.as_slice().try_into().unwrap(),
            &state_type_hash,
            1_000,
        ),
    );

    let state_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(CELL_CAPACITY)
            .lock(state_lock)
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
                .lock(wrong_state_lock)
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
fn sponsor_lock_rejects_finite_expiry_policy() {
    let mut context = Context::default();
    let wallet_lock = deploy_always_success(&mut context);
    let state_lock = deploy_always_success_with_args(&mut context, Bytes::from(vec![7]));
    let state_type = deploy_contract(&mut context, "morph-state-type", state_args(0));
    let state_type_hash: [u8; BYTE32_LEN] = state_type.calc_script_hash().unpack();
    let (old_state_data, new_state_data, sig_witness) = signed_state_pair(1, 1, 2, PHASE_SETTLING);
    let change_hash = wallet_lock.calc_script_hash();
    let sponsor_lock = deploy_contract(
        &mut context,
        "morph-sponsor-lock",
        sponsor_policy_with_bounds_and_expiry(
            change_hash.as_slice().try_into().unwrap(),
            &state_type_hash,
            0,
            u64::MAX,
            1_000,
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
fn sponsor_lock_rejects_fee_above_per_tx_limit() {
    let mut context = Context::default();
    let wallet_lock = deploy_always_success(&mut context);
    let state_lock = deploy_always_success_with_args(&mut context, Bytes::from(vec![7]));
    let state_type = deploy_contract(&mut context, "morph-state-type", state_args(0));
    let state_type_hash: [u8; BYTE32_LEN] = state_type.calc_script_hash().unpack();
    let (old_state_data, new_state_data, sig_witness) = signed_state_pair(1, 1, 2, PHASE_SETTLING);
    let change_hash = wallet_lock.calc_script_hash();
    let sponsor_lock = deploy_contract(
        &mut context,
        "morph-sponsor-lock",
        sponsor_policy(
            change_hash.as_slice().try_into().unwrap(),
            &state_type_hash,
            50,
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
fn sponsor_lock_rejects_state_number_outside_policy_range() {
    let mut context = Context::default();
    let wallet_lock = deploy_always_success(&mut context);
    let state_lock = deploy_always_success_with_args(&mut context, Bytes::from(vec![7]));
    let state_type = deploy_contract(&mut context, "morph-state-type", state_args(0));
    let state_type_hash: [u8; BYTE32_LEN] = state_type.calc_script_hash().unpack();
    let (old_state_data, new_state_data, sig_witness) = signed_state_pair(1, 1, 2, PHASE_SETTLING);
    let change_hash = wallet_lock.calc_script_hash();
    let sponsor_lock = deploy_contract(
        &mut context,
        "morph-sponsor-lock",
        sponsor_policy_with_bounds(
            change_hash.as_slice().try_into().unwrap(),
            &state_type_hash,
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
        sponsor_policy(
            change_hash.as_slice().try_into().unwrap(),
            &[9u8; BYTE32_LEN],
            1_000,
        ),
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

#[ignore = "requires `make build-contracts`"]
#[test]
fn sponsor_lock_rejects_fake_state_header_without_state_type() {
    let mut context = Context::default();
    let wallet_lock = deploy_always_success(&mut context);
    let state_type = deploy_contract(&mut context, "morph-state-type", state_args(0));
    let state_type_hash: [u8; BYTE32_LEN] = state_type.calc_script_hash().unpack();
    let (_, fake_state_data, _) = signed_state_pair(1, 1, 2, PHASE_SETTLING);
    let change_hash = wallet_lock.calc_script_hash();
    let sponsor_lock = deploy_contract(
        &mut context,
        "morph-sponsor-lock",
        sponsor_policy(
            change_hash.as_slice().try_into().unwrap(),
            &state_type_hash,
            1_000,
        ),
    );

    let sponsor_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(CELL_CAPACITY * 2)
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
                .capacity(CELL_CAPACITY)
                .lock(wallet_lock.clone())
                .build(),
        )
        .output(
            CellOutput::new_builder()
                .capacity(CELL_CAPACITY - 100)
                .lock(wallet_lock)
                .build(),
        )
        .output_data(fake_state_data.pack())
        .output_data(Bytes::new().pack())
        .build();
    let tx = context.complete_tx(tx);

    assert!(context.verify_tx(&tx, MAX_CYCLES).is_err());
}
