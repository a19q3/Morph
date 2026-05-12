use std::collections::BTreeSet;

use k256::ecdsa::signature::hazmat::PrehashSigner;
use k256::ecdsa::{Signature, SigningKey};
use morph_core::*;

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

fn signed_cells(
    old_number: u64,
    old_phase: Phase,
    new_number: u64,
    new_phase: Phase,
) -> (StateCell, StateCell, StateTransitionContext) {
    let mut old = state(old_number, old_phase);
    let mut new = state(new_number, new_phase);
    let authorization = authorization_for(&mut new.header);
    old.header.participants_commitment = new.header.participants_commitment;
    let ctx = StateTransitionContext {
        referenced_funding_anchor: bytes32(3),
        authorization,
        asset_registry: registry(),
        partition: good_partition(),
    };
    (old, new, ctx)
}

fn state(n: u64, phase: Phase) -> StateCell {
    StateCell {
        header: header(n, phase),
        capacity: 10_000,
        occupied_capacity: 1_000,
    }
}

fn registry() -> AssetRegistry {
    AssetRegistry {
        xudt_types: BTreeSet::from([bytes32(42)]),
    }
}

fn good_partition() -> PartitionedTransaction {
    PartitionedTransaction {
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
    }
}

fn factory_right(
    participant: u8,
    subchannel: u8,
    kind: FactoryRightKind,
    asset_type: Option<u8>,
    quantity: Amount,
) -> FactoryRight {
    FactoryRight {
        id: FactoryRightId {
            participant: bytes32(participant),
            subchannel: bytes32(subchannel),
            kind,
            asset_type: asset_type.map(bytes32),
        },
        quantity,
    }
}

fn factory_update() -> FactoryUpdate {
    let before = vec![
        factory_right(1, 10, FactoryRightKind::Balance, None, 100),
        factory_right(1, 10, FactoryRightKind::ReserveClaim, None, 50),
        factory_right(1, 10, FactoryRightKind::Membership, None, 1),
        factory_right(1, 10, FactoryRightKind::ExitPath, None, 1),
        factory_right(1, 10, FactoryRightKind::SponsorBudgetClaim, None, 20),
        factory_right(2, 10, FactoryRightKind::Balance, None, 100),
        factory_right(2, 10, FactoryRightKind::ReserveClaim, None, 50),
        factory_right(2, 10, FactoryRightKind::Membership, None, 1),
        factory_right(2, 10, FactoryRightKind::ExitPath, None, 1),
        factory_right(2, 10, FactoryRightKind::SponsorBudgetClaim, None, 20),
    ];
    FactoryUpdate {
        after: before.clone(),
        before,
        touched_participants: BTreeSet::from([bytes32(1)]),
        authorised_participants: BTreeSet::from([bytes32(1)]),
    }
}

fn factory_reduced_exit(update: &FactoryUpdate, release_quantity: Amount) -> FactoryReducedExit {
    let reserve_claim = update
        .before
        .iter()
        .find(|right| {
            right.id.participant == bytes32(1) && right.id.kind == FactoryRightKind::ReserveClaim
        })
        .expect("fixture reserve claim")
        .id
        .clone();
    FactoryReducedExit {
        participant: bytes32(1),
        reserve_claim,
        release_quantity,
    }
}

fn large_factory_rights() -> Vec<FactoryRight> {
    let mut rights = Vec::new();
    for participant in 1..=8 {
        for subchannel in 10..=13 {
            rights.push(factory_right(
                participant,
                subchannel,
                FactoryRightKind::Balance,
                None,
                100,
            ));
            rights.push(factory_right(
                participant,
                subchannel,
                FactoryRightKind::ReserveClaim,
                None,
                50,
            ));
            rights.push(factory_right(
                participant,
                subchannel,
                FactoryRightKind::Membership,
                None,
                1,
            ));
        }
    }
    rights
}

#[test]
fn signing_digest_is_domain_separated_and_state_sensitive() {
    let h1 = header(1, Phase::Settling);
    let mut h2 = h1.clone();
    h2.state_number = 2;

    assert_ne!(h1.signing_digest(), h2.signing_digest());
    assert_eq!(h1.signing_digest(), h1.signing_digest());
}

#[test]
fn factory_sparse_merkle_proof_accepts_single_right_update_in_large_tree() {
    let before = large_factory_rights();
    let mut after = before.clone();
    let changed = FactoryRightId {
        participant: bytes32(3),
        subchannel: bytes32(12),
        kind: FactoryRightKind::ReserveClaim,
        asset_type: None,
    };
    let changed_after = after
        .iter_mut()
        .find(|right| right.id == changed)
        .expect("changed right");
    changed_after.quantity = 35;

    let proof = FactorySingleRightMerkleUpdate {
        before_root: factory_right_sparse_root(&before).unwrap(),
        after_root: factory_right_sparse_root(&after).unwrap(),
        touched_participants: BTreeSet::from([bytes32(3)]),
        authorised_participants: BTreeSet::from([bytes32(3)]),
        before: factory_right_sparse_proof(&before, &changed).unwrap(),
        after: factory_right_sparse_proof(&after, &changed).unwrap(),
    };

    validate_factory_single_right_merkle_update(&proof).unwrap();
}

#[test]
fn factory_sparse_merkle_root_is_order_independent() {
    let rights = large_factory_rights();
    let mut reversed = rights.clone();
    reversed.reverse();

    assert_eq!(
        factory_right_sparse_root(&rights).unwrap(),
        factory_right_sparse_root(&reversed).unwrap()
    );
}

#[test]
fn factory_sparse_merkle_proof_rejects_unproved_sibling_change() {
    let before = large_factory_rights();
    let mut after = before.clone();
    let changed = FactoryRightId {
        participant: bytes32(3),
        subchannel: bytes32(12),
        kind: FactoryRightKind::ReserveClaim,
        asset_type: None,
    };
    after
        .iter_mut()
        .find(|right| right.id == changed)
        .expect("changed right")
        .quantity = 35;

    let mut proof = FactorySingleRightMerkleUpdate {
        before_root: factory_right_sparse_root(&before).unwrap(),
        after_root: factory_right_sparse_root(&after).unwrap(),
        touched_participants: BTreeSet::from([bytes32(3)]),
        authorised_participants: BTreeSet::from([bytes32(3)]),
        before: factory_right_sparse_proof(&before, &changed).unwrap(),
        after: factory_right_sparse_proof(&after, &changed).unwrap(),
    };
    proof.after.siblings[0].hash[0] ^= 1;

    let err = validate_factory_single_right_merkle_update(&proof).unwrap_err();
    assert_eq!(err, MorphError::FactoryMerkleProofInvalid);
}

#[test]
fn factory_sparse_merkle_update_requires_authorised_touched_participant() {
    let before = large_factory_rights();
    let mut after = before.clone();
    let changed = FactoryRightId {
        participant: bytes32(3),
        subchannel: bytes32(12),
        kind: FactoryRightKind::ReserveClaim,
        asset_type: None,
    };
    after
        .iter_mut()
        .find(|right| right.id == changed)
        .expect("changed right")
        .quantity = 35;

    let proof = FactorySingleRightMerkleUpdate {
        before_root: factory_right_sparse_root(&before).unwrap(),
        after_root: factory_right_sparse_root(&after).unwrap(),
        touched_participants: BTreeSet::from([bytes32(3)]),
        authorised_participants: BTreeSet::from([bytes32(4)]),
        before: factory_right_sparse_proof(&before, &changed).unwrap(),
        after: factory_right_sparse_proof(&after, &changed).unwrap(),
    };

    let err = validate_factory_single_right_merkle_update(&proof).unwrap_err();
    assert_eq!(err, MorphError::FactoryMissingAuthorisation);
}

#[test]
fn accepts_valid_state_supersession() {
    let (old, new, ctx) = signed_cells(1, Phase::Active, 2, Phase::Settling);

    validate_state_transition(&old, &new, &ctx).unwrap();
}

#[test]
fn rejects_stale_or_equal_state_number() {
    let (old, new, ctx) = signed_cells(2, Phase::Settling, 2, Phase::Settling);

    let err = validate_state_transition(&old, &new, &ctx).unwrap_err();
    assert_eq!(err, MorphError::NonMonotonicStateNumber);
}

#[test]
fn rejects_wrong_funding_anchor_reference() {
    let (old, new, mut ctx) = signed_cells(1, Phase::Active, 2, Phase::Settling);
    ctx.referenced_funding_anchor = bytes32(99);

    let err = validate_state_transition(&old, &new, &ctx).unwrap_err();
    assert_eq!(err, MorphError::FundingAnchorMismatch);
}

#[test]
fn rejects_changed_header_context() {
    let (old, mut new, ctx) = signed_cells(1, Phase::Active, 2, Phase::Settling);
    new.header.descriptor_version = 2;

    let err = validate_state_transition(&old, &new, &ctx).unwrap_err();
    assert_eq!(err, MorphError::HeaderContextChanged);
}

#[test]
fn rejects_invalid_state_signature() {
    let (old, new, mut ctx) = signed_cells(1, Phase::Active, 2, Phase::Settling);
    ctx.authorization.signatures[0].signature[0] ^= 1;

    let err = validate_state_transition(&old, &new, &ctx).unwrap_err();
    assert_eq!(err, MorphError::InvalidStateSignatures);
}

#[test]
fn partition_conservation_accepts_valid_partition() {
    let totals = validate_partition_conservation(&good_partition(), &registry()).unwrap();
    assert_eq!(totals.sponsor_in - totals.sponsor_out, 100);
}

#[test]
fn rejects_channel_paid_fee_leakage() {
    let mut tx = good_partition();
    tx.outputs[0].capacity -= 1;

    let err = validate_partition_conservation(&tx, &registry()).unwrap_err();
    assert_eq!(err, MorphError::ReserveNotConserved);
}

#[test]
fn rejects_business_ckb_confusion() {
    let mut tx = good_partition();
    tx.outputs[1].business_ckb += 1;

    let err = validate_partition_conservation(&tx, &registry()).unwrap_err();
    assert_eq!(err, MorphError::BusinessCkbNotConserved);
}

#[test]
fn rejects_xudt_type_mismatch() {
    let mut tx = good_partition();
    tx.outputs[2] = ClassifiedCell::xudt(bytes32(43), 1_000, 700, 10);

    let err = validate_partition_conservation(&tx, &registry()).unwrap_err();
    assert_eq!(err, MorphError::UnregisteredXudtType);
}

#[test]
fn rejects_xudt_amount_mismatch() {
    let mut tx = good_partition();
    tx.outputs[2].xudt_amount = 9;

    let err = validate_partition_conservation(&tx, &registry()).unwrap_err();
    assert_eq!(err, MorphError::XudtNotConserved);
}

#[test]
fn rejects_sponsor_change_contamination() {
    let mut tx = good_partition();
    tx.outputs[4].carries_registered_xudt = true;

    let err = validate_partition_conservation(&tx, &registry()).unwrap_err();
    assert_eq!(err, MorphError::SponsorChangeContaminated);
}

#[test]
fn rejects_unrelated_cell_used_for_channel_semantics() {
    let mut tx = good_partition();
    let mut helper = ClassifiedCell::unrelated(100, 50);
    helper.read_by_channel_script = true;
    tx.inputs.push(helper);

    let err = validate_partition_conservation(&tx, &registry()).unwrap_err();
    assert_eq!(err, MorphError::UnrelatedCellUsed);
}

#[test]
fn factory_non_interference_accepts_authorised_local_right_change() {
    let mut update = factory_update();
    update.after[0].quantity = 90;

    validate_factory_non_interference(&update).unwrap();
}

#[test]
fn factory_non_interference_rejects_untouched_balance_change() {
    let mut update = factory_update();
    update.after[5].quantity = 90;

    let err = validate_factory_non_interference(&update).unwrap_err();
    assert_eq!(err, MorphError::FactoryNonInterferenceViolation);
}

#[test]
fn factory_non_interference_rejects_untouched_exit_right_removal() {
    let mut update = factory_update();
    update.after.retain(|right| {
        !(right.id.participant == bytes32(2) && right.id.kind == FactoryRightKind::ExitPath)
    });

    let err = validate_factory_non_interference(&update).unwrap_err();
    assert_eq!(err, MorphError::FactoryNonInterferenceViolation);
}

#[test]
fn factory_non_interference_rejects_untouched_sponsor_right_creation() {
    let mut update = factory_update();
    update.after.push(factory_right(
        2,
        11,
        FactoryRightKind::SponsorBudgetClaim,
        None,
        10,
    ));

    let err = validate_factory_non_interference(&update).unwrap_err();
    assert_eq!(err, MorphError::FactoryNonInterferenceViolation);
}

#[test]
fn factory_non_interference_requires_touched_participant_authorisation() {
    let mut update = factory_update();
    update.authorised_participants.clear();

    let err = validate_factory_non_interference(&update).unwrap_err();
    assert_eq!(err, MorphError::FactoryMissingAuthorisation);
}

#[test]
fn factory_non_interference_rejects_duplicate_right_ids() {
    let mut update = factory_update();
    update.before.push(update.before[0].clone());

    let err = validate_factory_non_interference(&update).unwrap_err();
    assert_eq!(err, MorphError::FactoryDuplicateRight);
}

#[test]
fn reduced_factory_exit_accepts_authorised_reserve_claim_release() {
    let mut update = factory_update();
    update.after[1].quantity = 30;
    let exit = factory_reduced_exit(&update, 20);

    validate_reduced_factory_exit(&update, &exit).unwrap();
}

#[test]
fn reduced_factory_exit_accepts_full_reserve_claim_consumption() {
    let mut update = factory_update();
    let exit = factory_reduced_exit(&update, 50);
    update.after.retain(|right| right.id != exit.reserve_claim);

    validate_reduced_factory_exit(&update, &exit).unwrap();
}

#[test]
fn reduced_factory_exit_rejects_release_amount_mismatch() {
    let mut update = factory_update();
    update.after[1].quantity = 31;
    let exit = factory_reduced_exit(&update, 20);

    let err = validate_reduced_factory_exit(&update, &exit).unwrap_err();
    assert_eq!(err, MorphError::FactoryReducedExitInvalid);
}

#[test]
fn reduced_factory_exit_rejects_other_touched_right_changes() {
    let mut update = factory_update();
    update.after[0].quantity = 90;
    update.after[1].quantity = 30;
    let exit = factory_reduced_exit(&update, 20);

    let err = validate_reduced_factory_exit(&update, &exit).unwrap_err();
    assert_eq!(err, MorphError::FactoryReducedExitInterference);
}

#[test]
fn reduced_factory_exit_requires_exiting_participant_authorisation() {
    let mut update = factory_update();
    update.after[1].quantity = 30;
    update.authorised_participants.clear();
    let exit = factory_reduced_exit(&update, 20);

    let err = validate_reduced_factory_exit(&update, &exit).unwrap_err();
    assert_eq!(err, MorphError::FactoryMissingAuthorisation);
}

#[test]
fn reduced_factory_exit_rejects_extra_authorised_participant() {
    let mut update = factory_update();
    update.after[1].quantity = 30;
    update.authorised_participants.insert(bytes32(2));
    let exit = factory_reduced_exit(&update, 20);

    let err = validate_reduced_factory_exit(&update, &exit).unwrap_err();
    assert_eq!(err, MorphError::FactoryMissingAuthorisation);
}

#[test]
fn sponsor_policy_accepts_bounded_publication_fee() {
    let policy = SponsorPolicy {
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
    let spend = SponsorSpend {
        channel_id: bytes32(2),
        state_number: 2,
        fee: 150,
        now: 900,
        sponsor_source: bytes32(10),
        change_lock: bytes32(11),
        operation: ChannelOperation::Publish,
    };

    validate_sponsor_policy(&policy, &spend).unwrap();
}

#[test]
fn sponsor_policy_rejects_drain_attempt() {
    let policy = SponsorPolicy {
        channel_id: bytes32(2),
        min_state_number: 1,
        max_state_number: 10,
        max_fee_per_tx: 200,
        max_total_fee: 1_000,
        already_spent: 950,
        expiry: 1_000,
        allowed_sponsor_source: bytes32(10),
        change_lock: bytes32(11),
    };
    let spend = SponsorSpend {
        channel_id: bytes32(2),
        state_number: 2,
        fee: 100,
        now: 900,
        sponsor_source: bytes32(10),
        change_lock: bytes32(11),
        operation: ChannelOperation::Publish,
    };

    let err = validate_sponsor_policy(&policy, &spend).unwrap_err();
    assert_eq!(err, MorphError::SponsorBudgetExceeded);
}

#[test]
fn vault_spend_accepts_finalise_after_since() {
    let spend = VaultSpend {
        operation: ChannelOperation::Finalise,
        state_cell: state(2, Phase::Settling),
        signatures_or_phase_authorised: true,
        since_satisfied: true,
        expected_funding_anchor: bytes32(3),
        descriptor_outputs_match: true,
        asset_registry: registry(),
        partition: good_partition(),
    };

    validate_vault_spend(&spend).unwrap();
}

#[test]
fn vault_spend_rejects_unmatured_finalise() {
    let spend = VaultSpend {
        operation: ChannelOperation::Finalise,
        state_cell: state(2, Phase::Settling),
        signatures_or_phase_authorised: true,
        since_satisfied: false,
        expected_funding_anchor: bytes32(3),
        descriptor_outputs_match: true,
        asset_registry: registry(),
        partition: good_partition(),
    };

    let err = validate_vault_spend(&spend).unwrap_err();
    assert_eq!(err, MorphError::SinceNotSatisfied);
}
