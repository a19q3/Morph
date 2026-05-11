use std::collections::BTreeSet;

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

fn transition_context() -> StateTransitionContext {
    StateTransitionContext {
        referenced_funding_anchor: bytes32(3),
        signatures_valid: true,
        asset_registry: registry(),
        partition: good_partition(),
    }
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
fn accepts_valid_state_supersession() {
    let old = state(1, Phase::Active);
    let new = state(2, Phase::Settling);

    validate_state_transition(&old, &new, &transition_context()).unwrap();
}

#[test]
fn rejects_stale_or_equal_state_number() {
    let old = state(2, Phase::Settling);
    let new = state(2, Phase::Settling);

    let err = validate_state_transition(&old, &new, &transition_context()).unwrap_err();
    assert_eq!(err, MorphError::NonMonotonicStateNumber);
}

#[test]
fn rejects_wrong_funding_anchor_reference() {
    let old = state(1, Phase::Active);
    let new = state(2, Phase::Settling);
    let mut ctx = transition_context();
    ctx.referenced_funding_anchor = bytes32(99);

    let err = validate_state_transition(&old, &new, &ctx).unwrap_err();
    assert_eq!(err, MorphError::FundingAnchorMismatch);
}

#[test]
fn rejects_changed_header_context() {
    let old = state(1, Phase::Active);
    let mut new = state(2, Phase::Settling);
    new.header.descriptor_version = 2;

    let err = validate_state_transition(&old, &new, &transition_context()).unwrap_err();
    assert_eq!(err, MorphError::HeaderContextChanged);
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
