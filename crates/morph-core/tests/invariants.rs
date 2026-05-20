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

fn header_v2(n: u64, phase: Phase, funding_epoch: u64) -> StateHeaderV2 {
    StateHeaderV2 {
        protocol_version: 1,
        chain_id: bytes32(1),
        signature_scheme_id: 1,
        channel_id: bytes32(2),
        funding_epoch,
        funding_anchor: bytes32(3),
        vault_set_commitment: bytes32(33),
        state_number: n,
        mode: Mode::BilateralPlain,
        phase,
        participants_commitment: bytes32(4),
        asset_registry_commitment: bytes32(5),
        settlement_descriptor_commitment: bytes32(6),
        descriptor_version: 1,
        payload_commitment: bytes32(7),
        challenge_policy_commitment: bytes32(8),
        state_layout_version: 2,
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

fn splice_witness_for(header: &mut SpliceHeader) -> SpliceWitness {
    let key0 = signing_key(1);
    let key1 = signing_key(2);
    let mut entries = [(pubkey(&key0), key0), (pubkey(&key1), key1)];
    entries.sort_by(|left, right| left.0.cmp(&right.0));

    let pubkeys = [entries[0].0.as_slice(), entries[1].0.as_slice()];
    header.participants_commitment = participants_commitment(2, &pubkeys);
    let digest = header.signing_digest();
    SpliceWitness {
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

fn factory_splice_witness_for(header: &mut FactorySpliceHeader) -> SpliceWitness {
    let key0 = signing_key(1);
    let key1 = signing_key(2);
    let mut entries = [(pubkey(&key0), key0), (pubkey(&key1), key1)];
    entries.sort_by(|left, right| left.0.cmp(&right.0));

    let pubkeys = [entries[0].0.as_slice(), entries[1].0.as_slice()];
    header.participants_commitment = participants_commitment(2, &pubkeys);
    let digest = header.signing_digest();
    SpliceWitness {
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

fn factory_reduced_splice_witness_for(
    header: &mut FactorySpliceHeader,
) -> FactoryReducedSpliceWitness {
    let key0 = signing_key(1);
    let key1 = signing_key(2);
    let mut entries = [
        (bytes32(1), pubkey(&key0), key0),
        (bytes32(2), pubkey(&key1), key1),
    ];
    entries.sort_by(|left, right| left.0.cmp(&right.0));

    let pubkeys = [entries[0].1.as_slice(), entries[1].1.as_slice()];
    header.participants_commitment = participants_commitment(2, &pubkeys);
    let digest = header.signing_digest();
    FactoryReducedSpliceWitness {
        participant_threshold: 2,
        participant_keys: entries
            .iter()
            .map(|(participant, pubkey, _)| FactoryParticipantKey {
                participant: *participant,
                pubkey_sec1: pubkey.clone(),
            })
            .collect(),
        signatures: vec![FactoryParticipantSignature {
            participant: bytes32(1),
            pubkey_sec1: entries[0].1.clone(),
            signature: signature(&entries[0].2, &digest),
        }],
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

fn vault_descriptor(
    funding_anchor: Bytes32,
    ckb: Amount,
    xudt: Option<Amount>,
) -> VaultDescriptorV2 {
    let mut assets = vec![VaultAssetAmount {
        asset: VaultAsset::Ckb,
        amount: ckb,
    }];
    if let Some(amount) = xudt {
        assets.push(VaultAssetAmount {
            asset: VaultAsset::Xudt(bytes32(42)),
            amount,
        });
    }
    VaultDescriptorV2 {
        funding_anchor,
        assets,
    }
}

fn splice_transition(kind: SpliceKind) -> SpliceTransition {
    let mut current_state = state(5, Phase::Active);
    let (old_vault, new_vault, deltas, withdrawals, remaining_settlement) = match kind {
        SpliceKind::In => {
            let old_vault = vault_descriptor(bytes32(3), 10_000, Some(50));
            let new_vault = vault_descriptor(bytes32(33), 14_900, Some(60));
            (
                old_vault,
                new_vault,
                vec![
                    SpliceAssetDelta {
                        asset: VaultAsset::Ckb,
                        old_amount: 10_000,
                        new_amount: 14_900,
                        external_input: 5_000,
                        withdrawal: 0,
                        signed_fee: 100,
                    },
                    SpliceAssetDelta {
                        asset: VaultAsset::Xudt(bytes32(42)),
                        old_amount: 50,
                        new_amount: 60,
                        external_input: 10,
                        withdrawal: 0,
                        signed_fee: 0,
                    },
                ],
                Vec::new(),
                vec![
                    VaultAssetAmount {
                        asset: VaultAsset::Ckb,
                        amount: 12_000,
                    },
                    VaultAssetAmount {
                        asset: VaultAsset::Xudt(bytes32(42)),
                        amount: 60,
                    },
                ],
            )
        }
        SpliceKind::Out => {
            let old_vault = vault_descriptor(bytes32(3), 10_000, None);
            let new_vault = vault_descriptor(bytes32(33), 7_000, None);
            (
                old_vault,
                new_vault,
                vec![SpliceAssetDelta {
                    asset: VaultAsset::Ckb,
                    old_amount: 10_000,
                    new_amount: 7_000,
                    external_input: 0,
                    withdrawal: 3_000,
                    signed_fee: 0,
                }],
                vec![VaultAssetAmount {
                    asset: VaultAsset::Ckb,
                    amount: 3_000,
                }],
                vec![VaultAssetAmount {
                    asset: VaultAsset::Ckb,
                    amount: 6_500,
                }],
            )
        }
    };
    let mut header = SpliceHeader {
        protocol_version: 1,
        chain_id: current_state.header.chain_id,
        signature_scheme_id: current_state.header.signature_scheme_id,
        channel_id: current_state.header.channel_id,
        old_funding_anchor: current_state.header.funding_anchor,
        new_funding_anchor: bytes32(33),
        old_funding_epoch: 0,
        new_funding_epoch: 1,
        base_state_number: current_state.header.state_number,
        splice_number: 1,
        kind,
        old_vault_commitment: vault_descriptor_commitment_v2(&old_vault),
        new_vault_commitment: vault_descriptor_commitment_v2(&new_vault),
        asset_delta_commitment: splice_asset_delta_commitment_v1(&deltas),
        participants_commitment: current_state.header.participants_commitment,
        challenge_policy_commitment: current_state.header.challenge_policy_commitment,
    };
    let witness = splice_witness_for(&mut header);
    current_state.header.participants_commitment = header.participants_commitment;
    SpliceTransition {
        current_state,
        header,
        witness,
        old_vault,
        new_vault,
        deltas,
        withdrawals,
        remaining_settlement,
        asset_registry: registry(),
    }
}

fn xudt_splice_out_transition() -> SpliceTransition {
    let mut splice = splice_transition(SpliceKind::Out);
    splice.old_vault = vault_descriptor(bytes32(3), 10_000, Some(100));
    splice.new_vault = vault_descriptor(bytes32(33), 10_000, Some(70));
    splice.deltas = vec![SpliceAssetDelta {
        asset: VaultAsset::Xudt(bytes32(42)),
        old_amount: 100,
        new_amount: 70,
        external_input: 0,
        withdrawal: 30,
        signed_fee: 0,
    }];
    splice.withdrawals = vec![VaultAssetAmount {
        asset: VaultAsset::Xudt(bytes32(42)),
        amount: 30,
    }];
    splice.remaining_settlement = vec![
        VaultAssetAmount {
            asset: VaultAsset::Ckb,
            amount: 8_000,
        },
        VaultAssetAmount {
            asset: VaultAsset::Xudt(bytes32(42)),
            amount: 70,
        },
    ];
    splice.header.old_vault_commitment = vault_descriptor_commitment_v2(&splice.old_vault);
    splice.header.new_vault_commitment = vault_descriptor_commitment_v2(&splice.new_vault);
    splice.header.asset_delta_commitment = splice_asset_delta_commitment_v1(&splice.deltas);
    splice.witness = splice_witness_for(&mut splice.header);
    splice
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

fn factory_splice_transition(
    kind: FactorySpliceKind,
    asset: VaultAsset,
) -> FactorySpliceTransition {
    let participant = bytes32(1);
    let subchannel = bytes32(10);
    let asset_type = match asset {
        VaultAsset::Ckb => None,
        VaultAsset::Xudt(type_hash) => Some(type_hash),
    };
    let mut before = vec![
        factory_right(1, 10, FactoryRightKind::Balance, None, 100),
        factory_right(1, 10, FactoryRightKind::ReserveClaim, None, 50),
        factory_right(1, 10, FactoryRightKind::Membership, None, 1),
        factory_right(2, 10, FactoryRightKind::Balance, None, 100),
        factory_right(2, 10, FactoryRightKind::ReserveClaim, None, 50),
    ];
    if asset_type.is_some() {
        before[1].id.asset_type = asset_type;
    }
    let mut after = before.clone();
    let claim = after
        .iter_mut()
        .find(|right| {
            right.id.participant == participant
                && right.id.subchannel == subchannel
                && right.id.kind == FactoryRightKind::ReserveClaim
                && right.id.asset_type == asset_type
        })
        .expect("reserve claim");

    let (old_amount, new_amount, external_input, withdrawal) = match kind {
        FactorySpliceKind::In => {
            claim.quantity += 20;
            (50, 70, 20, 0)
        }
        FactorySpliceKind::Out => {
            claim.quantity -= 20;
            (50, 30, 0, 20)
        }
    };
    let update = FactoryUpdate {
        before,
        after,
        touched_participants: BTreeSet::from([participant]),
        authorised_participants: BTreeSet::from([participant]),
    };
    let old_vault = FactoryVaultDescriptorV1 {
        factory_id: bytes32(90),
        assets: vec![VaultAssetAmount {
            asset: asset.clone(),
            amount: old_amount,
        }],
    };
    let new_vault = FactoryVaultDescriptorV1 {
        factory_id: bytes32(90),
        assets: vec![VaultAssetAmount {
            asset: asset.clone(),
            amount: new_amount,
        }],
    };
    let deltas = vec![FactoryVaultDelta {
        asset,
        old_amount,
        new_amount,
        external_input,
        withdrawal,
    }];
    let mut header = FactorySpliceHeader {
        protocol_version: 1,
        factory_id: bytes32(90),
        old_update_number: 1,
        new_update_number: 2,
        old_state_root: factory_right_sparse_root(&update.before).unwrap(),
        new_state_root: factory_right_sparse_root(&update.after).unwrap(),
        old_access_manifest_root: bytes32(91),
        new_access_manifest_root: bytes32(92),
        kind,
        vault_delta_commitment: factory_vault_delta_commitment_v1(&deltas),
        non_interference_digest: blake2b256(b"factory splice fixture"),
        participants_commitment: bytes32(0),
    };
    let witness = factory_splice_witness_for(&mut header);
    FactorySpliceTransition {
        header,
        witness,
        update,
        old_vault,
        new_vault,
        deltas,
        asset_registry: registry(),
    }
}

fn factory_reduced_splice_transition(
    kind: FactorySpliceKind,
    asset: VaultAsset,
) -> FactoryReducedSpliceTransition {
    let full = factory_splice_transition(kind, asset);
    let changed_id = full.update.before[1].id.clone();
    let update = FactorySingleRightMerkleUpdate {
        before_root: full.header.old_state_root,
        after_root: full.header.new_state_root,
        touched_participants: full.update.touched_participants.clone(),
        authorised_participants: full.update.authorised_participants.clone(),
        before: factory_right_sparse_proof(&full.update.before, &changed_id).unwrap(),
        after: factory_right_sparse_proof(&full.update.after, &changed_id).unwrap(),
    };
    let mut header = full.header.clone();
    let witness = factory_reduced_splice_witness_for(&mut header);
    FactoryReducedSpliceTransition {
        header,
        witness,
        update,
        old_vault: full.old_vault,
        new_vault: full.new_vault,
        deltas: full.deltas,
        asset_registry: full.asset_registry,
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
fn state_header_v2_digest_binds_epoch_and_vault_set() {
    let h1 = header_v2(1, Phase::Settling, 3);
    let mut h2 = h1.clone();
    h2.funding_epoch = 4;

    let mut h3 = h1.clone();
    h3.vault_set_commitment = bytes32(34);

    assert_ne!(h1.signing_digest(), h2.signing_digest());
    assert_ne!(h1.signing_digest(), h3.signing_digest());
    assert_ne!(
        h1.signing_digest(),
        header(1, Phase::Settling).signing_digest()
    );
}

#[test]
fn state_header_v2_context_rejects_epoch_and_vault_set_changes() {
    let old = header_v2(1, Phase::Active, 3);
    let mut new = header_v2(9, Phase::Settling, 3);
    new.payload_commitment = bytes32(9);
    new.settlement_descriptor_commitment = bytes32(10);

    assert!(old.same_context_except_progress(&new));

    new.funding_epoch = 4;
    assert!(!old.same_context_except_progress(&new));

    let mut changed_vault_set = header_v2(9, Phase::Settling, 3);
    changed_vault_set.vault_set_commitment = bytes32(34);
    assert!(!old.same_context_except_progress(&changed_vault_set));
}

#[test]
fn splice_signing_digest_is_state_and_vault_sensitive() {
    let splice = splice_transition(SpliceKind::In);
    let mut changed = splice.header.clone();
    changed.new_funding_epoch += 1;

    assert_ne!(splice.header.signing_digest(), changed.signing_digest());
    assert_ne!(
        splice.header.old_vault_commitment,
        splice.header.new_vault_commitment
    );
}

#[test]
fn accepts_valid_splice_in_transition() {
    let splice = splice_transition(SpliceKind::In);

    validate_splice_transition(&splice).unwrap();
}

#[test]
fn accepts_valid_splice_out_transition() {
    let splice = splice_transition(SpliceKind::Out);

    validate_splice_transition(&splice).unwrap();
}

#[test]
fn accepts_valid_xudt_splice_out_transition() {
    let splice = xudt_splice_out_transition();

    validate_splice_transition(&splice).unwrap();
}

#[test]
fn splice_rejects_stale_base_state_number() {
    let mut splice = splice_transition(SpliceKind::In);
    splice.header.base_state_number -= 1;
    let witness = splice_witness_for(&mut splice.header);
    splice.witness = witness;

    let err = validate_splice_transition(&splice).unwrap_err();
    assert_eq!(err, MorphError::SpliceBaseStateMismatch);
}

#[test]
fn splice_rejects_wrong_channel_header() {
    let mut splice = splice_transition(SpliceKind::In);
    splice.header.channel_id = bytes32(99);
    let witness = splice_witness_for(&mut splice.header);
    splice.witness = witness;

    let err = validate_splice_transition(&splice).unwrap_err();
    assert_eq!(err, MorphError::SpliceHeaderContextMismatch);
}

#[test]
fn splice_rejects_tampered_asset_delta_commitment() {
    let mut splice = splice_transition(SpliceKind::In);
    splice.deltas[0].new_amount -= 1;

    let err = validate_splice_transition(&splice).unwrap_err();
    assert_eq!(err, MorphError::SpliceDeltaCommitmentMismatch);
}

#[test]
fn splice_rejects_same_supply_wrong_xudt_recipient_amount() {
    let mut splice = splice_transition(SpliceKind::In);
    splice.deltas[1].new_amount = 59;
    splice.header.asset_delta_commitment = splice_asset_delta_commitment_v1(&splice.deltas);
    let witness = splice_witness_for(&mut splice.header);
    splice.witness = witness;

    let err = validate_splice_transition(&splice).unwrap_err();
    assert_eq!(err, MorphError::SpliceVaultDeltaMismatch);
}

#[test]
fn splice_rejects_unsigned_withdrawal_output_change() {
    let mut splice = splice_transition(SpliceKind::Out);
    splice.withdrawals[0].amount = 2_999;

    let err = validate_splice_transition(&splice).unwrap_err();
    assert_eq!(err, MorphError::SpliceWithdrawalMismatch);
}

#[test]
fn splice_rejects_remaining_settlement_shortfall() {
    let mut splice = splice_transition(SpliceKind::Out);
    splice.remaining_settlement[0].amount = 7_001;

    let err = validate_splice_transition(&splice).unwrap_err();
    assert_eq!(err, MorphError::SpliceRemainingValueInsufficient);
}

#[test]
fn splice_rejects_unregistered_xudt_asset() {
    let mut splice = splice_transition(SpliceKind::In);
    splice.asset_registry.xudt_types.clear();

    let err = validate_splice_transition(&splice).unwrap_err();
    assert_eq!(err, MorphError::UnregisteredXudtType);
}

#[test]
fn splice_rejects_invalid_signature() {
    let mut splice = splice_transition(SpliceKind::In);
    splice.witness.signatures[0].signature[0] ^= 1;

    let err = validate_splice_transition(&splice).unwrap_err();
    assert_eq!(err, MorphError::InvalidSpliceSignatures);
}

#[test]
fn accepts_valid_factory_splice_in_transition() {
    let splice = factory_splice_transition(FactorySpliceKind::In, VaultAsset::Ckb);

    validate_factory_splice_transition(&splice).unwrap();
}

#[test]
fn accepts_valid_factory_xudt_splice_out_transition() {
    let splice = factory_splice_transition(FactorySpliceKind::Out, VaultAsset::Xudt(bytes32(42)));

    validate_factory_splice_transition(&splice).unwrap();
}

#[test]
fn factory_splice_rejects_reserve_claim_without_vault_input() {
    let mut splice = factory_splice_transition(FactorySpliceKind::In, VaultAsset::Ckb);
    splice.deltas[0].external_input = 19;
    splice.deltas[0].new_amount = 69;
    splice.header.vault_delta_commitment = factory_vault_delta_commitment_v1(&splice.deltas);
    splice.witness = factory_splice_witness_for(&mut splice.header);

    let err = validate_factory_splice_transition(&splice).unwrap_err();
    assert_eq!(err, MorphError::FactorySpliceVaultDeltaMismatch);
}

#[test]
fn factory_splice_rejects_vault_release_without_rights_decrease() {
    let mut splice = factory_splice_transition(FactorySpliceKind::Out, VaultAsset::Ckb);
    splice.update.after[1].quantity = splice.update.before[1].quantity;

    let err = validate_factory_splice_transition(&splice).unwrap_err();
    assert_eq!(err, MorphError::FactorySpliceReserveClaimInvalid);
}

#[test]
fn factory_splice_rejects_xudt_type_mismatch() {
    let mut splice =
        factory_splice_transition(FactorySpliceKind::In, VaultAsset::Xudt(bytes32(42)));
    splice.deltas[0].asset = VaultAsset::Xudt(bytes32(43));
    splice.header.vault_delta_commitment = factory_vault_delta_commitment_v1(&splice.deltas);
    splice.witness = factory_splice_witness_for(&mut splice.header);

    let err = validate_factory_splice_transition(&splice).unwrap_err();
    assert_eq!(err, MorphError::UnregisteredXudtType);
}

#[test]
fn factory_splice_rejects_invalid_signature() {
    let mut splice = factory_splice_transition(FactorySpliceKind::In, VaultAsset::Ckb);
    splice.witness.signatures[0].signature[0] ^= 1;

    let err = validate_factory_splice_transition(&splice).unwrap_err();
    assert_eq!(err, MorphError::InvalidFactorySpliceSignatures);
}

#[test]
fn accepts_valid_reduced_factory_splice_transition() {
    let splice = factory_reduced_splice_transition(FactorySpliceKind::In, VaultAsset::Ckb);

    validate_factory_reduced_splice_transition(&splice).unwrap();
}

#[test]
fn reduced_factory_splice_rejects_merkle_sibling_tamper() {
    let mut splice = factory_reduced_splice_transition(FactorySpliceKind::In, VaultAsset::Ckb);
    splice.update.before.siblings[0].hash[0] ^= 1;

    let err = validate_factory_reduced_splice_transition(&splice).unwrap_err();
    assert_eq!(err, MorphError::FactoryMerkleProofInvalid);
}

#[test]
fn reduced_factory_splice_rejects_unsigned_participant() {
    let mut splice = factory_reduced_splice_transition(FactorySpliceKind::In, VaultAsset::Ckb);
    splice.witness.signatures[0].participant = bytes32(2);

    let err = validate_factory_reduced_splice_transition(&splice).unwrap_err();
    assert_eq!(err, MorphError::FactorySpliceParticipantSetMismatch);
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
fn factory_sparse_merkle_update_rejects_value_right_increase() {
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
        .quantity = 251;

    let proof = FactorySingleRightMerkleUpdate {
        before_root: factory_right_sparse_root(&before).unwrap(),
        after_root: factory_right_sparse_root(&after).unwrap(),
        touched_participants: BTreeSet::from([bytes32(3)]),
        authorised_participants: BTreeSet::from([bytes32(3)]),
        before: factory_right_sparse_proof(&before, &changed).unwrap(),
        after: factory_right_sparse_proof(&after, &changed).unwrap(),
    };

    let err = validate_factory_single_right_merkle_update(&proof).unwrap_err();
    assert_eq!(err, MorphError::FactoryMerkleProofInvalid);
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
fn accepts_signed_settlement_descriptor_update() {
    let (old, mut new, mut ctx) = signed_cells(1, Phase::Active, 2, Phase::Settling);
    new.header.settlement_descriptor_commitment = bytes32(77);
    new.header.descriptor_version = 2;
    ctx.authorization = authorization_for(&mut new.header);

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
    new.header.challenge_policy_commitment = bytes32(99);

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
