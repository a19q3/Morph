use std::collections::{BTreeMap, BTreeSet};

use k256::ecdsa::signature::hazmat::PrehashVerifier;
use k256::ecdsa::{Signature, VerifyingKey};
use morph_script_common::{
    BILATERAL_CKB_DESCRIPTOR_VERSION, BILATERAL_CKB_XUDT_DESCRIPTOR_VERSION,
    BILATERAL_SIGNATURE_COUNT, BILATERAL_SIGNATURE_THRESHOLD, COMPRESSED_SECP256K1_PUBKEY_LEN,
    FACTORY_REDUCED_RIGHTS_PARTICIPANT_COUNT, FACTORY_REDUCED_RIGHTS_PARTICIPANT_THRESHOLD,
    FACTORY_SIGNATURE_COUNT, FACTORY_SIGNATURE_THRESHOLD, MORPH_PROTOCOL_VERSION,
    SIGNATURE_SCHEME_SECP256K1_ECDSA_BLAKE2B, SPLICE_SIGNATURE_COUNT, SPLICE_SIGNATURE_THRESHOLD,
    STATE_CARRIER_ACTIVATION_FEE, STATE_LAYOUT_VERSION,
};
use thiserror::Error;

use crate::hash::{
    asset_registry_commitment, blake2b256, factory_vault_delta_commitment, participants_commitment,
    splice_asset_delta_commitment, vault_descriptor_commitment,
};
use crate::types::*;

const FACTORY_RIGHT_KEY_DOMAIN: &[u8] = b"CKB_MORPH_FACTORY_RIGHT_KEY";
const FACTORY_RIGHT_LEAF_DOMAIN: &[u8] = b"CKB_MORPH_FACTORY_RIGHT_LEAF";
const FACTORY_RIGHT_NODE_DOMAIN: &[u8] = b"CKB_MORPH_FACTORY_RIGHT_NODE";
const FACTORY_RIGHT_EMPTY_DOMAIN: &[u8] = b"CKB_MORPH_FACTORY_RIGHT_EMPTY";
const FACTORY_SPARSE_MERKLE_DEPTH: usize = 256;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum MorphError {
    #[error("state transition must consume and recreate capacity-sufficient State Cells")]
    StateCapacityInsufficient,
    #[error("new state must have a strictly larger state number")]
    NonMonotonicStateNumber,
    #[error("new on-chain state must be in settling phase")]
    NewStateNotSettling,
    #[error("state header context changed across transition")]
    HeaderContextChanged,
    #[error("participant signatures over canonical header are invalid")]
    InvalidStateSignatures,
    #[error("state signature scheme is unsupported")]
    UnsupportedSignatureScheme,
    #[error("state uses an unsupported protocol, layout, mode, or descriptor profile")]
    UnsupportedProtocolProfile,
    #[error("participant set does not match signed state header")]
    ParticipantSetMismatch,
    #[error("participant signature encoding is invalid")]
    ParticipantSignatureEncoding,
    #[error("referenced funding anchor does not match signed state header")]
    FundingAnchorMismatch,
    #[error("asset registry does not match the signed state header")]
    AssetRegistryCommitmentMismatch,
    #[error("output capacity is below occupied capacity")]
    OutputBelowOccupiedCapacity,
    #[error("classified cell fields are inconsistent with its declared class")]
    InvalidCellClassification,
    #[error("unrelated cell participates in channel semantics")]
    UnrelatedCellUsed,
    #[error("channel reserve is not conserved")]
    ReserveNotConserved,
    #[error("business CKB is not conserved")]
    BusinessCkbNotConserved,
    #[error("xUDT asset type is not registered")]
    UnregisteredXudtType,
    #[error("xUDT amount is not conserved for registered type")]
    XudtNotConserved,
    #[error("State Cell carrier capacity is not conserved")]
    StateCarrierNotConserved,
    #[error("sponsor partition does not exactly pay the transaction fee")]
    SponsorFeeMismatch,
    #[error("sponsor output carries channel business asset or vault lock")]
    SponsorChangeContaminated,
    #[error("sponsor policy channel mismatch")]
    SponsorChannelMismatch,
    #[error("sponsor policy state number outside authorised range")]
    SponsorStateOutOfRange,
    #[error("sponsor policy contains a script-unsupported field value")]
    SponsorPolicyUnsupported,
    #[error("sponsor publication state type hash mismatch")]
    SponsorStateTypeMismatch,
    #[error("sponsor change lock mismatch")]
    SponsorChangeLockMismatch,
    #[error("sponsor fee exceeds per-transaction limit")]
    SponsorFeeTooHigh,
    #[error("sponsor total budget exceeded")]
    SponsorBudgetExceeded,
    #[error("sponsor policy may only pay publication or supersede transactions")]
    SponsorOperationNotAllowed,
    #[error("vault operation is not allowed")]
    VaultOperationNotAllowed,
    #[error("vault exact OutPoint binding is missing or invalid")]
    VaultOutPointBindingInvalid,
    #[error("vault state is not in settling phase")]
    VaultStateNotSettling,
    #[error("vault spend lacks current-state or phase authorisation")]
    VaultAuthorisationMissing,
    #[error("vault finalisation since guard has not matured")]
    SinceNotSatisfied,
    #[error("vault funding anchor mismatch")]
    VaultFundingAnchorMismatch,
    #[error("settlement descriptor did not match outputs")]
    DescriptorOutputMismatch,
    #[error("factory update has duplicate right identifiers")]
    FactoryDuplicateRight,
    #[error("factory update touches a participant without authorisation")]
    FactoryMissingAuthorisation,
    #[error("factory update changes a right outside the declared touched set")]
    FactoryNonInterferenceViolation,
    #[error("reduced factory exit claim is invalid")]
    FactoryReducedExitInvalid,
    #[error("reduced factory exit changes rights outside the consumed reserve claim")]
    FactoryReducedExitInterference,
    #[error("factory Merkle proof is invalid")]
    FactoryMerkleProofInvalid,
    #[error("factory Merkle proof changes data outside the proved right")]
    FactoryMerkleProofInterference,
    #[error("splice must be based on an active current state")]
    SpliceStateNotActive,
    #[error("splice header does not match the current channel context")]
    SpliceHeaderContextMismatch,
    #[error("splice base state number does not match the current state")]
    SpliceBaseStateMismatch,
    #[error("post-splice state does not match the splice successor context")]
    SpliceNextStateMismatch,
    #[error("post-splice State Cell carrier capacity does not match the chain rule")]
    SpliceCarrierCapacityMismatch,
    #[error("splice funding epoch must advance")]
    SpliceEpochNotAdvanced,
    #[error("splice vault commitment mismatch")]
    SpliceVaultCommitmentMismatch,
    #[error("splice asset delta commitment mismatch")]
    SpliceDeltaCommitmentMismatch,
    #[error("splice participant signatures are invalid")]
    InvalidSpliceSignatures,
    #[error("splice signature scheme is unsupported")]
    SpliceUnsupportedSignatureScheme,
    #[error("splice participant set does not match the header")]
    SpliceParticipantSetMismatch,
    #[error("splice asset delta is invalid")]
    SpliceAssetDeltaInvalid,
    #[error("splice vault descriptor does not match the signed asset deltas")]
    SpliceVaultDeltaMismatch,
    #[error("splice withdrawal descriptor does not match the signed deltas")]
    SpliceWithdrawalMismatch,
    #[error("post-splice vault does not cover the latest settlement descriptor")]
    SpliceRemainingValueInsufficient,
    #[error("factory splice update number must advance")]
    FactorySpliceUpdateNotAdvanced,
    #[error("factory splice header does not match the factory update")]
    FactorySpliceHeaderMismatch,
    #[error("factory splice signature scheme is unsupported")]
    FactorySpliceUnsupportedSignatureScheme,
    #[error("factory splice participant signatures are invalid")]
    InvalidFactorySpliceSignatures,
    #[error("factory splice participant set does not match the header")]
    FactorySpliceParticipantSetMismatch,
    #[error("factory splice vault delta commitment mismatch")]
    FactorySpliceDeltaCommitmentMismatch,
    #[error("factory splice reserve claim delta is invalid")]
    FactorySpliceReserveClaimInvalid,
    #[error("factory splice vault delta does not match reserve claim delta")]
    FactorySpliceVaultDeltaMismatch,
    #[error("factory splice asset delta is invalid")]
    FactorySpliceAssetDeltaInvalid,
}

pub type Result<T> = std::result::Result<T, MorphError>;

pub fn validate_state_transition(
    old: &StateCell,
    new: &StateCell,
    ctx: &StateTransitionContext,
) -> Result<()> {
    validate_state_profile(&old.header)?;
    validate_state_profile(&new.header)?;
    if !old.capacity_sufficient() || !new.capacity_sufficient() {
        return Err(MorphError::StateCapacityInsufficient);
    }
    if !matches!(old.header.phase, Phase::Active | Phase::Settling) {
        return Err(MorphError::HeaderContextChanged);
    }
    if new.header.state_number <= old.header.state_number {
        return Err(MorphError::NonMonotonicStateNumber);
    }
    if new.header.phase != Phase::Settling {
        return Err(MorphError::NewStateNotSettling);
    }
    if old.header.vault_outpoint_commitment == [0; 32]
        || new.header.vault_outpoint_commitment == [0; 32]
    {
        return Err(MorphError::VaultOutPointBindingInvalid);
    }
    require_same_header_context(&old.header, &new.header)?;
    validate_asset_registry_binding(&old.header, &ctx.asset_registry)?;
    validate_asset_registry_binding(&new.header, &ctx.asset_registry)?;
    validate_state_authorization(&new.header, &ctx.authorization)?;
    if ctx.referenced_funding_anchor != new.header.funding_anchor {
        return Err(MorphError::FundingAnchorMismatch);
    }
    let totals = validate_partition_conservation(&ctx.partition, &ctx.asset_registry)?;
    // Carrier capacity is not part of the signed StateHeader. Bind the
    // transaction model to these exact cells and mirror the State type's
    // ordinary-supersession rule that the carrier is recreated unchanged.
    if old.capacity != new.capacity
        || old.occupied_capacity != new.occupied_capacity
        || totals.state_carrier_in != old.capacity
        || totals.state_carrier_out != new.capacity
    {
        return Err(MorphError::StateCarrierNotConserved);
    }
    Ok(())
}

pub fn validate_state_authorization(
    header: &StateHeader,
    authorization: &StateAuthorization,
) -> Result<()> {
    validate_state_profile(header)?;
    if header.signature_scheme_id != SIGNATURE_SCHEME_SECP256K1_ECDSA_BLAKE2B {
        return Err(MorphError::UnsupportedSignatureScheme);
    }
    if authorization.threshold != BILATERAL_SIGNATURE_THRESHOLD
        || authorization.signatures.len() != BILATERAL_SIGNATURE_COUNT as usize
        || authorization
            .signatures
            .iter()
            .any(|signature| signature.pubkey_sec1.len() != COMPRESSED_SECP256K1_PUBKEY_LEN)
    {
        return Err(MorphError::ParticipantSetMismatch);
    }

    let pubkeys: Vec<&[u8]> = authorization
        .signatures
        .iter()
        .map(|signature| signature.pubkey_sec1.as_slice())
        .collect();
    if !pubkeys.windows(2).all(|window| window[0] < window[1]) {
        return Err(MorphError::ParticipantSetMismatch);
    }
    if participants_commitment(authorization.threshold, &pubkeys) != header.participants_commitment
    {
        return Err(MorphError::ParticipantSetMismatch);
    }

    let digest = header.signing_digest();
    let mut valid = 0usize;
    for participant_signature in &authorization.signatures {
        let verifying_key = VerifyingKey::from_sec1_bytes(&participant_signature.pubkey_sec1)
            .map_err(|_| MorphError::ParticipantSignatureEncoding)?;
        let signature = Signature::try_from(participant_signature.signature.as_slice())
            .map_err(|_| MorphError::ParticipantSignatureEncoding)?;
        verifying_key
            .verify_prehash(&digest, &signature)
            .map_err(|_| MorphError::InvalidStateSignatures)?;
        valid += 1;
    }
    if valid < authorization.threshold as usize {
        return Err(MorphError::InvalidStateSignatures);
    }
    Ok(())
}

pub fn validate_splice_transition(splice: &SpliceTransition) -> Result<()> {
    let current = &splice.current_state.header;
    validate_state_profile(current)?;
    validate_state_profile(&splice.next_state.header)?;
    if !splice.current_state.capacity_sufficient() {
        return Err(MorphError::StateCapacityInsufficient);
    }
    if !splice.next_state.capacity_sufficient() {
        return Err(MorphError::StateCapacityInsufficient);
    }
    if splice
        .current_state
        .capacity
        .checked_add(STATE_CARRIER_ACTIVATION_FEE)
        != Some(splice.next_state.capacity)
        || splice.current_state.occupied_capacity != splice.next_state.occupied_capacity
    {
        return Err(MorphError::SpliceCarrierCapacityMismatch);
    }
    if current.phase != Phase::Active {
        return Err(MorphError::SpliceStateNotActive);
    }
    if current.vault_outpoint_commitment == [0; 32]
        || splice.next_state.header.vault_outpoint_commitment != [0; 32]
    {
        return Err(MorphError::VaultOutPointBindingInvalid);
    }
    if splice.header.chain_id != current.chain_id
        || splice.header.signature_scheme_id != current.signature_scheme_id
        || splice.header.channel_id != current.channel_id
        || splice.header.old_funding_epoch != current.funding_epoch
        || splice.header.old_funding_anchor != current.funding_anchor
        || splice.header.old_vault_commitment != current.vault_set_commitment
        || splice.header.participants_commitment != current.participants_commitment
        || splice.header.vault_materialisation_root != current.vault_materialisation_root
        || splice.header.challenge_policy_commitment != current.challenge_policy_commitment
        || splice.header.old_vault_outpoint_commitment != current.vault_outpoint_commitment
    {
        return Err(MorphError::SpliceHeaderContextMismatch);
    }
    if splice.header.base_state_number != current.state_number {
        return Err(MorphError::SpliceBaseStateMismatch);
    }
    if !state_context_matches_splice_next(current, &splice.next_state.header, &splice.header) {
        return Err(MorphError::SpliceNextStateMismatch);
    }
    validate_asset_registry_binding(current, &splice.asset_registry)?;
    validate_asset_registry_binding(&splice.next_state.header, &splice.asset_registry)?;
    if splice.header.new_funding_epoch <= splice.header.old_funding_epoch
        || splice.header.new_funding_anchor == splice.header.old_funding_anchor
    {
        return Err(MorphError::SpliceEpochNotAdvanced);
    }
    if splice.old_vault.funding_anchor != splice.header.old_funding_anchor
        || splice.new_vault.funding_anchor != splice.header.new_funding_anchor
        || vault_descriptor_commitment(&splice.old_vault) != splice.header.old_vault_commitment
        || vault_descriptor_commitment(&splice.new_vault) != splice.header.new_vault_commitment
    {
        return Err(MorphError::SpliceVaultCommitmentMismatch);
    }
    if splice_asset_delta_commitment(&splice.deltas) != splice.header.asset_delta_commitment {
        return Err(MorphError::SpliceDeltaCommitmentMismatch);
    }
    if !wire_asset_amounts_are_canonical(&splice.old_vault.assets, false)
        || !wire_asset_amounts_are_canonical(&splice.new_vault.assets, false)
        || !wire_asset_amounts_are_canonical(&splice.withdrawals, true)
        || !wire_asset_amounts_are_canonical(&splice.remaining_settlement, true)
        || !wire_splice_deltas_are_canonical(&splice.deltas)
    {
        return Err(MorphError::SpliceAssetDeltaInvalid);
    }

    validate_splice_authorization(&splice.header, &splice.witness)?;
    validate_splice_assets_registered(splice)?;

    let old_assets = vault_amount_map(&splice.old_vault.assets)?;
    let new_assets = vault_amount_map(&splice.new_vault.assets)?;
    let withdrawals = vault_amount_map(&splice.withdrawals)?;
    let remaining_settlement = vault_amount_map(&splice.remaining_settlement)?;
    let deltas = splice_delta_map(&splice.deltas)?;

    for (asset, delta) in &deltas {
        if old_assets.get(asset).copied().unwrap_or_default() != delta.old_amount
            || new_assets.get(asset).copied().unwrap_or_default() != delta.new_amount
        {
            return Err(MorphError::SpliceVaultDeltaMismatch);
        }
        if withdrawals.get(asset).copied().unwrap_or_default() != delta.withdrawal {
            return Err(MorphError::SpliceWithdrawalMismatch);
        }
        validate_splice_delta(splice.header.kind, delta)?;
    }

    for (asset, old_amount) in &old_assets {
        if !deltas.contains_key(asset)
            && new_assets.get(asset).copied().unwrap_or_default() != *old_amount
        {
            return Err(MorphError::SpliceVaultDeltaMismatch);
        }
    }
    for (asset, new_amount) in &new_assets {
        if !deltas.contains_key(asset)
            && old_assets.get(asset).copied().unwrap_or_default() != *new_amount
        {
            return Err(MorphError::SpliceVaultDeltaMismatch);
        }
    }
    for (asset, withdrawal) in &withdrawals {
        if *withdrawal != 0 && !deltas.contains_key(asset) {
            return Err(MorphError::SpliceWithdrawalMismatch);
        }
    }
    for (asset, required) in &remaining_settlement {
        if new_assets.get(asset).copied().unwrap_or_default() < *required {
            return Err(MorphError::SpliceRemainingValueInsufficient);
        }
    }

    Ok(())
}

fn state_context_matches_splice_next(
    current: &StateHeader,
    next: &StateHeader,
    header: &SpliceHeader,
) -> bool {
    current.protocol_version == next.protocol_version
        && current.chain_id == next.chain_id
        && current.signature_scheme_id == next.signature_scheme_id
        && current.channel_id == next.channel_id
        && current.funding_epoch == header.old_funding_epoch
        && next.funding_epoch == header.new_funding_epoch
        && current.funding_anchor == header.old_funding_anchor
        && next.funding_anchor == header.new_funding_anchor
        && current.vault_set_commitment == header.old_vault_commitment
        && next.vault_set_commitment == header.new_vault_commitment
        && next.vault_materialisation_root == header.new_vault_materialisation_root
        && next.vault_outpoint_commitment == header.new_vault_outpoint_commitment
        && current.state_number == next.state_number
        && current.mode == next.mode
        && current.participants_commitment == next.participants_commitment
        && current.asset_registry_commitment == next.asset_registry_commitment
        && current.settlement_descriptor_commitment == next.settlement_descriptor_commitment
        && current.descriptor_version == next.descriptor_version
        && current.challenge_policy_commitment == next.challenge_policy_commitment
        && current.state_layout_version == next.state_layout_version
}

pub fn validate_splice_authorization(header: &SpliceHeader, witness: &SpliceWitness) -> Result<()> {
    if header.protocol_version != MORPH_PROTOCOL_VERSION {
        return Err(MorphError::UnsupportedProtocolProfile);
    }
    if header.signature_scheme_id != SIGNATURE_SCHEME_SECP256K1_ECDSA_BLAKE2B {
        return Err(MorphError::SpliceUnsupportedSignatureScheme);
    }
    if witness.threshold != SPLICE_SIGNATURE_THRESHOLD
        || witness.signatures.len() != SPLICE_SIGNATURE_COUNT as usize
        || witness
            .signatures
            .iter()
            .any(|signature| signature.pubkey_sec1.len() != COMPRESSED_SECP256K1_PUBKEY_LEN)
    {
        return Err(MorphError::SpliceParticipantSetMismatch);
    }

    let pubkeys: Vec<&[u8]> = witness
        .signatures
        .iter()
        .map(|signature| signature.pubkey_sec1.as_slice())
        .collect();
    if !pubkeys.windows(2).all(|window| window[0] < window[1]) {
        return Err(MorphError::SpliceParticipantSetMismatch);
    }
    if participants_commitment(witness.threshold, &pubkeys) != header.participants_commitment {
        return Err(MorphError::SpliceParticipantSetMismatch);
    }

    let digest = header.signing_digest();
    let mut valid = 0usize;
    for participant_signature in &witness.signatures {
        let verifying_key = VerifyingKey::from_sec1_bytes(&participant_signature.pubkey_sec1)
            .map_err(|_| MorphError::ParticipantSignatureEncoding)?;
        let signature = Signature::try_from(participant_signature.signature.as_slice())
            .map_err(|_| MorphError::ParticipantSignatureEncoding)?;
        verifying_key
            .verify_prehash(&digest, &signature)
            .map_err(|_| MorphError::InvalidSpliceSignatures)?;
        valid += 1;
    }
    if valid < witness.threshold as usize {
        return Err(MorphError::InvalidSpliceSignatures);
    }
    Ok(())
}

pub fn validate_sponsor_policy(policy: &SponsorPolicy, spend: &SponsorSpend) -> Result<()> {
    if spend.channel_id != policy.channel_id {
        return Err(MorphError::SponsorChannelMismatch);
    }
    if spend.state_number < policy.min_state_number || spend.state_number > policy.max_state_number
    {
        return Err(MorphError::SponsorStateOutOfRange);
    }
    if spend.publication_state_type_hash != policy.publication_state_type_hash {
        return Err(MorphError::SponsorStateTypeMismatch);
    }
    if spend.change_lock != policy.change_lock {
        return Err(MorphError::SponsorChangeLockMismatch);
    }
    if spend.fee > policy.max_fee_per_tx {
        return Err(MorphError::SponsorFeeTooHigh);
    }
    if policy
        .already_spent
        .checked_add(spend.fee)
        .ok_or(MorphError::SponsorBudgetExceeded)?
        > policy.max_total_fee
    {
        return Err(MorphError::SponsorBudgetExceeded);
    }
    if !spend.operation.is_publication_or_supersede() {
        return Err(MorphError::SponsorOperationNotAllowed);
    }
    Ok(())
}

pub fn validate_factory_non_interference(update: &FactoryUpdate) -> Result<()> {
    for participant in &update.touched_participants {
        if !update.authorised_participants.contains(participant) {
            return Err(MorphError::FactoryMissingAuthorisation);
        }
    }

    let before = factory_right_map(&update.before)?;
    let after = factory_right_map(&update.after)?;

    for (id, before_right) in &before {
        match after.get(id) {
            Some(after_right) if after_right.quantity == before_right.quantity => {}
            Some(_) | None => require_factory_right_change_authorised(update, id)?,
        }
    }

    for id in after.keys() {
        if !before.contains_key(id) {
            require_factory_right_change_authorised(update, id)?;
        }
    }

    Ok(())
}

pub fn validate_reduced_factory_exit(
    update: &FactoryUpdate,
    exit: &FactoryReducedExit,
) -> Result<()> {
    if exit.release_quantity == 0
        || exit.reserve_claim.participant != exit.participant
        || exit.reserve_claim.kind != FactoryRightKind::ReserveClaim
    {
        return Err(MorphError::FactoryReducedExitInvalid);
    }
    if update.touched_participants.len() != 1
        || update.authorised_participants.len() != 1
        || !update.touched_participants.contains(&exit.participant)
        || !update.authorised_participants.contains(&exit.participant)
    {
        return Err(MorphError::FactoryMissingAuthorisation);
    }

    let before = factory_right_map(&update.before)?;
    let after = factory_right_map(&update.after)?;
    let before_claim = before
        .get(&exit.reserve_claim)
        .ok_or(MorphError::FactoryReducedExitInvalid)?;
    let after_claim_quantity = after
        .get(&exit.reserve_claim)
        .map(|right| right.quantity)
        .unwrap_or_default();
    if before_claim.quantity < exit.release_quantity
        || before_claim.quantity - exit.release_quantity != after_claim_quantity
    {
        return Err(MorphError::FactoryReducedExitInvalid);
    }

    for (id, before_right) in &before {
        if id == &exit.reserve_claim {
            continue;
        }
        match after.get(id) {
            Some(after_right) if after_right.quantity == before_right.quantity => {}
            Some(_) | None => return Err(MorphError::FactoryReducedExitInterference),
        }
    }
    for id in after.keys() {
        if !before.contains_key(id) {
            return Err(MorphError::FactoryReducedExitInterference);
        }
    }

    Ok(())
}

pub fn validate_factory_single_right_merkle_update(
    update: &FactorySingleRightMerkleUpdate,
) -> Result<()> {
    validate_factory_single_right_merkle_localization(update)?;
    if update.after.right.quantity > update.before.right.quantity
        || !matches!(
            update.before.right.id.kind,
            FactoryRightKind::Balance
                | FactoryRightKind::ReserveClaim
                | FactoryRightKind::SponsorBudgetClaim
        )
    {
        return Err(MorphError::FactoryMerkleProofInvalid);
    }
    Ok(())
}

pub fn validate_factory_single_right_merkle_localization(
    update: &FactorySingleRightMerkleUpdate,
) -> Result<()> {
    verify_factory_right_merkle_proof(update.before_root, &update.before)?;
    verify_factory_right_merkle_proof(update.after_root, &update.after)?;

    if update.before.right.id != update.after.right.id
        || update.before.right.quantity == update.after.right.quantity
    {
        return Err(MorphError::FactoryMerkleProofInvalid);
    }
    if update.before.siblings != update.after.siblings {
        return Err(MorphError::FactoryMerkleProofInterference);
    }

    let participant = update.before.right.id.participant;
    if update.touched_participants.len() != 1
        || update.authorised_participants.len() != 1
        || !update.touched_participants.contains(&participant)
        || !update.authorised_participants.contains(&participant)
    {
        return Err(MorphError::FactoryMissingAuthorisation);
    }

    Ok(())
}

pub fn validate_factory_splice_transition(splice: &FactorySpliceTransition) -> Result<()> {
    validate_factory_non_interference(&splice.update)?;
    validate_factory_splice_authorization(&splice.header, &splice.witness)?;
    validate_factory_splice_assets_registered(splice)?;

    if splice.header.new_update_number <= splice.header.old_update_number {
        return Err(MorphError::FactorySpliceUpdateNotAdvanced);
    }
    if splice.header.old_vault_outpoint_commitment == [0; 32]
        || splice.header.new_vault_outpoint_commitment != [0; 32]
    {
        return Err(MorphError::VaultOutPointBindingInvalid);
    }
    let computed_old_root = factory_right_sparse_root(&splice.update.before)?;
    let computed_new_root = factory_right_sparse_root(&splice.update.after)?;
    if splice.header.old_state_root != computed_old_root
        || splice.header.new_state_root != computed_new_root
    {
        return Err(MorphError::FactorySpliceHeaderMismatch);
    }
    if splice.old_vault.factory_id != splice.header.factory_id
        || splice.new_vault.factory_id != splice.header.factory_id
    {
        return Err(MorphError::FactorySpliceHeaderMismatch);
    }
    if factory_vault_delta_commitment(&splice.deltas) != splice.header.vault_delta_commitment {
        return Err(MorphError::FactorySpliceDeltaCommitmentMismatch);
    }
    if !wire_asset_amounts_are_canonical(&splice.old_vault.assets, false)
        || !wire_asset_amounts_are_canonical(&splice.new_vault.assets, false)
        || !wire_factory_deltas_are_canonical(&splice.deltas)
    {
        return Err(MorphError::FactorySpliceAssetDeltaInvalid);
    }
    if splice.update.touched_participants.len() != 1
        || splice.update.authorised_participants.len() != 1
    {
        return Err(MorphError::FactoryMissingAuthorisation);
    }

    let old_assets = vault_amount_map(&splice.old_vault.assets)?;
    let new_assets = vault_amount_map(&splice.new_vault.assets)?;
    let deltas = factory_delta_map(&splice.deltas)?;
    let claim_delta = factory_splice_reserve_claim_delta(&splice.update)?;

    if !splice
        .update
        .touched_participants
        .contains(&claim_delta.participant)
        || !splice
            .update
            .authorised_participants
            .contains(&claim_delta.participant)
    {
        return Err(MorphError::FactoryMissingAuthorisation);
    }

    let claim_asset = reserve_claim_asset(&claim_delta.asset_type);
    let Some(delta) = deltas.get(&claim_asset) else {
        return Err(MorphError::FactorySpliceVaultDeltaMismatch);
    };
    if old_assets.get(&claim_asset).copied().unwrap_or_default() != delta.old_amount
        || new_assets.get(&claim_asset).copied().unwrap_or_default() != delta.new_amount
    {
        return Err(MorphError::FactorySpliceVaultDeltaMismatch);
    }

    validate_factory_vault_delta(splice.header.kind, delta)?;
    let claim_change = match splice.header.kind {
        FactorySpliceKind::In => claim_delta
            .new_quantity
            .checked_sub(claim_delta.old_quantity)
            .ok_or(MorphError::FactorySpliceReserveClaimInvalid)?,
        FactorySpliceKind::Out => claim_delta
            .old_quantity
            .checked_sub(claim_delta.new_quantity)
            .ok_or(MorphError::FactorySpliceReserveClaimInvalid)?,
    };
    let vault_change = match splice.header.kind {
        FactorySpliceKind::In => delta.external_input,
        FactorySpliceKind::Out => delta.withdrawal,
    };
    if claim_change == 0 || claim_change != vault_change {
        return Err(MorphError::FactorySpliceVaultDeltaMismatch);
    }

    for (asset, old_amount) in &old_assets {
        if !deltas.contains_key(asset)
            && new_assets.get(asset).copied().unwrap_or_default() != *old_amount
        {
            return Err(MorphError::FactorySpliceVaultDeltaMismatch);
        }
    }
    for (asset, new_amount) in &new_assets {
        if !deltas.contains_key(asset)
            && old_assets.get(asset).copied().unwrap_or_default() != *new_amount
        {
            return Err(MorphError::FactorySpliceVaultDeltaMismatch);
        }
    }
    for asset in deltas.keys() {
        if asset != &claim_asset {
            return Err(MorphError::FactorySpliceVaultDeltaMismatch);
        }
    }

    Ok(())
}

pub fn validate_factory_reduced_splice_transition(
    splice: &FactoryReducedSpliceTransition,
) -> Result<()> {
    validate_factory_single_right_merkle_localization(&splice.update)?;
    validate_factory_reduced_splice_authorization(&splice.header, &splice.update, &splice.witness)?;
    validate_factory_reduced_splice_assets_registered(splice)?;

    if splice.header.new_update_number <= splice.header.old_update_number {
        return Err(MorphError::FactorySpliceUpdateNotAdvanced);
    }
    if splice.header.old_state_root != splice.update.before_root
        || splice.header.new_state_root != splice.update.after_root
    {
        return Err(MorphError::FactorySpliceHeaderMismatch);
    }
    if splice.old_vault.factory_id != splice.header.factory_id
        || splice.new_vault.factory_id != splice.header.factory_id
    {
        return Err(MorphError::FactorySpliceHeaderMismatch);
    }
    if factory_vault_delta_commitment(&splice.deltas) != splice.header.vault_delta_commitment {
        return Err(MorphError::FactorySpliceDeltaCommitmentMismatch);
    }
    if !wire_asset_amounts_are_canonical(&splice.old_vault.assets, false)
        || !wire_asset_amounts_are_canonical(&splice.new_vault.assets, false)
        || !wire_factory_deltas_are_canonical(&splice.deltas)
    {
        return Err(MorphError::FactorySpliceAssetDeltaInvalid);
    }

    let old_assets = vault_amount_map(&splice.old_vault.assets)?;
    let new_assets = vault_amount_map(&splice.new_vault.assets)?;
    let deltas = factory_delta_map(&splice.deltas)?;
    let claim_delta = factory_reduced_splice_reserve_claim_delta(&splice.update)?;

    let claim_asset = reserve_claim_asset(&claim_delta.asset_type);
    let Some(delta) = deltas.get(&claim_asset) else {
        return Err(MorphError::FactorySpliceVaultDeltaMismatch);
    };
    if old_assets.get(&claim_asset).copied().unwrap_or_default() != delta.old_amount
        || new_assets.get(&claim_asset).copied().unwrap_or_default() != delta.new_amount
    {
        return Err(MorphError::FactorySpliceVaultDeltaMismatch);
    }

    validate_factory_vault_delta(splice.header.kind, delta)?;
    let claim_change = match splice.header.kind {
        FactorySpliceKind::In => claim_delta
            .new_quantity
            .checked_sub(claim_delta.old_quantity)
            .ok_or(MorphError::FactorySpliceReserveClaimInvalid)?,
        FactorySpliceKind::Out => claim_delta
            .old_quantity
            .checked_sub(claim_delta.new_quantity)
            .ok_or(MorphError::FactorySpliceReserveClaimInvalid)?,
    };
    let vault_change = match splice.header.kind {
        FactorySpliceKind::In => delta.external_input,
        FactorySpliceKind::Out => delta.withdrawal,
    };
    if claim_change == 0 || claim_change != vault_change {
        return Err(MorphError::FactorySpliceVaultDeltaMismatch);
    }

    for (asset, old_amount) in &old_assets {
        if !deltas.contains_key(asset)
            && new_assets.get(asset).copied().unwrap_or_default() != *old_amount
        {
            return Err(MorphError::FactorySpliceVaultDeltaMismatch);
        }
    }
    for (asset, new_amount) in &new_assets {
        if !deltas.contains_key(asset)
            && old_assets.get(asset).copied().unwrap_or_default() != *new_amount
        {
            return Err(MorphError::FactorySpliceVaultDeltaMismatch);
        }
    }
    for asset in deltas.keys() {
        if asset != &claim_asset {
            return Err(MorphError::FactorySpliceVaultDeltaMismatch);
        }
    }

    Ok(())
}

pub fn validate_factory_reduced_splice_authorization(
    header: &FactorySpliceHeader,
    update: &FactorySingleRightMerkleUpdate,
    witness: &FactoryReducedSpliceWitness,
) -> Result<()> {
    if header.protocol_version != MORPH_PROTOCOL_VERSION {
        return Err(MorphError::UnsupportedProtocolProfile);
    }
    if header.signature_scheme_id != SIGNATURE_SCHEME_SECP256K1_ECDSA_BLAKE2B {
        return Err(MorphError::FactorySpliceUnsupportedSignatureScheme);
    }
    if witness.participant_threshold != FACTORY_REDUCED_RIGHTS_PARTICIPANT_THRESHOLD
        || witness.participant_keys.len() != FACTORY_REDUCED_RIGHTS_PARTICIPANT_COUNT as usize
        || witness.signatures.is_empty()
        || witness
            .participant_keys
            .iter()
            .any(|key| key.pubkey_sec1.len() != COMPRESSED_SECP256K1_PUBKEY_LEN)
        || witness
            .signatures
            .iter()
            .any(|signature| signature.pubkey_sec1.len() != COMPRESSED_SECP256K1_PUBKEY_LEN)
    {
        return Err(MorphError::FactorySpliceParticipantSetMismatch);
    }

    let mut participants = BTreeSet::new();
    let mut pubkeys = BTreeSet::new();
    let mut key_map = BTreeMap::new();
    for key in &witness.participant_keys {
        if !participants.insert(key.participant) || !pubkeys.insert(key.pubkey_sec1.clone()) {
            return Err(MorphError::FactorySpliceParticipantSetMismatch);
        }
        key_map.insert(key.participant, key.pubkey_sec1.as_slice());
    }
    let pubkey_refs = witness
        .participant_keys
        .iter()
        .map(|key| key.pubkey_sec1.as_slice())
        .collect::<Vec<_>>();
    if participants_commitment(witness.participant_threshold, &pubkey_refs)
        != header.participants_commitment
    {
        return Err(MorphError::FactorySpliceParticipantSetMismatch);
    }

    let authorised = &update.authorised_participants;
    if witness.signatures.len() != authorised.len() {
        return Err(MorphError::FactorySpliceParticipantSetMismatch);
    }

    let digest = header.signing_digest();
    let mut signed_participants = BTreeSet::new();
    for participant_signature in &witness.signatures {
        if !authorised.contains(&participant_signature.participant)
            || !signed_participants.insert(participant_signature.participant)
        {
            return Err(MorphError::FactorySpliceParticipantSetMismatch);
        }
        let Some(expected_pubkey) = key_map.get(&participant_signature.participant) else {
            return Err(MorphError::FactorySpliceParticipantSetMismatch);
        };
        if *expected_pubkey != participant_signature.pubkey_sec1.as_slice() {
            return Err(MorphError::FactorySpliceParticipantSetMismatch);
        }
        let verifying_key = VerifyingKey::from_sec1_bytes(&participant_signature.pubkey_sec1)
            .map_err(|_| MorphError::ParticipantSignatureEncoding)?;
        let signature = Signature::try_from(participant_signature.signature.as_slice())
            .map_err(|_| MorphError::ParticipantSignatureEncoding)?;
        verifying_key
            .verify_prehash(&digest, &signature)
            .map_err(|_| MorphError::InvalidFactorySpliceSignatures)?;
    }

    Ok(())
}

pub fn validate_factory_splice_authorization(
    header: &FactorySpliceHeader,
    witness: &SpliceWitness,
) -> Result<()> {
    if header.protocol_version != MORPH_PROTOCOL_VERSION {
        return Err(MorphError::UnsupportedProtocolProfile);
    }
    if header.signature_scheme_id != SIGNATURE_SCHEME_SECP256K1_ECDSA_BLAKE2B {
        return Err(MorphError::FactorySpliceUnsupportedSignatureScheme);
    }
    if witness.threshold != FACTORY_SIGNATURE_THRESHOLD
        || witness.signatures.len() != FACTORY_SIGNATURE_COUNT as usize
        || witness
            .signatures
            .iter()
            .any(|signature| signature.pubkey_sec1.len() != COMPRESSED_SECP256K1_PUBKEY_LEN)
    {
        return Err(MorphError::FactorySpliceParticipantSetMismatch);
    }

    let pubkeys: Vec<&[u8]> = witness
        .signatures
        .iter()
        .map(|signature| signature.pubkey_sec1.as_slice())
        .collect();
    let unique_pubkeys = pubkeys.iter().copied().collect::<BTreeSet<_>>();
    if unique_pubkeys.len() != pubkeys.len() {
        return Err(MorphError::FactorySpliceParticipantSetMismatch);
    }
    if participants_commitment(witness.threshold, &pubkeys) != header.participants_commitment {
        return Err(MorphError::FactorySpliceParticipantSetMismatch);
    }

    let digest = header.signing_digest();
    let mut valid = 0usize;
    for participant_signature in &witness.signatures {
        let verifying_key = VerifyingKey::from_sec1_bytes(&participant_signature.pubkey_sec1)
            .map_err(|_| MorphError::ParticipantSignatureEncoding)?;
        let signature = Signature::try_from(participant_signature.signature.as_slice())
            .map_err(|_| MorphError::ParticipantSignatureEncoding)?;
        verifying_key
            .verify_prehash(&digest, &signature)
            .map_err(|_| MorphError::InvalidFactorySpliceSignatures)?;
        valid += 1;
    }
    if valid < witness.threshold as usize {
        return Err(MorphError::InvalidFactorySpliceSignatures);
    }
    Ok(())
}

pub fn verify_factory_right_merkle_proof(
    expected_root: Bytes32,
    proof: &FactoryRightMerkleProof,
) -> Result<()> {
    if proof.siblings.len() != FACTORY_SPARSE_MERKLE_DEPTH {
        return Err(MorphError::FactoryMerkleProofInvalid);
    }
    let mut current = factory_right_leaf_hash(&proof.right);
    for (depth, sibling) in proof.siblings.iter().enumerate().rev() {
        current = match sibling.side {
            FactoryMerkleSiblingSide::Left => factory_right_node_hash(depth, sibling.hash, current),
            FactoryMerkleSiblingSide::Right => {
                factory_right_node_hash(depth, current, sibling.hash)
            }
        };
    }
    if current == expected_root {
        Ok(())
    } else {
        Err(MorphError::FactoryMerkleProofInvalid)
    }
}

pub fn factory_right_sparse_root(rights: &[FactoryRight]) -> Result<Bytes32> {
    let entries = factory_sparse_entries(rights)?;
    let empty_hashes = factory_empty_hashes();
    Ok(factory_sparse_subtree_root(&entries, 0, &empty_hashes))
}

pub fn factory_right_sparse_proof(
    rights: &[FactoryRight],
    id: &FactoryRightId,
) -> Result<FactoryRightMerkleProof> {
    let entries = factory_sparse_entries(rights)?;
    let key = factory_right_key(id);
    let empty_hashes = factory_empty_hashes();
    let mut siblings = Vec::with_capacity(FACTORY_SPARSE_MERKLE_DEPTH);
    let right = factory_sparse_proof_inner(&entries, key, 0, &empty_hashes, &mut siblings)?;
    Ok(FactoryRightMerkleProof { right, siblings })
}

pub fn factory_right_key(id: &FactoryRightId) -> Bytes32 {
    let mut bytes = Vec::with_capacity(128);
    bytes.extend_from_slice(FACTORY_RIGHT_KEY_DOMAIN);
    bytes.extend_from_slice(&id.participant);
    bytes.extend_from_slice(&id.subchannel);
    bytes.push(factory_right_kind_byte(id.kind));
    match id.asset_type {
        Some(asset_type) => {
            bytes.push(1);
            bytes.extend_from_slice(&asset_type);
        }
        None => {
            bytes.push(0);
            bytes.extend_from_slice(&[0u8; 32]);
        }
    }
    blake2b256(&bytes)
}

pub fn factory_right_leaf_hash(right: &FactoryRight) -> Bytes32 {
    let mut bytes = Vec::with_capacity(160);
    bytes.extend_from_slice(FACTORY_RIGHT_LEAF_DOMAIN);
    bytes.extend_from_slice(&factory_right_key(&right.id));
    bytes.extend_from_slice(&right.id.participant);
    bytes.extend_from_slice(&right.id.subchannel);
    bytes.push(factory_right_kind_byte(right.id.kind));
    match right.id.asset_type {
        Some(asset_type) => {
            bytes.push(1);
            bytes.extend_from_slice(&asset_type);
        }
        None => {
            bytes.push(0);
            bytes.extend_from_slice(&[0u8; 32]);
        }
    }
    bytes.extend_from_slice(&right.quantity.to_le_bytes());
    blake2b256(&bytes)
}

pub fn validate_vault_spend(spend: &VaultSpend) -> Result<()> {
    validate_state_profile(&spend.state_cell.header)?;
    if spend.state_cell.header.signature_scheme_id != SIGNATURE_SCHEME_SECP256K1_ECDSA_BLAKE2B {
        return Err(MorphError::UnsupportedSignatureScheme);
    }
    validate_asset_registry_binding(&spend.state_cell.header, &spend.asset_registry)?;
    match spend.operation {
        ChannelOperation::Finalise | ChannelOperation::Splice | ChannelOperation::Materialise => {}
        ChannelOperation::Fund | ChannelOperation::Publish | ChannelOperation::Supersede => {
            return Err(MorphError::VaultOperationNotAllowed);
        }
    }

    if spend.state_cell.header.funding_anchor != spend.expected_funding_anchor {
        return Err(MorphError::VaultFundingAnchorMismatch);
    }
    if !spend.signatures_or_phase_authorised {
        return Err(MorphError::VaultAuthorisationMissing);
    }
    if spend.operation == ChannelOperation::Finalise {
        if spend.state_cell.header.phase != Phase::Settling {
            return Err(MorphError::VaultStateNotSettling);
        }
        if !spend.since_satisfied {
            return Err(MorphError::SinceNotSatisfied);
        }
    }
    if !spend.descriptor_outputs_match {
        return Err(MorphError::DescriptorOutputMismatch);
    }
    validate_partition_conservation(&spend.partition, &spend.asset_registry)?;
    Ok(())
}

pub fn validate_partition_conservation(
    tx: &PartitionedTransaction,
    registry: &AssetRegistry,
) -> Result<PartitionTotals> {
    for output in &tx.outputs {
        if output.capacity < output.occupied_capacity {
            return Err(MorphError::OutputBelowOccupiedCapacity);
        }
    }
    for cell in tx.inputs.iter().chain(tx.outputs.iter()) {
        validate_classified_cell(cell)?;
    }

    let mut totals = PartitionTotals {
        reserve_in: 0,
        reserve_out: 0,
        business_ckb_in: 0,
        business_ckb_out: 0,
        xudt_in: BTreeMap::new(),
        xudt_out: BTreeMap::new(),
        state_carrier_in: 0,
        state_carrier_out: 0,
        sponsor_in: 0,
        sponsor_out: 0,
    };

    fold_cells(&tx.inputs, registry, true, &mut totals)?;
    fold_cells(&tx.outputs, registry, false, &mut totals)?;

    let reserve_out_with_refund = totals
        .reserve_out
        .checked_add(tx.authorised_reserve_refund)
        .ok_or(MorphError::ReserveNotConserved)?;
    if reserve_out_with_refund != totals.reserve_in {
        return Err(MorphError::ReserveNotConserved);
    }
    if totals.state_carrier_in != totals.state_carrier_out {
        return Err(MorphError::StateCarrierNotConserved);
    }
    if totals.business_ckb_in != totals.business_ckb_out {
        return Err(MorphError::BusinessCkbNotConserved);
    }
    for asset_type in &registry.xudt_types {
        let input = totals.xudt_in.get(asset_type).copied().unwrap_or_default();
        let output = totals.xudt_out.get(asset_type).copied().unwrap_or_default();
        if input != output {
            return Err(MorphError::XudtNotConserved);
        }
    }
    let sponsor_fee = totals
        .sponsor_in
        .checked_sub(totals.sponsor_out)
        .ok_or(MorphError::SponsorFeeMismatch)?;
    if sponsor_fee != tx.tx_fee {
        return Err(MorphError::SponsorFeeMismatch);
    }
    for output in &tx.outputs {
        if matches!(output.class, CellClass::Sponsor)
            && (output.carries_registered_xudt || output.uses_channel_vault_lock)
        {
            return Err(MorphError::SponsorChangeContaminated);
        }
    }

    Ok(totals)
}

fn factory_right_map(rights: &[FactoryRight]) -> Result<BTreeMap<FactoryRightId, &FactoryRight>> {
    let mut map = BTreeMap::new();
    for right in rights {
        if map.insert(right.id.clone(), right).is_some() {
            return Err(MorphError::FactoryDuplicateRight);
        }
    }
    Ok(map)
}

fn factory_sparse_entries(
    rights: &[FactoryRight],
) -> Result<Vec<(Bytes32, Bytes32, FactoryRight)>> {
    let mut entries = rights
        .iter()
        .map(|right| {
            (
                factory_right_key(&right.id),
                factory_right_leaf_hash(right),
                right.clone(),
            )
        })
        .collect::<Vec<_>>();
    entries.sort_by(|left, right| left.0.cmp(&right.0));
    if entries.windows(2).any(|window| window[0].0 == window[1].0) {
        return Err(MorphError::FactoryDuplicateRight);
    }
    Ok(entries)
}

fn factory_sparse_proof_inner(
    entries: &[(Bytes32, Bytes32, FactoryRight)],
    target_key: Bytes32,
    depth: usize,
    empty_hashes: &[Bytes32; FACTORY_SPARSE_MERKLE_DEPTH + 1],
    siblings: &mut Vec<FactoryMerkleSibling>,
) -> Result<FactoryRight> {
    if depth == FACTORY_SPARSE_MERKLE_DEPTH {
        return entries
            .iter()
            .find(|(key, _, _)| *key == target_key)
            .map(|(_, _, right)| right.clone())
            .ok_or(MorphError::FactoryMerkleProofInvalid);
    }

    let split = entries.partition_point(|(key, _, _)| !factory_key_bit(key, depth));
    let target_is_right = factory_key_bit(&target_key, depth);
    let (branch, sibling, side) = if target_is_right {
        (
            &entries[split..],
            &entries[..split],
            FactoryMerkleSiblingSide::Left,
        )
    } else {
        (
            &entries[..split],
            &entries[split..],
            FactoryMerkleSiblingSide::Right,
        )
    };
    let sibling_hash = factory_sparse_subtree_root(sibling, depth + 1, empty_hashes);
    siblings.push(FactoryMerkleSibling {
        side,
        hash: sibling_hash,
    });
    factory_sparse_proof_inner(branch, target_key, depth + 1, empty_hashes, siblings)
}

fn factory_sparse_subtree_root(
    entries: &[(Bytes32, Bytes32, FactoryRight)],
    depth: usize,
    empty_hashes: &[Bytes32; FACTORY_SPARSE_MERKLE_DEPTH + 1],
) -> Bytes32 {
    if entries.is_empty() {
        return empty_hashes[FACTORY_SPARSE_MERKLE_DEPTH - depth];
    }
    if depth == FACTORY_SPARSE_MERKLE_DEPTH {
        return entries[0].1;
    }

    let split = entries.partition_point(|(key, _, _)| !factory_key_bit(key, depth));
    let left = factory_sparse_subtree_root(&entries[..split], depth + 1, empty_hashes);
    let right = factory_sparse_subtree_root(&entries[split..], depth + 1, empty_hashes);
    factory_right_node_hash(depth, left, right)
}

fn factory_empty_hashes() -> [Bytes32; FACTORY_SPARSE_MERKLE_DEPTH + 1] {
    let mut out = [[0u8; 32]; FACTORY_SPARSE_MERKLE_DEPTH + 1];
    out[0] = blake2b256(FACTORY_RIGHT_EMPTY_DOMAIN);
    for height in 1..=FACTORY_SPARSE_MERKLE_DEPTH {
        out[height] = factory_right_node_hash(
            FACTORY_SPARSE_MERKLE_DEPTH - height,
            out[height - 1],
            out[height - 1],
        );
    }
    out
}

fn factory_right_node_hash(depth: usize, left: Bytes32, right: Bytes32) -> Bytes32 {
    let mut bytes = Vec::with_capacity(72);
    bytes.extend_from_slice(FACTORY_RIGHT_NODE_DOMAIN);
    bytes.extend_from_slice(&(depth as u16).to_le_bytes());
    bytes.extend_from_slice(&left);
    bytes.extend_from_slice(&right);
    blake2b256(&bytes)
}

fn factory_key_bit(key: &Bytes32, depth: usize) -> bool {
    let byte = key[depth / 8];
    let mask = 0x80u8 >> (depth % 8);
    byte & mask != 0
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

fn require_factory_right_change_authorised(
    update: &FactoryUpdate,
    id: &FactoryRightId,
) -> Result<()> {
    if !update.touched_participants.contains(&id.participant) {
        return Err(MorphError::FactoryNonInterferenceViolation);
    }
    if !update.authorised_participants.contains(&id.participant) {
        return Err(MorphError::FactoryMissingAuthorisation);
    }
    Ok(())
}

fn validate_splice_delta(kind: SpliceKind, delta: &SpliceAssetDelta) -> Result<()> {
    if matches!(delta.asset, VaultAsset::Xudt(_)) && delta.signed_fee != 0 {
        return Err(MorphError::SpliceAssetDeltaInvalid);
    }
    let debits = checked_add3(delta.new_amount, delta.withdrawal, delta.signed_fee)?;
    let credits = delta
        .old_amount
        .checked_add(delta.external_input)
        .ok_or(MorphError::SpliceAssetDeltaInvalid)?;
    if debits != credits {
        return Err(MorphError::SpliceAssetDeltaInvalid);
    }

    match kind {
        SpliceKind::In => {
            if delta.external_input == 0
                || delta.withdrawal != 0
                || delta.new_amount <= delta.old_amount
            {
                return Err(MorphError::SpliceAssetDeltaInvalid);
            }
        }
        SpliceKind::Out => {
            if delta.external_input != 0 || delta.withdrawal == 0 || delta.signed_fee != 0 {
                return Err(MorphError::SpliceAssetDeltaInvalid);
            }
            if delta.new_amount >= delta.old_amount {
                return Err(MorphError::SpliceAssetDeltaInvalid);
            }
        }
    }

    Ok(())
}

fn validate_factory_vault_delta(kind: FactorySpliceKind, delta: &FactoryVaultDelta) -> Result<()> {
    let debits = delta
        .new_amount
        .checked_add(delta.withdrawal)
        .ok_or(MorphError::FactorySpliceAssetDeltaInvalid)?;
    let credits = delta
        .old_amount
        .checked_add(delta.external_input)
        .ok_or(MorphError::FactorySpliceAssetDeltaInvalid)?;
    if debits != credits {
        return Err(MorphError::FactorySpliceAssetDeltaInvalid);
    }

    match kind {
        FactorySpliceKind::In => {
            if delta.external_input == 0
                || delta.withdrawal != 0
                || delta.new_amount <= delta.old_amount
            {
                return Err(MorphError::FactorySpliceAssetDeltaInvalid);
            }
        }
        FactorySpliceKind::Out => {
            if delta.external_input != 0
                || delta.withdrawal == 0
                || delta.new_amount >= delta.old_amount
            {
                return Err(MorphError::FactorySpliceAssetDeltaInvalid);
            }
        }
    }

    Ok(())
}

fn checked_add3(left: Amount, middle: Amount, right: Amount) -> Result<Amount> {
    left.checked_add(middle)
        .and_then(|value| value.checked_add(right))
        .ok_or(MorphError::SpliceAssetDeltaInvalid)
}

fn validate_splice_assets_registered(splice: &SpliceTransition) -> Result<()> {
    for asset in splice
        .old_vault
        .assets
        .iter()
        .map(|amount| &amount.asset)
        .chain(splice.new_vault.assets.iter().map(|amount| &amount.asset))
        .chain(splice.deltas.iter().map(|delta| &delta.asset))
        .chain(splice.withdrawals.iter().map(|amount| &amount.asset))
        .chain(
            splice
                .remaining_settlement
                .iter()
                .map(|amount| &amount.asset),
        )
    {
        if let VaultAsset::Xudt(type_hash) = asset
            && !splice.asset_registry.contains(type_hash)
        {
            return Err(MorphError::UnregisteredXudtType);
        }
    }
    Ok(())
}

fn validate_factory_splice_assets_registered(splice: &FactorySpliceTransition) -> Result<()> {
    for asset in splice.old_vault.assets.iter().map(|amount| &amount.asset) {
        if let VaultAsset::Xudt(type_hash) = asset
            && !splice.asset_registry.contains(type_hash)
        {
            return Err(MorphError::UnregisteredXudtType);
        }
    }
    for asset in splice.new_vault.assets.iter().map(|amount| &amount.asset) {
        if let VaultAsset::Xudt(type_hash) = asset
            && !splice.asset_registry.contains(type_hash)
        {
            return Err(MorphError::UnregisteredXudtType);
        }
    }
    for asset in splice.deltas.iter().map(|delta| &delta.asset) {
        if let VaultAsset::Xudt(type_hash) = asset
            && !splice.asset_registry.contains(type_hash)
        {
            return Err(MorphError::UnregisteredXudtType);
        }
    }
    for asset in splice
        .update
        .before
        .iter()
        .chain(splice.update.after.iter())
        .map(|right| reserve_claim_asset(&right.id.asset_type))
    {
        if let VaultAsset::Xudt(type_hash) = asset
            && !splice.asset_registry.contains(&type_hash)
        {
            return Err(MorphError::UnregisteredXudtType);
        }
    }
    Ok(())
}

fn validate_factory_reduced_splice_assets_registered(
    splice: &FactoryReducedSpliceTransition,
) -> Result<()> {
    for asset in splice.old_vault.assets.iter().map(|amount| &amount.asset) {
        if let VaultAsset::Xudt(type_hash) = asset
            && !splice.asset_registry.contains(type_hash)
        {
            return Err(MorphError::UnregisteredXudtType);
        }
    }
    for asset in splice.new_vault.assets.iter().map(|amount| &amount.asset) {
        if let VaultAsset::Xudt(type_hash) = asset
            && !splice.asset_registry.contains(type_hash)
        {
            return Err(MorphError::UnregisteredXudtType);
        }
    }
    for asset in splice.deltas.iter().map(|delta| &delta.asset) {
        if let VaultAsset::Xudt(type_hash) = asset
            && !splice.asset_registry.contains(type_hash)
        {
            return Err(MorphError::UnregisteredXudtType);
        }
    }
    for asset in [
        reserve_claim_asset(&splice.update.before.right.id.asset_type),
        reserve_claim_asset(&splice.update.after.right.id.asset_type),
    ] {
        if let VaultAsset::Xudt(type_hash) = asset
            && !splice.asset_registry.contains(&type_hash)
        {
            return Err(MorphError::UnregisteredXudtType);
        }
    }
    Ok(())
}

fn vault_amount_map(amounts: &[VaultAssetAmount]) -> Result<BTreeMap<VaultAsset, Amount>> {
    let mut map = BTreeMap::new();
    for amount in amounts {
        if map.insert(amount.asset.clone(), amount.amount).is_some() {
            return Err(MorphError::SpliceAssetDeltaInvalid);
        }
    }
    Ok(map)
}

fn factory_delta_map(
    deltas: &[FactoryVaultDelta],
) -> Result<BTreeMap<VaultAsset, &FactoryVaultDelta>> {
    let mut map = BTreeMap::new();
    for delta in deltas {
        if map.insert(delta.asset.clone(), delta).is_some() {
            return Err(MorphError::FactorySpliceAssetDeltaInvalid);
        }
    }
    Ok(map)
}

fn splice_delta_map(
    deltas: &[SpliceAssetDelta],
) -> Result<BTreeMap<VaultAsset, &SpliceAssetDelta>> {
    let mut map = BTreeMap::new();
    for delta in deltas {
        if map.insert(delta.asset.clone(), delta).is_some() {
            return Err(MorphError::SpliceAssetDeltaInvalid);
        }
    }
    Ok(map)
}

struct FactoryReserveClaimDelta {
    participant: Bytes32,
    asset_type: Option<Bytes32>,
    old_quantity: Amount,
    new_quantity: Amount,
}

fn factory_splice_reserve_claim_delta(update: &FactoryUpdate) -> Result<FactoryReserveClaimDelta> {
    let before = factory_right_map(&update.before)?;
    let after = factory_right_map(&update.after)?;
    let mut found: Option<FactoryReserveClaimDelta> = None;

    for (id, before_right) in &before {
        let after_quantity = after
            .get(id)
            .map(|right| right.quantity)
            .unwrap_or_default();
        if after_quantity == before_right.quantity {
            continue;
        }
        if id.kind != FactoryRightKind::ReserveClaim || found.is_some() {
            return Err(MorphError::FactorySpliceReserveClaimInvalid);
        }
        found = Some(FactoryReserveClaimDelta {
            participant: id.participant,
            asset_type: id.asset_type,
            old_quantity: before_right.quantity,
            new_quantity: after_quantity,
        });
    }

    for (id, after_right) in &after {
        if before.contains_key(id) {
            continue;
        }
        if id.kind != FactoryRightKind::ReserveClaim || found.is_some() {
            return Err(MorphError::FactorySpliceReserveClaimInvalid);
        }
        found = Some(FactoryReserveClaimDelta {
            participant: id.participant,
            asset_type: id.asset_type,
            old_quantity: 0,
            new_quantity: after_right.quantity,
        });
    }

    found.ok_or(MorphError::FactorySpliceReserveClaimInvalid)
}

fn factory_reduced_splice_reserve_claim_delta(
    update: &FactorySingleRightMerkleUpdate,
) -> Result<FactoryReserveClaimDelta> {
    let before = &update.before.right;
    let after = &update.after.right;
    if before.id != after.id
        || before.id.kind != FactoryRightKind::ReserveClaim
        || before.quantity == after.quantity
        || update.touched_participants.len() != 1
        || update.authorised_participants.len() != 1
        || !update.touched_participants.contains(&before.id.participant)
        || !update
            .authorised_participants
            .contains(&before.id.participant)
    {
        return Err(MorphError::FactorySpliceReserveClaimInvalid);
    }
    Ok(FactoryReserveClaimDelta {
        participant: before.id.participant,
        asset_type: before.id.asset_type,
        old_quantity: before.quantity,
        new_quantity: after.quantity,
    })
}

fn reserve_claim_asset(asset_type: &Option<Bytes32>) -> VaultAsset {
    match asset_type {
        Some(asset_type) => VaultAsset::Xudt(*asset_type),
        None => VaultAsset::Ckb,
    }
}

fn validate_state_profile(header: &StateHeader) -> Result<()> {
    if header.protocol_version != MORPH_PROTOCOL_VERSION
        || header.state_layout_version != STATE_LAYOUT_VERSION
        || !matches!(header.mode, Mode::BilateralPlain | Mode::FactoryProof)
        || !matches!(
            header.descriptor_version,
            BILATERAL_CKB_DESCRIPTOR_VERSION | BILATERAL_CKB_XUDT_DESCRIPTOR_VERSION
        )
    {
        return Err(MorphError::UnsupportedProtocolProfile);
    }
    Ok(())
}

fn validate_asset_registry_binding(header: &StateHeader, registry: &AssetRegistry) -> Result<()> {
    if header.asset_registry_commitment != asset_registry_commitment(registry) {
        return Err(MorphError::AssetRegistryCommitmentMismatch);
    }
    Ok(())
}

fn validate_classified_cell(cell: &ClassifiedCell) -> Result<()> {
    if cell.capacity < cell.occupied_capacity {
        return Err(MorphError::InvalidCellClassification);
    }

    let no_business_assets =
        cell.business_ckb == 0 && cell.xudt_amount == 0 && !cell.carries_registered_xudt;
    let shape_is_valid = match cell.class {
        CellClass::ChannelReserve => {
            no_business_assets
                && cell.uses_channel_vault_lock
                && cell.read_by_channel_script
                && cell.contributes_to_conservation
        }
        CellClass::BusinessCkb => {
            cell.business_ckb == cell.capacity - cell.occupied_capacity
                && cell.xudt_amount == 0
                && !cell.carries_registered_xudt
                && cell.uses_channel_vault_lock
                && cell.read_by_channel_script
                && cell.contributes_to_conservation
        }
        CellClass::BusinessXudt(_) => {
            cell.business_ckb == cell.capacity - cell.occupied_capacity
                && cell.carries_registered_xudt
                && cell.uses_channel_vault_lock
                && cell.read_by_channel_script
                && cell.contributes_to_conservation
        }
        CellClass::StateCarrier => {
            no_business_assets
                && !cell.uses_channel_vault_lock
                && cell.read_by_channel_script
                && cell.contributes_to_conservation
        }
        CellClass::Sponsor => {
            if cell.carries_registered_xudt || cell.uses_channel_vault_lock {
                return Err(MorphError::SponsorChangeContaminated);
            }
            no_business_assets && !cell.read_by_channel_script && !cell.contributes_to_conservation
        }
        CellClass::Unrelated => {
            if cell.read_by_channel_script || cell.contributes_to_conservation {
                return Err(MorphError::UnrelatedCellUsed);
            }
            no_business_assets && !cell.uses_channel_vault_lock
        }
    };
    if !shape_is_valid {
        return Err(MorphError::InvalidCellClassification);
    }
    Ok(())
}

fn wire_asset_amounts_are_canonical(amounts: &[VaultAssetAmount], allow_empty: bool) -> bool {
    (allow_empty || !amounts.is_empty())
        && amounts.len() <= 2
        && amounts
            .windows(2)
            .all(|window| window[0].asset < window[1].asset)
}

fn wire_splice_deltas_are_canonical(deltas: &[SpliceAssetDelta]) -> bool {
    !deltas.is_empty()
        && deltas.len() <= 2
        && deltas
            .windows(2)
            .all(|window| window[0].asset < window[1].asset)
}

fn wire_factory_deltas_are_canonical(deltas: &[FactoryVaultDelta]) -> bool {
    !deltas.is_empty()
        && deltas.len() <= 2
        && deltas
            .windows(2)
            .all(|window| window[0].asset < window[1].asset)
}

fn require_same_header_context(old: &StateHeader, new: &StateHeader) -> Result<()> {
    if old.same_context_except_progress(new) {
        Ok(())
    } else {
        Err(MorphError::HeaderContextChanged)
    }
}

fn fold_cells(
    cells: &[ClassifiedCell],
    registry: &AssetRegistry,
    input: bool,
    totals: &mut PartitionTotals,
) -> Result<()> {
    for cell in cells {
        match &cell.class {
            CellClass::ChannelReserve => {
                if input {
                    totals.reserve_in = totals
                        .reserve_in
                        .checked_add(cell.capacity)
                        .ok_or(MorphError::ReserveNotConserved)?;
                } else {
                    totals.reserve_out = totals
                        .reserve_out
                        .checked_add(cell.capacity)
                        .ok_or(MorphError::ReserveNotConserved)?;
                }
            }
            CellClass::BusinessCkb => {
                if input {
                    totals.business_ckb_in = totals
                        .business_ckb_in
                        .checked_add(cell.business_ckb)
                        .ok_or(MorphError::BusinessCkbNotConserved)?;
                } else {
                    totals.business_ckb_out = totals
                        .business_ckb_out
                        .checked_add(cell.business_ckb)
                        .ok_or(MorphError::BusinessCkbNotConserved)?;
                }
            }
            CellClass::BusinessXudt(asset_type) => {
                if !registry.contains(asset_type) {
                    return Err(MorphError::UnregisteredXudtType);
                }
                if input {
                    totals.business_ckb_in = totals
                        .business_ckb_in
                        .checked_add(cell.business_ckb)
                        .ok_or(MorphError::BusinessCkbNotConserved)?;
                } else {
                    totals.business_ckb_out = totals
                        .business_ckb_out
                        .checked_add(cell.business_ckb)
                        .ok_or(MorphError::BusinessCkbNotConserved)?;
                }
                let target = if input {
                    &mut totals.xudt_in
                } else {
                    &mut totals.xudt_out
                };
                let amount = target.entry(*asset_type).or_default();
                *amount = amount
                    .checked_add(cell.xudt_amount)
                    .ok_or(MorphError::XudtNotConserved)?;
            }
            CellClass::Sponsor => {
                if input {
                    totals.sponsor_in = totals
                        .sponsor_in
                        .checked_add(cell.capacity)
                        .ok_or(MorphError::SponsorFeeMismatch)?;
                } else {
                    totals.sponsor_out = totals
                        .sponsor_out
                        .checked_add(cell.capacity)
                        .ok_or(MorphError::SponsorFeeMismatch)?;
                }
            }
            CellClass::StateCarrier => {
                if input {
                    totals.state_carrier_in = totals
                        .state_carrier_in
                        .checked_add(cell.capacity)
                        .ok_or(MorphError::StateCarrierNotConserved)?;
                } else {
                    totals.state_carrier_out = totals
                        .state_carrier_out
                        .checked_add(cell.capacity)
                        .ok_or(MorphError::StateCarrierNotConserved)?;
                }
            }
            CellClass::Unrelated => {}
        }
    }
    Ok(())
}
