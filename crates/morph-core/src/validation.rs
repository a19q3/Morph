use std::collections::BTreeMap;

use k256::ecdsa::signature::hazmat::PrehashVerifier;
use k256::ecdsa::{Signature, VerifyingKey};
use thiserror::Error;

use crate::hash::{blake2b256, participants_commitment};
use crate::types::*;

const FACTORY_RIGHT_KEY_DOMAIN_V1: &[u8] = b"CKB_MORPH_FACTORY_RIGHT_KEY_V1";
const FACTORY_RIGHT_LEAF_DOMAIN_V1: &[u8] = b"CKB_MORPH_FACTORY_RIGHT_LEAF_V1";
const FACTORY_RIGHT_NODE_DOMAIN_V1: &[u8] = b"CKB_MORPH_FACTORY_RIGHT_NODE_V1";
const FACTORY_RIGHT_EMPTY_DOMAIN_V1: &[u8] = b"CKB_MORPH_FACTORY_RIGHT_EMPTY_V1";
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
    #[error("participant set does not match signed state header")]
    ParticipantSetMismatch,
    #[error("participant signature encoding is invalid")]
    ParticipantSignatureEncoding,
    #[error("referenced funding anchor does not match signed state header")]
    FundingAnchorMismatch,
    #[error("output capacity is below occupied capacity")]
    OutputBelowOccupiedCapacity,
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
    #[error("sponsor partition does not exactly pay the transaction fee")]
    SponsorFeeMismatch,
    #[error("sponsor output carries channel business asset or vault lock")]
    SponsorChangeContaminated,
    #[error("sponsor policy channel mismatch")]
    SponsorChannelMismatch,
    #[error("sponsor policy state number outside authorised range")]
    SponsorStateOutOfRange,
    #[error("sponsor policy expired")]
    SponsorPolicyExpired,
    #[error("sponsor source is not authorised")]
    SponsorSourceMismatch,
    #[error("sponsor change lock mismatch")]
    SponsorChangeLockMismatch,
    #[error("sponsor fee exceeds per-transaction limit")]
    SponsorFeeTooHigh,
    #[error("sponsor total budget exceeded")]
    SponsorBudgetExceeded,
    #[error("sponsor policy may only pay publication or challenge transactions")]
    SponsorOperationNotAllowed,
    #[error("vault operation is not allowed")]
    VaultOperationNotAllowed,
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
}

pub type Result<T> = std::result::Result<T, MorphError>;

pub fn validate_state_transition(
    old: &StateCell,
    new: &StateCell,
    ctx: &StateTransitionContext,
) -> Result<()> {
    if !old.capacity_sufficient() || !new.capacity_sufficient() {
        return Err(MorphError::StateCapacityInsufficient);
    }
    if new.header.state_number <= old.header.state_number {
        return Err(MorphError::NonMonotonicStateNumber);
    }
    if new.header.phase != Phase::Settling {
        return Err(MorphError::NewStateNotSettling);
    }
    require_same_header_context(&old.header, &new.header)?;
    validate_state_authorization(&new.header, &ctx.authorization)?;
    if ctx.referenced_funding_anchor != new.header.funding_anchor {
        return Err(MorphError::FundingAnchorMismatch);
    }
    validate_partition_conservation(&ctx.partition, &ctx.asset_registry)?;
    Ok(())
}

pub fn validate_state_authorization(
    header: &StateHeader,
    authorization: &StateAuthorization,
) -> Result<()> {
    if authorization.threshold == 0
        || authorization.signatures.len() < authorization.threshold as usize
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

pub fn validate_sponsor_policy(policy: &SponsorPolicy, spend: &SponsorSpend) -> Result<()> {
    if spend.channel_id != policy.channel_id {
        return Err(MorphError::SponsorChannelMismatch);
    }
    if spend.state_number < policy.min_state_number || spend.state_number > policy.max_state_number
    {
        return Err(MorphError::SponsorStateOutOfRange);
    }
    if spend.now > policy.expiry {
        return Err(MorphError::SponsorPolicyExpired);
    }
    if spend.sponsor_source != policy.allowed_sponsor_source {
        return Err(MorphError::SponsorSourceMismatch);
    }
    if spend.change_lock != policy.change_lock {
        return Err(MorphError::SponsorChangeLockMismatch);
    }
    if spend.fee > policy.max_fee_per_tx {
        return Err(MorphError::SponsorFeeTooHigh);
    }
    if policy.already_spent.saturating_add(spend.fee) > policy.max_total_fee {
        return Err(MorphError::SponsorBudgetExceeded);
    }
    if !spend.operation.is_publication_or_challenge() {
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
    bytes.extend_from_slice(FACTORY_RIGHT_KEY_DOMAIN_V1);
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
    bytes.extend_from_slice(FACTORY_RIGHT_LEAF_DOMAIN_V1);
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
    match spend.operation {
        ChannelOperation::Finalise
        | ChannelOperation::CooperativeClose
        | ChannelOperation::Splice
        | ChannelOperation::Materialise => {}
        ChannelOperation::Publish | ChannelOperation::Supersede => {
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
        if matches!(cell.class, CellClass::Unrelated)
            && (cell.read_by_channel_script || cell.contributes_to_conservation)
        {
            return Err(MorphError::UnrelatedCellUsed);
        }
    }

    let mut totals = PartitionTotals {
        reserve_in: 0,
        reserve_out: 0,
        business_ckb_in: 0,
        business_ckb_out: 0,
        xudt_in: BTreeMap::new(),
        xudt_out: BTreeMap::new(),
        sponsor_in: 0,
        sponsor_out: 0,
    };

    fold_cells(&tx.inputs, registry, true, &mut totals)?;
    fold_cells(&tx.outputs, registry, false, &mut totals)?;

    if totals
        .reserve_out
        .saturating_add(tx.authorised_reserve_refund)
        != totals.reserve_in
    {
        return Err(MorphError::ReserveNotConserved);
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
    if totals.sponsor_in.saturating_sub(totals.sponsor_out) != tx.tx_fee {
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
    out[0] = blake2b256(FACTORY_RIGHT_EMPTY_DOMAIN_V1);
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
    bytes.extend_from_slice(FACTORY_RIGHT_NODE_DOMAIN_V1);
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

fn require_same_header_context(old: &StateHeader, new: &StateHeader) -> Result<()> {
    let same = old.protocol_version == new.protocol_version
        && old.chain_id == new.chain_id
        && old.signature_scheme_id == new.signature_scheme_id
        && old.channel_id == new.channel_id
        && old.funding_anchor == new.funding_anchor
        && old.mode == new.mode
        && old.participants_commitment == new.participants_commitment
        && old.asset_registry_commitment == new.asset_registry_commitment
        && old.settlement_descriptor_commitment == new.settlement_descriptor_commitment
        && old.descriptor_version == new.descriptor_version
        && old.challenge_policy_commitment == new.challenge_policy_commitment
        && old.state_layout_version == new.state_layout_version;
    if same {
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
                    totals.reserve_in = totals.reserve_in.saturating_add(cell.capacity);
                } else {
                    totals.reserve_out = totals.reserve_out.saturating_add(cell.capacity);
                }
            }
            CellClass::BusinessCkb => {
                if input {
                    totals.business_ckb_in =
                        totals.business_ckb_in.saturating_add(cell.business_ckb);
                } else {
                    totals.business_ckb_out =
                        totals.business_ckb_out.saturating_add(cell.business_ckb);
                }
            }
            CellClass::BusinessXudt(asset_type) => {
                if !registry.contains(asset_type) {
                    return Err(MorphError::UnregisteredXudtType);
                }
                let target = if input {
                    &mut totals.xudt_in
                } else {
                    &mut totals.xudt_out
                };
                let amount = target.entry(*asset_type).or_default();
                *amount = amount.saturating_add(cell.xudt_amount);
            }
            CellClass::Sponsor => {
                if input {
                    totals.sponsor_in = totals.sponsor_in.saturating_add(cell.capacity);
                } else {
                    totals.sponsor_out = totals.sponsor_out.saturating_add(cell.capacity);
                }
            }
            CellClass::StateCarrier | CellClass::Unrelated => {}
        }
    }
    Ok(())
}
