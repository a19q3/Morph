//! Native bilateral ChannelBackend built on the existing Morph State/Vault
//! model. It does not introduce a second channel state machine.

use std::collections::{BTreeMap, BTreeSet};

use morph_script_common::{
    BILATERAL_CKB_DESCRIPTOR_LEN, BILATERAL_CKB_XUDT_DESCRIPTOR_LEN,
    BilateralCkbSettlementDescriptor, BilateralCkbXudtSettlementDescriptor,
    settlement_descriptor_commitment,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::agent::{
    AgentAsset, BackendSettlementEvidence, MorphStateSettlementEvidence, PaymentIntent,
};
use crate::validation::{MorphError, validate_state_authorization, validate_state_transition};
use crate::{
    AssetRegistry, Bytes32, Phase, StateAuthorization, StateCell, StateTransitionContext,
    blake2b256,
};

const PREPARED_PAYMENT_DOMAIN: &[u8] = b"CKB_MORPH_PREPARED_PAYMENT_V1";
const SETTLEMENT_ID_DOMAIN: &[u8] = b"CKB_MORPH_BACKEND_SETTLEMENT_V1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChannelParticipant {
    pub node_id: Bytes32,
    pub settlement_lock_hash: Bytes32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PreparedPayment {
    pub prepared_id: Bytes32,
    pub intent: PaymentIntent,
    pub base_state_number: u64,
    pub prepared_at_unix: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum BackendPaymentState {
    Prepared(PreparedPayment),
    Settled(BackendSettlementEvidence),
    Cancelled(BackendSettlementEvidence),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MorphSignedStateUpdate {
    pub next_state: StateCell,
    pub context: StateTransitionContext,
    /// Exact descriptor whose commitment is carried by `next_state`.
    pub settlement_descriptor: Vec<u8>,
}

/// Interface consumed by Morph Agent and routing adapters. Implementations are
/// required to return canonical backend evidence rather than an RPC success
/// boolean.
pub trait ChannelBackend {
    fn backend_id(&self) -> &'static str;
    fn channel_id(&self) -> Bytes32;
    fn funding_context_id(&self) -> Bytes32;
    fn current_state(&self) -> &StateCell;
    fn payment_state(&self, intent_id: &Bytes32) -> Option<&BackendPaymentState>;
    fn prepare_payment(
        &mut self,
        intent: PaymentIntent,
        now_unix: u64,
    ) -> BackendResult<PreparedPayment>;
    fn commit_payment(
        &mut self,
        prepared_id: &Bytes32,
        update: MorphSignedStateUpdate,
        committed_at_unix: u64,
    ) -> BackendResult<BackendSettlementEvidence>;
    fn cancel_payment(
        &mut self,
        prepared_id: &Bytes32,
        cancelled_at_unix: u64,
    ) -> BackendResult<BackendSettlementEvidence>;
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MorphBilateralChannelBackend {
    current_state: StateCell,
    current_authorization: StateAuthorization,
    current_settlement_descriptor: Vec<u8>,
    participants: [ChannelParticipant; 2],
    asset_registry: AssetRegistry,
    verified_rgbpp_bindings: BTreeSet<Bytes32>,
    payments: BTreeMap<Bytes32, BackendPaymentState>,
    idempotency_index: BTreeMap<Bytes32, Bytes32>,
}

impl MorphBilateralChannelBackend {
    pub fn new(
        current_state: StateCell,
        current_authorization: StateAuthorization,
        current_settlement_descriptor: Vec<u8>,
        participants: [ChannelParticipant; 2],
        asset_registry: AssetRegistry,
        verified_rgbpp_bindings: BTreeSet<Bytes32>,
    ) -> BackendResult<Self> {
        if !matches!(current_state.header.phase, Phase::Active | Phase::Settling)
            || participants[0].node_id == participants[1].node_id
            || participants[0].settlement_lock_hash == participants[1].settlement_lock_hash
            || participants.iter().any(|participant| {
                is_zero(&participant.node_id) || is_zero(&participant.settlement_lock_hash)
            })
        {
            return Err(BackendError::InvalidChannel);
        }
        validate_state_authorization(&current_state.header, &current_authorization)?;
        validate_participant_identities(&current_authorization, &participants)?;
        validate_descriptor_commitment(&current_state, &current_settlement_descriptor)?;
        validate_descriptor_locks(&current_settlement_descriptor, &participants)?;
        if verified_rgbpp_bindings.iter().any(is_zero) {
            return Err(BackendError::InvalidRgbppEvidence);
        }
        Ok(Self {
            current_state,
            current_authorization,
            current_settlement_descriptor,
            participants,
            asset_registry,
            verified_rgbpp_bindings,
            payments: BTreeMap::new(),
            idempotency_index: BTreeMap::new(),
        })
    }

    pub fn current_authorization(&self) -> &StateAuthorization {
        &self.current_authorization
    }

    pub fn current_settlement_descriptor(&self) -> &[u8] {
        &self.current_settlement_descriptor
    }

    pub fn register_verified_rgbpp_binding(&mut self, commitment: Bytes32) -> BackendResult<()> {
        if is_zero(&commitment) {
            return Err(BackendError::InvalidRgbppEvidence);
        }
        self.verified_rgbpp_bindings.insert(commitment);
        Ok(())
    }

    fn prepared_by_id(&self, prepared_id: &Bytes32) -> BackendResult<&PreparedPayment> {
        self.payments
            .values()
            .find_map(|state| match state {
                BackendPaymentState::Prepared(prepared) if &prepared.prepared_id == prepared_id => {
                    Some(prepared)
                }
                _ => None,
            })
            .ok_or(BackendError::PreparedPaymentNotFound)
    }

    fn validate_intent_asset(&self, intent: &PaymentIntent) -> BackendResult<()> {
        let ckb_genesis_hash = match &intent.asset {
            AgentAsset::Ckb { ckb_genesis_hash }
            | AgentAsset::Xudt {
                ckb_genesis_hash, ..
            } => ckb_genesis_hash,
            AgentAsset::Rgbpp(asset) => &asset.ckb_genesis_hash,
        };
        if ckb_genesis_hash != &self.current_state.header.chain_id {
            return Err(BackendError::WrongNetwork);
        }
        match &intent.asset {
            AgentAsset::Ckb { .. } => {}
            AgentAsset::Xudt {
                type_script_hash, ..
            } => {
                if !self.asset_registry.contains(type_script_hash) {
                    return Err(BackendError::AssetNotRegistered);
                }
            }
            AgentAsset::Rgbpp(asset) => {
                if !self.asset_registry.contains(&asset.xudt_type_script_hash) {
                    return Err(BackendError::AssetNotRegistered);
                }
                let commitment = intent
                    .required_rgbpp_proof_commitment
                    .ok_or(BackendError::InvalidRgbppEvidence)?;
                if !self.verified_rgbpp_bindings.contains(&commitment) {
                    return Err(BackendError::InvalidRgbppEvidence);
                }
            }
        }
        Ok(())
    }
}

impl ChannelBackend for MorphBilateralChannelBackend {
    fn backend_id(&self) -> &'static str {
        "morph-bilateral-v1"
    }

    fn channel_id(&self) -> Bytes32 {
        self.current_state.header.channel_id
    }

    fn funding_context_id(&self) -> Bytes32 {
        self.current_state.header.funding_context_id()
    }

    fn current_state(&self) -> &StateCell {
        &self.current_state
    }

    fn payment_state(&self, intent_id: &Bytes32) -> Option<&BackendPaymentState> {
        self.payments.get(intent_id)
    }

    fn prepare_payment(
        &mut self,
        intent: PaymentIntent,
        now_unix: u64,
    ) -> BackendResult<PreparedPayment> {
        intent.validate(now_unix)?;
        if !matches!(
            self.current_state.header.phase,
            Phase::Active | Phase::Settling
        ) {
            return Err(BackendError::InvalidChannel);
        }
        let binding = intent
            .channel_binding
            .as_ref()
            .ok_or(BackendError::MissingChannelBinding)?;
        if binding.channel_id != self.channel_id()
            || binding.funding_context_id != self.funding_context_id()
        {
            return Err(BackendError::WrongChannelBinding);
        }
        self.validate_intent_asset(&intent)?;

        if let Some(existing_intent_id) = self.idempotency_index.get(&intent.idempotency_key) {
            if existing_intent_id != &intent.intent_id {
                return Err(BackendError::IdempotencyConflict);
            }
            return match self.payments.get(existing_intent_id) {
                Some(BackendPaymentState::Prepared(prepared)) => Ok(prepared.clone()),
                _ => Err(BackendError::AlreadyTerminal),
            };
        }
        // The current bilateral wire profile signs one complete successor
        // descriptor at a time. Multiple simultaneous reservations would make
        // their expected descriptors mutually incompatible.
        if self
            .payments
            .values()
            .any(|state| matches!(state, BackendPaymentState::Prepared(_)))
        {
            return Err(BackendError::ConcurrentPreparationUnsupported);
        }
        let mut raw = Vec::with_capacity(PREPARED_PAYMENT_DOMAIN.len() + 72);
        raw.extend_from_slice(PREPARED_PAYMENT_DOMAIN);
        raw.extend_from_slice(&intent.intent_id);
        raw.extend_from_slice(&self.current_state.header.state_number.to_le_bytes());
        raw.extend_from_slice(&self.current_state.header.signing_digest());
        let prepared = PreparedPayment {
            prepared_id: blake2b256(&raw),
            intent: intent.clone(),
            base_state_number: self.current_state.header.state_number,
            prepared_at_unix: now_unix,
        };
        self.idempotency_index
            .insert(intent.idempotency_key, intent.intent_id);
        self.payments.insert(
            intent.intent_id,
            BackendPaymentState::Prepared(prepared.clone()),
        );
        Ok(prepared)
    }

    fn commit_payment(
        &mut self,
        prepared_id: &Bytes32,
        update: MorphSignedStateUpdate,
        committed_at_unix: u64,
    ) -> BackendResult<BackendSettlementEvidence> {
        let prepared = self.prepared_by_id(prepared_id)?.clone();
        if committed_at_unix < prepared.prepared_at_unix
            || committed_at_unix >= prepared.intent.expires_at_unix
        {
            return Err(BackendError::InvalidCommitTime);
        }
        if prepared.base_state_number != self.current_state.header.state_number {
            return Err(BackendError::StalePreparation);
        }
        let binding = prepared
            .intent
            .channel_binding
            .as_ref()
            .ok_or(BackendError::MissingChannelBinding)?;
        if update.next_state.header.settlement_descriptor_commitment
            != binding.expected_settlement_descriptor_commitment
        {
            return Err(BackendError::WrongSettlementDescriptor);
        }
        validate_descriptor_commitment(&update.next_state, &update.settlement_descriptor)?;
        validate_descriptor_locks(&update.settlement_descriptor, &self.participants)?;
        validate_payment_delta(
            &self.current_settlement_descriptor,
            &update.settlement_descriptor,
            &self.participants,
            &prepared.intent,
        )?;
        if update.context.asset_registry != self.asset_registry {
            return Err(BackendError::AssetRegistryMismatch);
        }
        validate_participant_identities(&update.context.authorization, &self.participants)?;
        validate_state_transition(&self.current_state, &update.next_state, &update.context)?;

        let state_commitment = update.next_state.header.signing_digest();
        let mut settlement_raw = Vec::with_capacity(SETTLEMENT_ID_DOMAIN.len() + 96);
        settlement_raw.extend_from_slice(SETTLEMENT_ID_DOMAIN);
        settlement_raw.extend_from_slice(&prepared.intent.intent_id);
        settlement_raw.extend_from_slice(&state_commitment);
        settlement_raw.extend_from_slice(prepared_id);
        let evidence = BackendSettlementEvidence {
            provider_id: self.backend_id().to_string(),
            settlement_id: blake2b256(&settlement_raw),
            opaque_commitment: state_commitment,
            morph_state: Some(MorphStateSettlementEvidence {
                channel_id: update.next_state.header.channel_id,
                funding_context_id: update.next_state.header.funding_context_id(),
                state_number: update.next_state.header.state_number,
                state_header_commitment: state_commitment,
                settlement_descriptor_commitment: update
                    .next_state
                    .header
                    .settlement_descriptor_commitment,
            }),
            ckb_anchor: None,
            rgbpp_proof_commitment: prepared.intent.required_rgbpp_proof_commitment,
            failure_code: None,
        };
        self.current_authorization = update.context.authorization;
        self.current_settlement_descriptor = update.settlement_descriptor;
        self.current_state = update.next_state;
        self.payments.insert(
            prepared.intent.intent_id,
            BackendPaymentState::Settled(evidence.clone()),
        );
        Ok(evidence)
    }

    fn cancel_payment(
        &mut self,
        prepared_id: &Bytes32,
        cancelled_at_unix: u64,
    ) -> BackendResult<BackendSettlementEvidence> {
        let prepared = self.prepared_by_id(prepared_id)?.clone();
        if cancelled_at_unix < prepared.prepared_at_unix {
            return Err(BackendError::InvalidCancellationTime);
        }
        let mut raw = Vec::with_capacity(SETTLEMENT_ID_DOMAIN.len() + 81);
        raw.extend_from_slice(SETTLEMENT_ID_DOMAIN);
        raw.extend_from_slice(&prepared.intent.intent_id);
        raw.extend_from_slice(prepared_id);
        raw.extend_from_slice(&cancelled_at_unix.to_le_bytes());
        raw.extend_from_slice(b"cancelled");
        let commitment = blake2b256(&raw);
        let evidence = BackendSettlementEvidence {
            provider_id: self.backend_id().to_string(),
            settlement_id: commitment,
            opaque_commitment: commitment,
            morph_state: None,
            ckb_anchor: None,
            rgbpp_proof_commitment: None,
            failure_code: None,
        };
        self.payments.insert(
            prepared.intent.intent_id,
            BackendPaymentState::Cancelled(evidence.clone()),
        );
        Ok(evidence)
    }
}

fn validate_descriptor_commitment(state: &StateCell, descriptor: &[u8]) -> BackendResult<()> {
    parse_descriptor(descriptor)?;
    if settlement_descriptor_commitment(descriptor) != state.header.settlement_descriptor_commitment
    {
        return Err(BackendError::WrongSettlementDescriptor);
    }
    Ok(())
}

fn validate_descriptor_locks(
    descriptor: &[u8],
    participants: &[ChannelParticipant; 2],
) -> BackendResult<()> {
    let expected = [
        participants[0].settlement_lock_hash,
        participants[1].settlement_lock_hash,
    ];
    let actual = descriptor_locks(descriptor)?;
    if !expected.iter().all(|lock| actual.contains(lock)) {
        return Err(BackendError::WrongSettlementParticipants);
    }
    Ok(())
}

fn validate_payment_delta(
    old_descriptor: &[u8],
    new_descriptor: &[u8],
    participants: &[ChannelParticipant; 2],
    intent: &PaymentIntent,
) -> BackendResult<()> {
    let payer = participants
        .iter()
        .find(|participant| participant.node_id == intent.payer)
        .ok_or(BackendError::WrongSettlementParticipants)?;
    let payee = participants
        .iter()
        .find(|participant| participant.node_id == intent.payee)
        .ok_or(BackendError::WrongSettlementParticipants)?;
    let old = descriptor_amounts(old_descriptor, &intent.asset)?;
    let new = descriptor_amounts(new_descriptor, &intent.asset)?;
    let locks = descriptor_locks(old_descriptor)?;
    let payer_index = locks
        .iter()
        .position(|lock| lock == &payer.settlement_lock_hash)
        .ok_or(BackendError::WrongSettlementParticipants)?;
    let payee_index = locks
        .iter()
        .position(|lock| lock == &payee.settlement_lock_hash)
        .ok_or(BackendError::WrongSettlementParticipants)?;
    if matches!(
        &intent.asset,
        AgentAsset::Xudt { .. } | AgentAsset::Rgbpp(_)
    ) && descriptor_capacities(old_descriptor)? != descriptor_capacities(new_descriptor)?
    {
        return Err(BackendError::UnrelatedAssetDelta);
    }
    let old_total = old[0]
        .checked_add(old[1])
        .ok_or(BackendError::PaymentDeltaMismatch)?;
    let new_total = new[0]
        .checked_add(new[1])
        .ok_or(BackendError::PaymentDeltaMismatch)?;
    if old[payer_index].checked_sub(intent.amount) != Some(new[payer_index])
        || old[payee_index].checked_add(intent.amount) != Some(new[payee_index])
        || old_total != new_total
    {
        return Err(BackendError::PaymentDeltaMismatch);
    }
    Ok(())
}

pub(crate) fn validate_participant_identities(
    authorization: &StateAuthorization,
    participants: &[ChannelParticipant; 2],
) -> BackendResult<()> {
    if authorization.threshold != 2 || authorization.signatures.len() != 2 {
        return Err(BackendError::WrongSettlementParticipants);
    }
    let mut signed_node_ids = authorization
        .signatures
        .iter()
        .map(|signature| blake2b256(&signature.pubkey_sec1))
        .collect::<Vec<_>>();
    signed_node_ids.sort();
    let mut configured_node_ids = participants
        .iter()
        .map(|participant| participant.node_id)
        .collect::<Vec<_>>();
    configured_node_ids.sort();
    if signed_node_ids != configured_node_ids {
        return Err(BackendError::WrongSettlementParticipants);
    }
    Ok(())
}

enum ParsedDescriptor<'a> {
    Ckb(BilateralCkbSettlementDescriptor<'a>),
    Xudt(BilateralCkbXudtSettlementDescriptor<'a>),
}

fn parse_descriptor(raw: &[u8]) -> BackendResult<ParsedDescriptor<'_>> {
    match raw.len() {
        BILATERAL_CKB_DESCRIPTOR_LEN => BilateralCkbSettlementDescriptor::parse(raw)
            .map(ParsedDescriptor::Ckb)
            .map_err(|_| BackendError::InvalidSettlementDescriptor),
        BILATERAL_CKB_XUDT_DESCRIPTOR_LEN => BilateralCkbXudtSettlementDescriptor::parse(raw)
            .map(ParsedDescriptor::Xudt)
            .map_err(|_| BackendError::InvalidSettlementDescriptor),
        _ => Err(BackendError::InvalidSettlementDescriptor),
    }
}

fn descriptor_locks(raw: &[u8]) -> BackendResult<[Bytes32; 2]> {
    let parsed = parse_descriptor(raw)?;
    let lock = |index| -> BackendResult<Bytes32> {
        let bytes = match &parsed {
            ParsedDescriptor::Ckb(descriptor) => descriptor.lock_hash(index),
            ParsedDescriptor::Xudt(descriptor) => descriptor.lock_hash(index),
        };
        bytes
            .try_into()
            .map_err(|_| BackendError::InvalidSettlementDescriptor)
    };
    Ok([lock(0)?, lock(1)?])
}

fn descriptor_amounts(raw: &[u8], asset: &AgentAsset) -> BackendResult<[u128; 2]> {
    match (parse_descriptor(raw)?, asset) {
        (ParsedDescriptor::Ckb(descriptor), AgentAsset::Ckb { .. }) => Ok([
            u128::from(descriptor.capacity(0)),
            u128::from(descriptor.capacity(1)),
        ]),
        (
            ParsedDescriptor::Xudt(descriptor),
            AgentAsset::Xudt {
                type_script_hash, ..
            },
        ) => {
            if descriptor.xudt_type_hash() != type_script_hash {
                return Err(BackendError::AssetMismatch);
            }
            Ok([descriptor.xudt_amount(0), descriptor.xudt_amount(1)])
        }
        (ParsedDescriptor::Xudt(descriptor), AgentAsset::Rgbpp(asset)) => {
            if descriptor.xudt_type_hash() != asset.xudt_type_script_hash {
                return Err(BackendError::AssetMismatch);
            }
            Ok([descriptor.xudt_amount(0), descriptor.xudt_amount(1)])
        }
        _ => Err(BackendError::AssetMismatch),
    }
}

fn descriptor_capacities(raw: &[u8]) -> BackendResult<[u64; 2]> {
    match parse_descriptor(raw)? {
        ParsedDescriptor::Ckb(descriptor) => Ok([descriptor.capacity(0), descriptor.capacity(1)]),
        ParsedDescriptor::Xudt(descriptor) => Ok([descriptor.capacity(0), descriptor.capacity(1)]),
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum BackendError {
    #[error("Morph bilateral channel is invalid or not active")]
    InvalidChannel,
    #[error("payment intent does not bind a Morph channel")]
    MissingChannelBinding,
    #[error("payment intent binds another channel or funding context")]
    WrongChannelBinding,
    #[error("payment asset is not registered in the channel")]
    AssetNotRegistered,
    #[error("payment asset belongs to another CKB network")]
    WrongNetwork,
    #[error("RGB++ proof commitment is missing or not verified")]
    InvalidRgbppEvidence,
    #[error("another intent already uses this idempotency key")]
    IdempotencyConflict,
    #[error("payment intent is already terminal")]
    AlreadyTerminal,
    #[error("current bilateral profile permits one prepared successor at a time")]
    ConcurrentPreparationUnsupported,
    #[error("prepared payment was not found")]
    PreparedPaymentNotFound,
    #[error("prepared payment is stale relative to the current signed state")]
    StalePreparation,
    #[error("settlement descriptor is malformed")]
    InvalidSettlementDescriptor,
    #[error("settlement descriptor commitment does not match the payment or State header")]
    WrongSettlementDescriptor,
    #[error("settlement descriptor does not pay the channel participants")]
    WrongSettlementParticipants,
    #[error("settlement descriptor asset does not match the payment asset")]
    AssetMismatch,
    #[error("settlement descriptor delta does not match the payment amount and direction")]
    PaymentDeltaMismatch,
    #[error("settlement descriptor changes an asset outside the payment intent")]
    UnrelatedAssetDelta,
    #[error("state update uses a different asset registry")]
    AssetRegistryMismatch,
    #[error("cancellation time predates preparation")]
    InvalidCancellationTime,
    #[error("commit time predates preparation or is at/after intent expiry")]
    InvalidCommitTime,
    #[error(transparent)]
    Agent(#[from] crate::agent::AgentError),
    #[error(transparent)]
    Morph(#[from] MorphError),
}

pub type BackendResult<T> = Result<T, BackendError>;

fn is_zero(value: &Bytes32) -> bool {
    value.iter().all(|byte| *byte == 0)
}

#[cfg(test)]
mod tests {
    use k256::ecdsa::signature::hazmat::PrehashSigner;
    use k256::ecdsa::{Signature, SigningKey};
    use morph_script_common::{
        BILATERAL_CKB_DESCRIPTOR_OUTPUT_COUNT, BILATERAL_CKB_DESCRIPTOR_VERSION,
        BILATERAL_CKB_XUDT_DESCRIPTOR_ASSET_COUNT, BILATERAL_CKB_XUDT_DESCRIPTOR_VERSION,
    };

    use super::*;
    use crate::agent::{HttpOperation, MorphChannelPaymentBinding, PaymentHashAlgorithm};
    use crate::{ClassifiedCell, Mode, ParticipantSignature, PartitionedTransaction};

    fn descriptor(first_lock: Bytes32, first: u64, second_lock: Bytes32, second: u64) -> Vec<u8> {
        let mut entries = [(first_lock, first), (second_lock, second)];
        entries.sort_by_key(|entry| entry.0);
        let mut raw = vec![0; BILATERAL_CKB_DESCRIPTOR_LEN];
        raw[0..2].copy_from_slice(&BILATERAL_CKB_DESCRIPTOR_VERSION.to_le_bytes());
        raw[2] = BILATERAL_CKB_DESCRIPTOR_OUTPUT_COUNT;
        for (index, (lock, capacity)) in entries.iter().enumerate() {
            let offset = 4 + index * 40;
            raw[offset..offset + 32].copy_from_slice(lock);
            raw[offset + 32..offset + 40].copy_from_slice(&capacity.to_le_bytes());
        }
        raw
    }

    fn xudt_descriptor(
        type_hash: Bytes32,
        first_lock: Bytes32,
        first: u128,
        second_lock: Bytes32,
        second: u128,
    ) -> Vec<u8> {
        let mut entries = [(first_lock, first), (second_lock, second)];
        entries.sort_by_key(|entry| entry.0);
        let mut raw = vec![0; BILATERAL_CKB_XUDT_DESCRIPTOR_LEN];
        raw[0..2].copy_from_slice(&BILATERAL_CKB_XUDT_DESCRIPTOR_VERSION.to_le_bytes());
        raw[2] = BILATERAL_CKB_DESCRIPTOR_OUTPUT_COUNT;
        raw[3] = BILATERAL_CKB_XUDT_DESCRIPTOR_ASSET_COUNT;
        raw[4..36].copy_from_slice(&type_hash);
        for (index, (lock, amount)) in entries.iter().enumerate() {
            let offset = 36 + index * 56;
            raw[offset..offset + 32].copy_from_slice(lock);
            raw[offset + 32..offset + 40].copy_from_slice(&1_000u64.to_le_bytes());
            raw[offset + 40..offset + 56].copy_from_slice(&amount.to_le_bytes());
        }
        raw
    }

    fn authorization(header: &crate::StateHeader, keys: &[SigningKey; 2]) -> StateAuthorization {
        let mut signatures = keys
            .iter()
            .map(|key| {
                let signature: Signature = key.sign_prehash(&header.signing_digest()).unwrap();
                ParticipantSignature {
                    pubkey_sec1: key
                        .verifying_key()
                        .to_encoded_point(true)
                        .as_bytes()
                        .to_vec(),
                    signature: signature.to_bytes().to_vec(),
                }
            })
            .collect::<Vec<_>>();
        signatures.sort_by(|left, right| left.pubkey_sec1.cmp(&right.pubkey_sec1));
        StateAuthorization {
            threshold: 2,
            signatures,
        }
    }

    fn fixture() -> (
        MorphBilateralChannelBackend,
        [SigningKey; 2],
        [ChannelParticipant; 2],
    ) {
        let keys = [
            SigningKey::from_slice(&[1; 32]).unwrap(),
            SigningKey::from_slice(&[2; 32]).unwrap(),
        ];
        let mut pubkeys = keys
            .iter()
            .map(|key| {
                key.verifying_key()
                    .to_encoded_point(true)
                    .as_bytes()
                    .to_vec()
            })
            .collect::<Vec<_>>();
        pubkeys.sort();
        let participants_commitment =
            crate::participants_commitment(2, &[pubkeys[0].as_slice(), pubkeys[1].as_slice()]);
        let participants = [
            ChannelParticipant {
                node_id: blake2b256(keys[0].verifying_key().to_encoded_point(true).as_bytes()),
                settlement_lock_hash: [21; 32],
            },
            ChannelParticipant {
                node_id: blake2b256(keys[1].verifying_key().to_encoded_point(true).as_bytes()),
                settlement_lock_hash: [22; 32],
            },
        ];
        let descriptor = descriptor([21; 32], 6_000, [22; 32], 4_000);
        let state = StateCell {
            header: crate::StateHeader {
                protocol_version: 1,
                chain_id: [3; 32],
                signature_scheme_id: 1,
                channel_id: [4; 32],
                funding_epoch: 0,
                funding_anchor: [5; 32],
                vault_set_commitment: [6; 32],
                state_number: 0,
                mode: Mode::BilateralPlain,
                phase: Phase::Active,
                participants_commitment,
                asset_registry_commitment: [7; 32],
                settlement_descriptor_commitment: settlement_descriptor_commitment(&descriptor),
                descriptor_version: BILATERAL_CKB_DESCRIPTOR_VERSION,
                vault_materialisation_root: [8; 32],
                vault_outpoint_commitment: [10; 32],
                challenge_policy_commitment: [9; 32],
                state_layout_version: 2,
            },
            capacity: 1_000,
            occupied_capacity: 1_000,
        };
        let auth = authorization(&state.header, &keys);
        (
            MorphBilateralChannelBackend::new(
                state,
                auth,
                descriptor,
                participants.clone(),
                AssetRegistry {
                    xudt_types: BTreeSet::new(),
                },
                BTreeSet::new(),
            )
            .unwrap(),
            keys,
            participants,
        )
    }

    fn intent(backend: &MorphBilateralChannelBackend) -> PaymentIntent {
        let next_descriptor = descriptor([21; 32], 5_500, [22; 32], 4_500);
        let mut intent = PaymentIntent {
            intent_id: [0; 32],
            payer: backend.participants[0].node_id,
            payee: backend.participants[1].node_id,
            asset: AgentAsset::Ckb {
                ckb_genesis_hash: [3; 32],
            },
            amount: 500,
            payment_hash: [31; 32],
            hash_algorithm: PaymentHashAlgorithm::Sha256,
            resource: "/compute/result".to_string(),
            operation: HttpOperation::Get,
            nonce: [32; 32],
            idempotency_key: [33; 32],
            created_at_unix: 100,
            expires_at_unix: 200,
            required_rgbpp_proof_commitment: None,
            channel_binding: Some(MorphChannelPaymentBinding {
                channel_id: backend.channel_id(),
                funding_context_id: backend.funding_context_id(),
                expected_settlement_descriptor_commitment: settlement_descriptor_commitment(
                    &next_descriptor,
                ),
            }),
        };
        intent.intent_id = intent.derive_id().unwrap();
        intent
    }

    fn update(
        backend: &MorphBilateralChannelBackend,
        keys: &[SigningKey; 2],
        descriptor: Vec<u8>,
    ) -> MorphSignedStateUpdate {
        let mut next = backend.current_state.clone();
        next.header.state_number += 1;
        next.header.phase = Phase::Settling;
        next.header.settlement_descriptor_commitment =
            settlement_descriptor_commitment(&descriptor);
        let authorization = authorization(&next.header, keys);
        MorphSignedStateUpdate {
            next_state: next,
            context: StateTransitionContext {
                referenced_funding_anchor: backend.current_state.header.funding_anchor,
                authorization,
                asset_registry: AssetRegistry {
                    xudt_types: BTreeSet::new(),
                },
                partition: PartitionedTransaction {
                    inputs: vec![
                        ClassifiedCell::business_ckb(10_000, 1_000, 9_000),
                        ClassifiedCell::state_carrier(
                            backend.current_state.capacity,
                            backend.current_state.occupied_capacity,
                        ),
                    ],
                    outputs: vec![
                        ClassifiedCell::business_ckb(10_000, 1_000, 9_000),
                        ClassifiedCell::state_carrier(
                            backend.current_state.capacity,
                            backend.current_state.occupied_capacity,
                        ),
                    ],
                    tx_fee: 0,
                    authorised_reserve_refund: 0,
                },
            },
            settlement_descriptor: descriptor,
        }
    }

    #[test]
    fn signed_descriptor_delta_settles_exact_intent() {
        let (mut backend, keys, _) = fixture();
        let prepared = backend.prepare_payment(intent(&backend), 110).unwrap();
        let evidence = backend
            .commit_payment(
                &prepared.prepared_id,
                update(
                    &backend,
                    &keys,
                    descriptor([21; 32], 5_500, [22; 32], 4_500),
                ),
                120,
            )
            .unwrap();
        assert_eq!(evidence.provider_id, "morph-bilateral-v1");
        assert_eq!(evidence.morph_state.unwrap().state_number, 1);
    }

    #[test]
    fn signed_but_wrong_amount_descriptor_is_rejected() {
        let (mut backend, keys, _) = fixture();
        let mut intent = intent(&backend);
        let wrong_descriptor = descriptor([21; 32], 5_600, [22; 32], 4_400);
        intent
            .channel_binding
            .as_mut()
            .unwrap()
            .expected_settlement_descriptor_commitment =
            settlement_descriptor_commitment(&wrong_descriptor);
        intent.intent_id = intent.derive_id().unwrap();
        let prepared = backend.prepare_payment(intent, 110).unwrap();
        assert_eq!(
            backend.commit_payment(
                &prepared.prepared_id,
                update(&backend, &keys, wrong_descriptor),
                120,
            ),
            Err(BackendError::PaymentDeltaMismatch)
        );
    }

    #[test]
    fn commit_rejects_times_outside_the_prepared_intent_window() {
        let (mut backend, keys, _) = fixture();
        let prepared = backend.prepare_payment(intent(&backend), 110).unwrap();
        let signed_update = update(
            &backend,
            &keys,
            descriptor([21; 32], 5_500, [22; 32], 4_500),
        );

        assert_eq!(
            backend.commit_payment(&prepared.prepared_id, signed_update.clone(), 109),
            Err(BackendError::InvalidCommitTime)
        );
        assert_eq!(
            backend.commit_payment(&prepared.prepared_id, signed_update, 200),
            Err(BackendError::InvalidCommitTime)
        );
        assert!(matches!(
            backend.payment_state(&prepared.intent.intent_id),
            Some(BackendPaymentState::Prepared(_))
        ));
    }

    #[test]
    fn overflowing_xudt_totals_are_rejected_without_panicking() {
        let participants = [
            ChannelParticipant {
                node_id: [1; 32],
                settlement_lock_hash: [21; 32],
            },
            ChannelParticipant {
                node_id: [2; 32],
                settlement_lock_hash: [22; 32],
            },
        ];
        let intent = PaymentIntent {
            intent_id: [3; 32],
            payer: [1; 32],
            payee: [2; 32],
            asset: AgentAsset::Xudt {
                ckb_genesis_hash: [4; 32],
                type_script_hash: [5; 32],
            },
            amount: 1,
            payment_hash: [6; 32],
            hash_algorithm: PaymentHashAlgorithm::Sha256,
            resource: "/overflow".to_string(),
            operation: HttpOperation::Get,
            nonce: [7; 32],
            idempotency_key: [8; 32],
            created_at_unix: 1,
            expires_at_unix: 2,
            required_rgbpp_proof_commitment: None,
            channel_binding: None,
        };
        let old = xudt_descriptor([5; 32], [21; 32], u128::MAX, [22; 32], 1);
        let new = xudt_descriptor([5; 32], [21; 32], u128::MAX - 1, [22; 32], 2);
        assert!(matches!(
            validate_payment_delta(&old, &new, &participants, &intent),
            Err(BackendError::InvalidSettlementDescriptor | BackendError::PaymentDeltaMismatch)
        ));
    }

    #[test]
    fn idempotency_key_cannot_be_reused_for_another_intent() {
        let (mut backend, _, _) = fixture();
        let original = intent(&backend);
        backend.prepare_payment(original.clone(), 110).unwrap();
        let mut conflict = original;
        conflict.nonce = [34; 32];
        conflict.intent_id = conflict.derive_id().unwrap();
        assert_eq!(
            backend.prepare_payment(conflict, 111),
            Err(BackendError::IdempotencyConflict)
        );
    }

    #[test]
    fn payment_asset_must_match_the_channel_ckb_network() {
        let (mut backend, _, _) = fixture();
        let mut wrong_network = intent(&backend);
        wrong_network.asset = AgentAsset::Ckb {
            ckb_genesis_hash: [99; 32],
        };
        wrong_network.intent_id = wrong_network.derive_id().unwrap();
        assert_eq!(
            backend.prepare_payment(wrong_network, 110),
            Err(BackendError::WrongNetwork)
        );
    }

    #[test]
    fn channel_node_ids_must_derive_from_the_state_signers() {
        let (backend, _, mut participants) = fixture();
        participants[0].node_id = [99; 32];
        assert_eq!(
            MorphBilateralChannelBackend::new(
                backend.current_state.clone(),
                backend.current_authorization.clone(),
                backend.current_settlement_descriptor.clone(),
                participants,
                backend.asset_registry.clone(),
                BTreeSet::new(),
            ),
            Err(BackendError::WrongSettlementParticipants)
        );
    }
}
