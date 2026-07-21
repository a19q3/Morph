//! Sovereign Factory-right -> materialised Channel -> provider-edge lifecycle.
//!
//! A routing provider mirrors `ProviderEdgeDescriptor`; it is never the source
//! of truth for Factory rights, Morph script identity, or channel settlement.

use std::collections::BTreeMap;

use k256::ecdsa::VerifyingKey;
use morph_script_common::{
    BILATERAL_CKB_DESCRIPTOR_LEN, BILATERAL_CKB_XUDT_DESCRIPTOR_LEN,
    BilateralCkbSettlementDescriptor, BilateralCkbXudtSettlementDescriptor,
    settlement_descriptor_commitment, vault_cell_commitment,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::agent::AgentAsset;
use crate::backend::{ChannelParticipant, validate_participant_identities};
use crate::rgbpp::CkbOutPoint;
use crate::validation::{MorphError, validate_state_authorization};
use crate::{
    Amount, Bytes32, FactoryRightId, FactoryRightKind, FactoryRightMerkleProof, Mode, Phase,
    StateAuthorization, StateCell, blake2b256, factory_right_leaf_hash,
    verify_factory_right_merkle_proof,
};

const DEPLOYMENT_ID_DOMAIN: &[u8] = b"CKB_MORPH_DEPLOYMENT_ID_V1";
const FACTORY_RESERVATION_DOMAIN: &[u8] = b"CKB_MORPH_FACTORY_RESERVATION_V1";
const FACTORY_RIGHT_PROOF_DOMAIN: &[u8] = b"CKB_MORPH_FACTORY_RIGHT_PROOF_V1";
const EDGE_DESCRIPTOR_DOMAIN: &[u8] = b"CKB_MORPH_PROVIDER_EDGE_V1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrustedMorphDeployment {
    pub ckb_genesis_hash: Bytes32,
    pub state_type_code_hash: Bytes32,
    pub state_lock_code_hash: Bytes32,
    pub vault_lock_code_hash: Bytes32,
    pub factory_type_code_hash: Bytes32,
    pub factory_vault_lock_code_hash: Bytes32,
}

impl TrustedMorphDeployment {
    pub fn validate(&self) -> BridgeResult<()> {
        if [
            self.ckb_genesis_hash,
            self.state_type_code_hash,
            self.state_lock_code_hash,
            self.vault_lock_code_hash,
            self.factory_type_code_hash,
            self.factory_vault_lock_code_hash,
        ]
        .iter()
        .any(is_zero)
        {
            return Err(BridgeError::InvalidDeployment);
        }
        Ok(())
    }

    pub fn deployment_id(&self) -> BridgeResult<Bytes32> {
        self.validate()?;
        let mut raw = Vec::with_capacity(DEPLOYMENT_ID_DOMAIN.len() + 192);
        raw.extend_from_slice(DEPLOYMENT_ID_DOMAIN);
        raw.extend_from_slice(&self.ckb_genesis_hash);
        raw.extend_from_slice(&self.state_type_code_hash);
        raw.extend_from_slice(&self.state_lock_code_hash);
        raw.extend_from_slice(&self.vault_lock_code_hash);
        raw.extend_from_slice(&self.factory_type_code_hash);
        raw.extend_from_slice(&self.factory_vault_lock_code_hash);
        Ok(blake2b256(&raw))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FactoryRightReservation {
    pub reservation_id: Bytes32,
    pub factory_id: Bytes32,
    pub factory_update_number: u64,
    pub right: FactoryRightId,
    pub quantity: Amount,
    pub factory_state_root: Bytes32,
    pub access_manifest_root: Bytes32,
    pub right_proof: FactoryRightMerkleProof,
    pub proof_commitment: Bytes32,
    pub idempotency_key: Bytes32,
    pub reserved_at_unix: u64,
    pub expires_at_unix: u64,
}

impl FactoryRightReservation {
    pub fn derive_id(&self) -> BridgeResult<Bytes32> {
        self.validate_fields(false)?;
        let mut raw = Vec::with_capacity(FACTORY_RESERVATION_DOMAIN.len() + 320);
        raw.extend_from_slice(FACTORY_RESERVATION_DOMAIN);
        raw.extend_from_slice(&self.factory_id);
        raw.extend_from_slice(&self.factory_update_number.to_le_bytes());
        encode_right_id(&self.right, &mut raw);
        raw.extend_from_slice(&self.quantity.to_le_bytes());
        raw.extend_from_slice(&self.factory_state_root);
        raw.extend_from_slice(&self.access_manifest_root);
        raw.extend_from_slice(&self.proof_commitment);
        raw.extend_from_slice(&self.idempotency_key);
        raw.extend_from_slice(&self.reserved_at_unix.to_le_bytes());
        raw.extend_from_slice(&self.expires_at_unix.to_le_bytes());
        Ok(blake2b256(&raw))
    }

    pub fn validate(&self, now_unix: u64) -> BridgeResult<()> {
        self.validate_fields(true)?;
        if self.reservation_id != self.derive_id()? {
            return Err(BridgeError::ReservationIdMismatch);
        }
        if now_unix < self.reserved_at_unix {
            return Err(BridgeError::ReservationNotYetValid);
        }
        if now_unix >= self.expires_at_unix {
            return Err(BridgeError::ReservationExpired);
        }
        Ok(())
    }

    fn validate_fields(&self, check_id: bool) -> BridgeResult<()> {
        if check_id && is_zero(&self.reservation_id) {
            return Err(BridgeError::InvalidReservation);
        }
        if is_zero(&self.factory_id)
            || is_zero(&self.right.participant)
            || is_zero(&self.right.subchannel)
            || self.right.asset_type.is_some_and(|asset| is_zero(&asset))
            || self.quantity == 0
            || is_zero(&self.factory_state_root)
            || is_zero(&self.access_manifest_root)
            || is_zero(&self.proof_commitment)
            || is_zero(&self.idempotency_key)
            || self.expires_at_unix <= self.reserved_at_unix
        {
            return Err(BridgeError::InvalidReservation);
        }
        if !matches!(
            self.right.kind,
            FactoryRightKind::Balance | FactoryRightKind::ReserveClaim
        ) {
            return Err(BridgeError::UnsupportedFactoryRight);
        }
        if self.right_proof.right.id != self.right
            || self.right_proof.right.quantity < self.quantity
            || self.proof_commitment != factory_right_proof_commitment(&self.right_proof)
        {
            return Err(BridgeError::InvalidFactoryProof);
        }
        verify_factory_right_merkle_proof(self.factory_state_root, &self.right_proof)
            .map_err(|_| BridgeError::InvalidFactoryProof)?;
        Ok(())
    }
}

pub fn factory_right_proof_commitment(proof: &FactoryRightMerkleProof) -> Bytes32 {
    let mut raw =
        Vec::with_capacity(FACTORY_RIGHT_PROOF_DOMAIN.len() + 64 + proof.siblings.len() * 33);
    raw.extend_from_slice(FACTORY_RIGHT_PROOF_DOMAIN);
    raw.extend_from_slice(&factory_right_leaf_hash(&proof.right));
    raw.extend_from_slice(&(proof.siblings.len() as u16).to_le_bytes());
    for sibling in &proof.siblings {
        raw.push(match sibling.side {
            crate::FactoryMerkleSiblingSide::Left => 0,
            crate::FactoryMerkleSiblingSide::Right => 1,
        });
        raw.extend_from_slice(&sibling.hash);
    }
    blake2b256(&raw)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MaterializedCellEvidence {
    pub out_point: CkbOutPoint,
    pub lock_hash: Bytes32,
    pub type_hash: Option<Bytes32>,
    pub capacity: u64,
    pub data: Vec<u8>,
}

impl MaterializedCellEvidence {
    fn commitment(&self) -> Bytes32 {
        vault_cell_commitment(
            &self.lock_hash,
            self.capacity,
            self.type_hash.as_ref().map(|hash| hash.as_slice()),
            &self.data,
        )
    }

    fn validate(&self) -> BridgeResult<()> {
        if is_zero(&self.out_point.tx_hash)
            || is_zero(&self.lock_hash)
            || self.type_hash.is_some_and(|hash| is_zero(&hash))
        {
            return Err(BridgeError::InvalidMaterialisation);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeploymentEvidence {
    pub state_type_code_hash: Bytes32,
    pub state_lock_code_hash: Bytes32,
    pub vault_lock_code_hash: Bytes32,
    pub factory_type_code_hash: Option<Bytes32>,
    pub factory_vault_lock_code_hash: Option<Bytes32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MaterializedChannelEvidence {
    pub state: StateCell,
    pub authorization: StateAuthorization,
    pub state_out_point: CkbOutPoint,
    pub vault: MaterializedCellEvidence,
    pub settlement_descriptor: Vec<u8>,
    pub participants: [ChannelParticipant; 2],
    pub asset: AgentAsset,
    pub factory_reservation_id: Option<Bytes32>,
    pub deployment: DeploymentEvidence,
    pub committed_block_hash: Bytes32,
    pub committed_block_number: u64,
    pub confirmations: u64,
    pub rgbpp_proof_commitment: Option<Bytes32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderEdgeDescriptor {
    pub edge_id: Bytes32,
    pub channel_id: Bytes32,
    pub funding_context_id: Bytes32,
    pub funding_epoch: u64,
    pub state_number: u64,
    pub participants: [Bytes32; 2],
    /// State-signer keys corresponding positionally to `participants`.
    pub participant_pubkeys_sec1: [Vec<u8>; 2],
    pub asset: AgentAsset,
    pub directional_liquidity: [Amount; 2],
    pub deployment_id: Bytes32,
    pub factory_id: Option<Bytes32>,
    pub factory_update_number: Option<u64>,
    pub factory_reservation_id: Option<Bytes32>,
    pub evidence_block_hash: Bytes32,
    pub evidence_block_number: u64,
    pub opaque_morph_commitment: Bytes32,
}

impl ProviderEdgeDescriptor {
    pub fn derive_id(&self) -> BridgeResult<Bytes32> {
        self.asset.validate()?;
        if [
            self.channel_id,
            self.funding_context_id,
            self.participants[0],
            self.participants[1],
            self.deployment_id,
            self.evidence_block_hash,
            self.opaque_morph_commitment,
        ]
        .iter()
        .any(is_zero)
            || self.participants[0] == self.participants[1]
            || self.directional_liquidity.iter().all(|amount| *amount == 0)
        {
            return Err(BridgeError::InvalidMaterialisation);
        }
        for (participant, public_key) in self
            .participants
            .iter()
            .zip(self.participant_pubkeys_sec1.iter())
        {
            let key = VerifyingKey::from_sec1_bytes(public_key)
                .map_err(|_| BridgeError::InvalidMaterialisation)?;
            if key.to_encoded_point(true).as_bytes() != public_key
                || blake2b256(public_key) != *participant
            {
                return Err(BridgeError::InvalidMaterialisation);
            }
        }
        let mut raw = Vec::with_capacity(EDGE_DESCRIPTOR_DOMAIN.len() + 480);
        raw.extend_from_slice(EDGE_DESCRIPTOR_DOMAIN);
        raw.extend_from_slice(&self.channel_id);
        raw.extend_from_slice(&self.funding_context_id);
        raw.extend_from_slice(&self.funding_epoch.to_le_bytes());
        raw.extend_from_slice(&self.participants[0]);
        raw.extend_from_slice(&self.participants[1]);
        raw.extend_from_slice(&self.participant_pubkeys_sec1[0]);
        raw.extend_from_slice(&self.participant_pubkeys_sec1[1]);
        raw.extend_from_slice(&self.asset.commitment()?);
        raw.extend_from_slice(&self.deployment_id);
        encode_option_bytes32(self.factory_id, &mut raw);
        match self.factory_update_number {
            Some(value) => {
                raw.push(1);
                raw.extend_from_slice(&value.to_le_bytes());
            }
            None => raw.push(0),
        }
        encode_option_bytes32(self.factory_reservation_id, &mut raw);
        Ok(blake2b256(&raw))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum EdgeLifecycle {
    Reserved,
    Materializing,
    Active(ProviderEdgeDescriptor),
    Draining(ProviderEdgeDescriptor),
    Disabled {
        edge: ProviderEdgeDescriptor,
        reason: String,
        disabled_at_unix: u64,
    },
    Invalidated {
        edge: ProviderEdgeDescriptor,
        reason: String,
        invalidated_at_unix: u64,
    },
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SovereignEdgeRegistry {
    reservations: BTreeMap<Bytes32, FactoryRightReservation>,
    reservation_idempotency: BTreeMap<Bytes32, Bytes32>,
    lifecycles: BTreeMap<Bytes32, EdgeLifecycle>,
    channel_edges: BTreeMap<Bytes32, Bytes32>,
}

impl SovereignEdgeRegistry {
    pub fn reserve(
        &mut self,
        reservation: FactoryRightReservation,
        now_unix: u64,
    ) -> BridgeResult<Bytes32> {
        reservation.validate(now_unix)?;
        if let Some(existing) = self
            .reservation_idempotency
            .get(&reservation.idempotency_key)
        {
            if existing == &reservation.reservation_id {
                return Ok(*existing);
            }
            return Err(BridgeError::IdempotencyConflict);
        }
        if self.reservations.contains_key(&reservation.reservation_id) {
            return Err(BridgeError::ReservationConflict);
        }
        self.reservation_idempotency
            .insert(reservation.idempotency_key, reservation.reservation_id);
        self.lifecycles
            .insert(reservation.reservation_id, EdgeLifecycle::Reserved);
        self.reservations
            .insert(reservation.reservation_id, reservation.clone());
        Ok(reservation.reservation_id)
    }

    pub fn begin_materialisation(&mut self, reservation_id: &Bytes32) -> BridgeResult<()> {
        match self.lifecycles.get_mut(reservation_id) {
            Some(lifecycle @ EdgeLifecycle::Reserved) => {
                *lifecycle = EdgeLifecycle::Materializing;
                Ok(())
            }
            _ => Err(BridgeError::InvalidLifecycle),
        }
    }

    pub fn activate(
        &mut self,
        evidence: MaterializedChannelEvidence,
        deployment: &TrustedMorphDeployment,
        minimum_confirmations: u64,
        now_unix: u64,
    ) -> BridgeResult<ProviderEdgeDescriptor> {
        let reservation = match evidence.factory_reservation_id {
            Some(id) => Some(
                self.reservations
                    .get(&id)
                    .ok_or(BridgeError::ReservationNotFound)?,
            ),
            None => None,
        };
        if let Some(reservation) = reservation {
            reservation.validate(now_unix)?;
            if !matches!(
                self.lifecycles.get(&reservation.reservation_id),
                Some(EdgeLifecycle::Materializing)
            ) {
                return Err(BridgeError::InvalidLifecycle);
            }
        }
        let edge = derive_edge(
            &evidence,
            reservation,
            deployment,
            minimum_confirmations,
            true,
        )?;
        if let Some(existing_edge_id) = self.channel_edges.get(&edge.channel_id)
            && existing_edge_id != &edge.edge_id
            && matches!(
                self.lifecycles.get(existing_edge_id),
                Some(EdgeLifecycle::Active(_) | EdgeLifecycle::Draining(_))
            )
        {
            return Err(BridgeError::ActiveEdgeConflict);
        }
        let lifecycle_key = evidence.factory_reservation_id.unwrap_or(edge.edge_id);
        self.channel_edges.insert(edge.channel_id, lifecycle_key);
        self.lifecycles
            .insert(lifecycle_key, EdgeLifecycle::Active(edge.clone()));
        Ok(edge)
    }

    pub fn begin_draining(&mut self, channel_id: &Bytes32) -> BridgeResult<()> {
        let edge_id = *self
            .channel_edges
            .get(channel_id)
            .ok_or(BridgeError::EdgeNotFound)?;
        let edge = match self.lifecycles.get(&edge_id) {
            Some(EdgeLifecycle::Active(edge)) => edge.clone(),
            _ => return Err(BridgeError::InvalidLifecycle),
        };
        self.lifecycles
            .insert(edge_id, EdgeLifecycle::Draining(edge));
        Ok(())
    }

    /// Refresh liquidity/state evidence without changing the stable provider
    /// edge identity. A splice has a new funding context and must instead use
    /// the explicit drain/disable/activate path.
    pub fn refresh(
        &mut self,
        evidence: MaterializedChannelEvidence,
        deployment: &TrustedMorphDeployment,
        minimum_confirmations: u64,
    ) -> BridgeResult<ProviderEdgeDescriptor> {
        let lifecycle_key = *self
            .channel_edges
            .get(&evidence.state.header.channel_id)
            .ok_or(BridgeError::EdgeNotFound)?;
        let (previous, draining) = match self.lifecycles.get(&lifecycle_key) {
            Some(EdgeLifecycle::Active(edge)) => (edge.clone(), false),
            Some(EdgeLifecycle::Draining(edge)) => (edge.clone(), true),
            _ => return Err(BridgeError::InvalidLifecycle),
        };
        let reservation = match evidence.factory_reservation_id {
            Some(id) => Some(
                self.reservations
                    .get(&id)
                    .ok_or(BridgeError::ReservationNotFound)?,
            ),
            None => None,
        };
        let refreshed = derive_edge(
            &evidence,
            reservation,
            deployment,
            minimum_confirmations,
            false,
        )?;
        if refreshed.edge_id != previous.edge_id
            || refreshed.funding_context_id != previous.funding_context_id
            || refreshed.state_number <= previous.state_number
            || refreshed.evidence_block_number < previous.evidence_block_number
        {
            return Err(BridgeError::StaleEdgeEvidence);
        }
        self.lifecycles.insert(
            lifecycle_key,
            if draining {
                EdgeLifecycle::Draining(refreshed.clone())
            } else {
                EdgeLifecycle::Active(refreshed.clone())
            },
        );
        Ok(refreshed)
    }

    pub fn disable(
        &mut self,
        channel_id: &Bytes32,
        reason: String,
        disabled_at_unix: u64,
    ) -> BridgeResult<()> {
        if reason.trim().is_empty() || reason.len() > 256 {
            return Err(BridgeError::InvalidReason);
        }
        let edge_id = *self
            .channel_edges
            .get(channel_id)
            .ok_or(BridgeError::EdgeNotFound)?;
        let edge = match self.lifecycles.get(&edge_id) {
            Some(EdgeLifecycle::Active(edge) | EdgeLifecycle::Draining(edge)) => edge.clone(),
            _ => return Err(BridgeError::InvalidLifecycle),
        };
        self.lifecycles.insert(
            edge_id,
            EdgeLifecycle::Disabled {
                edge,
                reason,
                disabled_at_unix,
            },
        );
        Ok(())
    }

    pub fn invalidate(
        &mut self,
        channel_id: &Bytes32,
        reason: String,
        invalidated_at_unix: u64,
    ) -> BridgeResult<()> {
        if reason.trim().is_empty() || reason.len() > 256 {
            return Err(BridgeError::InvalidReason);
        }
        let edge_id = *self
            .channel_edges
            .get(channel_id)
            .ok_or(BridgeError::EdgeNotFound)?;
        let edge = match self.lifecycles.get(&edge_id) {
            Some(
                EdgeLifecycle::Active(edge)
                | EdgeLifecycle::Draining(edge)
                | EdgeLifecycle::Disabled { edge, .. },
            ) => edge.clone(),
            _ => return Err(BridgeError::InvalidLifecycle),
        };
        self.lifecycles.insert(
            edge_id,
            EdgeLifecycle::Invalidated {
                edge,
                reason,
                invalidated_at_unix,
            },
        );
        Ok(())
    }

    pub fn lifecycle(&self, key: &Bytes32) -> Option<&EdgeLifecycle> {
        self.lifecycles.get(key)
    }

    pub fn edge_for_channel(&self, channel_id: &Bytes32) -> Option<&ProviderEdgeDescriptor> {
        let key = self.channel_edges.get(channel_id)?;
        match self.lifecycles.get(key)? {
            EdgeLifecycle::Active(edge)
            | EdgeLifecycle::Draining(edge)
            | EdgeLifecycle::Disabled { edge, .. }
            | EdgeLifecycle::Invalidated { edge, .. } => Some(edge),
            _ => None,
        }
    }
}

fn derive_edge(
    evidence: &MaterializedChannelEvidence,
    reservation: Option<&FactoryRightReservation>,
    deployment: &TrustedMorphDeployment,
    minimum_confirmations: u64,
    enforce_reservation_quantity: bool,
) -> BridgeResult<ProviderEdgeDescriptor> {
    deployment.validate()?;
    evidence.asset.validate()?;
    evidence.vault.validate()?;
    if evidence.confirmations < minimum_confirmations || minimum_confirmations == 0 {
        return Err(BridgeError::InsufficientConfirmations);
    }
    if is_zero(&evidence.state_out_point.tx_hash)
        || is_zero(&evidence.committed_block_hash)
        || evidence.committed_block_number == 0
        || !evidence.state.capacity_sufficient()
        || evidence.state_out_point == evidence.vault.out_point
        || evidence.participants[0].node_id == evidence.participants[1].node_id
    {
        return Err(BridgeError::InvalidMaterialisation);
    }
    if evidence.state.header.chain_id != deployment.ckb_genesis_hash
        || asset_ckb_genesis_hash(&evidence.asset) != &deployment.ckb_genesis_hash
    {
        return Err(BridgeError::WrongNetwork);
    }
    if evidence.deployment.state_type_code_hash != deployment.state_type_code_hash
        || evidence.deployment.state_lock_code_hash != deployment.state_lock_code_hash
        || evidence.deployment.vault_lock_code_hash != deployment.vault_lock_code_hash
    {
        return Err(BridgeError::UntrustedDeployment);
    }
    validate_state_authorization(&evidence.state.header, &evidence.authorization)?;
    validate_participant_identities(&evidence.authorization, &evidence.participants)
        .map_err(|_| BridgeError::InvalidMaterialisation)?;
    if settlement_descriptor_commitment(&evidence.settlement_descriptor)
        != evidence.state.header.settlement_descriptor_commitment
        || descriptor_version(&evidence.settlement_descriptor)?
            != evidence.state.header.descriptor_version
        || evidence.vault.commitment() != evidence.state.header.vault_materialisation_root
    {
        return Err(BridgeError::InvalidMaterialisation);
    }
    if !matches!(evidence.state.header.phase, Phase::Active | Phase::Settling) {
        return Err(BridgeError::InvalidMaterialisation);
    }
    let descriptor_liquidity =
        descriptor_amounts(&evidence.settlement_descriptor, &evidence.asset)?;
    validate_vault_asset(
        &evidence.vault,
        &evidence.settlement_descriptor,
        &evidence.asset,
        descriptor_liquidity,
    )?;
    let locks = descriptor_locks(&evidence.settlement_descriptor)?;
    let participant_liquidity = |participant: &ChannelParticipant| -> BridgeResult<Amount> {
        let index = locks
            .iter()
            .position(|lock| lock == &participant.settlement_lock_hash)
            .ok_or(BridgeError::InvalidMaterialisation)?;
        Ok(descriptor_liquidity[index])
    };
    let directional_liquidity = [
        participant_liquidity(&evidence.participants[0])?,
        participant_liquidity(&evidence.participants[1])?,
    ];
    match (reservation, evidence.state.header.mode) {
        (Some(reservation), Mode::FactoryProof) => {
            if evidence.deployment.factory_type_code_hash != Some(deployment.factory_type_code_hash)
                || evidence.deployment.factory_vault_lock_code_hash
                    != Some(deployment.factory_vault_lock_code_hash)
                || reservation.right.subchannel != evidence.state.header.channel_id
                || reservation_asset_type(&reservation.right) != asset_type_hash(&evidence.asset)
            {
                return Err(BridgeError::FactoryOriginMismatch);
            }
            let participant_index = evidence
                .participants
                .iter()
                .position(|participant| participant.node_id == reservation.right.participant)
                .ok_or(BridgeError::FactoryOriginMismatch)?;
            if enforce_reservation_quantity
                && reservation.quantity > directional_liquidity[participant_index]
            {
                return Err(BridgeError::FactoryOriginMismatch);
            }
        }
        (None, Mode::BilateralPlain) => {
            if evidence.deployment.factory_type_code_hash.is_some()
                || evidence.deployment.factory_vault_lock_code_hash.is_some()
            {
                return Err(BridgeError::FactoryOriginMismatch);
            }
        }
        _ => return Err(BridgeError::FactoryOriginMismatch),
    }
    match (&evidence.asset, evidence.rgbpp_proof_commitment) {
        (AgentAsset::Rgbpp(_), Some(commitment)) if !is_zero(&commitment) => {}
        (AgentAsset::Rgbpp(_), _) | (_, Some(_)) => {
            return Err(BridgeError::RgbppProofMismatch);
        }
        _ => {}
    }

    let factory_id = reservation.map(|reservation| reservation.factory_id);
    let factory_update_number = reservation.map(|reservation| reservation.factory_update_number);
    let factory_reservation_id = reservation.map(|reservation| reservation.reservation_id);
    let participant_pubkeys_sec1 = [
        signer_pubkey_for_node(&evidence.authorization, &evidence.participants[0].node_id)?,
        signer_pubkey_for_node(&evidence.authorization, &evidence.participants[1].node_id)?,
    ];
    let mut edge = ProviderEdgeDescriptor {
        edge_id: [0; 32],
        channel_id: evidence.state.header.channel_id,
        funding_context_id: evidence.state.header.funding_context_id(),
        funding_epoch: evidence.state.header.funding_epoch,
        state_number: evidence.state.header.state_number,
        participants: [
            evidence.participants[0].node_id,
            evidence.participants[1].node_id,
        ],
        participant_pubkeys_sec1,
        asset: evidence.asset.clone(),
        directional_liquidity,
        deployment_id: deployment.deployment_id()?,
        factory_id,
        factory_update_number,
        factory_reservation_id,
        evidence_block_hash: evidence.committed_block_hash,
        evidence_block_number: evidence.committed_block_number,
        opaque_morph_commitment: evidence.state.header.signing_digest(),
    };
    edge.edge_id = edge.derive_id()?;
    Ok(edge)
}

fn signer_pubkey_for_node(
    authorization: &StateAuthorization,
    node_id: &Bytes32,
) -> BridgeResult<Vec<u8>> {
    authorization
        .signatures
        .iter()
        .find(|signature| blake2b256(&signature.pubkey_sec1) == *node_id)
        .map(|signature| signature.pubkey_sec1.clone())
        .ok_or(BridgeError::InvalidMaterialisation)
}

fn asset_ckb_genesis_hash(asset: &AgentAsset) -> &Bytes32 {
    match asset {
        AgentAsset::Ckb { ckb_genesis_hash }
        | AgentAsset::Xudt {
            ckb_genesis_hash, ..
        } => ckb_genesis_hash,
        AgentAsset::Rgbpp(asset) => &asset.ckb_genesis_hash,
    }
}

fn asset_type_hash(asset: &AgentAsset) -> Option<Bytes32> {
    match asset {
        AgentAsset::Ckb { .. } => None,
        AgentAsset::Xudt {
            type_script_hash, ..
        } => Some(*type_script_hash),
        AgentAsset::Rgbpp(asset) => Some(asset.xudt_type_script_hash),
    }
}

fn reservation_asset_type(right: &FactoryRightId) -> Option<Bytes32> {
    right.asset_type
}

fn validate_vault_asset(
    vault: &MaterializedCellEvidence,
    descriptor_raw: &[u8],
    asset: &AgentAsset,
    liquidity: [Amount; 2],
) -> BridgeResult<()> {
    let total_liquidity = liquidity[0]
        .checked_add(liquidity[1])
        .ok_or(BridgeError::InvalidMaterialisation)?;
    match asset {
        AgentAsset::Ckb { .. } => {
            if vault.type_hash.is_some()
                || !vault.data.is_empty()
                || u128::from(vault.capacity) != total_liquidity
            {
                return Err(BridgeError::InvalidMaterialisation);
            }
        }
        AgentAsset::Xudt {
            type_script_hash, ..
        } => validate_xudt_vault(vault, descriptor_raw, type_script_hash, total_liquidity)?,
        AgentAsset::Rgbpp(asset) => validate_xudt_vault(
            vault,
            descriptor_raw,
            &asset.xudt_type_script_hash,
            total_liquidity,
        )?,
    }
    Ok(())
}

fn validate_xudt_vault(
    vault: &MaterializedCellEvidence,
    descriptor_raw: &[u8],
    expected_type_hash: &Bytes32,
    total_liquidity: Amount,
) -> BridgeResult<()> {
    let descriptor = BilateralCkbXudtSettlementDescriptor::parse(descriptor_raw)
        .map_err(|_| BridgeError::InvalidDescriptor)?;
    let total_capacity = descriptor
        .capacity(0)
        .checked_add(descriptor.capacity(1))
        .ok_or(BridgeError::InvalidDescriptor)?;
    if vault.type_hash != Some(*expected_type_hash)
        || vault.capacity != total_capacity
        || vault.data.len() != 16
        || u128::from_le_bytes(
            vault
                .data
                .as_slice()
                .try_into()
                .map_err(|_| BridgeError::InvalidMaterialisation)?,
        ) != total_liquidity
    {
        return Err(BridgeError::InvalidMaterialisation);
    }
    Ok(())
}

fn descriptor_locks(raw: &[u8]) -> BridgeResult<[Bytes32; 2]> {
    match raw.len() {
        BILATERAL_CKB_DESCRIPTOR_LEN => {
            let descriptor = BilateralCkbSettlementDescriptor::parse(raw)
                .map_err(|_| BridgeError::InvalidDescriptor)?;
            Ok([
                descriptor
                    .lock_hash(0)
                    .try_into()
                    .map_err(|_| BridgeError::InvalidDescriptor)?,
                descriptor
                    .lock_hash(1)
                    .try_into()
                    .map_err(|_| BridgeError::InvalidDescriptor)?,
            ])
        }
        BILATERAL_CKB_XUDT_DESCRIPTOR_LEN => {
            let descriptor = BilateralCkbXudtSettlementDescriptor::parse(raw)
                .map_err(|_| BridgeError::InvalidDescriptor)?;
            Ok([
                descriptor
                    .lock_hash(0)
                    .try_into()
                    .map_err(|_| BridgeError::InvalidDescriptor)?,
                descriptor
                    .lock_hash(1)
                    .try_into()
                    .map_err(|_| BridgeError::InvalidDescriptor)?,
            ])
        }
        _ => Err(BridgeError::InvalidDescriptor),
    }
}

fn descriptor_version(raw: &[u8]) -> BridgeResult<u16> {
    match raw.len() {
        BILATERAL_CKB_DESCRIPTOR_LEN => BilateralCkbSettlementDescriptor::parse(raw)
            .map(|descriptor| descriptor.version())
            .map_err(|_| BridgeError::InvalidDescriptor),
        BILATERAL_CKB_XUDT_DESCRIPTOR_LEN => BilateralCkbXudtSettlementDescriptor::parse(raw)
            .map(|descriptor| descriptor.version())
            .map_err(|_| BridgeError::InvalidDescriptor),
        _ => Err(BridgeError::InvalidDescriptor),
    }
}

fn descriptor_amounts(raw: &[u8], asset: &AgentAsset) -> BridgeResult<[Amount; 2]> {
    match (raw.len(), asset) {
        (BILATERAL_CKB_DESCRIPTOR_LEN, AgentAsset::Ckb { .. }) => {
            let descriptor = BilateralCkbSettlementDescriptor::parse(raw)
                .map_err(|_| BridgeError::InvalidDescriptor)?;
            Ok([
                u128::from(descriptor.capacity(0)),
                u128::from(descriptor.capacity(1)),
            ])
        }
        (
            BILATERAL_CKB_XUDT_DESCRIPTOR_LEN,
            AgentAsset::Xudt {
                type_script_hash, ..
            },
        ) => xudt_amounts(raw, type_script_hash),
        (BILATERAL_CKB_XUDT_DESCRIPTOR_LEN, AgentAsset::Rgbpp(asset)) => {
            xudt_amounts(raw, &asset.xudt_type_script_hash)
        }
        _ => Err(BridgeError::InvalidDescriptor),
    }
}

fn xudt_amounts(raw: &[u8], expected_type_hash: &Bytes32) -> BridgeResult<[Amount; 2]> {
    let descriptor = BilateralCkbXudtSettlementDescriptor::parse(raw)
        .map_err(|_| BridgeError::InvalidDescriptor)?;
    if descriptor.xudt_type_hash() != expected_type_hash {
        return Err(BridgeError::InvalidDescriptor);
    }
    Ok([descriptor.xudt_amount(0), descriptor.xudt_amount(1)])
}

fn encode_right_id(right: &FactoryRightId, out: &mut Vec<u8>) {
    out.extend_from_slice(&right.participant);
    out.extend_from_slice(&right.subchannel);
    out.push(match right.kind {
        FactoryRightKind::Balance => 0,
        FactoryRightKind::ReserveClaim => 1,
        FactoryRightKind::Membership => 2,
        FactoryRightKind::ExitPath => 3,
        FactoryRightKind::SponsorBudgetClaim => 4,
    });
    encode_option_bytes32(right.asset_type, out);
}

fn encode_option_bytes32(value: Option<Bytes32>, out: &mut Vec<u8>) {
    match value {
        Some(value) => {
            out.push(1);
            out.extend_from_slice(&value);
        }
        None => out.push(0),
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum BridgeError {
    #[error("trusted Morph deployment profile is invalid")]
    InvalidDeployment,
    #[error("Factory reservation is invalid")]
    InvalidReservation,
    #[error("Factory reservation id does not match its canonical fields")]
    ReservationIdMismatch,
    #[error("Factory reservation has expired")]
    ReservationExpired,
    #[error("Factory reservation is not yet valid")]
    ReservationNotYetValid,
    #[error("Factory right kind cannot fund a routable channel")]
    UnsupportedFactoryRight,
    #[error("Factory right proof does not match the reserved root, right, or quantity")]
    InvalidFactoryProof,
    #[error("reservation idempotency key conflicts with another reservation")]
    IdempotencyConflict,
    #[error("Factory reservation already exists with conflicting state")]
    ReservationConflict,
    #[error("Factory reservation was not found")]
    ReservationNotFound,
    #[error("edge lifecycle does not permit this operation")]
    InvalidLifecycle,
    #[error("another active funding context already owns this channel edge")]
    ActiveEdgeConflict,
    #[error("provider edge refresh is stale or changes stable edge identity")]
    StaleEdgeEvidence,
    #[error("provider edge was not found")]
    EdgeNotFound,
    #[error("edge disable/invalidation reason is invalid")]
    InvalidReason,
    #[error("materialised State/Vault evidence is invalid")]
    InvalidMaterialisation,
    #[error("materialised channel uses an untrusted Morph deployment")]
    UntrustedDeployment,
    #[error("materialised channel or asset belongs to another CKB network")]
    WrongNetwork,
    #[error("Factory origin does not match the materialised child")]
    FactoryOriginMismatch,
    #[error("materialised channel has too few CKB confirmations")]
    InsufficientConfirmations,
    #[error("settlement descriptor is invalid for the advertised asset")]
    InvalidDescriptor,
    #[error("RGB++ proof commitment is missing or unexpected")]
    RgbppProofMismatch,
    #[error(transparent)]
    Agent(#[from] crate::agent::AgentError),
    #[error(transparent)]
    Morph(#[from] MorphError),
}

pub type BridgeResult<T> = Result<T, BridgeError>;

fn is_zero(value: &Bytes32) -> bool {
    value.iter().all(|byte| *byte == 0)
}

#[cfg(test)]
mod tests {
    use k256::ecdsa::signature::hazmat::PrehashSigner;
    use k256::ecdsa::{Signature, SigningKey};
    use morph_script_common::{
        BILATERAL_CKB_DESCRIPTOR_OUTPUT_COUNT, BILATERAL_CKB_DESCRIPTOR_VERSION,
    };

    use super::*;
    use crate::{ParticipantSignature, StateHeader, participants_commitment};

    fn deployment() -> TrustedMorphDeployment {
        TrustedMorphDeployment {
            ckb_genesis_hash: [1; 32],
            state_type_code_hash: [2; 32],
            state_lock_code_hash: [3; 32],
            vault_lock_code_hash: [4; 32],
            factory_type_code_hash: [5; 32],
            factory_vault_lock_code_hash: [6; 32],
        }
    }

    fn participant_node_id(seed: u8) -> Bytes32 {
        let key = SigningKey::from_slice(&[seed; 32]).unwrap();
        blake2b256(key.verifying_key().to_encoded_point(true).as_bytes())
    }

    fn reservation(now: u64) -> FactoryRightReservation {
        let right_id = FactoryRightId {
            participant: participant_node_id(31),
            subchannel: [9; 32],
            kind: FactoryRightKind::Balance,
            asset_type: None,
        };
        let rights = vec![crate::FactoryRight {
            id: right_id.clone(),
            quantity: 6_000,
        }];
        let right_proof = crate::factory_right_sparse_proof(&rights, &right_id).unwrap();
        let factory_state_root = crate::factory_right_sparse_root(&rights).unwrap();
        let proof_commitment = factory_right_proof_commitment(&right_proof);
        let mut reservation = FactoryRightReservation {
            reservation_id: [0; 32],
            factory_id: [7; 32],
            factory_update_number: 9,
            right: right_id,
            quantity: 6_000,
            factory_state_root,
            access_manifest_root: [11; 32],
            right_proof,
            proof_commitment,
            idempotency_key: [13; 32],
            reserved_at_unix: now,
            expires_at_unix: now + 100,
        };
        reservation.reservation_id = reservation.derive_id().unwrap();
        reservation
    }

    fn descriptor() -> Vec<u8> {
        let mut raw = vec![0; BILATERAL_CKB_DESCRIPTOR_LEN];
        raw[0..2].copy_from_slice(&BILATERAL_CKB_DESCRIPTOR_VERSION.to_le_bytes());
        raw[2] = BILATERAL_CKB_DESCRIPTOR_OUTPUT_COUNT;
        raw[4..36].copy_from_slice(&[21; 32]);
        raw[36..44].copy_from_slice(&6_000u64.to_le_bytes());
        raw[44..76].copy_from_slice(&[22; 32]);
        raw[76..84].copy_from_slice(&4_000u64.to_le_bytes());
        raw
    }

    fn evidence(reservation_id: Bytes32) -> MaterializedChannelEvidence {
        let keys = [
            SigningKey::from_slice(&[31; 32]).unwrap(),
            SigningKey::from_slice(&[32; 32]).unwrap(),
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
        let vault = MaterializedCellEvidence {
            out_point: CkbOutPoint {
                tx_hash: [40; 32],
                index: 1,
            },
            lock_hash: [41; 32],
            type_hash: None,
            capacity: 10_000,
            data: vec![],
        };
        let descriptor = descriptor();
        let header = StateHeader {
            protocol_version: 1,
            chain_id: [1; 32],
            signature_scheme_id: 1,
            channel_id: [9; 32],
            funding_epoch: 0,
            funding_anchor: [42; 32],
            vault_set_commitment: [43; 32],
            state_number: 0,
            mode: Mode::FactoryProof,
            phase: Phase::Active,
            participants_commitment: participants_commitment(
                2,
                &[pubkeys[0].as_slice(), pubkeys[1].as_slice()],
            ),
            asset_registry_commitment: [44; 32],
            settlement_descriptor_commitment: settlement_descriptor_commitment(&descriptor),
            descriptor_version: BILATERAL_CKB_DESCRIPTOR_VERSION,
            vault_materialisation_root: vault.commitment(),
            challenge_policy_commitment: [45; 32],
            state_layout_version: 2,
        };
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
        MaterializedChannelEvidence {
            state: StateCell {
                header,
                capacity: 1_000,
                occupied_capacity: 1_000,
            },
            authorization: StateAuthorization {
                threshold: 2,
                signatures,
            },
            state_out_point: CkbOutPoint {
                tx_hash: [46; 32],
                index: 0,
            },
            vault,
            settlement_descriptor: descriptor,
            participants: [
                ChannelParticipant {
                    node_id: participant_node_id(31),
                    settlement_lock_hash: [21; 32],
                },
                ChannelParticipant {
                    node_id: participant_node_id(32),
                    settlement_lock_hash: [22; 32],
                },
            ],
            asset: AgentAsset::Ckb {
                ckb_genesis_hash: [1; 32],
            },
            factory_reservation_id: Some(reservation_id),
            deployment: DeploymentEvidence {
                state_type_code_hash: [2; 32],
                state_lock_code_hash: [3; 32],
                vault_lock_code_hash: [4; 32],
                factory_type_code_hash: Some([5; 32]),
                factory_vault_lock_code_hash: Some([6; 32]),
            },
            committed_block_hash: [47; 32],
            committed_block_number: 100,
            confirmations: 6,
            rgbpp_proof_commitment: None,
        }
    }

    #[test]
    fn factory_right_materialises_into_a_verified_edge() {
        let mut registry = SovereignEdgeRegistry::default();
        let reservation = reservation(100);
        assert_eq!(
            reservation.validate(99),
            Err(BridgeError::ReservationNotYetValid)
        );
        let reservation_id = registry.reserve(reservation, 100).unwrap();
        registry.begin_materialisation(&reservation_id).unwrap();
        let edge = registry
            .activate(evidence(reservation_id), &deployment(), 6, 101)
            .unwrap();
        assert_eq!(edge.factory_id, Some([7; 32]));
        assert_eq!(edge.directional_liquidity, [6_000, 4_000]);
        assert!(matches!(
            registry.lifecycle(&reservation_id),
            Some(EdgeLifecycle::Active(_))
        ));
    }

    #[test]
    fn edge_liquidity_is_aligned_with_participant_order() {
        let mut registry = SovereignEdgeRegistry::default();
        let reservation = reservation(100);
        let reservation_id = registry.reserve(reservation, 100).unwrap();
        registry.begin_materialisation(&reservation_id).unwrap();
        let mut materialized = evidence(reservation_id);
        materialized.participants.reverse();
        let edge = registry
            .activate(materialized, &deployment(), 6, 101)
            .unwrap();
        assert_eq!(
            edge.participants,
            [participant_node_id(32), participant_node_id(31)]
        );
        assert_eq!(edge.directional_liquidity, [4_000, 6_000]);
    }

    #[test]
    fn untrusted_code_hash_never_becomes_a_provider_edge() {
        let mut registry = SovereignEdgeRegistry::default();
        let reservation = reservation(100);
        let reservation_id = registry.reserve(reservation, 100).unwrap();
        registry.begin_materialisation(&reservation_id).unwrap();
        let mut evidence = evidence(reservation_id);
        evidence.deployment.vault_lock_code_hash = [99; 32];
        assert_eq!(
            registry.activate(evidence, &deployment(), 6, 101),
            Err(BridgeError::UntrustedDeployment)
        );
    }

    #[test]
    fn edge_must_disable_before_a_new_funding_context_can_activate() {
        let mut registry = SovereignEdgeRegistry::default();
        let reservation = reservation(100);
        let reservation_id = registry.reserve(reservation, 100).unwrap();
        registry.begin_materialisation(&reservation_id).unwrap();
        registry
            .activate(evidence(reservation_id), &deployment(), 6, 101)
            .unwrap();
        registry.begin_draining(&[9; 32]).unwrap();
        registry
            .disable(&[9; 32], "splice".to_string(), 102)
            .unwrap();
        assert!(matches!(
            registry.lifecycle(&reservation_id),
            Some(EdgeLifecycle::Disabled { .. })
        ));
    }

    #[test]
    fn signed_liquidity_refresh_preserves_stable_edge_identity() {
        let mut registry = SovereignEdgeRegistry::default();
        let reservation = reservation(100);
        let reservation_id = registry.reserve(reservation, 100).unwrap();
        registry.begin_materialisation(&reservation_id).unwrap();
        let original = registry
            .activate(evidence(reservation_id), &deployment(), 6, 101)
            .unwrap();

        let mut refreshed_evidence = evidence(reservation_id);
        refreshed_evidence.state.header.state_number = 1;
        refreshed_evidence.state.header.phase = Phase::Settling;
        refreshed_evidence.settlement_descriptor[36..44].copy_from_slice(&5_500u64.to_le_bytes());
        refreshed_evidence.settlement_descriptor[76..84].copy_from_slice(&4_500u64.to_le_bytes());
        refreshed_evidence
            .state
            .header
            .settlement_descriptor_commitment =
            settlement_descriptor_commitment(&refreshed_evidence.settlement_descriptor);
        let keys = [
            SigningKey::from_slice(&[31; 32]).unwrap(),
            SigningKey::from_slice(&[32; 32]).unwrap(),
        ];
        let mut signatures = keys
            .iter()
            .map(|key| {
                let signature: Signature = key
                    .sign_prehash(&refreshed_evidence.state.header.signing_digest())
                    .unwrap();
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
        refreshed_evidence.authorization = StateAuthorization {
            threshold: 2,
            signatures,
        };
        let refreshed = registry
            .refresh(refreshed_evidence, &deployment(), 6)
            .unwrap();
        assert_eq!(refreshed.edge_id, original.edge_id);
        assert_eq!(refreshed.directional_liquidity, [5_500, 4_500]);
        assert_eq!(refreshed.state_number, 1);
    }
}
