use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

pub type Bytes32 = [u8; 32];
pub type Capacity = u64;
pub type Amount = u128;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Mode {
    BilateralPlain,
    FactoryProof,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Phase {
    Funding,
    Active,
    Settling,
    Closed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChannelOperation {
    Publish,
    Supersede,
    Finalise,
    CooperativeClose,
    Splice,
    Materialise,
}

impl ChannelOperation {
    pub const fn is_publication_or_challenge(self) -> bool {
        matches!(self, Self::Publish | Self::Supersede)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StateHeader {
    pub protocol_version: u16,
    pub chain_id: Bytes32,
    pub signature_scheme_id: u16,
    pub channel_id: Bytes32,
    pub funding_anchor: Bytes32,
    pub state_number: u64,
    pub mode: Mode,
    pub phase: Phase,
    pub participants_commitment: Bytes32,
    pub asset_registry_commitment: Bytes32,
    pub settlement_descriptor_commitment: Bytes32,
    pub descriptor_version: u16,
    pub payload_commitment: Bytes32,
    pub challenge_policy_commitment: Bytes32,
    pub state_layout_version: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StateHeaderV2 {
    pub protocol_version: u16,
    pub chain_id: Bytes32,
    pub signature_scheme_id: u16,
    pub channel_id: Bytes32,
    pub funding_epoch: u64,
    pub funding_anchor: Bytes32,
    pub vault_set_commitment: Bytes32,
    pub state_number: u64,
    pub mode: Mode,
    pub phase: Phase,
    pub participants_commitment: Bytes32,
    pub asset_registry_commitment: Bytes32,
    pub settlement_descriptor_commitment: Bytes32,
    pub descriptor_version: u16,
    pub payload_commitment: Bytes32,
    pub challenge_policy_commitment: Bytes32,
    pub state_layout_version: u16,
}

impl StateHeaderV2 {
    pub fn same_context_except_progress(&self, next: &Self) -> bool {
        self.protocol_version == next.protocol_version
            && self.chain_id == next.chain_id
            && self.signature_scheme_id == next.signature_scheme_id
            && self.channel_id == next.channel_id
            && self.funding_epoch == next.funding_epoch
            && self.funding_anchor == next.funding_anchor
            && self.vault_set_commitment == next.vault_set_commitment
            && self.mode == next.mode
            && self.participants_commitment == next.participants_commitment
            && self.asset_registry_commitment == next.asset_registry_commitment
            && self.challenge_policy_commitment == next.challenge_policy_commitment
            && self.state_layout_version == next.state_layout_version
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StateCell {
    pub header: StateHeader,
    pub capacity: Capacity,
    pub occupied_capacity: Capacity,
}

impl StateCell {
    pub const fn capacity_sufficient(&self) -> bool {
        self.capacity >= self.occupied_capacity
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParticipantSignature {
    pub pubkey_sec1: Vec<u8>,
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StateAuthorization {
    pub threshold: u8,
    pub signatures: Vec<ParticipantSignature>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AssetRegistry {
    pub xudt_types: BTreeSet<Bytes32>,
}

impl AssetRegistry {
    pub fn contains(&self, asset_type: &Bytes32) -> bool {
        self.xudt_types.contains(asset_type)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChallengePolicy {
    pub since_value: u64,
    pub detection_depth: u32,
    pub min_emergency_rebuilds: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SponsorPolicy {
    pub channel_id: Bytes32,
    pub min_state_number: u64,
    pub max_state_number: u64,
    pub max_fee_per_tx: Capacity,
    pub max_total_fee: Capacity,
    pub already_spent: Capacity,
    pub expiry: u64,
    pub allowed_sponsor_source: Bytes32,
    pub change_lock: Bytes32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SponsorSpend {
    pub channel_id: Bytes32,
    pub state_number: u64,
    pub fee: Capacity,
    pub now: u64,
    pub sponsor_source: Bytes32,
    pub change_lock: Bytes32,
    pub operation: ChannelOperation,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum FactoryRightKind {
    Balance,
    ReserveClaim,
    Membership,
    ExitPath,
    SponsorBudgetClaim,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct FactoryRightId {
    pub participant: Bytes32,
    pub subchannel: Bytes32,
    pub kind: FactoryRightKind,
    pub asset_type: Option<Bytes32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FactoryRight {
    pub id: FactoryRightId,
    pub quantity: Amount,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FactoryUpdate {
    pub before: Vec<FactoryRight>,
    pub after: Vec<FactoryRight>,
    pub touched_participants: BTreeSet<Bytes32>,
    pub authorised_participants: BTreeSet<Bytes32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FactoryReducedExit {
    pub participant: Bytes32,
    pub reserve_claim: FactoryRightId,
    pub release_quantity: Amount,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FactoryMerkleSiblingSide {
    Left,
    Right,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FactoryMerkleSibling {
    pub side: FactoryMerkleSiblingSide,
    pub hash: Bytes32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FactoryRightMerkleProof {
    pub right: FactoryRight,
    pub siblings: Vec<FactoryMerkleSibling>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FactorySingleRightMerkleUpdate {
    pub before_root: Bytes32,
    pub after_root: Bytes32,
    pub touched_participants: BTreeSet<Bytes32>,
    pub authorised_participants: BTreeSet<Bytes32>,
    pub before: FactoryRightMerkleProof,
    pub after: FactoryRightMerkleProof,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FactorySpliceKind {
    In,
    Out,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FactoryVaultDescriptorV1 {
    pub factory_id: Bytes32,
    pub assets: Vec<VaultAssetAmount>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FactoryVaultDelta {
    pub asset: VaultAsset,
    pub old_amount: Amount,
    pub new_amount: Amount,
    pub external_input: Amount,
    pub withdrawal: Amount,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FactorySpliceHeader {
    pub protocol_version: u16,
    pub factory_id: Bytes32,
    pub old_update_number: u64,
    pub new_update_number: u64,
    pub old_state_root: Bytes32,
    pub new_state_root: Bytes32,
    pub old_access_manifest_root: Bytes32,
    pub new_access_manifest_root: Bytes32,
    pub kind: FactorySpliceKind,
    pub vault_delta_commitment: Bytes32,
    pub non_interference_digest: Bytes32,
    pub participants_commitment: Bytes32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FactorySpliceTransition {
    pub header: FactorySpliceHeader,
    pub witness: SpliceWitness,
    pub update: FactoryUpdate,
    pub old_vault: FactoryVaultDescriptorV1,
    pub new_vault: FactoryVaultDescriptorV1,
    pub deltas: Vec<FactoryVaultDelta>,
    pub asset_registry: AssetRegistry,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FactoryParticipantKey {
    pub participant: Bytes32,
    pub pubkey_sec1: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FactoryParticipantSignature {
    pub participant: Bytes32,
    pub pubkey_sec1: Vec<u8>,
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FactoryReducedSpliceWitness {
    pub participant_threshold: u8,
    pub participant_keys: Vec<FactoryParticipantKey>,
    pub signatures: Vec<FactoryParticipantSignature>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FactoryReducedSpliceTransition {
    pub header: FactorySpliceHeader,
    pub witness: FactoryReducedSpliceWitness,
    pub update: FactorySingleRightMerkleUpdate,
    pub old_vault: FactoryVaultDescriptorV1,
    pub new_vault: FactoryVaultDescriptorV1,
    pub deltas: Vec<FactoryVaultDelta>,
    pub asset_registry: AssetRegistry,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum CellClass {
    ChannelReserve,
    BusinessCkb,
    BusinessXudt(Bytes32),
    StateCarrier,
    Sponsor,
    Unrelated,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClassifiedCell {
    pub class: CellClass,
    pub capacity: Capacity,
    pub occupied_capacity: Capacity,
    pub business_ckb: Capacity,
    pub xudt_amount: Amount,
    pub carries_registered_xudt: bool,
    pub uses_channel_vault_lock: bool,
    pub read_by_channel_script: bool,
    pub contributes_to_conservation: bool,
}

impl ClassifiedCell {
    pub fn channel_reserve(capacity: Capacity, occupied_capacity: Capacity) -> Self {
        Self {
            class: CellClass::ChannelReserve,
            capacity,
            occupied_capacity,
            business_ckb: 0,
            xudt_amount: 0,
            carries_registered_xudt: false,
            uses_channel_vault_lock: true,
            read_by_channel_script: true,
            contributes_to_conservation: true,
        }
    }

    pub fn business_ckb(
        capacity: Capacity,
        occupied_capacity: Capacity,
        business_ckb: Capacity,
    ) -> Self {
        Self {
            class: CellClass::BusinessCkb,
            capacity,
            occupied_capacity,
            business_ckb,
            xudt_amount: 0,
            carries_registered_xudt: false,
            uses_channel_vault_lock: true,
            read_by_channel_script: true,
            contributes_to_conservation: true,
        }
    }

    pub fn xudt(
        asset_type: Bytes32,
        capacity: Capacity,
        occupied_capacity: Capacity,
        amount: Amount,
    ) -> Self {
        Self {
            class: CellClass::BusinessXudt(asset_type),
            capacity,
            occupied_capacity,
            business_ckb: 0,
            xudt_amount: amount,
            carries_registered_xudt: true,
            uses_channel_vault_lock: true,
            read_by_channel_script: true,
            contributes_to_conservation: true,
        }
    }

    pub fn state_carrier(capacity: Capacity, occupied_capacity: Capacity) -> Self {
        Self {
            class: CellClass::StateCarrier,
            capacity,
            occupied_capacity,
            business_ckb: 0,
            xudt_amount: 0,
            carries_registered_xudt: false,
            uses_channel_vault_lock: false,
            read_by_channel_script: true,
            contributes_to_conservation: false,
        }
    }

    pub fn sponsor(capacity: Capacity, occupied_capacity: Capacity) -> Self {
        Self {
            class: CellClass::Sponsor,
            capacity,
            occupied_capacity,
            business_ckb: 0,
            xudt_amount: 0,
            carries_registered_xudt: false,
            uses_channel_vault_lock: false,
            read_by_channel_script: false,
            contributes_to_conservation: false,
        }
    }

    pub fn unrelated(capacity: Capacity, occupied_capacity: Capacity) -> Self {
        Self {
            class: CellClass::Unrelated,
            capacity,
            occupied_capacity,
            business_ckb: 0,
            xudt_amount: 0,
            carries_registered_xudt: false,
            uses_channel_vault_lock: false,
            read_by_channel_script: false,
            contributes_to_conservation: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PartitionedTransaction {
    pub inputs: Vec<ClassifiedCell>,
    pub outputs: Vec<ClassifiedCell>,
    pub tx_fee: Capacity,
    pub authorised_reserve_refund: Capacity,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PartitionTotals {
    pub reserve_in: Capacity,
    pub reserve_out: Capacity,
    pub business_ckb_in: Capacity,
    pub business_ckb_out: Capacity,
    pub xudt_in: BTreeMap<Bytes32, Amount>,
    pub xudt_out: BTreeMap<Bytes32, Amount>,
    pub sponsor_in: Capacity,
    pub sponsor_out: Capacity,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StateTransitionContext {
    pub referenced_funding_anchor: Bytes32,
    pub authorization: StateAuthorization,
    pub asset_registry: AssetRegistry,
    pub partition: PartitionedTransaction,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultSpend {
    pub operation: ChannelOperation,
    pub state_cell: StateCell,
    pub signatures_or_phase_authorised: bool,
    pub since_satisfied: bool,
    pub expected_funding_anchor: Bytes32,
    pub descriptor_outputs_match: bool,
    pub asset_registry: AssetRegistry,
    pub partition: PartitionedTransaction,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SpliceKind {
    In,
    Out,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum VaultAsset {
    Ckb,
    Xudt(Bytes32),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultAssetAmount {
    pub asset: VaultAsset,
    pub amount: Amount,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultDescriptorV2 {
    pub funding_anchor: Bytes32,
    pub assets: Vec<VaultAssetAmount>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpliceAssetDelta {
    pub asset: VaultAsset,
    pub old_amount: Amount,
    pub new_amount: Amount,
    pub external_input: Amount,
    pub withdrawal: Amount,
    pub signed_fee: Amount,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpliceHeader {
    pub protocol_version: u16,
    pub chain_id: Bytes32,
    pub signature_scheme_id: u16,
    pub channel_id: Bytes32,
    pub old_funding_anchor: Bytes32,
    pub new_funding_anchor: Bytes32,
    pub old_funding_epoch: u64,
    pub new_funding_epoch: u64,
    pub base_state_number: u64,
    pub splice_number: u64,
    pub kind: SpliceKind,
    pub old_vault_commitment: Bytes32,
    pub new_vault_commitment: Bytes32,
    pub asset_delta_commitment: Bytes32,
    pub participants_commitment: Bytes32,
    pub challenge_policy_commitment: Bytes32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpliceWitness {
    pub threshold: u8,
    pub signatures: Vec<ParticipantSignature>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpliceTransition {
    pub current_state: StateCell,
    pub header: SpliceHeader,
    pub witness: SpliceWitness,
    pub old_vault: VaultDescriptorV2,
    pub new_vault: VaultDescriptorV2,
    pub deltas: Vec<SpliceAssetDelta>,
    pub withdrawals: Vec<VaultAssetAmount>,
    pub remaining_settlement: Vec<VaultAssetAmount>,
    pub asset_registry: AssetRegistry,
}

pub fn bytes32(tag: u8) -> Bytes32 {
    [tag; 32]
}
