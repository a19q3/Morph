use std::collections::BTreeSet;
use std::fs;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, anyhow, ensure};
#[cfg(test)]
use k256::ecdsa::VerifyingKey;
use k256::ecdsa::signature::hazmat::PrehashSigner;
#[cfg(test)]
use k256::ecdsa::signature::hazmat::PrehashVerifier;
use k256::ecdsa::{Signature, SigningKey};
use morph_core::{
    Amount, Bytes32, Mode, ParticipantSignature, Phase, SpliceAssetDelta, SpliceHeader, SpliceKind,
    SpliceTransition, SpliceWitness, StateCell, StateHeader, VaultAsset, VaultAssetAmount,
    VaultDescriptor, bytes32, funding_context_id, participants_commitment,
    splice_asset_delta_commitment, validate_splice_transition, vault_descriptor_commitment,
};
use morph_script_common::{
    COMPRESSED_SECP256K1_PUBKEY_LEN, ECDSA_SIGNATURE_LEN, SPLICE_ASSET_DELTA_LEN,
    SPLICE_ASSET_DELTAS_LEN, SPLICE_HEADER_LEN, SPLICE_SIGNATURE_COUNT, SPLICE_SIGNATURE_THRESHOLD,
    SPLICE_SIGNATURE_WITNESS_LEN, SPLICE_SIGNATURE_WITNESS_VERSION,
    SPLICE_STATE_TRANSITION_WITNESS_LEN, SPLICE_STATE_TRANSITION_WITNESS_VERSION,
    SPLICE_VAULT_ASSET_AMOUNT_LEN, SPLICE_VAULT_DESCRIPTOR_LEN, STATE_HEADER_LEN,
    SpliceStateTransitionWitness, StateHeaderInput, VAULT_ASSET_KIND_CKB, VAULT_ASSET_KIND_XUDT,
    encode_state_header,
};
use serde::{Deserialize, Serialize};

use crate::packages::{PackageOutPoint, canonical_hex32};

const SPLICE_PACKAGE_SCHEMA: &str = "morph.splice_package";
const SIGNATURE_SCHEME_SECP256K1_ECDSA_BLAKE2B: u16 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FixtureSpliceKind {
    SpliceIn,
    SpliceOut,
    XudtSpliceIn,
    XudtSpliceOut,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredSpliceStateRef {
    pub protocol_version: u16,
    pub chain_id: String,
    pub signature_scheme_id: u16,
    pub channel_id: String,
    pub funding_epoch: u64,
    pub funding_anchor: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub funding_context_id: Option<String>,
    pub vault_set_commitment: String,
    pub state_number: u64,
    pub mode: String,
    pub phase: String,
    pub participants_commitment: String,
    pub asset_registry_commitment: String,
    pub settlement_descriptor_commitment: String,
    pub descriptor_version: u16,
    pub payload_commitment: String,
    pub challenge_policy_commitment: String,
    pub state_layout_version: u16,
    pub capacity: u64,
    pub occupied_capacity: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredVaultAssetAmount {
    pub asset: String,
    pub type_hash: Option<String>,
    pub amount: Amount,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredVaultDescriptor {
    pub funding_anchor: String,
    pub assets: Vec<StoredVaultAssetAmount>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredSpliceAssetDelta {
    pub asset: String,
    pub type_hash: Option<String>,
    pub old_amount: Amount,
    pub new_amount: Amount,
    pub external_input: Amount,
    pub withdrawal: Amount,
    pub signed_fee: Amount,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredSpliceSignature {
    pub pubkey_sec1: String,
    pub signature: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredSpliceSponsorHint {
    pub sponsor_source: String,
    pub change_lock: String,
    pub max_fee_per_tx: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredSplicePackage {
    pub schema: String,
    pub created_unix_ms: u64,
    pub kind: String,
    pub channel_id: String,
    pub old_funding_anchor: String,
    pub new_funding_anchor: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub old_funding_context_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub new_funding_context_id: Option<String>,
    pub old_funding_epoch: u64,
    pub new_funding_epoch: u64,
    pub base_state_number: u64,
    pub splice_number: u64,
    pub old_vault_commitment: String,
    pub new_vault_commitment: String,
    pub asset_delta_commitment: String,
    pub participants_commitment: String,
    pub payload_commitment: String,
    pub challenge_policy_commitment: String,
    pub signing_digest: String,
    pub current_state: StoredSpliceStateRef,
    pub old_vault_descriptor: StoredVaultDescriptor,
    pub expected_new_vault_descriptor: StoredVaultDescriptor,
    pub asset_deltas: Vec<StoredSpliceAssetDelta>,
    pub withdrawals: Vec<StoredVaultAssetAmount>,
    pub remaining_settlement: Vec<StoredVaultAssetAmount>,
    pub signature_threshold: u8,
    pub signatures: Vec<StoredSpliceSignature>,
    pub current_state_out_point: Option<PackageOutPoint>,
    pub old_vault_out_point: Option<PackageOutPoint>,
    pub sponsor_policy_hint: Option<StoredSpliceSponsorHint>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SplicePackageSummary {
    pub channel_id: String,
    pub kind: String,
    pub base_state_number: u64,
    pub old_funding_epoch: u64,
    pub new_funding_epoch: u64,
    pub splice_number: u64,
    pub signing_digest: String,
    pub asset_delta_commitment: String,
    pub deltas: usize,
    pub withdrawals: usize,
    pub withdrawal_payout_policy: String,
    pub withdrawal_participant_pubkey_sec1: Option<String>,
    pub remaining_settlement_assets: usize,
    pub contract_witness_len: usize,
    pub contract_witness_hex: String,
    pub current_state_header_hex: String,
    pub next_state_header_hex: String,
}

impl StoredSplicePackage {
    pub fn from_transition(
        transition: &SpliceTransition,
        current_state_out_point: Option<PackageOutPoint>,
        old_vault_out_point: Option<PackageOutPoint>,
        sponsor_policy_hint: Option<StoredSpliceSponsorHint>,
    ) -> Result<Self> {
        let package = Self::from_transition_unchecked(
            transition,
            current_state_out_point,
            old_vault_out_point,
            sponsor_policy_hint,
        )?;
        package.validate()?;
        Ok(package)
    }

    pub(crate) fn from_transition_unchecked(
        transition: &SpliceTransition,
        current_state_out_point: Option<PackageOutPoint>,
        old_vault_out_point: Option<PackageOutPoint>,
        sponsor_policy_hint: Option<StoredSpliceSponsorHint>,
    ) -> Result<Self> {
        let digest = transition.header.signing_digest();
        Ok(Self {
            schema: SPLICE_PACKAGE_SCHEMA.to_string(),
            created_unix_ms: now_unix_ms()?,
            kind: match transition.header.kind {
                SpliceKind::In => "splice_in",
                SpliceKind::Out => "splice_out",
            }
            .to_string(),
            channel_id: hex_prefixed(&transition.header.channel_id),
            old_funding_anchor: hex_prefixed(&transition.header.old_funding_anchor),
            new_funding_anchor: hex_prefixed(&transition.header.new_funding_anchor),
            old_funding_context_id: Some(funding_context_id_hex(
                &transition.header.chain_id,
                &transition.header.channel_id,
                &transition.header.old_funding_anchor,
                &transition.header.old_vault_commitment,
            )),
            new_funding_context_id: Some(funding_context_id_hex(
                &transition.header.chain_id,
                &transition.header.channel_id,
                &transition.header.new_funding_anchor,
                &transition.header.new_vault_commitment,
            )),
            old_funding_epoch: transition.header.old_funding_epoch,
            new_funding_epoch: transition.header.new_funding_epoch,
            base_state_number: transition.header.base_state_number,
            splice_number: transition.header.splice_number,
            old_vault_commitment: hex_prefixed(&transition.header.old_vault_commitment),
            new_vault_commitment: hex_prefixed(&transition.header.new_vault_commitment),
            asset_delta_commitment: hex_prefixed(&transition.header.asset_delta_commitment),
            participants_commitment: hex_prefixed(&transition.header.participants_commitment),
            payload_commitment: hex_prefixed(&transition.header.payload_commitment),
            challenge_policy_commitment: hex_prefixed(
                &transition.header.challenge_policy_commitment,
            ),
            signing_digest: hex_prefixed(&digest),
            current_state: StoredSpliceStateRef::from_state_cell(&transition.current_state),
            old_vault_descriptor: StoredVaultDescriptor::from_descriptor(&transition.old_vault),
            expected_new_vault_descriptor: StoredVaultDescriptor::from_descriptor(
                &transition.new_vault,
            ),
            asset_deltas: transition
                .deltas
                .iter()
                .map(StoredSpliceAssetDelta::from_delta)
                .collect(),
            withdrawals: transition
                .withdrawals
                .iter()
                .map(StoredVaultAssetAmount::from_amount)
                .collect(),
            remaining_settlement: transition
                .remaining_settlement
                .iter()
                .map(StoredVaultAssetAmount::from_amount)
                .collect(),
            signature_threshold: transition.witness.threshold,
            signatures: transition
                .witness
                .signatures
                .iter()
                .map(StoredSpliceSignature::from_signature)
                .collect(),
            current_state_out_point,
            old_vault_out_point,
            sponsor_policy_hint,
        })
    }

    pub fn validate(&self) -> Result<SpliceTransition> {
        ensure!(
            self.schema == SPLICE_PACKAGE_SCHEMA,
            "unsupported splice package schema {}",
            self.schema
        );
        ensure!(
            self.kind == "splice_in" || self.kind == "splice_out",
            "unsupported splice kind {}",
            self.kind
        );
        ensure!(
            self.channel_id == canonical_hex32(&self.channel_id)?,
            "channel_id must be canonical"
        );
        ensure!(
            self.old_funding_anchor == canonical_hex32(&self.old_funding_anchor)?,
            "old_funding_anchor must be canonical"
        );
        ensure!(
            self.new_funding_anchor == canonical_hex32(&self.new_funding_anchor)?,
            "new_funding_anchor must be canonical"
        );
        if let Some(context_id) = &self.old_funding_context_id {
            ensure!(
                *context_id == canonical_hex32(context_id)?,
                "old_funding_context_id must be canonical"
            );
        }
        if let Some(context_id) = &self.new_funding_context_id {
            ensure!(
                *context_id == canonical_hex32(context_id)?,
                "new_funding_context_id must be canonical"
            );
        }
        ensure!(
            self.old_vault_commitment == canonical_hex32(&self.old_vault_commitment)?,
            "old_vault_commitment must be canonical"
        );
        ensure!(
            self.new_vault_commitment == canonical_hex32(&self.new_vault_commitment)?,
            "new_vault_commitment must be canonical"
        );
        ensure!(
            self.asset_delta_commitment == canonical_hex32(&self.asset_delta_commitment)?,
            "asset_delta_commitment must be canonical"
        );
        ensure!(
            self.participants_commitment == canonical_hex32(&self.participants_commitment)?,
            "participants_commitment must be canonical"
        );
        ensure!(
            self.challenge_policy_commitment == canonical_hex32(&self.challenge_policy_commitment)?,
            "challenge_policy_commitment must be canonical"
        );
        ensure!(
            self.signing_digest == canonical_hex32(&self.signing_digest)?,
            "signing_digest must be canonical"
        );
        if let Some(hint) = &self.sponsor_policy_hint {
            ensure!(
                hint.sponsor_source == canonical_hex32(&hint.sponsor_source)?,
                "sponsor_policy_hint.sponsor_source must be canonical"
            );
            ensure!(
                hint.change_lock == canonical_hex32(&hint.change_lock)?,
                "sponsor_policy_hint.change_lock must be canonical"
            );
        }
        ensure!(
            self.asset_deltas == canonical_deltas(&self.asset_deltas)?,
            "asset_deltas must be sorted unique canonical assets"
        );
        ensure!(
            self.withdrawals == canonical_amounts(&self.withdrawals)?,
            "withdrawals must be sorted unique canonical assets"
        );
        ensure!(
            self.remaining_settlement == canonical_amounts(&self.remaining_settlement)?,
            "remaining_settlement must be sorted unique canonical assets"
        );
        ensure!(
            self.signatures == canonical_signatures(&self.signatures)?,
            "signatures must contain sorted unique canonical pubkeys"
        );

        let transition = self.to_transition()?;
        let old_commitment = hex_prefixed(&vault_descriptor_commitment(&transition.old_vault));
        let new_commitment = hex_prefixed(&vault_descriptor_commitment(&transition.new_vault));
        let delta_commitment = hex_prefixed(&splice_asset_delta_commitment(&transition.deltas));
        ensure!(
            self.old_vault_commitment == old_commitment,
            "old_vault_commitment does not match old_vault_descriptor"
        );
        ensure!(
            self.new_vault_commitment == new_commitment,
            "new_vault_commitment does not match expected_new_vault_descriptor"
        );
        ensure!(
            self.asset_delta_commitment == delta_commitment,
            "asset_delta_commitment does not match asset_deltas"
        );
        ensure!(
            self.signing_digest == hex_prefixed(&transition.header.signing_digest()),
            "signing_digest does not match splice header"
        );
        if let Some(context_id) = &self.old_funding_context_id {
            ensure!(
                context_id
                    == &funding_context_id_hex(
                        &transition.header.chain_id,
                        &transition.header.channel_id,
                        &transition.header.old_funding_anchor,
                        &transition.header.old_vault_commitment,
                    ),
                "old_funding_context_id does not match splice old funding context"
            );
        }
        if let Some(context_id) = &self.new_funding_context_id {
            ensure!(
                context_id
                    == &funding_context_id_hex(
                        &transition.header.chain_id,
                        &transition.header.channel_id,
                        &transition.header.new_funding_anchor,
                        &transition.header.new_vault_commitment,
                    ),
                "new_funding_context_id does not match splice new funding context"
            );
        }

        validate_splice_transition(&transition)
            .map_err(|err| anyhow!("splice transition check failed: {err}"))?;
        Ok(transition)
    }

    pub fn summary(&self) -> Result<SplicePackageSummary> {
        let transition = self.validate()?;
        let contract_witness = self.contract_witness_bytes()?;
        let current_state_header = current_state_header_wire_bytes(&transition)?;
        let next_state_header = next_state_header_wire_bytes(&transition)?;
        let (withdrawal_payout_policy, withdrawal_participant_pubkey_sec1) =
            withdrawal_payout_summary(&self.withdrawals, &self.signatures);
        Ok(SplicePackageSummary {
            channel_id: self.channel_id.clone(),
            kind: self.kind.clone(),
            base_state_number: self.base_state_number,
            old_funding_epoch: self.old_funding_epoch,
            new_funding_epoch: self.new_funding_epoch,
            splice_number: self.splice_number,
            signing_digest: self.signing_digest.clone(),
            asset_delta_commitment: self.asset_delta_commitment.clone(),
            deltas: self.asset_deltas.len(),
            withdrawals: self.withdrawals.len(),
            withdrawal_payout_policy,
            withdrawal_participant_pubkey_sec1,
            remaining_settlement_assets: self.remaining_settlement.len(),
            contract_witness_len: contract_witness.len(),
            contract_witness_hex: hex_prefixed(&contract_witness),
            current_state_header_hex: hex_prefixed(&current_state_header),
            next_state_header_hex: hex_prefixed(&next_state_header),
        })
    }

    pub fn contract_witness_bytes(&self) -> Result<Vec<u8>> {
        let transition = self.validate()?;
        contract_witness_bytes_from_transition(&transition)
    }

    pub fn current_state_header_bytes(&self) -> Result<[u8; STATE_HEADER_LEN]> {
        let transition = self.validate()?;
        current_state_header_wire_bytes(&transition)
    }

    pub fn next_state_header_bytes(&self) -> Result<[u8; STATE_HEADER_LEN]> {
        let transition = self.validate()?;
        next_state_header_wire_bytes(&transition)
    }

    pub fn file_name(&self) -> String {
        let channel = self.channel_id.trim_start_matches("0x");
        let digest = self.signing_digest.trim_start_matches("0x");
        format!(
            "splice-{channel}-{:020}-{:020}-{}.json",
            self.new_funding_epoch,
            self.splice_number,
            &digest[0..16]
        )
    }

    fn to_transition(&self) -> Result<SpliceTransition> {
        let old_vault = self.old_vault_descriptor.to_descriptor()?;
        let new_vault = self.expected_new_vault_descriptor.to_descriptor()?;
        let deltas = self
            .asset_deltas
            .iter()
            .map(StoredSpliceAssetDelta::to_delta)
            .collect::<Result<Vec<_>>>()?;
        let withdrawals = self
            .withdrawals
            .iter()
            .map(StoredVaultAssetAmount::to_amount)
            .collect::<Result<Vec<_>>>()?;
        let remaining_settlement = self
            .remaining_settlement
            .iter()
            .map(StoredVaultAssetAmount::to_amount)
            .collect::<Result<Vec<_>>>()?;
        let header = SpliceHeader {
            protocol_version: self.current_state.protocol_version,
            chain_id: hex32_bytes(&self.current_state.chain_id)?,
            signature_scheme_id: self.current_state.signature_scheme_id,
            channel_id: hex32_bytes(&self.channel_id)?,
            old_funding_anchor: hex32_bytes(&self.old_funding_anchor)?,
            new_funding_anchor: hex32_bytes(&self.new_funding_anchor)?,
            old_funding_epoch: self.old_funding_epoch,
            new_funding_epoch: self.new_funding_epoch,
            base_state_number: self.base_state_number,
            splice_number: self.splice_number,
            kind: parse_kind(&self.kind)?,
            old_vault_commitment: hex32_bytes(&self.old_vault_commitment)?,
            new_vault_commitment: hex32_bytes(&self.new_vault_commitment)?,
            asset_delta_commitment: hex32_bytes(&self.asset_delta_commitment)?,
            participants_commitment: hex32_bytes(&self.participants_commitment)?,
            payload_commitment: hex32_bytes(&self.payload_commitment)?,
            challenge_policy_commitment: hex32_bytes(&self.challenge_policy_commitment)?,
        };
        Ok(SpliceTransition {
            current_state: self.current_state.to_state_cell()?,
            header,
            witness: SpliceWitness {
                threshold: self.signature_threshold,
                signatures: self
                    .signatures
                    .iter()
                    .map(StoredSpliceSignature::to_signature)
                    .collect::<Result<Vec<_>>>()?,
            },
            old_vault,
            new_vault,
            deltas,
            withdrawals,
            remaining_settlement,
            asset_registry: asset_registry_from_package(self)?,
        })
    }
}

impl StoredSpliceStateRef {
    fn from_state_cell(state: &StateCell) -> Self {
        Self {
            protocol_version: state.header.protocol_version,
            chain_id: hex_prefixed(&state.header.chain_id),
            signature_scheme_id: state.header.signature_scheme_id,
            channel_id: hex_prefixed(&state.header.channel_id),
            funding_epoch: state.header.funding_epoch,
            funding_anchor: hex_prefixed(&state.header.funding_anchor),
            funding_context_id: Some(hex_prefixed(&state.header.funding_context_id())),
            vault_set_commitment: hex_prefixed(&state.header.vault_set_commitment),
            state_number: state.header.state_number,
            mode: mode_label(state.header.mode).to_string(),
            phase: phase_label(state.header.phase).to_string(),
            participants_commitment: hex_prefixed(&state.header.participants_commitment),
            asset_registry_commitment: hex_prefixed(&state.header.asset_registry_commitment),
            settlement_descriptor_commitment: hex_prefixed(
                &state.header.settlement_descriptor_commitment,
            ),
            descriptor_version: state.header.descriptor_version,
            payload_commitment: hex_prefixed(&state.header.payload_commitment),
            challenge_policy_commitment: hex_prefixed(&state.header.challenge_policy_commitment),
            state_layout_version: state.header.state_layout_version,
            capacity: state.capacity,
            occupied_capacity: state.occupied_capacity,
        }
    }

    fn to_state_cell(&self) -> Result<StateCell> {
        let mode = parse_mode(&self.mode)?;
        let phase = parse_phase(&self.phase)?;
        ensure!(
            mode == Mode::BilateralPlain,
            "splice current_state mode must be bilateral_plain"
        );
        ensure!(
            phase == Phase::Active,
            "splice current_state phase must be active"
        );
        ensure!(
            self.chain_id == canonical_hex32(&self.chain_id)?,
            "current_state.chain_id must be canonical"
        );
        ensure!(
            self.channel_id == canonical_hex32(&self.channel_id)?,
            "current_state.channel_id must be canonical"
        );
        ensure!(
            self.funding_anchor == canonical_hex32(&self.funding_anchor)?,
            "current_state.funding_anchor must be canonical"
        );
        ensure!(
            self.vault_set_commitment == canonical_hex32(&self.vault_set_commitment)?,
            "current_state.vault_set_commitment must be canonical"
        );
        if let Some(context_id) = &self.funding_context_id {
            ensure!(
                *context_id == canonical_hex32(context_id)?,
                "current_state.funding_context_id must be canonical"
            );
        }
        ensure!(
            self.participants_commitment == canonical_hex32(&self.participants_commitment)?,
            "current_state.participants_commitment must be canonical"
        );
        ensure!(
            self.asset_registry_commitment == canonical_hex32(&self.asset_registry_commitment)?,
            "current_state.asset_registry_commitment must be canonical"
        );
        ensure!(
            self.settlement_descriptor_commitment
                == canonical_hex32(&self.settlement_descriptor_commitment)?,
            "current_state.settlement_descriptor_commitment must be canonical"
        );
        ensure!(
            self.payload_commitment == canonical_hex32(&self.payload_commitment)?,
            "current_state.payload_commitment must be canonical"
        );
        ensure!(
            self.challenge_policy_commitment == canonical_hex32(&self.challenge_policy_commitment)?,
            "current_state.challenge_policy_commitment must be canonical"
        );
        let state = StateCell {
            header: StateHeader {
                protocol_version: self.protocol_version,
                chain_id: hex32_bytes(&self.chain_id)?,
                signature_scheme_id: self.signature_scheme_id,
                channel_id: hex32_bytes(&self.channel_id)?,
                funding_epoch: self.funding_epoch,
                funding_anchor: hex32_bytes(&self.funding_anchor)?,
                vault_set_commitment: hex32_bytes(&self.vault_set_commitment)?,
                state_number: self.state_number,
                mode,
                phase,
                participants_commitment: hex32_bytes(&self.participants_commitment)?,
                asset_registry_commitment: hex32_bytes(&self.asset_registry_commitment)?,
                settlement_descriptor_commitment: hex32_bytes(
                    &self.settlement_descriptor_commitment,
                )?,
                descriptor_version: self.descriptor_version,
                payload_commitment: hex32_bytes(&self.payload_commitment)?,
                challenge_policy_commitment: hex32_bytes(&self.challenge_policy_commitment)?,
                state_layout_version: self.state_layout_version,
            },
            capacity: self.capacity,
            occupied_capacity: self.occupied_capacity,
        };
        if let Some(context_id) = &self.funding_context_id {
            ensure!(
                context_id == &hex_prefixed(&state.header.funding_context_id()),
                "current_state.funding_context_id does not match current_state funding context"
            );
        }
        Ok(state)
    }
}

impl StoredVaultDescriptor {
    fn from_descriptor(descriptor: &VaultDescriptor) -> Self {
        Self {
            funding_anchor: hex_prefixed(&descriptor.funding_anchor),
            assets: descriptor
                .assets
                .iter()
                .map(StoredVaultAssetAmount::from_amount)
                .collect(),
        }
    }

    fn to_descriptor(&self) -> Result<VaultDescriptor> {
        ensure!(
            self.funding_anchor == canonical_hex32(&self.funding_anchor)?,
            "vault descriptor funding_anchor must be canonical"
        );
        ensure!(
            self.assets == canonical_amounts(&self.assets)?,
            "vault descriptor assets must be sorted unique canonical assets"
        );
        Ok(VaultDescriptor {
            funding_anchor: hex32_bytes(&self.funding_anchor)?,
            assets: self
                .assets
                .iter()
                .map(StoredVaultAssetAmount::to_amount)
                .collect::<Result<Vec<_>>>()?,
        })
    }
}

impl StoredVaultAssetAmount {
    fn from_amount(amount: &VaultAssetAmount) -> Self {
        let (asset, type_hash) = stored_asset(&amount.asset);
        Self {
            asset,
            type_hash,
            amount: amount.amount,
        }
    }

    fn to_amount(&self) -> Result<VaultAssetAmount> {
        Ok(VaultAssetAmount {
            asset: self.to_asset()?,
            amount: self.amount,
        })
    }

    fn to_asset(&self) -> Result<VaultAsset> {
        parse_asset(&self.asset, self.type_hash.as_deref())
    }

    fn canonical(&self) -> Result<Self> {
        let asset = self.to_asset()?;
        let (asset, type_hash) = stored_asset(&asset);
        Ok(Self {
            asset,
            type_hash,
            amount: self.amount,
        })
    }
}

impl StoredSpliceAssetDelta {
    fn from_delta(delta: &SpliceAssetDelta) -> Self {
        let (asset, type_hash) = stored_asset(&delta.asset);
        Self {
            asset,
            type_hash,
            old_amount: delta.old_amount,
            new_amount: delta.new_amount,
            external_input: delta.external_input,
            withdrawal: delta.withdrawal,
            signed_fee: delta.signed_fee,
        }
    }

    fn to_delta(&self) -> Result<SpliceAssetDelta> {
        Ok(SpliceAssetDelta {
            asset: parse_asset(&self.asset, self.type_hash.as_deref())?,
            old_amount: self.old_amount,
            new_amount: self.new_amount,
            external_input: self.external_input,
            withdrawal: self.withdrawal,
            signed_fee: self.signed_fee,
        })
    }

    fn canonical(&self) -> Result<Self> {
        let delta = self.to_delta()?;
        Ok(Self::from_delta(&delta))
    }
}

impl StoredSpliceSignature {
    fn from_signature(signature: &ParticipantSignature) -> Self {
        Self {
            pubkey_sec1: hex_prefixed(&signature.pubkey_sec1),
            signature: hex_prefixed(&signature.signature),
        }
    }

    fn to_signature(&self) -> Result<ParticipantSignature> {
        Ok(ParticipantSignature {
            pubkey_sec1: decode_hex_exact(&self.pubkey_sec1, 33, "pubkey_sec1")?,
            signature: decode_hex_exact(&self.signature, 64, "signature")?,
        })
    }
}

pub fn read_splice_package(path: &Path) -> Result<StoredSplicePackage> {
    let bytes = fs::read(path)
        .with_context(|| format!("failed to read splice package {}", path.display()))?;
    let package: StoredSplicePackage = serde_json::from_slice(&bytes)
        .with_context(|| format!("failed to parse splice package {}", path.display()))?;
    package
        .validate()
        .with_context(|| format!("invalid splice package {}", path.display()))?;
    Ok(package)
}

pub fn write_splice_package(
    dir: &Path,
    package: &StoredSplicePackage,
) -> Result<std::path::PathBuf> {
    package.validate()?;
    fs::create_dir_all(dir).with_context(|| {
        format!(
            "failed to create splice package directory {}",
            dir.display()
        )
    })?;
    let path = dir.join(package.file_name());
    let tmp = crate::packages::atomic_json_tmp_path(&path);
    let json = serde_json::to_vec_pretty(package)?;
    fs::write(&tmp, json)
        .with_context(|| format!("failed to write temporary splice package {}", tmp.display()))?;
    fs::rename(&tmp, &path).with_context(|| {
        format!(
            "failed to atomically move splice package {} to {}",
            tmp.display(),
            path.display()
        )
    })?;
    Ok(path)
}

pub fn fixture_package_with_kind(kind: FixtureSpliceKind) -> Result<StoredSplicePackage> {
    let alice = SigningKey::from_slice(&[1u8; 32]).unwrap();
    let bob = SigningKey::from_slice(&[2u8; 32]).unwrap();
    let mut entries = [
        (compressed_pubkey(&alice), alice),
        (compressed_pubkey(&bob), bob),
    ];
    entries.sort_by(|left, right| left.0.cmp(&right.0));
    let pubkeys = [entries[0].0.as_slice(), entries[1].0.as_slice()];
    let participants_commitment = participants_commitment(2, &pubkeys);

    let mut current_state = StateCell {
        header: StateHeader {
            protocol_version: 1,
            chain_id: bytes32(1),
            signature_scheme_id: SIGNATURE_SCHEME_SECP256K1_ECDSA_BLAKE2B,
            channel_id: bytes32(2),
            funding_epoch: 0,
            funding_anchor: bytes32(3),
            vault_set_commitment: bytes32(0),
            state_number: 7,
            mode: Mode::BilateralPlain,
            phase: Phase::Active,
            participants_commitment,
            asset_registry_commitment: bytes32(4),
            settlement_descriptor_commitment: bytes32(5),
            descriptor_version: 1,
            payload_commitment: bytes32(6),
            challenge_policy_commitment: bytes32(8),
            state_layout_version: 1,
        },
        capacity: 10_000,
        occupied_capacity: 1_000,
    };
    let (kind_label, header_kind, old_vault, new_vault, deltas, withdrawals, remaining_settlement) =
        fixture_splice_parts(kind);
    current_state.header.vault_set_commitment = vault_descriptor_commitment(&old_vault);
    let header = SpliceHeader {
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
        kind: header_kind,
        old_vault_commitment: vault_descriptor_commitment(&old_vault),
        new_vault_commitment: vault_descriptor_commitment(&new_vault),
        asset_delta_commitment: splice_asset_delta_commitment(&deltas),
        participants_commitment,
        payload_commitment: current_state.header.payload_commitment,
        challenge_policy_commitment: current_state.header.challenge_policy_commitment,
    };
    let digest = header.signing_digest();
    let signatures = entries
        .iter()
        .map(|(pubkey, key)| sign_digest(pubkey, key, &digest))
        .collect::<Result<Vec<_>>>()?;

    let package = StoredSplicePackage {
        schema: SPLICE_PACKAGE_SCHEMA.to_string(),
        created_unix_ms: now_unix_ms()?,
        kind: kind_label.to_string(),
        channel_id: hex_prefixed(&header.channel_id),
        old_funding_anchor: hex_prefixed(&header.old_funding_anchor),
        new_funding_anchor: hex_prefixed(&header.new_funding_anchor),
        old_funding_context_id: Some(funding_context_id_hex(
            &header.chain_id,
            &header.channel_id,
            &header.old_funding_anchor,
            &header.old_vault_commitment,
        )),
        new_funding_context_id: Some(funding_context_id_hex(
            &header.chain_id,
            &header.channel_id,
            &header.new_funding_anchor,
            &header.new_vault_commitment,
        )),
        old_funding_epoch: header.old_funding_epoch,
        new_funding_epoch: header.new_funding_epoch,
        base_state_number: header.base_state_number,
        splice_number: header.splice_number,
        old_vault_commitment: hex_prefixed(&header.old_vault_commitment),
        new_vault_commitment: hex_prefixed(&header.new_vault_commitment),
        asset_delta_commitment: hex_prefixed(&header.asset_delta_commitment),
        participants_commitment: hex_prefixed(&header.participants_commitment),
        payload_commitment: hex_prefixed(&header.payload_commitment),
        challenge_policy_commitment: hex_prefixed(&header.challenge_policy_commitment),
        signing_digest: hex_prefixed(&digest),
        current_state: StoredSpliceStateRef::from_state_cell(&current_state),
        old_vault_descriptor: StoredVaultDescriptor::from_descriptor(&old_vault),
        expected_new_vault_descriptor: StoredVaultDescriptor::from_descriptor(&new_vault),
        asset_deltas: deltas
            .iter()
            .map(StoredSpliceAssetDelta::from_delta)
            .collect(),
        withdrawals: withdrawals
            .iter()
            .map(StoredVaultAssetAmount::from_amount)
            .collect(),
        remaining_settlement: remaining_settlement
            .iter()
            .map(StoredVaultAssetAmount::from_amount)
            .collect(),
        signature_threshold: 2,
        signatures,
        current_state_out_point: Some(PackageOutPoint {
            tx_hash: hex_prefixed(&bytes32(90)),
            index: 0,
        }),
        old_vault_out_point: Some(PackageOutPoint {
            tx_hash: hex_prefixed(&bytes32(91)),
            index: 1,
        }),
        sponsor_policy_hint: Some(StoredSpliceSponsorHint {
            sponsor_source: hex_prefixed(&bytes32(92)),
            change_lock: hex_prefixed(&bytes32(93)),
            max_fee_per_tx: 200_000_000,
        }),
    };
    package.validate()?;
    Ok(package)
}

type FixtureSpliceParts = (
    &'static str,
    SpliceKind,
    VaultDescriptor,
    VaultDescriptor,
    Vec<SpliceAssetDelta>,
    Vec<VaultAssetAmount>,
    Vec<VaultAssetAmount>,
);

fn fixture_splice_parts(kind: FixtureSpliceKind) -> FixtureSpliceParts {
    match kind {
        FixtureSpliceKind::SpliceIn => {
            let old_vault = VaultDescriptor {
                funding_anchor: bytes32(3),
                assets: vec![
                    VaultAssetAmount {
                        asset: VaultAsset::Ckb,
                        amount: 10_000_000_000,
                    },
                    VaultAssetAmount {
                        asset: VaultAsset::Xudt(bytes32(42)),
                        amount: 100,
                    },
                ],
            };
            let new_vault = VaultDescriptor {
                funding_anchor: bytes32(33),
                assets: vec![
                    VaultAssetAmount {
                        asset: VaultAsset::Ckb,
                        amount: 14_900_000_000,
                    },
                    VaultAssetAmount {
                        asset: VaultAsset::Xudt(bytes32(42)),
                        amount: 125,
                    },
                ],
            };
            (
                "splice_in",
                SpliceKind::In,
                old_vault,
                new_vault,
                vec![
                    SpliceAssetDelta {
                        asset: VaultAsset::Ckb,
                        old_amount: 10_000_000_000,
                        new_amount: 14_900_000_000,
                        external_input: 5_000_000_000,
                        withdrawal: 0,
                        signed_fee: 100_000_000,
                    },
                    SpliceAssetDelta {
                        asset: VaultAsset::Xudt(bytes32(42)),
                        old_amount: 100,
                        new_amount: 125,
                        external_input: 25,
                        withdrawal: 0,
                        signed_fee: 0,
                    },
                ],
                Vec::new(),
                vec![
                    VaultAssetAmount {
                        asset: VaultAsset::Ckb,
                        amount: 12_000_000_000,
                    },
                    VaultAssetAmount {
                        asset: VaultAsset::Xudt(bytes32(42)),
                        amount: 125,
                    },
                ],
            )
        }
        FixtureSpliceKind::SpliceOut => {
            let old_vault = VaultDescriptor {
                funding_anchor: bytes32(3),
                assets: vec![
                    VaultAssetAmount {
                        asset: VaultAsset::Ckb,
                        amount: 10_000_000_000,
                    },
                    VaultAssetAmount {
                        asset: VaultAsset::Xudt(bytes32(42)),
                        amount: 100,
                    },
                ],
            };
            let new_vault = VaultDescriptor {
                funding_anchor: bytes32(33),
                assets: vec![
                    VaultAssetAmount {
                        asset: VaultAsset::Ckb,
                        amount: 7_000_000_000,
                    },
                    VaultAssetAmount {
                        asset: VaultAsset::Xudt(bytes32(42)),
                        amount: 100,
                    },
                ],
            };
            (
                "splice_out",
                SpliceKind::Out,
                old_vault,
                new_vault,
                vec![SpliceAssetDelta {
                    asset: VaultAsset::Ckb,
                    old_amount: 10_000_000_000,
                    new_amount: 7_000_000_000,
                    external_input: 0,
                    withdrawal: 3_000_000_000,
                    signed_fee: 0,
                }],
                vec![VaultAssetAmount {
                    asset: VaultAsset::Ckb,
                    amount: 3_000_000_000,
                }],
                vec![
                    VaultAssetAmount {
                        asset: VaultAsset::Ckb,
                        amount: 6_500_000_000,
                    },
                    VaultAssetAmount {
                        asset: VaultAsset::Xudt(bytes32(42)),
                        amount: 100,
                    },
                ],
            )
        }
        FixtureSpliceKind::XudtSpliceIn => {
            let old_vault = VaultDescriptor {
                funding_anchor: bytes32(3),
                assets: vec![
                    VaultAssetAmount {
                        asset: VaultAsset::Ckb,
                        amount: 10_000_000_000,
                    },
                    VaultAssetAmount {
                        asset: VaultAsset::Xudt(bytes32(42)),
                        amount: 100,
                    },
                ],
            };
            let new_vault = VaultDescriptor {
                funding_anchor: bytes32(33),
                assets: vec![
                    VaultAssetAmount {
                        asset: VaultAsset::Ckb,
                        amount: 10_000_000_000,
                    },
                    VaultAssetAmount {
                        asset: VaultAsset::Xudt(bytes32(42)),
                        amount: 125,
                    },
                ],
            };
            (
                "splice_in",
                SpliceKind::In,
                old_vault,
                new_vault,
                vec![SpliceAssetDelta {
                    asset: VaultAsset::Xudt(bytes32(42)),
                    old_amount: 100,
                    new_amount: 125,
                    external_input: 25,
                    withdrawal: 0,
                    signed_fee: 0,
                }],
                Vec::new(),
                vec![
                    VaultAssetAmount {
                        asset: VaultAsset::Ckb,
                        amount: 8_000_000_000,
                    },
                    VaultAssetAmount {
                        asset: VaultAsset::Xudt(bytes32(42)),
                        amount: 125,
                    },
                ],
            )
        }
        FixtureSpliceKind::XudtSpliceOut => {
            let old_vault = VaultDescriptor {
                funding_anchor: bytes32(3),
                assets: vec![
                    VaultAssetAmount {
                        asset: VaultAsset::Ckb,
                        amount: 10_000_000_000,
                    },
                    VaultAssetAmount {
                        asset: VaultAsset::Xudt(bytes32(42)),
                        amount: 100,
                    },
                ],
            };
            let new_vault = VaultDescriptor {
                funding_anchor: bytes32(33),
                assets: vec![
                    VaultAssetAmount {
                        asset: VaultAsset::Ckb,
                        amount: 10_000_000_000,
                    },
                    VaultAssetAmount {
                        asset: VaultAsset::Xudt(bytes32(42)),
                        amount: 70,
                    },
                ],
            };
            (
                "splice_out",
                SpliceKind::Out,
                old_vault,
                new_vault,
                vec![SpliceAssetDelta {
                    asset: VaultAsset::Xudt(bytes32(42)),
                    old_amount: 100,
                    new_amount: 70,
                    external_input: 0,
                    withdrawal: 30,
                    signed_fee: 0,
                }],
                vec![VaultAssetAmount {
                    asset: VaultAsset::Xudt(bytes32(42)),
                    amount: 30,
                }],
                vec![
                    VaultAssetAmount {
                        asset: VaultAsset::Ckb,
                        amount: 8_000_000_000,
                    },
                    VaultAssetAmount {
                        asset: VaultAsset::Xudt(bytes32(42)),
                        amount: 70,
                    },
                ],
            )
        }
    }
}

fn asset_registry_from_package(package: &StoredSplicePackage) -> Result<morph_core::AssetRegistry> {
    let mut xudt_types = BTreeSet::new();
    for asset in package
        .old_vault_descriptor
        .assets
        .iter()
        .chain(package.expected_new_vault_descriptor.assets.iter())
        .chain(package.withdrawals.iter())
        .chain(package.remaining_settlement.iter())
    {
        if let VaultAsset::Xudt(type_hash) = asset.to_asset()? {
            xudt_types.insert(type_hash);
        }
    }
    for delta in &package.asset_deltas {
        if let VaultAsset::Xudt(type_hash) = delta.to_delta()?.asset {
            xudt_types.insert(type_hash);
        }
    }
    Ok(morph_core::AssetRegistry { xudt_types })
}

fn parse_kind(value: &str) -> Result<SpliceKind> {
    match value {
        "splice_in" => Ok(SpliceKind::In),
        "splice_out" => Ok(SpliceKind::Out),
        other => Err(anyhow!("unsupported splice kind {other}")),
    }
}

fn parse_asset(asset: &str, type_hash: Option<&str>) -> Result<VaultAsset> {
    match asset {
        "ckb" => {
            ensure!(type_hash.is_none(), "ckb asset must not include type_hash");
            Ok(VaultAsset::Ckb)
        }
        "xudt" => {
            let type_hash = type_hash.ok_or_else(|| anyhow!("xudt asset requires type_hash"))?;
            Ok(VaultAsset::Xudt(hex32_bytes(type_hash)?))
        }
        other => Err(anyhow!("unsupported vault asset {other}")),
    }
}

fn stored_asset(asset: &VaultAsset) -> (String, Option<String>) {
    match asset {
        VaultAsset::Ckb => ("ckb".to_string(), None),
        VaultAsset::Xudt(type_hash) => ("xudt".to_string(), Some(hex_prefixed(type_hash))),
    }
}

fn next_state_header_for_splice(transition: &SpliceTransition) -> StateHeader {
    let mut header = transition.current_state.header.clone();
    header.funding_epoch = transition.header.new_funding_epoch;
    header.funding_anchor = transition.header.new_funding_anchor;
    header.vault_set_commitment = transition.header.new_vault_commitment;
    header.phase = Phase::Active;
    header
}

fn current_state_header_wire_bytes(
    transition: &SpliceTransition,
) -> Result<[u8; STATE_HEADER_LEN]> {
    state_header_wire_bytes(&transition.current_state.header)
}

fn next_state_header_wire_bytes(transition: &SpliceTransition) -> Result<[u8; STATE_HEADER_LEN]> {
    state_header_wire_bytes(&next_state_header_for_splice(transition))
}

fn state_header_wire_bytes(header: &StateHeader) -> Result<[u8; STATE_HEADER_LEN]> {
    Ok(encode_state_header(&StateHeaderInput {
        protocol_version: header.protocol_version,
        chain_id: header.chain_id,
        signature_scheme_id: header.signature_scheme_id,
        channel_id: header.channel_id,
        funding_epoch: header.funding_epoch,
        funding_anchor: header.funding_anchor,
        vault_set_commitment: header.vault_set_commitment,
        state_number: header.state_number,
        mode: mode_wire_byte(header.mode),
        phase: phase_wire_byte(header.phase),
        participants_commitment: header.participants_commitment,
        asset_registry_commitment: header.asset_registry_commitment,
        settlement_descriptor_commitment: header.settlement_descriptor_commitment,
        descriptor_version: header.descriptor_version,
        payload_commitment: header.payload_commitment,
        challenge_policy_commitment: header.challenge_policy_commitment,
        state_layout_version: 2,
    }))
}

fn contract_witness_bytes_from_transition(transition: &SpliceTransition) -> Result<Vec<u8>> {
    let header = splice_header_wire_bytes(&transition.header);
    let signatures = splice_signature_witness_wire_bytes(&transition.witness)?;
    let old_vault = splice_vault_descriptor_wire_bytes(&transition.old_vault)?;
    let new_vault = splice_vault_descriptor_wire_bytes(&transition.new_vault)?;
    let deltas = splice_asset_deltas_wire_bytes(&transition.deltas)?;

    let mut raw = vec![0u8; SPLICE_STATE_TRANSITION_WITNESS_LEN];
    put_u16(&mut raw, 0, SPLICE_STATE_TRANSITION_WITNESS_VERSION);
    let mut offset = 2;
    raw[offset..offset + SPLICE_HEADER_LEN].copy_from_slice(&header);
    offset += SPLICE_HEADER_LEN;
    raw[offset..offset + SPLICE_SIGNATURE_WITNESS_LEN].copy_from_slice(&signatures);
    offset += SPLICE_SIGNATURE_WITNESS_LEN;
    raw[offset..offset + SPLICE_VAULT_DESCRIPTOR_LEN].copy_from_slice(&old_vault);
    offset += SPLICE_VAULT_DESCRIPTOR_LEN;
    raw[offset..offset + SPLICE_VAULT_DESCRIPTOR_LEN].copy_from_slice(&new_vault);
    offset += SPLICE_VAULT_DESCRIPTOR_LEN;
    raw[offset..offset + SPLICE_ASSET_DELTAS_LEN].copy_from_slice(&deltas);

    let parsed = SpliceStateTransitionWitness::parse(&raw)
        .map_err(|err| anyhow!("encoded splice transition witness is invalid: {err:?}"))?;
    parsed
        .header()
        .map_err(|err| anyhow!("encoded splice header is invalid: {err:?}"))?;
    parsed
        .signatures()
        .map_err(|err| anyhow!("encoded splice signatures are invalid: {err:?}"))?;
    parsed
        .old_vault()
        .map_err(|err| anyhow!("encoded old splice vault descriptor is invalid: {err:?}"))?;
    parsed
        .new_vault()
        .map_err(|err| anyhow!("encoded new splice vault descriptor is invalid: {err:?}"))?;
    parsed
        .deltas()
        .map_err(|err| anyhow!("encoded splice asset deltas are invalid: {err:?}"))?;
    Ok(raw)
}

fn splice_header_wire_bytes(header: &SpliceHeader) -> [u8; SPLICE_HEADER_LEN] {
    let mut raw = [0u8; SPLICE_HEADER_LEN];
    put_u16(&mut raw, 0, header.protocol_version);
    raw[2..34].copy_from_slice(&header.chain_id);
    put_u16(&mut raw, 34, header.signature_scheme_id);
    raw[36..68].copy_from_slice(&header.channel_id);
    raw[68..100].copy_from_slice(&header.old_funding_anchor);
    raw[100..132].copy_from_slice(&header.new_funding_anchor);
    put_u64(&mut raw, 132, header.old_funding_epoch);
    put_u64(&mut raw, 140, header.new_funding_epoch);
    put_u64(&mut raw, 148, header.base_state_number);
    put_u64(&mut raw, 156, header.splice_number);
    raw[164] = splice_kind_wire_byte(header.kind);
    raw[165..197].copy_from_slice(&header.old_vault_commitment);
    raw[197..229].copy_from_slice(&header.new_vault_commitment);
    raw[229..261].copy_from_slice(&header.asset_delta_commitment);
    raw[261..293].copy_from_slice(&header.participants_commitment);
    raw[293..325].copy_from_slice(&header.payload_commitment);
    raw[325..357].copy_from_slice(&header.challenge_policy_commitment);
    raw
}

fn splice_signature_witness_wire_bytes(
    witness: &SpliceWitness,
) -> Result<[u8; SPLICE_SIGNATURE_WITNESS_LEN]> {
    ensure!(
        witness.threshold == SPLICE_SIGNATURE_THRESHOLD
            && witness.signatures.len() == SPLICE_SIGNATURE_COUNT as usize,
        "contract splice witness requires exactly two participant signatures"
    );

    let mut raw = [0u8; SPLICE_SIGNATURE_WITNESS_LEN];
    put_u16(&mut raw, 0, SPLICE_SIGNATURE_WITNESS_VERSION);
    raw[2] = SPLICE_SIGNATURE_THRESHOLD;
    raw[3] = SPLICE_SIGNATURE_COUNT;
    for (index, signature) in witness.signatures.iter().enumerate() {
        ensure!(
            signature.pubkey_sec1.len() == COMPRESSED_SECP256K1_PUBKEY_LEN,
            "splice participant pubkey must be compressed secp256k1"
        );
        ensure!(
            signature.signature.len() == ECDSA_SIGNATURE_LEN,
            "splice participant signature must be 64 bytes"
        );
        let offset = 4 + index * (COMPRESSED_SECP256K1_PUBKEY_LEN + ECDSA_SIGNATURE_LEN);
        raw[offset..offset + COMPRESSED_SECP256K1_PUBKEY_LEN]
            .copy_from_slice(&signature.pubkey_sec1);
        raw[offset + COMPRESSED_SECP256K1_PUBKEY_LEN
            ..offset + COMPRESSED_SECP256K1_PUBKEY_LEN + ECDSA_SIGNATURE_LEN]
            .copy_from_slice(&signature.signature);
    }
    Ok(raw)
}

fn splice_vault_descriptor_wire_bytes(
    descriptor: &VaultDescriptor,
) -> Result<[u8; SPLICE_VAULT_DESCRIPTOR_LEN]> {
    ensure!(
        !descriptor.assets.is_empty() && descriptor.assets.len() <= 2,
        "contract splice vault descriptor supports one or two assets"
    );
    let mut raw = [0u8; SPLICE_VAULT_DESCRIPTOR_LEN];
    raw[0..32].copy_from_slice(&descriptor.funding_anchor);
    put_u16(&mut raw, 32, descriptor.assets.len() as u16);
    for (index, asset) in descriptor.assets.iter().enumerate() {
        let offset = 34 + index * SPLICE_VAULT_ASSET_AMOUNT_LEN;
        raw[offset..offset + SPLICE_VAULT_ASSET_AMOUNT_LEN]
            .copy_from_slice(&splice_vault_asset_wire_bytes(asset));
    }
    Ok(raw)
}

fn splice_vault_asset_wire_bytes(amount: &VaultAssetAmount) -> [u8; SPLICE_VAULT_ASSET_AMOUNT_LEN] {
    let mut raw = [0u8; SPLICE_VAULT_ASSET_AMOUNT_LEN];
    let (kind, type_hash) = vault_asset_wire_key(&amount.asset);
    raw[0] = kind;
    raw[1..33].copy_from_slice(&type_hash);
    put_u128(&mut raw, 33, amount.amount);
    raw
}

fn splice_asset_deltas_wire_bytes(
    deltas: &[SpliceAssetDelta],
) -> Result<[u8; SPLICE_ASSET_DELTAS_LEN]> {
    ensure!(
        !deltas.is_empty() && deltas.len() <= 2,
        "contract splice asset deltas support one or two assets"
    );
    let mut raw = [0u8; SPLICE_ASSET_DELTAS_LEN];
    put_u16(&mut raw, 0, deltas.len() as u16);
    for (index, delta) in deltas.iter().enumerate() {
        let offset = 2 + index * SPLICE_ASSET_DELTA_LEN;
        raw[offset..offset + SPLICE_ASSET_DELTA_LEN]
            .copy_from_slice(&splice_asset_delta_wire_bytes(delta));
    }
    Ok(raw)
}

fn splice_asset_delta_wire_bytes(delta: &SpliceAssetDelta) -> [u8; SPLICE_ASSET_DELTA_LEN] {
    let mut raw = [0u8; SPLICE_ASSET_DELTA_LEN];
    let (kind, type_hash) = vault_asset_wire_key(&delta.asset);
    raw[0] = kind;
    raw[1..33].copy_from_slice(&type_hash);
    put_u128(&mut raw, 33, delta.old_amount);
    put_u128(&mut raw, 49, delta.new_amount);
    put_u128(&mut raw, 65, delta.external_input);
    put_u128(&mut raw, 81, delta.withdrawal);
    put_u128(&mut raw, 97, delta.signed_fee);
    raw
}

fn splice_kind_wire_byte(kind: SpliceKind) -> u8 {
    match kind {
        SpliceKind::In => 0,
        SpliceKind::Out => 1,
    }
}

fn vault_asset_wire_key(asset: &VaultAsset) -> (u8, Bytes32) {
    match asset {
        VaultAsset::Ckb => (VAULT_ASSET_KIND_CKB, [0u8; 32]),
        VaultAsset::Xudt(type_hash) => (VAULT_ASSET_KIND_XUDT, *type_hash),
    }
}

fn mode_wire_byte(mode: Mode) -> u8 {
    match mode {
        Mode::BilateralPlain => 1,
        Mode::FactoryProof => 2,
    }
}

fn phase_wire_byte(phase: Phase) -> u8 {
    match phase {
        Phase::Funding => 0,
        Phase::Active => 1,
        Phase::Settling => 2,
        Phase::Closed => 3,
    }
}

fn canonical_amounts(values: &[StoredVaultAssetAmount]) -> Result<Vec<StoredVaultAssetAmount>> {
    let mut out = values
        .iter()
        .map(StoredVaultAssetAmount::canonical)
        .collect::<Result<Vec<_>>>()?;
    out.sort_by_key(asset_amount_sort_key);
    ensure_unique_asset_amounts(&out)?;
    Ok(out)
}

fn canonical_deltas(values: &[StoredSpliceAssetDelta]) -> Result<Vec<StoredSpliceAssetDelta>> {
    let mut out = values
        .iter()
        .map(StoredSpliceAssetDelta::canonical)
        .collect::<Result<Vec<_>>>()?;
    out.sort_by_key(delta_sort_key);
    ensure_unique_deltas(&out)?;
    Ok(out)
}

fn canonical_signatures(values: &[StoredSpliceSignature]) -> Result<Vec<StoredSpliceSignature>> {
    let mut out = values
        .iter()
        .map(|signature| {
            Ok(StoredSpliceSignature {
                pubkey_sec1: canonical_hex_exact(&signature.pubkey_sec1, 33)?,
                signature: canonical_hex_exact(&signature.signature, 64)?,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    out.sort_by(|left, right| left.pubkey_sec1.cmp(&right.pubkey_sec1));
    ensure!(
        out.windows(2)
            .all(|window| window[0].pubkey_sec1 != window[1].pubkey_sec1),
        "splice package signatures contain duplicate pubkeys"
    );
    Ok(out)
}

fn ensure_unique_asset_amounts(values: &[StoredVaultAssetAmount]) -> Result<()> {
    ensure!(
        values.windows(2).all(
            |window| asset_key(&window[0].asset, window[0].type_hash.as_deref())
                != asset_key(&window[1].asset, window[1].type_hash.as_deref())
        ),
        "asset list contains duplicate assets"
    );
    Ok(())
}

fn ensure_unique_deltas(values: &[StoredSpliceAssetDelta]) -> Result<()> {
    ensure!(
        values.windows(2).all(
            |window| asset_key(&window[0].asset, window[0].type_hash.as_deref())
                != asset_key(&window[1].asset, window[1].type_hash.as_deref())
        ),
        "asset delta list contains duplicate assets"
    );
    Ok(())
}

fn asset_amount_sort_key(value: &StoredVaultAssetAmount) -> (u8, String) {
    asset_key(&value.asset, value.type_hash.as_deref())
}

fn delta_sort_key(value: &StoredSpliceAssetDelta) -> (u8, String) {
    asset_key(&value.asset, value.type_hash.as_deref())
}

fn asset_key(asset: &str, type_hash: Option<&str>) -> (u8, String) {
    match asset {
        "ckb" => (0, String::new()),
        "xudt" => (1, type_hash.unwrap_or_default().to_string()),
        _ => (u8::MAX, asset.to_string()),
    }
}

fn mode_label(mode: Mode) -> &'static str {
    match mode {
        Mode::BilateralPlain => "bilateral_plain",
        Mode::FactoryProof => "factory_proof",
    }
}

fn parse_mode(value: &str) -> Result<Mode> {
    match value {
        "bilateral_plain" => Ok(Mode::BilateralPlain),
        "factory_proof" => Ok(Mode::FactoryProof),
        other => Err(anyhow!("unsupported splice current_state mode {other}")),
    }
}

fn phase_label(phase: Phase) -> &'static str {
    match phase {
        Phase::Funding => "funding",
        Phase::Active => "active",
        Phase::Settling => "settling",
        Phase::Closed => "closed",
    }
}

fn parse_phase(value: &str) -> Result<Phase> {
    match value {
        "funding" => Ok(Phase::Funding),
        "active" => Ok(Phase::Active),
        "settling" => Ok(Phase::Settling),
        "closed" => Ok(Phase::Closed),
        other => Err(anyhow!("unsupported splice current_state phase {other}")),
    }
}

fn compressed_pubkey(key: &SigningKey) -> Vec<u8> {
    key.verifying_key()
        .to_encoded_point(true)
        .as_bytes()
        .to_vec()
}

fn sign_digest(pubkey: &[u8], key: &SigningKey, digest: &Bytes32) -> Result<StoredSpliceSignature> {
    let signature: Signature = key
        .sign_prehash(digest)
        .map_err(|err| anyhow!("failed to sign splice digest: {err:?}"))?;
    Ok(StoredSpliceSignature {
        pubkey_sec1: hex_prefixed(pubkey),
        signature: hex_prefixed(signature.to_bytes().as_ref()),
    })
}

#[cfg(test)]
fn verify_signature(pubkey_sec1: &str, signature: &str, digest: &Bytes32) -> Result<()> {
    let pubkey = decode_hex_exact(pubkey_sec1, 33, "pubkey_sec1")?;
    let signature = decode_hex_exact(signature, 64, "signature")?;
    let verifying_key = VerifyingKey::from_sec1_bytes(&pubkey)
        .map_err(|err| anyhow!("splice participant pubkey is invalid: {err:?}"))?;
    let signature = Signature::try_from(signature.as_slice())
        .map_err(|err| anyhow!("splice signature encoding is invalid: {err:?}"))?;
    verifying_key
        .verify_prehash(digest, &signature)
        .map_err(|err| anyhow!("splice signature is invalid: {err:?}"))
}

fn canonical_hex_exact(value: &str, byte_len: usize) -> Result<String> {
    let stripped = value.strip_prefix("0x").unwrap_or(value);
    ensure!(
        stripped.len() == byte_len * 2,
        "hex value must be {byte_len} bytes"
    );
    let bytes = hex::decode(stripped)?;
    ensure!(
        bytes.len() == byte_len,
        "hex value must be {byte_len} bytes"
    );
    Ok(hex_prefixed(&bytes))
}

fn decode_hex_exact(value: &str, byte_len: usize, field: &str) -> Result<Vec<u8>> {
    let canonical = canonical_hex_exact(value, byte_len)
        .with_context(|| format!("{field} must be canonical {byte_len}-byte hex"))?;
    Ok(hex::decode(canonical.trim_start_matches("0x"))?)
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

fn hex32_bytes(value: &str) -> Result<Bytes32> {
    let canonical = canonical_hex32(value)?;
    let bytes = hex::decode(canonical.trim_start_matches("0x"))?;
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn funding_context_id_hex(
    chain_id: &Bytes32,
    channel_id: &Bytes32,
    funding_anchor: &Bytes32,
    vault_set_commitment: &Bytes32,
) -> String {
    hex_prefixed(&funding_context_id(
        chain_id,
        channel_id,
        funding_anchor,
        vault_set_commitment,
    ))
}

fn hex_prefixed(bytes: &[u8]) -> String {
    format!("0x{}", hex::encode(bytes))
}

fn withdrawal_payout_summary(
    withdrawals: &[StoredVaultAssetAmount],
    signatures: &[StoredSpliceSignature],
) -> (String, Option<String>) {
    if withdrawals.is_empty() {
        return ("none".to_string(), None);
    }
    (
        "participant_signature_pubkey".to_string(),
        signatures
            .first()
            .map(|signature| signature.pubkey_sec1.clone()),
    )
}

fn now_unix_ms() -> Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system time is before unix epoch")?
        .as_millis()
        .try_into()
        .context("unix time does not fit in u64 milliseconds")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_contract_witness_verifies(package: &StoredSplicePackage) {
        let witness_bytes = package.contract_witness_bytes().unwrap();
        assert_eq!(witness_bytes.len(), SPLICE_STATE_TRANSITION_WITNESS_LEN);

        let parsed = SpliceStateTransitionWitness::parse(&witness_bytes).unwrap();
        let transition = package.validate().unwrap();
        let current_raw = current_state_header_wire_bytes(&transition).unwrap();
        let next_raw = next_state_header_wire_bytes(&transition).unwrap();
        let current = morph_script_common::StateHeader::parse(&current_raw).unwrap();
        let next = morph_script_common::StateHeader::parse(&next_raw).unwrap();
        morph_script_common::verify_splice_state_transition_bundle(&current, &next, &parsed)
            .unwrap();
    }

    #[test]
    fn validates_splice_fixture() {
        let package = fixture_package_with_kind(FixtureSpliceKind::SpliceIn).unwrap();
        let summary = package.summary().unwrap();

        assert_eq!(summary.kind, "splice_in");
        assert_eq!(summary.base_state_number, 7);
        assert_eq!(summary.deltas, 2);
        assert_eq!(summary.withdrawal_payout_policy.as_str(), "none");
        assert_eq!(summary.withdrawal_participant_pubkey_sec1, None);
        assert_eq!(summary.remaining_settlement_assets, 2);
        assert_eq!(
            summary.contract_witness_len,
            SPLICE_STATE_TRANSITION_WITNESS_LEN
        );
        assert_eq!(
            decode_hex_exact(
                &summary.current_state_header_hex,
                STATE_HEADER_LEN,
                "current_state_header_hex"
            )
            .unwrap()
            .len(),
            STATE_HEADER_LEN
        );
        assert_eq!(
            decode_hex_exact(
                &summary.next_state_header_hex,
                STATE_HEADER_LEN,
                "next_state_header_hex"
            )
            .unwrap()
            .len(),
            STATE_HEADER_LEN
        );
        let digest = hex32_bytes(&summary.signing_digest).unwrap();
        for signature in &package.signatures {
            verify_signature(&signature.pubkey_sec1, &signature.signature, &digest).unwrap();
        }
    }

    #[test]
    fn builds_package_from_transition() {
        let fixture = fixture_package_with_kind(FixtureSpliceKind::SpliceOut).unwrap();
        let transition = fixture.validate().unwrap();
        let package = StoredSplicePackage::from_transition(&transition, None, None, None).unwrap();

        assert_eq!(package.kind, fixture.kind);
        assert_eq!(package.channel_id, fixture.channel_id);
        assert_eq!(package.signing_digest, fixture.signing_digest);
        assert!(package.file_name().starts_with("splice-"));
        assert_contract_witness_verifies(&package);
    }

    #[test]
    fn builds_unchecked_negative_splice_package() {
        let fixture = fixture_package_with_kind(FixtureSpliceKind::SpliceOut).unwrap();
        let mut transition = fixture.validate().unwrap();
        transition.header.new_funding_epoch = transition.header.old_funding_epoch;

        let package =
            StoredSplicePackage::from_transition_unchecked(&transition, None, None, None).unwrap();
        let err = package.validate().unwrap_err();
        assert!(
            err.to_string()
                .contains("splice funding epoch must advance")
        );
    }

    #[test]
    fn encodes_contract_splice_transition_witness() {
        let package = fixture_package_with_kind(FixtureSpliceKind::SpliceIn).unwrap();
        let witness_bytes = package.contract_witness_bytes().unwrap();
        assert_eq!(witness_bytes.len(), SPLICE_STATE_TRANSITION_WITNESS_LEN);

        let parsed = SpliceStateTransitionWitness::parse(&witness_bytes).unwrap();
        assert_eq!(parsed.header().unwrap().base_state_number(), 7);
        assert_eq!(parsed.old_vault().unwrap().asset_count(), 2);
        assert_eq!(parsed.new_vault().unwrap().asset_count(), 2);
        assert_eq!(parsed.deltas().unwrap().delta_count(), 2);
        assert_contract_witness_verifies(&package);
    }

    #[test]
    fn validates_splice_out_fixture() {
        let package = fixture_package_with_kind(FixtureSpliceKind::SpliceOut).unwrap();
        let summary = package.summary().unwrap();

        assert_eq!(summary.kind, "splice_out");
        assert_eq!(summary.deltas, 1);
        assert_eq!(summary.withdrawals, 1);
        assert_eq!(
            summary.withdrawal_payout_policy.as_str(),
            "participant_signature_pubkey"
        );
        assert_eq!(
            summary.withdrawal_participant_pubkey_sec1.as_deref(),
            Some(package.signatures[0].pubkey_sec1.as_str())
        );
        assert_eq!(summary.remaining_settlement_assets, 2);
    }

    #[test]
    fn validates_xudt_splice_in_fixture() {
        let package = fixture_package_with_kind(FixtureSpliceKind::XudtSpliceIn).unwrap();
        let summary = package.summary().unwrap();

        assert_eq!(summary.kind, "splice_in");
        assert_eq!(summary.deltas, 1);
        assert_eq!(summary.withdrawals, 0);
        assert_eq!(summary.withdrawal_payout_policy.as_str(), "none");
        assert_eq!(summary.withdrawal_participant_pubkey_sec1, None);
        assert_eq!(summary.remaining_settlement_assets, 2);
        assert_eq!(package.asset_deltas[0].asset, "xudt");
        assert_eq!(package.asset_deltas[0].old_amount, 100);
        assert_eq!(package.asset_deltas[0].new_amount, 125);
        assert_eq!(package.asset_deltas[0].external_input, 25);
        assert_eq!(package.asset_deltas[0].withdrawal, 0);
        assert!(package.withdrawals.is_empty());
        assert_eq!(
            summary.contract_witness_len,
            SPLICE_STATE_TRANSITION_WITNESS_LEN
        );
        assert_contract_witness_verifies(&package);
    }

    #[test]
    fn validates_xudt_splice_out_fixture() {
        let package = fixture_package_with_kind(FixtureSpliceKind::XudtSpliceOut).unwrap();
        let summary = package.summary().unwrap();

        assert_eq!(summary.kind, "splice_out");
        assert_eq!(summary.deltas, 1);
        assert_eq!(summary.withdrawals, 1);
        assert_eq!(
            summary.withdrawal_payout_policy.as_str(),
            "participant_signature_pubkey"
        );
        assert_eq!(
            summary.withdrawal_participant_pubkey_sec1.as_deref(),
            Some(package.signatures[0].pubkey_sec1.as_str())
        );
        assert_eq!(summary.remaining_settlement_assets, 2);
        assert_eq!(package.asset_deltas[0].asset, "xudt");
        assert_eq!(package.asset_deltas[0].old_amount, 100);
        assert_eq!(package.asset_deltas[0].new_amount, 70);
        assert_eq!(package.withdrawals[0].amount, 30);
        assert_eq!(
            summary.contract_witness_len,
            SPLICE_STATE_TRANSITION_WITNESS_LEN
        );
        assert_contract_witness_verifies(&package);
    }

    #[test]
    fn rejects_splice_digest_mismatch() {
        let mut package = fixture_package_with_kind(FixtureSpliceKind::SpliceIn).unwrap();
        package.signing_digest = hex_prefixed(&bytes32(99));

        let err = package.validate().unwrap_err();
        assert!(err.to_string().contains("signing_digest"));
    }

    #[test]
    fn rejects_splice_delta_mismatch() {
        let mut package = fixture_package_with_kind(FixtureSpliceKind::SpliceIn).unwrap();
        package.asset_deltas[0].new_amount -= 1;
        package.asset_delta_commitment = hex_prefixed(&splice_asset_delta_commitment(
            &package
                .asset_deltas
                .iter()
                .map(StoredSpliceAssetDelta::to_delta)
                .collect::<Result<Vec<_>>>()
                .unwrap(),
        ));

        let err = package.validate().unwrap_err();
        assert!(err.to_string().contains("signing_digest"));
    }

    #[test]
    fn rejects_invalid_splice_signature() {
        let mut package = fixture_package_with_kind(FixtureSpliceKind::SpliceIn).unwrap();
        let mut signature =
            decode_hex_exact(&package.signatures[0].signature, 64, "signature").unwrap();
        signature[0] ^= 1;
        package.signatures[0].signature = hex_prefixed(&signature);

        let err = package.validate().unwrap_err();
        assert!(err.to_string().contains("splice transition check failed"));
    }
}
