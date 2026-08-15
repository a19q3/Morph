use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, ensure};
use k256::ecdsa::signature::hazmat::{PrehashSigner, PrehashVerifier};
use k256::ecdsa::{Signature, SigningKey, VerifyingKey};
use morph_core::{
    Amount, Bytes32, FactoryMerkleSibling, FactoryMerkleSiblingSide, FactoryParticipantKey,
    FactoryParticipantSignature, FactoryReducedExit, FactoryReducedSpliceTransition,
    FactoryReducedSpliceWitness, FactoryRight, FactoryRightId, FactoryRightKind,
    FactoryRightMerkleProof, FactorySingleRightMerkleUpdate, FactorySpliceHeader,
    FactorySpliceKind, FactorySpliceTransition, FactoryUpdate, FactoryVaultDelta,
    FactoryVaultDescriptor, ParticipantSignature, SpliceWitness, VaultAsset, VaultAssetAmount,
    blake2b256, bytes32, factory_right_sparse_proof, factory_right_sparse_root,
    factory_vault_delta_commitment, participants_commitment, validate_factory_non_interference,
    validate_factory_reduced_splice_transition, validate_factory_single_right_merkle_localization,
    validate_factory_single_right_merkle_update, validate_factory_splice_transition,
    validate_reduced_factory_exit,
};
use morph_script_common::{
    BYTE32_LEN, COMPRESSED_SECP256K1_PUBKEY_LEN, ECDSA_SIGNATURE_LEN, FACTORY_MAX_PARTICIPANTS,
    FACTORY_MERKLE_UPDATE_DOMAIN, FACTORY_MERKLE_UPDATE_RIGHT_COUNT,
    FACTORY_MERKLE_UPDATE_WITNESS_VERSION, FACTORY_MIN_PARTICIPANTS,
    FACTORY_REDUCED_RIGHTS_AUTHORISED_COUNT, FACTORY_REDUCED_RIGHTS_PARTICIPANT_ENTRY_LEN,
    FACTORY_REDUCED_SPLICE_WITNESS_VERSION, FACTORY_RIGHT_LEN, FACTORY_SIGNATURE_WITNESS_VERSION,
    FACTORY_SPARSE_MERKLE_DEPTH, FACTORY_SPLICE_HEADER_LEN, FACTORY_SPLICE_WITNESS_VERSION,
    FACTORY_VAULT_ASSET_AMOUNT_LEN, FACTORY_VAULT_DELTA_LEN, FACTORY_VAULT_DELTAS_LEN,
    FACTORY_VAULT_DESCRIPTOR_LEN, FactoryReducedSpliceWitness as WireFactoryReducedSpliceWitness,
    FactorySpliceWitness as WireFactorySpliceWitness, SIGNATURE_SCHEME_SECP256K1_ECDSA_BLAKE2B,
    VAULT_ASSET_KIND_CKB, VAULT_ASSET_KIND_XUDT, WITNESS_ENVELOPE_FORMAT,
    WITNESS_ENVELOPE_KIND_FACTORY_REDUCED_SPLICE, WITNESS_ENVELOPE_KIND_FACTORY_SPLICE,
    WITNESS_ENVELOPE_LEN, WITNESS_ENVELOPE_MAGIC, WitnessEnvelope,
    factory_merkle_update_witness_len, factory_reduced_splice_witness_len,
    factory_signature_witness_len, factory_splice_witness_len, witness_envelope_body_commitment,
};
use serde::{Deserialize, Serialize};

use crate::packages::canonical_hex32;

const FACTORY_PACKAGE_SCHEMA: &str = "morph.factory_update_package";
const FACTORY_DIGEST_DOMAIN: &str = "CKB_MORPH_FACTORY_UPDATE_PACKAGE";
const FACTORY_STATE_PACKAGE_SCHEMA: &str = "morph.factory_state_package";
const FACTORY_STATE_DIGEST_DOMAIN: &str = "CKB_MORPH_FACTORY_STATE_PACKAGE";
const FACTORY_REDUCED_EXIT_PACKAGE_SCHEMA: &str = "morph.factory_reduced_exit_package";
const FACTORY_MERKLE_UPDATE_PACKAGE_SCHEMA: &str = "morph.factory_merkle_update_package";
const FACTORY_MERKLE_UPDATE_DIGEST_DOMAIN: &str = "CKB_MORPH_FACTORY_MERKLE_UPDATE_PACKAGE";
const FACTORY_SPLICE_PACKAGE_SCHEMA: &str = "morph.factory_splice_package";
const FACTORY_REDUCED_SPLICE_PACKAGE_SCHEMA: &str = "morph.factory_reduced_splice_package";
const FACTORY_SIGNATURE_MODE_ALL_PARTICIPANTS: &str = "all_participants";
const FACTORY_SIGNATURE_MODE_AUTHORISED_PARTICIPANTS: &str = "authorised_participants";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FixtureFactorySpliceKind {
    CkbSpliceIn,
    CkbSpliceOut,
    XudtSpliceIn,
    XudtSpliceOut,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredFactoryRight {
    pub participant: String,
    pub subchannel: String,
    pub kind: FactoryRightKind,
    pub asset_type: Option<String>,
    pub quantity: Amount,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredFactoryUpdatePackage {
    pub schema: String,
    pub created_unix_ms: u64,
    pub factory_id: String,
    pub update_number: u64,
    pub state_root_before: String,
    pub state_root_after: String,
    pub touched_participants: Vec<String>,
    pub authorised_participants: Vec<String>,
    pub rights_before: Vec<StoredFactoryRight>,
    pub rights_after: Vec<StoredFactoryRight>,
    pub non_interference_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredFactoryParticipantKey {
    pub participant: String,
    pub pubkey_sec1: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredFactorySignature {
    pub participant: String,
    pub pubkey_sec1: String,
    pub signature: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredFactoryStatePackage {
    pub schema: String,
    pub created_unix_ms: u64,
    pub signature_mode: String,
    pub factory_id: String,
    pub update_number: u64,
    pub state_root_before: String,
    pub state_root_after: String,
    pub non_interference_digest: String,
    pub participant_keys: Vec<StoredFactoryParticipantKey>,
    pub signature_threshold: u8,
    pub signatures: Vec<StoredFactorySignature>,
    pub update_package: StoredFactoryUpdatePackage,
    pub factory_state_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredFactoryReducedExitPackage {
    pub schema: String,
    pub created_unix_ms: u64,
    pub factory_id: String,
    pub update_number: u64,
    pub participant: String,
    pub reserve_claim_subchannel: String,
    pub reserve_claim_asset_type: Option<String>,
    pub release_quantity: Amount,
    pub update_package: StoredFactoryUpdatePackage,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredFactoryMerkleSibling {
    pub side: String,
    pub hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredFactoryMerkleUpdatePackage {
    pub schema: String,
    pub created_unix_ms: u64,
    pub factory_id: String,
    pub update_number: u64,
    pub state_root_before: String,
    pub state_root_after: String,
    pub touched_participants: Vec<String>,
    pub authorised_participants: Vec<String>,
    pub right_before: StoredFactoryRight,
    pub right_after: StoredFactoryRight,
    pub proof_siblings: Vec<StoredFactoryMerkleSibling>,
    pub non_interference_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredFactoryVaultAssetAmount {
    pub asset: String,
    pub type_hash: Option<String>,
    pub amount: Amount,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredFactoryVaultDelta {
    pub asset: String,
    pub type_hash: Option<String>,
    pub old_amount: Amount,
    pub new_amount: Amount,
    pub external_input: Amount,
    pub withdrawal: Amount,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredFactorySplicePackage {
    pub schema: String,
    pub created_unix_ms: u64,
    pub kind: String,
    pub factory_id: String,
    pub chain_id: String,
    pub signature_scheme_id: u16,
    pub old_update_number: u64,
    pub new_update_number: u64,
    pub old_state_root: String,
    pub new_state_root: String,
    pub old_access_manifest_root: String,
    pub new_access_manifest_root: String,
    pub vault_delta_commitment: String,
    pub non_interference_digest: String,
    pub participants_commitment: String,
    pub old_vault_materialisation_root: String,
    pub new_vault_materialisation_root: String,
    pub old_vault_outpoint_commitment: String,
    pub new_vault_outpoint_commitment: String,
    pub withdrawal_lock_hash: String,
    pub signing_digest: String,
    pub old_vault: Vec<StoredFactoryVaultAssetAmount>,
    pub new_vault: Vec<StoredFactoryVaultAssetAmount>,
    pub vault_deltas: Vec<StoredFactoryVaultDelta>,
    pub update_package: StoredFactoryUpdatePackage,
    pub participant_keys: Vec<StoredFactoryParticipantKey>,
    pub signature_threshold: u8,
    pub signatures: Vec<StoredFactorySignature>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredFactoryReducedSplicePackage {
    pub schema: String,
    pub created_unix_ms: u64,
    pub kind: String,
    pub factory_id: String,
    pub chain_id: String,
    pub signature_scheme_id: u16,
    pub old_update_number: u64,
    pub new_update_number: u64,
    pub old_state_root: String,
    pub new_state_root: String,
    pub old_access_manifest_root: String,
    pub new_access_manifest_root: String,
    pub vault_delta_commitment: String,
    pub non_interference_digest: String,
    pub participants_commitment: String,
    pub old_vault_materialisation_root: String,
    pub new_vault_materialisation_root: String,
    pub old_vault_outpoint_commitment: String,
    pub new_vault_outpoint_commitment: String,
    pub withdrawal_lock_hash: String,
    pub signing_digest: String,
    pub old_vault: Vec<StoredFactoryVaultAssetAmount>,
    pub new_vault: Vec<StoredFactoryVaultAssetAmount>,
    pub vault_deltas: Vec<StoredFactoryVaultDelta>,
    pub merkle_update_package: StoredFactoryMerkleUpdatePackage,
    pub participant_keys: Vec<StoredFactoryParticipantKey>,
    pub signature_threshold: u8,
    pub signatures: Vec<StoredFactorySignature>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FactoryPackageSummary {
    pub factory_id: String,
    pub update_number: u64,
    pub state_root_before: String,
    pub state_root_after: String,
    pub touched_participants: usize,
    pub authorised_participants: usize,
    pub rights_before: usize,
    pub rights_after: usize,
    pub non_interference_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FactoryStatePackageSummary {
    pub factory_id: String,
    pub update_number: u64,
    pub state_root_before: String,
    pub state_root_after: String,
    pub non_interference_digest: String,
    pub signature_mode: String,
    pub signature_threshold: u8,
    pub participants: usize,
    pub signatures: usize,
    pub factory_state_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FactoryReducedExitPackageSummary {
    pub factory_id: String,
    pub update_number: u64,
    pub participant: String,
    pub reserve_claim_subchannel: String,
    pub reserve_claim_asset_type: Option<String>,
    pub release_quantity: Amount,
    pub reserve_claim_before: Amount,
    pub reserve_claim_after: Amount,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FactoryMerkleUpdatePackageSummary {
    pub factory_id: String,
    pub update_number: u64,
    pub state_root_before: String,
    pub state_root_after: String,
    pub touched_participants: usize,
    pub authorised_participants: usize,
    pub changed_participant: String,
    pub changed_kind: FactoryRightKind,
    pub quantity_before: Amount,
    pub quantity_after: Amount,
    pub proof_siblings: usize,
    pub non_interference_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FactorySplicePackageSummary {
    pub factory_id: String,
    pub chain_id: String,
    pub signature_scheme_id: u16,
    pub kind: String,
    pub old_update_number: u64,
    pub new_update_number: u64,
    pub old_state_root: String,
    pub new_state_root: String,
    pub old_access_manifest_root: String,
    pub new_access_manifest_root: String,
    pub signing_digest: String,
    pub vault_delta_commitment: String,
    pub non_interference_digest: String,
    pub reserve_claim_participant: String,
    pub reserve_claim_subchannel: String,
    pub reserve_claim_asset: String,
    pub reserve_claim_before: Amount,
    pub reserve_claim_after: Amount,
    pub vault_old_amount: Amount,
    pub vault_new_amount: Amount,
    pub external_input: Amount,
    pub withdrawal: Amount,
    pub withdrawal_lock_hash: String,
    pub signature_threshold: u8,
    pub signatures: usize,
    pub contract_witness_len: usize,
    pub contract_witness_hex: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FactoryReducedSplicePackageSummary {
    pub factory_id: String,
    pub chain_id: String,
    pub signature_scheme_id: u16,
    pub kind: String,
    pub old_update_number: u64,
    pub new_update_number: u64,
    pub old_state_root: String,
    pub new_state_root: String,
    pub old_access_manifest_root: String,
    pub new_access_manifest_root: String,
    pub signing_digest: String,
    pub vault_delta_commitment: String,
    pub non_interference_digest: String,
    pub reserve_claim_participant: String,
    pub reserve_claim_subchannel: String,
    pub reserve_claim_asset: String,
    pub reserve_claim_before: Amount,
    pub reserve_claim_after: Amount,
    pub vault_old_amount: Amount,
    pub vault_new_amount: Amount,
    pub external_input: Amount,
    pub withdrawal: Amount,
    pub withdrawal_lock_hash: String,
    pub participant_keys: usize,
    pub signature_threshold: u8,
    pub signatures: usize,
    pub proof_siblings: usize,
    pub contract_witness_len: usize,
    pub contract_witness_hex: String,
}

#[derive(Debug, Serialize)]
struct DigestPayload {
    domain: &'static str,
    schema: &'static str,
    factory_id: String,
    update_number: u64,
    state_root_before: String,
    state_root_after: String,
    touched_participants: Vec<String>,
    authorised_participants: Vec<String>,
    rights_before: Vec<StoredFactoryRight>,
    rights_after: Vec<StoredFactoryRight>,
}

#[derive(Debug, Serialize)]
struct FactoryStateDigestPayload {
    domain: &'static str,
    schema: &'static str,
    signature_mode: String,
    factory_id: String,
    update_number: u64,
    state_root_before: String,
    state_root_after: String,
    non_interference_digest: String,
    signature_threshold: u8,
    participant_keys: Vec<StoredFactoryParticipantKey>,
}

#[derive(Debug, Serialize)]
struct FactoryMerkleDigestPayload {
    domain: &'static str,
    schema: &'static str,
    factory_id: String,
    update_number: u64,
    state_root_before: String,
    state_root_after: String,
    touched_participants: Vec<String>,
    authorised_participants: Vec<String>,
    right_before: StoredFactoryRight,
    right_after: StoredFactoryRight,
    proof_siblings: Vec<StoredFactoryMerkleSibling>,
}

impl StoredFactoryUpdatePackage {
    pub fn from_update(
        factory_id: Bytes32,
        update_number: u64,
        state_root_before: Bytes32,
        state_root_after: Bytes32,
        update: FactoryUpdate,
    ) -> Result<Self> {
        let mut package = Self {
            schema: FACTORY_PACKAGE_SCHEMA.to_string(),
            created_unix_ms: now_unix_ms()?,
            factory_id: hex_prefixed(&factory_id),
            update_number,
            state_root_before: hex_prefixed(&state_root_before),
            state_root_after: hex_prefixed(&state_root_after),
            touched_participants: update
                .touched_participants
                .iter()
                .map(|participant| hex_prefixed(participant))
                .collect(),
            authorised_participants: update
                .authorised_participants
                .iter()
                .map(|participant| hex_prefixed(participant))
                .collect(),
            rights_before: update
                .before
                .iter()
                .map(StoredFactoryRight::from_right)
                .collect(),
            rights_after: update
                .after
                .iter()
                .map(StoredFactoryRight::from_right)
                .collect(),
            non_interference_digest: String::new(),
        };
        package.normalise()?;
        package.non_interference_digest = package.compute_digest()?;
        package.validate()?;
        Ok(package)
    }

    pub fn validate(&self) -> Result<FactoryUpdate> {
        ensure!(
            self.schema == FACTORY_PACKAGE_SCHEMA,
            "unsupported factory package schema {}",
            self.schema
        );
        ensure!(
            self.factory_id == canonical_hex32(&self.factory_id)?,
            "factory_id must be canonical"
        );
        ensure!(
            self.state_root_before == canonical_hex32(&self.state_root_before)?,
            "state_root_before must be canonical"
        );
        ensure!(
            self.state_root_after == canonical_hex32(&self.state_root_after)?,
            "state_root_after must be canonical"
        );
        ensure_sorted_unique_hex32(&self.touched_participants, "touched_participants")?;
        ensure_sorted_unique_hex32(&self.authorised_participants, "authorised_participants")?;
        ensure!(
            self.non_interference_digest == self.compute_digest()?,
            "factory package non_interference_digest mismatch"
        );

        let update = FactoryUpdate {
            before: self
                .rights_before
                .iter()
                .map(StoredFactoryRight::to_right)
                .collect::<Result<Vec<_>>>()?,
            after: self
                .rights_after
                .iter()
                .map(StoredFactoryRight::to_right)
                .collect::<Result<Vec<_>>>()?,
            touched_participants: self
                .touched_participants
                .iter()
                .map(|value| hex32_bytes(value))
                .collect::<Result<BTreeSet<_>>>()?,
            authorised_participants: self
                .authorised_participants
                .iter()
                .map(|value| hex32_bytes(value))
                .collect::<Result<BTreeSet<_>>>()?,
        };
        validate_factory_non_interference(&update)
            .map_err(|err| anyhow::anyhow!("factory non-interference check failed: {err}"))?;
        Ok(update)
    }

    pub fn summary(&self) -> Result<FactoryPackageSummary> {
        self.validate()?;
        Ok(FactoryPackageSummary {
            factory_id: self.factory_id.clone(),
            update_number: self.update_number,
            state_root_before: self.state_root_before.clone(),
            state_root_after: self.state_root_after.clone(),
            touched_participants: self.touched_participants.len(),
            authorised_participants: self.authorised_participants.len(),
            rights_before: self.rights_before.len(),
            rights_after: self.rights_after.len(),
            non_interference_digest: self.non_interference_digest.clone(),
        })
    }

    fn normalise(&mut self) -> Result<()> {
        self.factory_id = canonical_hex32(&self.factory_id)?;
        self.state_root_before = canonical_hex32(&self.state_root_before)?;
        self.state_root_after = canonical_hex32(&self.state_root_after)?;
        self.touched_participants = canonical_hex32_vec(&self.touched_participants)?;
        self.authorised_participants = canonical_hex32_vec(&self.authorised_participants)?;
        self.rights_before = canonical_rights(&self.rights_before)?;
        self.rights_after = canonical_rights(&self.rights_after)?;
        Ok(())
    }

    fn compute_digest(&self) -> Result<String> {
        let payload = DigestPayload {
            domain: FACTORY_DIGEST_DOMAIN,
            schema: FACTORY_PACKAGE_SCHEMA,
            factory_id: canonical_hex32(&self.factory_id)?,
            update_number: self.update_number,
            state_root_before: canonical_hex32(&self.state_root_before)?,
            state_root_after: canonical_hex32(&self.state_root_after)?,
            touched_participants: canonical_hex32_vec(&self.touched_participants)?,
            authorised_participants: canonical_hex32_vec(&self.authorised_participants)?,
            rights_before: canonical_rights(&self.rights_before)?,
            rights_after: canonical_rights(&self.rights_after)?,
        };
        let encoded = serde_json::to_vec(&payload)?;
        Ok(hex_prefixed(&blake2b256(&encoded)))
    }
}

impl StoredFactoryStatePackage {
    pub fn from_update_package(
        update_package: StoredFactoryUpdatePackage,
        signing_keys: &[(Bytes32, SigningKey)],
    ) -> Result<Self> {
        Self::from_update_package_with_mode(
            update_package,
            signing_keys,
            FACTORY_SIGNATURE_MODE_ALL_PARTICIPANTS,
        )
    }

    pub fn from_reduced_update_package(
        update_package: StoredFactoryUpdatePackage,
        signing_keys: &[(Bytes32, SigningKey)],
    ) -> Result<Self> {
        Self::from_update_package_with_mode(
            update_package,
            signing_keys,
            FACTORY_SIGNATURE_MODE_AUTHORISED_PARTICIPANTS,
        )
    }

    fn from_update_package_with_mode(
        update_package: StoredFactoryUpdatePackage,
        signing_keys: &[(Bytes32, SigningKey)],
        signature_mode: &str,
    ) -> Result<Self> {
        let update_summary = update_package.summary()?;
        ensure!(
            !signing_keys.is_empty(),
            "factory state package requires at least one participant key"
        );
        ensure!(
            signing_keys.len() <= u8::MAX as usize,
            "factory state package supports at most 255 participant keys"
        );

        let mut entries = signing_keys
            .iter()
            .map(|(participant, key)| (hex_prefixed(participant), pubkey_hex(key), key))
            .collect::<Vec<_>>();
        entries.sort_by(|left, right| left.0.cmp(&right.0));
        ensure!(
            entries.windows(2).all(|window| window[0].0 != window[1].0),
            "factory participant ids must be unique"
        );
        ensure!(
            unique_pubkeys(entries.iter().map(|(_, pubkey, _)| pubkey.as_str())),
            "factory participant pubkeys must be unique"
        );

        let participant_keys = entries
            .iter()
            .map(|(participant, pubkey, _)| StoredFactoryParticipantKey {
                participant: participant.clone(),
                pubkey_sec1: pubkey.clone(),
            })
            .collect::<Vec<_>>();
        let mut package = Self {
            schema: FACTORY_STATE_PACKAGE_SCHEMA.to_string(),
            created_unix_ms: now_unix_ms()?,
            signature_mode: signature_mode.to_string(),
            factory_id: update_summary.factory_id,
            update_number: update_summary.update_number,
            state_root_before: update_summary.state_root_before,
            state_root_after: update_summary.state_root_after,
            non_interference_digest: update_summary.non_interference_digest,
            participant_keys,
            signature_threshold: signing_keys.len() as u8,
            signatures: Vec::new(),
            update_package,
            factory_state_digest: String::new(),
        };
        package.factory_state_digest = package.compute_digest()?;
        let digest = hex32_bytes(&package.factory_state_digest)?;
        package.signatures = entries
            .iter()
            .map(|(participant, pubkey, key)| {
                sign_factory_digest(participant, pubkey, key, &digest)
            })
            .collect::<Result<Vec<_>>>()?;
        package.validate()?;
        Ok(package)
    }

    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.schema == FACTORY_STATE_PACKAGE_SCHEMA,
            "unsupported factory state package schema {}",
            self.schema
        );
        ensure!(
            self.signature_mode == FACTORY_SIGNATURE_MODE_ALL_PARTICIPANTS
                || self.signature_mode == FACTORY_SIGNATURE_MODE_AUTHORISED_PARTICIPANTS,
            "unsupported factory signature mode {}",
            self.signature_mode
        );

        let update_summary = self.update_package.summary()?;
        ensure!(
            self.factory_id == update_summary.factory_id,
            "factory state package factory_id does not match update package"
        );
        ensure!(
            self.update_number == update_summary.update_number,
            "factory state package update_number does not match update package"
        );
        ensure!(
            self.state_root_before == update_summary.state_root_before,
            "factory state package state_root_before does not match update package"
        );
        ensure!(
            self.state_root_after == update_summary.state_root_after,
            "factory state package state_root_after does not match update package"
        );
        ensure!(
            self.non_interference_digest == update_summary.non_interference_digest,
            "factory state package non_interference_digest does not match update package"
        );

        let canonical_participant_keys = canonical_participant_keys(&self.participant_keys)?;
        ensure!(
            canonical_participant_keys == self.participant_keys,
            "participant_keys must contain sorted unique canonical participant ids and pubkeys"
        );
        ensure!(
            !self.participant_keys.is_empty(),
            "factory state package requires at least one participant"
        );
        let expected_participants = match self.signature_mode.as_str() {
            FACTORY_SIGNATURE_MODE_ALL_PARTICIPANTS => update_participants(&self.update_package)?,
            FACTORY_SIGNATURE_MODE_AUTHORISED_PARTICIPANTS => self
                .update_package
                .authorised_participants
                .iter()
                .map(|value| canonical_hex32(value))
                .collect::<Result<BTreeSet<_>>>()?,
            _ => {
                return Err(anyhow::anyhow!(
                    "unknown signature_mode {} (expected {} or {})",
                    self.signature_mode,
                    FACTORY_SIGNATURE_MODE_ALL_PARTICIPANTS,
                    FACTORY_SIGNATURE_MODE_AUTHORISED_PARTICIPANTS
                ));
            }
        };
        ensure!(
            !expected_participants.is_empty(),
            "factory signature mode requires at least one expected signer"
        );
        let signed_participants = self
            .participant_keys
            .iter()
            .map(|key| canonical_hex32(&key.participant))
            .collect::<Result<BTreeSet<_>>>()?;
        ensure!(
            signed_participants == expected_participants,
            "factory participant keys must cover every participant in the update package"
        );
        ensure!(
            self.signature_threshold as usize == self.participant_keys.len(),
            "factory signature threshold must equal participant key count"
        );
        let canonical_signatures = canonical_factory_signatures(&self.signatures)?;
        ensure!(
            canonical_signatures == self.signatures,
            "factory signatures must contain sorted unique canonical pubkeys and signatures"
        );
        ensure!(
            self.signatures.len() == self.participant_keys.len(),
            "factory state package must include one signature per participant"
        );
        let signature_keys = self
            .signatures
            .iter()
            .map(|signature| StoredFactoryParticipantKey {
                participant: signature.participant.clone(),
                pubkey_sec1: signature.pubkey_sec1.clone(),
            })
            .collect::<Vec<_>>();
        ensure!(
            signature_keys == self.participant_keys,
            "factory signatures do not match participant key set"
        );
        ensure!(
            self.factory_state_digest == self.compute_digest()?,
            "factory state package digest mismatch"
        );
        self.verify_signatures()?;
        Ok(())
    }

    pub fn summary(&self) -> Result<FactoryStatePackageSummary> {
        self.validate()?;
        Ok(FactoryStatePackageSummary {
            factory_id: self.factory_id.clone(),
            update_number: self.update_number,
            state_root_before: self.state_root_before.clone(),
            state_root_after: self.state_root_after.clone(),
            non_interference_digest: self.non_interference_digest.clone(),
            signature_mode: self.signature_mode.clone(),
            signature_threshold: self.signature_threshold,
            participants: self.participant_keys.len(),
            signatures: self.signatures.len(),
            factory_state_digest: self.factory_state_digest.clone(),
        })
    }

    fn compute_digest(&self) -> Result<String> {
        let payload = FactoryStateDigestPayload {
            domain: FACTORY_STATE_DIGEST_DOMAIN,
            schema: FACTORY_STATE_PACKAGE_SCHEMA,
            signature_mode: self.signature_mode.clone(),
            factory_id: canonical_hex32(&self.factory_id)?,
            update_number: self.update_number,
            state_root_before: canonical_hex32(&self.state_root_before)?,
            state_root_after: canonical_hex32(&self.state_root_after)?,
            non_interference_digest: canonical_hex32(&self.non_interference_digest)?,
            signature_threshold: self.signature_threshold,
            participant_keys: canonical_participant_keys(&self.participant_keys)?,
        };
        let encoded = serde_json::to_vec(&payload)?;
        Ok(hex_prefixed(&blake2b256(&encoded)))
    }

    fn verify_signatures(&self) -> Result<()> {
        let digest = hex32_bytes(&self.factory_state_digest)?;
        for signature in &self.signatures {
            let _participant = hex32_bytes(&signature.participant)?;
            let pubkey_bytes = decode_hex_exact(&signature.pubkey_sec1, 33, "pubkey_sec1")?;
            let signature_bytes = decode_hex_exact(&signature.signature, 64, "signature")?;
            let verifying_key = VerifyingKey::from_sec1_bytes(&pubkey_bytes)
                .map_err(|err| anyhow::anyhow!("factory participant pubkey is invalid: {err:?}"))?;
            let signature = Signature::try_from(signature_bytes.as_slice())
                .map_err(|err| anyhow::anyhow!("factory signature encoding is invalid: {err:?}"))?;
            verifying_key
                .verify_prehash(&digest, &signature)
                .map_err(|err| anyhow::anyhow!("factory signature is invalid: {err:?}"))?;
        }
        Ok(())
    }
}

impl StoredFactoryReducedExitPackage {
    pub fn from_update_package(
        update_package: StoredFactoryUpdatePackage,
        exit: FactoryReducedExit,
    ) -> Result<Self> {
        let update_summary = update_package.summary()?;
        let mut package = Self {
            schema: FACTORY_REDUCED_EXIT_PACKAGE_SCHEMA.to_string(),
            created_unix_ms: now_unix_ms()?,
            factory_id: update_summary.factory_id,
            update_number: update_summary.update_number,
            participant: hex_prefixed(&exit.participant),
            reserve_claim_subchannel: hex_prefixed(&exit.reserve_claim.subchannel),
            reserve_claim_asset_type: exit
                .reserve_claim
                .asset_type
                .map(|asset| hex_prefixed(&asset)),
            release_quantity: exit.release_quantity,
            update_package,
        };
        package.normalise()?;
        package.validate()?;
        Ok(package)
    }

    pub fn validate(&self) -> Result<FactoryReducedExit> {
        ensure!(
            self.schema == FACTORY_REDUCED_EXIT_PACKAGE_SCHEMA,
            "unsupported factory reduced-exit package schema {}",
            self.schema
        );
        ensure!(
            self.factory_id == canonical_hex32(&self.factory_id)?,
            "factory_id must be canonical"
        );
        ensure!(
            self.participant == canonical_hex32(&self.participant)?,
            "participant must be canonical"
        );
        ensure!(
            self.reserve_claim_subchannel == canonical_hex32(&self.reserve_claim_subchannel)?,
            "reserve_claim_subchannel must be canonical"
        );
        if let Some(asset_type) = &self.reserve_claim_asset_type {
            ensure!(
                asset_type == &canonical_hex32(asset_type)?,
                "reserve_claim_asset_type must be canonical"
            );
        }

        let update_summary = self.update_package.summary()?;
        ensure!(
            self.factory_id == update_summary.factory_id,
            "factory reduced-exit package factory_id does not match update package"
        );
        ensure!(
            self.update_number == update_summary.update_number,
            "factory reduced-exit package update_number does not match update package"
        );

        let exit = FactoryReducedExit {
            participant: hex32_bytes(&self.participant)?,
            reserve_claim: FactoryRightId {
                participant: hex32_bytes(&self.participant)?,
                subchannel: hex32_bytes(&self.reserve_claim_subchannel)?,
                kind: FactoryRightKind::ReserveClaim,
                asset_type: self
                    .reserve_claim_asset_type
                    .as_ref()
                    .map(|value| hex32_bytes(value))
                    .transpose()?,
            },
            release_quantity: self.release_quantity,
        };
        let update = self.update_package.validate()?;
        validate_reduced_factory_exit(&update, &exit)
            .map_err(|err| anyhow::anyhow!("factory reduced-exit check failed: {err}"))?;
        Ok(exit)
    }

    pub fn summary(&self) -> Result<FactoryReducedExitPackageSummary> {
        let exit = self.validate()?;
        let update = self.update_package.validate()?;
        let before = reserve_claim_quantity(&update.before, &exit.reserve_claim)?;
        let after = reserve_claim_quantity(&update.after, &exit.reserve_claim).unwrap_or_default();
        Ok(FactoryReducedExitPackageSummary {
            factory_id: self.factory_id.clone(),
            update_number: self.update_number,
            participant: self.participant.clone(),
            reserve_claim_subchannel: self.reserve_claim_subchannel.clone(),
            reserve_claim_asset_type: self.reserve_claim_asset_type.clone(),
            release_quantity: self.release_quantity,
            reserve_claim_before: before,
            reserve_claim_after: after,
        })
    }

    fn normalise(&mut self) -> Result<()> {
        self.factory_id = canonical_hex32(&self.factory_id)?;
        self.participant = canonical_hex32(&self.participant)?;
        self.reserve_claim_subchannel = canonical_hex32(&self.reserve_claim_subchannel)?;
        self.reserve_claim_asset_type = self
            .reserve_claim_asset_type
            .as_ref()
            .map(|value| canonical_hex32(value))
            .transpose()?;
        Ok(())
    }
}

impl StoredFactoryMerkleUpdatePackage {
    pub fn from_update_localization(
        factory_id: Bytes32,
        update_number: u64,
        update: FactorySingleRightMerkleUpdate,
    ) -> Result<Self> {
        Self::from_update_with_predicate(factory_id, update_number, update, false)
    }

    fn from_update_with_predicate(
        factory_id: Bytes32,
        update_number: u64,
        update: FactorySingleRightMerkleUpdate,
        enforce_local_decrease: bool,
    ) -> Result<Self> {
        validate_factory_single_right_merkle_update(&update)
            .or_else(|err| {
                if enforce_local_decrease {
                    Err(err)
                } else {
                    validate_factory_single_right_merkle_localization(&update)
                }
            })
            .map_err(|err| anyhow::anyhow!("factory Merkle update proof failed: {err}"))?;
        let mut package = Self {
            schema: FACTORY_MERKLE_UPDATE_PACKAGE_SCHEMA.to_string(),
            created_unix_ms: now_unix_ms()?,
            factory_id: hex_prefixed(&factory_id),
            update_number,
            state_root_before: hex_prefixed(&update.before_root),
            state_root_after: hex_prefixed(&update.after_root),
            touched_participants: update
                .touched_participants
                .iter()
                .map(|participant| hex_prefixed(participant))
                .collect(),
            authorised_participants: update
                .authorised_participants
                .iter()
                .map(|participant| hex_prefixed(participant))
                .collect(),
            right_before: StoredFactoryRight::from_right(&update.before.right),
            right_after: StoredFactoryRight::from_right(&update.after.right),
            proof_siblings: update
                .before
                .siblings
                .iter()
                .map(StoredFactoryMerkleSibling::from_sibling)
                .collect(),
            non_interference_digest: String::new(),
        };
        package.normalise()?;
        package.non_interference_digest = package.compute_digest()?;
        if enforce_local_decrease {
            package.validate()?;
        } else {
            package.validate_localization()?;
        }
        Ok(package)
    }

    pub fn from_rights(
        factory_id: Bytes32,
        update_number: u64,
        before: Vec<FactoryRight>,
        after: Vec<FactoryRight>,
        changed_id: FactoryRightId,
        touched_participants: BTreeSet<Bytes32>,
        authorised_participants: BTreeSet<Bytes32>,
    ) -> Result<Self> {
        let before_root = factory_right_sparse_root(&before)
            .map_err(|err| anyhow::anyhow!("failed to compute before root: {err}"))?;
        let after_root = factory_right_sparse_root(&after)
            .map_err(|err| anyhow::anyhow!("failed to compute after root: {err}"))?;
        let before_proof = factory_right_sparse_proof(&before, &changed_id)
            .map_err(|err| anyhow::anyhow!("failed to build before proof: {err}"))?;
        let after_proof = factory_right_sparse_proof(&after, &changed_id)
            .map_err(|err| anyhow::anyhow!("failed to build after proof: {err}"))?;
        ensure!(
            before_proof.siblings == after_proof.siblings,
            "single-right Merkle update requires an unchanged sibling frontier"
        );

        let mut package = Self {
            schema: FACTORY_MERKLE_UPDATE_PACKAGE_SCHEMA.to_string(),
            created_unix_ms: now_unix_ms()?,
            factory_id: hex_prefixed(&factory_id),
            update_number,
            state_root_before: hex_prefixed(&before_root),
            state_root_after: hex_prefixed(&after_root),
            touched_participants: touched_participants
                .iter()
                .map(|participant| hex_prefixed(participant))
                .collect(),
            authorised_participants: authorised_participants
                .iter()
                .map(|participant| hex_prefixed(participant))
                .collect(),
            right_before: StoredFactoryRight::from_right(&before_proof.right),
            right_after: StoredFactoryRight::from_right(&after_proof.right),
            proof_siblings: before_proof
                .siblings
                .iter()
                .map(StoredFactoryMerkleSibling::from_sibling)
                .collect(),
            non_interference_digest: String::new(),
        };
        package.normalise()?;
        package.non_interference_digest = package.compute_digest()?;
        package.validate()?;
        Ok(package)
    }

    pub fn validate(&self) -> Result<FactorySingleRightMerkleUpdate> {
        let update = self.decode_update()?;
        validate_factory_single_right_merkle_update(&update)
            .map_err(|err| anyhow::anyhow!("factory Merkle update proof failed: {err}"))?;
        Ok(update)
    }

    pub fn validate_localization(&self) -> Result<FactorySingleRightMerkleUpdate> {
        let update = self.decode_update()?;
        validate_factory_single_right_merkle_localization(&update)
            .map_err(|err| anyhow::anyhow!("factory Merkle update proof failed: {err}"))?;
        Ok(update)
    }

    fn decode_update(&self) -> Result<FactorySingleRightMerkleUpdate> {
        ensure!(
            self.schema == FACTORY_MERKLE_UPDATE_PACKAGE_SCHEMA,
            "unsupported factory Merkle update package schema {}",
            self.schema
        );
        ensure!(
            self.factory_id == canonical_hex32(&self.factory_id)?,
            "factory_id must be canonical"
        );
        ensure!(
            self.state_root_before == canonical_hex32(&self.state_root_before)?,
            "state_root_before must be canonical"
        );
        ensure!(
            self.state_root_after == canonical_hex32(&self.state_root_after)?,
            "state_root_after must be canonical"
        );
        ensure_sorted_unique_hex32(&self.touched_participants, "touched_participants")?;
        ensure_sorted_unique_hex32(&self.authorised_participants, "authorised_participants")?;
        ensure!(
            self.proof_siblings == canonical_merkle_siblings(&self.proof_siblings)?,
            "proof_siblings must be canonical"
        );
        ensure!(
            self.non_interference_digest == self.compute_digest()?,
            "factory Merkle update package non_interference_digest mismatch"
        );

        let siblings = self
            .proof_siblings
            .iter()
            .map(StoredFactoryMerkleSibling::to_sibling)
            .collect::<Result<Vec<_>>>()?;
        let update = FactorySingleRightMerkleUpdate {
            before_root: hex32_bytes(&self.state_root_before)?,
            after_root: hex32_bytes(&self.state_root_after)?,
            touched_participants: self
                .touched_participants
                .iter()
                .map(|value| hex32_bytes(value))
                .collect::<Result<BTreeSet<_>>>()?,
            authorised_participants: self
                .authorised_participants
                .iter()
                .map(|value| hex32_bytes(value))
                .collect::<Result<BTreeSet<_>>>()?,
            before: FactoryRightMerkleProof {
                right: self.right_before.to_right()?,
                siblings: siblings.clone(),
            },
            after: FactoryRightMerkleProof {
                right: self.right_after.to_right()?,
                siblings,
            },
        };
        Ok(update)
    }

    pub fn summary(&self) -> Result<FactoryMerkleUpdatePackageSummary> {
        let update = self.validate()?;
        Ok(FactoryMerkleUpdatePackageSummary {
            factory_id: self.factory_id.clone(),
            update_number: self.update_number,
            state_root_before: self.state_root_before.clone(),
            state_root_after: self.state_root_after.clone(),
            touched_participants: self.touched_participants.len(),
            authorised_participants: self.authorised_participants.len(),
            changed_participant: hex_prefixed(&update.before.right.id.participant),
            changed_kind: update.before.right.id.kind,
            quantity_before: update.before.right.quantity,
            quantity_after: update.after.right.quantity,
            proof_siblings: self.proof_siblings.len(),
            non_interference_digest: self.non_interference_digest.clone(),
        })
    }

    fn normalise(&mut self) -> Result<()> {
        self.factory_id = canonical_hex32(&self.factory_id)?;
        self.state_root_before = canonical_hex32(&self.state_root_before)?;
        self.state_root_after = canonical_hex32(&self.state_root_after)?;
        self.touched_participants = canonical_hex32_vec(&self.touched_participants)?;
        self.authorised_participants = canonical_hex32_vec(&self.authorised_participants)?;
        self.right_before = self.right_before.canonical()?;
        self.right_after = self.right_after.canonical()?;
        self.proof_siblings = canonical_merkle_siblings(&self.proof_siblings)?;
        Ok(())
    }

    fn compute_digest(&self) -> Result<String> {
        let payload = FactoryMerkleDigestPayload {
            domain: FACTORY_MERKLE_UPDATE_DIGEST_DOMAIN,
            schema: FACTORY_MERKLE_UPDATE_PACKAGE_SCHEMA,
            factory_id: canonical_hex32(&self.factory_id)?,
            update_number: self.update_number,
            state_root_before: canonical_hex32(&self.state_root_before)?,
            state_root_after: canonical_hex32(&self.state_root_after)?,
            touched_participants: canonical_hex32_vec(&self.touched_participants)?,
            authorised_participants: canonical_hex32_vec(&self.authorised_participants)?,
            right_before: self.right_before.canonical()?,
            right_after: self.right_after.canonical()?,
            proof_siblings: canonical_merkle_siblings(&self.proof_siblings)?,
        };
        let encoded = serde_json::to_vec(&payload)?;
        Ok(hex_prefixed(&blake2b256(&encoded)))
    }
}

impl StoredFactorySplicePackage {
    pub fn from_transition(
        transition: FactorySpliceTransition,
        signing_keys: &[(Bytes32, SigningKey)],
    ) -> Result<Self> {
        ensure!(
            !signing_keys.is_empty(),
            "factory splice package requires at least one participant key"
        );
        ensure!(
            signing_keys.len() <= u8::MAX as usize,
            "factory splice package supports at most 255 participant keys"
        );
        let update_package = StoredFactoryUpdatePackage::from_update(
            transition.header.factory_id,
            transition.header.new_update_number,
            transition.header.old_state_root,
            transition.header.new_state_root,
            transition.update.clone(),
        )?;
        let mut entries = signing_keys
            .iter()
            .map(|(participant, key)| (hex_prefixed(participant), pubkey_hex(key), key))
            .collect::<Vec<_>>();
        entries.sort_by(|left, right| left.0.cmp(&right.0));
        ensure!(
            entries.windows(2).all(|window| window[0].0 != window[1].0),
            "factory participant ids must be unique"
        );
        ensure!(
            unique_pubkeys(entries.iter().map(|(_, pubkey, _)| pubkey.as_str())),
            "factory participant pubkeys must be unique"
        );
        let participant_keys = entries
            .iter()
            .map(|(participant, pubkey, _)| StoredFactoryParticipantKey {
                participant: participant.clone(),
                pubkey_sec1: pubkey.clone(),
            })
            .collect::<Vec<_>>();
        let pubkeys = entries
            .iter()
            .map(|(_, pubkey, _)| decode_hex_exact(pubkey, 33, "pubkey_sec1"))
            .collect::<Result<Vec<_>>>()?;
        let pubkey_refs = pubkeys.iter().map(Vec::as_slice).collect::<Vec<_>>();
        let participants_commitment =
            participants_commitment(signing_keys.len() as u8, &pubkey_refs);
        let mut package = Self {
            schema: FACTORY_SPLICE_PACKAGE_SCHEMA.to_string(),
            created_unix_ms: now_unix_ms()?,
            kind: factory_splice_kind_name(transition.header.kind).to_string(),
            factory_id: hex_prefixed(&transition.header.factory_id),
            chain_id: hex_prefixed(&transition.header.chain_id),
            signature_scheme_id: transition.header.signature_scheme_id,
            old_update_number: transition.header.old_update_number,
            new_update_number: transition.header.new_update_number,
            old_state_root: hex_prefixed(&transition.header.old_state_root),
            new_state_root: hex_prefixed(&transition.header.new_state_root),
            old_access_manifest_root: hex_prefixed(&transition.header.old_access_manifest_root),
            new_access_manifest_root: hex_prefixed(&transition.header.new_access_manifest_root),
            vault_delta_commitment: hex_prefixed(&factory_vault_delta_commitment(
                &transition.deltas,
            )),
            non_interference_digest: update_package.non_interference_digest.clone(),
            participants_commitment: hex_prefixed(&participants_commitment),
            old_vault_materialisation_root: hex_prefixed(
                &transition.header.old_vault_materialisation_root,
            ),
            new_vault_materialisation_root: hex_prefixed(
                &transition.header.new_vault_materialisation_root,
            ),
            old_vault_outpoint_commitment: hex_prefixed(
                &transition.header.old_vault_outpoint_commitment,
            ),
            new_vault_outpoint_commitment: hex_prefixed(
                &transition.header.new_vault_outpoint_commitment,
            ),
            withdrawal_lock_hash: hex_prefixed(&transition.header.withdrawal_lock_hash),
            signing_digest: String::new(),
            old_vault: transition
                .old_vault
                .assets
                .iter()
                .map(StoredFactoryVaultAssetAmount::from_amount)
                .collect(),
            new_vault: transition
                .new_vault
                .assets
                .iter()
                .map(StoredFactoryVaultAssetAmount::from_amount)
                .collect(),
            vault_deltas: transition
                .deltas
                .iter()
                .map(StoredFactoryVaultDelta::from_delta)
                .collect(),
            update_package,
            participant_keys,
            signature_threshold: signing_keys.len() as u8,
            signatures: Vec::new(),
        };
        package.normalise()?;
        package.signing_digest = hex_prefixed(&package.header()?.signing_digest());
        let digest = hex32_bytes(&package.signing_digest)?;
        package.signatures = entries
            .iter()
            .map(|(participant, pubkey, key)| {
                sign_factory_digest(participant, pubkey, key, &digest)
            })
            .collect::<Result<Vec<_>>>()?;
        package.validate()?;
        Ok(package)
    }

    pub fn validate(&self) -> Result<FactorySpliceTransition> {
        ensure!(
            self.schema == FACTORY_SPLICE_PACKAGE_SCHEMA,
            "unsupported factory splice package schema {}",
            self.schema
        );
        ensure!(
            self.factory_id == canonical_hex32(&self.factory_id)?,
            "factory_id must be canonical"
        );
        ensure!(
            self.chain_id == canonical_hex32(&self.chain_id)?,
            "chain_id must be canonical"
        );
        ensure!(
            self.signature_scheme_id == SIGNATURE_SCHEME_SECP256K1_ECDSA_BLAKE2B,
            "signature_scheme_id must be SECP256K1_BLAKE2B (1)"
        );
        ensure!(
            self.old_state_root == canonical_hex32(&self.old_state_root)?,
            "old_state_root must be canonical"
        );
        ensure!(
            self.new_state_root == canonical_hex32(&self.new_state_root)?,
            "new_state_root must be canonical"
        );
        ensure!(
            self.old_access_manifest_root == canonical_hex32(&self.old_access_manifest_root)?,
            "old_access_manifest_root must be canonical"
        );
        ensure!(
            self.new_access_manifest_root == canonical_hex32(&self.new_access_manifest_root)?,
            "new_access_manifest_root must be canonical"
        );
        ensure!(
            self.vault_delta_commitment == canonical_hex32(&self.vault_delta_commitment)?,
            "vault_delta_commitment must be canonical"
        );
        ensure!(
            self.non_interference_digest == canonical_hex32(&self.non_interference_digest)?,
            "non_interference_digest must be canonical"
        );
        ensure!(
            self.participants_commitment == canonical_hex32(&self.participants_commitment)?,
            "participants_commitment must be canonical"
        );
        ensure!(
            self.signing_digest == canonical_hex32(&self.signing_digest)?,
            "signing_digest must be canonical"
        );
        ensure!(
            self.old_vault == canonical_factory_amounts(&self.old_vault)?,
            "old_vault must contain sorted unique canonical assets"
        );
        ensure!(
            self.new_vault == canonical_factory_amounts(&self.new_vault)?,
            "new_vault must contain sorted unique canonical assets"
        );
        ensure!(
            self.vault_deltas == canonical_factory_deltas(&self.vault_deltas)?,
            "vault_deltas must contain sorted unique canonical assets"
        );
        let update = self.update_package.validate()?;
        let update_summary = self.update_package.summary()?;
        ensure!(
            self.factory_id == update_summary.factory_id,
            "factory splice package factory_id does not match update package"
        );
        ensure!(
            self.new_update_number == update_summary.update_number,
            "factory splice package new_update_number does not match update package"
        );
        ensure!(
            self.old_state_root == update_summary.state_root_before,
            "factory splice package old_state_root does not match update package"
        );
        ensure!(
            self.new_state_root == update_summary.state_root_after,
            "factory splice package new_state_root does not match update package"
        );
        ensure!(
            self.non_interference_digest == update_summary.non_interference_digest,
            "factory splice package non_interference_digest does not match update package"
        );
        let canonical_participant_keys = canonical_participant_keys(&self.participant_keys)?;
        ensure!(
            canonical_participant_keys == self.participant_keys,
            "participant_keys must contain sorted unique canonical participant ids and pubkeys"
        );
        ensure!(
            self.signature_threshold as usize == self.participant_keys.len(),
            "factory splice signature threshold must equal participant key count"
        );
        let canonical_signatures = canonical_factory_signatures(&self.signatures)?;
        ensure!(
            canonical_signatures == self.signatures,
            "factory splice signatures must contain sorted unique canonical participants and pubkeys"
        );
        ensure!(
            self.signatures.len() == self.participant_keys.len(),
            "factory splice package must include one signature per participant"
        );
        let signature_keys = self
            .signatures
            .iter()
            .map(|signature| StoredFactoryParticipantKey {
                participant: signature.participant.clone(),
                pubkey_sec1: signature.pubkey_sec1.clone(),
            })
            .collect::<Vec<_>>();
        ensure!(
            signature_keys == self.participant_keys,
            "factory splice signatures do not match participant key set"
        );
        let update_participant_ids = factory_participants_from_update(&update)?
            .iter()
            .map(|participant| hex_prefixed(participant))
            .collect::<Vec<_>>();
        let package_participant_ids = self
            .participant_keys
            .iter()
            .map(|key| key.participant.clone())
            .collect::<Vec<_>>();
        ensure!(
            package_participant_ids == update_participant_ids,
            "factory splice participant_keys do not match update participants"
        );

        let witness_signatures = self
            .signatures
            .iter()
            .map(|signature| {
                Ok(ParticipantSignature {
                    pubkey_sec1: decode_hex_exact(&signature.pubkey_sec1, 33, "pubkey_sec1")?,
                    signature: decode_hex_exact(&signature.signature, 64, "signature")?,
                })
            })
            .collect::<Result<Vec<_>>>()?;

        let transition = FactorySpliceTransition {
            header: self.header()?,
            witness: SpliceWitness {
                threshold: self.signature_threshold,
                signatures: witness_signatures,
            },
            update,
            old_vault: FactoryVaultDescriptor {
                factory_id: hex32_bytes(&self.factory_id)?,
                assets: self
                    .old_vault
                    .iter()
                    .map(StoredFactoryVaultAssetAmount::to_amount)
                    .collect::<Result<Vec<_>>>()?,
            },
            new_vault: FactoryVaultDescriptor {
                factory_id: hex32_bytes(&self.factory_id)?,
                assets: self
                    .new_vault
                    .iter()
                    .map(StoredFactoryVaultAssetAmount::to_amount)
                    .collect::<Result<Vec<_>>>()?,
            },
            deltas: self
                .vault_deltas
                .iter()
                .map(StoredFactoryVaultDelta::to_delta)
                .collect::<Result<Vec<_>>>()?,
            asset_registry: factory_splice_asset_registry(self)?,
        };
        ensure!(
            self.signing_digest == hex_prefixed(&transition.header.signing_digest()),
            "factory splice signing_digest mismatch"
        );
        validate_factory_splice_transition(&transition)
            .map_err(|err| anyhow::anyhow!("factory splice transition check failed: {err}"))?;
        Ok(transition)
    }

    pub fn summary(&self) -> Result<FactorySplicePackageSummary> {
        let transition = self.validate()?;
        let (right_before, right_after) = changed_reserve_claim(&transition.update)?;
        let delta = transition
            .deltas
            .first()
            .ok_or_else(|| anyhow::anyhow!("factory splice package has no vault delta"))?;
        let contract_witness = contract_witness_bytes_from_transition(
            &transition,
            &self.participant_keys,
            &self.signatures,
        )?;
        Ok(FactorySplicePackageSummary {
            factory_id: self.factory_id.clone(),
            chain_id: self.chain_id.clone(),
            signature_scheme_id: self.signature_scheme_id,
            kind: self.kind.clone(),
            old_update_number: self.old_update_number,
            new_update_number: self.new_update_number,
            old_state_root: self.old_state_root.clone(),
            new_state_root: self.new_state_root.clone(),
            old_access_manifest_root: self.old_access_manifest_root.clone(),
            new_access_manifest_root: self.new_access_manifest_root.clone(),
            signing_digest: self.signing_digest.clone(),
            vault_delta_commitment: self.vault_delta_commitment.clone(),
            non_interference_digest: self.non_interference_digest.clone(),
            reserve_claim_participant: hex_prefixed(&right_before.id.participant),
            reserve_claim_subchannel: hex_prefixed(&right_before.id.subchannel),
            reserve_claim_asset: asset_name(&delta.asset),
            reserve_claim_before: right_before.quantity,
            reserve_claim_after: right_after.map(|right| right.quantity).unwrap_or_default(),
            vault_old_amount: delta.old_amount,
            vault_new_amount: delta.new_amount,
            external_input: delta.external_input,
            withdrawal: delta.withdrawal,
            withdrawal_lock_hash: self.withdrawal_lock_hash.clone(),
            signature_threshold: self.signature_threshold,
            signatures: self.signatures.len(),
            contract_witness_len: contract_witness.len(),
            contract_witness_hex: hex_prefixed(&contract_witness),
        })
    }

    fn normalise(&mut self) -> Result<()> {
        self.factory_id = canonical_hex32(&self.factory_id)?;
        self.old_state_root = canonical_hex32(&self.old_state_root)?;
        self.new_state_root = canonical_hex32(&self.new_state_root)?;
        self.old_access_manifest_root = canonical_hex32(&self.old_access_manifest_root)?;
        self.new_access_manifest_root = canonical_hex32(&self.new_access_manifest_root)?;
        self.vault_delta_commitment = canonical_hex32(&self.vault_delta_commitment)?;
        self.non_interference_digest = canonical_hex32(&self.non_interference_digest)?;
        self.participants_commitment = canonical_hex32(&self.participants_commitment)?;
        self.old_vault_materialisation_root =
            canonical_hex32(&self.old_vault_materialisation_root)?;
        self.new_vault_materialisation_root =
            canonical_hex32(&self.new_vault_materialisation_root)?;
        self.old_vault_outpoint_commitment = canonical_hex32(&self.old_vault_outpoint_commitment)?;
        self.new_vault_outpoint_commitment = canonical_hex32(&self.new_vault_outpoint_commitment)?;
        self.withdrawal_lock_hash = canonical_hex32(&self.withdrawal_lock_hash)?;
        if !self.signing_digest.is_empty() {
            self.signing_digest = canonical_hex32(&self.signing_digest)?;
        }
        self.old_vault = canonical_factory_amounts(&self.old_vault)?;
        self.new_vault = canonical_factory_amounts(&self.new_vault)?;
        self.vault_deltas = canonical_factory_deltas(&self.vault_deltas)?;
        self.participant_keys = canonical_participant_keys(&self.participant_keys)?;
        self.signatures = canonical_factory_signatures(&self.signatures)?;
        Ok(())
    }

    pub fn file_name(&self) -> String {
        let factory = self.factory_id.trim_start_matches("0x");
        let digest = self.signing_digest.trim_start_matches("0x");
        format!(
            "factory-splice-{factory}-{:020}-{}.json",
            self.new_update_number,
            &digest[0..16]
        )
    }

    pub fn contract_witness_bytes(&self) -> Result<Vec<u8>> {
        let transition = self.validate()?;
        contract_witness_bytes_from_transition(
            &transition,
            &self.participant_keys,
            &self.signatures,
        )
    }

    fn header(&self) -> Result<FactorySpliceHeader> {
        Ok(FactorySpliceHeader {
            protocol_version: 1,
            chain_id: hex32_bytes(&self.chain_id)?,
            signature_scheme_id: self.signature_scheme_id,
            factory_id: hex32_bytes(&self.factory_id)?,
            old_update_number: self.old_update_number,
            new_update_number: self.new_update_number,
            old_state_root: hex32_bytes(&self.old_state_root)?,
            new_state_root: hex32_bytes(&self.new_state_root)?,
            old_access_manifest_root: hex32_bytes(&self.old_access_manifest_root)?,
            new_access_manifest_root: hex32_bytes(&self.new_access_manifest_root)?,
            kind: parse_factory_splice_kind(&self.kind)?,
            vault_delta_commitment: hex32_bytes(&self.vault_delta_commitment)?,
            non_interference_digest: hex32_bytes(&self.non_interference_digest)?,
            participants_commitment: hex32_bytes(&self.participants_commitment)?,
            old_vault_materialisation_root: hex32_bytes(&self.old_vault_materialisation_root)?,
            new_vault_materialisation_root: hex32_bytes(&self.new_vault_materialisation_root)?,
            old_vault_outpoint_commitment: hex32_bytes(&self.old_vault_outpoint_commitment)?,
            new_vault_outpoint_commitment: hex32_bytes(&self.new_vault_outpoint_commitment)?,
            withdrawal_lock_hash: hex32_bytes(&self.withdrawal_lock_hash)?,
        })
    }
}

impl StoredFactoryReducedSplicePackage {
    pub fn from_transition(
        transition: FactoryReducedSpliceTransition,
        participant_keys: &[(Bytes32, SigningKey)],
    ) -> Result<Self> {
        ensure!(
            !participant_keys.is_empty(),
            "reduced factory splice package requires participant keys"
        );
        ensure!(
            participant_keys.len() <= u8::MAX as usize,
            "reduced factory splice package supports at most 255 participant keys"
        );
        let merkle_update_package = StoredFactoryMerkleUpdatePackage::from_update_localization(
            transition.header.factory_id,
            transition.header.new_update_number,
            transition.update.clone(),
        )?;
        let contract_non_interference_digest =
            factory_reduced_splice_contract_non_interference_digest(
                &transition.header,
                &transition.update,
            )?;
        let mut entries = participant_keys
            .iter()
            .map(|(participant, key)| (hex_prefixed(participant), pubkey_hex(key), key))
            .collect::<Vec<_>>();
        entries.sort_by(|left, right| left.0.cmp(&right.0));
        ensure!(
            entries.windows(2).all(|window| window[0].0 != window[1].0),
            "factory participant ids must be unique"
        );
        ensure!(
            unique_pubkeys(entries.iter().map(|(_, pubkey, _)| pubkey.as_str())),
            "factory participant pubkeys must be unique"
        );
        let participant_key_records = entries
            .iter()
            .map(|(participant, pubkey, _)| StoredFactoryParticipantKey {
                participant: participant.clone(),
                pubkey_sec1: pubkey.clone(),
            })
            .collect::<Vec<_>>();
        let pubkeys = entries
            .iter()
            .map(|(_, pubkey, _)| decode_hex_exact(pubkey, 33, "pubkey_sec1"))
            .collect::<Result<Vec<_>>>()?;
        let pubkey_refs = pubkeys.iter().map(Vec::as_slice).collect::<Vec<_>>();
        let participants_commitment =
            participants_commitment(participant_keys.len() as u8, &pubkey_refs);
        let mut package = Self {
            schema: FACTORY_REDUCED_SPLICE_PACKAGE_SCHEMA.to_string(),
            created_unix_ms: now_unix_ms()?,
            kind: factory_splice_kind_name(transition.header.kind).to_string(),
            factory_id: hex_prefixed(&transition.header.factory_id),
            chain_id: hex_prefixed(&transition.header.chain_id),
            signature_scheme_id: transition.header.signature_scheme_id,
            old_update_number: transition.header.old_update_number,
            new_update_number: transition.header.new_update_number,
            old_state_root: hex_prefixed(&transition.header.old_state_root),
            new_state_root: hex_prefixed(&transition.header.new_state_root),
            old_access_manifest_root: hex_prefixed(&transition.header.old_access_manifest_root),
            new_access_manifest_root: hex_prefixed(&transition.header.new_access_manifest_root),
            vault_delta_commitment: hex_prefixed(&factory_vault_delta_commitment(
                &transition.deltas,
            )),
            non_interference_digest: hex_prefixed(&contract_non_interference_digest),
            participants_commitment: hex_prefixed(&participants_commitment),
            old_vault_materialisation_root: hex_prefixed(
                &transition.header.old_vault_materialisation_root,
            ),
            new_vault_materialisation_root: hex_prefixed(
                &transition.header.new_vault_materialisation_root,
            ),
            old_vault_outpoint_commitment: hex_prefixed(
                &transition.header.old_vault_outpoint_commitment,
            ),
            new_vault_outpoint_commitment: hex_prefixed(
                &transition.header.new_vault_outpoint_commitment,
            ),
            withdrawal_lock_hash: hex_prefixed(&transition.header.withdrawal_lock_hash),
            signing_digest: String::new(),
            old_vault: transition
                .old_vault
                .assets
                .iter()
                .map(StoredFactoryVaultAssetAmount::from_amount)
                .collect(),
            new_vault: transition
                .new_vault
                .assets
                .iter()
                .map(StoredFactoryVaultAssetAmount::from_amount)
                .collect(),
            vault_deltas: transition
                .deltas
                .iter()
                .map(StoredFactoryVaultDelta::from_delta)
                .collect(),
            merkle_update_package,
            participant_keys: participant_key_records,
            signature_threshold: participant_keys.len() as u8,
            signatures: Vec::new(),
        };
        package.normalise()?;
        package.signing_digest = hex_prefixed(&package.header()?.signing_digest());
        let digest = hex32_bytes(&package.signing_digest)?;
        let authorised = package
            .merkle_update_package
            .authorised_participants
            .iter()
            .map(|participant| canonical_hex32(participant))
            .collect::<Result<BTreeSet<_>>>()?;
        package.signatures = entries
            .iter()
            .filter(|(participant, _, _)| authorised.contains(participant))
            .map(|(participant, pubkey, key)| {
                sign_factory_digest(participant, pubkey, key, &digest)
            })
            .collect::<Result<Vec<_>>>()?;
        package.validate()?;
        Ok(package)
    }

    pub fn validate(&self) -> Result<FactoryReducedSpliceTransition> {
        ensure!(
            self.schema == FACTORY_REDUCED_SPLICE_PACKAGE_SCHEMA,
            "unsupported reduced factory splice package schema {}",
            self.schema
        );
        ensure!(
            self.factory_id == canonical_hex32(&self.factory_id)?,
            "factory_id must be canonical"
        );
        ensure!(
            self.chain_id == canonical_hex32(&self.chain_id)?,
            "chain_id must be canonical"
        );
        ensure!(
            self.signature_scheme_id == SIGNATURE_SCHEME_SECP256K1_ECDSA_BLAKE2B,
            "signature_scheme_id must be SECP256K1_BLAKE2B (1)"
        );
        ensure!(
            self.old_state_root == canonical_hex32(&self.old_state_root)?,
            "old_state_root must be canonical"
        );
        ensure!(
            self.new_state_root == canonical_hex32(&self.new_state_root)?,
            "new_state_root must be canonical"
        );
        ensure!(
            self.old_access_manifest_root == canonical_hex32(&self.old_access_manifest_root)?,
            "old_access_manifest_root must be canonical"
        );
        ensure!(
            self.new_access_manifest_root == canonical_hex32(&self.new_access_manifest_root)?,
            "new_access_manifest_root must be canonical"
        );
        ensure!(
            self.old_access_manifest_root == self.new_access_manifest_root,
            "reduced factory splice contract witness requires unchanged access manifest roots"
        );
        ensure!(
            self.vault_delta_commitment == canonical_hex32(&self.vault_delta_commitment)?,
            "vault_delta_commitment must be canonical"
        );
        ensure!(
            self.non_interference_digest == canonical_hex32(&self.non_interference_digest)?,
            "non_interference_digest must be canonical"
        );
        ensure!(
            self.participants_commitment == canonical_hex32(&self.participants_commitment)?,
            "participants_commitment must be canonical"
        );
        ensure!(
            self.signing_digest == canonical_hex32(&self.signing_digest)?,
            "signing_digest must be canonical"
        );
        ensure!(
            self.old_vault == canonical_factory_amounts(&self.old_vault)?,
            "old_vault must contain sorted unique canonical assets"
        );
        ensure!(
            self.new_vault == canonical_factory_amounts(&self.new_vault)?,
            "new_vault must contain sorted unique canonical assets"
        );
        ensure!(
            self.vault_deltas == canonical_factory_deltas(&self.vault_deltas)?,
            "vault_deltas must contain sorted unique canonical assets"
        );

        let update = self.merkle_update_package.validate_localization()?;
        ensure!(
            self.factory_id == self.merkle_update_package.factory_id,
            "reduced factory splice package factory_id does not match Merkle update package"
        );
        ensure!(
            self.new_update_number == self.merkle_update_package.update_number,
            "reduced factory splice package new_update_number does not match Merkle update package"
        );
        ensure!(
            self.old_state_root == self.merkle_update_package.state_root_before,
            "reduced factory splice package old_state_root does not match Merkle update package"
        );
        ensure!(
            self.new_state_root == self.merkle_update_package.state_root_after,
            "reduced factory splice package new_state_root does not match Merkle update package"
        );
        let expected_non_interference_digest = hex_prefixed(
            &factory_reduced_splice_contract_non_interference_digest(&self.header()?, &update)?,
        );
        ensure!(
            self.non_interference_digest == expected_non_interference_digest,
            "reduced factory splice package contract non_interference_digest mismatch"
        );

        let canonical_participant_keys = canonical_participant_keys(&self.participant_keys)?;
        ensure!(
            canonical_participant_keys == self.participant_keys,
            "participant_keys must contain sorted unique canonical participant ids and pubkeys"
        );
        ensure!(
            self.signature_threshold as usize == self.participant_keys.len(),
            "reduced factory splice signature threshold must equal participant key count"
        );
        let canonical_signatures = canonical_factory_signatures(&self.signatures)?;
        ensure!(
            canonical_signatures == self.signatures,
            "reduced factory splice signatures must contain sorted unique canonical participants and pubkeys"
        );
        let authorised = self
            .merkle_update_package
            .authorised_participants
            .iter()
            .map(|participant| canonical_hex32(participant))
            .collect::<Result<BTreeSet<_>>>()?;
        let signed_participants = self
            .signatures
            .iter()
            .map(|signature| canonical_hex32(&signature.participant))
            .collect::<Result<BTreeSet<_>>>()?;
        ensure!(
            signed_participants == authorised,
            "reduced factory splice signatures must cover exactly the authorised participants"
        );
        for signature in &self.signatures {
            let Some(key) = self
                .participant_keys
                .iter()
                .find(|key| key.participant == signature.participant)
            else {
                return Err(anyhow::anyhow!(
                    "reduced factory splice signature has no participant key"
                ));
            };
            ensure!(
                key.pubkey_sec1 == signature.pubkey_sec1,
                "reduced factory splice signature pubkey does not match participant key"
            );
        }

        let transition = FactoryReducedSpliceTransition {
            header: self.header()?,
            witness: FactoryReducedSpliceWitness {
                participant_threshold: self.signature_threshold,
                participant_keys: self
                    .participant_keys
                    .iter()
                    .map(|key| {
                        Ok(FactoryParticipantKey {
                            participant: hex32_bytes(&key.participant)?,
                            pubkey_sec1: decode_hex_exact(&key.pubkey_sec1, 33, "pubkey_sec1")?,
                        })
                    })
                    .collect::<Result<Vec<_>>>()?,
                signatures: self
                    .signatures
                    .iter()
                    .map(|signature| {
                        Ok(FactoryParticipantSignature {
                            participant: hex32_bytes(&signature.participant)?,
                            pubkey_sec1: decode_hex_exact(
                                &signature.pubkey_sec1,
                                33,
                                "pubkey_sec1",
                            )?,
                            signature: decode_hex_exact(&signature.signature, 64, "signature")?,
                        })
                    })
                    .collect::<Result<Vec<_>>>()?,
            },
            update,
            old_vault: FactoryVaultDescriptor {
                factory_id: hex32_bytes(&self.factory_id)?,
                assets: self
                    .old_vault
                    .iter()
                    .map(StoredFactoryVaultAssetAmount::to_amount)
                    .collect::<Result<Vec<_>>>()?,
            },
            new_vault: FactoryVaultDescriptor {
                factory_id: hex32_bytes(&self.factory_id)?,
                assets: self
                    .new_vault
                    .iter()
                    .map(StoredFactoryVaultAssetAmount::to_amount)
                    .collect::<Result<Vec<_>>>()?,
            },
            deltas: self
                .vault_deltas
                .iter()
                .map(StoredFactoryVaultDelta::to_delta)
                .collect::<Result<Vec<_>>>()?,
            asset_registry: factory_reduced_splice_asset_registry(self)?,
        };
        ensure!(
            self.signing_digest == hex_prefixed(&transition.header.signing_digest()),
            "reduced factory splice signing_digest mismatch"
        );
        validate_factory_reduced_splice_transition(&transition).map_err(|err| {
            anyhow::anyhow!("reduced factory splice transition check failed: {err}")
        })?;
        Ok(transition)
    }

    pub fn summary(&self) -> Result<FactoryReducedSplicePackageSummary> {
        let transition = self.validate()?;
        let (right_before, right_after) = changed_merkle_reserve_claim(&transition.update)?;
        let delta = transition
            .deltas
            .first()
            .ok_or_else(|| anyhow::anyhow!("reduced factory splice package has no vault delta"))?;
        let contract_witness = contract_reduced_splice_witness_bytes_from_transition(&transition)?;
        Ok(FactoryReducedSplicePackageSummary {
            factory_id: self.factory_id.clone(),
            chain_id: self.chain_id.clone(),
            signature_scheme_id: self.signature_scheme_id,
            kind: self.kind.clone(),
            old_update_number: self.old_update_number,
            new_update_number: self.new_update_number,
            old_state_root: self.old_state_root.clone(),
            new_state_root: self.new_state_root.clone(),
            old_access_manifest_root: self.old_access_manifest_root.clone(),
            new_access_manifest_root: self.new_access_manifest_root.clone(),
            signing_digest: self.signing_digest.clone(),
            vault_delta_commitment: self.vault_delta_commitment.clone(),
            non_interference_digest: self.non_interference_digest.clone(),
            reserve_claim_participant: hex_prefixed(&right_before.id.participant),
            reserve_claim_subchannel: hex_prefixed(&right_before.id.subchannel),
            reserve_claim_asset: asset_name(&delta.asset),
            reserve_claim_before: right_before.quantity,
            reserve_claim_after: right_after.quantity,
            vault_old_amount: delta.old_amount,
            vault_new_amount: delta.new_amount,
            external_input: delta.external_input,
            withdrawal: delta.withdrawal,
            withdrawal_lock_hash: self.withdrawal_lock_hash.clone(),
            participant_keys: self.participant_keys.len(),
            signature_threshold: self.signature_threshold,
            signatures: self.signatures.len(),
            proof_siblings: transition.update.before.siblings.len(),
            contract_witness_len: contract_witness.len(),
            contract_witness_hex: hex_prefixed(&contract_witness),
        })
    }

    fn normalise(&mut self) -> Result<()> {
        self.factory_id = canonical_hex32(&self.factory_id)?;
        self.old_state_root = canonical_hex32(&self.old_state_root)?;
        self.new_state_root = canonical_hex32(&self.new_state_root)?;
        self.old_access_manifest_root = canonical_hex32(&self.old_access_manifest_root)?;
        self.new_access_manifest_root = canonical_hex32(&self.new_access_manifest_root)?;
        self.vault_delta_commitment = canonical_hex32(&self.vault_delta_commitment)?;
        self.non_interference_digest = canonical_hex32(&self.non_interference_digest)?;
        self.participants_commitment = canonical_hex32(&self.participants_commitment)?;
        self.old_vault_materialisation_root =
            canonical_hex32(&self.old_vault_materialisation_root)?;
        self.new_vault_materialisation_root =
            canonical_hex32(&self.new_vault_materialisation_root)?;
        self.old_vault_outpoint_commitment = canonical_hex32(&self.old_vault_outpoint_commitment)?;
        self.new_vault_outpoint_commitment = canonical_hex32(&self.new_vault_outpoint_commitment)?;
        self.withdrawal_lock_hash = canonical_hex32(&self.withdrawal_lock_hash)?;
        if !self.signing_digest.is_empty() {
            self.signing_digest = canonical_hex32(&self.signing_digest)?;
        }
        self.old_vault = canonical_factory_amounts(&self.old_vault)?;
        self.new_vault = canonical_factory_amounts(&self.new_vault)?;
        self.vault_deltas = canonical_factory_deltas(&self.vault_deltas)?;
        self.participant_keys = canonical_participant_keys(&self.participant_keys)?;
        self.signatures = canonical_factory_signatures(&self.signatures)?;
        Ok(())
    }

    pub fn file_name(&self) -> String {
        let factory = self.factory_id.trim_start_matches("0x");
        let digest = self.signing_digest.trim_start_matches("0x");
        format!(
            "factory-reduced-splice-{factory}-{:020}-{}.json",
            self.new_update_number,
            &digest[0..16]
        )
    }

    pub fn contract_witness_bytes(&self) -> Result<Vec<u8>> {
        let transition = self.validate()?;
        contract_reduced_splice_witness_bytes_from_transition(&transition)
    }

    fn header(&self) -> Result<FactorySpliceHeader> {
        Ok(FactorySpliceHeader {
            protocol_version: 1,
            chain_id: hex32_bytes(&self.chain_id)?,
            signature_scheme_id: self.signature_scheme_id,
            factory_id: hex32_bytes(&self.factory_id)?,
            old_update_number: self.old_update_number,
            new_update_number: self.new_update_number,
            old_state_root: hex32_bytes(&self.old_state_root)?,
            new_state_root: hex32_bytes(&self.new_state_root)?,
            old_access_manifest_root: hex32_bytes(&self.old_access_manifest_root)?,
            new_access_manifest_root: hex32_bytes(&self.new_access_manifest_root)?,
            kind: parse_factory_splice_kind(&self.kind)?,
            vault_delta_commitment: hex32_bytes(&self.vault_delta_commitment)?,
            non_interference_digest: hex32_bytes(&self.non_interference_digest)?,
            participants_commitment: hex32_bytes(&self.participants_commitment)?,
            old_vault_materialisation_root: hex32_bytes(&self.old_vault_materialisation_root)?,
            new_vault_materialisation_root: hex32_bytes(&self.new_vault_materialisation_root)?,
            old_vault_outpoint_commitment: hex32_bytes(&self.old_vault_outpoint_commitment)?,
            new_vault_outpoint_commitment: hex32_bytes(&self.new_vault_outpoint_commitment)?,
            withdrawal_lock_hash: hex32_bytes(&self.withdrawal_lock_hash)?,
        })
    }
}

impl StoredFactoryRight {
    fn from_right(right: &FactoryRight) -> Self {
        Self {
            participant: hex_prefixed(&right.id.participant),
            subchannel: hex_prefixed(&right.id.subchannel),
            kind: right.id.kind,
            asset_type: right
                .id
                .asset_type
                .map(|asset_type| hex_prefixed(&asset_type)),
            quantity: right.quantity,
        }
    }

    fn to_right(&self) -> Result<FactoryRight> {
        Ok(FactoryRight {
            id: FactoryRightId {
                participant: hex32_bytes(&self.participant)?,
                subchannel: hex32_bytes(&self.subchannel)?,
                kind: self.kind,
                asset_type: self
                    .asset_type
                    .as_ref()
                    .map(|value| hex32_bytes(value))
                    .transpose()?,
            },
            quantity: self.quantity,
        })
    }

    fn canonical(&self) -> Result<Self> {
        Ok(Self {
            participant: canonical_hex32(&self.participant)?,
            subchannel: canonical_hex32(&self.subchannel)?,
            kind: self.kind,
            asset_type: self
                .asset_type
                .as_ref()
                .map(|value| canonical_hex32(value))
                .transpose()?,
            quantity: self.quantity,
        })
    }
}

impl StoredFactoryVaultAssetAmount {
    fn from_amount(amount: &VaultAssetAmount) -> Self {
        let (asset, type_hash) = stored_asset_fields(&amount.asset);
        Self {
            asset,
            type_hash,
            amount: amount.amount,
        }
    }

    fn to_amount(&self) -> Result<VaultAssetAmount> {
        Ok(VaultAssetAmount {
            asset: parse_vault_asset(&self.asset, self.type_hash.as_deref())?,
            amount: self.amount,
        })
    }

    fn canonical(&self) -> Result<Self> {
        let asset = parse_vault_asset(&self.asset, self.type_hash.as_deref())?;
        let (asset, type_hash) = stored_asset_fields(&asset);
        Ok(Self {
            asset,
            type_hash,
            amount: self.amount,
        })
    }
}

impl StoredFactoryVaultDelta {
    fn from_delta(delta: &FactoryVaultDelta) -> Self {
        let (asset, type_hash) = stored_asset_fields(&delta.asset);
        Self {
            asset,
            type_hash,
            old_amount: delta.old_amount,
            new_amount: delta.new_amount,
            external_input: delta.external_input,
            withdrawal: delta.withdrawal,
        }
    }

    fn to_delta(&self) -> Result<FactoryVaultDelta> {
        Ok(FactoryVaultDelta {
            asset: parse_vault_asset(&self.asset, self.type_hash.as_deref())?,
            old_amount: self.old_amount,
            new_amount: self.new_amount,
            external_input: self.external_input,
            withdrawal: self.withdrawal,
        })
    }

    fn canonical(&self) -> Result<Self> {
        let asset = parse_vault_asset(&self.asset, self.type_hash.as_deref())?;
        let (asset, type_hash) = stored_asset_fields(&asset);
        Ok(Self {
            asset,
            type_hash,
            old_amount: self.old_amount,
            new_amount: self.new_amount,
            external_input: self.external_input,
            withdrawal: self.withdrawal,
        })
    }
}

impl StoredFactoryMerkleSibling {
    fn from_sibling(sibling: &FactoryMerkleSibling) -> Self {
        Self {
            side: match sibling.side {
                FactoryMerkleSiblingSide::Left => "left",
                FactoryMerkleSiblingSide::Right => "right",
            }
            .to_string(),
            hash: hex_prefixed(&sibling.hash),
        }
    }

    fn to_sibling(&self) -> Result<FactoryMerkleSibling> {
        let side = match self.side.as_str() {
            "left" => FactoryMerkleSiblingSide::Left,
            "right" => FactoryMerkleSiblingSide::Right,
            other => return Err(anyhow::anyhow!("unsupported Merkle sibling side {other}")),
        };
        Ok(FactoryMerkleSibling {
            side,
            hash: hex32_bytes(&self.hash)?,
        })
    }

    fn canonical(&self) -> Result<Self> {
        ensure!(
            self.side == "left" || self.side == "right",
            "Merkle sibling side must be left or right"
        );
        Ok(Self {
            side: self.side.clone(),
            hash: canonical_hex32(&self.hash)?,
        })
    }
}

pub fn read_factory_update_package(path: &Path) -> Result<StoredFactoryUpdatePackage> {
    let bytes = fs::read(path)
        .with_context(|| format!("failed to read factory package {}", path.display()))?;
    let package: StoredFactoryUpdatePackage = serde_json::from_slice(&bytes)
        .with_context(|| format!("failed to parse factory package {}", path.display()))?;
    package
        .validate()
        .with_context(|| format!("invalid factory package {}", path.display()))?;
    Ok(package)
}

pub fn read_factory_state_package(path: &Path) -> Result<StoredFactoryStatePackage> {
    let bytes = fs::read(path)
        .with_context(|| format!("failed to read factory state package {}", path.display()))?;
    let package: StoredFactoryStatePackage = serde_json::from_slice(&bytes)
        .with_context(|| format!("failed to parse factory state package {}", path.display()))?;
    package
        .validate()
        .with_context(|| format!("invalid factory state package {}", path.display()))?;
    Ok(package)
}

pub fn read_factory_reduced_exit_package(path: &Path) -> Result<StoredFactoryReducedExitPackage> {
    let bytes = fs::read(path).with_context(|| {
        format!(
            "failed to read factory reduced-exit package {}",
            path.display()
        )
    })?;
    let package: StoredFactoryReducedExitPackage =
        serde_json::from_slice(&bytes).with_context(|| {
            format!(
                "failed to parse factory reduced-exit package {}",
                path.display()
            )
        })?;
    package
        .validate()
        .with_context(|| format!("invalid factory reduced-exit package {}", path.display()))?;
    Ok(package)
}

pub fn read_factory_merkle_update_package(path: &Path) -> Result<StoredFactoryMerkleUpdatePackage> {
    let bytes = fs::read(path).with_context(|| {
        format!(
            "failed to read factory Merkle update package {}",
            path.display()
        )
    })?;
    let package: StoredFactoryMerkleUpdatePackage =
        serde_json::from_slice(&bytes).with_context(|| {
            format!(
                "failed to parse factory Merkle update package {}",
                path.display()
            )
        })?;
    package
        .validate()
        .with_context(|| format!("invalid factory Merkle update package {}", path.display()))?;
    Ok(package)
}

pub fn read_factory_splice_package(path: &Path) -> Result<StoredFactorySplicePackage> {
    let bytes = fs::read(path)
        .with_context(|| format!("failed to read factory splice package {}", path.display()))?;
    let package: StoredFactorySplicePackage = serde_json::from_slice(&bytes)
        .with_context(|| format!("failed to parse factory splice package {}", path.display()))?;
    package
        .validate()
        .with_context(|| format!("invalid factory splice package {}", path.display()))?;
    Ok(package)
}

pub fn read_factory_reduced_splice_package(
    path: &Path,
) -> Result<StoredFactoryReducedSplicePackage> {
    let bytes = fs::read(path).with_context(|| {
        format!(
            "failed to read reduced factory splice package {}",
            path.display()
        )
    })?;
    let package: StoredFactoryReducedSplicePackage =
        serde_json::from_slice(&bytes).with_context(|| {
            format!(
                "failed to parse reduced factory splice package {}",
                path.display()
            )
        })?;
    package
        .validate()
        .with_context(|| format!("invalid reduced factory splice package {}", path.display()))?;
    Ok(package)
}

pub fn write_factory_splice_package(
    dir: &Path,
    package: &StoredFactorySplicePackage,
) -> Result<PathBuf> {
    package.validate()?;
    fs::create_dir_all(dir).with_context(|| {
        format!(
            "failed to create factory splice package directory {}",
            dir.display()
        )
    })?;
    let path = dir.join(package.file_name());
    let tmp = crate::packages::atomic_json_tmp_path(&path);
    let json = serde_json::to_vec_pretty(package)?;
    fs::write(&tmp, json).with_context(|| {
        format!(
            "failed to write temporary factory splice package {}",
            tmp.display()
        )
    })?;
    fs::rename(&tmp, &path).with_context(|| {
        format!(
            "failed to atomically move factory splice package {} to {}",
            tmp.display(),
            path.display()
        )
    })?;
    Ok(path)
}

pub fn write_factory_reduced_splice_package(
    dir: &Path,
    package: &StoredFactoryReducedSplicePackage,
) -> Result<PathBuf> {
    package.validate()?;
    fs::create_dir_all(dir).with_context(|| {
        format!(
            "failed to create reduced factory splice package directory {}",
            dir.display()
        )
    })?;
    let path = dir.join(package.file_name());
    let tmp = crate::packages::atomic_json_tmp_path(&path);
    let json = serde_json::to_vec_pretty(package)?;
    fs::write(&tmp, json).with_context(|| {
        format!(
            "failed to write temporary reduced factory splice package {}",
            tmp.display()
        )
    })?;
    fs::rename(&tmp, &path).with_context(|| {
        format!(
            "failed to atomically move reduced factory splice package {} to {}",
            tmp.display(),
            path.display()
        )
    })?;
    Ok(path)
}

pub fn fixture_factory_splice_package_with_kind(
    kind: FixtureFactorySpliceKind,
) -> Result<StoredFactorySplicePackage> {
    fixture_factory_splice_package_with_participant_count(kind, FACTORY_MIN_PARTICIPANTS)
}

pub fn fixture_factory_splice_package_with_participant_count(
    kind: FixtureFactorySpliceKind,
    participant_count: u8,
) -> Result<StoredFactorySplicePackage> {
    ensure!(
        (FACTORY_MIN_PARTICIPANTS..=FACTORY_MAX_PARTICIPANTS).contains(&participant_count),
        "dynamic factory fixture participant count must be in 2..=16"
    );
    let (splice_kind, asset, old_amount, new_amount, external_input, withdrawal) = match kind {
        FixtureFactorySpliceKind::CkbSpliceIn => {
            (FactorySpliceKind::In, VaultAsset::Ckb, 50, 70, 20, 0)
        }
        FixtureFactorySpliceKind::CkbSpliceOut => {
            (FactorySpliceKind::Out, VaultAsset::Ckb, 50, 30, 0, 20)
        }
        FixtureFactorySpliceKind::XudtSpliceIn => (
            FactorySpliceKind::In,
            VaultAsset::Xudt(bytes32(42)),
            50,
            70,
            20,
            0,
        ),
        FixtureFactorySpliceKind::XudtSpliceOut => (
            FactorySpliceKind::Out,
            VaultAsset::Xudt(bytes32(42)),
            50,
            30,
            0,
            20,
        ),
    };
    let asset_type = match asset {
        VaultAsset::Ckb => None,
        VaultAsset::Xudt(type_hash) => Some(type_hash),
    };
    let mut before = Vec::with_capacity(participant_count as usize * 4);
    for participant in 1..=participant_count {
        before.push(right(participant, 10, FactoryRightKind::Balance, None, 100));
        before.push(right_with_asset(
            participant,
            10,
            FactoryRightKind::ReserveClaim,
            if participant == 1 { asset_type } else { None },
            50,
        ));
        before.push(right(
            participant,
            10,
            FactoryRightKind::Membership,
            None,
            1,
        ));
        before.push(right(participant, 10, FactoryRightKind::ExitPath, None, 1));
    }
    let mut after = before.clone();
    after[1].quantity = match splice_kind {
        FactorySpliceKind::In => 70,
        FactorySpliceKind::Out => 30,
    };
    let update = FactoryUpdate {
        before: before.clone(),
        after: after.clone(),
        touched_participants: BTreeSet::from([bytes32(1)]),
        authorised_participants: BTreeSet::from([bytes32(1)]),
    };
    let deltas = vec![FactoryVaultDelta {
        asset: asset.clone(),
        old_amount,
        new_amount,
        external_input,
        withdrawal,
    }];
    let mut header = FactorySpliceHeader {
        protocol_version: 1,
        chain_id: bytes32(2),
        signature_scheme_id: 1,
        factory_id: bytes32(90),
        old_update_number: 1,
        new_update_number: 2,
        old_state_root: factory_right_sparse_root(&before)
            .map_err(|err| anyhow::anyhow!("failed to compute old factory root: {err}"))?,
        new_state_root: factory_right_sparse_root(&after)
            .map_err(|err| anyhow::anyhow!("failed to compute new factory root: {err}"))?,
        old_access_manifest_root: bytes32(91),
        new_access_manifest_root: bytes32(92),
        kind: splice_kind,
        vault_delta_commitment: factory_vault_delta_commitment(&deltas),
        non_interference_digest: bytes32(0),
        participants_commitment: bytes32(0),
        old_vault_materialisation_root: bytes32(93),
        new_vault_materialisation_root: bytes32(94),
        old_vault_outpoint_commitment: bytes32(95),
        new_vault_outpoint_commitment: [0; 32],
        withdrawal_lock_hash: match splice_kind {
            FactorySpliceKind::In => [0; 32],
            FactorySpliceKind::Out => bytes32(96),
        },
    };
    let update_package = StoredFactoryUpdatePackage::from_update(
        header.factory_id,
        header.new_update_number,
        header.old_state_root,
        header.new_state_root,
        update.clone(),
    )?;
    header.non_interference_digest = hex32_bytes(&update_package.non_interference_digest)?;
    let transition = FactorySpliceTransition {
        header,
        witness: SpliceWitness {
            threshold: 0,
            signatures: Vec::new(),
        },
        update,
        old_vault: FactoryVaultDescriptor {
            factory_id: bytes32(90),
            assets: vec![VaultAssetAmount {
                asset: asset.clone(),
                amount: old_amount,
            }],
        },
        new_vault: FactoryVaultDescriptor {
            factory_id: bytes32(90),
            assets: vec![VaultAssetAmount {
                asset,
                amount: new_amount,
            }],
        },
        deltas,
        asset_registry: morph_core::AssetRegistry {
            xudt_types: BTreeSet::from([bytes32(42)]),
        },
    };
    let signing_keys = (1..=participant_count)
        .map(|participant| Ok((bytes32(participant), fixture_signing_key(participant)?)))
        .collect::<Result<Vec<_>>>()?;
    StoredFactorySplicePackage::from_transition(transition, &signing_keys)
}

pub fn fixture_factory_reduced_splice_package_with_kind(
    kind: FixtureFactorySpliceKind,
) -> Result<StoredFactoryReducedSplicePackage> {
    fixture_factory_reduced_splice_package_with_participant_count(kind, FACTORY_MIN_PARTICIPANTS)
}

pub fn fixture_factory_reduced_splice_package_with_participant_count(
    kind: FixtureFactorySpliceKind,
    participant_count: u8,
) -> Result<StoredFactoryReducedSplicePackage> {
    let full = fixture_factory_splice_package_with_participant_count(kind, participant_count)?
        .validate()?;
    let mut header = full.header;
    header.new_access_manifest_root = header.old_access_manifest_root;
    let changed_id = full
        .update
        .before
        .iter()
        .find(|right| {
            full.update
                .after
                .iter()
                .find(|after| after.id == right.id)
                .map(|after| after.quantity)
                .unwrap_or_default()
                != right.quantity
                && right.id.kind == FactoryRightKind::ReserveClaim
        })
        .ok_or_else(|| anyhow::anyhow!("factory splice fixture did not change a reserve claim"))?
        .id
        .clone();
    let update = FactorySingleRightMerkleUpdate {
        before_root: header.old_state_root,
        after_root: header.new_state_root,
        touched_participants: full.update.touched_participants.clone(),
        authorised_participants: full.update.authorised_participants.clone(),
        before: factory_right_sparse_proof(&full.update.before, &changed_id)
            .map_err(|err| anyhow::anyhow!("failed to build reduced splice before proof: {err}"))?,
        after: factory_right_sparse_proof(&full.update.after, &changed_id)
            .map_err(|err| anyhow::anyhow!("failed to build reduced splice after proof: {err}"))?,
    };
    let transition = FactoryReducedSpliceTransition {
        header,
        witness: FactoryReducedSpliceWitness {
            participant_threshold: 0,
            participant_keys: Vec::new(),
            signatures: Vec::new(),
        },
        update,
        old_vault: full.old_vault,
        new_vault: full.new_vault,
        deltas: full.deltas,
        asset_registry: full.asset_registry,
    };
    let signing_keys = (1..=participant_count)
        .map(|participant| Ok((bytes32(participant), fixture_signing_key(participant)?)))
        .collect::<Result<Vec<_>>>()?;
    StoredFactoryReducedSplicePackage::from_transition(transition, &signing_keys)
}

pub fn fixture_package() -> Result<StoredFactoryUpdatePackage> {
    let before = vec![
        right(1, 10, FactoryRightKind::Balance, None, 100),
        right(1, 10, FactoryRightKind::ReserveClaim, None, 50),
        right(1, 10, FactoryRightKind::Membership, None, 1),
        right(1, 10, FactoryRightKind::ExitPath, None, 1),
        right(1, 10, FactoryRightKind::SponsorBudgetClaim, None, 20),
        right(2, 10, FactoryRightKind::Balance, None, 100),
        right(2, 10, FactoryRightKind::ReserveClaim, None, 50),
        right(2, 10, FactoryRightKind::Membership, None, 1),
        right(2, 10, FactoryRightKind::ExitPath, None, 1),
        right(2, 10, FactoryRightKind::SponsorBudgetClaim, None, 20),
    ];
    let mut after = before.clone();
    after[0].quantity = 90;
    after[1].quantity = 60;
    let update = FactoryUpdate {
        before,
        after,
        touched_participants: BTreeSet::from([bytes32(1)]),
        authorised_participants: BTreeSet::from([bytes32(1)]),
    };
    StoredFactoryUpdatePackage::from_update(bytes32(90), 1, bytes32(91), bytes32(92), update)
}

pub fn fixture_reduced_exit_package() -> Result<StoredFactoryReducedExitPackage> {
    let before = vec![
        right(1, 10, FactoryRightKind::Balance, None, 100),
        right(1, 10, FactoryRightKind::ReserveClaim, None, 50),
        right(1, 10, FactoryRightKind::Membership, None, 1),
        right(1, 10, FactoryRightKind::ExitPath, None, 1),
        right(1, 10, FactoryRightKind::SponsorBudgetClaim, None, 20),
        right(2, 10, FactoryRightKind::Balance, None, 100),
        right(2, 10, FactoryRightKind::ReserveClaim, None, 50),
        right(2, 10, FactoryRightKind::Membership, None, 1),
        right(2, 10, FactoryRightKind::ExitPath, None, 1),
        right(2, 10, FactoryRightKind::SponsorBudgetClaim, None, 20),
    ];
    let mut after = before.clone();
    after[1].quantity = 30;
    let update = FactoryUpdate {
        before,
        after,
        touched_participants: BTreeSet::from([bytes32(1)]),
        authorised_participants: BTreeSet::from([bytes32(1)]),
    };
    let update_package =
        StoredFactoryUpdatePackage::from_update(bytes32(90), 1, bytes32(91), bytes32(92), update)?;
    let exit = FactoryReducedExit {
        participant: bytes32(1),
        reserve_claim: FactoryRightId {
            participant: bytes32(1),
            subchannel: bytes32(10),
            kind: FactoryRightKind::ReserveClaim,
            asset_type: None,
        },
        release_quantity: 20,
    };
    StoredFactoryReducedExitPackage::from_update_package(update_package, exit)
}

pub fn fixture_merkle_update_package() -> Result<StoredFactoryMerkleUpdatePackage> {
    let before = large_factory_rights();
    let mut after = before.clone();
    let changed_id = FactoryRightId {
        participant: bytes32(3),
        subchannel: bytes32(12),
        kind: FactoryRightKind::ReserveClaim,
        asset_type: None,
    };
    after
        .iter_mut()
        .find(|right| right.id == changed_id)
        .ok_or_else(|| anyhow::anyhow!("fixture changed right is missing"))?
        .quantity = 35;
    StoredFactoryMerkleUpdatePackage::from_rights(
        bytes32(90),
        2,
        before,
        after,
        changed_id,
        BTreeSet::from([bytes32(3)]),
        BTreeSet::from([bytes32(3)]),
    )
}

pub fn fixture_state_package() -> Result<StoredFactoryStatePackage> {
    let update_package = fixture_package()?;
    let alice = fixture_signing_key(1)?;
    let bob = fixture_signing_key(2)?;
    StoredFactoryStatePackage::from_update_package(
        update_package,
        &[(bytes32(1), alice), (bytes32(2), bob)],
    )
}

fn large_factory_rights() -> Vec<FactoryRight> {
    let mut rights = Vec::new();
    for participant in 1..=8 {
        for subchannel in 10..=13 {
            rights.push(right(
                participant,
                subchannel,
                FactoryRightKind::Balance,
                None,
                100,
            ));
            rights.push(right(
                participant,
                subchannel,
                FactoryRightKind::ReserveClaim,
                None,
                50,
            ));
            rights.push(right(
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

pub fn fixture_reduced_state_package() -> Result<StoredFactoryStatePackage> {
    let update_package = fixture_package()?;
    let alice = fixture_signing_key(1)?;
    StoredFactoryStatePackage::from_reduced_update_package(update_package, &[(bytes32(1), alice)])
}

fn fixture_signing_key(byte: u8) -> Result<SigningKey> {
    SigningKey::from_slice(&[byte; 32])
        .map_err(|err| anyhow::anyhow!("invalid built-in fixture signing key: {err:?}"))
}

fn right(
    participant: u8,
    subchannel: u8,
    kind: FactoryRightKind,
    asset_type: Option<u8>,
    quantity: Amount,
) -> FactoryRight {
    right_with_asset(
        participant,
        subchannel,
        kind,
        asset_type.map(bytes32),
        quantity,
    )
}

fn right_with_asset(
    participant: u8,
    subchannel: u8,
    kind: FactoryRightKind,
    asset_type: Option<Bytes32>,
    quantity: Amount,
) -> FactoryRight {
    FactoryRight {
        id: FactoryRightId {
            participant: bytes32(participant),
            subchannel: bytes32(subchannel),
            kind,
            asset_type,
        },
        quantity,
    }
}

fn reserve_claim_quantity(rights: &[FactoryRight], id: &FactoryRightId) -> Result<Amount> {
    rights
        .iter()
        .find(|right| &right.id == id)
        .map(|right| right.quantity)
        .ok_or_else(|| anyhow::anyhow!("reserve claim right is missing"))
}

fn canonical_hex32_vec(values: &[String]) -> Result<Vec<String>> {
    canonical_hex_vec(values, 32)
}

fn canonical_hex_vec(values: &[String], byte_len: usize) -> Result<Vec<String>> {
    let mut out = values
        .iter()
        .map(|value| canonical_hex_exact(value, byte_len))
        .collect::<Result<Vec<_>>>()?;
    out.sort();
    out.dedup();
    Ok(out)
}

fn canonical_rights(values: &[StoredFactoryRight]) -> Result<Vec<StoredFactoryRight>> {
    let mut out = values
        .iter()
        .map(StoredFactoryRight::canonical)
        .collect::<Result<Vec<_>>>()?;
    out.sort_by_key(right_sort_key);
    Ok(out)
}

fn canonical_factory_amounts(
    values: &[StoredFactoryVaultAssetAmount],
) -> Result<Vec<StoredFactoryVaultAssetAmount>> {
    let mut out = values
        .iter()
        .map(StoredFactoryVaultAssetAmount::canonical)
        .collect::<Result<Vec<_>>>()?;
    out.sort_by_key(factory_amount_sort_key);
    ensure!(
        out.windows(2).all(
            |window| factory_amount_sort_key(&window[0]) != factory_amount_sort_key(&window[1])
        ),
        "factory vault assets must be unique"
    );
    Ok(out)
}

fn canonical_factory_deltas(
    values: &[StoredFactoryVaultDelta],
) -> Result<Vec<StoredFactoryVaultDelta>> {
    let mut out = values
        .iter()
        .map(StoredFactoryVaultDelta::canonical)
        .collect::<Result<Vec<_>>>()?;
    out.sort_by_key(factory_delta_sort_key);
    ensure!(
        out.windows(2)
            .all(|window| factory_delta_sort_key(&window[0]) != factory_delta_sort_key(&window[1])),
        "factory vault deltas must be unique"
    );
    Ok(out)
}

fn canonical_merkle_siblings(
    values: &[StoredFactoryMerkleSibling],
) -> Result<Vec<StoredFactoryMerkleSibling>> {
    values
        .iter()
        .map(StoredFactoryMerkleSibling::canonical)
        .collect()
}

fn ensure_sorted_unique_hex32(values: &[String], field: &str) -> Result<()> {
    let canonical = canonical_hex32_vec(values)?;
    ensure!(
        canonical == values,
        "{field} must contain sorted unique canonical hex32 values"
    );
    Ok(())
}

fn canonical_participant_keys(
    keys: &[StoredFactoryParticipantKey],
) -> Result<Vec<StoredFactoryParticipantKey>> {
    let mut out = keys
        .iter()
        .map(|key| {
            Ok(StoredFactoryParticipantKey {
                participant: canonical_hex32(&key.participant)?,
                pubkey_sec1: canonical_hex_exact(&key.pubkey_sec1, 33)?,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    out.sort_by(|left, right| left.participant.cmp(&right.participant));
    out.dedup_by(|left, right| left.participant == right.participant);
    ensure!(
        unique_pubkeys(out.iter().map(|key| key.pubkey_sec1.as_str())),
        "factory participant pubkeys must be unique"
    );
    Ok(out)
}

fn canonical_factory_signatures(
    signatures: &[StoredFactorySignature],
) -> Result<Vec<StoredFactorySignature>> {
    let mut out = signatures
        .iter()
        .map(|signature| {
            Ok(StoredFactorySignature {
                participant: canonical_hex32(&signature.participant)?,
                pubkey_sec1: canonical_hex_exact(&signature.pubkey_sec1, 33)?,
                signature: canonical_hex_exact(&signature.signature, 64)?,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    out.sort_by(|left, right| left.participant.cmp(&right.participant));
    out.dedup_by(|left, right| left.participant == right.participant);
    ensure!(
        unique_pubkeys(out.iter().map(|signature| signature.pubkey_sec1.as_str())),
        "factory signature pubkeys must be unique"
    );
    Ok(out)
}

fn update_participants(package: &StoredFactoryUpdatePackage) -> Result<BTreeSet<String>> {
    let mut participants = BTreeSet::new();
    for participant in package
        .touched_participants
        .iter()
        .chain(package.authorised_participants.iter())
    {
        participants.insert(canonical_hex32(participant)?);
    }
    for right in package
        .rights_before
        .iter()
        .chain(package.rights_after.iter())
    {
        participants.insert(canonical_hex32(&right.participant)?);
    }
    Ok(participants)
}

fn unique_pubkeys<'a>(values: impl Iterator<Item = &'a str>) -> bool {
    let mut seen = BTreeSet::new();
    values
        .into_iter()
        .all(|value| seen.insert(value.to_string()))
}

fn right_sort_key(right: &StoredFactoryRight) -> (String, String, u8, String, Amount) {
    (
        right.participant.clone(),
        right.subchannel.clone(),
        factory_kind_order(right.kind),
        right.asset_type.clone().unwrap_or_default(),
        right.quantity,
    )
}

fn factory_amount_sort_key(right: &StoredFactoryVaultAssetAmount) -> (String, String) {
    (
        right.asset.clone(),
        right.type_hash.clone().unwrap_or_default(),
    )
}

fn factory_delta_sort_key(delta: &StoredFactoryVaultDelta) -> (String, String) {
    (
        delta.asset.clone(),
        delta.type_hash.clone().unwrap_or_default(),
    )
}

fn factory_kind_order(kind: FactoryRightKind) -> u8 {
    match kind {
        FactoryRightKind::Balance => 0,
        FactoryRightKind::ReserveClaim => 1,
        FactoryRightKind::Membership => 2,
        FactoryRightKind::ExitPath => 3,
        FactoryRightKind::SponsorBudgetClaim => 4,
    }
}

fn parse_factory_splice_kind(kind: &str) -> Result<FactorySpliceKind> {
    match kind {
        "splice_in" => Ok(FactorySpliceKind::In),
        "splice_out" => Ok(FactorySpliceKind::Out),
        other => Err(anyhow::anyhow!("unsupported factory splice kind {other}")),
    }
}

fn factory_splice_kind_name(kind: FactorySpliceKind) -> &'static str {
    match kind {
        FactorySpliceKind::In => "splice_in",
        FactorySpliceKind::Out => "splice_out",
    }
}

fn stored_asset_fields(asset: &VaultAsset) -> (String, Option<String>) {
    match asset {
        VaultAsset::Ckb => ("ckb".to_string(), None),
        VaultAsset::Xudt(type_hash) => ("xudt".to_string(), Some(hex_prefixed(type_hash))),
    }
}

fn parse_vault_asset(asset: &str, type_hash: Option<&str>) -> Result<VaultAsset> {
    match asset {
        "ckb" => {
            ensure!(
                type_hash.is_none(),
                "CKB factory vault asset must not carry type_hash"
            );
            Ok(VaultAsset::Ckb)
        }
        "xudt" => Ok(VaultAsset::Xudt(hex32_bytes(type_hash.ok_or_else(
            || anyhow::anyhow!("xUDT factory vault asset requires type_hash"),
        )?)?)),
        other => Err(anyhow::anyhow!("unsupported factory vault asset {other}")),
    }
}

fn asset_name(asset: &VaultAsset) -> String {
    match asset {
        VaultAsset::Ckb => "ckb".to_string(),
        VaultAsset::Xudt(type_hash) => format!("xudt:{}", hex_prefixed(type_hash)),
    }
}

fn factory_splice_asset_registry(
    package: &StoredFactorySplicePackage,
) -> Result<morph_core::AssetRegistry> {
    let mut xudt_types = BTreeSet::new();
    for amount in package.old_vault.iter().chain(package.new_vault.iter()) {
        if let VaultAsset::Xudt(type_hash) =
            parse_vault_asset(&amount.asset, amount.type_hash.as_deref())?
        {
            xudt_types.insert(type_hash);
        }
    }
    for delta in &package.vault_deltas {
        if let VaultAsset::Xudt(type_hash) =
            parse_vault_asset(&delta.asset, delta.type_hash.as_deref())?
        {
            xudt_types.insert(type_hash);
        }
    }
    for right in package
        .update_package
        .rights_before
        .iter()
        .chain(package.update_package.rights_after.iter())
    {
        if let Some(asset_type) = &right.asset_type {
            xudt_types.insert(hex32_bytes(asset_type)?);
        }
    }
    Ok(morph_core::AssetRegistry { xudt_types })
}

fn factory_reduced_splice_asset_registry(
    package: &StoredFactoryReducedSplicePackage,
) -> Result<morph_core::AssetRegistry> {
    let mut xudt_types = BTreeSet::new();
    for amount in package.old_vault.iter().chain(package.new_vault.iter()) {
        if let VaultAsset::Xudt(type_hash) =
            parse_vault_asset(&amount.asset, amount.type_hash.as_deref())?
        {
            xudt_types.insert(type_hash);
        }
    }
    for delta in &package.vault_deltas {
        if let VaultAsset::Xudt(type_hash) =
            parse_vault_asset(&delta.asset, delta.type_hash.as_deref())?
        {
            xudt_types.insert(type_hash);
        }
    }
    for right in [
        &package.merkle_update_package.right_before,
        &package.merkle_update_package.right_after,
    ] {
        if let Some(asset_type) = &right.asset_type {
            xudt_types.insert(hex32_bytes(asset_type)?);
        }
    }
    Ok(morph_core::AssetRegistry { xudt_types })
}

fn changed_reserve_claim(update: &FactoryUpdate) -> Result<(&FactoryRight, Option<&FactoryRight>)> {
    let mut found = None;
    for before in &update.before {
        let after = update.after.iter().find(|right| right.id == before.id);
        if after.map(|right| right.quantity).unwrap_or_default() != before.quantity {
            ensure!(
                before.id.kind == FactoryRightKind::ReserveClaim,
                "changed factory splice right must be a reserve claim"
            );
            ensure!(
                found.is_none(),
                "factory splice package changed multiple rights"
            );
            found = Some((before, after));
        }
    }
    for after in &update.after {
        if update.before.iter().any(|right| right.id == after.id) {
            continue;
        }
        ensure!(
            after.id.kind == FactoryRightKind::ReserveClaim,
            "created factory splice right must be a reserve claim"
        );
        ensure!(
            found.is_none(),
            "factory splice package changed multiple rights"
        );
        found = Some((after, Some(after)));
    }
    found.ok_or_else(|| anyhow::anyhow!("factory splice package did not change a reserve claim"))
}

fn changed_merkle_reserve_claim(
    update: &FactorySingleRightMerkleUpdate,
) -> Result<(&FactoryRight, &FactoryRight)> {
    ensure!(
        update.before.right.id == update.after.right.id
            && update.before.right.id.kind == FactoryRightKind::ReserveClaim
            && update.before.right.quantity != update.after.right.quantity,
        "reduced factory splice package must change exactly one reserve claim"
    );
    Ok((&update.before.right, &update.after.right))
}

fn contract_witness_bytes_from_transition(
    transition: &FactorySpliceTransition,
    participant_keys: &[StoredFactoryParticipantKey],
    signatures: &[StoredFactorySignature],
) -> Result<Vec<u8>> {
    let header = factory_splice_header_wire_bytes(&transition.header);
    let signatures = factory_signature_witness_wire_bytes(
        &transition.header,
        &transition.update,
        participant_keys,
        signatures,
    )?;
    let old_vault =
        factory_vault_descriptor_wire_bytes(&transition.header.factory_id, &transition.old_vault)?;
    let new_vault =
        factory_vault_descriptor_wire_bytes(&transition.header.factory_id, &transition.new_vault)?;
    let deltas = factory_vault_deltas_wire_bytes(&transition.deltas)?;

    let body_len = factory_splice_witness_len(participant_keys.len() as u8);
    let mut raw = vec![0u8; body_len];
    put_u16(&mut raw, 0, FACTORY_SPLICE_WITNESS_VERSION);
    let mut offset = 2;
    raw[offset..offset + FACTORY_SPLICE_HEADER_LEN].copy_from_slice(&header);
    offset += FACTORY_SPLICE_HEADER_LEN;
    raw[offset..offset + signatures.len()].copy_from_slice(&signatures);
    offset += signatures.len();
    raw[offset..offset + FACTORY_VAULT_DESCRIPTOR_LEN].copy_from_slice(&old_vault);
    offset += FACTORY_VAULT_DESCRIPTOR_LEN;
    raw[offset..offset + FACTORY_VAULT_DESCRIPTOR_LEN].copy_from_slice(&new_vault);
    offset += FACTORY_VAULT_DESCRIPTOR_LEN;
    raw[offset..offset + FACTORY_VAULT_DELTAS_LEN].copy_from_slice(&deltas);

    WireFactorySpliceWitness::parse(&raw)
        .map_err(|err| anyhow::anyhow!("encoded factory splice witness is invalid: {err:?}"))?;
    witness_envelope(WITNESS_ENVELOPE_KIND_FACTORY_SPLICE, &raw)
}

fn contract_reduced_splice_witness_bytes_from_transition(
    transition: &FactoryReducedSpliceTransition,
) -> Result<Vec<u8>> {
    let header = factory_splice_header_wire_bytes(&transition.header);
    let merkle_update =
        factory_merkle_update_witness_wire_bytes(&transition.update, &transition.witness)?;
    let old_vault =
        factory_vault_descriptor_wire_bytes(&transition.header.factory_id, &transition.old_vault)?;
    let new_vault =
        factory_vault_descriptor_wire_bytes(&transition.header.factory_id, &transition.new_vault)?;
    let deltas = factory_vault_deltas_wire_bytes(&transition.deltas)?;

    let body_len =
        factory_reduced_splice_witness_len(transition.witness.participant_keys.len() as u8);
    let mut raw = vec![0u8; body_len];
    put_u16(&mut raw, 0, FACTORY_REDUCED_SPLICE_WITNESS_VERSION);
    let mut offset = 2;
    raw[offset..offset + FACTORY_SPLICE_HEADER_LEN].copy_from_slice(&header);
    offset += FACTORY_SPLICE_HEADER_LEN;
    raw[offset..offset + merkle_update.len()].copy_from_slice(&merkle_update);
    offset += merkle_update.len();
    raw[offset..offset + FACTORY_VAULT_DESCRIPTOR_LEN].copy_from_slice(&old_vault);
    offset += FACTORY_VAULT_DESCRIPTOR_LEN;
    raw[offset..offset + FACTORY_VAULT_DESCRIPTOR_LEN].copy_from_slice(&new_vault);
    offset += FACTORY_VAULT_DESCRIPTOR_LEN;
    raw[offset..offset + FACTORY_VAULT_DELTAS_LEN].copy_from_slice(&deltas);

    WireFactoryReducedSpliceWitness::parse(&raw).map_err(|err| {
        anyhow::anyhow!("encoded reduced factory splice witness is invalid: {err:?}")
    })?;
    witness_envelope(WITNESS_ENVELOPE_KIND_FACTORY_REDUCED_SPLICE, &raw)
}

fn witness_envelope(kind: u16, body: &[u8]) -> Result<Vec<u8>> {
    let body_len: u32 = body
        .len()
        .try_into()
        .context("factory witness body length does not fit in u32")?;
    let mut raw = vec![0u8; WITNESS_ENVELOPE_LEN + body.len()];
    raw[0..WITNESS_ENVELOPE_MAGIC.len()].copy_from_slice(WITNESS_ENVELOPE_MAGIC);
    put_u16(&mut raw, 8, WITNESS_ENVELOPE_FORMAT);
    put_u16(&mut raw, 10, kind);
    put_u16(&mut raw, 12, 0);
    put_u32(&mut raw, 14, body_len);
    raw[18..50].copy_from_slice(&witness_envelope_body_commitment(kind, body));
    raw[WITNESS_ENVELOPE_LEN..].copy_from_slice(body);
    WitnessEnvelope::parse(&raw)
        .map_err(|err| anyhow::anyhow!("encoded factory witness envelope is invalid: {err:?}"))?;
    Ok(raw)
}

fn factory_reduced_splice_contract_non_interference_digest(
    header: &FactorySpliceHeader,
    update: &FactorySingleRightMerkleUpdate,
) -> Result<Bytes32> {
    ensure!(
        update.before.right.id == update.after.right.id,
        "reduced factory splice contract digest requires one stable right id"
    );
    let old_update_number = header.old_update_number.to_le_bytes();
    let new_update_number = header.new_update_number.to_le_bytes();
    let before = factory_right_wire_bytes(&update.before.right);
    let after = factory_right_wire_bytes(&update.after.right);

    let mut payload = Vec::new();
    payload.extend_from_slice(FACTORY_MERKLE_UPDATE_DOMAIN);
    payload.extend_from_slice(&header.factory_id);
    payload.extend_from_slice(&old_update_number);
    payload.extend_from_slice(&new_update_number);
    payload.extend_from_slice(&header.old_state_root);
    payload.extend_from_slice(&header.new_state_root);
    payload.extend_from_slice(&header.old_access_manifest_root);
    payload.extend_from_slice(&header.new_access_manifest_root);
    payload.extend_from_slice(&update.before.right.id.participant);
    payload.extend_from_slice(&before);
    payload.extend_from_slice(&after);
    Ok(blake2b256(&payload))
}

fn factory_splice_header_wire_bytes(
    header: &FactorySpliceHeader,
) -> [u8; FACTORY_SPLICE_HEADER_LEN] {
    let mut raw = [0u8; FACTORY_SPLICE_HEADER_LEN];
    put_u16(&mut raw, 0, header.protocol_version);
    raw[2..34].copy_from_slice(&header.chain_id);
    put_u16(&mut raw, 34, header.signature_scheme_id);
    raw[36..68].copy_from_slice(&header.factory_id);
    put_u64(&mut raw, 68, header.old_update_number);
    put_u64(&mut raw, 76, header.new_update_number);
    raw[84..116].copy_from_slice(&header.old_state_root);
    raw[116..148].copy_from_slice(&header.new_state_root);
    raw[148..180].copy_from_slice(&header.old_access_manifest_root);
    raw[180..212].copy_from_slice(&header.new_access_manifest_root);
    raw[212] = factory_splice_kind_wire_byte(header.kind);
    raw[213..245].copy_from_slice(&header.vault_delta_commitment);
    raw[245..277].copy_from_slice(&header.non_interference_digest);
    raw[277..309].copy_from_slice(&header.participants_commitment);
    raw[309..341].copy_from_slice(&header.old_vault_materialisation_root);
    raw[341..373].copy_from_slice(&header.new_vault_materialisation_root);
    raw[373..405].copy_from_slice(&header.old_vault_outpoint_commitment);
    raw[405..437].copy_from_slice(&header.new_vault_outpoint_commitment);
    raw[437..469].copy_from_slice(&header.withdrawal_lock_hash);
    raw
}

fn factory_signature_witness_wire_bytes(
    header: &FactorySpliceHeader,
    update: &FactoryUpdate,
    participant_keys: &[StoredFactoryParticipantKey],
    signatures: &[StoredFactorySignature],
) -> Result<Vec<u8>> {
    ensure!(
        participant_keys.len() >= FACTORY_MIN_PARTICIPANTS as usize
            && participant_keys.len() <= FACTORY_MAX_PARTICIPANTS as usize
            && signatures.len() == participant_keys.len(),
        "dynamic factory splice witness requires 2..=16 participant keys and one signature each"
    );
    let participants = factory_participants_from_update(update)?;
    ensure!(
        participants.len() == participant_keys.len(),
        "factory splice witness participant keys must cover every update participant"
    );
    let mut key_by_participant = BTreeMap::new();
    for key in participant_keys {
        let participant = hex32_bytes(&key.participant)?;
        let pubkey = decode_hex_exact(&key.pubkey_sec1, 33, "pubkey_sec1")?;
        ensure!(
            key_by_participant.insert(participant, pubkey).is_none(),
            "factory splice participant keys must be unique"
        );
    }
    let mut signature_by_participant = BTreeMap::new();
    for signature in signatures {
        let participant = hex32_bytes(&signature.participant)?;
        let pubkey = decode_hex_exact(&signature.pubkey_sec1, 33, "pubkey_sec1")?;
        let signature_bytes = decode_hex_exact(&signature.signature, 64, "signature")?;
        let expected_pubkey = key_by_participant
            .get(&participant)
            .ok_or_else(|| anyhow::anyhow!("factory splice signature has unknown participant"))?;
        ensure!(
            expected_pubkey == &pubkey,
            "factory splice signature pubkey does not match participant key"
        );
        ensure!(
            signature_by_participant
                .insert(participant, (pubkey, signature_bytes))
                .is_none(),
            "factory splice signatures must be unique by participant"
        );
    }
    ensure!(
        participants
            .iter()
            .all(|participant| key_by_participant.contains_key(participant))
            && participants
                .iter()
                .all(|participant| signature_by_participant.contains_key(participant)),
        "factory splice witness keys and signatures must cover update participants"
    );
    let pubkey_refs = participants
        .iter()
        .map(|participant| {
            key_by_participant
                .get(participant)
                .map(Vec::as_slice)
                .ok_or_else(|| anyhow::anyhow!("factory splice participant key missing"))
        })
        .collect::<Result<Vec<_>>>()?;
    ensure!(
        participants_commitment(participants.len() as u8, &pubkey_refs)
            == header.participants_commitment,
        "factory splice header participant commitment does not match witness pubkeys"
    );

    let mut raw = vec![0u8; factory_signature_witness_len(participants.len() as u8)];
    put_u16(&mut raw, 0, FACTORY_SIGNATURE_WITNESS_VERSION);
    raw[2] = participants.len() as u8;
    raw[3] = participants.len() as u8;
    for (index, participant) in participants.iter().enumerate() {
        let (pubkey, signature) = signature_by_participant
            .get(participant)
            .ok_or_else(|| anyhow::anyhow!("factory splice signature missing participant"))?;
        ensure!(
            pubkey.len() == COMPRESSED_SECP256K1_PUBKEY_LEN,
            "factory splice participant pubkey must be compressed secp256k1"
        );
        ensure!(
            signature.len() == ECDSA_SIGNATURE_LEN,
            "factory splice participant signature must be 64 bytes"
        );
        let offset =
            4 + index * (BYTE32_LEN + COMPRESSED_SECP256K1_PUBKEY_LEN + ECDSA_SIGNATURE_LEN);
        raw[offset..offset + BYTE32_LEN].copy_from_slice(participant);
        raw[offset + BYTE32_LEN..offset + BYTE32_LEN + COMPRESSED_SECP256K1_PUBKEY_LEN]
            .copy_from_slice(pubkey);
        raw[offset + BYTE32_LEN + COMPRESSED_SECP256K1_PUBKEY_LEN
            ..offset + BYTE32_LEN + COMPRESSED_SECP256K1_PUBKEY_LEN + ECDSA_SIGNATURE_LEN]
            .copy_from_slice(signature);
    }
    Ok(raw)
}

fn factory_merkle_update_witness_wire_bytes(
    update: &FactorySingleRightMerkleUpdate,
    witness: &FactoryReducedSpliceWitness,
) -> Result<Vec<u8>> {
    ensure!(
        witness.participant_keys.len() >= FACTORY_MIN_PARTICIPANTS as usize
            && witness.participant_keys.len() <= FACTORY_MAX_PARTICIPANTS as usize
            && witness.participant_threshold as usize == witness.participant_keys.len()
            && witness.signatures.len() == FACTORY_REDUCED_RIGHTS_AUTHORISED_COUNT as usize,
        "dynamic reduced factory splice witness requires 2..=16 participant keys and one authorised signature"
    );
    ensure!(
        update.before.siblings == update.after.siblings
            && update.before.siblings.len() == FACTORY_SPARSE_MERKLE_DEPTH,
        "contract reduced factory splice witness requires one unchanged sparse Merkle frontier"
    );
    ensure!(
        update.before.right.id == update.after.right.id,
        "contract reduced factory splice witness requires one changed right"
    );

    let mut raw =
        vec![0u8; factory_merkle_update_witness_len(witness.participant_keys.len() as u8)];
    put_u16(&mut raw, 0, FACTORY_MERKLE_UPDATE_WITNESS_VERSION);
    raw[2] = witness.participant_keys.len() as u8;
    raw[3] = witness.participant_keys.len() as u8;
    raw[4] = FACTORY_REDUCED_RIGHTS_AUTHORISED_COUNT;
    raw[5] = FACTORY_MERKLE_UPDATE_RIGHT_COUNT;

    for (index, key) in witness.participant_keys.iter().enumerate() {
        ensure!(
            key.pubkey_sec1.len() == COMPRESSED_SECP256K1_PUBKEY_LEN,
            "contract reduced factory splice participant pubkey must be compressed secp256k1"
        );
        let offset = 8 + index * FACTORY_REDUCED_RIGHTS_PARTICIPANT_ENTRY_LEN;
        raw[offset..offset + BYTE32_LEN].copy_from_slice(&key.participant);
        raw[offset + BYTE32_LEN..offset + BYTE32_LEN + COMPRESSED_SECP256K1_PUBKEY_LEN]
            .copy_from_slice(&key.pubkey_sec1);
        if let Some(signature) = witness
            .signatures
            .iter()
            .find(|signature| signature.participant == key.participant)
        {
            ensure!(
                signature.pubkey_sec1 == key.pubkey_sec1
                    && signature.signature.len() == ECDSA_SIGNATURE_LEN,
                "contract reduced factory splice signature must match the participant key"
            );
            raw[offset + BYTE32_LEN + COMPRESSED_SECP256K1_PUBKEY_LEN] = 1;
            raw[offset + BYTE32_LEN + COMPRESSED_SECP256K1_PUBKEY_LEN + 1
                ..offset + BYTE32_LEN + COMPRESSED_SECP256K1_PUBKEY_LEN + 1 + ECDSA_SIGNATURE_LEN]
                .copy_from_slice(&signature.signature);
        }
    }

    let touched_offset =
        8 + witness.participant_keys.len() * FACTORY_REDUCED_RIGHTS_PARTICIPANT_ENTRY_LEN;
    raw[touched_offset..touched_offset + BYTE32_LEN]
        .copy_from_slice(&update.before.right.id.participant);
    let before_offset = touched_offset + BYTE32_LEN;
    raw[before_offset..before_offset + FACTORY_RIGHT_LEN]
        .copy_from_slice(&factory_right_wire_bytes(&update.before.right));
    let after_offset = before_offset + FACTORY_RIGHT_LEN;
    raw[after_offset..after_offset + FACTORY_RIGHT_LEN]
        .copy_from_slice(&factory_right_wire_bytes(&update.after.right));
    let siblings_offset = after_offset + FACTORY_RIGHT_LEN;
    for (depth, sibling) in update.before.siblings.iter().enumerate() {
        let offset = siblings_offset + depth * BYTE32_LEN;
        raw[offset..offset + BYTE32_LEN].copy_from_slice(&sibling.hash);
    }

    Ok(raw)
}

fn factory_participants_from_update(update: &FactoryUpdate) -> Result<Vec<Bytes32>> {
    let mut participants = BTreeSet::new();
    for right in update.before.iter().chain(update.after.iter()) {
        participants.insert(right.id.participant);
    }
    ensure!(
        !participants.is_empty() && participants.len() <= u8::MAX as usize,
        "factory splice update must contain participant ids"
    );
    Ok(participants.into_iter().collect())
}

fn factory_right_wire_bytes(right: &FactoryRight) -> [u8; FACTORY_RIGHT_LEN] {
    let mut raw = [0u8; FACTORY_RIGHT_LEN];
    raw[0..32].copy_from_slice(&right.id.participant);
    raw[32..64].copy_from_slice(&right.id.subchannel);
    raw[64] = factory_right_kind_wire_byte(right.id.kind);
    if let Some(asset_type) = right.id.asset_type {
        raw[65] = 1;
        raw[66..98].copy_from_slice(&asset_type);
    }
    put_u128(&mut raw, 98, right.quantity);
    raw
}

fn factory_right_kind_wire_byte(kind: FactoryRightKind) -> u8 {
    match kind {
        FactoryRightKind::Balance => 0,
        FactoryRightKind::ReserveClaim => 1,
        FactoryRightKind::Membership => 2,
        FactoryRightKind::ExitPath => 3,
        FactoryRightKind::SponsorBudgetClaim => 4,
    }
}

fn factory_vault_descriptor_wire_bytes(
    expected_factory_id: &Bytes32,
    descriptor: &FactoryVaultDescriptor,
) -> Result<[u8; FACTORY_VAULT_DESCRIPTOR_LEN]> {
    ensure!(
        &descriptor.factory_id == expected_factory_id,
        "factory vault descriptor factory_id mismatch"
    );
    ensure!(
        !descriptor.assets.is_empty() && descriptor.assets.len() <= 2,
        "contract factory vault descriptor supports one or two assets"
    );
    let mut raw = [0u8; FACTORY_VAULT_DESCRIPTOR_LEN];
    raw[0..32].copy_from_slice(&descriptor.factory_id);
    put_u16(&mut raw, 32, descriptor.assets.len() as u16);
    for (index, asset) in descriptor.assets.iter().enumerate() {
        let offset = 34 + index * FACTORY_VAULT_ASSET_AMOUNT_LEN;
        raw[offset..offset + FACTORY_VAULT_ASSET_AMOUNT_LEN]
            .copy_from_slice(&factory_vault_asset_wire_bytes(asset));
    }
    Ok(raw)
}

fn factory_vault_asset_wire_bytes(
    amount: &VaultAssetAmount,
) -> [u8; FACTORY_VAULT_ASSET_AMOUNT_LEN] {
    let mut raw = [0u8; FACTORY_VAULT_ASSET_AMOUNT_LEN];
    let (kind, type_hash) = vault_asset_wire_key(&amount.asset);
    raw[0] = kind;
    raw[1..33].copy_from_slice(&type_hash);
    put_u128(&mut raw, 33, amount.amount);
    raw
}

fn factory_vault_deltas_wire_bytes(
    deltas: &[FactoryVaultDelta],
) -> Result<[u8; FACTORY_VAULT_DELTAS_LEN]> {
    ensure!(
        !deltas.is_empty() && deltas.len() <= 2,
        "contract factory vault deltas support one or two assets"
    );
    let mut raw = [0u8; FACTORY_VAULT_DELTAS_LEN];
    put_u16(&mut raw, 0, deltas.len() as u16);
    for (index, delta) in deltas.iter().enumerate() {
        let offset = 2 + index * FACTORY_VAULT_DELTA_LEN;
        raw[offset..offset + FACTORY_VAULT_DELTA_LEN]
            .copy_from_slice(&factory_vault_delta_wire_bytes(delta));
    }
    Ok(raw)
}

fn factory_vault_delta_wire_bytes(delta: &FactoryVaultDelta) -> [u8; FACTORY_VAULT_DELTA_LEN] {
    let mut raw = [0u8; FACTORY_VAULT_DELTA_LEN];
    let (kind, type_hash) = vault_asset_wire_key(&delta.asset);
    raw[0] = kind;
    raw[1..33].copy_from_slice(&type_hash);
    put_u128(&mut raw, 33, delta.old_amount);
    put_u128(&mut raw, 49, delta.new_amount);
    put_u128(&mut raw, 65, delta.external_input);
    put_u128(&mut raw, 81, delta.withdrawal);
    raw
}

fn factory_splice_kind_wire_byte(kind: FactorySpliceKind) -> u8 {
    match kind {
        FactorySpliceKind::In => 0,
        FactorySpliceKind::Out => 1,
    }
}

fn vault_asset_wire_key(asset: &VaultAsset) -> (u8, Bytes32) {
    match asset {
        VaultAsset::Ckb => (VAULT_ASSET_KIND_CKB, [0u8; 32]),
        VaultAsset::Xudt(type_hash) => (VAULT_ASSET_KIND_XUDT, *type_hash),
    }
}

fn hex32_bytes(value: &str) -> Result<Bytes32> {
    let canonical = canonical_hex32(value)?;
    let bytes = hex::decode(canonical.trim_start_matches("0x"))?;
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn canonical_hex_exact(value: &str, byte_len: usize) -> Result<String> {
    let without_prefix = value.strip_prefix("0x").unwrap_or(value);
    ensure!(
        without_prefix.len() == byte_len * 2,
        "hex value must be {byte_len} bytes"
    );
    let bytes = hex::decode(without_prefix)?;
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

fn put_u32(raw: &mut [u8], offset: usize, value: u32) {
    raw[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn put_u64(raw: &mut [u8], offset: usize, value: u64) {
    raw[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn put_u128(raw: &mut [u8], offset: usize, value: u128) {
    raw[offset..offset + 16].copy_from_slice(&value.to_le_bytes());
}

fn hex_prefixed(bytes: &[u8]) -> String {
    format!("0x{}", hex::encode(bytes))
}

fn pubkey_hex(key: &SigningKey) -> String {
    hex_prefixed(key.verifying_key().to_encoded_point(true).as_bytes())
}

fn sign_factory_digest(
    participant: &str,
    pubkey_sec1: &str,
    key: &SigningKey,
    digest: &Bytes32,
) -> Result<StoredFactorySignature> {
    let signature: Signature = key
        .sign_prehash(digest)
        .map_err(|err| anyhow::anyhow!("failed to sign factory state digest: {err:?}"))?;
    Ok(StoredFactorySignature {
        participant: participant.to_string(),
        pubkey_sec1: pubkey_sec1.to_string(),
        signature: hex_prefixed(signature.to_bytes().as_ref()),
    })
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

    #[test]
    fn validates_factory_update_package() {
        let package = fixture_package().unwrap();
        let summary = package.summary().unwrap();

        assert_eq!(summary.update_number, 1);
        assert_eq!(summary.touched_participants, 1);
        assert_eq!(summary.authorised_participants, 1);
        assert_eq!(summary.rights_before, 10);
        assert_eq!(summary.rights_after, 10);
    }

    #[test]
    fn rejects_interfering_factory_update_package() {
        let mut package = fixture_package().unwrap();
        package.rights_after[5].quantity = 1;
        package.non_interference_digest = package.compute_digest().unwrap();

        let err = package.validate().unwrap_err();
        assert!(err.to_string().contains("non-interference"));
    }

    #[test]
    fn rejects_factory_package_digest_mismatch() {
        let mut package = fixture_package().unwrap();
        package.non_interference_digest = hex_prefixed(&[9u8; 32]);

        let err = package.validate().unwrap_err();
        assert!(err.to_string().contains("digest mismatch"));
    }

    #[test]
    fn validates_factory_state_package() {
        let package = fixture_state_package().unwrap();
        let summary = package.summary().unwrap();

        assert_eq!(summary.signature_mode, "all_participants");
        assert_eq!(summary.signature_threshold, 2);
        assert_eq!(summary.participants, 2);
        assert_eq!(summary.signatures, 2);
    }

    #[test]
    fn validates_reduced_factory_state_package() {
        let package = fixture_reduced_state_package().unwrap();
        let summary = package.summary().unwrap();

        assert_eq!(summary.signature_mode, "authorised_participants");
        assert_eq!(summary.signature_threshold, 1);
        assert_eq!(summary.participants, 1);
        assert_eq!(summary.signatures, 1);
    }

    #[test]
    fn validates_reduced_factory_exit_package() {
        let package = fixture_reduced_exit_package().unwrap();
        let summary = package.summary().unwrap();

        assert_eq!(summary.update_number, 1);
        assert_eq!(summary.participant, hex_prefixed(&bytes32(1)));
        assert_eq!(summary.reserve_claim_before, 50);
        assert_eq!(summary.reserve_claim_after, 30);
        assert_eq!(summary.release_quantity, 20);
    }

    #[test]
    fn validates_factory_merkle_update_package() {
        let package = fixture_merkle_update_package().unwrap();
        let summary = package.summary().unwrap();

        assert_eq!(summary.update_number, 2);
        assert_eq!(summary.changed_participant, hex_prefixed(&bytes32(3)));
        assert_eq!(summary.changed_kind, FactoryRightKind::ReserveClaim);
        assert_eq!(summary.quantity_before, 50);
        assert_eq!(summary.quantity_after, 35);
        assert_eq!(summary.proof_siblings, 256);
    }

    #[test]
    fn validates_factory_splice_package() {
        let package =
            fixture_factory_splice_package_with_kind(FixtureFactorySpliceKind::CkbSpliceIn)
                .unwrap();
        let summary = package.summary().unwrap();

        assert_eq!(summary.kind, "splice_in");
        assert_eq!(summary.old_update_number, 1);
        assert_eq!(summary.new_update_number, 2);
        assert_eq!(summary.reserve_claim_before, 50);
        assert_eq!(summary.reserve_claim_after, 70);
        assert_eq!(summary.external_input, 20);
        assert_eq!(summary.withdrawal, 0);
        assert_eq!(summary.signature_threshold, 2);
        assert_eq!(summary.signatures, 2);
        assert_factory_splice_contract_witness(&package, &summary);
    }

    #[test]
    fn validates_three_party_dynamic_factory_splice_package() {
        let package = fixture_factory_splice_package_with_participant_count(
            FixtureFactorySpliceKind::CkbSpliceIn,
            3,
        )
        .unwrap();
        let summary = package.summary().unwrap();
        let envelope_bytes = package.contract_witness_bytes().unwrap();
        let envelope = WitnessEnvelope::parse(&envelope_bytes).unwrap();
        let witness = WireFactorySpliceWitness::parse(envelope.body()).unwrap();

        assert_eq!(summary.signature_threshold, 3);
        assert_eq!(summary.signatures, 3);
        assert_eq!(envelope.kind(), WITNESS_ENVELOPE_KIND_FACTORY_SPLICE);
        assert_eq!(witness.participant_count(), 3);
    }

    #[test]
    fn rejects_factory_splice_participant_key_set_mismatch() {
        let mut package =
            fixture_factory_splice_package_with_kind(FixtureFactorySpliceKind::CkbSpliceIn)
                .unwrap();
        let wrong_participant = hex_prefixed(&bytes32(0));
        package.participant_keys[0].participant = wrong_participant.clone();
        package.signatures[0].participant = wrong_participant;

        let err = package.validate().unwrap_err();
        assert!(
            err.to_string()
                .contains("participant_keys do not match update participants")
        );
    }

    #[test]
    fn validates_factory_xudt_splice_out_package() {
        let package =
            fixture_factory_splice_package_with_kind(FixtureFactorySpliceKind::XudtSpliceOut)
                .unwrap();
        let summary = package.summary().unwrap();

        assert_eq!(summary.kind, "splice_out");
        assert!(summary.reserve_claim_asset.starts_with("xudt:"));
        assert_eq!(summary.reserve_claim_before, 50);
        assert_eq!(summary.reserve_claim_after, 30);
        assert_eq!(summary.external_input, 0);
        assert_eq!(summary.withdrawal, 20);
        assert_factory_splice_contract_witness(&package, &summary);
    }

    #[test]
    fn writes_reads_and_validates_factory_splice_package() {
        let package =
            fixture_factory_splice_package_with_kind(FixtureFactorySpliceKind::CkbSpliceIn)
                .unwrap();
        let dir = std::env::temp_dir().join(format!(
            "morph-factory-splice-package-test-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        let path = write_factory_splice_package(&dir, &package).unwrap();
        let loaded = read_factory_splice_package(&path).unwrap();

        assert_eq!(loaded.signing_digest, package.signing_digest);
        assert_eq!(
            loaded.summary().unwrap().contract_witness_len,
            WITNESS_ENVELOPE_LEN + factory_splice_witness_len(2)
        );

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn validates_factory_reduced_splice_package() {
        let package =
            fixture_factory_reduced_splice_package_with_kind(FixtureFactorySpliceKind::CkbSpliceIn)
                .unwrap();
        let summary = package.summary().unwrap();

        assert_eq!(summary.kind, "splice_in");
        assert_eq!(summary.old_update_number, 1);
        assert_eq!(summary.new_update_number, 2);
        assert_eq!(summary.reserve_claim_before, 50);
        assert_eq!(summary.reserve_claim_after, 70);
        assert_eq!(summary.external_input, 20);
        assert_eq!(summary.withdrawal, 0);
        assert_eq!(summary.participant_keys, 2);
        assert_eq!(summary.signature_threshold, 2);
        assert_eq!(summary.signatures, 1);
        assert_eq!(summary.proof_siblings, 256);
        assert_factory_reduced_splice_contract_witness(&package, &summary);
    }

    #[test]
    fn validates_three_party_dynamic_reduced_factory_splice_package() {
        let package = fixture_factory_reduced_splice_package_with_participant_count(
            FixtureFactorySpliceKind::CkbSpliceOut,
            3,
        )
        .unwrap();
        let summary = package.summary().unwrap();
        let envelope_bytes = package.contract_witness_bytes().unwrap();
        let envelope = WitnessEnvelope::parse(&envelope_bytes).unwrap();
        let witness = WireFactoryReducedSpliceWitness::parse(envelope.body()).unwrap();

        assert_eq!(summary.participant_keys, 3);
        assert_eq!(summary.signature_threshold, 3);
        assert_eq!(summary.signatures, 1);
        assert_eq!(
            envelope.kind(),
            WITNESS_ENVELOPE_KIND_FACTORY_REDUCED_SPLICE
        );
        assert_eq!(witness.participant_count(), 3);
    }

    #[test]
    fn validates_factory_reduced_xudt_splice_out_package() {
        let package = fixture_factory_reduced_splice_package_with_kind(
            FixtureFactorySpliceKind::XudtSpliceOut,
        )
        .unwrap();
        let summary = package.summary().unwrap();

        assert_eq!(summary.kind, "splice_out");
        assert!(summary.reserve_claim_asset.starts_with("xudt:"));
        assert_eq!(summary.reserve_claim_before, 50);
        assert_eq!(summary.reserve_claim_after, 30);
        assert_eq!(summary.external_input, 0);
        assert_eq!(summary.withdrawal, 20);
        assert_eq!(summary.signatures, 1);
        assert_eq!(summary.proof_siblings, 256);
        assert_factory_reduced_splice_contract_witness(&package, &summary);
    }

    #[test]
    fn writes_reads_and_validates_factory_reduced_splice_package() {
        let package =
            fixture_factory_reduced_splice_package_with_kind(FixtureFactorySpliceKind::CkbSpliceIn)
                .unwrap();
        let dir = std::env::temp_dir().join(format!(
            "morph-factory-reduced-splice-package-test-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        let path = write_factory_reduced_splice_package(&dir, &package).unwrap();
        let loaded = read_factory_reduced_splice_package(&path).unwrap();

        assert_eq!(loaded.signing_digest, package.signing_digest);
        let loaded_summary = loaded.summary().unwrap();
        assert_eq!(loaded_summary.proof_siblings, 256);
        assert_eq!(
            loaded_summary.contract_witness_len,
            WITNESS_ENVELOPE_LEN + factory_reduced_splice_witness_len(2)
        );

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn rejects_factory_reduced_splice_sibling_mismatch() {
        let mut package =
            fixture_factory_reduced_splice_package_with_kind(FixtureFactorySpliceKind::CkbSpliceIn)
                .unwrap();
        package.merkle_update_package.proof_siblings[0].hash = hex_prefixed(&[8u8; 32]);
        package.merkle_update_package.non_interference_digest =
            package.merkle_update_package.compute_digest().unwrap();

        let err = package.validate().unwrap_err();
        assert!(
            err.to_string()
                .contains("factory Merkle update proof failed")
        );
    }

    #[test]
    fn rejects_factory_reduced_splice_missing_authorised_signature() {
        let mut package =
            fixture_factory_reduced_splice_package_with_kind(FixtureFactorySpliceKind::CkbSpliceIn)
                .unwrap();
        package.signatures.clear();

        let err = package.validate().unwrap_err();
        assert!(
            err.to_string()
                .contains("signatures must cover exactly the authorised participants")
        );
    }

    fn assert_factory_splice_contract_witness(
        package: &StoredFactorySplicePackage,
        summary: &FactorySplicePackageSummary,
    ) {
        assert_eq!(
            summary.contract_witness_len,
            WITNESS_ENVELOPE_LEN + factory_splice_witness_len(2)
        );
        let summary_bytes = decode_hex_exact(
            &summary.contract_witness_hex,
            WITNESS_ENVELOPE_LEN + factory_splice_witness_len(2),
            "contract_witness_hex",
        )
        .unwrap();
        assert_eq!(summary_bytes, package.contract_witness_bytes().unwrap());

        let envelope = WitnessEnvelope::parse(&summary_bytes).unwrap();
        assert_eq!(envelope.kind(), WITNESS_ENVELOPE_KIND_FACTORY_SPLICE);
        let parsed = WireFactorySpliceWitness::parse(envelope.body()).unwrap();
        let header = parsed.header().unwrap();
        let signature = parsed.factory_signature().unwrap();
        let old_vault = parsed.old_vault().unwrap();
        let new_vault = parsed.new_vault().unwrap();
        let deltas = parsed.deltas().unwrap();

        assert_eq!(
            header.signing_digest(),
            hex32_bytes(&summary.signing_digest).unwrap()
        );
        assert_eq!(
            header.vault_delta_commitment(),
            hex32_bytes(&summary.vault_delta_commitment)
                .unwrap()
                .as_slice()
        );
        assert_eq!(
            old_vault.factory_id(),
            hex32_bytes(&summary.factory_id).unwrap().as_slice()
        );
        assert_eq!(
            new_vault.factory_id(),
            hex32_bytes(&summary.factory_id).unwrap().as_slice()
        );
        assert_eq!(deltas.delta_count(), package.vault_deltas.len() as u16);
        morph_script_common::verify_factory_splice_signatures(&header, &signature).unwrap();
    }

    fn assert_factory_reduced_splice_contract_witness(
        package: &StoredFactoryReducedSplicePackage,
        summary: &FactoryReducedSplicePackageSummary,
    ) {
        assert_eq!(
            summary.contract_witness_len,
            WITNESS_ENVELOPE_LEN + factory_reduced_splice_witness_len(2)
        );
        let summary_bytes = decode_hex_exact(
            &summary.contract_witness_hex,
            WITNESS_ENVELOPE_LEN + factory_reduced_splice_witness_len(2),
            "contract_witness_hex",
        )
        .unwrap();
        let transition = package.validate().unwrap();
        assert_eq!(
            summary_bytes,
            contract_reduced_splice_witness_bytes_from_transition(&transition).unwrap()
        );

        let envelope = WitnessEnvelope::parse(&summary_bytes).unwrap();
        assert_eq!(
            envelope.kind(),
            WITNESS_ENVELOPE_KIND_FACTORY_REDUCED_SPLICE
        );
        let parsed = WireFactoryReducedSpliceWitness::parse(envelope.body()).unwrap();
        let header = parsed.header().unwrap();
        let merkle_update = parsed.merkle_update().unwrap();
        let old_vault = parsed.old_vault().unwrap();
        let new_vault = parsed.new_vault().unwrap();
        let deltas = parsed.deltas().unwrap();

        assert_eq!(
            header.signing_digest(),
            hex32_bytes(&summary.signing_digest).unwrap()
        );
        assert_eq!(merkle_update.sibling_hash(255).len(), BYTE32_LEN);
        assert_eq!(
            old_vault.factory_id(),
            hex32_bytes(&summary.factory_id).unwrap().as_slice()
        );
        assert_eq!(
            new_vault.factory_id(),
            hex32_bytes(&summary.factory_id).unwrap().as_slice()
        );
        assert_eq!(deltas.delta_count(), package.vault_deltas.len() as u16);

        let factory_participants = reduced_splice_factory_participants_commitment(package);
        let old_header_raw = factory_state_header_wire_bytes_for_test(
            &hex32_bytes(&summary.factory_id).unwrap(),
            summary.old_update_number,
            &hex32_bytes(&summary.old_state_root).unwrap(),
            &factory_participants,
            &hex32_bytes(&summary.old_access_manifest_root).unwrap(),
            &[0u8; 32],
            &hex32_bytes(&package.old_vault_materialisation_root).unwrap(),
            &hex32_bytes(&package.old_vault_outpoint_commitment).unwrap(),
        );
        let new_header_raw = factory_state_header_wire_bytes_for_test(
            &hex32_bytes(&summary.factory_id).unwrap(),
            summary.new_update_number,
            &hex32_bytes(&summary.new_state_root).unwrap(),
            &factory_participants,
            &hex32_bytes(&summary.new_access_manifest_root).unwrap(),
            &hex32_bytes(&summary.non_interference_digest).unwrap(),
            &hex32_bytes(&package.new_vault_materialisation_root).unwrap(),
            &hex32_bytes(&package.new_vault_outpoint_commitment).unwrap(),
        );
        let old_header = morph_script_common::FactoryStateHeader::parse(&old_header_raw).unwrap();
        let new_header = morph_script_common::FactoryStateHeader::parse(&new_header_raw).unwrap();
        morph_script_common::verify_factory_reduced_splice_update(
            &old_header,
            &new_header,
            &parsed,
        )
        .unwrap();
    }

    fn reduced_splice_factory_participants_commitment(
        package: &StoredFactoryReducedSplicePackage,
    ) -> Bytes32 {
        assert_eq!(package.participant_keys.len(), 2);
        let participant_0 = hex32_bytes(&package.participant_keys[0].participant).unwrap();
        let participant_1 = hex32_bytes(&package.participant_keys[1].participant).unwrap();
        let pubkey_0 =
            decode_hex_exact(&package.participant_keys[0].pubkey_sec1, 33, "pubkey_sec1").unwrap();
        let pubkey_1 =
            decode_hex_exact(&package.participant_keys[1].pubkey_sec1, 33, "pubkey_sec1").unwrap();
        morph_script_common::factory_participants_commitment(
            package.signature_threshold,
            &[
                (participant_0.as_slice(), pubkey_0.as_slice()),
                (participant_1.as_slice(), pubkey_1.as_slice()),
            ],
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn factory_state_header_wire_bytes_for_test(
        factory_id: &Bytes32,
        update_number: u64,
        state_root: &Bytes32,
        participants_commitment: &Bytes32,
        access_manifest_root: &Bytes32,
        non_interference_digest: &Bytes32,
        vault_materialisation_root: &Bytes32,
        vault_outpoint_commitment: &Bytes32,
    ) -> [u8; morph_script_common::FACTORY_STATE_HEADER_LEN] {
        let mut raw = [0u8; morph_script_common::FACTORY_STATE_HEADER_LEN];
        put_u16(&mut raw, 0, 1);
        raw[2..34].fill(2);
        put_u16(
            &mut raw,
            34,
            morph_script_common::SIGNATURE_SCHEME_SECP256K1_ECDSA_BLAKE2B,
        );
        raw[36..68].copy_from_slice(factory_id);
        put_u64(&mut raw, 68, update_number);
        raw[76..108].copy_from_slice(state_root);
        raw[108..140].copy_from_slice(participants_commitment);
        raw[140..172].copy_from_slice(access_manifest_root);
        raw[172..204].copy_from_slice(non_interference_digest);
        raw[204..236].fill(8);
        put_u16(&mut raw, 236, 1);
        raw[238..270].copy_from_slice(vault_materialisation_root);
        raw[270..302].copy_from_slice(vault_outpoint_commitment);
        raw
    }

    #[test]
    fn rejects_factory_splice_vault_delta_mismatch() {
        let mut package =
            fixture_factory_splice_package_with_kind(FixtureFactorySpliceKind::CkbSpliceIn)
                .unwrap();
        package.vault_deltas[0].new_amount -= 1;
        package.vault_delta_commitment = hex_prefixed(&factory_vault_delta_commitment(
            &package
                .vault_deltas
                .iter()
                .map(StoredFactoryVaultDelta::to_delta)
                .collect::<Result<Vec<_>>>()
                .unwrap(),
        ));
        package.signing_digest = hex_prefixed(&package.header().unwrap().signing_digest());
        let digest = hex32_bytes(&package.signing_digest).unwrap();
        for signature in &mut package.signatures {
            let key = if signature.participant == hex_prefixed(&bytes32(1)) {
                SigningKey::from_slice(&[1u8; 32]).unwrap()
            } else {
                SigningKey::from_slice(&[2u8; 32]).unwrap()
            };
            *signature = sign_factory_digest(
                &signature.participant,
                &signature.pubkey_sec1,
                &key,
                &digest,
            )
            .unwrap();
        }

        let err = package.validate().unwrap_err();
        assert!(
            err.to_string()
                .contains("factory splice transition check failed")
        );
    }

    #[test]
    fn rejects_factory_merkle_update_digest_mismatch() {
        let mut package = fixture_merkle_update_package().unwrap();
        package.non_interference_digest = hex_prefixed(&[9u8; 32]);

        let err = package.validate().unwrap_err();
        assert!(err.to_string().contains("digest mismatch"));
    }

    #[test]
    fn rejects_factory_merkle_update_sibling_mismatch() {
        let mut package = fixture_merkle_update_package().unwrap();
        package.proof_siblings[0].hash = hex_prefixed(&[8u8; 32]);
        package.non_interference_digest = package.compute_digest().unwrap();

        let err = package.validate().unwrap_err();
        assert!(err.to_string().contains("Merkle update proof failed"));
    }

    #[test]
    fn rejects_reduced_factory_exit_release_mismatch() {
        let mut package = fixture_reduced_exit_package().unwrap();
        package.release_quantity = 19;

        let err = package.validate().unwrap_err();
        assert!(err.to_string().contains("reduced-exit check failed"));
    }

    #[test]
    fn rejects_reduced_factory_exit_extra_authorised_participant() {
        let mut package = fixture_reduced_exit_package().unwrap();
        package
            .update_package
            .authorised_participants
            .push(hex_prefixed(&bytes32(2)));
        package.update_package.authorised_participants.sort();
        package.update_package.non_interference_digest =
            package.update_package.compute_digest().unwrap();

        let err = package.validate().unwrap_err();
        assert!(err.to_string().contains("reduced-exit check failed"));
    }

    #[test]
    fn rejects_missing_factory_state_signature() {
        let mut package = fixture_state_package().unwrap();
        package.signatures.pop();

        let err = package.validate().unwrap_err();
        assert!(err.to_string().contains("one signature per participant"));
    }

    #[test]
    fn rejects_factory_state_missing_participant_key() {
        let mut package = fixture_state_package().unwrap();
        package.participant_keys.pop();
        package.signature_threshold = package.participant_keys.len() as u8;
        package.factory_state_digest = package.compute_digest().unwrap();

        let err = package.validate().unwrap_err();
        assert!(err.to_string().contains("cover every participant"));
    }

    #[test]
    fn rejects_invalid_factory_state_signature() {
        let mut package = fixture_state_package().unwrap();
        let mut bytes =
            decode_hex_exact(&package.signatures[0].signature, 64, "signature").unwrap();
        bytes[0] ^= 1;
        package.signatures[0].signature = hex_prefixed(&bytes);

        let err = package.validate().unwrap_err();
        assert!(err.to_string().contains("signature is invalid"));
    }

    #[test]
    fn rejects_non_all_participant_factory_threshold() {
        let mut package = fixture_state_package().unwrap();
        package.signature_threshold = 1;
        package.factory_state_digest = package.compute_digest().unwrap();

        let err = package.validate().unwrap_err();
        assert!(
            err.to_string()
                .contains("threshold must equal participant key count")
        );
    }

    #[test]
    fn rejects_reduced_factory_state_missing_authorised_signature() {
        let mut package = fixture_reduced_state_package().unwrap();
        package.participant_keys.clear();
        package.signatures.clear();
        package.signature_threshold = 0;
        package.factory_state_digest = package.compute_digest().unwrap();

        let err = package.validate().unwrap_err();
        assert!(err.to_string().contains("at least one participant"));
    }

    #[test]
    fn rejects_reduced_factory_state_extra_participant() {
        let mut package = fixture_reduced_state_package().unwrap();
        let bob = SigningKey::from_slice(&[2u8; 32]).unwrap();
        let digest = hex32_bytes(&package.factory_state_digest).unwrap();
        package.participant_keys.push(StoredFactoryParticipantKey {
            participant: hex_prefixed(&bytes32(2)),
            pubkey_sec1: pubkey_hex(&bob),
        });
        package.signatures.push(
            sign_factory_digest(&hex_prefixed(&bytes32(2)), &pubkey_hex(&bob), &bob, &digest)
                .unwrap(),
        );
        package.signature_threshold = 2;

        let err = package.validate().unwrap_err();
        assert!(err.to_string().contains("cover every participant"));
    }
}
