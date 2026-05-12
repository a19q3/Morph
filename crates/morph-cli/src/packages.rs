use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, anyhow, ensure};
use morph_script_common::{
    BILATERAL_CKB_DESCRIPTOR_V1_LEN, BILATERAL_CKB_DESCRIPTOR_VERSION_V1,
    BILATERAL_CKB_XUDT_DESCRIPTOR_V1_LEN, BILATERAL_CKB_XUDT_DESCRIPTOR_VERSION_V1,
    BILATERAL_SIGNATURE_COUNT_V1, BILATERAL_SIGNATURE_THRESHOLD_V1,
    BILATERAL_SIGNATURE_WITNESS_V1_LEN, BILATERAL_SIGNATURE_WITNESS_VERSION_V1, BYTE32_LEN,
    BilateralSignatureWitnessV1, COMPRESSED_SECP256K1_PUBKEY_LEN, ECDSA_SIGNATURE_LEN,
    FACTORY_LOCAL_EXIT_WITNESS_VERSION_V1, FACTORY_MERKLE_UPDATE_WITNESS_V1_LEN,
    FACTORY_REDUCED_RIGHTS_AUTHORISED_COUNT_V1, FACTORY_REDUCED_RIGHTS_COUNT_V1,
    FACTORY_REDUCED_RIGHTS_PARTICIPANT_COUNT_V1, FACTORY_REDUCED_RIGHTS_PARTICIPANT_ENTRY_V1_LEN,
    FACTORY_REDUCED_RIGHTS_PARTICIPANT_THRESHOLD_V1, FACTORY_REDUCED_RIGHTS_WITNESS_V1_LEN,
    FACTORY_REDUCED_RIGHTS_WITNESS_VERSION_V1, FACTORY_RIGHT_V1_LEN, FACTORY_SIGNATURE_COUNT_V1,
    FACTORY_SIGNATURE_THRESHOLD_V1, FACTORY_SIGNATURE_WITNESS_V1_LEN,
    FACTORY_SIGNATURE_WITNESS_VERSION_V1, FACTORY_STATE_HEADER_V1_LEN, FactoryLocalExitWitnessV1,
    FactoryMerkleUpdateWitnessV1, FactoryReducedRightsWitnessV1, FactorySignatureWitnessV1,
    FactoryStateHeaderV1, PHASE_ACTIVE, PHASE_SETTLING,
    SIGNATURE_SCHEME_SECP256K1_ECDSA_BLAKE2B_V1, STATE_HEADER_V1_LEN, StateHeaderV1,
    blake2b256 as script_blake2b256, factory_local_exit_digest_v1,
    factory_participants_commitment_v1, participants_commitment_v1,
    settlement_descriptor_commitment_v1, verify_bilateral_state_signatures,
    verify_factory_merkle_update, verify_factory_state_signatures,
    verify_reduced_factory_rights_update,
};
#[cfg(test)]
use morph_script_common::{
    FACTORY_MERKLE_UPDATE_RIGHT_COUNT_V1, FACTORY_MERKLE_UPDATE_WITNESS_VERSION_V1,
};
use serde::{Deserialize, Serialize};

const PACKAGE_SCHEMA: &str = "morph.state_package.v1";
const FACTORY_STATE_CELL_PACKAGE_SCHEMA: &str = "morph.factory_state_cell_package.v1";
const FACTORY_REDUCED_RIGHTS_PACKAGE_SCHEMA: &str = "morph.factory_reduced_rights_package.v1";
const FACTORY_MERKLE_UPDATE_STATE_PACKAGE_SCHEMA: &str =
    "morph.factory_merkle_update_state_package.v1";
const FACTORY_LOCAL_EXIT_PACKAGE_SCHEMA: &str = "morph.factory_local_exit_package.v1";
const WATCH_CURSOR_SCHEMA: &str = "morph.watch_cursor.v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackageOutPoint {
    pub tx_hash: String,
    pub index: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredStatePackage {
    pub schema: String,
    pub created_unix_ms: u64,
    pub channel_id: String,
    pub funding_anchor: String,
    pub state_number: u64,
    pub phase: String,
    pub signing_digest: String,
    pub header_hex: String,
    pub witness_hex: String,
    pub source_state_out_point: Option<PackageOutPoint>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StatePackageRecord {
    pub path: PathBuf,
    pub package: StoredStatePackage,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredFactoryStateCellPackage {
    pub schema: String,
    pub created_unix_ms: u64,
    pub factory_id: String,
    pub update_number: u64,
    pub signing_digest: String,
    pub state_root: String,
    pub access_manifest_root: String,
    pub non_interference_digest: String,
    pub header_hex: String,
    pub witness_hex: String,
    pub source_factory_out_point: Option<PackageOutPoint>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FactoryStateCellPackageRecord {
    pub path: PathBuf,
    pub package: StoredFactoryStateCellPackage,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredFactoryReducedRightsPackage {
    pub schema: String,
    pub created_unix_ms: u64,
    pub factory_id: String,
    pub old_update_number: u64,
    pub new_update_number: u64,
    pub signing_digest: String,
    pub old_state_root: String,
    pub new_state_root: String,
    pub old_access_manifest_root: String,
    pub new_access_manifest_root: String,
    pub non_interference_digest: String,
    pub old_header_hex: String,
    pub new_header_hex: String,
    pub witness_hex: String,
    pub source_factory_out_point: Option<PackageOutPoint>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredFactoryMerkleUpdateStatePackage {
    pub schema: String,
    pub created_unix_ms: u64,
    pub factory_id: String,
    pub old_update_number: u64,
    pub new_update_number: u64,
    pub signing_digest: String,
    pub old_state_root: String,
    pub new_state_root: String,
    pub old_access_manifest_root: String,
    pub new_access_manifest_root: String,
    pub non_interference_digest: String,
    pub changed_participant: String,
    pub quantity_before: u128,
    pub quantity_after: u128,
    pub proof_siblings: usize,
    pub witness_len: usize,
    pub old_header_hex: String,
    pub new_header_hex: String,
    pub witness_hex: String,
    pub source_factory_out_point: Option<PackageOutPoint>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FactoryReducedRightsPackageSummary {
    pub factory_id: String,
    pub old_update_number: u64,
    pub new_update_number: u64,
    pub signing_digest: String,
    pub old_state_root: String,
    pub new_state_root: String,
    pub old_access_manifest_root: String,
    pub new_access_manifest_root: String,
    pub non_interference_digest: String,
    pub witness_len: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FactoryMerkleUpdateStatePackageSummary {
    pub factory_id: String,
    pub old_update_number: u64,
    pub new_update_number: u64,
    pub signing_digest: String,
    pub old_state_root: String,
    pub new_state_root: String,
    pub old_access_manifest_root: String,
    pub new_access_manifest_root: String,
    pub non_interference_digest: String,
    pub changed_participant: String,
    pub quantity_before: u128,
    pub quantity_after: u128,
    pub proof_siblings: usize,
    pub witness_len: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum FactoryStateCellUpdatePackage {
    Full(StoredFactoryStateCellPackage),
    ReducedRights(StoredFactoryReducedRightsPackage),
    MerkleUpdate(StoredFactoryMerkleUpdateStatePackage),
}

impl FactoryStateCellUpdatePackage {
    pub fn new_header_bytes(&self) -> Result<Vec<u8>> {
        match self {
            Self::Full(package) => package.header_bytes(),
            Self::ReducedRights(package) => package.new_header_bytes(),
            Self::MerkleUpdate(package) => package.new_header_bytes(),
        }
    }

    pub fn witness_bytes(&self) -> Result<Vec<u8>> {
        match self {
            Self::Full(package) => package.witness_bytes(),
            Self::ReducedRights(package) => package.witness_bytes(),
            Self::MerkleUpdate(package) => package.witness_bytes(),
        }
    }

    pub fn factory_id(&self) -> &str {
        match self {
            Self::Full(package) => &package.factory_id,
            Self::ReducedRights(package) => &package.factory_id,
            Self::MerkleUpdate(package) => &package.factory_id,
        }
    }

    pub fn update_number(&self) -> u64 {
        match self {
            Self::Full(package) => package.update_number,
            Self::ReducedRights(package) => package.new_update_number,
            Self::MerkleUpdate(package) => package.new_update_number,
        }
    }

    pub fn state_root(&self) -> &str {
        match self {
            Self::Full(package) => &package.state_root,
            Self::ReducedRights(package) => &package.new_state_root,
            Self::MerkleUpdate(package) => &package.new_state_root,
        }
    }

    pub fn access_manifest_root(&self) -> &str {
        match self {
            Self::Full(package) => &package.access_manifest_root,
            Self::ReducedRights(package) => &package.new_access_manifest_root,
            Self::MerkleUpdate(package) => &package.new_access_manifest_root,
        }
    }

    pub fn non_interference_digest(&self) -> &str {
        match self {
            Self::Full(package) => &package.non_interference_digest,
            Self::ReducedRights(package) => &package.non_interference_digest,
            Self::MerkleUpdate(package) => &package.non_interference_digest,
        }
    }

    pub fn validate_against_current_header(
        &self,
        current_header: &FactoryStateHeaderV1<'_>,
    ) -> Result<()> {
        match self {
            Self::Full(_) => Ok(()),
            Self::ReducedRights(package) => package.validate_against_current_header(current_header),
            Self::MerkleUpdate(package) => package.validate_against_current_header(current_header),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredFactoryLocalExitPackage {
    pub schema: String,
    pub created_unix_ms: u64,
    pub factory_id: String,
    pub update_number: u64,
    pub factory_signing_digest: String,
    pub exit_digest: String,
    pub child_channel_id: String,
    pub child_funding_anchor: String,
    pub child_state_number: u64,
    pub child_phase: String,
    pub descriptor_version: u16,
    pub descriptor_commitment: String,
    pub state_output_index: u32,
    pub vault_output_index: u32,
    pub state_type_hash: String,
    pub state_lock_hash: String,
    pub vault_lock_hash: String,
    pub factory_header_hex: String,
    pub local_exit_witness_hex: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FactoryLocalExitPackageSummary {
    pub factory_id: String,
    pub update_number: u64,
    pub factory_signing_digest: String,
    pub exit_digest: String,
    pub child_channel_id: String,
    pub child_state_number: u64,
    pub child_phase: String,
    pub descriptor_version: u16,
    pub state_output_index: u32,
    pub vault_output_index: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WatchCursor {
    pub schema: String,
    pub channel_id: String,
    pub next_block: u64,
    pub scanned_to_block: u64,
    pub updated_unix_ms: u64,
}

impl StoredStatePackage {
    pub fn from_signed_state(
        header_bytes: &[u8],
        witness_bytes: &[u8],
        source_state_out_point: Option<PackageOutPoint>,
    ) -> Result<Self> {
        let header = parse_header(header_bytes)?;
        let witness = parse_witness(witness_bytes)?;
        ensure!(
            header.phase() == PHASE_SETTLING,
            "state package must contain a settling state header"
        );
        verify_bilateral_state_signatures(&header, &witness)
            .map_err(|err| anyhow!("state package signatures are invalid: {err:?}"))?;

        let package = Self {
            schema: PACKAGE_SCHEMA.to_string(),
            created_unix_ms: now_unix_ms()?,
            channel_id: hex_prefixed(header.channel_id()),
            funding_anchor: hex_prefixed(header.funding_anchor()),
            state_number: header.state_number(),
            phase: "settling".to_string(),
            signing_digest: hex_prefixed(&header.signing_digest()),
            header_hex: hex_prefixed(header_bytes),
            witness_hex: hex_prefixed(witness_bytes),
            source_state_out_point,
        };
        package.validate()?;
        Ok(package)
    }

    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.schema == PACKAGE_SCHEMA,
            "unsupported state package schema {}",
            self.schema
        );

        let header_bytes = self.header_bytes()?;
        let witness_bytes = self.witness_bytes()?;
        let header = parse_header(&header_bytes)?;
        let witness = parse_witness(&witness_bytes)?;
        ensure!(
            header.signature_scheme_id() == SIGNATURE_SCHEME_SECP256K1_ECDSA_BLAKE2B_V1,
            "unsupported signature scheme {}",
            header.signature_scheme_id()
        );
        ensure!(
            header.phase() == PHASE_SETTLING,
            "state package must contain a settling state header"
        );
        verify_bilateral_state_signatures(&header, &witness)
            .map_err(|err| anyhow!("state package signatures are invalid: {err:?}"))?;

        ensure!(
            self.channel_id == hex_prefixed(header.channel_id()),
            "state package channel_id does not match header"
        );
        ensure!(
            self.funding_anchor == hex_prefixed(header.funding_anchor()),
            "state package funding_anchor does not match header"
        );
        ensure!(
            self.state_number == header.state_number(),
            "state package state_number does not match header"
        );
        ensure!(
            self.phase == "settling",
            "state package phase metadata must be settling"
        );
        ensure!(
            self.signing_digest == hex_prefixed(&header.signing_digest()),
            "state package signing_digest does not match header"
        );
        Ok(())
    }

    pub fn header_bytes(&self) -> Result<Vec<u8>> {
        decode_hex_exact(&self.header_hex, STATE_HEADER_V1_LEN, "header_hex")
    }

    pub fn witness_bytes(&self) -> Result<Vec<u8>> {
        decode_hex_exact(
            &self.witness_hex,
            BILATERAL_SIGNATURE_WITNESS_V1_LEN,
            "witness_hex",
        )
    }

    pub fn file_name(&self) -> String {
        let channel = self.channel_id.trim_start_matches("0x");
        let digest = self.signing_digest.trim_start_matches("0x");
        format!(
            "state-{channel}-{:020}-{}.json",
            self.state_number,
            &digest[0..16]
        )
    }
}

impl WatchCursor {
    pub fn new(channel_id: &str, next_block: u64, scanned_to_block: u64) -> Result<Self> {
        let cursor = Self {
            schema: WATCH_CURSOR_SCHEMA.to_string(),
            channel_id: canonical_hex32(channel_id)?,
            next_block,
            scanned_to_block,
            updated_unix_ms: now_unix_ms()?,
        };
        cursor.validate()?;
        Ok(cursor)
    }

    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.schema == WATCH_CURSOR_SCHEMA,
            "unsupported watch cursor schema {}",
            self.schema
        );
        let canonical_channel_id = canonical_hex32(&self.channel_id)?;
        ensure!(
            self.channel_id == canonical_channel_id,
            "watch cursor channel_id must be canonical"
        );
        ensure!(
            self.scanned_to_block < self.next_block
                || self.scanned_to_block == 0
                || self.next_block == 0,
            "watch cursor next_block must advance past scanned_to_block"
        );
        Ok(())
    }
}

impl StoredFactoryStateCellPackage {
    pub fn from_signed_factory_state(
        header_bytes: &[u8],
        witness_bytes: &[u8],
        source_factory_out_point: Option<PackageOutPoint>,
    ) -> Result<Self> {
        let header = parse_factory_header(header_bytes)?;
        let witness = parse_factory_witness(witness_bytes)?;
        verify_factory_state_signatures(&header, &witness)
            .map_err(|err| anyhow!("factory state package signatures are invalid: {err:?}"))?;

        let package = Self {
            schema: FACTORY_STATE_CELL_PACKAGE_SCHEMA.to_string(),
            created_unix_ms: now_unix_ms()?,
            factory_id: hex_prefixed(header.factory_id()),
            update_number: header.update_number(),
            signing_digest: hex_prefixed(&header.signing_digest()),
            state_root: hex_prefixed(header.state_root()),
            access_manifest_root: hex_prefixed(header.access_manifest_root()),
            non_interference_digest: hex_prefixed(header.non_interference_digest()),
            header_hex: hex_prefixed(header_bytes),
            witness_hex: hex_prefixed(witness_bytes),
            source_factory_out_point,
        };
        package.validate()?;
        Ok(package)
    }

    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.schema == FACTORY_STATE_CELL_PACKAGE_SCHEMA,
            "unsupported factory state cell package schema {}",
            self.schema
        );

        let header_bytes = self.header_bytes()?;
        let witness_bytes = self.witness_bytes()?;
        let header = parse_factory_header(&header_bytes)?;
        let witness = parse_factory_witness(&witness_bytes)?;
        ensure!(
            header.signature_scheme_id() == SIGNATURE_SCHEME_SECP256K1_ECDSA_BLAKE2B_V1,
            "unsupported factory signature scheme {}",
            header.signature_scheme_id()
        );
        verify_factory_state_signatures(&header, &witness)
            .map_err(|err| anyhow!("factory state package signatures are invalid: {err:?}"))?;

        ensure!(
            self.factory_id == hex_prefixed(header.factory_id()),
            "factory state package factory_id does not match header"
        );
        ensure!(
            self.update_number == header.update_number(),
            "factory state package update_number does not match header"
        );
        ensure!(
            self.signing_digest == hex_prefixed(&header.signing_digest()),
            "factory state package signing_digest does not match header"
        );
        ensure!(
            self.state_root == hex_prefixed(header.state_root()),
            "factory state package state_root does not match header"
        );
        ensure!(
            self.access_manifest_root == hex_prefixed(header.access_manifest_root()),
            "factory state package access_manifest_root does not match header"
        );
        ensure!(
            self.non_interference_digest == hex_prefixed(header.non_interference_digest()),
            "factory state package non_interference_digest does not match header"
        );
        Ok(())
    }

    pub fn header_bytes(&self) -> Result<Vec<u8>> {
        decode_hex_exact(&self.header_hex, FACTORY_STATE_HEADER_V1_LEN, "header_hex")
    }

    pub fn witness_bytes(&self) -> Result<Vec<u8>> {
        decode_hex_exact(
            &self.witness_hex,
            FACTORY_SIGNATURE_WITNESS_V1_LEN,
            "witness_hex",
        )
    }

    pub fn file_name(&self) -> String {
        let factory = self.factory_id.trim_start_matches("0x");
        let digest = self.signing_digest.trim_start_matches("0x");
        format!(
            "factory-state-cell-{factory}-{:020}-{}.json",
            self.update_number,
            &digest[0..16]
        )
    }
}

impl StoredFactoryReducedRightsPackage {
    pub fn from_reduced_rights_update(
        old_header_bytes: &[u8],
        new_header_bytes: &[u8],
        witness_bytes: &[u8],
        source_factory_out_point: Option<PackageOutPoint>,
    ) -> Result<Self> {
        let old_header = parse_factory_header(old_header_bytes)?;
        let new_header = parse_factory_header(new_header_bytes)?;
        let witness = parse_factory_reduced_rights_witness(witness_bytes)?;
        validate_reduced_rights_pair(&old_header, &new_header, &witness)?;

        let package = Self {
            schema: FACTORY_REDUCED_RIGHTS_PACKAGE_SCHEMA.to_string(),
            created_unix_ms: now_unix_ms()?,
            factory_id: hex_prefixed(new_header.factory_id()),
            old_update_number: old_header.update_number(),
            new_update_number: new_header.update_number(),
            signing_digest: hex_prefixed(&new_header.signing_digest()),
            old_state_root: hex_prefixed(old_header.state_root()),
            new_state_root: hex_prefixed(new_header.state_root()),
            old_access_manifest_root: hex_prefixed(old_header.access_manifest_root()),
            new_access_manifest_root: hex_prefixed(new_header.access_manifest_root()),
            non_interference_digest: hex_prefixed(new_header.non_interference_digest()),
            old_header_hex: hex_prefixed(old_header_bytes),
            new_header_hex: hex_prefixed(new_header_bytes),
            witness_hex: hex_prefixed(witness_bytes),
            source_factory_out_point,
        };
        package.validate()?;
        Ok(package)
    }

    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.schema == FACTORY_REDUCED_RIGHTS_PACKAGE_SCHEMA,
            "unsupported factory reduced-rights package schema {}",
            self.schema
        );

        let old_header_bytes = self.old_header_bytes()?;
        let new_header_bytes = self.new_header_bytes()?;
        let witness_bytes = self.witness_bytes()?;
        let old_header = parse_factory_header(&old_header_bytes)?;
        let new_header = parse_factory_header(&new_header_bytes)?;
        let witness = parse_factory_reduced_rights_witness(&witness_bytes)?;
        validate_reduced_rights_pair(&old_header, &new_header, &witness)?;

        ensure!(
            self.factory_id == hex_prefixed(new_header.factory_id()),
            "factory reduced-rights package factory_id does not match new header"
        );
        ensure!(
            self.old_update_number == old_header.update_number(),
            "factory reduced-rights package old_update_number does not match old header"
        );
        ensure!(
            self.new_update_number == new_header.update_number(),
            "factory reduced-rights package new_update_number does not match new header"
        );
        ensure!(
            self.signing_digest == hex_prefixed(&new_header.signing_digest()),
            "factory reduced-rights package signing_digest does not match new header"
        );
        ensure!(
            self.old_state_root == hex_prefixed(old_header.state_root()),
            "factory reduced-rights package old_state_root does not match old header"
        );
        ensure!(
            self.new_state_root == hex_prefixed(new_header.state_root()),
            "factory reduced-rights package new_state_root does not match new header"
        );
        ensure!(
            self.old_access_manifest_root == hex_prefixed(old_header.access_manifest_root()),
            "factory reduced-rights package old_access_manifest_root does not match old header"
        );
        ensure!(
            self.new_access_manifest_root == hex_prefixed(new_header.access_manifest_root()),
            "factory reduced-rights package new_access_manifest_root does not match new header"
        );
        ensure!(
            self.non_interference_digest == hex_prefixed(new_header.non_interference_digest()),
            "factory reduced-rights package non_interference_digest does not match new header"
        );
        Ok(())
    }

    pub fn validate_against_current_header(
        &self,
        current_header: &FactoryStateHeaderV1<'_>,
    ) -> Result<()> {
        self.validate()?;
        let old_header_bytes = self.old_header_bytes()?;
        let old_header = parse_factory_header(&old_header_bytes)?;
        ensure!(
            factory_headers_equal(&old_header, current_header),
            "factory reduced-rights package old header does not match the current FactoryStateCell"
        );
        Ok(())
    }

    pub fn summary(&self) -> Result<FactoryReducedRightsPackageSummary> {
        self.validate()?;
        Ok(FactoryReducedRightsPackageSummary {
            factory_id: self.factory_id.clone(),
            old_update_number: self.old_update_number,
            new_update_number: self.new_update_number,
            signing_digest: self.signing_digest.clone(),
            old_state_root: self.old_state_root.clone(),
            new_state_root: self.new_state_root.clone(),
            old_access_manifest_root: self.old_access_manifest_root.clone(),
            new_access_manifest_root: self.new_access_manifest_root.clone(),
            non_interference_digest: self.non_interference_digest.clone(),
            witness_len: self.witness_bytes()?.len(),
        })
    }

    pub fn old_header_bytes(&self) -> Result<Vec<u8>> {
        decode_hex_exact(
            &self.old_header_hex,
            FACTORY_STATE_HEADER_V1_LEN,
            "old_header_hex",
        )
    }

    pub fn new_header_bytes(&self) -> Result<Vec<u8>> {
        decode_hex_exact(
            &self.new_header_hex,
            FACTORY_STATE_HEADER_V1_LEN,
            "new_header_hex",
        )
    }

    pub fn witness_bytes(&self) -> Result<Vec<u8>> {
        decode_hex_exact(
            &self.witness_hex,
            FACTORY_REDUCED_RIGHTS_WITNESS_V1_LEN,
            "witness_hex",
        )
    }

    pub fn file_name(&self) -> String {
        let factory = self.factory_id.trim_start_matches("0x");
        let digest = self.signing_digest.trim_start_matches("0x");
        format!(
            "factory-reduced-rights-{factory}-{:020}-{}.json",
            self.new_update_number,
            &digest[0..16]
        )
    }
}

impl StoredFactoryMerkleUpdateStatePackage {
    pub fn from_merkle_update(
        old_header_bytes: &[u8],
        new_header_bytes: &[u8],
        witness_bytes: &[u8],
        source_factory_out_point: Option<PackageOutPoint>,
    ) -> Result<Self> {
        let old_header = parse_factory_header(old_header_bytes)?;
        let new_header = parse_factory_header(new_header_bytes)?;
        let witness = parse_factory_merkle_update_witness(witness_bytes)?;
        validate_merkle_update_pair(&old_header, &new_header, &witness)?;
        let right_before = witness
            .right_before()
            .map_err(|err| anyhow!("factory Merkle package right_before is invalid: {err:?}"))?;
        let right_after = witness
            .right_after()
            .map_err(|err| anyhow!("factory Merkle package right_after is invalid: {err:?}"))?;

        let package = Self {
            schema: FACTORY_MERKLE_UPDATE_STATE_PACKAGE_SCHEMA.to_string(),
            created_unix_ms: now_unix_ms()?,
            factory_id: hex_prefixed(new_header.factory_id()),
            old_update_number: old_header.update_number(),
            new_update_number: new_header.update_number(),
            signing_digest: hex_prefixed(&new_header.signing_digest()),
            old_state_root: hex_prefixed(old_header.state_root()),
            new_state_root: hex_prefixed(new_header.state_root()),
            old_access_manifest_root: hex_prefixed(old_header.access_manifest_root()),
            new_access_manifest_root: hex_prefixed(new_header.access_manifest_root()),
            non_interference_digest: hex_prefixed(new_header.non_interference_digest()),
            changed_participant: hex_prefixed(right_before.participant()),
            quantity_before: right_before.quantity(),
            quantity_after: right_after.quantity(),
            proof_siblings: 256,
            witness_len: witness_bytes.len(),
            old_header_hex: hex_prefixed(old_header_bytes),
            new_header_hex: hex_prefixed(new_header_bytes),
            witness_hex: hex_prefixed(witness_bytes),
            source_factory_out_point,
        };
        package.validate()?;
        Ok(package)
    }

    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.schema == FACTORY_MERKLE_UPDATE_STATE_PACKAGE_SCHEMA,
            "unsupported factory Merkle update package schema {}",
            self.schema
        );

        let old_header_bytes = self.old_header_bytes()?;
        let new_header_bytes = self.new_header_bytes()?;
        let witness_bytes = self.witness_bytes()?;
        let old_header = parse_factory_header(&old_header_bytes)?;
        let new_header = parse_factory_header(&new_header_bytes)?;
        let witness = parse_factory_merkle_update_witness(&witness_bytes)?;
        validate_merkle_update_pair(&old_header, &new_header, &witness)?;
        let right_before = witness
            .right_before()
            .map_err(|err| anyhow!("factory Merkle package right_before is invalid: {err:?}"))?;
        let right_after = witness
            .right_after()
            .map_err(|err| anyhow!("factory Merkle package right_after is invalid: {err:?}"))?;

        ensure!(
            self.factory_id == hex_prefixed(new_header.factory_id()),
            "factory Merkle package factory_id does not match new header"
        );
        ensure!(
            self.old_update_number == old_header.update_number(),
            "factory Merkle package old_update_number does not match old header"
        );
        ensure!(
            self.new_update_number == new_header.update_number(),
            "factory Merkle package new_update_number does not match new header"
        );
        ensure!(
            self.signing_digest == hex_prefixed(&new_header.signing_digest()),
            "factory Merkle package signing_digest does not match new header"
        );
        ensure!(
            self.old_state_root == hex_prefixed(old_header.state_root()),
            "factory Merkle package old_state_root does not match old header"
        );
        ensure!(
            self.new_state_root == hex_prefixed(new_header.state_root()),
            "factory Merkle package new_state_root does not match new header"
        );
        ensure!(
            self.old_access_manifest_root == hex_prefixed(old_header.access_manifest_root()),
            "factory Merkle package old_access_manifest_root does not match old header"
        );
        ensure!(
            self.new_access_manifest_root == hex_prefixed(new_header.access_manifest_root()),
            "factory Merkle package new_access_manifest_root does not match new header"
        );
        ensure!(
            self.non_interference_digest == hex_prefixed(new_header.non_interference_digest()),
            "factory Merkle package non_interference_digest does not match new header"
        );
        ensure!(
            self.changed_participant == hex_prefixed(right_before.participant()),
            "factory Merkle package changed_participant does not match witness"
        );
        ensure!(
            self.quantity_before == right_before.quantity()
                && self.quantity_after == right_after.quantity(),
            "factory Merkle package quantity metadata does not match witness"
        );
        ensure!(
            self.proof_siblings == 256 && self.witness_len == FACTORY_MERKLE_UPDATE_WITNESS_V1_LEN,
            "factory Merkle package proof metadata is invalid"
        );
        Ok(())
    }

    pub fn validate_against_current_header(
        &self,
        current_header: &FactoryStateHeaderV1<'_>,
    ) -> Result<()> {
        self.validate()?;
        let old_header_bytes = self.old_header_bytes()?;
        let old_header = parse_factory_header(&old_header_bytes)?;
        ensure!(
            factory_headers_equal(&old_header, current_header),
            "factory Merkle package old header does not match the current FactoryStateCell"
        );
        Ok(())
    }

    pub fn summary(&self) -> Result<FactoryMerkleUpdateStatePackageSummary> {
        self.validate()?;
        Ok(FactoryMerkleUpdateStatePackageSummary {
            factory_id: self.factory_id.clone(),
            old_update_number: self.old_update_number,
            new_update_number: self.new_update_number,
            signing_digest: self.signing_digest.clone(),
            old_state_root: self.old_state_root.clone(),
            new_state_root: self.new_state_root.clone(),
            old_access_manifest_root: self.old_access_manifest_root.clone(),
            new_access_manifest_root: self.new_access_manifest_root.clone(),
            non_interference_digest: self.non_interference_digest.clone(),
            changed_participant: self.changed_participant.clone(),
            quantity_before: self.quantity_before,
            quantity_after: self.quantity_after,
            proof_siblings: self.proof_siblings,
            witness_len: self.witness_len,
        })
    }

    pub fn old_header_bytes(&self) -> Result<Vec<u8>> {
        decode_hex_exact(
            &self.old_header_hex,
            FACTORY_STATE_HEADER_V1_LEN,
            "old_header_hex",
        )
    }

    pub fn new_header_bytes(&self) -> Result<Vec<u8>> {
        decode_hex_exact(
            &self.new_header_hex,
            FACTORY_STATE_HEADER_V1_LEN,
            "new_header_hex",
        )
    }

    pub fn witness_bytes(&self) -> Result<Vec<u8>> {
        decode_hex_exact(
            &self.witness_hex,
            FACTORY_MERKLE_UPDATE_WITNESS_V1_LEN,
            "witness_hex",
        )
    }

    pub fn file_name(&self) -> String {
        let factory = self.factory_id.trim_start_matches("0x");
        let digest = self.signing_digest.trim_start_matches("0x");
        format!(
            "factory-merkle-update-{factory}-{:020}-{}.json",
            self.new_update_number,
            &digest[0..16]
        )
    }
}

impl StoredFactoryLocalExitPackage {
    pub fn from_factory_local_exit(
        factory_header_bytes: &[u8],
        local_exit_witness_bytes: &[u8],
    ) -> Result<Self> {
        let factory_header = parse_factory_header(factory_header_bytes)?;
        let witness = parse_factory_local_exit_witness(local_exit_witness_bytes)?;
        let exit_state = parse_header(witness.exit_state_header())?;
        validate_factory_local_exit_pair(&factory_header, &witness)?;

        let package = Self {
            schema: FACTORY_LOCAL_EXIT_PACKAGE_SCHEMA.to_string(),
            created_unix_ms: now_unix_ms()?,
            factory_id: hex_prefixed(factory_header.factory_id()),
            update_number: factory_header.update_number(),
            factory_signing_digest: hex_prefixed(&factory_header.signing_digest()),
            exit_digest: hex_prefixed(&witness.exit_digest()),
            child_channel_id: hex_prefixed(exit_state.channel_id()),
            child_funding_anchor: hex_prefixed(exit_state.funding_anchor()),
            child_state_number: exit_state.state_number(),
            child_phase: phase_label(exit_state.phase()).to_string(),
            descriptor_version: exit_state.descriptor_version(),
            descriptor_commitment: hex_prefixed(exit_state.settlement_descriptor_commitment()),
            state_output_index: witness.state_output_index(),
            vault_output_index: witness.vault_output_index(),
            state_type_hash: hex_prefixed(witness.state_type_hash()),
            state_lock_hash: hex_prefixed(witness.state_lock_hash()),
            vault_lock_hash: hex_prefixed(witness.vault_lock_hash()),
            factory_header_hex: hex_prefixed(factory_header_bytes),
            local_exit_witness_hex: hex_prefixed(local_exit_witness_bytes),
        };
        package.validate()?;
        Ok(package)
    }

    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.schema == FACTORY_LOCAL_EXIT_PACKAGE_SCHEMA,
            "unsupported factory local-exit package schema {}",
            self.schema
        );

        let factory_header_bytes = self.factory_header_bytes()?;
        let witness_bytes = self.local_exit_witness_bytes()?;
        let factory_header = parse_factory_header(&factory_header_bytes)?;
        let witness = parse_factory_local_exit_witness(&witness_bytes)?;
        let exit_state = parse_header(witness.exit_state_header())?;
        validate_factory_local_exit_pair(&factory_header, &witness)?;

        ensure!(
            self.factory_id == hex_prefixed(factory_header.factory_id()),
            "factory local-exit package factory_id does not match header"
        );
        ensure!(
            self.update_number == factory_header.update_number(),
            "factory local-exit package update_number does not match header"
        );
        ensure!(
            self.factory_signing_digest == hex_prefixed(&factory_header.signing_digest()),
            "factory local-exit package signing digest does not match header"
        );
        ensure!(
            self.exit_digest == hex_prefixed(&witness.exit_digest()),
            "factory local-exit package exit digest does not match witness"
        );
        ensure!(
            self.child_channel_id == hex_prefixed(exit_state.channel_id()),
            "factory local-exit package child_channel_id does not match exit StateHeader"
        );
        ensure!(
            self.child_funding_anchor == hex_prefixed(exit_state.funding_anchor()),
            "factory local-exit package child_funding_anchor does not match exit StateHeader"
        );
        ensure!(
            self.child_state_number == exit_state.state_number(),
            "factory local-exit package child_state_number does not match exit StateHeader"
        );
        ensure!(
            self.child_phase == phase_label(exit_state.phase()),
            "factory local-exit package child_phase does not match exit StateHeader"
        );
        ensure!(
            self.descriptor_version == exit_state.descriptor_version(),
            "factory local-exit package descriptor_version does not match exit StateHeader"
        );
        ensure!(
            self.descriptor_commitment
                == hex_prefixed(exit_state.settlement_descriptor_commitment()),
            "factory local-exit package descriptor_commitment does not match exit StateHeader"
        );
        ensure!(
            self.state_output_index == witness.state_output_index(),
            "factory local-exit package state_output_index does not match witness"
        );
        ensure!(
            self.vault_output_index == witness.vault_output_index(),
            "factory local-exit package vault_output_index does not match witness"
        );
        ensure!(
            self.state_type_hash == hex_prefixed(witness.state_type_hash()),
            "factory local-exit package state_type_hash does not match witness"
        );
        ensure!(
            self.state_lock_hash == hex_prefixed(witness.state_lock_hash()),
            "factory local-exit package state_lock_hash does not match witness"
        );
        ensure!(
            self.vault_lock_hash == hex_prefixed(witness.vault_lock_hash()),
            "factory local-exit package vault_lock_hash does not match witness"
        );
        Ok(())
    }

    pub fn summary(&self) -> Result<FactoryLocalExitPackageSummary> {
        self.validate()?;
        Ok(FactoryLocalExitPackageSummary {
            factory_id: self.factory_id.clone(),
            update_number: self.update_number,
            factory_signing_digest: self.factory_signing_digest.clone(),
            exit_digest: self.exit_digest.clone(),
            child_channel_id: self.child_channel_id.clone(),
            child_state_number: self.child_state_number,
            child_phase: self.child_phase.clone(),
            descriptor_version: self.descriptor_version,
            state_output_index: self.state_output_index,
            vault_output_index: self.vault_output_index,
        })
    }

    pub fn factory_header_bytes(&self) -> Result<Vec<u8>> {
        decode_hex_exact(
            &self.factory_header_hex,
            FACTORY_STATE_HEADER_V1_LEN,
            "factory_header_hex",
        )
    }

    pub fn local_exit_witness_bytes(&self) -> Result<Vec<u8>> {
        decode_hex(&self.local_exit_witness_hex, "local_exit_witness_hex")
    }
}

pub fn write_package(dir: &Path, package: &StoredStatePackage) -> Result<PathBuf> {
    package.validate()?;
    fs::create_dir_all(dir)
        .with_context(|| format!("failed to create package directory {}", dir.display()))?;
    let path = dir.join(package.file_name());
    let tmp = path.with_extension("json.tmp");
    let json = serde_json::to_vec_pretty(package)?;
    fs::write(&tmp, json)
        .with_context(|| format!("failed to write temporary package {}", tmp.display()))?;
    fs::rename(&tmp, &path).with_context(|| {
        format!(
            "failed to atomically move package {} to {}",
            tmp.display(),
            path.display()
        )
    })?;
    Ok(path)
}

pub fn write_factory_state_cell_package(
    dir: &Path,
    package: &StoredFactoryStateCellPackage,
) -> Result<PathBuf> {
    package.validate()?;
    fs::create_dir_all(dir)
        .with_context(|| format!("failed to create package directory {}", dir.display()))?;
    let path = dir.join(package.file_name());
    let tmp = path.with_extension("json.tmp");
    let json = serde_json::to_vec_pretty(package)?;
    fs::write(&tmp, json)
        .with_context(|| format!("failed to write temporary package {}", tmp.display()))?;
    fs::rename(&tmp, &path).with_context(|| {
        format!(
            "failed to atomically move package {} to {}",
            tmp.display(),
            path.display()
        )
    })?;
    Ok(path)
}

pub fn write_factory_reduced_rights_package(
    dir: &Path,
    package: &StoredFactoryReducedRightsPackage,
) -> Result<PathBuf> {
    package.validate()?;
    fs::create_dir_all(dir)
        .with_context(|| format!("failed to create package directory {}", dir.display()))?;
    let path = dir.join(package.file_name());
    let tmp = path.with_extension("json.tmp");
    let json = serde_json::to_vec_pretty(package)?;
    fs::write(&tmp, json).with_context(|| {
        format!(
            "failed to write temporary reduced-rights package {}",
            tmp.display()
        )
    })?;
    fs::rename(&tmp, &path).with_context(|| {
        format!(
            "failed to atomically move reduced-rights package {} to {}",
            tmp.display(),
            path.display()
        )
    })?;
    Ok(path)
}

pub fn write_factory_merkle_update_package(
    dir: &Path,
    package: &StoredFactoryMerkleUpdateStatePackage,
) -> Result<PathBuf> {
    package.validate()?;
    fs::create_dir_all(dir)
        .with_context(|| format!("failed to create package directory {}", dir.display()))?;
    let path = dir.join(package.file_name());
    let tmp = path.with_extension("json.tmp");
    let json = serde_json::to_vec_pretty(package)?;
    fs::write(&tmp, json).with_context(|| {
        format!(
            "failed to write temporary factory Merkle package {}",
            tmp.display()
        )
    })?;
    fs::rename(&tmp, &path).with_context(|| {
        format!(
            "failed to atomically move factory Merkle package {} to {}",
            tmp.display(),
            path.display()
        )
    })?;
    Ok(path)
}

pub fn default_watch_cursor_path(dir: &Path, channel_id: &str) -> Result<PathBuf> {
    let channel = canonical_hex32(channel_id)?;
    Ok(dir.join(format!(
        "watch-cursor-{}.json",
        channel.trim_start_matches("0x")
    )))
}

pub fn read_watch_cursor(path: &Path) -> Result<Option<WatchCursor>> {
    if !path.exists() {
        return Ok(None);
    }
    let bytes = fs::read(path)
        .with_context(|| format!("failed to read watch cursor {}", path.display()))?;
    let cursor: WatchCursor = serde_json::from_slice(&bytes)
        .with_context(|| format!("failed to parse watch cursor {}", path.display()))?;
    cursor
        .validate()
        .with_context(|| format!("invalid watch cursor {}", path.display()))?;
    Ok(Some(cursor))
}

pub fn write_watch_cursor(path: &Path, cursor: &WatchCursor) -> Result<()> {
    cursor.validate()?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create cursor directory {}", parent.display()))?;
    }
    let tmp = path.with_extension("json.tmp");
    let json = serde_json::to_vec_pretty(cursor)?;
    fs::write(&tmp, json)
        .with_context(|| format!("failed to write temporary watch cursor {}", tmp.display()))?;
    fs::rename(&tmp, path).with_context(|| {
        format!(
            "failed to atomically move watch cursor {} to {}",
            tmp.display(),
            path.display()
        )
    })?;
    Ok(())
}

pub fn read_package(path: &Path) -> Result<StoredStatePackage> {
    let bytes = fs::read(path)
        .with_context(|| format!("failed to read state package {}", path.display()))?;
    let package: StoredStatePackage = serde_json::from_slice(&bytes)
        .with_context(|| format!("failed to parse state package {}", path.display()))?;
    package
        .validate()
        .with_context(|| format!("invalid state package {}", path.display()))?;
    Ok(package)
}

pub fn read_factory_state_cell_package(path: &Path) -> Result<StoredFactoryStateCellPackage> {
    let bytes = fs::read(path)
        .with_context(|| format!("failed to read factory state package {}", path.display()))?;
    let package: StoredFactoryStateCellPackage = serde_json::from_slice(&bytes)
        .with_context(|| format!("failed to parse factory state package {}", path.display()))?;
    package
        .validate()
        .with_context(|| format!("invalid factory state package {}", path.display()))?;
    Ok(package)
}

pub fn read_factory_reduced_rights_package(
    path: &Path,
) -> Result<StoredFactoryReducedRightsPackage> {
    let bytes = fs::read(path).with_context(|| {
        format!(
            "failed to read factory reduced-rights package {}",
            path.display()
        )
    })?;
    let package: StoredFactoryReducedRightsPackage =
        serde_json::from_slice(&bytes).with_context(|| {
            format!(
                "failed to parse factory reduced-rights package {}",
                path.display()
            )
        })?;
    package
        .validate()
        .with_context(|| format!("invalid factory reduced-rights package {}", path.display()))?;
    Ok(package)
}

pub fn read_factory_state_cell_update_package(
    path: &Path,
) -> Result<FactoryStateCellUpdatePackage> {
    let bytes = fs::read(path)
        .with_context(|| format!("failed to read factory update package {}", path.display()))?;
    let value: serde_json::Value = serde_json::from_slice(&bytes)
        .with_context(|| format!("failed to parse factory update package {}", path.display()))?;
    let schema = value
        .get("schema")
        .and_then(|schema| schema.as_str())
        .ok_or_else(|| anyhow!("factory update package {} has no schema", path.display()))?;
    match schema {
        FACTORY_STATE_CELL_PACKAGE_SCHEMA => {
            let package: StoredFactoryStateCellPackage = serde_json::from_value(value)
                .with_context(|| {
                    format!(
                        "failed to parse factory state-cell package {}",
                        path.display()
                    )
                })?;
            package.validate().with_context(|| {
                format!("invalid factory state-cell package {}", path.display())
            })?;
            Ok(FactoryStateCellUpdatePackage::Full(package))
        }
        FACTORY_REDUCED_RIGHTS_PACKAGE_SCHEMA => {
            let package: StoredFactoryReducedRightsPackage = serde_json::from_value(value)
                .with_context(|| {
                    format!(
                        "failed to parse factory reduced-rights package {}",
                        path.display()
                    )
                })?;
            package.validate().with_context(|| {
                format!("invalid factory reduced-rights package {}", path.display())
            })?;
            Ok(FactoryStateCellUpdatePackage::ReducedRights(package))
        }
        FACTORY_MERKLE_UPDATE_STATE_PACKAGE_SCHEMA => {
            let package: StoredFactoryMerkleUpdateStatePackage = serde_json::from_value(value)
                .with_context(|| {
                    format!(
                        "failed to parse factory Merkle update package {}",
                        path.display()
                    )
                })?;
            package.validate().with_context(|| {
                format!("invalid factory Merkle update package {}", path.display())
            })?;
            Ok(FactoryStateCellUpdatePackage::MerkleUpdate(package))
        }
        other => Err(anyhow!(
            "unsupported factory update package schema {other} in {}",
            path.display()
        )),
    }
}

pub fn read_factory_local_exit_package(path: &Path) -> Result<StoredFactoryLocalExitPackage> {
    let bytes = fs::read(path).with_context(|| {
        format!(
            "failed to read factory local-exit package {}",
            path.display()
        )
    })?;
    let package: StoredFactoryLocalExitPackage =
        serde_json::from_slice(&bytes).with_context(|| {
            format!(
                "failed to parse factory local-exit package {}",
                path.display()
            )
        })?;
    package
        .validate()
        .with_context(|| format!("invalid factory local-exit package {}", path.display()))?;
    Ok(package)
}

pub fn reduced_rights_package_from_factory_header(
    old_header_bytes: &[u8],
    alice: &k256::ecdsa::SigningKey,
    bob: &k256::ecdsa::SigningKey,
    new_update_number: Option<u64>,
    touched_after_balance: u128,
    source_factory_out_point: Option<PackageOutPoint>,
) -> Result<StoredFactoryReducedRightsPackage> {
    let old_header = parse_factory_header(old_header_bytes)?;
    let mut witness = reduced_rights_witness_bytes(touched_after_balance, alice, bob)?;
    let parsed_witness = parse_factory_reduced_rights_witness(&witness)?;
    let participant_entries = reduced_participant_entries(alice, bob);
    let participants_commitment = factory_participants_commitment_v1(
        2,
        &[
            (
                participant_entries[0].0.as_slice(),
                participant_entries[0].1.as_slice(),
            ),
            (
                participant_entries[1].0.as_slice(),
                participant_entries[1].1.as_slice(),
            ),
        ],
    );
    ensure!(
        old_header.participants_commitment() == participants_commitment.as_slice(),
        "live factory participant commitment does not match supplied Alice/Bob keys"
    );
    let before_root = parsed_witness
        .rights_root(false)
        .map_err(|err| anyhow!("failed to compute reduced-rights old root: {err:?}"))?;
    ensure!(
        old_header.state_root() == before_root.as_slice(),
        "live factory state_root does not match reduced-rights old root"
    );
    let before_access_root = parsed_witness
        .access_manifest_root(false)
        .map_err(|err| anyhow!("failed to compute reduced-rights old access root: {err:?}"))?;
    ensure!(
        old_header.access_manifest_root() == before_access_root.as_slice(),
        "live factory access_manifest_root does not match reduced-rights old access root"
    );
    let update_number = new_update_number.unwrap_or_else(|| old_header.update_number() + 1);
    ensure!(
        update_number > old_header.update_number(),
        "new update number must be greater than old update number {}",
        old_header.update_number()
    );

    let mut new_header = old_header_bytes.to_vec();
    put_u64(&mut new_header, 68, update_number);
    new_header[76..108].copy_from_slice(
        &parsed_witness
            .rights_root(true)
            .map_err(|err| anyhow!("failed to compute reduced-rights new root: {err:?}"))?,
    );
    new_header[140..172].copy_from_slice(
        &parsed_witness
            .access_manifest_root(true)
            .map_err(|err| anyhow!("failed to compute reduced-rights new access root: {err:?}"))?,
    );
    let preliminary_new = parse_factory_header(&new_header)?;
    let non_interference_digest = parsed_witness
        .non_interference_digest(&old_header, &preliminary_new)
        .map_err(|err| anyhow!("failed to compute reduced-rights digest: {err:?}"))?;
    new_header[172..204].copy_from_slice(&non_interference_digest);
    let new_header_parsed = parse_factory_header(&new_header)?;
    sign_reduced_rights_witness(
        &mut witness,
        [1u8; BYTE32_LEN],
        alice,
        &new_header_parsed.signing_digest(),
    )?;

    StoredFactoryReducedRightsPackage::from_reduced_rights_update(
        old_header_bytes,
        &new_header,
        &witness,
        source_factory_out_point,
    )
}

pub fn fixture_factory_reduced_rights_package() -> Result<StoredFactoryReducedRightsPackage> {
    let alice = k256::ecdsa::SigningKey::from_slice(&[1u8; 32])
        .map_err(|err| anyhow!("invalid fixture Alice key: {err:?}"))?;
    let bob = k256::ecdsa::SigningKey::from_slice(&[2u8; 32])
        .map_err(|err| anyhow!("invalid fixture Bob key: {err:?}"))?;
    let mut witness = reduced_rights_witness_bytes(90, &alice, &bob)?;
    let parsed_witness = parse_factory_reduced_rights_witness(&witness)?;

    let entries = reduced_participant_entries(&alice, &bob);
    let participants_commitment = factory_participants_commitment_v1(
        2,
        &[
            (entries[0].0.as_slice(), entries[0].1.as_slice()),
            (entries[1].0.as_slice(), entries[1].1.as_slice()),
        ],
    );

    let mut old_header = factory_header_fixture(1, [8u8; BYTE32_LEN]);
    old_header[76..108].copy_from_slice(
        &parsed_witness
            .rights_root(false)
            .map_err(|err| anyhow!("failed to compute reduced-rights old root: {err:?}"))?,
    );
    old_header[108..140].copy_from_slice(&participants_commitment);
    old_header[140..172].copy_from_slice(
        &parsed_witness
            .access_manifest_root(false)
            .map_err(|err| anyhow!("failed to compute reduced-rights old access root: {err:?}"))?,
    );
    let old_parsed = parse_factory_header(&old_header)?;

    let mut new_header = factory_header_fixture(2, [8u8; BYTE32_LEN]);
    new_header[76..108].copy_from_slice(
        &parsed_witness
            .rights_root(true)
            .map_err(|err| anyhow!("failed to compute reduced-rights new root: {err:?}"))?,
    );
    new_header[108..140].copy_from_slice(&participants_commitment);
    new_header[140..172].copy_from_slice(
        &parsed_witness
            .access_manifest_root(true)
            .map_err(|err| anyhow!("failed to compute reduced-rights new access root: {err:?}"))?,
    );
    let preliminary_new = parse_factory_header(&new_header)?;
    let non_interference_digest = parsed_witness
        .non_interference_digest(&old_parsed, &preliminary_new)
        .map_err(|err| anyhow!("failed to compute reduced-rights digest: {err:?}"))?;
    new_header[172..204].copy_from_slice(&non_interference_digest);
    let new_parsed = parse_factory_header(&new_header)?;
    sign_reduced_rights_witness(
        &mut witness,
        [1u8; BYTE32_LEN],
        &alice,
        &new_parsed.signing_digest(),
    )?;

    StoredFactoryReducedRightsPackage::from_reduced_rights_update(
        &old_header,
        &new_header,
        &witness,
        None,
    )
}

#[cfg(test)]
pub fn fixture_factory_merkle_update_package() -> Result<StoredFactoryMerkleUpdateStatePackage> {
    let alice = k256::ecdsa::SigningKey::from_slice(&[1u8; 32])
        .map_err(|err| anyhow!("invalid fixture Alice key: {err:?}"))?;
    let bob = k256::ecdsa::SigningKey::from_slice(&[2u8; 32])
        .map_err(|err| anyhow!("invalid fixture Bob key: {err:?}"))?;
    let mut witness = merkle_update_witness_bytes(900, &alice, &bob)?;
    let parsed_witness = parse_factory_merkle_update_witness(&witness)?;

    let entries = reduced_participant_entries(&alice, &bob);
    let participants_commitment = factory_participants_commitment_v1(
        2,
        &[
            (entries[0].0.as_slice(), entries[0].1.as_slice()),
            (entries[1].0.as_slice(), entries[1].1.as_slice()),
        ],
    );
    let access_manifest_root = script_blake2b256(&[b"CKB_MORPH_FACTORY_MERKLE_ACCESS_FIXTURE_V1"]);

    let mut old_header = factory_header_fixture(1, [8u8; BYTE32_LEN]);
    old_header[76..108].copy_from_slice(
        &parsed_witness
            .rights_root(false)
            .map_err(|err| anyhow!("failed to compute Merkle old root: {err:?}"))?,
    );
    old_header[108..140].copy_from_slice(&participants_commitment);
    old_header[140..172].copy_from_slice(&access_manifest_root);
    let old_parsed = parse_factory_header(&old_header)?;

    let mut new_header = factory_header_fixture(2, [8u8; BYTE32_LEN]);
    new_header[76..108].copy_from_slice(
        &parsed_witness
            .rights_root(true)
            .map_err(|err| anyhow!("failed to compute Merkle new root: {err:?}"))?,
    );
    new_header[108..140].copy_from_slice(&participants_commitment);
    new_header[140..172].copy_from_slice(&access_manifest_root);
    let preliminary_new = parse_factory_header(&new_header)?;
    let non_interference_digest = parsed_witness
        .non_interference_digest(&old_parsed, &preliminary_new)
        .map_err(|err| anyhow!("failed to compute Merkle digest: {err:?}"))?;
    new_header[172..204].copy_from_slice(&non_interference_digest);
    let new_parsed = parse_factory_header(&new_header)?;
    sign_merkle_update_witness(
        &mut witness,
        [1u8; BYTE32_LEN],
        &alice,
        &new_parsed.signing_digest(),
    )?;

    StoredFactoryMerkleUpdateStatePackage::from_merkle_update(
        &old_header,
        &new_header,
        &witness,
        None,
    )
}

pub fn fixture_factory_local_exit_package() -> Result<StoredFactoryLocalExitPackage> {
    let alice = k256::ecdsa::SigningKey::from_slice(&[1u8; 32])
        .map_err(|err| anyhow!("invalid fixture Alice key: {err:?}"))?;
    let bob = k256::ecdsa::SigningKey::from_slice(&[2u8; 32])
        .map_err(|err| anyhow!("invalid fixture Bob key: {err:?}"))?;
    let mut factory_entries = [
        ([1u8; BYTE32_LEN], compressed_pubkey(&alice), alice),
        ([2u8; BYTE32_LEN], compressed_pubkey(&bob), bob),
    ];
    factory_entries.sort_by(|left, right| left.0.cmp(&right.0));
    let participant_pubkeys = [
        factory_entries[0].1.as_slice(),
        factory_entries[1].1.as_slice(),
    ];

    let descriptor = bilateral_ckb_descriptor(
        [21u8; BYTE32_LEN],
        6_000_000_000,
        [22u8; BYTE32_LEN],
        4_000_000_000,
    );
    let descriptor_commitment = settlement_descriptor_commitment_v1(&descriptor);
    let child_channel_id = [31u8; BYTE32_LEN];
    let funding_anchor = [32u8; BYTE32_LEN];
    let mut state_header = vec![0u8; STATE_HEADER_V1_LEN];
    put_u16(&mut state_header, 0, 1);
    state_header[2..34].copy_from_slice(&[30u8; BYTE32_LEN]);
    put_u16(
        &mut state_header,
        34,
        SIGNATURE_SCHEME_SECP256K1_ECDSA_BLAKE2B_V1,
    );
    state_header[36..68].copy_from_slice(&child_channel_id);
    state_header[68..100].copy_from_slice(&funding_anchor);
    put_u64(&mut state_header, 100, 0);
    state_header[108] = 0;
    state_header[109] = PHASE_ACTIVE;
    state_header[110..142].copy_from_slice(&participants_commitment_v1(2, &participant_pubkeys));
    state_header[142..174]
        .copy_from_slice(&script_blake2b256(&[b"CKB_MORPH_EMPTY_ASSET_REGISTRY_V1"]));
    state_header[174..206].copy_from_slice(&descriptor_commitment);
    put_u16(&mut state_header, 206, BILATERAL_CKB_DESCRIPTOR_VERSION_V1);
    state_header[208..240].copy_from_slice(&script_blake2b256(&[
        b"CKB_MORPH_EMPTY_BILATERAL_PAYLOAD_V1",
    ]));
    state_header[240..272].copy_from_slice(&script_blake2b256(&[b"CKB_MORPH_CHALLENGE_POLICY_V1"]));
    put_u16(&mut state_header, 272, 1);

    let state_output_index = 1u32;
    let vault_output_index = 2u32;
    let state_type_hash = [41u8; BYTE32_LEN];
    let vault_lock_hash = [42u8; BYTE32_LEN];
    let state_lock_hash = [43u8; BYTE32_LEN];
    let exit_digest = factory_local_exit_digest_v1(
        state_output_index,
        vault_output_index,
        &state_type_hash,
        &vault_lock_hash,
        &state_lock_hash,
        &state_header,
        &descriptor,
    );

    let mut factory_header = vec![0u8; FACTORY_STATE_HEADER_V1_LEN];
    put_u16(&mut factory_header, 0, 1);
    factory_header[2..34].copy_from_slice(&[50u8; BYTE32_LEN]);
    put_u16(
        &mut factory_header,
        34,
        SIGNATURE_SCHEME_SECP256K1_ECDSA_BLAKE2B_V1,
    );
    factory_header[36..68].copy_from_slice(&[51u8; BYTE32_LEN]);
    put_u64(&mut factory_header, 68, 2);
    factory_header[76..108].copy_from_slice(&[52u8; BYTE32_LEN]);
    factory_header[108..140].copy_from_slice(&factory_participants_commitment_v1(
        2,
        &[
            (
                factory_entries[0].0.as_slice(),
                factory_entries[0].1.as_slice(),
            ),
            (
                factory_entries[1].0.as_slice(),
                factory_entries[1].1.as_slice(),
            ),
        ],
    ));
    factory_header[140..172].copy_from_slice(&[53u8; BYTE32_LEN]);
    factory_header[172..204].copy_from_slice(&exit_digest);
    factory_header[204..236].copy_from_slice(&[54u8; BYTE32_LEN]);
    put_u16(&mut factory_header, 236, 1);

    let factory_signature = signed_factory_witness(&factory_header, &factory_entries)?;
    let local_exit_witness = factory_local_exit_witness_bytes(
        &factory_signature,
        state_output_index,
        vault_output_index,
        &state_type_hash,
        &vault_lock_hash,
        &state_lock_hash,
        &state_header,
        &descriptor,
    );
    StoredFactoryLocalExitPackage::from_factory_local_exit(&factory_header, &local_exit_witness)
}

pub fn list_packages(dir: &Path, channel_id: Option<&str>) -> Result<Vec<StatePackageRecord>> {
    if !dir.exists() {
        return Ok(Vec::new());
    }
    ensure!(
        dir.is_dir(),
        "state package path {} is not a directory",
        dir.display()
    );
    let channel_filter = channel_id
        .map(canonical_hex32)
        .transpose()
        .context("invalid channel id filter")?;
    let mut records = Vec::new();
    for entry in fs::read_dir(dir)
        .with_context(|| format!("failed to read package directory {}", dir.display()))?
    {
        let entry =
            entry.with_context(|| format!("failed to read package entry in {}", dir.display()))?;
        let path = entry.path();
        if !is_package_file(&path) {
            continue;
        }
        let package = read_package(&path)?;
        if channel_filter
            .as_ref()
            .is_some_and(|channel_id| &package.channel_id != channel_id)
        {
            continue;
        }
        records.push(StatePackageRecord { path, package });
    }
    records.sort_by(|left, right| {
        left.package
            .channel_id
            .cmp(&right.package.channel_id)
            .then_with(|| left.package.state_number.cmp(&right.package.state_number))
            .then_with(|| {
                left.package
                    .signing_digest
                    .cmp(&right.package.signing_digest)
            })
            .then_with(|| left.path.cmp(&right.path))
    });
    Ok(records)
}

pub fn list_factory_state_cell_packages(
    dir: &Path,
    factory_id: Option<&str>,
) -> Result<Vec<FactoryStateCellPackageRecord>> {
    if !dir.exists() {
        return Ok(Vec::new());
    }
    ensure!(
        dir.is_dir(),
        "factory state package path {} is not a directory",
        dir.display()
    );
    let factory_filter = factory_id
        .map(canonical_hex32)
        .transpose()
        .context("invalid factory id filter")?;
    let mut records = Vec::new();
    for entry in fs::read_dir(dir)
        .with_context(|| format!("failed to read package directory {}", dir.display()))?
    {
        let entry =
            entry.with_context(|| format!("failed to read package entry in {}", dir.display()))?;
        let path = entry.path();
        if !is_factory_state_cell_package_file(&path) {
            continue;
        }
        let package = read_factory_state_cell_package(&path)?;
        if factory_filter
            .as_ref()
            .is_some_and(|factory_id| &package.factory_id != factory_id)
        {
            continue;
        }
        records.push(FactoryStateCellPackageRecord { path, package });
    }
    records.sort_by(|left, right| {
        left.package
            .factory_id
            .cmp(&right.package.factory_id)
            .then_with(|| left.package.update_number.cmp(&right.package.update_number))
            .then_with(|| {
                left.package
                    .signing_digest
                    .cmp(&right.package.signing_digest)
            })
            .then_with(|| left.path.cmp(&right.path))
    });
    Ok(records)
}

pub fn latest_factory_state_cell_package(
    dir: &Path,
    factory_id: &str,
) -> Result<FactoryStateCellPackageRecord> {
    let factory_id = canonical_hex32(factory_id)?;
    let records = list_factory_state_cell_packages(dir, Some(&factory_id))?;
    records
        .into_iter()
        .max_by(|left, right| {
            left.package
                .update_number
                .cmp(&right.package.update_number)
                .then_with(|| {
                    left.package
                        .created_unix_ms
                        .cmp(&right.package.created_unix_ms)
                })
                .then_with(|| {
                    left.package
                        .signing_digest
                        .cmp(&right.package.signing_digest)
                })
        })
        .ok_or_else(|| anyhow!("no factory state package found for factory {factory_id}"))
}

pub fn latest_package(dir: &Path, channel_id: &str) -> Result<StatePackageRecord> {
    let channel_id = canonical_hex32(channel_id)?;
    let records = list_packages(dir, Some(&channel_id))?;
    records
        .into_iter()
        .max_by(|left, right| {
            left.package
                .state_number
                .cmp(&right.package.state_number)
                .then_with(|| {
                    left.package
                        .created_unix_ms
                        .cmp(&right.package.created_unix_ms)
                })
                .then_with(|| {
                    left.package
                        .signing_digest
                        .cmp(&right.package.signing_digest)
                })
        })
        .ok_or_else(|| anyhow!("no state package found for channel {channel_id}"))
}

pub fn canonical_hex32(value: &str) -> Result<String> {
    let stripped = value.strip_prefix("0x").unwrap_or(value);
    ensure!(
        stripped.len() == 64,
        "expected 32-byte hex string, got {} hex characters",
        stripped.len()
    );
    let bytes = hex::decode(stripped).context("hex string is not valid")?;
    ensure!(bytes.len() == 32, "expected 32 bytes");
    Ok(hex_prefixed(&bytes))
}

fn parse_header(raw: &[u8]) -> Result<StateHeaderV1<'_>> {
    StateHeaderV1::parse(raw).map_err(|err| anyhow!("invalid state header encoding: {err:?}"))
}

fn parse_witness(raw: &[u8]) -> Result<BilateralSignatureWitnessV1<'_>> {
    let witness = BilateralSignatureWitnessV1::parse(raw)
        .map_err(|err| anyhow!("invalid bilateral signature witness: {err:?}"))?;
    ensure!(
        witness.threshold() == BILATERAL_SIGNATURE_THRESHOLD_V1
            && witness.count() == BILATERAL_SIGNATURE_COUNT_V1
            && witness.version() == BILATERAL_SIGNATURE_WITNESS_VERSION_V1,
        "unsupported bilateral signature witness"
    );
    Ok(witness)
}

fn parse_factory_header(raw: &[u8]) -> Result<FactoryStateHeaderV1<'_>> {
    FactoryStateHeaderV1::parse(raw)
        .map_err(|err| anyhow!("invalid factory state header encoding: {err:?}"))
}

fn parse_factory_witness(raw: &[u8]) -> Result<FactorySignatureWitnessV1<'_>> {
    let witness = FactorySignatureWitnessV1::parse(raw)
        .map_err(|err| anyhow!("invalid factory signature witness: {err:?}"))?;
    ensure!(
        witness.threshold() == FACTORY_SIGNATURE_THRESHOLD_V1
            && witness.count() == FACTORY_SIGNATURE_COUNT_V1
            && witness.version() == FACTORY_SIGNATURE_WITNESS_VERSION_V1,
        "unsupported factory signature witness"
    );
    Ok(witness)
}

fn parse_factory_reduced_rights_witness(raw: &[u8]) -> Result<FactoryReducedRightsWitnessV1<'_>> {
    FactoryReducedRightsWitnessV1::parse(raw)
        .map_err(|err| anyhow!("invalid factory reduced-rights witness: {err:?}"))
}

fn parse_factory_merkle_update_witness(raw: &[u8]) -> Result<FactoryMerkleUpdateWitnessV1<'_>> {
    FactoryMerkleUpdateWitnessV1::parse(raw)
        .map_err(|err| anyhow!("invalid factory Merkle update witness: {err:?}"))
}

fn parse_factory_local_exit_witness(raw: &[u8]) -> Result<FactoryLocalExitWitnessV1<'_>> {
    FactoryLocalExitWitnessV1::parse(raw)
        .map_err(|err| anyhow!("invalid factory local-exit witness: {err:?}"))
}

fn validate_reduced_rights_pair(
    old_header: &FactoryStateHeaderV1<'_>,
    new_header: &FactoryStateHeaderV1<'_>,
    witness: &FactoryReducedRightsWitnessV1<'_>,
) -> Result<()> {
    ensure!(
        new_header.signature_scheme_id() == SIGNATURE_SCHEME_SECP256K1_ECDSA_BLAKE2B_V1,
        "unsupported factory signature scheme {}",
        new_header.signature_scheme_id()
    );
    ensure!(
        old_header.same_context_except_progress(new_header),
        "factory reduced-rights package changes immutable factory context"
    );
    ensure!(
        new_header.update_number() > old_header.update_number(),
        "factory reduced-rights package must advance the update number"
    );
    verify_reduced_factory_rights_update(old_header, new_header, witness)
        .map_err(|err| anyhow!("factory reduced-rights proof is invalid: {err:?}"))?;
    Ok(())
}

fn validate_merkle_update_pair(
    old_header: &FactoryStateHeaderV1<'_>,
    new_header: &FactoryStateHeaderV1<'_>,
    witness: &FactoryMerkleUpdateWitnessV1<'_>,
) -> Result<()> {
    ensure!(
        new_header.signature_scheme_id() == SIGNATURE_SCHEME_SECP256K1_ECDSA_BLAKE2B_V1,
        "unsupported factory signature scheme {}",
        new_header.signature_scheme_id()
    );
    ensure!(
        old_header.same_context_except_progress(new_header),
        "factory Merkle package changes immutable factory context"
    );
    ensure!(
        new_header.update_number() > old_header.update_number(),
        "factory Merkle package must advance the update number"
    );
    verify_factory_merkle_update(old_header, new_header, witness)
        .map_err(|err| anyhow!("factory Merkle update proof is invalid: {err:?}"))?;
    Ok(())
}

fn factory_headers_equal(
    left: &FactoryStateHeaderV1<'_>,
    right: &FactoryStateHeaderV1<'_>,
) -> bool {
    left.protocol_version() == right.protocol_version()
        && left.chain_id() == right.chain_id()
        && left.signature_scheme_id() == right.signature_scheme_id()
        && left.factory_id() == right.factory_id()
        && left.update_number() == right.update_number()
        && left.state_root() == right.state_root()
        && left.participants_commitment() == right.participants_commitment()
        && left.access_manifest_root() == right.access_manifest_root()
        && left.non_interference_digest() == right.non_interference_digest()
        && left.challenge_policy_commitment() == right.challenge_policy_commitment()
        && left.state_layout_version() == right.state_layout_version()
}

fn validate_factory_local_exit_pair(
    factory_header: &FactoryStateHeaderV1<'_>,
    witness: &FactoryLocalExitWitnessV1<'_>,
) -> Result<()> {
    ensure!(
        factory_header.signature_scheme_id() == SIGNATURE_SCHEME_SECP256K1_ECDSA_BLAKE2B_V1,
        "unsupported factory signature scheme {}",
        factory_header.signature_scheme_id()
    );
    let factory_signature = witness
        .factory_signature()
        .map_err(|err| anyhow!("invalid embedded factory signature witness: {err:?}"))?;
    verify_factory_state_signatures(factory_header, &factory_signature)
        .map_err(|err| anyhow!("embedded factory signatures are invalid: {err:?}"))?;

    let exit_digest = witness.exit_digest();
    ensure!(
        factory_header.non_interference_digest() == exit_digest.as_slice(),
        "factory header non_interference_digest does not match local-exit digest"
    );

    let exit_state = parse_header(witness.exit_state_header())?;
    ensure!(
        exit_state.signature_scheme_id() == SIGNATURE_SCHEME_SECP256K1_ECDSA_BLAKE2B_V1,
        "unsupported child state signature scheme {}",
        exit_state.signature_scheme_id()
    );
    ensure!(
        exit_state.state_number() == 0,
        "factory local exit must materialise child state number 0"
    );
    ensure!(
        exit_state.phase() == PHASE_ACTIVE,
        "factory local exit must materialise an active child StateCell"
    );
    let descriptor_commitment =
        settlement_descriptor_commitment_v1(witness.settlement_descriptor());
    ensure!(
        exit_state.settlement_descriptor_commitment() == descriptor_commitment.as_slice(),
        "exit StateHeader descriptor commitment does not match local-exit descriptor"
    );
    let expected_descriptor_version = match witness.settlement_descriptor().len() {
        BILATERAL_CKB_DESCRIPTOR_V1_LEN => BILATERAL_CKB_DESCRIPTOR_VERSION_V1,
        BILATERAL_CKB_XUDT_DESCRIPTOR_V1_LEN => BILATERAL_CKB_XUDT_DESCRIPTOR_VERSION_V1,
        _ => unreachable!("FactoryLocalExitWitnessV1::parse accepted only known descriptors"),
    };
    ensure!(
        exit_state.descriptor_version() == expected_descriptor_version,
        "exit StateHeader descriptor version does not match descriptor encoding"
    );
    Ok(())
}

fn decode_hex_exact(value: &str, expected_len: usize, field: &str) -> Result<Vec<u8>> {
    let bytes = decode_hex(value, field)?;
    ensure!(
        bytes.len() == expected_len,
        "{field} must be {expected_len} bytes, got {}",
        bytes.len()
    );
    Ok(bytes)
}

fn decode_hex(value: &str, field: &str) -> Result<Vec<u8>> {
    let stripped = value.strip_prefix("0x").unwrap_or(value);
    hex::decode(stripped).with_context(|| format!("{field} is not valid hex"))
}

fn is_package_file(path: &Path) -> bool {
    path.is_file()
        && path.extension().and_then(|ext| ext.to_str()) == Some("json")
        && path
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.starts_with("state-"))
}

fn is_factory_state_cell_package_file(path: &Path) -> bool {
    path.is_file()
        && path.extension().and_then(|ext| ext.to_str()) == Some("json")
        && path
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.starts_with("factory-state-cell-"))
}

fn hex_prefixed(bytes: &[u8]) -> String {
    format!("0x{}", hex::encode(bytes))
}

fn compressed_pubkey(key: &k256::ecdsa::SigningKey) -> [u8; COMPRESSED_SECP256K1_PUBKEY_LEN] {
    let encoded = key.verifying_key().to_encoded_point(true);
    let mut out = [0u8; COMPRESSED_SECP256K1_PUBKEY_LEN];
    out.copy_from_slice(encoded.as_bytes());
    out
}

fn bilateral_ckb_descriptor(
    left_lock_hash: [u8; BYTE32_LEN],
    left_capacity: u64,
    right_lock_hash: [u8; BYTE32_LEN],
    right_capacity: u64,
) -> [u8; BILATERAL_CKB_DESCRIPTOR_V1_LEN] {
    let mut entries = [
        (left_lock_hash, left_capacity),
        (right_lock_hash, right_capacity),
    ];
    entries.sort_by(|left, right| left.0.cmp(&right.0));

    let mut raw = [0u8; BILATERAL_CKB_DESCRIPTOR_V1_LEN];
    put_u16(&mut raw, 0, BILATERAL_CKB_DESCRIPTOR_VERSION_V1);
    raw[2] = 2;
    raw[3] = 0;
    for (index, (lock_hash, capacity)) in entries.iter().enumerate() {
        let offset = 4 + index * (BYTE32_LEN + 8);
        raw[offset..offset + BYTE32_LEN].copy_from_slice(lock_hash);
        put_u64(&mut raw, offset + BYTE32_LEN, *capacity);
    }
    raw
}

fn factory_header_fixture(update_number: u64, factory_id: [u8; BYTE32_LEN]) -> Vec<u8> {
    let mut header = vec![0u8; FACTORY_STATE_HEADER_V1_LEN];
    put_u16(&mut header, 0, 1);
    header[2..34].copy_from_slice(&[7u8; BYTE32_LEN]);
    put_u16(&mut header, 34, SIGNATURE_SCHEME_SECP256K1_ECDSA_BLAKE2B_V1);
    header[36..68].copy_from_slice(&factory_id);
    put_u64(&mut header, 68, update_number);
    header[204..236].copy_from_slice(&[12u8; BYTE32_LEN]);
    put_u16(&mut header, 236, 1);
    header
}

fn reduced_participant_offset(index: usize) -> usize {
    8 + index * FACTORY_REDUCED_RIGHTS_PARTICIPANT_ENTRY_V1_LEN
}

fn reduced_touched_offset() -> usize {
    8 + FACTORY_REDUCED_RIGHTS_PARTICIPANT_COUNT_V1 as usize
        * FACTORY_REDUCED_RIGHTS_PARTICIPANT_ENTRY_V1_LEN
}

fn reduced_right_offset(after: bool, index: usize) -> usize {
    let before_offset = reduced_touched_offset() + BYTE32_LEN;
    if after {
        before_offset
            + FACTORY_REDUCED_RIGHTS_COUNT_V1 as usize * FACTORY_RIGHT_V1_LEN
            + index * FACTORY_RIGHT_V1_LEN
    } else {
        before_offset + index * FACTORY_RIGHT_V1_LEN
    }
}

#[cfg(test)]
fn merkle_update_participant_offset(index: usize) -> usize {
    8 + index * FACTORY_REDUCED_RIGHTS_PARTICIPANT_ENTRY_V1_LEN
}

#[cfg(test)]
fn merkle_update_touched_offset() -> usize {
    8 + FACTORY_REDUCED_RIGHTS_PARTICIPANT_COUNT_V1 as usize
        * FACTORY_REDUCED_RIGHTS_PARTICIPANT_ENTRY_V1_LEN
}

#[cfg(test)]
fn merkle_update_right_offset(after: bool) -> usize {
    let before_offset = merkle_update_touched_offset() + BYTE32_LEN;
    if after {
        before_offset + FACTORY_RIGHT_V1_LEN
    } else {
        before_offset
    }
}

#[cfg(test)]
fn merkle_update_sibling_offset(depth: usize) -> usize {
    merkle_update_right_offset(true) + FACTORY_RIGHT_V1_LEN + depth * BYTE32_LEN
}

fn factory_right_bytes(
    participant: u8,
    subchannel: u8,
    kind: u8,
    quantity: u128,
) -> [u8; FACTORY_RIGHT_V1_LEN] {
    let mut raw = [0u8; FACTORY_RIGHT_V1_LEN];
    raw[0..BYTE32_LEN].fill(participant);
    raw[BYTE32_LEN..2 * BYTE32_LEN].fill(subchannel);
    raw[2 * BYTE32_LEN] = kind;
    raw[2 * BYTE32_LEN + 1] = 0;
    put_u128(&mut raw, 2 * BYTE32_LEN + 2 + BYTE32_LEN, quantity);
    raw
}

#[cfg(test)]
fn merkle_update_witness_bytes(
    touched_after_balance: u128,
    alice: &k256::ecdsa::SigningKey,
    bob: &k256::ecdsa::SigningKey,
) -> Result<[u8; FACTORY_MERKLE_UPDATE_WITNESS_V1_LEN]> {
    let entries = reduced_participant_entries(alice, bob);
    let mut raw = [0u8; FACTORY_MERKLE_UPDATE_WITNESS_V1_LEN];
    put_u16(&mut raw, 0, FACTORY_MERKLE_UPDATE_WITNESS_VERSION_V1);
    raw[2] = FACTORY_REDUCED_RIGHTS_PARTICIPANT_THRESHOLD_V1;
    raw[3] = FACTORY_REDUCED_RIGHTS_PARTICIPANT_COUNT_V1;
    raw[4] = FACTORY_REDUCED_RIGHTS_AUTHORISED_COUNT_V1;
    raw[5] = FACTORY_MERKLE_UPDATE_RIGHT_COUNT_V1;
    for (index, (participant, pubkey)) in entries.iter().enumerate() {
        let offset = merkle_update_participant_offset(index);
        raw[offset..offset + BYTE32_LEN].copy_from_slice(participant);
        raw[offset + BYTE32_LEN..offset + BYTE32_LEN + COMPRESSED_SECP256K1_PUBKEY_LEN]
            .copy_from_slice(pubkey);
        raw[offset + BYTE32_LEN + COMPRESSED_SECP256K1_PUBKEY_LEN] =
            u8::from(participant == &[1u8; BYTE32_LEN]);
    }
    raw[merkle_update_touched_offset()..merkle_update_touched_offset() + BYTE32_LEN]
        .copy_from_slice(&[1u8; BYTE32_LEN]);
    raw[merkle_update_right_offset(false)
        ..merkle_update_right_offset(false) + FACTORY_RIGHT_V1_LEN]
        .copy_from_slice(&factory_right_bytes(1, 10, 0, 1_000));
    raw[merkle_update_right_offset(true)..merkle_update_right_offset(true) + FACTORY_RIGHT_V1_LEN]
        .copy_from_slice(&factory_right_bytes(1, 10, 0, touched_after_balance));
    for depth in 0..256 {
        let offset = merkle_update_sibling_offset(depth);
        raw[offset..offset + BYTE32_LEN].fill(depth as u8);
    }
    parse_factory_merkle_update_witness(&raw)?;
    Ok(raw)
}

fn reduced_rights_pair(
    touched_after_balance: u128,
) -> (
    [[u8; FACTORY_RIGHT_V1_LEN]; FACTORY_REDUCED_RIGHTS_COUNT_V1 as usize],
    [[u8; FACTORY_RIGHT_V1_LEN]; FACTORY_REDUCED_RIGHTS_COUNT_V1 as usize],
) {
    let before = [
        factory_right_bytes(1, 10, 0, 100),
        factory_right_bytes(1, 10, 1, 50),
        factory_right_bytes(1, 10, 2, 1),
        factory_right_bytes(1, 10, 3, 1),
        factory_right_bytes(1, 10, 4, 20),
        factory_right_bytes(2, 10, 0, 100),
        factory_right_bytes(2, 10, 1, 50),
        factory_right_bytes(2, 10, 2, 1),
        factory_right_bytes(2, 10, 3, 1),
        factory_right_bytes(2, 10, 4, 20),
    ];
    let mut after = before;
    after[0] = factory_right_bytes(1, 10, 0, touched_after_balance);
    (before, after)
}

fn reduced_participant_entries(
    alice: &k256::ecdsa::SigningKey,
    bob: &k256::ecdsa::SigningKey,
) -> [([u8; BYTE32_LEN], [u8; COMPRESSED_SECP256K1_PUBKEY_LEN]); 2] {
    let mut entries = [
        ([1u8; BYTE32_LEN], compressed_pubkey(alice)),
        ([2u8; BYTE32_LEN], compressed_pubkey(bob)),
    ];
    entries.sort_by(|left, right| left.0.cmp(&right.0));
    entries
}

fn reduced_rights_witness_bytes(
    touched_after_balance: u128,
    alice: &k256::ecdsa::SigningKey,
    bob: &k256::ecdsa::SigningKey,
) -> Result<[u8; FACTORY_REDUCED_RIGHTS_WITNESS_V1_LEN]> {
    let entries = reduced_participant_entries(alice, bob);
    let (before, after) = reduced_rights_pair(touched_after_balance);

    let mut raw = [0u8; FACTORY_REDUCED_RIGHTS_WITNESS_V1_LEN];
    put_u16(&mut raw, 0, FACTORY_REDUCED_RIGHTS_WITNESS_VERSION_V1);
    raw[2] = FACTORY_REDUCED_RIGHTS_PARTICIPANT_THRESHOLD_V1;
    raw[3] = FACTORY_REDUCED_RIGHTS_PARTICIPANT_COUNT_V1;
    raw[4] = FACTORY_REDUCED_RIGHTS_AUTHORISED_COUNT_V1;
    raw[5] = FACTORY_REDUCED_RIGHTS_COUNT_V1;
    for (index, (participant, pubkey)) in entries.iter().enumerate() {
        let offset = reduced_participant_offset(index);
        raw[offset..offset + BYTE32_LEN].copy_from_slice(participant);
        raw[offset + BYTE32_LEN..offset + BYTE32_LEN + COMPRESSED_SECP256K1_PUBKEY_LEN]
            .copy_from_slice(pubkey);
        raw[offset + BYTE32_LEN + COMPRESSED_SECP256K1_PUBKEY_LEN] =
            u8::from(participant == &[1u8; BYTE32_LEN]);
    }
    raw[reduced_touched_offset()..reduced_touched_offset() + BYTE32_LEN]
        .copy_from_slice(&[1u8; BYTE32_LEN]);
    for index in 0..FACTORY_REDUCED_RIGHTS_COUNT_V1 as usize {
        let before_offset = reduced_right_offset(false, index);
        raw[before_offset..before_offset + FACTORY_RIGHT_V1_LEN].copy_from_slice(&before[index]);
        let after_offset = reduced_right_offset(true, index);
        raw[after_offset..after_offset + FACTORY_RIGHT_V1_LEN].copy_from_slice(&after[index]);
    }
    parse_factory_reduced_rights_witness(&raw)?;
    Ok(raw)
}

fn sign_reduced_rights_witness(
    witness: &mut [u8; FACTORY_REDUCED_RIGHTS_WITNESS_V1_LEN],
    participant: [u8; BYTE32_LEN],
    key: &k256::ecdsa::SigningKey,
    digest: &[u8; BYTE32_LEN],
) -> Result<()> {
    use k256::ecdsa::signature::hazmat::PrehashSigner;

    let sig: k256::ecdsa::Signature = key
        .sign_prehash(digest)
        .map_err(|err| anyhow!("failed to sign reduced factory rights witness: {err:?}"))?;
    for index in 0..FACTORY_REDUCED_RIGHTS_PARTICIPANT_COUNT_V1 as usize {
        let offset = reduced_participant_offset(index);
        if &witness[offset..offset + BYTE32_LEN] == participant.as_slice() {
            let signature_offset = offset + BYTE32_LEN + COMPRESSED_SECP256K1_PUBKEY_LEN + 1;
            witness[signature_offset..signature_offset + ECDSA_SIGNATURE_LEN]
                .copy_from_slice(sig.to_bytes().as_slice());
            return Ok(());
        }
    }
    Err(anyhow!(
        "participant not present in reduced factory rights witness"
    ))
}

#[cfg(test)]
fn sign_merkle_update_witness(
    witness: &mut [u8; FACTORY_MERKLE_UPDATE_WITNESS_V1_LEN],
    participant: [u8; BYTE32_LEN],
    key: &k256::ecdsa::SigningKey,
    digest: &[u8; BYTE32_LEN],
) -> Result<()> {
    use k256::ecdsa::signature::hazmat::PrehashSigner;

    let sig: k256::ecdsa::Signature = key
        .sign_prehash(digest)
        .map_err(|err| anyhow!("failed to sign factory Merkle update witness: {err:?}"))?;
    for index in 0..FACTORY_REDUCED_RIGHTS_PARTICIPANT_COUNT_V1 as usize {
        let offset = merkle_update_participant_offset(index);
        if &witness[offset..offset + BYTE32_LEN] == participant.as_slice() {
            let signature_offset = offset + BYTE32_LEN + COMPRESSED_SECP256K1_PUBKEY_LEN + 1;
            witness[signature_offset..signature_offset + ECDSA_SIGNATURE_LEN]
                .copy_from_slice(sig.to_bytes().as_slice());
            return Ok(());
        }
    }
    Err(anyhow!(
        "participant not present in factory Merkle update witness"
    ))
}

fn signed_factory_witness(
    factory_header: &[u8],
    entries: &[(
        [u8; BYTE32_LEN],
        [u8; COMPRESSED_SECP256K1_PUBKEY_LEN],
        k256::ecdsa::SigningKey,
    )],
) -> Result<[u8; FACTORY_SIGNATURE_WITNESS_V1_LEN]> {
    use k256::ecdsa::signature::hazmat::PrehashSigner;

    ensure!(
        entries.len() == FACTORY_SIGNATURE_COUNT_V1 as usize,
        "factory local-exit fixture must have {} signers",
        FACTORY_SIGNATURE_COUNT_V1
    );
    let header = parse_factory_header(factory_header)?;
    let digest = header.signing_digest();
    let mut raw = [0u8; FACTORY_SIGNATURE_WITNESS_V1_LEN];
    put_u16(&mut raw, 0, FACTORY_SIGNATURE_WITNESS_VERSION_V1);
    raw[2] = FACTORY_SIGNATURE_THRESHOLD_V1;
    raw[3] = FACTORY_SIGNATURE_COUNT_V1;
    for (index, (participant, pubkey, key)) in entries.iter().enumerate() {
        let offset =
            4 + index * (BYTE32_LEN + COMPRESSED_SECP256K1_PUBKEY_LEN + ECDSA_SIGNATURE_LEN);
        raw[offset..offset + BYTE32_LEN].copy_from_slice(participant);
        raw[offset + BYTE32_LEN..offset + BYTE32_LEN + COMPRESSED_SECP256K1_PUBKEY_LEN]
            .copy_from_slice(pubkey);
        let sig: k256::ecdsa::Signature = key
            .sign_prehash(&digest)
            .map_err(|err| anyhow!("failed to sign factory local-exit fixture: {err:?}"))?;
        raw[offset + BYTE32_LEN + COMPRESSED_SECP256K1_PUBKEY_LEN
            ..offset + BYTE32_LEN + COMPRESSED_SECP256K1_PUBKEY_LEN + ECDSA_SIGNATURE_LEN]
            .copy_from_slice(sig.to_bytes().as_slice());
    }
    Ok(raw)
}

#[allow(clippy::too_many_arguments)]
fn factory_local_exit_witness_bytes(
    factory_signature: &[u8; FACTORY_SIGNATURE_WITNESS_V1_LEN],
    state_output_index: u32,
    vault_output_index: u32,
    state_type_hash: &[u8; BYTE32_LEN],
    vault_lock_hash: &[u8; BYTE32_LEN],
    state_lock_hash: &[u8; BYTE32_LEN],
    state_header: &[u8],
    descriptor: &[u8],
) -> Vec<u8> {
    let mut raw = vec![
        0u8;
        2 + FACTORY_SIGNATURE_WITNESS_V1_LEN
            + 8
            + 3 * BYTE32_LEN
            + STATE_HEADER_V1_LEN
            + descriptor.len()
    ];
    put_u16(&mut raw, 0, FACTORY_LOCAL_EXIT_WITNESS_VERSION_V1);
    let mut offset = 2;
    raw[offset..offset + FACTORY_SIGNATURE_WITNESS_V1_LEN].copy_from_slice(factory_signature);
    offset += FACTORY_SIGNATURE_WITNESS_V1_LEN;
    put_u32(&mut raw, offset, state_output_index);
    offset += 4;
    put_u32(&mut raw, offset, vault_output_index);
    offset += 4;
    raw[offset..offset + BYTE32_LEN].copy_from_slice(state_type_hash);
    offset += BYTE32_LEN;
    raw[offset..offset + BYTE32_LEN].copy_from_slice(vault_lock_hash);
    offset += BYTE32_LEN;
    raw[offset..offset + BYTE32_LEN].copy_from_slice(state_lock_hash);
    offset += BYTE32_LEN;
    raw[offset..offset + STATE_HEADER_V1_LEN].copy_from_slice(state_header);
    offset += STATE_HEADER_V1_LEN;
    raw[offset..offset + descriptor.len()].copy_from_slice(descriptor);
    raw
}

fn phase_label(phase: u8) -> &'static str {
    match phase {
        PHASE_ACTIVE => "active",
        PHASE_SETTLING => "settling",
        _ => "unknown",
    }
}

fn now_unix_ms() -> Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system time is before unix epoch")?
        .as_millis()
        .try_into()
        .context("unix time does not fit in u64 milliseconds")
}

fn put_u16(out: &mut [u8], offset: usize, value: u16) {
    out[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn put_u32(out: &mut [u8], offset: usize, value: u32) {
    out[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn put_u64(out: &mut [u8], offset: usize, value: u64) {
    out[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn put_u128(out: &mut [u8], offset: usize, value: u128) {
    out[offset..offset + 16].copy_from_slice(&value.to_le_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;
    use k256::ecdsa::signature::hazmat::PrehashSigner;
    use k256::ecdsa::{Signature, SigningKey};
    use morph_script_common::{
        BILATERAL_SIGNATURE_WITNESS_VERSION_V1, BYTE32_LEN, COMPRESSED_SECP256K1_PUBKEY_LEN,
        ECDSA_SIGNATURE_LEN, FACTORY_SIGNATURE_WITNESS_VERSION_V1,
        factory_participants_commitment_v1, participants_commitment_v1,
    };

    #[test]
    fn writes_lists_and_selects_latest_package() {
        let dir = temp_dir("latest");
        let first = signed_package(1);
        let latest = signed_package(3);

        let first_path = write_package(&dir, &first).unwrap();
        let latest_path = write_package(&dir, &latest).unwrap();

        let records = list_packages(&dir, Some(&first.channel_id)).unwrap();
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].path, first_path);
        assert_eq!(records[1].path, latest_path);

        let selected = latest_package(&dir, &first.channel_id).unwrap();
        assert_eq!(selected.package.state_number, 3);
        assert_eq!(selected.path, latest_path);

        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn rejects_tampered_signature_witness() {
        let package = signed_package(2);
        let header = package.header_bytes().unwrap();
        let mut witness = package.witness_bytes().unwrap();
        let last = witness.len() - 1;
        witness[last] ^= 1;

        let err = StoredStatePackage::from_signed_state(&header, &witness, None).unwrap_err();
        assert!(err.to_string().contains("signatures are invalid"));
    }

    #[test]
    fn writes_lists_and_selects_latest_factory_state_cell_package() {
        let dir = temp_dir("factory-latest");
        let first = signed_factory_state_cell_package(1);
        let latest = signed_factory_state_cell_package(4);

        let first_path = write_factory_state_cell_package(&dir, &first).unwrap();
        let latest_path = write_factory_state_cell_package(&dir, &latest).unwrap();

        let records = list_factory_state_cell_packages(&dir, Some(&first.factory_id)).unwrap();
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].path, first_path);
        assert_eq!(records[1].path, latest_path);

        let selected = latest_factory_state_cell_package(&dir, &first.factory_id).unwrap();
        assert_eq!(selected.package.update_number, 4);
        assert_eq!(selected.path, latest_path);

        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn rejects_tampered_factory_signature_witness() {
        let package = signed_factory_state_cell_package(2);
        let header = package.header_bytes().unwrap();
        let mut witness = package.witness_bytes().unwrap();
        let last = witness.len() - 1;
        witness[last] ^= 1;

        let err = StoredFactoryStateCellPackage::from_signed_factory_state(&header, &witness, None)
            .unwrap_err();
        assert!(err.to_string().contains("signatures are invalid"));
    }

    #[test]
    fn writes_reads_and_validates_factory_reduced_rights_package() {
        let dir = temp_dir("factory-reduced-rights");
        let package = fixture_factory_reduced_rights_package().unwrap();
        let path = write_factory_reduced_rights_package(&dir, &package).unwrap();

        let loaded = read_factory_reduced_rights_package(&path).unwrap();
        let summary = loaded.summary().unwrap();
        assert_eq!(summary.old_update_number, 1);
        assert_eq!(summary.new_update_number, 2);
        assert_eq!(summary.witness_len, FACTORY_REDUCED_RIGHTS_WITNESS_V1_LEN);

        let update_package = read_factory_state_cell_update_package(&path).unwrap();
        assert_eq!(update_package.update_number(), 2);
        assert_eq!(update_package.factory_id(), package.factory_id);

        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn rejects_tampered_factory_reduced_rights_signature() {
        let mut package = fixture_factory_reduced_rights_package().unwrap();
        let mut witness = package.witness_bytes().unwrap();
        let signature_offset =
            reduced_participant_offset(0) + BYTE32_LEN + COMPRESSED_SECP256K1_PUBKEY_LEN + 1;
        witness[signature_offset + ECDSA_SIGNATURE_LEN - 1] ^= 1;
        package.witness_hex = hex_prefixed(&witness);

        let err = package.validate().unwrap_err();
        assert!(
            err.to_string()
                .contains("factory reduced-rights proof is invalid")
        );
    }

    #[test]
    fn validates_factory_local_exit_package() {
        let package = fixture_factory_local_exit_package().unwrap();
        let summary = package.summary().unwrap();

        assert_eq!(summary.update_number, 2);
        assert_eq!(summary.child_state_number, 0);
        assert_eq!(summary.child_phase, "active");
        assert_eq!(summary.state_output_index, 1);
        assert_eq!(summary.vault_output_index, 2);
    }

    #[test]
    fn rejects_tampered_factory_local_exit_descriptor() {
        let mut package = fixture_factory_local_exit_package().unwrap();
        let mut witness = package.local_exit_witness_bytes().unwrap();
        let last = witness.len() - 1;
        witness[last] ^= 1;
        package.local_exit_witness_hex = hex_prefixed(&witness);

        let err = package.validate().unwrap_err();
        assert!(
            err.to_string()
                .contains("non_interference_digest does not match local-exit digest")
        );
    }

    #[test]
    fn rejects_tampered_factory_local_exit_header_signature() {
        let mut package = fixture_factory_local_exit_package().unwrap();
        let mut header = package.factory_header_bytes().unwrap();
        header[76] ^= 1;
        package.factory_header_hex = hex_prefixed(&header);

        let err = package.validate().unwrap_err();
        assert!(
            err.to_string()
                .contains("embedded factory signatures are invalid")
        );
    }

    #[test]
    fn writes_and_reads_watch_cursor() {
        let dir = temp_dir("cursor");
        let channel_id = format!("0x{}", "11".repeat(BYTE32_LEN));
        let path = default_watch_cursor_path(&dir, &channel_id).unwrap();
        let cursor = WatchCursor::new(&channel_id, 43, 42).unwrap();

        assert!(read_watch_cursor(&path).unwrap().is_none());
        write_watch_cursor(&path, &cursor).unwrap();

        let loaded = read_watch_cursor(&path).unwrap().unwrap();
        assert_eq!(loaded.channel_id, channel_id);
        assert_eq!(loaded.next_block, 43);
        assert_eq!(loaded.scanned_to_block, 42);

        fs::remove_dir_all(dir).unwrap();
    }

    fn signed_package(state_number: u64) -> StoredStatePackage {
        let alice = SigningKey::from_slice(&[1u8; 32]).unwrap();
        let bob = SigningKey::from_slice(&[2u8; 32]).unwrap();
        let mut entries = [(pubkey(&alice), alice), (pubkey(&bob), bob)];
        entries.sort_by(|left, right| left.0.cmp(&right.0));

        let mut header = vec![0u8; STATE_HEADER_V1_LEN];
        put_u16(&mut header, 0, 1);
        header[2..34].copy_from_slice(&[7u8; BYTE32_LEN]);
        put_u16(&mut header, 34, SIGNATURE_SCHEME_SECP256K1_ECDSA_BLAKE2B_V1);
        header[36..68].copy_from_slice(&[8u8; BYTE32_LEN]);
        header[68..100].copy_from_slice(&[9u8; BYTE32_LEN]);
        put_u64(&mut header, 100, state_number);
        header[108] = 0;
        header[109] = PHASE_SETTLING;
        let pubkeys = [entries[0].0.as_slice(), entries[1].0.as_slice()];
        header[110..142].copy_from_slice(&participants_commitment_v1(2, &pubkeys));
        put_u16(&mut header, 206, 1);
        put_u16(&mut header, 272, 1);

        let parsed = StateHeaderV1::parse(&header).unwrap();
        let digest = parsed.signing_digest();
        let mut witness = vec![0u8; BILATERAL_SIGNATURE_WITNESS_V1_LEN];
        put_u16(&mut witness, 0, BILATERAL_SIGNATURE_WITNESS_VERSION_V1);
        witness[2] = BILATERAL_SIGNATURE_THRESHOLD_V1;
        witness[3] = BILATERAL_SIGNATURE_COUNT_V1;
        for (index, (pubkey, key)) in entries.iter().enumerate() {
            let offset = 4 + index * (COMPRESSED_SECP256K1_PUBKEY_LEN + ECDSA_SIGNATURE_LEN);
            witness[offset..offset + COMPRESSED_SECP256K1_PUBKEY_LEN].copy_from_slice(pubkey);
            let sig: Signature = key.sign_prehash(&digest).unwrap();
            witness[offset + COMPRESSED_SECP256K1_PUBKEY_LEN
                ..offset + COMPRESSED_SECP256K1_PUBKEY_LEN + ECDSA_SIGNATURE_LEN]
                .copy_from_slice(sig.to_bytes().as_slice());
        }

        StoredStatePackage::from_signed_state(&header, &witness, None).unwrap()
    }

    fn signed_factory_state_cell_package(update_number: u64) -> StoredFactoryStateCellPackage {
        let alice = SigningKey::from_slice(&[1u8; 32]).unwrap();
        let bob = SigningKey::from_slice(&[2u8; 32]).unwrap();
        let mut entries = [
            ([1u8; BYTE32_LEN], pubkey(&alice), alice),
            ([2u8; BYTE32_LEN], pubkey(&bob), bob),
        ];
        entries.sort_by(|left, right| left.0.cmp(&right.0));

        let mut header = vec![0u8; FACTORY_STATE_HEADER_V1_LEN];
        put_u16(&mut header, 0, 1);
        header[2..34].copy_from_slice(&[7u8; BYTE32_LEN]);
        put_u16(&mut header, 34, SIGNATURE_SCHEME_SECP256K1_ECDSA_BLAKE2B_V1);
        header[36..68].copy_from_slice(&[8u8; BYTE32_LEN]);
        put_u64(&mut header, 68, update_number);
        header[76..108].copy_from_slice(&[9u8; BYTE32_LEN]);
        header[108..140].copy_from_slice(&factory_participants_commitment_v1(
            2,
            &[
                (entries[0].0.as_slice(), entries[0].1.as_slice()),
                (entries[1].0.as_slice(), entries[1].1.as_slice()),
            ],
        ));
        header[140..172].copy_from_slice(&[10u8; BYTE32_LEN]);
        header[172..204].copy_from_slice(&[11u8; BYTE32_LEN]);
        header[204..236].copy_from_slice(&[12u8; BYTE32_LEN]);
        put_u16(&mut header, 236, 1);

        let parsed = FactoryStateHeaderV1::parse(&header).unwrap();
        let digest = parsed.signing_digest();
        let mut witness = vec![0u8; FACTORY_SIGNATURE_WITNESS_V1_LEN];
        put_u16(&mut witness, 0, FACTORY_SIGNATURE_WITNESS_VERSION_V1);
        witness[2] = FACTORY_SIGNATURE_THRESHOLD_V1;
        witness[3] = FACTORY_SIGNATURE_COUNT_V1;
        for (index, (participant, pubkey, key)) in entries.iter().enumerate() {
            let offset =
                4 + index * (BYTE32_LEN + COMPRESSED_SECP256K1_PUBKEY_LEN + ECDSA_SIGNATURE_LEN);
            witness[offset..offset + BYTE32_LEN].copy_from_slice(participant);
            witness[offset + BYTE32_LEN..offset + BYTE32_LEN + COMPRESSED_SECP256K1_PUBKEY_LEN]
                .copy_from_slice(pubkey);
            let sig: Signature = key.sign_prehash(&digest).unwrap();
            witness[offset + BYTE32_LEN + COMPRESSED_SECP256K1_PUBKEY_LEN
                ..offset + BYTE32_LEN + COMPRESSED_SECP256K1_PUBKEY_LEN + ECDSA_SIGNATURE_LEN]
                .copy_from_slice(sig.to_bytes().as_slice());
        }

        StoredFactoryStateCellPackage::from_signed_factory_state(&header, &witness, None).unwrap()
    }

    fn pubkey(key: &SigningKey) -> [u8; COMPRESSED_SECP256K1_PUBKEY_LEN] {
        let encoded = key.verifying_key().to_encoded_point(true);
        let mut out = [0u8; COMPRESSED_SECP256K1_PUBKEY_LEN];
        out.copy_from_slice(encoded.as_bytes());
        out
    }

    fn temp_dir(label: &str) -> PathBuf {
        let mut path = std::env::temp_dir();
        path.push(format!(
            "morph-state-package-test-{label}-{}-{}",
            std::process::id(),
            now_unix_ms().unwrap()
        ));
        path
    }

    fn put_u16(out: &mut [u8], offset: usize, value: u16) {
        out[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    }

    fn put_u64(out: &mut [u8], offset: usize, value: u64) {
        out[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }
}
