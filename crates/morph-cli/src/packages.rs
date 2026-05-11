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
    FACTORY_LOCAL_EXIT_WITNESS_VERSION_V1, FACTORY_SIGNATURE_COUNT_V1,
    FACTORY_SIGNATURE_THRESHOLD_V1, FACTORY_SIGNATURE_WITNESS_V1_LEN,
    FACTORY_SIGNATURE_WITNESS_VERSION_V1, FACTORY_STATE_HEADER_V1_LEN, FactoryLocalExitWitnessV1,
    FactorySignatureWitnessV1, FactoryStateHeaderV1, PHASE_ACTIVE, PHASE_SETTLING,
    SIGNATURE_SCHEME_SECP256K1_ECDSA_BLAKE2B_V1, STATE_HEADER_V1_LEN, StateHeaderV1,
    blake2b256 as script_blake2b256, factory_local_exit_digest_v1,
    factory_participants_commitment_v1, participants_commitment_v1,
    settlement_descriptor_commitment_v1, verify_bilateral_state_signatures,
    verify_factory_state_signatures,
};
use serde::{Deserialize, Serialize};

const PACKAGE_SCHEMA: &str = "morph.state_package.v1";
const FACTORY_STATE_CELL_PACKAGE_SCHEMA: &str = "morph.factory_state_cell_package.v1";
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

fn parse_factory_local_exit_witness(raw: &[u8]) -> Result<FactoryLocalExitWitnessV1<'_>> {
    FactoryLocalExitWitnessV1::parse(raw)
        .map_err(|err| anyhow!("invalid factory local-exit witness: {err:?}"))
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
