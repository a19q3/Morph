use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, anyhow, ensure};
use morph_script_common::{
    BILATERAL_SIGNATURE_COUNT_V1, BILATERAL_SIGNATURE_THRESHOLD_V1,
    BILATERAL_SIGNATURE_WITNESS_V1_LEN, BILATERAL_SIGNATURE_WITNESS_VERSION_V1,
    BilateralSignatureWitnessV1, PHASE_SETTLING, SIGNATURE_SCHEME_SECP256K1_ECDSA_BLAKE2B_V1,
    STATE_HEADER_V1_LEN, StateHeaderV1, verify_bilateral_state_signatures,
};
use serde::{Deserialize, Serialize};

const PACKAGE_SCHEMA: &str = "morph.state_package.v1";

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

fn decode_hex_exact(value: &str, expected_len: usize, field: &str) -> Result<Vec<u8>> {
    let stripped = value.strip_prefix("0x").unwrap_or(value);
    let bytes = hex::decode(stripped).with_context(|| format!("{field} is not valid hex"))?;
    ensure!(
        bytes.len() == expected_len,
        "{field} must be {expected_len} bytes, got {}",
        bytes.len()
    );
    Ok(bytes)
}

fn is_package_file(path: &Path) -> bool {
    path.is_file()
        && path.extension().and_then(|ext| ext.to_str()) == Some("json")
        && path
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.starts_with("state-"))
}

fn hex_prefixed(bytes: &[u8]) -> String {
    format!("0x{}", hex::encode(bytes))
}

fn now_unix_ms() -> Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system time is before unix epoch")?
        .as_millis()
        .try_into()
        .context("unix time does not fit in u64 milliseconds")?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use k256::ecdsa::signature::hazmat::PrehashSigner;
    use k256::ecdsa::{Signature, SigningKey};
    use morph_script_common::{
        BILATERAL_SIGNATURE_WITNESS_VERSION_V1, BYTE32_LEN, COMPRESSED_SECP256K1_PUBKEY_LEN,
        ECDSA_SIGNATURE_LEN, participants_commitment_v1,
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
