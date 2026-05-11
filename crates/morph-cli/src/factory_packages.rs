use std::collections::BTreeSet;
use std::fs;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, ensure};
use k256::ecdsa::signature::hazmat::{PrehashSigner, PrehashVerifier};
use k256::ecdsa::{Signature, SigningKey, VerifyingKey};
use morph_core::{
    Amount, Bytes32, FactoryRight, FactoryRightId, FactoryRightKind, FactoryUpdate, blake2b256,
    bytes32, validate_factory_non_interference,
};
use serde::{Deserialize, Serialize};

use crate::packages::canonical_hex32;

const FACTORY_PACKAGE_SCHEMA: &str = "morph.factory_update_package.v1";
const FACTORY_DIGEST_DOMAIN_V1: &str = "CKB_MORPH_FACTORY_UPDATE_PACKAGE_V1";
const FACTORY_STATE_PACKAGE_SCHEMA: &str = "morph.factory_state_package.v1";
const FACTORY_STATE_DIGEST_DOMAIN_V1: &str = "CKB_MORPH_FACTORY_STATE_PACKAGE_V1";
const FACTORY_SIGNATURE_MODE_ALL_PARTICIPANTS_V1: &str = "all_participants_v1";

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
    signature_mode: &'static str,
    factory_id: String,
    update_number: u64,
    state_root_before: String,
    state_root_after: String,
    non_interference_digest: String,
    signature_threshold: u8,
    participant_keys: Vec<StoredFactoryParticipantKey>,
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
            domain: FACTORY_DIGEST_DOMAIN_V1,
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
            signature_mode: FACTORY_SIGNATURE_MODE_ALL_PARTICIPANTS_V1.to_string(),
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
            self.signature_mode == FACTORY_SIGNATURE_MODE_ALL_PARTICIPANTS_V1,
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
        let expected_participants = update_participants(&self.update_package)?;
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
            "all-participant factory mode requires threshold equal to participant count"
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
            domain: FACTORY_STATE_DIGEST_DOMAIN_V1,
            schema: FACTORY_STATE_PACKAGE_SCHEMA,
            signature_mode: FACTORY_SIGNATURE_MODE_ALL_PARTICIPANTS_V1,
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

pub fn fixture_state_package() -> Result<StoredFactoryStatePackage> {
    let update_package = fixture_package()?;
    let alice = SigningKey::from_slice(&[1u8; 32]).unwrap();
    let bob = SigningKey::from_slice(&[2u8; 32]).unwrap();
    StoredFactoryStatePackage::from_update_package(
        update_package,
        &[(bytes32(1), alice), (bytes32(2), bob)],
    )
}

fn right(
    participant: u8,
    subchannel: u8,
    kind: FactoryRightKind,
    asset_type: Option<u8>,
    quantity: Amount,
) -> FactoryRight {
    FactoryRight {
        id: FactoryRightId {
            participant: bytes32(participant),
            subchannel: bytes32(subchannel),
            kind,
            asset_type: asset_type.map(bytes32),
        },
        quantity,
    }
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
    out.sort_by(|left, right| right_sort_key(left).cmp(&right_sort_key(right)));
    Ok(out)
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

fn factory_kind_order(kind: FactoryRightKind) -> u8 {
    match kind {
        FactoryRightKind::Balance => 0,
        FactoryRightKind::ReserveClaim => 1,
        FactoryRightKind::Membership => 2,
        FactoryRightKind::ExitPath => 3,
        FactoryRightKind::SponsorBudgetClaim => 4,
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
        signature: hex_prefixed(signature.to_bytes().as_slice()),
    })
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

        assert_eq!(summary.signature_mode, "all_participants_v1");
        assert_eq!(summary.signature_threshold, 2);
        assert_eq!(summary.participants, 2);
        assert_eq!(summary.signatures, 2);
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
                .contains("threshold equal to participant count")
        );
    }
}
