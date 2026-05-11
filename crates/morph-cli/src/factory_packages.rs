use std::collections::BTreeSet;
use std::fs;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, ensure};
use morph_core::{
    Amount, Bytes32, FactoryRight, FactoryRightId, FactoryRightKind, FactoryUpdate, blake2b256,
    bytes32, validate_factory_non_interference,
};
use serde::{Deserialize, Serialize};

use crate::packages::canonical_hex32;

const FACTORY_PACKAGE_SCHEMA: &str = "morph.factory_update_package.v1";
const FACTORY_DIGEST_DOMAIN_V1: &str = "CKB_MORPH_FACTORY_UPDATE_PACKAGE_V1";

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
    let mut out = values
        .iter()
        .map(|value| canonical_hex32(value))
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
}
