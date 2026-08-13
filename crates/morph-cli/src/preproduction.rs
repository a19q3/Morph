use std::fs;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, ensure};
use morph_script_common::{
    FACTORY_DYNAMIC_MAX_PARTICIPANTS, FACTORY_DYNAMIC_MIN_PARTICIPANTS,
    FACTORY_REDUCED_RIGHTS_COUNT,
};
use serde::{Deserialize, Serialize};

use crate::release::FACTORY_V1_RELEASE_PROFILE;

pub const PREPRODUCTION_ENVELOPE_SCHEMA: &str = "morph.preproduction_envelope";
pub const PREPRODUCTION_ENVELOPE_VERSION: u16 = 2;

const MAX_ACTIVE_FACTORIES: u32 = 4;
const MAX_CHILDREN_PER_FACTORY: u32 = FACTORY_REDUCED_RIGHTS_COUNT as u32;
const MAX_CHANNEL_CAPACITY_SHANNONS: u64 = 100_000_000_000;
const MAX_FACTORY_CAPACITY_SHANNONS: u64 = 1_000_000_000_000;
const MAX_SPONSOR_CAPACITY_SHANNONS: u64 = 50_000_000_000;
const MAX_FEE_PER_TRANSACTION_SHANNONS: u64 = 200_000_000;
const MAX_TOTAL_PILOT_CAPACITY_SHANNONS: u64 = 4_000_000_000_000;
const MAX_DEVNET_XUDT_UNITS_PER_FACTORY: u128 = 1_000_000_000_000;
const MIN_WATCHTOWER_DETECTION_DEPTH: u64 = 3;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PreproductionEnvelope {
    pub schema: String,
    pub envelope_version: u16,
    pub release_profile: String,
    pub effective_date: String,
    pub review_by: String,
    pub approval_timezone: String,
    pub effective_unix: u64,
    pub review_by_unix: u64,
    pub approved_networks: Vec<String>,
    pub real_assets_allowed: bool,
    pub hub_chain_actions_allowed: bool,
    pub factory: FactoryLimits,
    pub channel: ChannelLimits,
    pub sponsor: SponsorLimits,
    pub xudt: XudtLimits,
    pub watchtower: WatchtowerLimits,
    pub legacy_factory_policy: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FactoryLimits {
    pub min_participant_count: u32,
    pub max_participant_count: u32,
    pub max_active_factories: u32,
    pub max_children_per_factory: u32,
    pub max_capacity_shannons: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChannelLimits {
    pub max_capacity_shannons: u64,
    pub max_total_pilot_capacity_shannons: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SponsorLimits {
    pub max_capacity_shannons: u64,
    pub max_fee_per_transaction_shannons: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct XudtLimits {
    pub allowed_scripts: Vec<String>,
    pub max_asset_types_per_factory: u32,
    pub max_units_per_factory: u128,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WatchtowerLimits {
    pub minimum_detection_depth: u64,
    pub reorg_mode: String,
    pub restart_scan_floor_required: bool,
    pub independent_operator_required: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PreproductionEnvelopeVerification {
    pub schema: &'static str,
    pub envelope_path: String,
    pub release_profile: String,
    pub approved_networks: Vec<String>,
    pub real_assets_allowed: bool,
    pub factory_min_participant_count: u32,
    pub factory_max_participant_count: u32,
    pub max_active_factories: u32,
    pub reorg_mode: String,
    pub verified: bool,
}

impl PreproductionEnvelope {
    pub fn validate(&self) -> Result<()> {
        let now_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .context("system clock is before the Unix epoch")?
            .as_secs();
        self.validate_at(now_unix)
    }

    fn validate_at(&self, now_unix: u64) -> Result<()> {
        ensure!(
            self.schema == PREPRODUCTION_ENVELOPE_SCHEMA,
            "unsupported pre-production envelope schema {}",
            self.schema
        );
        ensure!(
            self.envelope_version == PREPRODUCTION_ENVELOPE_VERSION,
            "unsupported pre-production envelope version {}",
            self.envelope_version
        );
        ensure!(
            self.release_profile == FACTORY_V1_RELEASE_PROFILE,
            "pre-production release profile must be {FACTORY_V1_RELEASE_PROFILE}"
        );
        ensure!(
            is_iso_date(&self.effective_date) && is_iso_date(&self.review_by),
            "effective_date and review_by must use YYYY-MM-DD"
        );
        ensure!(
            self.effective_date <= self.review_by,
            "effective_date must not be after review_by"
        );
        ensure!(
            self.approval_timezone == "Asia/Shanghai",
            "approval_timezone must be Asia/Shanghai for this dated envelope"
        );
        ensure!(
            self.effective_unix <= self.review_by_unix,
            "effective_unix must not be after review_by_unix"
        );
        ensure!(
            now_unix >= self.effective_unix,
            "pre-production envelope is not effective yet"
        );
        ensure!(
            now_unix <= self.review_by_unix,
            "pre-production envelope expired at review_by; release owner review is required"
        );
        ensure!(
            self.approved_networks == ["devnet"],
            "the current pre-production envelope is restricted to devnet"
        );
        ensure!(
            !self.real_assets_allowed,
            "real assets are prohibited by the current pre-production envelope"
        );
        ensure!(
            !self.hub_chain_actions_allowed,
            "Morph Hub chain actions must remain disabled until they submit and verify CKB transactions"
        );
        ensure!(
            self.factory.min_participant_count == FACTORY_DYNAMIC_MIN_PARTICIPANTS as u32
                && self.factory.max_participant_count == FACTORY_DYNAMIC_MAX_PARTICIPANTS as u32,
            "factory participant bounds must match the executable dynamic-N profile ({FACTORY_DYNAMIC_MIN_PARTICIPANTS}..={FACTORY_DYNAMIC_MAX_PARTICIPANTS})"
        );
        ensure!(
            (1..=MAX_ACTIVE_FACTORIES).contains(&self.factory.max_active_factories),
            "max_active_factories exceeds the reviewed pilot cap {MAX_ACTIVE_FACTORIES}"
        );
        ensure!(
            (1..=MAX_CHILDREN_PER_FACTORY).contains(&self.factory.max_children_per_factory),
            "max_children_per_factory exceeds the fixed rights profile {MAX_CHILDREN_PER_FACTORY}"
        );
        ensure_nonzero_at_most(
            self.factory.max_capacity_shannons,
            MAX_FACTORY_CAPACITY_SHANNONS,
            "factory max_capacity_shannons",
        )?;
        ensure_nonzero_at_most(
            self.channel.max_capacity_shannons,
            MAX_CHANNEL_CAPACITY_SHANNONS,
            "channel max_capacity_shannons",
        )?;
        ensure!(
            self.channel.max_capacity_shannons <= self.factory.max_capacity_shannons,
            "channel cap must not exceed factory cap"
        );
        ensure_nonzero_at_most(
            self.channel.max_total_pilot_capacity_shannons,
            MAX_TOTAL_PILOT_CAPACITY_SHANNONS,
            "pilot max_total_pilot_capacity_shannons",
        )?;
        ensure!(
            self.channel.max_total_pilot_capacity_shannons >= self.factory.max_capacity_shannons,
            "total pilot cap must cover one permitted factory"
        );
        ensure_nonzero_at_most(
            self.sponsor.max_capacity_shannons,
            MAX_SPONSOR_CAPACITY_SHANNONS,
            "sponsor max_capacity_shannons",
        )?;
        ensure_nonzero_at_most(
            self.sponsor.max_fee_per_transaction_shannons,
            MAX_FEE_PER_TRANSACTION_SHANNONS,
            "sponsor max_fee_per_transaction_shannons",
        )?;
        ensure!(
            self.sponsor.max_fee_per_transaction_shannons <= self.sponsor.max_capacity_shannons,
            "sponsor fee cap must not exceed sponsor capacity cap"
        );
        ensure!(
            self.xudt.allowed_scripts == ["morph-devnet-xudt"],
            "only morph-devnet-xudt is admitted in the current envelope"
        );
        ensure!(
            self.xudt.max_asset_types_per_factory == 1,
            "current Factory descriptor profile admits one devnet xUDT type"
        );
        ensure!(
            (1..=MAX_DEVNET_XUDT_UNITS_PER_FACTORY).contains(&self.xudt.max_units_per_factory),
            "xUDT units per factory exceed the reviewed devnet cap"
        );
        ensure!(
            self.watchtower.minimum_detection_depth >= MIN_WATCHTOWER_DETECTION_DEPTH,
            "watchtower detection depth must be at least {MIN_WATCHTOWER_DETECTION_DEPTH}"
        );
        ensure!(
            self.watchtower.reorg_mode == "detect_reset_and_rescan",
            "watchtower reorg_mode must require canonical cursor reset and rescan"
        );
        ensure!(
            self.watchtower.restart_scan_floor_required,
            "watchtower configuration must retain an explicit rescan floor"
        );
        ensure!(
            self.watchtower.independent_operator_required,
            "a separate watchtower operator is required by the pilot envelope"
        );
        ensure!(
            self.legacy_factory_policy == "recreate",
            "legacy owner-locked factories must be recreated, never migrated in place"
        );
        Ok(())
    }
}

pub fn verify_preproduction_envelope(path: &Path) -> Result<PreproductionEnvelopeVerification> {
    let bytes = fs::read(path)
        .with_context(|| format!("failed to read pre-production envelope {}", path.display()))?;
    let envelope: PreproductionEnvelope = serde_json::from_slice(&bytes)
        .with_context(|| format!("failed to parse pre-production envelope {}", path.display()))?;
    envelope
        .validate()
        .with_context(|| format!("invalid pre-production envelope {}", path.display()))?;
    Ok(PreproductionEnvelopeVerification {
        schema: "morph.preproduction_envelope_verification",
        envelope_path: path.display().to_string(),
        release_profile: envelope.release_profile,
        approved_networks: envelope.approved_networks,
        real_assets_allowed: envelope.real_assets_allowed,
        factory_min_participant_count: envelope.factory.min_participant_count,
        factory_max_participant_count: envelope.factory.max_participant_count,
        max_active_factories: envelope.factory.max_active_factories,
        reorg_mode: envelope.watchtower.reorg_mode,
        verified: true,
    })
}

fn ensure_nonzero_at_most(value: u64, maximum: u64, label: &str) -> Result<()> {
    ensure!(value > 0, "{label} must be non-zero");
    ensure!(value <= maximum, "{label} exceeds reviewed cap {maximum}");
    Ok(())
}

fn is_iso_date(value: &str) -> bool {
    value.len() == 10
        && value.as_bytes()[4] == b'-'
        && value.as_bytes()[7] == b'-'
        && value
            .as_bytes()
            .iter()
            .enumerate()
            .all(|(index, byte)| matches!(index, 4 | 7) || byte.is_ascii_digit())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> PreproductionEnvelope {
        PreproductionEnvelope {
            schema: PREPRODUCTION_ENVELOPE_SCHEMA.to_string(),
            envelope_version: PREPRODUCTION_ENVELOPE_VERSION,
            release_profile: FACTORY_V1_RELEASE_PROFILE.to_string(),
            effective_date: "2026-08-14".to_string(),
            review_by: "2026-09-13".to_string(),
            approval_timezone: "Asia/Shanghai".to_string(),
            effective_unix: 1,
            review_by_unix: u64::MAX,
            approved_networks: vec!["devnet".to_string()],
            real_assets_allowed: false,
            hub_chain_actions_allowed: false,
            factory: FactoryLimits {
                min_participant_count: FACTORY_DYNAMIC_MIN_PARTICIPANTS as u32,
                max_participant_count: FACTORY_DYNAMIC_MAX_PARTICIPANTS as u32,
                max_active_factories: 4,
                max_children_per_factory: 10,
                max_capacity_shannons: MAX_FACTORY_CAPACITY_SHANNONS,
            },
            channel: ChannelLimits {
                max_capacity_shannons: MAX_CHANNEL_CAPACITY_SHANNONS,
                max_total_pilot_capacity_shannons: MAX_TOTAL_PILOT_CAPACITY_SHANNONS,
            },
            sponsor: SponsorLimits {
                max_capacity_shannons: MAX_SPONSOR_CAPACITY_SHANNONS,
                max_fee_per_transaction_shannons: MAX_FEE_PER_TRANSACTION_SHANNONS,
            },
            xudt: XudtLimits {
                allowed_scripts: vec!["morph-devnet-xudt".to_string()],
                max_asset_types_per_factory: 1,
                max_units_per_factory: MAX_DEVNET_XUDT_UNITS_PER_FACTORY,
            },
            watchtower: WatchtowerLimits {
                minimum_detection_depth: MIN_WATCHTOWER_DETECTION_DEPTH,
                reorg_mode: "detect_reset_and_rescan".to_string(),
                restart_scan_floor_required: true,
                independent_operator_required: true,
            },
            legacy_factory_policy: "recreate".to_string(),
        }
    }

    #[test]
    fn accepts_the_reviewed_dynamic_factory_envelope() {
        fixture().validate_at(2).unwrap();
    }

    #[test]
    fn rejects_mainnet_or_real_assets() {
        let mut envelope = fixture();
        envelope.approved_networks = vec!["mainnet".to_string()];
        assert!(
            envelope
                .validate_at(2)
                .unwrap_err()
                .to_string()
                .contains("devnet")
        );

        let mut envelope = fixture();
        envelope.real_assets_allowed = true;
        assert!(
            envelope
                .validate_at(2)
                .unwrap_err()
                .to_string()
                .contains("real assets")
        );
    }

    #[test]
    fn rejects_unsupported_factory_shape_and_caps() {
        let mut envelope = fixture();
        envelope.factory.max_participant_count += 1;
        assert!(
            envelope
                .validate_at(2)
                .unwrap_err()
                .to_string()
                .contains("participant bounds")
        );

        let mut envelope = fixture();
        envelope.factory.max_active_factories = MAX_ACTIVE_FACTORIES + 1;
        assert!(
            envelope
                .validate_at(2)
                .unwrap_err()
                .to_string()
                .contains("max_active_factories")
        );
    }

    #[test]
    fn rejects_missing_reorg_recovery() {
        let mut envelope = fixture();
        envelope.watchtower.reorg_mode = "best_effort".to_string();
        assert!(
            envelope
                .validate_at(2)
                .unwrap_err()
                .to_string()
                .contains("reorg_mode")
        );
    }

    #[test]
    fn rejects_an_expired_or_not_yet_effective_envelope() {
        let envelope = fixture();
        assert!(
            envelope
                .validate_at(0)
                .unwrap_err()
                .to_string()
                .contains("not effective")
        );

        let mut envelope = fixture();
        envelope.review_by_unix = 3;
        assert!(
            envelope
                .validate_at(4)
                .unwrap_err()
                .to_string()
                .contains("expired")
        );
    }
}
