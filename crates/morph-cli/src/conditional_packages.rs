use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use anyhow::{Context, Result, ensure};
use morph_core::{
    Bytes32, ConditionalBatch, ConditionalHashAlgorithm, ConditionalParticipant,
    ConditionalResolution, ConditionalTransferSpec, blake2b256, derive_conditional_batch_id,
    derive_conditional_payment_hash,
};
use morph_script_common::{
    BILATERAL_CKB_CONDITIONAL_DESCRIPTOR_LEN, CONDITIONAL_BATCH_RESOLUTION_WITNESS_LEN,
};
use serde::{Deserialize, Serialize};

const CONDITIONAL_BATCH_PACKAGE_SCHEMA: &str = "morph.conditional_batch_package";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredConditionalBatchPackage {
    pub schema: String,
    pub channel_id: String,
    pub funding_context_id: String,
    pub state_number: u64,
    pub batch_id: String,
    pub application_context_commitment: String,
    pub participants: Vec<StoredConditionalParticipant>,
    pub transfers: Vec<StoredConditionalTransfer>,
    pub resolutions: Vec<StoredConditionalResolution>,
    pub input_since: u64,
    pub descriptor_hex: String,
    pub descriptor_commitment: String,
    pub resolution_witness_hex: String,
    pub resolved_capacities: [u64; 2],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredConditionalParticipant {
    pub settlement_lock_hash: String,
    pub settled_capacity: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredConditionalTransfer {
    pub transfer_id: String,
    pub payer_lock_hash: String,
    pub hash_algorithm: ConditionalHashAlgorithm,
    pub payment_hash: String,
    pub amount: u64,
    pub refund_after_block: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum StoredConditionalResolution {
    Fulfill {
        transfer_id: String,
        preimage: String,
    },
    Refund {
        transfer_id: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ConditionalBatchPackageSummary {
    pub schema: String,
    pub batch_id: String,
    pub transfer_count: usize,
    pub total_capacity: u64,
    pub descriptor_commitment: String,
    pub input_since: u64,
    pub resolved_capacities: [u64; 2],
}

impl StoredConditionalBatchPackage {
    pub fn validate(&self) -> Result<ConditionalBatchPackageSummary> {
        ensure!(
            self.schema == CONDITIONAL_BATCH_PACKAGE_SCHEMA,
            "unsupported conditional package schema {}",
            self.schema
        );
        ensure!(
            self.participants.len() == 2,
            "conditional package must contain exactly two participants"
        );
        let channel_id = parse_hex32("channel_id", &self.channel_id)?;
        let funding_context_id = parse_hex32("funding_context_id", &self.funding_context_id)?;
        let application_context_commitment = parse_hex32(
            "application_context_commitment",
            &self.application_context_commitment,
        )?;
        let batch = ConditionalBatch {
            batch_id: parse_hex32("batch_id", &self.batch_id)?,
            application_context_commitment,
            participants: [
                parse_participant(&self.participants[0])?,
                parse_participant(&self.participants[1])?,
            ],
            transfers: self
                .transfers
                .iter()
                .map(parse_transfer)
                .collect::<Result<Vec<_>>>()?,
        };
        ensure!(
            batch.batch_id
                == derive_conditional_batch_id(
                    &channel_id,
                    &funding_context_id,
                    self.state_number,
                    &application_context_commitment,
                ),
            "batch_id does not match its channel, funding context, state number, and application context"
        );
        let descriptor = batch.encode_descriptor()?;
        ensure!(
            decode_hex_exact(
                "descriptor_hex",
                &self.descriptor_hex,
                BILATERAL_CKB_CONDITIONAL_DESCRIPTOR_LEN,
            )? == descriptor,
            "descriptor_hex does not match the canonical package fields"
        );
        let descriptor_commitment = blake2b256(&descriptor);
        ensure!(
            parse_hex32("descriptor_commitment", &self.descriptor_commitment)?
                == descriptor_commitment,
            "descriptor_commitment does not match descriptor_hex"
        );

        let resolutions = parse_resolutions(&self.resolutions)?;
        let witness = batch.encode_resolution_witness(&resolutions)?;
        ensure!(
            decode_hex_exact(
                "resolution_witness_hex",
                &self.resolution_witness_hex,
                CONDITIONAL_BATCH_RESOLUTION_WITNESS_LEN,
            )? == witness,
            "resolution_witness_hex does not match the canonical resolutions"
        );
        let resolved_capacities = batch.resolve(&resolutions, self.input_since)?;
        ensure!(
            self.resolved_capacities == resolved_capacities,
            "resolved_capacities do not match the enforced resolution"
        );
        Ok(ConditionalBatchPackageSummary {
            schema: self.schema.clone(),
            batch_id: canonical_hex(&batch.batch_id),
            transfer_count: batch.transfers.len(),
            total_capacity: batch.total_capacity()?,
            descriptor_commitment: canonical_hex(&descriptor_commitment),
            input_since: self.input_since,
            resolved_capacities,
        })
    }
}

pub fn read_package(path: &Path) -> Result<StoredConditionalBatchPackage> {
    let raw = fs::read(path)
        .with_context(|| format!("failed to read conditional package {}", path.display()))?;
    let package: StoredConditionalBatchPackage = serde_json::from_slice(&raw)
        .with_context(|| format!("failed to decode conditional package {}", path.display()))?;
    package.validate()?;
    Ok(package)
}

pub fn fixture_package() -> Result<StoredConditionalBatchPackage> {
    let alice_lock = [0x11; 32];
    let bob_lock = [0x22; 32];
    let channel_id = [0x21; 32];
    let funding_context_id = [0x23; 32];
    let state_number = 7;
    let application_context_commitment = [0x41; 32];
    let fulfill_preimage = [0x51; 32];
    let refund_preimage = [0x52; 32];
    let batch = ConditionalBatch {
        batch_id: derive_conditional_batch_id(
            &channel_id,
            &funding_context_id,
            state_number,
            &application_context_commitment,
        ),
        application_context_commitment,
        participants: [
            ConditionalParticipant {
                settlement_lock_hash: alice_lock,
                settled_capacity: 12_000_000_000,
            },
            ConditionalParticipant {
                settlement_lock_hash: bob_lock,
                settled_capacity: 7_000_000_000,
            },
        ],
        transfers: vec![
            ConditionalTransferSpec {
                transfer_id: [0x61; 32],
                payer_lock_hash: alice_lock,
                hash_algorithm: ConditionalHashAlgorithm::Sha256,
                payment_hash: derive_conditional_payment_hash(
                    ConditionalHashAlgorithm::Sha256,
                    &fulfill_preimage,
                )?,
                amount: 600_000_000,
                refund_after_block: 500,
            },
            ConditionalTransferSpec {
                transfer_id: [0x62; 32],
                payer_lock_hash: bob_lock,
                hash_algorithm: ConditionalHashAlgorithm::CkbBlake2b,
                payment_hash: derive_conditional_payment_hash(
                    ConditionalHashAlgorithm::CkbBlake2b,
                    &refund_preimage,
                )?,
                amount: 400_000_000,
                refund_after_block: 600,
            },
        ],
    };
    let resolutions = BTreeMap::from([
        (
            [0x61; 32],
            ConditionalResolution::Fulfill {
                preimage: fulfill_preimage,
            },
        ),
        ([0x62; 32], ConditionalResolution::Refund),
    ]);
    let descriptor = batch.encode_descriptor()?;
    let witness = batch.encode_resolution_witness(&resolutions)?;
    let input_since = 600;
    let package = StoredConditionalBatchPackage {
        schema: CONDITIONAL_BATCH_PACKAGE_SCHEMA.to_string(),
        channel_id: canonical_hex(&channel_id),
        funding_context_id: canonical_hex(&funding_context_id),
        state_number,
        batch_id: canonical_hex(&batch.batch_id),
        application_context_commitment: canonical_hex(&batch.application_context_commitment),
        participants: batch
            .participants
            .iter()
            .map(|participant| StoredConditionalParticipant {
                settlement_lock_hash: canonical_hex(&participant.settlement_lock_hash),
                settled_capacity: participant.settled_capacity,
            })
            .collect(),
        transfers: batch
            .transfers
            .iter()
            .map(|transfer| StoredConditionalTransfer {
                transfer_id: canonical_hex(&transfer.transfer_id),
                payer_lock_hash: canonical_hex(&transfer.payer_lock_hash),
                hash_algorithm: transfer.hash_algorithm,
                payment_hash: canonical_hex(&transfer.payment_hash),
                amount: transfer.amount,
                refund_after_block: transfer.refund_after_block,
            })
            .collect(),
        resolutions: vec![
            StoredConditionalResolution::Fulfill {
                transfer_id: canonical_hex(&[0x61; 32]),
                preimage: canonical_hex(&fulfill_preimage),
            },
            StoredConditionalResolution::Refund {
                transfer_id: canonical_hex(&[0x62; 32]),
            },
        ],
        input_since,
        descriptor_hex: canonical_hex(&descriptor),
        descriptor_commitment: canonical_hex(&blake2b256(&descriptor)),
        resolution_witness_hex: canonical_hex(&witness),
        resolved_capacities: batch.resolve(&resolutions, input_since)?,
    };
    package.validate()?;
    Ok(package)
}

fn parse_participant(value: &StoredConditionalParticipant) -> Result<ConditionalParticipant> {
    Ok(ConditionalParticipant {
        settlement_lock_hash: parse_hex32("settlement_lock_hash", &value.settlement_lock_hash)?,
        settled_capacity: value.settled_capacity,
    })
}

fn parse_transfer(value: &StoredConditionalTransfer) -> Result<ConditionalTransferSpec> {
    Ok(ConditionalTransferSpec {
        transfer_id: parse_hex32("transfer_id", &value.transfer_id)?,
        payer_lock_hash: parse_hex32("payer_lock_hash", &value.payer_lock_hash)?,
        hash_algorithm: value.hash_algorithm,
        payment_hash: parse_hex32("payment_hash", &value.payment_hash)?,
        amount: value.amount,
        refund_after_block: value.refund_after_block,
    })
}

fn parse_resolutions(
    values: &[StoredConditionalResolution],
) -> Result<BTreeMap<Bytes32, ConditionalResolution>> {
    let mut resolutions = BTreeMap::new();
    for value in values {
        let (transfer_id, resolution) = match value {
            StoredConditionalResolution::Fulfill {
                transfer_id,
                preimage,
            } => (
                parse_hex32("transfer_id", transfer_id)?,
                ConditionalResolution::Fulfill {
                    preimage: parse_hex32("preimage", preimage)?,
                },
            ),
            StoredConditionalResolution::Refund { transfer_id } => (
                parse_hex32("transfer_id", transfer_id)?,
                ConditionalResolution::Refund,
            ),
        };
        ensure!(
            resolutions.insert(transfer_id, resolution).is_none(),
            "duplicate resolution for {}",
            canonical_hex(&transfer_id)
        );
    }
    Ok(resolutions)
}

fn parse_hex32(label: &str, value: &str) -> Result<Bytes32> {
    decode_hex_exact(label, value, 32)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("{label} must contain exactly 32 bytes"))
}

fn decode_hex_exact(label: &str, value: &str, expected_len: usize) -> Result<Vec<u8>> {
    ensure!(value.starts_with("0x"), "{label} must start with 0x");
    ensure!(
        value.len() == 2 + expected_len * 2,
        "{label} must contain exactly {expected_len} bytes"
    );
    hex::decode(&value[2..]).with_context(|| format!("{label} is not valid hex"))
}

fn canonical_hex(value: &[u8]) -> String {
    format!("0x{}", hex::encode(value))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixture_is_self_validating() {
        let package = fixture_package().unwrap();
        let summary = package.validate().unwrap();
        assert_eq!(summary.transfer_count, 2);
        assert_eq!(summary.total_capacity, 20_000_000_000);
        assert_eq!(summary.resolved_capacities, [12_000_000_000, 8_000_000_000]);
    }

    #[test]
    fn tampered_resolution_witness_is_rejected() {
        let mut package = fixture_package().unwrap();
        package.resolution_witness_hex.replace_range(2..4, "ff");
        assert!(package.validate().is_err());
    }
}
