use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use anyhow::{Context, Result, ensure};
use k256::ecdsa::signature::hazmat::PrehashSigner;
use k256::ecdsa::{Signature, SigningKey};
use morph_core::{
    Bytes32, ConditionalBatch, ConditionalHashAlgorithm, ConditionalParticipant,
    ConditionalResolution, ConditionalTransferSpec, derive_conditional_batch_id,
    derive_conditional_payment_hash,
};
use morph_script_common::{
    BILATERAL_CKB_CONDITIONAL_DESCRIPTOR_LEN, BILATERAL_CKB_CONDITIONAL_DESCRIPTOR_VERSION,
    BILATERAL_SIGNATURE_COUNT, BILATERAL_SIGNATURE_THRESHOLD, BILATERAL_SIGNATURE_WITNESS_LEN,
    BILATERAL_SIGNATURE_WITNESS_VERSION, BilateralSignatureWitness,
    COMPRESSED_SECP256K1_PUBKEY_LEN, CONDITIONAL_BATCH_RESOLUTION_WITNESS_LEN, ECDSA_SIGNATURE_LEN,
    MORPH_PROTOCOL_VERSION, PHASE_SETTLING, SIGNATURE_SCHEME_SECP256K1_ECDSA_BLAKE2B,
    STATE_HEADER_LEN, STATE_LAYOUT_VERSION, STATE_MODE_BILATERAL_PLAINTEXT, StateHeader,
    StateHeaderInput, absolute_block_since, encode_state_header, funding_context_id,
    participants_commitment, settlement_descriptor_commitment, verify_bilateral_state_signatures,
};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

const CONDITIONAL_BATCH_PACKAGE_SCHEMA: &str = "morph.conditional_batch_package";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredConditionalBatchPackage {
    pub schema: String,
    pub channel_id: String,
    pub funding_context_id: String,
    #[serde(with = "u64_decimal")]
    pub state_number: u64,
    pub batch_id: String,
    pub application_context_commitment: String,
    pub participants: Vec<StoredConditionalParticipant>,
    pub transfers: Vec<StoredConditionalTransfer>,
    pub resolutions: Vec<StoredConditionalResolution>,
    #[serde(with = "u64_decimal")]
    pub input_since: u64,
    pub descriptor_hex: String,
    pub descriptor_commitment: String,
    pub resolution_witness_hex: String,
    #[serde(with = "u64_decimal_pair")]
    pub resolved_capacities: [u64; 2],
    /// Exact participant-signed StateHeader that commits `descriptor_hex`.
    pub signed_state_header_hex: String,
    /// Canonical bilateral signature witness for `signed_state_header_hex`.
    pub signed_state_witness_hex: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredConditionalParticipant {
    pub settlement_lock_hash: String,
    #[serde(with = "u64_decimal")]
    pub settled_capacity: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredConditionalTransfer {
    pub transfer_id: String,
    pub payer_lock_hash: String,
    pub hash_algorithm: ConditionalHashAlgorithm,
    pub payment_hash: String,
    #[serde(with = "u64_decimal")]
    pub amount: u64,
    #[serde(with = "u64_decimal")]
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
    #[serde(with = "u64_decimal")]
    pub total_capacity: u64,
    pub descriptor_commitment: String,
    #[serde(with = "u64_decimal")]
    pub input_since: u64,
    #[serde(with = "u64_decimal_pair")]
    pub resolved_capacities: [u64; 2],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConditionalBatchPlan {
    pub schema: String,
    pub application_context_commitment: String,
    pub participants: Vec<StoredConditionalParticipant>,
    pub transfers: Vec<StoredConditionalTransfer>,
    pub resolutions: Vec<StoredConditionalResolution>,
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
        let package_funding_context_id =
            parse_hex32("funding_context_id", &self.funding_context_id)?;
        let state_header_raw = decode_hex_exact(
            "signed_state_header_hex",
            &self.signed_state_header_hex,
            STATE_HEADER_LEN,
        )?;
        let state_witness_raw = decode_hex_exact(
            "signed_state_witness_hex",
            &self.signed_state_witness_hex,
            BILATERAL_SIGNATURE_WITNESS_LEN,
        )?;
        let state_header = StateHeader::parse(&state_header_raw).map_err(|error| {
            anyhow::anyhow!("conditional package StateHeader is invalid: {error:?}")
        })?;
        state_header.validate_profile().map_err(|error| {
            anyhow::anyhow!("conditional package StateHeader profile is invalid: {error:?}")
        })?;
        let state_witness =
            BilateralSignatureWitness::parse(&state_witness_raw).map_err(|error| {
                anyhow::anyhow!("conditional package state witness is invalid: {error:?}")
            })?;
        verify_bilateral_state_signatures(&state_header, &state_witness).map_err(|error| {
            anyhow::anyhow!("conditional package state signatures are invalid: {error:?}")
        })?;
        ensure!(
            state_header.phase() == PHASE_SETTLING,
            "conditional package StateHeader must be settling"
        );
        ensure!(
            state_header.descriptor_version() == BILATERAL_CKB_CONDITIONAL_DESCRIPTOR_VERSION,
            "conditional package StateHeader must use descriptor v3"
        );
        ensure!(
            state_header.channel_id() == channel_id,
            "conditional package channel_id does not match signed StateHeader"
        );
        ensure!(
            state_header.state_number() == self.state_number,
            "conditional package state_number does not match signed StateHeader"
        );
        ensure!(
            funding_context_id(
                state_header.chain_id(),
                state_header.channel_id(),
                state_header.funding_anchor(),
                state_header.vault_set_commitment(),
                state_header.vault_outpoint_commitment(),
            ) == package_funding_context_id,
            "conditional package funding_context_id does not match signed StateHeader"
        );
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
                    &package_funding_context_id,
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
        let descriptor_commitment = settlement_descriptor_commitment(&descriptor);
        ensure!(
            parse_hex32("descriptor_commitment", &self.descriptor_commitment)?
                == descriptor_commitment,
            "descriptor_commitment does not match descriptor_hex"
        );
        ensure!(
            state_header.settlement_descriptor_commitment() == descriptor_commitment,
            "descriptor_commitment does not match signed StateHeader"
        );

        let resolutions = parse_resolutions(&self.resolutions)?;
        let canonical_since = canonical_resolution_since(&batch, &resolutions)?;
        ensure!(
            self.input_since == canonical_since,
            "input_since must be the canonical maximum refund height, or zero when all transfers fulfill"
        );
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

    pub fn same_authorization(&self, other: &Self) -> bool {
        self.schema == other.schema
            && self.channel_id == other.channel_id
            && self.funding_context_id == other.funding_context_id
            && self.state_number == other.state_number
            && self.batch_id == other.batch_id
            && self.application_context_commitment == other.application_context_commitment
            && self.participants == other.participants
            && self.transfers == other.transfers
            && self.descriptor_hex == other.descriptor_hex
            && self.descriptor_commitment == other.descriptor_commitment
            && self.signed_state_header_hex == other.signed_state_header_hex
            && self.signed_state_witness_hex == other.signed_state_witness_hex
    }

    pub fn is_monotonic_replacement_for(&self, previous: &Self) -> Result<bool> {
        self.validate()?;
        previous.validate()?;
        if !self.same_authorization(previous) {
            return Ok(false);
        }
        let current = parse_resolutions(&self.resolutions)?;
        let old = parse_resolutions(&previous.resolutions)?;
        for (transfer_id, old_resolution) in old {
            let Some(new_resolution) = current.get(&transfer_id) else {
                return Ok(false);
            };
            if let ConditionalResolution::Fulfill { preimage } = old_resolution
                && new_resolution != &(ConditionalResolution::Fulfill { preimage })
            {
                return Ok(false);
            }
        }
        Ok(true)
    }

    pub fn signed_state_header_bytes(&self) -> Result<Vec<u8>> {
        decode_hex_exact(
            "signed_state_header_hex",
            &self.signed_state_header_hex,
            STATE_HEADER_LEN,
        )
    }

    pub fn signed_state_witness_bytes(&self) -> Result<Vec<u8>> {
        decode_hex_exact(
            "signed_state_witness_hex",
            &self.signed_state_witness_hex,
            BILATERAL_SIGNATURE_WITNESS_LEN,
        )
    }

    pub fn descriptor_bytes(&self) -> Result<Vec<u8>> {
        decode_hex_exact(
            "descriptor_hex",
            &self.descriptor_hex,
            BILATERAL_CKB_CONDITIONAL_DESCRIPTOR_LEN,
        )
    }

    pub fn resolution_witness_bytes(&self) -> Result<Vec<u8>> {
        decode_hex_exact(
            "resolution_witness_hex",
            &self.resolution_witness_hex,
            CONDITIONAL_BATCH_RESOLUTION_WITNESS_LEN,
        )
    }

    /// Adds one newly learned preimage while preserving the exact signed authorization.
    pub fn with_fulfillment(&self, transfer_id: Bytes32, preimage: Bytes32) -> Result<Self> {
        self.validate()?;
        let channel_id = parse_hex32("channel_id", &self.channel_id)?;
        let funding_context_id = parse_hex32("funding_context_id", &self.funding_context_id)?;
        let batch =
            conditional_batch_from_stored(self, channel_id, funding_context_id, self.state_number)?;
        let mut resolutions = parse_resolutions(&self.resolutions)?;
        let previous = resolutions
            .get_mut(&transfer_id)
            .ok_or_else(|| anyhow::anyhow!("conditional transfer is not present in the package"))?;
        ensure!(
            matches!(previous, ConditionalResolution::Refund),
            "conditional transfer is already fulfilled"
        );
        *previous = ConditionalResolution::Fulfill { preimage };
        let replacement = package_from_signed_state(
            &self.signed_state_header_bytes()?,
            &self.signed_state_witness_bytes()?,
            &batch,
            &resolutions,
        )?;
        ensure!(
            replacement.is_monotonic_replacement_for(self)?,
            "conditional replacement is not monotonic"
        );
        Ok(replacement)
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

pub fn write_package(path: &Path, package: &StoredConditionalBatchPackage) -> Result<()> {
    package.validate()?;
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    let raw = serde_json::to_vec_pretty(package)?;
    let temporary = crate::packages::atomic_json_tmp_path(path);
    fs::write(&temporary, raw)
        .with_context(|| format!("failed to write {}", temporary.display()))?;
    fs::rename(&temporary, path).with_context(|| {
        format!(
            "failed to atomically replace {} with {}",
            path.display(),
            temporary.display()
        )
    })?;
    Ok(())
}

pub fn read_plan(path: &Path) -> Result<ConditionalBatchPlan> {
    let raw = fs::read(path)
        .with_context(|| format!("failed to read conditional plan {}", path.display()))?;
    let plan: ConditionalBatchPlan = serde_json::from_slice(&raw)
        .with_context(|| format!("failed to decode conditional plan {}", path.display()))?;
    ensure!(
        plan.schema == "morph.conditional_batch_plan",
        "unsupported conditional plan schema {}",
        plan.schema
    );
    ensure!(
        plan.participants.len() == 2,
        "conditional plan must contain exactly two participants"
    );
    Ok(plan)
}

pub fn batch_from_plan(
    plan: &ConditionalBatchPlan,
    channel_id: Bytes32,
    funding_context_id: Bytes32,
    state_number: u64,
) -> Result<ConditionalBatch> {
    let application_context_commitment = parse_hex32(
        "application_context_commitment",
        &plan.application_context_commitment,
    )?;
    let batch = ConditionalBatch {
        batch_id: derive_conditional_batch_id(
            &channel_id,
            &funding_context_id,
            state_number,
            &application_context_commitment,
        ),
        application_context_commitment,
        participants: [
            parse_participant(&plan.participants[0])?,
            parse_participant(&plan.participants[1])?,
        ],
        transfers: plan
            .transfers
            .iter()
            .map(parse_transfer)
            .collect::<Result<Vec<_>>>()?,
    };
    batch.validate()?;
    Ok(batch)
}

fn conditional_batch_from_stored(
    package: &StoredConditionalBatchPackage,
    channel_id: Bytes32,
    funding_context_id: Bytes32,
    state_number: u64,
) -> Result<ConditionalBatch> {
    ensure!(
        package.participants.len() == 2,
        "conditional package must contain exactly two participants"
    );
    let application_context_commitment = parse_hex32(
        "application_context_commitment",
        &package.application_context_commitment,
    )?;
    let batch = ConditionalBatch {
        batch_id: derive_conditional_batch_id(
            &channel_id,
            &funding_context_id,
            state_number,
            &application_context_commitment,
        ),
        application_context_commitment,
        participants: [
            parse_participant(&package.participants[0])?,
            parse_participant(&package.participants[1])?,
        ],
        transfers: package
            .transfers
            .iter()
            .map(parse_transfer)
            .collect::<Result<Vec<_>>>()?,
    };
    ensure!(
        canonical_hex(&batch.batch_id) == package.batch_id,
        "stored conditional batch id is not canonical"
    );
    batch.validate()?;
    Ok(batch)
}

pub fn resolutions_from_plan(
    plan: &ConditionalBatchPlan,
) -> Result<BTreeMap<Bytes32, ConditionalResolution>> {
    parse_resolutions(&plan.resolutions)
}

pub fn package_from_signed_state(
    signed_state_header: &[u8],
    signed_state_witness: &[u8],
    batch: &ConditionalBatch,
    resolutions: &BTreeMap<Bytes32, ConditionalResolution>,
) -> Result<StoredConditionalBatchPackage> {
    let state_header = StateHeader::parse(signed_state_header)
        .map_err(|error| anyhow::anyhow!("signed conditional StateHeader is invalid: {error:?}"))?;
    let descriptor = batch.encode_descriptor()?;
    let descriptor_commitment = settlement_descriptor_commitment(&descriptor);
    ensure!(
        state_header.descriptor_version() == BILATERAL_CKB_CONDITIONAL_DESCRIPTOR_VERSION
            && state_header.settlement_descriptor_commitment() == descriptor_commitment,
        "signed StateHeader does not commit the conditional descriptor"
    );
    let witness = batch.encode_resolution_witness(resolutions)?;
    let input_since = canonical_resolution_since(batch, resolutions)?;
    let funding_context = funding_context_id(
        state_header.chain_id(),
        state_header.channel_id(),
        state_header.funding_anchor(),
        state_header.vault_set_commitment(),
        state_header.vault_outpoint_commitment(),
    );
    let package = StoredConditionalBatchPackage {
        schema: CONDITIONAL_BATCH_PACKAGE_SCHEMA.to_string(),
        channel_id: canonical_hex(state_header.channel_id()),
        funding_context_id: canonical_hex(&funding_context),
        state_number: state_header.state_number(),
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
        resolutions: stored_resolutions(batch, resolutions)?,
        input_since,
        descriptor_hex: canonical_hex(&descriptor),
        descriptor_commitment: canonical_hex(&descriptor_commitment),
        resolution_witness_hex: canonical_hex(&witness),
        resolved_capacities: batch.resolve(resolutions, input_since)?,
        signed_state_header_hex: canonical_hex(signed_state_header),
        signed_state_witness_hex: canonical_hex(signed_state_witness),
    };
    package.validate()?;
    Ok(package)
}

pub fn fixture_package() -> Result<StoredConditionalBatchPackage> {
    let alice_lock = [0x11; 32];
    let bob_lock = [0x22; 32];
    let channel_id = [0x21; 32];
    let chain_id = [0x20; 32];
    let funding_anchor = [0x23; 32];
    let vault_set_commitment = [0x24; 32];
    let vault_outpoint_commitment = [0x25; 32];
    let funding_context_id = funding_context_id(
        &chain_id,
        &channel_id,
        &funding_anchor,
        &vault_set_commitment,
        &vault_outpoint_commitment,
    );
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
    let alice_key = SigningKey::from_slice(&[1u8; 32])
        .map_err(|error| anyhow::anyhow!("fixture Alice key is invalid: {error:?}"))?;
    let bob_key = SigningKey::from_slice(&[2u8; 32])
        .map_err(|error| anyhow::anyhow!("fixture Bob key is invalid: {error:?}"))?;
    let mut signing_keys = [alice_key, bob_key];
    signing_keys.sort_by_key(compressed_pubkey);
    let pubkeys = [
        compressed_pubkey(&signing_keys[0]),
        compressed_pubkey(&signing_keys[1]),
    ];
    let state_header = encode_state_header(&StateHeaderInput {
        protocol_version: MORPH_PROTOCOL_VERSION,
        chain_id,
        signature_scheme_id: SIGNATURE_SCHEME_SECP256K1_ECDSA_BLAKE2B,
        channel_id,
        funding_epoch: 1,
        funding_anchor,
        vault_set_commitment,
        state_number,
        mode: STATE_MODE_BILATERAL_PLAINTEXT,
        phase: PHASE_SETTLING,
        participants_commitment: participants_commitment(
            BILATERAL_SIGNATURE_THRESHOLD,
            &[pubkeys[0].as_slice(), pubkeys[1].as_slice()],
        ),
        asset_registry_commitment: [0x26; 32],
        settlement_descriptor_commitment: settlement_descriptor_commitment(&descriptor),
        descriptor_version: BILATERAL_CKB_CONDITIONAL_DESCRIPTOR_VERSION,
        vault_materialisation_root: [0x27; 32],
        challenge_policy_commitment: [0x28; 32],
        state_layout_version: STATE_LAYOUT_VERSION,
        vault_outpoint_commitment,
    });
    let state_witness = sign_state_witness(&state_header, &signing_keys)?;
    package_from_signed_state(&state_header, &state_witness, &batch, &resolutions)
}

fn parse_participant(value: &StoredConditionalParticipant) -> Result<ConditionalParticipant> {
    Ok(ConditionalParticipant {
        settlement_lock_hash: parse_hex32("settlement_lock_hash", &value.settlement_lock_hash)?,
        settled_capacity: value.settled_capacity,
    })
}

fn compressed_pubkey(key: &SigningKey) -> [u8; COMPRESSED_SECP256K1_PUBKEY_LEN] {
    let encoded = key.verifying_key().to_encoded_point(true);
    let mut pubkey = [0u8; COMPRESSED_SECP256K1_PUBKEY_LEN];
    pubkey.copy_from_slice(encoded.as_bytes());
    pubkey
}

fn sign_state_witness(
    state_header: &[u8],
    signing_keys: &[SigningKey; 2],
) -> Result<[u8; BILATERAL_SIGNATURE_WITNESS_LEN]> {
    let header = StateHeader::parse(state_header)
        .map_err(|error| anyhow::anyhow!("conditional StateHeader is invalid: {error:?}"))?;
    let mut witness = [0u8; BILATERAL_SIGNATURE_WITNESS_LEN];
    witness[0..2].copy_from_slice(&BILATERAL_SIGNATURE_WITNESS_VERSION.to_le_bytes());
    witness[2] = BILATERAL_SIGNATURE_THRESHOLD;
    witness[3] = BILATERAL_SIGNATURE_COUNT;
    for (index, key) in signing_keys.iter().enumerate() {
        let pubkey = compressed_pubkey(key);
        let signature: Signature = key
            .sign_prehash(&header.signing_digest())
            .map_err(|error| {
                anyhow::anyhow!("failed to sign conditional StateHeader: {error:?}")
            })?;
        let offset = 4 + index * (COMPRESSED_SECP256K1_PUBKEY_LEN + ECDSA_SIGNATURE_LEN);
        witness[offset..offset + COMPRESSED_SECP256K1_PUBKEY_LEN].copy_from_slice(&pubkey);
        witness[offset + COMPRESSED_SECP256K1_PUBKEY_LEN
            ..offset + COMPRESSED_SECP256K1_PUBKEY_LEN + ECDSA_SIGNATURE_LEN]
            .copy_from_slice(signature.to_bytes().as_ref());
    }
    Ok(witness)
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

fn stored_resolutions(
    batch: &ConditionalBatch,
    resolutions: &BTreeMap<Bytes32, ConditionalResolution>,
) -> Result<Vec<StoredConditionalResolution>> {
    batch
        .transfers
        .iter()
        .map(|transfer| {
            let resolution = resolutions
                .get(&transfer.transfer_id)
                .ok_or_else(|| anyhow::anyhow!("missing resolution for conditional transfer"))?;
            Ok(match resolution {
                ConditionalResolution::Fulfill { preimage } => {
                    StoredConditionalResolution::Fulfill {
                        transfer_id: canonical_hex(&transfer.transfer_id),
                        preimage: canonical_hex(preimage),
                    }
                }
                ConditionalResolution::Refund => StoredConditionalResolution::Refund {
                    transfer_id: canonical_hex(&transfer.transfer_id),
                },
            })
        })
        .collect()
}

fn canonical_resolution_since(
    batch: &ConditionalBatch,
    resolutions: &BTreeMap<Bytes32, ConditionalResolution>,
) -> Result<u64> {
    ensure!(
        resolutions.len() == batch.transfers.len(),
        "conditional package must resolve every transfer exactly once"
    );
    let mut refund_block = 0u64;
    for transfer in &batch.transfers {
        match resolutions.get(&transfer.transfer_id) {
            Some(ConditionalResolution::Refund) => {
                refund_block = refund_block.max(transfer.refund_after_block);
            }
            Some(ConditionalResolution::Fulfill { .. }) => {}
            None => anyhow::bail!("missing resolution for conditional transfer"),
        }
    }
    absolute_block_since(refund_block)
        .map_err(|error| anyhow::anyhow!("conditional input_since is invalid: {error:?}"))
}

mod u64_decimal {
    use super::*;

    pub fn serialize<S>(value: &u64, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&value.to_string())
    }

    pub fn deserialize<'de, D>(deserializer: D) -> std::result::Result<u64, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        if value.is_empty()
            || (value.len() > 1 && value.starts_with('0'))
            || !value.bytes().all(|byte| byte.is_ascii_digit())
        {
            return Err(serde::de::Error::custom(
                "u64 values must be canonical unsigned decimal strings",
            ));
        }
        value.parse().map_err(serde::de::Error::custom)
    }
}

mod u64_decimal_pair {
    use super::*;

    pub fn serialize<S>(value: &[u64; 2], serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        [value[0].to_string(), value[1].to_string()].serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> std::result::Result<[u64; 2], D::Error>
    where
        D: Deserializer<'de>,
    {
        let values = <[String; 2]>::deserialize(deserializer)?;
        let parse = |value: &str| {
            if value.is_empty()
                || (value.len() > 1 && value.starts_with('0'))
                || !value.bytes().all(|byte| byte.is_ascii_digit())
            {
                return Err(serde::de::Error::custom(
                    "u64 values must be canonical unsigned decimal strings",
                ));
            }
            value.parse().map_err(serde::de::Error::custom)
        };
        Ok([parse(&values[0])?, parse(&values[1])?])
    }
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

    #[test]
    fn descriptor_commitment_uses_the_wire_domain() {
        let package = fixture_package().unwrap();
        let descriptor = package.descriptor_bytes().unwrap();
        assert_eq!(
            package.descriptor_commitment,
            canonical_hex(&settlement_descriptor_commitment(&descriptor))
        );
        assert_ne!(
            package.descriptor_commitment,
            canonical_hex(&morph_script_common::blake2b256(&[descriptor.as_slice()]))
        );
    }

    #[test]
    fn signed_authorization_and_canonical_since_are_load_bearing() {
        let mut package = fixture_package().unwrap();
        package.input_since = package.input_since.saturating_add(1);
        assert!(package.validate().is_err());

        let mut package = fixture_package().unwrap();
        package.signed_state_header_hex.replace_range(2..4, "ff");
        assert!(package.validate().is_err());
    }

    #[test]
    fn fulfillment_updates_are_monotonic_and_remove_unneeded_since() {
        let package = fixture_package().unwrap();
        let replacement = package.with_fulfillment([0x62; 32], [0x52; 32]).unwrap();
        assert_eq!(replacement.input_since, 0);
        assert!(replacement.is_monotonic_replacement_for(&package).unwrap());
        assert!(!package.is_monotonic_replacement_for(&replacement).unwrap());
        replacement.validate().unwrap();
    }

    #[test]
    fn u64_json_fields_are_lossless_decimal_strings() {
        let mut package = fixture_package().unwrap();
        package.state_number = u64::MAX;
        let value = serde_json::to_value(&package).unwrap();
        assert_eq!(value["state_number"], u64::MAX.to_string());
        assert_eq!(value["input_since"], package.input_since.to_string());

        let mut numeric = value.clone();
        numeric["state_number"] = serde_json::json!(7);
        assert!(serde_json::from_value::<StoredConditionalBatchPackage>(numeric).is_err());

        let mut leading_zero = value;
        leading_zero["state_number"] = serde_json::json!("07");
        assert!(serde_json::from_value::<StoredConditionalBatchPackage>(leading_zero).is_err());
    }
}
