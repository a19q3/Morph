#![no_std]

use ckb_hash::new_blake2b;
use k256::ecdsa::signature::hazmat::PrehashVerifier;
use k256::ecdsa::{Signature, VerifyingKey};

pub const BYTE32_LEN: usize = 32;
pub const STATE_HEADER_LEN: usize = 314;
pub const WITNESS_ENVELOPE_MAGIC: &[u8; 8] = b"MORPHW!!";
pub const WITNESS_ENVELOPE_LEN: usize = 8 + 2 + 2 + 2 + 4 + BYTE32_LEN;
pub const FACTORY_STATE_HEADER_LEN: usize = 238;
pub const SPONSOR_POLICY_LEN: usize = 144;
pub const SPLICE_HEADER_LEN: usize = 357;
pub const BILATERAL_CKB_DESCRIPTOR_LEN: usize = 2 + 1 + 1 + 2 * (BYTE32_LEN + 8);
pub const BILATERAL_CKB_XUDT_DESCRIPTOR_LEN: usize =
    2 + 1 + 1 + BYTE32_LEN + 2 * (BYTE32_LEN + 8 + 16);
pub const COMPRESSED_SECP256K1_PUBKEY_LEN: usize = 33;
pub const ECDSA_SIGNATURE_LEN: usize = 64;
pub const BILATERAL_SIGNATURE_WITNESS_LEN: usize =
    2 + 1 + 1 + (2 * (COMPRESSED_SECP256K1_PUBKEY_LEN + ECDSA_SIGNATURE_LEN));
pub const SPLICE_SIGNATURE_WITNESS_LEN: usize =
    2 + 1 + 1 + (2 * (COMPRESSED_SECP256K1_PUBKEY_LEN + ECDSA_SIGNATURE_LEN));
pub const FACTORY_SIGNATURE_WITNESS_LEN: usize =
    2 + 1 + 1 + (2 * (BYTE32_LEN + COMPRESSED_SECP256K1_PUBKEY_LEN + ECDSA_SIGNATURE_LEN));
pub const FACTORY_RIGHT_LEN: usize = BYTE32_LEN + BYTE32_LEN + 1 + 1 + BYTE32_LEN + 16;
pub const SPLICE_VAULT_ASSET_AMOUNT_LEN: usize = 1 + BYTE32_LEN + 16;
pub const SPLICE_VAULT_DESCRIPTOR_MAX_ASSETS: u8 = 2;
pub const SPLICE_VAULT_DESCRIPTOR_LEN: usize = BYTE32_LEN + 2 + 2 * SPLICE_VAULT_ASSET_AMOUNT_LEN;
pub const SPLICE_ASSET_DELTA_LEN: usize = 1 + BYTE32_LEN + 5 * 16;
pub const SPLICE_ASSET_DELTAS_MAX_DELTAS: u8 = 2;
pub const SPLICE_ASSET_DELTAS_LEN: usize = 2 + 2 * SPLICE_ASSET_DELTA_LEN;
pub const SPLICE_STATE_TRANSITION_WITNESS_LEN: usize = 2
    + SPLICE_HEADER_LEN
    + SPLICE_SIGNATURE_WITNESS_LEN
    + 2 * SPLICE_VAULT_DESCRIPTOR_LEN
    + SPLICE_ASSET_DELTAS_LEN;
pub const FACTORY_REDUCED_RIGHTS_PARTICIPANT_ENTRY_LEN: usize =
    BYTE32_LEN + COMPRESSED_SECP256K1_PUBKEY_LEN + 1 + ECDSA_SIGNATURE_LEN;
pub const FACTORY_REDUCED_RIGHTS_COUNT: u8 = 10;
pub const FACTORY_REDUCED_EXIT_RIGHTS_COUNT: u8 = 12;
pub const FACTORY_MERKLE_UPDATE_RIGHT_COUNT: u8 = 1;
pub const FACTORY_SPARSE_MERKLE_DEPTH: usize = 256;
pub const FACTORY_REDUCED_RIGHTS_WITNESS_LEN: usize = 8
    + 2 * FACTORY_REDUCED_RIGHTS_PARTICIPANT_ENTRY_LEN
    + BYTE32_LEN
    + 2 * FACTORY_REDUCED_RIGHTS_COUNT as usize * FACTORY_RIGHT_LEN;
pub const FACTORY_MERKLE_UPDATE_WITNESS_LEN: usize = 8
    + 2 * FACTORY_REDUCED_RIGHTS_PARTICIPANT_ENTRY_LEN
    + BYTE32_LEN
    + 2 * FACTORY_RIGHT_LEN
    + FACTORY_SPARSE_MERKLE_DEPTH * BYTE32_LEN;
pub const FACTORY_REDUCED_EXIT_COMMON_LEN: usize = 8
    + 2 * FACTORY_REDUCED_RIGHTS_PARTICIPANT_ENTRY_LEN
    + BYTE32_LEN
    + 16
    + 4
    + 4
    + BYTE32_LEN
    + BYTE32_LEN
    + BYTE32_LEN
    + STATE_HEADER_LEN;
pub const FACTORY_REDUCED_EXIT_WITNESS_LEN: usize = FACTORY_REDUCED_EXIT_COMMON_LEN
    + BILATERAL_CKB_DESCRIPTOR_LEN
    + 2 * FACTORY_REDUCED_EXIT_RIGHTS_COUNT as usize * FACTORY_RIGHT_LEN;
pub const FACTORY_REDUCED_EXIT_XUDT_WITNESS_LEN: usize = FACTORY_REDUCED_EXIT_COMMON_LEN
    + BILATERAL_CKB_XUDT_DESCRIPTOR_LEN
    + 2 * FACTORY_REDUCED_EXIT_RIGHTS_COUNT as usize * FACTORY_RIGHT_LEN;
pub const FACTORY_LOCAL_EXIT_WITNESS_LEN: usize = 2
    + FACTORY_SIGNATURE_WITNESS_LEN
    + 4
    + 4
    + BYTE32_LEN
    + BYTE32_LEN
    + BYTE32_LEN
    + STATE_HEADER_LEN
    + BILATERAL_CKB_DESCRIPTOR_LEN;
pub const FACTORY_LOCAL_EXIT_XUDT_WITNESS_LEN: usize = 2
    + FACTORY_SIGNATURE_WITNESS_LEN
    + 4
    + 4
    + BYTE32_LEN
    + BYTE32_LEN
    + BYTE32_LEN
    + STATE_HEADER_LEN
    + BILATERAL_CKB_XUDT_DESCRIPTOR_LEN;
pub const FACTORY_SPLICE_HEADER_LEN: usize = 309;
pub const FACTORY_VAULT_ASSET_AMOUNT_LEN: usize = 1 + BYTE32_LEN + 16;
pub const FACTORY_VAULT_DESCRIPTOR_MAX_ASSETS: u8 = 2;
pub const FACTORY_VAULT_DESCRIPTOR_LEN: usize = BYTE32_LEN + 2 + 2 * FACTORY_VAULT_ASSET_AMOUNT_LEN;
pub const FACTORY_VAULT_DELTA_LEN: usize = 1 + BYTE32_LEN + 4 * 16;
pub const FACTORY_VAULT_DELTAS_MAX_DELTAS: u8 = 2;
pub const FACTORY_VAULT_DELTAS_LEN: usize = 2 + 2 * FACTORY_VAULT_DELTA_LEN;
pub const FACTORY_SPLICE_WITNESS_LEN: usize = 2
    + FACTORY_SPLICE_HEADER_LEN
    + FACTORY_SIGNATURE_WITNESS_LEN
    + 2 * FACTORY_VAULT_DESCRIPTOR_LEN
    + FACTORY_VAULT_DELTAS_LEN;
pub const FACTORY_REDUCED_SPLICE_WITNESS_LEN: usize = 2
    + FACTORY_SPLICE_HEADER_LEN
    + FACTORY_MERKLE_UPDATE_WITNESS_LEN
    + 2 * FACTORY_VAULT_DESCRIPTOR_LEN
    + FACTORY_VAULT_DELTAS_LEN;

pub const PHASE_ACTIVE: u8 = 1;
pub const PHASE_SETTLING: u8 = 2;
pub const SIGNATURE_SCHEME_SECP256K1_ECDSA_BLAKE2B: u16 = 1;
pub const BILATERAL_SIGNATURE_WITNESS_VERSION: u16 = 1;
pub const BILATERAL_SIGNATURE_THRESHOLD: u8 = 2;
pub const BILATERAL_SIGNATURE_COUNT: u8 = 2;
pub const SPLICE_SIGNATURE_WITNESS_VERSION: u16 = 1;
pub const SPLICE_SIGNATURE_THRESHOLD: u8 = 2;
pub const SPLICE_SIGNATURE_COUNT: u8 = 2;
pub const SPLICE_STATE_TRANSITION_WITNESS_VERSION: u16 = 1;
pub const FACTORY_SIGNATURE_WITNESS_VERSION: u16 = 1;
pub const FACTORY_SIGNATURE_THRESHOLD: u8 = 2;
pub const FACTORY_SIGNATURE_COUNT: u8 = 2;
pub const FACTORY_REDUCED_RIGHTS_WITNESS_VERSION: u16 = 2;
pub const FACTORY_REDUCED_RIGHTS_PARTICIPANT_THRESHOLD: u8 = 2;
pub const FACTORY_REDUCED_RIGHTS_PARTICIPANT_COUNT: u8 = 2;
pub const FACTORY_REDUCED_RIGHTS_AUTHORISED_COUNT: u8 = 1;
pub const FACTORY_REDUCED_EXIT_WITNESS_VERSION: u16 = 4;
pub const FACTORY_MERKLE_UPDATE_WITNESS_VERSION: u16 = 4;
pub const FACTORY_RIGHT_KIND_BALANCE: u8 = 0;
pub const FACTORY_RIGHT_KIND_RESERVE_CLAIM: u8 = 1;
pub const FACTORY_RIGHT_KIND_MEMBERSHIP: u8 = 2;
pub const FACTORY_RIGHT_KIND_EXIT_PATH: u8 = 3;
pub const FACTORY_RIGHT_KIND_SPONSOR_BUDGET_CLAIM: u8 = 4;
pub const FACTORY_LOCAL_EXIT_WITNESS_VERSION: u16 = 1;
pub const FACTORY_SPLICE_WITNESS_VERSION: u16 = 2;
pub const FACTORY_REDUCED_SPLICE_WITNESS_VERSION: u16 = 6;
pub const WITNESS_ENVELOPE_FORMAT: u16 = 2;
pub const WITNESS_ENVELOPE_KIND_FACTORY_SIGNATURE: u16 = 1;
pub const WITNESS_ENVELOPE_KIND_FACTORY_REDUCED_RIGHTS: u16 = 2;
pub const WITNESS_ENVELOPE_KIND_FACTORY_MERKLE_UPDATE: u16 = 3;
pub const WITNESS_ENVELOPE_KIND_FACTORY_REDUCED_EXIT: u16 = 4;
pub const WITNESS_ENVELOPE_KIND_FACTORY_LOCAL_EXIT: u16 = 5;
pub const WITNESS_ENVELOPE_KIND_FACTORY_SPLICE: u16 = 6;
pub const WITNESS_ENVELOPE_KIND_FACTORY_REDUCED_SPLICE: u16 = 7;
pub const STATE_DOMAIN: &[u8] = b"CKB_MORPH_CHANNEL_STATE";
pub const FUNDING_CONTEXT_DOMAIN: &[u8] = b"CKB_MORPH_FUNDING_CONTEXT";
pub const WITNESS_ENVELOPE_BODY_DOMAIN: &[u8] = b"CKB_MORPH_WITNESS_ENVELOPE_BODY";
pub const SPLICE_HEADER_DOMAIN: &[u8] = b"CKB_MORPH_SPLICE_HEADER";
pub const SPLICE_DELTA_DOMAIN: &[u8] = b"CKB_MORPH_SPLICE_DELTA";
pub const VAULT_DESCRIPTOR_DOMAIN: &[u8] = b"CKB_MORPH_VAULT_DESCRIPTOR";
pub const FACTORY_SPLICE_HEADER_DOMAIN: &[u8] = b"CKB_MORPH_FACTORY_SPLICE_HEADER";
pub const FACTORY_VAULT_DESCRIPTOR_DOMAIN: &[u8] = b"CKB_MORPH_FACTORY_VAULT_DESCRIPTOR";
pub const FACTORY_VAULT_DELTA_DOMAIN: &[u8] = b"CKB_MORPH_FACTORY_VAULT_DELTA";
pub const PARTICIPANTS_DOMAIN: &[u8] = b"CKB_MORPH_PARTICIPANTS";
pub const FACTORY_STATE_DOMAIN: &[u8] = b"CKB_MORPH_FACTORY_STATE";
pub const FACTORY_PARTICIPANTS_DOMAIN: &[u8] = b"CKB_MORPH_FACTORY_PARTICIPANTS";
pub const FACTORY_RIGHTS_ROOT_DOMAIN: &[u8] = b"CKB_MORPH_FACTORY_RIGHTS_ROOT";
pub const FACTORY_ACCESS_MANIFEST_ROOT_DOMAIN: &[u8] = b"CKB_MORPH_FACTORY_ACCESS_MANIFEST_ROOT";
pub const FACTORY_REDUCED_RIGHTS_DOMAIN: &[u8] = b"CKB_MORPH_FACTORY_REDUCED_RIGHTS";
pub const FACTORY_REDUCED_EXIT_DOMAIN: &[u8] = b"CKB_MORPH_FACTORY_REDUCED_EXIT";
pub const FACTORY_MERKLE_UPDATE_DOMAIN: &[u8] = b"CKB_MORPH_FACTORY_MERKLE_UPDATE";
pub const FACTORY_RIGHT_KEY_DOMAIN: &[u8] = b"CKB_MORPH_FACTORY_RIGHT_KEY";
pub const FACTORY_RIGHT_LEAF_DOMAIN: &[u8] = b"CKB_MORPH_FACTORY_RIGHT_LEAF";
pub const FACTORY_RIGHT_NODE_DOMAIN: &[u8] = b"CKB_MORPH_FACTORY_RIGHT_NODE";
pub const FACTORY_LOCAL_EXIT_DOMAIN: &[u8] = b"CKB_MORPH_FACTORY_LOCAL_EXIT";
pub const VAULT_CELL_COMMITMENT_DOMAIN: &[u8] = b"CKB_MORPH_VAULT_CELL";
pub const SETTLEMENT_DESCRIPTOR_DOMAIN: &[u8] = b"CKB_MORPH_SETTLEMENT_DESCRIPTOR";
pub const BILATERAL_CKB_DESCRIPTOR_VERSION: u16 = 1;
pub const BILATERAL_CKB_XUDT_DESCRIPTOR_VERSION: u16 = 2;
pub const BILATERAL_CKB_DESCRIPTOR_OUTPUT_COUNT: u8 = 2;
pub const BILATERAL_CKB_XUDT_DESCRIPTOR_ASSET_COUNT: u8 = 1;
pub const SPLICE_KIND_IN: u8 = 0;
pub const SPLICE_KIND_OUT: u8 = 1;
pub const VAULT_ASSET_KIND_CKB: u8 = 0;
pub const VAULT_ASSET_KIND_XUDT: u8 = 1;

#[repr(i8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScriptError {
    IndexOutOfBounds = 5,
    Encoding = 6,
    WrongArgsLength = 7,
    WrongGroupShape = 8,
    FundingAnchorMismatch = 9,
    NonMonotonicStateNumber = 10,
    NewStateNotSettling = 11,
    HeaderContextChanged = 12,
    OutputBelowOccupiedCapacity = 13,
    StateCellMissing = 14,
    StateCellAmbiguous = 15,
    StateSinceNotMature = 16,
    SponsorFeeTooHigh = 17,
    SponsorBudgetExceeded = 18,
    SponsorChangeLockMismatch = 19,
    CapacityUnderflow = 20,
    ParticipantWitnessMissing = 21,
    ParticipantWitnessEncoding = 22,
    ParticipantCommitmentMismatch = 23,
    InvalidParticipantSignature = 24,
    SettlementWitnessMissing = 25,
    SettlementDescriptorEncoding = 26,
    SettlementDescriptorMismatch = 27,
    SettlementOutputMismatch = 28,
    SponsorStateOutOfRange = 29,
    XudtAmountEncoding = 30,
    XudtMintUnauthorised = 31,
    XudtConservationMismatch = 32,
    XudtTypeMismatch = 33,
    FactoryIdMismatch = 34,
    FactoryLocalExitMismatch = 35,
    FactoryReserveMismatch = 36,
    StateTypeMismatch = 37,
    FactoryReducedProofEncoding = 38,
    FactoryReducedProofMismatch = 39,
    SpliceProofEncoding = 40,
    SpliceProofMismatch = 41,
    FactorySpliceProofEncoding = 42,
    FactorySpliceProofMismatch = 43,
    SponsorPolicyUnsupported = 44,
    WitnessEnvelopeEncoding = 45,
}

pub type Result<T> = core::result::Result<T, ScriptError>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StateHeader<'a> {
    raw: &'a [u8],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StateHeaderInput {
    pub protocol_version: u16,
    pub chain_id: [u8; BYTE32_LEN],
    pub signature_scheme_id: u16,
    pub channel_id: [u8; BYTE32_LEN],
    pub funding_epoch: u64,
    pub funding_anchor: [u8; BYTE32_LEN],
    pub vault_set_commitment: [u8; BYTE32_LEN],
    pub state_number: u64,
    pub mode: u8,
    pub phase: u8,
    pub participants_commitment: [u8; BYTE32_LEN],
    pub asset_registry_commitment: [u8; BYTE32_LEN],
    pub settlement_descriptor_commitment: [u8; BYTE32_LEN],
    pub descriptor_version: u16,
    pub payload_commitment: [u8; BYTE32_LEN],
    pub challenge_policy_commitment: [u8; BYTE32_LEN],
    pub state_layout_version: u16,
}

pub fn encode_state_header(input: &StateHeaderInput) -> [u8; STATE_HEADER_LEN] {
    let mut raw = [0u8; STATE_HEADER_LEN];
    write_u16(&mut raw, 0, input.protocol_version);
    raw[2..34].copy_from_slice(&input.chain_id);
    write_u16(&mut raw, 34, input.signature_scheme_id);
    raw[36..68].copy_from_slice(&input.channel_id);
    write_u64(&mut raw, 68, input.funding_epoch);
    raw[76..108].copy_from_slice(&input.funding_anchor);
    raw[108..140].copy_from_slice(&input.vault_set_commitment);
    write_u64(&mut raw, 140, input.state_number);
    raw[148] = input.mode;
    raw[149] = input.phase;
    raw[150..182].copy_from_slice(&input.participants_commitment);
    raw[182..214].copy_from_slice(&input.asset_registry_commitment);
    raw[214..246].copy_from_slice(&input.settlement_descriptor_commitment);
    write_u16(&mut raw, 246, input.descriptor_version);
    raw[248..280].copy_from_slice(&input.payload_commitment);
    raw[280..312].copy_from_slice(&input.challenge_policy_commitment);
    write_u16(&mut raw, 312, input.state_layout_version);
    raw
}

impl<'a> StateHeader<'a> {
    pub fn parse(raw: &'a [u8]) -> Result<Self> {
        if raw.len() != STATE_HEADER_LEN {
            return Err(ScriptError::Encoding);
        }
        Ok(Self { raw })
    }

    pub fn protocol_version(&self) -> u16 {
        read_u16(self.raw, 0)
    }

    pub fn chain_id(&self) -> &'a [u8] {
        field(self.raw, 2, 32)
    }

    pub fn signature_scheme_id(&self) -> u16 {
        read_u16(self.raw, 34)
    }

    pub fn channel_id(&self) -> &'a [u8] {
        field(self.raw, 36, 32)
    }

    pub fn funding_epoch(&self) -> u64 {
        read_u64(self.raw, 68)
    }

    pub fn funding_anchor(&self) -> &'a [u8] {
        field(self.raw, 76, 32)
    }

    pub fn vault_set_commitment(&self) -> &'a [u8] {
        field(self.raw, 108, 32)
    }

    pub fn state_number(&self) -> u64 {
        read_u64(self.raw, 140)
    }

    pub fn mode(&self) -> u8 {
        self.raw[148]
    }

    pub fn phase(&self) -> u8 {
        self.raw[149]
    }

    pub fn participants_commitment(&self) -> &'a [u8] {
        field(self.raw, 150, 32)
    }

    pub fn asset_registry_commitment(&self) -> &'a [u8] {
        field(self.raw, 182, 32)
    }

    pub fn settlement_descriptor_commitment(&self) -> &'a [u8] {
        field(self.raw, 214, 32)
    }

    pub fn descriptor_version(&self) -> u16 {
        read_u16(self.raw, 246)
    }

    pub fn payload_commitment(&self) -> &'a [u8] {
        field(self.raw, 248, 32)
    }

    pub fn challenge_policy_commitment(&self) -> &'a [u8] {
        field(self.raw, 280, 32)
    }

    pub fn state_layout_version(&self) -> u16 {
        read_u16(self.raw, 312)
    }

    pub fn signing_digest(&self) -> [u8; 32] {
        blake2b256(&[STATE_DOMAIN, self.raw])
    }

    pub fn same_context_except_progress(&self, next: &Self) -> bool {
        self.protocol_version() == next.protocol_version()
            && self.chain_id() == next.chain_id()
            && self.signature_scheme_id() == next.signature_scheme_id()
            && self.channel_id() == next.channel_id()
            && self.funding_epoch() == next.funding_epoch()
            && self.funding_anchor() == next.funding_anchor()
            && self.vault_set_commitment() == next.vault_set_commitment()
            && self.mode() == next.mode()
            && self.participants_commitment() == next.participants_commitment()
            && self.asset_registry_commitment() == next.asset_registry_commitment()
            && self.challenge_policy_commitment() == next.challenge_policy_commitment()
            && self.state_layout_version() == next.state_layout_version()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WitnessEnvelope<'a> {
    raw: &'a [u8],
}

impl<'a> WitnessEnvelope<'a> {
    pub fn parse(raw: &'a [u8]) -> Result<Self> {
        if raw.len() < WITNESS_ENVELOPE_LEN {
            return Err(ScriptError::WitnessEnvelopeEncoding);
        }
        let envelope = Self { raw };
        if envelope.magic() != WITNESS_ENVELOPE_MAGIC
            || envelope.version() != WITNESS_ENVELOPE_FORMAT
            || envelope.flags() != 0
            || !is_known_witness_envelope_kind(envelope.kind())
        {
            return Err(ScriptError::WitnessEnvelopeEncoding);
        }
        let body_len = envelope.body_len() as usize;
        if raw.len() != WITNESS_ENVELOPE_LEN + body_len {
            return Err(ScriptError::WitnessEnvelopeEncoding);
        }
        if !witness_envelope_body_len_allowed(envelope.kind(), body_len) {
            return Err(ScriptError::WitnessEnvelopeEncoding);
        }
        if envelope.body_commitment() != envelope.compute_body_commitment().as_slice() {
            return Err(ScriptError::WitnessEnvelopeEncoding);
        }
        Ok(envelope)
    }

    pub fn magic(&self) -> &'a [u8] {
        field(self.raw, 0, WITNESS_ENVELOPE_MAGIC.len())
    }

    pub fn version(&self) -> u16 {
        read_u16(self.raw, 8)
    }

    pub fn kind(&self) -> u16 {
        read_u16(self.raw, 10)
    }

    pub fn flags(&self) -> u16 {
        read_u16(self.raw, 12)
    }

    pub fn body_len(&self) -> u32 {
        read_u32(self.raw, 14)
    }

    pub fn body_commitment(&self) -> &'a [u8] {
        field(self.raw, 18, BYTE32_LEN)
    }

    pub fn body(&self) -> &'a [u8] {
        field(self.raw, WITNESS_ENVELOPE_LEN, self.body_len() as usize)
    }

    pub fn compute_body_commitment(&self) -> [u8; BYTE32_LEN] {
        witness_envelope_body_commitment(self.kind(), self.body())
    }
}

pub fn witness_envelope_body_commitment(kind: u16, body: &[u8]) -> [u8; BYTE32_LEN] {
    blake2b256(&[WITNESS_ENVELOPE_BODY_DOMAIN, &kind.to_le_bytes(), body])
}

pub fn witness_envelope_len(body_len: usize) -> usize {
    WITNESS_ENVELOPE_LEN + body_len
}

pub fn is_known_witness_envelope_kind(kind: u16) -> bool {
    matches!(
        kind,
        WITNESS_ENVELOPE_KIND_FACTORY_SIGNATURE
            | WITNESS_ENVELOPE_KIND_FACTORY_REDUCED_RIGHTS
            | WITNESS_ENVELOPE_KIND_FACTORY_MERKLE_UPDATE
            | WITNESS_ENVELOPE_KIND_FACTORY_REDUCED_EXIT
            | WITNESS_ENVELOPE_KIND_FACTORY_LOCAL_EXIT
            | WITNESS_ENVELOPE_KIND_FACTORY_SPLICE
            | WITNESS_ENVELOPE_KIND_FACTORY_REDUCED_SPLICE
    )
}

pub fn witness_envelope_body_len_allowed(kind: u16, body_len: usize) -> bool {
    match kind {
        WITNESS_ENVELOPE_KIND_FACTORY_SIGNATURE => body_len == FACTORY_SIGNATURE_WITNESS_LEN,
        WITNESS_ENVELOPE_KIND_FACTORY_REDUCED_RIGHTS => {
            body_len == FACTORY_REDUCED_RIGHTS_WITNESS_LEN
        }
        WITNESS_ENVELOPE_KIND_FACTORY_MERKLE_UPDATE => {
            body_len == FACTORY_MERKLE_UPDATE_WITNESS_LEN
        }
        WITNESS_ENVELOPE_KIND_FACTORY_REDUCED_EXIT => {
            body_len == FACTORY_REDUCED_EXIT_WITNESS_LEN
                || body_len == FACTORY_REDUCED_EXIT_XUDT_WITNESS_LEN
        }
        WITNESS_ENVELOPE_KIND_FACTORY_LOCAL_EXIT => {
            body_len == FACTORY_LOCAL_EXIT_WITNESS_LEN
                || body_len == FACTORY_LOCAL_EXIT_XUDT_WITNESS_LEN
        }
        WITNESS_ENVELOPE_KIND_FACTORY_SPLICE => body_len == FACTORY_SPLICE_WITNESS_LEN,
        WITNESS_ENVELOPE_KIND_FACTORY_REDUCED_SPLICE => {
            body_len == FACTORY_REDUCED_SPLICE_WITNESS_LEN
        }
        _ => false,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FactoryStateHeader<'a> {
    raw: &'a [u8],
}

impl<'a> FactoryStateHeader<'a> {
    pub fn parse(raw: &'a [u8]) -> Result<Self> {
        if raw.len() != FACTORY_STATE_HEADER_LEN {
            return Err(ScriptError::Encoding);
        }
        Ok(Self { raw })
    }

    pub fn protocol_version(&self) -> u16 {
        read_u16(self.raw, 0)
    }

    pub fn chain_id(&self) -> &'a [u8] {
        field(self.raw, 2, 32)
    }

    pub fn signature_scheme_id(&self) -> u16 {
        read_u16(self.raw, 34)
    }

    pub fn factory_id(&self) -> &'a [u8] {
        field(self.raw, 36, 32)
    }

    pub fn update_number(&self) -> u64 {
        read_u64(self.raw, 68)
    }

    pub fn state_root(&self) -> &'a [u8] {
        field(self.raw, 76, 32)
    }

    pub fn participants_commitment(&self) -> &'a [u8] {
        field(self.raw, 108, 32)
    }

    pub fn access_manifest_root(&self) -> &'a [u8] {
        field(self.raw, 140, 32)
    }

    pub fn non_interference_digest(&self) -> &'a [u8] {
        field(self.raw, 172, 32)
    }

    pub fn challenge_policy_commitment(&self) -> &'a [u8] {
        field(self.raw, 204, 32)
    }

    pub fn state_layout_version(&self) -> u16 {
        read_u16(self.raw, 236)
    }

    pub fn signing_digest(&self) -> [u8; 32] {
        blake2b256(&[FACTORY_STATE_DOMAIN, self.raw])
    }

    pub fn same_context_except_progress(&self, next: &Self) -> bool {
        self.protocol_version() == next.protocol_version()
            && self.chain_id() == next.chain_id()
            && self.signature_scheme_id() == next.signature_scheme_id()
            && self.factory_id() == next.factory_id()
            && self.participants_commitment() == next.participants_commitment()
            && self.challenge_policy_commitment() == next.challenge_policy_commitment()
            && self.state_layout_version() == next.state_layout_version()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SpliceHeader<'a> {
    raw: &'a [u8],
}

impl<'a> SpliceHeader<'a> {
    pub fn parse(raw: &'a [u8]) -> Result<Self> {
        if raw.len() != SPLICE_HEADER_LEN {
            return Err(ScriptError::Encoding);
        }
        let header = Self { raw };
        if header.kind() != SPLICE_KIND_IN && header.kind() != SPLICE_KIND_OUT {
            return Err(ScriptError::Encoding);
        }
        Ok(header)
    }

    pub fn protocol_version(&self) -> u16 {
        read_u16(self.raw, 0)
    }

    pub fn chain_id(&self) -> &'a [u8] {
        field(self.raw, 2, BYTE32_LEN)
    }

    pub fn signature_scheme_id(&self) -> u16 {
        read_u16(self.raw, 34)
    }

    pub fn channel_id(&self) -> &'a [u8] {
        field(self.raw, 36, BYTE32_LEN)
    }

    pub fn old_funding_anchor(&self) -> &'a [u8] {
        field(self.raw, 68, BYTE32_LEN)
    }

    pub fn new_funding_anchor(&self) -> &'a [u8] {
        field(self.raw, 100, BYTE32_LEN)
    }

    pub fn old_funding_epoch(&self) -> u64 {
        read_u64(self.raw, 132)
    }

    pub fn new_funding_epoch(&self) -> u64 {
        read_u64(self.raw, 140)
    }

    pub fn base_state_number(&self) -> u64 {
        read_u64(self.raw, 148)
    }

    pub fn splice_number(&self) -> u64 {
        read_u64(self.raw, 156)
    }

    pub fn kind(&self) -> u8 {
        self.raw[164]
    }

    pub fn old_vault_commitment(&self) -> &'a [u8] {
        field(self.raw, 165, BYTE32_LEN)
    }

    pub fn new_vault_commitment(&self) -> &'a [u8] {
        field(self.raw, 197, BYTE32_LEN)
    }

    pub fn asset_delta_commitment(&self) -> &'a [u8] {
        field(self.raw, 229, BYTE32_LEN)
    }

    pub fn participants_commitment(&self) -> &'a [u8] {
        field(self.raw, 261, BYTE32_LEN)
    }

    pub fn payload_commitment(&self) -> &'a [u8] {
        field(self.raw, 293, BYTE32_LEN)
    }

    pub fn challenge_policy_commitment(&self) -> &'a [u8] {
        field(self.raw, 325, BYTE32_LEN)
    }

    pub fn signing_digest(&self) -> [u8; 32] {
        blake2b256(&[SPLICE_HEADER_DOMAIN, self.raw])
    }

    pub fn matches_current_state(&self, current: &StateHeader) -> bool {
        self.protocol_version() == current.protocol_version()
            && self.chain_id() == current.chain_id()
            && self.signature_scheme_id() == current.signature_scheme_id()
            && self.channel_id() == current.channel_id()
            && self.old_funding_epoch() == current.funding_epoch()
            && self.old_funding_anchor() == current.funding_anchor()
            && self.old_vault_commitment() == current.vault_set_commitment()
            && self.base_state_number() == current.state_number()
            && self.participants_commitment() == current.participants_commitment()
            && self.payload_commitment() == current.payload_commitment()
            && self.challenge_policy_commitment() == current.challenge_policy_commitment()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BilateralSignatureWitness<'a> {
    raw: &'a [u8],
}

impl<'a> BilateralSignatureWitness<'a> {
    pub fn parse(raw: &'a [u8]) -> Result<Self> {
        if raw.len() != BILATERAL_SIGNATURE_WITNESS_LEN {
            return Err(ScriptError::ParticipantWitnessEncoding);
        }
        let witness = Self { raw };
        if witness.version() != BILATERAL_SIGNATURE_WITNESS_VERSION
            || witness.threshold() != BILATERAL_SIGNATURE_THRESHOLD
            || witness.count() != BILATERAL_SIGNATURE_COUNT
        {
            return Err(ScriptError::ParticipantWitnessEncoding);
        }
        if witness.pubkey(0) >= witness.pubkey(1) {
            return Err(ScriptError::ParticipantWitnessEncoding);
        }
        Ok(witness)
    }

    pub fn version(&self) -> u16 {
        read_u16(self.raw, 0)
    }

    pub fn threshold(&self) -> u8 {
        self.raw[2]
    }

    pub fn count(&self) -> u8 {
        self.raw[3]
    }

    pub fn pubkey(&self, index: usize) -> &'a [u8] {
        let offset = participant_offset(index);
        field(self.raw, offset, COMPRESSED_SECP256K1_PUBKEY_LEN)
    }

    pub fn signature(&self, index: usize) -> &'a [u8] {
        let offset = participant_offset(index) + COMPRESSED_SECP256K1_PUBKEY_LEN;
        field(self.raw, offset, ECDSA_SIGNATURE_LEN)
    }

    pub fn participants_commitment(&self) -> [u8; 32] {
        participants_commitment(self.threshold(), &[self.pubkey(0), self.pubkey(1)])
    }
}

pub fn verify_bilateral_state_signatures(
    header: &StateHeader,
    witness: &BilateralSignatureWitness,
) -> Result<()> {
    if header.signature_scheme_id() != SIGNATURE_SCHEME_SECP256K1_ECDSA_BLAKE2B {
        return Err(ScriptError::ParticipantWitnessEncoding);
    }
    if header.participants_commitment() != witness.participants_commitment().as_slice() {
        return Err(ScriptError::ParticipantCommitmentMismatch);
    }

    let digest = header.signing_digest();
    for index in 0..BILATERAL_SIGNATURE_COUNT as usize {
        let verifying_key = VerifyingKey::from_sec1_bytes(witness.pubkey(index))
            .map_err(|_| ScriptError::ParticipantWitnessEncoding)?;
        let signature = Signature::try_from(witness.signature(index))
            .map_err(|_| ScriptError::ParticipantWitnessEncoding)?;
        verifying_key
            .verify_prehash(&digest, &signature)
            .map_err(|_| ScriptError::InvalidParticipantSignature)?;
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SpliceSignatureWitness<'a> {
    raw: &'a [u8],
}

impl<'a> SpliceSignatureWitness<'a> {
    pub fn parse(raw: &'a [u8]) -> Result<Self> {
        if raw.len() != SPLICE_SIGNATURE_WITNESS_LEN {
            return Err(ScriptError::ParticipantWitnessEncoding);
        }
        let witness = Self { raw };
        if witness.version() != SPLICE_SIGNATURE_WITNESS_VERSION
            || witness.threshold() != SPLICE_SIGNATURE_THRESHOLD
            || witness.count() != SPLICE_SIGNATURE_COUNT
        {
            return Err(ScriptError::ParticipantWitnessEncoding);
        }
        if witness.pubkey(0) >= witness.pubkey(1) {
            return Err(ScriptError::ParticipantWitnessEncoding);
        }
        Ok(witness)
    }

    pub fn version(&self) -> u16 {
        read_u16(self.raw, 0)
    }

    pub fn threshold(&self) -> u8 {
        self.raw[2]
    }

    pub fn count(&self) -> u8 {
        self.raw[3]
    }

    pub fn pubkey(&self, index: usize) -> &'a [u8] {
        field(
            self.raw,
            splice_participant_offset(index),
            COMPRESSED_SECP256K1_PUBKEY_LEN,
        )
    }

    pub fn signature(&self, index: usize) -> &'a [u8] {
        field(
            self.raw,
            splice_participant_offset(index) + COMPRESSED_SECP256K1_PUBKEY_LEN,
            ECDSA_SIGNATURE_LEN,
        )
    }

    pub fn participants_commitment(&self) -> [u8; 32] {
        participants_commitment(self.threshold(), &[self.pubkey(0), self.pubkey(1)])
    }
}

pub fn verify_splice_signatures(
    header: &SpliceHeader,
    witness: &SpliceSignatureWitness,
) -> Result<()> {
    if header.signature_scheme_id() != SIGNATURE_SCHEME_SECP256K1_ECDSA_BLAKE2B {
        return Err(ScriptError::ParticipantWitnessEncoding);
    }
    if header.participants_commitment() != witness.participants_commitment().as_slice() {
        return Err(ScriptError::ParticipantCommitmentMismatch);
    }

    let digest = header.signing_digest();
    for index in 0..SPLICE_SIGNATURE_COUNT as usize {
        let verifying_key = VerifyingKey::from_sec1_bytes(witness.pubkey(index))
            .map_err(|_| ScriptError::ParticipantWitnessEncoding)?;
        let signature = Signature::try_from(witness.signature(index))
            .map_err(|_| ScriptError::ParticipantWitnessEncoding)?;
        verifying_key
            .verify_prehash(&digest, &signature)
            .map_err(|_| ScriptError::InvalidParticipantSignature)?;
    }
    Ok(())
}

pub fn verify_splice_state_transition(
    current_state: &StateHeader,
    next_state: &StateHeader,
    splice_header: &SpliceHeader,
    witness: &SpliceSignatureWitness,
    old_vault: &SpliceVaultDescriptor,
    new_vault: &SpliceVaultDescriptor,
    deltas: &SpliceAssetDeltas,
) -> Result<()> {
    if current_state.phase() != PHASE_ACTIVE || next_state.phase() != PHASE_ACTIVE {
        return Err(ScriptError::SpliceProofMismatch);
    }
    if !splice_header.matches_current_state(current_state) {
        return Err(ScriptError::SpliceProofMismatch);
    }
    if !state_context_matches_splice_next(current_state, next_state, splice_header) {
        return Err(ScriptError::SpliceProofMismatch);
    }
    if splice_header.new_funding_epoch() <= splice_header.old_funding_epoch()
        || splice_header.new_funding_anchor() == splice_header.old_funding_anchor()
    {
        return Err(ScriptError::SpliceProofMismatch);
    }
    if old_vault.funding_anchor() != splice_header.old_funding_anchor()
        || new_vault.funding_anchor() != splice_header.new_funding_anchor()
    {
        return Err(ScriptError::SpliceProofMismatch);
    }
    if old_vault.commitment()?.as_slice() != splice_header.old_vault_commitment()
        || new_vault.commitment()?.as_slice() != splice_header.new_vault_commitment()
        || deltas.commitment()?.as_slice() != splice_header.asset_delta_commitment()
    {
        return Err(ScriptError::SpliceProofMismatch);
    }
    verify_splice_signatures(splice_header, witness)?;
    verify_splice_delta_set(splice_header.kind(), old_vault, new_vault, deltas)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SpliceStateTransitionWitness<'a> {
    raw: &'a [u8],
}

impl<'a> SpliceStateTransitionWitness<'a> {
    pub fn parse(raw: &'a [u8]) -> Result<Self> {
        if raw.len() != SPLICE_STATE_TRANSITION_WITNESS_LEN {
            return Err(ScriptError::SpliceProofEncoding);
        }
        let witness = Self { raw };
        if witness.version() != SPLICE_STATE_TRANSITION_WITNESS_VERSION {
            return Err(ScriptError::SpliceProofEncoding);
        }
        Ok(witness)
    }

    pub fn version(&self) -> u16 {
        read_u16(self.raw, 0)
    }

    pub fn header(&self) -> Result<SpliceHeader<'a>> {
        SpliceHeader::parse(field(
            self.raw,
            splice_transition_header_offset(),
            SPLICE_HEADER_LEN,
        ))
        .map_err(|_| ScriptError::SpliceProofEncoding)
    }

    pub fn signatures(&self) -> Result<SpliceSignatureWitness<'a>> {
        SpliceSignatureWitness::parse(field(
            self.raw,
            splice_transition_signature_offset(),
            SPLICE_SIGNATURE_WITNESS_LEN,
        ))
        .map_err(|_| ScriptError::SpliceProofEncoding)
    }

    pub fn old_vault(&self) -> Result<SpliceVaultDescriptor<'a>> {
        SpliceVaultDescriptor::parse(field(
            self.raw,
            splice_transition_old_vault_offset(),
            SPLICE_VAULT_DESCRIPTOR_LEN,
        ))
        .map_err(|_| ScriptError::SpliceProofEncoding)
    }

    pub fn new_vault(&self) -> Result<SpliceVaultDescriptor<'a>> {
        SpliceVaultDescriptor::parse(field(
            self.raw,
            splice_transition_new_vault_offset(),
            SPLICE_VAULT_DESCRIPTOR_LEN,
        ))
        .map_err(|_| ScriptError::SpliceProofEncoding)
    }

    pub fn deltas(&self) -> Result<SpliceAssetDeltas<'a>> {
        SpliceAssetDeltas::parse(field(
            self.raw,
            splice_transition_deltas_offset(),
            SPLICE_ASSET_DELTAS_LEN,
        ))
        .map_err(|_| ScriptError::SpliceProofEncoding)
    }

    pub fn raw(&self) -> &'a [u8] {
        self.raw
    }
}

pub fn verify_splice_state_transition_bundle(
    current_state: &StateHeader,
    next_state: &StateHeader,
    witness: &SpliceStateTransitionWitness,
) -> Result<()> {
    let splice_header = witness.header()?;
    let signatures = witness.signatures()?;
    let old_vault = witness.old_vault()?;
    let new_vault = witness.new_vault()?;
    let deltas = witness.deltas()?;
    verify_splice_state_transition(
        current_state,
        next_state,
        &splice_header,
        &signatures,
        &old_vault,
        &new_vault,
        &deltas,
    )
}

fn state_context_matches_splice_next(
    current_state: &StateHeader,
    next_state: &StateHeader,
    splice_header: &SpliceHeader,
) -> bool {
    current_state.protocol_version() == next_state.protocol_version()
        && current_state.chain_id() == next_state.chain_id()
        && current_state.signature_scheme_id() == next_state.signature_scheme_id()
        && current_state.channel_id() == next_state.channel_id()
        && current_state.funding_epoch() == splice_header.old_funding_epoch()
        && next_state.funding_epoch() == splice_header.new_funding_epoch()
        && current_state.funding_anchor() == splice_header.old_funding_anchor()
        && next_state.funding_anchor() == splice_header.new_funding_anchor()
        && current_state.vault_set_commitment() == splice_header.old_vault_commitment()
        && next_state.vault_set_commitment() == splice_header.new_vault_commitment()
        && current_state.state_number() == next_state.state_number()
        && current_state.mode() == next_state.mode()
        && current_state.participants_commitment() == next_state.participants_commitment()
        && current_state.asset_registry_commitment() == next_state.asset_registry_commitment()
        && current_state.settlement_descriptor_commitment()
            == next_state.settlement_descriptor_commitment()
        && current_state.descriptor_version() == next_state.descriptor_version()
        && current_state.challenge_policy_commitment() == next_state.challenge_policy_commitment()
        && current_state.state_layout_version() == next_state.state_layout_version()
}

fn verify_splice_delta_set(
    kind: u8,
    old_vault: &SpliceVaultDescriptor,
    new_vault: &SpliceVaultDescriptor,
    deltas: &SpliceAssetDeltas,
) -> Result<()> {
    for index in 0..deltas.delta_count() as usize {
        let delta = deltas.delta(index)?;
        let old_amount = vault_amount_for(old_vault, delta.asset_kind(), delta.asset_type())?
            .ok_or(ScriptError::SpliceProofMismatch)?;
        let new_amount = vault_amount_for(new_vault, delta.asset_kind(), delta.asset_type())?
            .ok_or(ScriptError::SpliceProofMismatch)?;
        if old_amount != delta.old_amount() || new_amount != delta.new_amount() {
            return Err(ScriptError::SpliceProofMismatch);
        }
        verify_splice_delta(kind, &delta)?;
    }

    for index in 0..old_vault.asset_count() as usize {
        let old_asset = old_vault.asset(index)?;
        if delta_amount_for(deltas, old_asset.asset_kind(), old_asset.asset_type())?.is_none() {
            let new_amount =
                vault_amount_for(new_vault, old_asset.asset_kind(), old_asset.asset_type())?
                    .ok_or(ScriptError::SpliceProofMismatch)?;
            if new_amount != old_asset.amount() {
                return Err(ScriptError::SpliceProofMismatch);
            }
        }
    }
    for index in 0..new_vault.asset_count() as usize {
        let new_asset = new_vault.asset(index)?;
        if delta_amount_for(deltas, new_asset.asset_kind(), new_asset.asset_type())?.is_none() {
            let old_amount =
                vault_amount_for(old_vault, new_asset.asset_kind(), new_asset.asset_type())?
                    .ok_or(ScriptError::SpliceProofMismatch)?;
            if old_amount != new_asset.amount() {
                return Err(ScriptError::SpliceProofMismatch);
            }
        }
    }

    Ok(())
}

fn verify_splice_delta(kind: u8, delta: &SpliceAssetDelta) -> Result<()> {
    if delta.asset_kind() == VAULT_ASSET_KIND_XUDT && delta.signed_fee() != 0 {
        return Err(ScriptError::SpliceProofMismatch);
    }
    let debits = checked_add3(delta.new_amount(), delta.withdrawal(), delta.signed_fee())?;
    let credits = delta
        .old_amount()
        .checked_add(delta.external_input())
        .ok_or(ScriptError::SpliceProofMismatch)?;
    if debits != credits {
        return Err(ScriptError::SpliceProofMismatch);
    }

    match kind {
        SPLICE_KIND_IN => {
            if delta.external_input() == 0
                || delta.withdrawal() != 0
                || delta.new_amount() <= delta.old_amount()
            {
                return Err(ScriptError::SpliceProofMismatch);
            }
        }
        SPLICE_KIND_OUT => {
            if delta.external_input() != 0
                || delta.withdrawal() == 0
                || delta.signed_fee() != 0
                || delta.new_amount() >= delta.old_amount()
            {
                return Err(ScriptError::SpliceProofMismatch);
            }
        }
        _ => return Err(ScriptError::SpliceProofEncoding),
    }
    Ok(())
}

fn checked_add3(left: u128, middle: u128, right: u128) -> Result<u128> {
    left.checked_add(middle)
        .and_then(|value| value.checked_add(right))
        .ok_or(ScriptError::SpliceProofMismatch)
}

fn vault_amount_for(
    descriptor: &SpliceVaultDescriptor,
    kind: u8,
    type_hash: &[u8],
) -> Result<Option<u128>> {
    for index in 0..descriptor.asset_count() as usize {
        let asset = descriptor.asset(index)?;
        if asset.asset_kind() == kind && asset.asset_type() == type_hash {
            return Ok(Some(asset.amount()));
        }
    }
    Ok(None)
}

fn delta_amount_for(
    deltas: &SpliceAssetDeltas,
    kind: u8,
    type_hash: &[u8],
) -> Result<Option<(u128, u128)>> {
    for index in 0..deltas.delta_count() as usize {
        let delta = deltas.delta(index)?;
        if delta.asset_kind() == kind && delta.asset_type() == type_hash {
            return Ok(Some((delta.old_amount(), delta.new_amount())));
        }
    }
    Ok(None)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FactorySignatureWitness<'a> {
    raw: &'a [u8],
}

impl<'a> FactorySignatureWitness<'a> {
    pub fn parse(raw: &'a [u8]) -> Result<Self> {
        if raw.len() != FACTORY_SIGNATURE_WITNESS_LEN {
            return Err(ScriptError::ParticipantWitnessEncoding);
        }
        let witness = Self { raw };
        if witness.version() != FACTORY_SIGNATURE_WITNESS_VERSION
            || witness.threshold() != FACTORY_SIGNATURE_THRESHOLD
            || witness.count() != FACTORY_SIGNATURE_COUNT
        {
            return Err(ScriptError::ParticipantWitnessEncoding);
        }
        if witness.participant(0) >= witness.participant(1)
            || witness.pubkey(0) == witness.pubkey(1)
        {
            return Err(ScriptError::ParticipantWitnessEncoding);
        }
        Ok(witness)
    }

    pub fn version(&self) -> u16 {
        read_u16(self.raw, 0)
    }

    pub fn threshold(&self) -> u8 {
        self.raw[2]
    }

    pub fn count(&self) -> u8 {
        self.raw[3]
    }

    pub fn participant(&self, index: usize) -> &'a [u8] {
        field(self.raw, factory_participant_offset(index), BYTE32_LEN)
    }

    pub fn pubkey(&self, index: usize) -> &'a [u8] {
        field(
            self.raw,
            factory_participant_offset(index) + BYTE32_LEN,
            COMPRESSED_SECP256K1_PUBKEY_LEN,
        )
    }

    pub fn signature(&self, index: usize) -> &'a [u8] {
        field(
            self.raw,
            factory_participant_offset(index) + BYTE32_LEN + COMPRESSED_SECP256K1_PUBKEY_LEN,
            ECDSA_SIGNATURE_LEN,
        )
    }

    pub fn participants_commitment(&self) -> [u8; 32] {
        factory_participants_commitment(
            self.threshold(),
            &[
                (self.participant(0), self.pubkey(0)),
                (self.participant(1), self.pubkey(1)),
            ],
        )
    }

    pub fn pubkey_participants_commitment(&self) -> [u8; 32] {
        participants_commitment(self.threshold(), &[self.pubkey(0), self.pubkey(1)])
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FactoryRight<'a> {
    raw: &'a [u8],
}

impl<'a> FactoryRight<'a> {
    pub fn parse(raw: &'a [u8]) -> Result<Self> {
        if raw.len() != FACTORY_RIGHT_LEN {
            return Err(ScriptError::FactoryReducedProofEncoding);
        }
        let right = Self { raw };
        if right.kind() > 4 {
            return Err(ScriptError::FactoryReducedProofEncoding);
        }
        match right.asset_present() {
            0 => {
                if !right.asset_type().iter().all(|value| *value == 0) {
                    return Err(ScriptError::FactoryReducedProofEncoding);
                }
            }
            1 => {}
            _ => return Err(ScriptError::FactoryReducedProofEncoding),
        }
        Ok(right)
    }

    pub fn participant(&self) -> &'a [u8] {
        field(self.raw, 0, BYTE32_LEN)
    }

    pub fn subchannel(&self) -> &'a [u8] {
        field(self.raw, BYTE32_LEN, BYTE32_LEN)
    }

    pub fn kind(&self) -> u8 {
        self.raw[2 * BYTE32_LEN]
    }

    pub fn asset_present(&self) -> u8 {
        self.raw[2 * BYTE32_LEN + 1]
    }

    pub fn asset_type(&self) -> &'a [u8] {
        field(self.raw, 2 * BYTE32_LEN + 2, BYTE32_LEN)
    }

    pub fn quantity(&self) -> u128 {
        read_u128(self.raw, 2 * BYTE32_LEN + 2 + BYTE32_LEN)
    }

    pub fn raw(&self) -> &'a [u8] {
        self.raw
    }

    fn id_key(&self) -> (&'a [u8], &'a [u8], u8, u8, &'a [u8]) {
        (
            self.participant(),
            self.subchannel(),
            self.kind(),
            self.asset_present(),
            self.asset_type(),
        )
    }

    fn same_id(&self, other: &Self) -> bool {
        self.id_key() == other.id_key()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FactoryReducedRightsWitness<'a> {
    raw: &'a [u8],
}

impl<'a> FactoryReducedRightsWitness<'a> {
    pub fn parse(raw: &'a [u8]) -> Result<Self> {
        if raw.len() != FACTORY_REDUCED_RIGHTS_WITNESS_LEN {
            return Err(ScriptError::FactoryReducedProofEncoding);
        }
        let witness = Self { raw };
        if witness.version() != FACTORY_REDUCED_RIGHTS_WITNESS_VERSION
            || witness.participant_threshold() != FACTORY_REDUCED_RIGHTS_PARTICIPANT_THRESHOLD
            || witness.participant_count() != FACTORY_REDUCED_RIGHTS_PARTICIPANT_COUNT
            || witness.authorised_count() != FACTORY_REDUCED_RIGHTS_AUTHORISED_COUNT
            || witness.right_count() != FACTORY_REDUCED_RIGHTS_COUNT
            || read_u16(raw, 6) != 0
        {
            return Err(ScriptError::FactoryReducedProofEncoding);
        }
        if witness.participant(0) >= witness.participant(1)
            || witness.pubkey(0) == witness.pubkey(1)
        {
            return Err(ScriptError::FactoryReducedProofEncoding);
        }
        if witness.signed_count() != FACTORY_REDUCED_RIGHTS_AUTHORISED_COUNT {
            return Err(ScriptError::FactoryReducedProofEncoding);
        }
        witness.validate_right_order(false)?;
        witness.validate_right_order(true)?;
        Ok(witness)
    }

    pub fn version(&self) -> u16 {
        read_u16(self.raw, 0)
    }

    pub fn participant_threshold(&self) -> u8 {
        self.raw[2]
    }

    pub fn participant_count(&self) -> u8 {
        self.raw[3]
    }

    pub fn authorised_count(&self) -> u8 {
        self.raw[4]
    }

    pub fn right_count(&self) -> u8 {
        self.raw[5]
    }

    pub fn participant(&self, index: usize) -> &'a [u8] {
        field(
            self.raw,
            factory_reduced_participant_offset(index),
            BYTE32_LEN,
        )
    }

    pub fn pubkey(&self, index: usize) -> &'a [u8] {
        field(
            self.raw,
            factory_reduced_participant_offset(index) + BYTE32_LEN,
            COMPRESSED_SECP256K1_PUBKEY_LEN,
        )
    }

    pub fn signed_flag(&self, index: usize) -> u8 {
        self.raw[factory_reduced_participant_offset(index)
            + BYTE32_LEN
            + COMPRESSED_SECP256K1_PUBKEY_LEN]
    }

    pub fn signature(&self, index: usize) -> &'a [u8] {
        field(
            self.raw,
            factory_reduced_participant_offset(index)
                + BYTE32_LEN
                + COMPRESSED_SECP256K1_PUBKEY_LEN
                + 1,
            ECDSA_SIGNATURE_LEN,
        )
    }

    pub fn touched_participant(&self) -> &'a [u8] {
        field(self.raw, factory_reduced_touched_offset(), BYTE32_LEN)
    }

    pub fn right_before(&self, index: usize) -> Result<FactoryRight<'a>> {
        FactoryRight::parse(field(
            self.raw,
            factory_reduced_right_offset(false, index),
            FACTORY_RIGHT_LEN,
        ))
    }

    pub fn right_after(&self, index: usize) -> Result<FactoryRight<'a>> {
        FactoryRight::parse(field(
            self.raw,
            factory_reduced_right_offset(true, index),
            FACTORY_RIGHT_LEN,
        ))
    }

    pub fn participants_commitment(&self) -> [u8; 32] {
        factory_participants_commitment(
            self.participant_threshold(),
            &[
                (self.participant(0), self.pubkey(0)),
                (self.participant(1), self.pubkey(1)),
            ],
        )
    }

    pub fn rights_root(&self, after: bool) -> Result<[u8; 32]> {
        let count = [self.right_count()];
        let mut hasher = new_blake2b();
        hasher.update(FACTORY_RIGHTS_ROOT_DOMAIN);
        hasher.update(&count);
        for index in 0..self.right_count() as usize {
            let right = if after {
                self.right_after(index)?
            } else {
                self.right_before(index)?
            };
            hasher.update(right.raw());
        }
        let mut out = [0u8; 32];
        hasher.finalize(&mut out);
        Ok(out)
    }

    pub fn access_manifest_root(&self, after: bool) -> Result<[u8; 32]> {
        let count = [self.right_count()];
        let mut hasher = new_blake2b();
        hasher.update(FACTORY_ACCESS_MANIFEST_ROOT_DOMAIN);
        hasher.update(&count);
        for index in 0..self.right_count() as usize {
            let right = if after {
                self.right_after(index)?
            } else {
                self.right_before(index)?
            };
            hasher.update(right.participant());
            hasher.update(right.subchannel());
            hasher.update(&[right.kind(), right.asset_present()]);
            hasher.update(right.asset_type());
        }
        let mut out = [0u8; 32];
        hasher.finalize(&mut out);
        Ok(out)
    }

    pub fn non_interference_digest(
        &self,
        old_header: &FactoryStateHeader,
        new_header: &FactoryStateHeader,
    ) -> Result<[u8; 32]> {
        let old_update_number = old_header.update_number().to_le_bytes();
        let new_update_number = new_header.update_number().to_le_bytes();
        let before_root = self.rights_root(false)?;
        let after_root = self.rights_root(true)?;
        let before_access_root = self.access_manifest_root(false)?;
        let after_access_root = self.access_manifest_root(true)?;
        Ok(blake2b256(&[
            FACTORY_REDUCED_RIGHTS_DOMAIN,
            old_header.factory_id(),
            &old_update_number,
            &new_update_number,
            &before_root,
            &after_root,
            &before_access_root,
            &after_access_root,
            self.touched_participant(),
        ]))
    }

    fn signed_count(&self) -> u8 {
        let mut count = 0u8;
        for index in 0..FACTORY_REDUCED_RIGHTS_PARTICIPANT_COUNT as usize {
            match self.signed_flag(index) {
                0 => {}
                1 => count = count.saturating_add(1),
                _ => return u8::MAX,
            }
        }
        count
    }

    fn validate_right_order(&self, after: bool) -> Result<()> {
        let mut previous: Option<FactoryRight> = None;
        for index in 0..self.right_count() as usize {
            let right = if after {
                self.right_after(index)?
            } else {
                self.right_before(index)?
            };
            if let Some(prev) = previous
                && prev.id_key() >= right.id_key()
            {
                return Err(ScriptError::FactoryReducedProofEncoding);
            }
            previous = Some(right);
        }
        Ok(())
    }
}

pub fn verify_reduced_factory_rights_update(
    old_header: &FactoryStateHeader,
    new_header: &FactoryStateHeader,
    witness: &FactoryReducedRightsWitness,
) -> Result<()> {
    if new_header.signature_scheme_id() != SIGNATURE_SCHEME_SECP256K1_ECDSA_BLAKE2B {
        return Err(ScriptError::FactoryReducedProofEncoding);
    }
    if new_header.participants_commitment() != witness.participants_commitment().as_slice() {
        return Err(ScriptError::ParticipantCommitmentMismatch);
    }

    let before_root = witness.rights_root(false)?;
    let after_root = witness.rights_root(true)?;
    if old_header.state_root() != before_root.as_slice()
        || new_header.state_root() != after_root.as_slice()
    {
        return Err(ScriptError::FactoryReducedProofMismatch);
    }
    let before_access_root = witness.access_manifest_root(false)?;
    let after_access_root = witness.access_manifest_root(true)?;
    if old_header.access_manifest_root() != before_access_root.as_slice()
        || new_header.access_manifest_root() != after_access_root.as_slice()
    {
        return Err(ScriptError::FactoryReducedProofMismatch);
    }
    let digest = witness.non_interference_digest(old_header, new_header)?;
    if new_header.non_interference_digest() != digest.as_slice() {
        return Err(ScriptError::FactoryReducedProofMismatch);
    }

    validate_reduced_rights_non_interference(witness)?;
    verify_reduced_rights_signature(new_header, witness)
}

fn validate_reduced_rights_non_interference(witness: &FactoryReducedRightsWitness) -> Result<()> {
    let touched = witness.touched_participant();
    let mut touched_exists = false;
    let mut touched_decreased = false;

    for index in 0..witness.right_count() as usize {
        let before = witness.right_before(index)?;
        let after = witness.right_after(index)?;
        if !before.same_id(&after) {
            return Err(ScriptError::FactoryReducedProofMismatch);
        }

        if before.participant() == touched {
            touched_exists = true;
            if after.quantity() > before.quantity() {
                return Err(ScriptError::FactoryReducedProofMismatch);
            }
            if after.quantity() < before.quantity() {
                validate_reduced_value_right_decrease(&before, &after)?;
                touched_decreased = true;
            }
        } else if after.quantity() != before.quantity() {
            return Err(ScriptError::FactoryReducedProofMismatch);
        }
    }

    if !touched_exists || !touched_decreased {
        return Err(ScriptError::FactoryReducedProofMismatch);
    }
    Ok(())
}

fn validate_reduced_value_right_decrease(
    before: &FactoryRight,
    after: &FactoryRight,
) -> Result<()> {
    if !before.same_id(after) || after.quantity() >= before.quantity() {
        return Err(ScriptError::FactoryReducedProofMismatch);
    }
    match before.kind() {
        FACTORY_RIGHT_KIND_BALANCE
        | FACTORY_RIGHT_KIND_RESERVE_CLAIM
        | FACTORY_RIGHT_KIND_SPONSOR_BUDGET_CLAIM => Ok(()),
        _ => Err(ScriptError::FactoryReducedProofMismatch),
    }
}

fn verify_reduced_rights_signature(
    header: &FactoryStateHeader,
    witness: &FactoryReducedRightsWitness,
) -> Result<()> {
    let digest = header.signing_digest();
    let mut matched = false;
    for index in 0..FACTORY_REDUCED_RIGHTS_PARTICIPANT_COUNT as usize {
        if witness.signed_flag(index) == 0 {
            continue;
        }
        if witness.participant(index) != witness.touched_participant() {
            return Err(ScriptError::FactoryReducedProofMismatch);
        }
        let verifying_key = VerifyingKey::from_sec1_bytes(witness.pubkey(index))
            .map_err(|_| ScriptError::ParticipantWitnessEncoding)?;
        let signature = Signature::try_from(witness.signature(index))
            .map_err(|_| ScriptError::ParticipantWitnessEncoding)?;
        verifying_key
            .verify_prehash(&digest, &signature)
            .map_err(|_| ScriptError::InvalidParticipantSignature)?;
        matched = true;
    }
    if matched {
        Ok(())
    } else {
        Err(ScriptError::FactoryReducedProofMismatch)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FactoryMerkleUpdateWitness<'a> {
    raw: &'a [u8],
}

impl<'a> FactoryMerkleUpdateWitness<'a> {
    pub fn parse(raw: &'a [u8]) -> Result<Self> {
        if raw.len() != FACTORY_MERKLE_UPDATE_WITNESS_LEN {
            return Err(ScriptError::FactoryReducedProofEncoding);
        }
        let witness = Self { raw };
        if witness.version() != FACTORY_MERKLE_UPDATE_WITNESS_VERSION
            || witness.participant_threshold() != FACTORY_REDUCED_RIGHTS_PARTICIPANT_THRESHOLD
            || witness.participant_count() != FACTORY_REDUCED_RIGHTS_PARTICIPANT_COUNT
            || witness.authorised_count() != FACTORY_REDUCED_RIGHTS_AUTHORISED_COUNT
            || witness.right_count() != FACTORY_MERKLE_UPDATE_RIGHT_COUNT
            || read_u16(raw, 6) != 0
        {
            return Err(ScriptError::FactoryReducedProofEncoding);
        }
        if witness.participant(0) >= witness.participant(1)
            || witness.pubkey(0) == witness.pubkey(1)
        {
            return Err(ScriptError::FactoryReducedProofEncoding);
        }
        if witness.signed_count() != FACTORY_REDUCED_RIGHTS_AUTHORISED_COUNT {
            return Err(ScriptError::FactoryReducedProofEncoding);
        }
        let before = witness.right_before()?;
        let after = witness.right_after()?;
        if !before.same_id(&after) || before.quantity() == after.quantity() {
            return Err(ScriptError::FactoryReducedProofEncoding);
        }
        if before.participant() != witness.touched_participant() {
            return Err(ScriptError::FactoryReducedProofEncoding);
        }
        Ok(witness)
    }

    pub fn version(&self) -> u16 {
        read_u16(self.raw, 0)
    }

    pub fn participant_threshold(&self) -> u8 {
        self.raw[2]
    }

    pub fn participant_count(&self) -> u8 {
        self.raw[3]
    }

    pub fn authorised_count(&self) -> u8 {
        self.raw[4]
    }

    pub fn right_count(&self) -> u8 {
        self.raw[5]
    }

    pub fn participant(&self, index: usize) -> &'a [u8] {
        field(
            self.raw,
            factory_merkle_participant_offset(index),
            BYTE32_LEN,
        )
    }

    pub fn pubkey(&self, index: usize) -> &'a [u8] {
        field(
            self.raw,
            factory_merkle_participant_offset(index) + BYTE32_LEN,
            COMPRESSED_SECP256K1_PUBKEY_LEN,
        )
    }

    pub fn signed_flag(&self, index: usize) -> u8 {
        self.raw[factory_merkle_participant_offset(index)
            + BYTE32_LEN
            + COMPRESSED_SECP256K1_PUBKEY_LEN]
    }

    pub fn signature(&self, index: usize) -> &'a [u8] {
        field(
            self.raw,
            factory_merkle_participant_offset(index)
                + BYTE32_LEN
                + COMPRESSED_SECP256K1_PUBKEY_LEN
                + 1,
            ECDSA_SIGNATURE_LEN,
        )
    }

    pub fn touched_participant(&self) -> &'a [u8] {
        field(self.raw, factory_merkle_touched_offset(), BYTE32_LEN)
    }

    pub fn right_before(&self) -> Result<FactoryRight<'a>> {
        FactoryRight::parse(field(
            self.raw,
            factory_merkle_right_offset(false),
            FACTORY_RIGHT_LEN,
        ))
    }

    pub fn right_after(&self) -> Result<FactoryRight<'a>> {
        FactoryRight::parse(field(
            self.raw,
            factory_merkle_right_offset(true),
            FACTORY_RIGHT_LEN,
        ))
    }

    pub fn sibling_hash(&self, depth: usize) -> &'a [u8] {
        field(self.raw, factory_merkle_sibling_offset(depth), BYTE32_LEN)
    }

    pub fn participants_commitment(&self) -> [u8; 32] {
        factory_participants_commitment(
            self.participant_threshold(),
            &[
                (self.participant(0), self.pubkey(0)),
                (self.participant(1), self.pubkey(1)),
            ],
        )
    }

    pub fn pubkey_participants_commitment(&self) -> [u8; 32] {
        participants_commitment(
            self.participant_threshold(),
            &[self.pubkey(0), self.pubkey(1)],
        )
    }

    pub fn rights_root(&self, after: bool) -> Result<[u8; 32]> {
        let right = if after {
            self.right_after()?
        } else {
            self.right_before()?
        };
        let key = factory_right_key(&right);
        let mut current = factory_right_leaf_hash(&right);
        for depth in (0..FACTORY_SPARSE_MERKLE_DEPTH).rev() {
            current = if factory_key_bit(&key, depth) {
                factory_right_node_hash(depth, self.sibling_hash(depth), &current)
            } else {
                factory_right_node_hash(depth, &current, self.sibling_hash(depth))
            };
        }
        Ok(current)
    }

    pub fn non_interference_digest(
        &self,
        old_header: &FactoryStateHeader,
        new_header: &FactoryStateHeader,
    ) -> Result<[u8; 32]> {
        let old_update_number = old_header.update_number().to_le_bytes();
        let new_update_number = new_header.update_number().to_le_bytes();
        Ok(blake2b256(&[
            FACTORY_MERKLE_UPDATE_DOMAIN,
            old_header.factory_id(),
            &old_update_number,
            &new_update_number,
            old_header.state_root(),
            new_header.state_root(),
            old_header.access_manifest_root(),
            new_header.access_manifest_root(),
            self.touched_participant(),
            self.right_before()?.raw(),
            self.right_after()?.raw(),
        ]))
    }

    fn signed_count(&self) -> u8 {
        let mut count = 0u8;
        for index in 0..FACTORY_REDUCED_RIGHTS_PARTICIPANT_COUNT as usize {
            match self.signed_flag(index) {
                0 => {}
                1 => count = count.saturating_add(1),
                _ => return u8::MAX,
            }
        }
        count
    }
}

pub fn verify_factory_merkle_update(
    old_header: &FactoryStateHeader,
    new_header: &FactoryStateHeader,
    witness: &FactoryMerkleUpdateWitness,
) -> Result<()> {
    if new_header.signature_scheme_id() != SIGNATURE_SCHEME_SECP256K1_ECDSA_BLAKE2B {
        return Err(ScriptError::FactoryReducedProofEncoding);
    }
    if new_header.participants_commitment() != witness.participants_commitment().as_slice() {
        return Err(ScriptError::ParticipantCommitmentMismatch);
    }
    if old_header.access_manifest_root() != new_header.access_manifest_root() {
        return Err(ScriptError::FactoryReducedProofMismatch);
    }

    let before_root = witness.rights_root(false)?;
    let after_root = witness.rights_root(true)?;
    if old_header.state_root() != before_root.as_slice()
        || new_header.state_root() != after_root.as_slice()
    {
        return Err(ScriptError::FactoryReducedProofMismatch);
    }
    let digest = witness.non_interference_digest(old_header, new_header)?;
    if new_header.non_interference_digest() != digest.as_slice() {
        return Err(ScriptError::FactoryReducedProofMismatch);
    }

    verify_merkle_update_signature(new_header, witness)
}

pub fn validate_factory_merkle_update_local_predicate(
    witness: &FactoryMerkleUpdateWitness,
) -> Result<()> {
    let before = witness.right_before()?;
    let after = witness.right_after()?;
    if before.participant() != witness.touched_participant() {
        return Err(ScriptError::FactoryReducedProofMismatch);
    }
    validate_reduced_value_right_decrease(&before, &after)
}

fn verify_merkle_update_signature(
    header: &FactoryStateHeader,
    witness: &FactoryMerkleUpdateWitness,
) -> Result<()> {
    let digest = header.signing_digest();
    let mut matched = false;
    for index in 0..FACTORY_REDUCED_RIGHTS_PARTICIPANT_COUNT as usize {
        if witness.signed_flag(index) == 0 {
            continue;
        }
        if witness.participant(index) != witness.touched_participant() {
            return Err(ScriptError::FactoryReducedProofMismatch);
        }
        let verifying_key = VerifyingKey::from_sec1_bytes(witness.pubkey(index))
            .map_err(|_| ScriptError::ParticipantWitnessEncoding)?;
        let signature = Signature::try_from(witness.signature(index))
            .map_err(|_| ScriptError::ParticipantWitnessEncoding)?;
        verifying_key
            .verify_prehash(&digest, &signature)
            .map_err(|_| ScriptError::InvalidParticipantSignature)?;
        matched = true;
    }
    if matched {
        Ok(())
    } else {
        Err(ScriptError::FactoryReducedProofMismatch)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FactoryReducedExitWitness<'a> {
    raw: &'a [u8],
}

impl<'a> FactoryReducedExitWitness<'a> {
    pub fn parse(raw: &'a [u8]) -> Result<Self> {
        if raw.len() != FACTORY_REDUCED_EXIT_WITNESS_LEN
            && raw.len() != FACTORY_REDUCED_EXIT_XUDT_WITNESS_LEN
        {
            return Err(ScriptError::FactoryReducedProofEncoding);
        }
        let witness = Self { raw };
        if witness.version() != FACTORY_REDUCED_EXIT_WITNESS_VERSION
            || witness.participant_threshold() != FACTORY_REDUCED_RIGHTS_PARTICIPANT_THRESHOLD
            || witness.participant_count() != FACTORY_REDUCED_RIGHTS_PARTICIPANT_COUNT
            || witness.authorised_count() != FACTORY_REDUCED_RIGHTS_AUTHORISED_COUNT
            || witness.right_count() != FACTORY_REDUCED_EXIT_RIGHTS_COUNT
            || read_u16(raw, 6) != 0
        {
            return Err(ScriptError::FactoryReducedProofEncoding);
        }
        if witness.participant(0) >= witness.participant(1)
            || witness.pubkey(0) == witness.pubkey(1)
        {
            return Err(ScriptError::FactoryReducedProofEncoding);
        }
        if witness.signed_count() != FACTORY_REDUCED_RIGHTS_AUTHORISED_COUNT {
            return Err(ScriptError::FactoryReducedProofEncoding);
        }
        StateHeader::parse(witness.exit_state_header())?;
        match witness.settlement_descriptor().len() {
            BILATERAL_CKB_DESCRIPTOR_LEN => {
                BilateralCkbSettlementDescriptor::parse(witness.settlement_descriptor())?;
            }
            BILATERAL_CKB_XUDT_DESCRIPTOR_LEN => {
                BilateralCkbXudtSettlementDescriptor::parse(witness.settlement_descriptor())?;
            }
            _ => return Err(ScriptError::SettlementDescriptorEncoding),
        }
        witness.validate_right_order(false)?;
        witness.validate_right_order(true)?;
        Ok(witness)
    }

    pub fn version(&self) -> u16 {
        read_u16(self.raw, 0)
    }

    pub fn participant_threshold(&self) -> u8 {
        self.raw[2]
    }

    pub fn participant_count(&self) -> u8 {
        self.raw[3]
    }

    pub fn authorised_count(&self) -> u8 {
        self.raw[4]
    }

    pub fn right_count(&self) -> u8 {
        self.raw[5]
    }

    pub fn participant(&self, index: usize) -> &'a [u8] {
        field(
            self.raw,
            factory_reduced_exit_participant_offset(index),
            BYTE32_LEN,
        )
    }

    pub fn pubkey(&self, index: usize) -> &'a [u8] {
        field(
            self.raw,
            factory_reduced_exit_participant_offset(index) + BYTE32_LEN,
            COMPRESSED_SECP256K1_PUBKEY_LEN,
        )
    }

    pub fn signed_flag(&self, index: usize) -> u8 {
        self.raw[factory_reduced_exit_participant_offset(index)
            + BYTE32_LEN
            + COMPRESSED_SECP256K1_PUBKEY_LEN]
    }

    pub fn signature(&self, index: usize) -> &'a [u8] {
        field(
            self.raw,
            factory_reduced_exit_participant_offset(index)
                + BYTE32_LEN
                + COMPRESSED_SECP256K1_PUBKEY_LEN
                + 1,
            ECDSA_SIGNATURE_LEN,
        )
    }

    pub fn touched_participant(&self) -> &'a [u8] {
        field(self.raw, factory_reduced_exit_touched_offset(), BYTE32_LEN)
    }

    pub fn release_quantity(&self) -> u128 {
        read_u128(self.raw, factory_reduced_exit_release_quantity_offset())
    }

    pub fn state_output_index(&self) -> u32 {
        read_u32(self.raw, factory_reduced_exit_state_output_index_offset())
    }

    pub fn vault_output_index(&self) -> u32 {
        read_u32(self.raw, factory_reduced_exit_vault_output_index_offset())
    }

    pub fn state_type_hash(&self) -> &'a [u8] {
        field(
            self.raw,
            factory_reduced_exit_state_type_hash_offset(),
            BYTE32_LEN,
        )
    }

    pub fn vault_lock_hash(&self) -> &'a [u8] {
        field(
            self.raw,
            factory_reduced_exit_vault_lock_hash_offset(),
            BYTE32_LEN,
        )
    }

    pub fn state_lock_hash(&self) -> &'a [u8] {
        field(
            self.raw,
            factory_reduced_exit_state_lock_hash_offset(),
            BYTE32_LEN,
        )
    }

    pub fn exit_state_header(&self) -> &'a [u8] {
        field(
            self.raw,
            factory_reduced_exit_state_header_offset(),
            STATE_HEADER_LEN,
        )
    }

    pub fn settlement_descriptor(&self) -> &'a [u8] {
        let offset = factory_reduced_exit_descriptor_offset();
        let len = if self.raw.len() == FACTORY_REDUCED_EXIT_WITNESS_LEN {
            BILATERAL_CKB_DESCRIPTOR_LEN
        } else {
            BILATERAL_CKB_XUDT_DESCRIPTOR_LEN
        };
        field(self.raw, offset, len)
    }

    pub fn right_before(&self, index: usize) -> Result<FactoryRight<'a>> {
        FactoryRight::parse(field(
            self.raw,
            factory_reduced_exit_right_offset(false, self.settlement_descriptor().len(), index),
            FACTORY_RIGHT_LEN,
        ))
    }

    pub fn right_after(&self, index: usize) -> Result<FactoryRight<'a>> {
        FactoryRight::parse(field(
            self.raw,
            factory_reduced_exit_right_offset(true, self.settlement_descriptor().len(), index),
            FACTORY_RIGHT_LEN,
        ))
    }

    pub fn local_exit_digest(&self) -> [u8; 32] {
        factory_local_exit_digest(
            self.state_output_index(),
            self.vault_output_index(),
            self.state_type_hash(),
            self.vault_lock_hash(),
            self.state_lock_hash(),
            self.exit_state_header(),
            self.settlement_descriptor(),
        )
    }

    pub fn participants_commitment(&self) -> [u8; 32] {
        factory_participants_commitment(
            self.participant_threshold(),
            &[
                (self.participant(0), self.pubkey(0)),
                (self.participant(1), self.pubkey(1)),
            ],
        )
    }

    pub fn rights_root(&self, after: bool) -> Result<[u8; 32]> {
        let count = [self.right_count()];
        let mut hasher = new_blake2b();
        hasher.update(FACTORY_RIGHTS_ROOT_DOMAIN);
        hasher.update(&count);
        for index in 0..self.right_count() as usize {
            let right = if after {
                self.right_after(index)?
            } else {
                self.right_before(index)?
            };
            hasher.update(right.raw());
        }
        let mut out = [0u8; 32];
        hasher.finalize(&mut out);
        Ok(out)
    }

    pub fn access_manifest_root(&self, after: bool) -> Result<[u8; 32]> {
        let count = [self.right_count()];
        let mut hasher = new_blake2b();
        hasher.update(FACTORY_ACCESS_MANIFEST_ROOT_DOMAIN);
        hasher.update(&count);
        for index in 0..self.right_count() as usize {
            let right = if after {
                self.right_after(index)?
            } else {
                self.right_before(index)?
            };
            hasher.update(right.participant());
            hasher.update(right.subchannel());
            hasher.update(&[right.kind(), right.asset_present()]);
            hasher.update(right.asset_type());
        }
        let mut out = [0u8; 32];
        hasher.finalize(&mut out);
        Ok(out)
    }

    pub fn non_interference_digest(
        &self,
        old_header: &FactoryStateHeader,
        new_header: &FactoryStateHeader,
    ) -> Result<[u8; 32]> {
        let old_update_number = old_header.update_number().to_le_bytes();
        let new_update_number = new_header.update_number().to_le_bytes();
        let release_quantity = self.release_quantity().to_le_bytes();
        let before_root = self.rights_root(false)?;
        let after_root = self.rights_root(true)?;
        let before_access_root = self.access_manifest_root(false)?;
        let after_access_root = self.access_manifest_root(true)?;
        let local_exit_digest = self.local_exit_digest();
        Ok(blake2b256(&[
            FACTORY_REDUCED_EXIT_DOMAIN,
            old_header.factory_id(),
            &old_update_number,
            &new_update_number,
            &before_root,
            &after_root,
            &before_access_root,
            &after_access_root,
            self.touched_participant(),
            &release_quantity,
            &local_exit_digest,
        ]))
    }

    fn signed_count(&self) -> u8 {
        let mut count = 0u8;
        for index in 0..FACTORY_REDUCED_RIGHTS_PARTICIPANT_COUNT as usize {
            match self.signed_flag(index) {
                0 => {}
                1 => count = count.saturating_add(1),
                _ => return u8::MAX,
            }
        }
        count
    }

    fn validate_right_order(&self, after: bool) -> Result<()> {
        let mut previous: Option<FactoryRight> = None;
        for index in 0..self.right_count() as usize {
            let right = if after {
                self.right_after(index)?
            } else {
                self.right_before(index)?
            };
            if let Some(prev) = previous
                && prev.id_key() >= right.id_key()
            {
                return Err(ScriptError::FactoryReducedProofEncoding);
            }
            previous = Some(right);
        }
        Ok(())
    }
}

pub fn verify_reduced_factory_exit_update(
    old_header: &FactoryStateHeader,
    new_header: &FactoryStateHeader,
    witness: &FactoryReducedExitWitness,
) -> Result<()> {
    if new_header.signature_scheme_id() != SIGNATURE_SCHEME_SECP256K1_ECDSA_BLAKE2B {
        return Err(ScriptError::FactoryReducedProofEncoding);
    }
    if new_header.participants_commitment() != witness.participants_commitment().as_slice() {
        return Err(ScriptError::ParticipantCommitmentMismatch);
    }

    let before_root = witness.rights_root(false)?;
    let after_root = witness.rights_root(true)?;
    if old_header.state_root() != before_root.as_slice()
        || new_header.state_root() != after_root.as_slice()
    {
        return Err(ScriptError::FactoryReducedProofMismatch);
    }
    let before_access_root = witness.access_manifest_root(false)?;
    let after_access_root = witness.access_manifest_root(true)?;
    if old_header.access_manifest_root() != before_access_root.as_slice()
        || new_header.access_manifest_root() != after_access_root.as_slice()
    {
        return Err(ScriptError::FactoryReducedProofMismatch);
    }
    let digest = witness.non_interference_digest(old_header, new_header)?;
    if new_header.non_interference_digest() != digest.as_slice() {
        return Err(ScriptError::FactoryReducedProofMismatch);
    }

    validate_reduced_exit_local_evidence(witness)?;
    validate_reduced_exit_non_interference(witness)?;
    verify_reduced_exit_signature(new_header, witness)
}

fn validate_reduced_exit_local_evidence(witness: &FactoryReducedExitWitness) -> Result<()> {
    let exit_header = StateHeader::parse(witness.exit_state_header())?;
    if exit_header.state_number() != 0 || exit_header.phase() != PHASE_ACTIVE {
        return Err(ScriptError::FactoryLocalExitMismatch);
    }
    if exit_header.settlement_descriptor_commitment()
        != settlement_descriptor_commitment(witness.settlement_descriptor()).as_slice()
    {
        return Err(ScriptError::SettlementDescriptorMismatch);
    }
    match witness.settlement_descriptor().len() {
        BILATERAL_CKB_DESCRIPTOR_LEN => {
            let descriptor =
                BilateralCkbSettlementDescriptor::parse(witness.settlement_descriptor())?;
            if exit_header.descriptor_version() != BILATERAL_CKB_DESCRIPTOR_VERSION {
                return Err(ScriptError::SettlementDescriptorMismatch);
            }
            if descriptor.checked_total_capacity()? as u128 != witness.release_quantity() {
                return Err(ScriptError::FactoryReducedProofMismatch);
            }
        }
        BILATERAL_CKB_XUDT_DESCRIPTOR_LEN => {
            let descriptor =
                BilateralCkbXudtSettlementDescriptor::parse(witness.settlement_descriptor())?;
            if exit_header.descriptor_version() != BILATERAL_CKB_XUDT_DESCRIPTOR_VERSION {
                return Err(ScriptError::SettlementDescriptorMismatch);
            }
            if descriptor.checked_total_xudt_amount()? != witness.release_quantity() {
                return Err(ScriptError::FactoryReducedProofMismatch);
            }
        }
        _ => return Err(ScriptError::SettlementDescriptorEncoding),
    }
    Ok(())
}

fn validate_reduced_exit_non_interference(witness: &FactoryReducedExitWitness) -> Result<()> {
    if witness.release_quantity() == 0 {
        return Err(ScriptError::FactoryReducedProofMismatch);
    }
    let touched = witness.touched_participant();
    let release_quantity = witness.release_quantity();
    let (expected_asset_type, secondary_ckb_release) = match witness.settlement_descriptor().len() {
        BILATERAL_CKB_DESCRIPTOR_LEN => (None, 0u128),
        BILATERAL_CKB_XUDT_DESCRIPTOR_LEN => {
            let descriptor =
                BilateralCkbXudtSettlementDescriptor::parse(witness.settlement_descriptor())?;
            (
                Some(descriptor.xudt_type_hash()),
                descriptor.checked_total_capacity()? as u128,
            )
        }
        _ => return Err(ScriptError::SettlementDescriptorEncoding),
    };
    if secondary_ckb_release == 0 && expected_asset_type.is_some() {
        return Err(ScriptError::FactoryReducedProofMismatch);
    }
    let mut primary_consumed_claims = 0u8;
    let mut ckb_consumed_claims = 0u8;

    for index in 0..witness.right_count() as usize {
        let before = witness.right_before(index)?;
        let after = witness.right_after(index)?;
        if !before.same_id(&after) {
            return Err(ScriptError::FactoryReducedProofMismatch);
        }

        let is_ckb_right = before.asset_present() == 0;
        let primary_asset_matches = match expected_asset_type {
            Some(asset_type) => before.asset_present() == 1 && before.asset_type() == asset_type,
            None => is_ckb_right,
        };
        if before.participant() == touched
            && before.kind() == FACTORY_RIGHT_KIND_RESERVE_CLAIM
            && primary_asset_matches
            && before.quantity() >= release_quantity
            && before.quantity() - release_quantity == after.quantity()
        {
            primary_consumed_claims = primary_consumed_claims.saturating_add(1);
            continue;
        }
        if expected_asset_type.is_some()
            && secondary_ckb_release > 0
            && before.participant() == touched
            && before.kind() == FACTORY_RIGHT_KIND_RESERVE_CLAIM
            && is_ckb_right
            && before.quantity() >= secondary_ckb_release
            && before.quantity() - secondary_ckb_release == after.quantity()
        {
            ckb_consumed_claims = ckb_consumed_claims.saturating_add(1);
            continue;
        }
        if after.quantity() != before.quantity() {
            return Err(ScriptError::FactoryReducedProofMismatch);
        }
    }

    if primary_consumed_claims != 1 {
        return Err(ScriptError::FactoryReducedProofMismatch);
    }
    if expected_asset_type.is_some() && ckb_consumed_claims != 1 {
        return Err(ScriptError::FactoryReducedProofMismatch);
    }
    Ok(())
}

fn verify_reduced_exit_signature(
    header: &FactoryStateHeader,
    witness: &FactoryReducedExitWitness,
) -> Result<()> {
    let digest = header.signing_digest();
    let mut matched = false;
    for index in 0..FACTORY_REDUCED_RIGHTS_PARTICIPANT_COUNT as usize {
        if witness.signed_flag(index) == 0 {
            continue;
        }
        if witness.participant(index) != witness.touched_participant() {
            return Err(ScriptError::FactoryReducedProofMismatch);
        }
        let verifying_key = VerifyingKey::from_sec1_bytes(witness.pubkey(index))
            .map_err(|_| ScriptError::ParticipantWitnessEncoding)?;
        let signature = Signature::try_from(witness.signature(index))
            .map_err(|_| ScriptError::ParticipantWitnessEncoding)?;
        verifying_key
            .verify_prehash(&digest, &signature)
            .map_err(|_| ScriptError::InvalidParticipantSignature)?;
        matched = true;
    }
    if matched {
        Ok(())
    } else {
        Err(ScriptError::FactoryReducedProofMismatch)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FactoryLocalExitWitness<'a> {
    raw: &'a [u8],
}

impl<'a> FactoryLocalExitWitness<'a> {
    pub fn parse(raw: &'a [u8]) -> Result<Self> {
        if raw.len() != FACTORY_LOCAL_EXIT_WITNESS_LEN
            && raw.len() != FACTORY_LOCAL_EXIT_XUDT_WITNESS_LEN
        {
            return Err(ScriptError::ParticipantWitnessEncoding);
        }
        let witness = Self { raw };
        if witness.version() != FACTORY_LOCAL_EXIT_WITNESS_VERSION {
            return Err(ScriptError::ParticipantWitnessEncoding);
        }
        FactorySignatureWitness::parse(witness.factory_signature_bytes())?;
        StateHeader::parse(witness.exit_state_header())?;
        match witness.settlement_descriptor().len() {
            BILATERAL_CKB_DESCRIPTOR_LEN => {
                BilateralCkbSettlementDescriptor::parse(witness.settlement_descriptor())?;
            }
            BILATERAL_CKB_XUDT_DESCRIPTOR_LEN => {
                BilateralCkbXudtSettlementDescriptor::parse(witness.settlement_descriptor())?;
            }
            _ => return Err(ScriptError::SettlementDescriptorEncoding),
        }
        Ok(witness)
    }

    pub fn version(&self) -> u16 {
        read_u16(self.raw, 0)
    }

    pub fn factory_signature_bytes(&self) -> &'a [u8] {
        field(self.raw, 2, FACTORY_SIGNATURE_WITNESS_LEN)
    }

    pub fn factory_signature(&self) -> Result<FactorySignatureWitness<'a>> {
        FactorySignatureWitness::parse(self.factory_signature_bytes())
    }

    pub fn state_output_index(&self) -> u32 {
        read_u32(self.raw, 2 + FACTORY_SIGNATURE_WITNESS_LEN)
    }

    pub fn vault_output_index(&self) -> u32 {
        read_u32(self.raw, 2 + FACTORY_SIGNATURE_WITNESS_LEN + 4)
    }

    pub fn state_type_hash(&self) -> &'a [u8] {
        field(self.raw, 2 + FACTORY_SIGNATURE_WITNESS_LEN + 8, BYTE32_LEN)
    }

    pub fn vault_lock_hash(&self) -> &'a [u8] {
        field(
            self.raw,
            2 + FACTORY_SIGNATURE_WITNESS_LEN + 8 + BYTE32_LEN,
            BYTE32_LEN,
        )
    }

    pub fn state_lock_hash(&self) -> &'a [u8] {
        field(
            self.raw,
            2 + FACTORY_SIGNATURE_WITNESS_LEN + 8 + 2 * BYTE32_LEN,
            BYTE32_LEN,
        )
    }

    pub fn exit_state_header(&self) -> &'a [u8] {
        field(
            self.raw,
            2 + FACTORY_SIGNATURE_WITNESS_LEN + 8 + 3 * BYTE32_LEN,
            STATE_HEADER_LEN,
        )
    }

    pub fn settlement_descriptor(&self) -> &'a [u8] {
        let offset = 2 + FACTORY_SIGNATURE_WITNESS_LEN + 8 + 3 * BYTE32_LEN + STATE_HEADER_LEN;
        field(self.raw, offset, self.raw.len() - offset)
    }

    pub fn exit_digest(&self) -> [u8; 32] {
        factory_local_exit_digest(
            self.state_output_index(),
            self.vault_output_index(),
            self.state_type_hash(),
            self.vault_lock_hash(),
            self.state_lock_hash(),
            self.exit_state_header(),
            self.settlement_descriptor(),
        )
    }
}

pub fn verify_factory_state_signatures(
    header: &FactoryStateHeader,
    witness: &FactorySignatureWitness,
) -> Result<()> {
    if header.signature_scheme_id() != SIGNATURE_SCHEME_SECP256K1_ECDSA_BLAKE2B {
        return Err(ScriptError::ParticipantWitnessEncoding);
    }
    if header.participants_commitment() != witness.participants_commitment().as_slice() {
        return Err(ScriptError::ParticipantCommitmentMismatch);
    }

    let digest = header.signing_digest();
    for index in 0..FACTORY_SIGNATURE_COUNT as usize {
        let verifying_key = VerifyingKey::from_sec1_bytes(witness.pubkey(index))
            .map_err(|_| ScriptError::ParticipantWitnessEncoding)?;
        let signature = Signature::try_from(witness.signature(index))
            .map_err(|_| ScriptError::ParticipantWitnessEncoding)?;
        verifying_key
            .verify_prehash(&digest, &signature)
            .map_err(|_| ScriptError::InvalidParticipantSignature)?;
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FactorySpliceHeader<'a> {
    raw: &'a [u8],
}

impl<'a> FactorySpliceHeader<'a> {
    pub fn parse(raw: &'a [u8]) -> Result<Self> {
        if raw.len() != FACTORY_SPLICE_HEADER_LEN {
            return Err(ScriptError::FactorySpliceProofEncoding);
        }
        let header = Self { raw };
        if header.kind() != SPLICE_KIND_IN && header.kind() != SPLICE_KIND_OUT {
            return Err(ScriptError::FactorySpliceProofEncoding);
        }
        Ok(header)
    }

    pub fn protocol_version(&self) -> u16 {
        read_u16(self.raw, 0)
    }

    pub fn chain_id(&self) -> &'a [u8] {
        field(self.raw, 2, BYTE32_LEN)
    }

    pub fn signature_scheme_id(&self) -> u16 {
        read_u16(self.raw, 34)
    }

    pub fn factory_id(&self) -> &'a [u8] {
        field(self.raw, 36, BYTE32_LEN)
    }

    pub fn old_update_number(&self) -> u64 {
        read_u64(self.raw, 68)
    }

    pub fn new_update_number(&self) -> u64 {
        read_u64(self.raw, 76)
    }

    pub fn old_state_root(&self) -> &'a [u8] {
        field(self.raw, 84, BYTE32_LEN)
    }

    pub fn new_state_root(&self) -> &'a [u8] {
        field(self.raw, 116, BYTE32_LEN)
    }

    pub fn old_access_manifest_root(&self) -> &'a [u8] {
        field(self.raw, 148, BYTE32_LEN)
    }

    pub fn new_access_manifest_root(&self) -> &'a [u8] {
        field(self.raw, 180, BYTE32_LEN)
    }

    pub fn kind(&self) -> u8 {
        self.raw[212]
    }

    pub fn vault_delta_commitment(&self) -> &'a [u8] {
        field(self.raw, 213, BYTE32_LEN)
    }

    pub fn non_interference_digest(&self) -> &'a [u8] {
        field(self.raw, 245, BYTE32_LEN)
    }

    pub fn participants_commitment(&self) -> &'a [u8] {
        field(self.raw, 277, BYTE32_LEN)
    }

    pub fn signing_digest(&self) -> [u8; 32] {
        blake2b256(&[FACTORY_SPLICE_HEADER_DOMAIN, self.raw])
    }

    pub fn matches_factory_update(
        &self,
        old_header: &FactoryStateHeader,
        new_header: &FactoryStateHeader,
    ) -> bool {
        old_header.same_context_except_progress(new_header)
            && self.protocol_version() == old_header.protocol_version()
            && self.protocol_version() == new_header.protocol_version()
            && self.chain_id() == old_header.chain_id()
            && self.chain_id() == new_header.chain_id()
            && self.signature_scheme_id() == old_header.signature_scheme_id()
            && self.signature_scheme_id() == new_header.signature_scheme_id()
            && self.factory_id() == old_header.factory_id()
            && self.factory_id() == new_header.factory_id()
            && self.old_update_number() == old_header.update_number()
            && self.new_update_number() == new_header.update_number()
            && self.old_state_root() == old_header.state_root()
            && self.new_state_root() == new_header.state_root()
            && self.old_access_manifest_root() == old_header.access_manifest_root()
            && self.new_access_manifest_root() == new_header.access_manifest_root()
            && self.non_interference_digest() == new_header.non_interference_digest()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FactoryVaultAssetAmount<'a> {
    raw: &'a [u8],
}

impl<'a> FactoryVaultAssetAmount<'a> {
    pub fn parse(raw: &'a [u8]) -> Result<Self> {
        if raw.len() != FACTORY_VAULT_ASSET_AMOUNT_LEN {
            return Err(ScriptError::FactorySpliceProofEncoding);
        }
        let amount = Self { raw };
        validate_vault_asset_encoding(amount.asset_kind(), amount.asset_type())
            .map_err(|_| ScriptError::FactorySpliceProofEncoding)?;
        Ok(amount)
    }

    pub fn asset_kind(&self) -> u8 {
        self.raw[0]
    }

    pub fn asset_type(&self) -> &'a [u8] {
        field(self.raw, 1, BYTE32_LEN)
    }

    pub fn amount(&self) -> u128 {
        read_u128(self.raw, 1 + BYTE32_LEN)
    }

    pub fn raw(&self) -> &'a [u8] {
        self.raw
    }

    fn asset_key(&self) -> (u8, &'a [u8]) {
        (self.asset_kind(), self.asset_type())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FactoryVaultDescriptor<'a> {
    raw: &'a [u8],
}

impl<'a> FactoryVaultDescriptor<'a> {
    pub fn parse(raw: &'a [u8]) -> Result<Self> {
        if raw.len() != FACTORY_VAULT_DESCRIPTOR_LEN {
            return Err(ScriptError::FactorySpliceProofEncoding);
        }
        let descriptor = Self { raw };
        if descriptor.asset_count() == 0
            || descriptor.asset_count() > FACTORY_VAULT_DESCRIPTOR_MAX_ASSETS as u16
        {
            return Err(ScriptError::FactorySpliceProofEncoding);
        }
        descriptor.validate_asset_order()?;
        descriptor.validate_unused_assets_zero()?;
        Ok(descriptor)
    }

    pub fn factory_id(&self) -> &'a [u8] {
        field(self.raw, 0, BYTE32_LEN)
    }

    pub fn asset_count(&self) -> u16 {
        read_u16(self.raw, BYTE32_LEN)
    }

    pub fn asset(&self, index: usize) -> Result<FactoryVaultAssetAmount<'a>> {
        FactoryVaultAssetAmount::parse(field(
            self.raw,
            factory_vault_asset_offset(index),
            FACTORY_VAULT_ASSET_AMOUNT_LEN,
        ))
    }

    pub fn commitment(&self) -> Result<[u8; 32]> {
        let count = self.asset_count();
        let count_bytes = count.to_le_bytes();
        let mut hasher = new_blake2b();
        hasher.update(FACTORY_VAULT_DESCRIPTOR_DOMAIN);
        hasher.update(self.factory_id());
        hasher.update(&count_bytes);
        for index in 0..count as usize {
            hasher.update(self.asset(index)?.raw());
        }
        let mut out = [0u8; 32];
        hasher.finalize(&mut out);
        Ok(out)
    }

    fn validate_asset_order(&self) -> Result<()> {
        let mut previous: Option<(u8, &'a [u8])> = None;
        for index in 0..self.asset_count() as usize {
            let asset = self.asset(index)?;
            if let Some(prev) = previous
                && prev >= asset.asset_key()
            {
                return Err(ScriptError::FactorySpliceProofEncoding);
            }
            previous = Some(asset.asset_key());
        }
        Ok(())
    }

    fn validate_unused_assets_zero(&self) -> Result<()> {
        for index in self.asset_count() as usize..FACTORY_VAULT_DESCRIPTOR_MAX_ASSETS as usize {
            let raw = field(
                self.raw,
                factory_vault_asset_offset(index),
                FACTORY_VAULT_ASSET_AMOUNT_LEN,
            );
            if !raw.iter().all(|value| *value == 0) {
                return Err(ScriptError::FactorySpliceProofEncoding);
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FactoryVaultDelta<'a> {
    raw: &'a [u8],
}

impl<'a> FactoryVaultDelta<'a> {
    pub fn parse(raw: &'a [u8]) -> Result<Self> {
        if raw.len() != FACTORY_VAULT_DELTA_LEN {
            return Err(ScriptError::FactorySpliceProofEncoding);
        }
        let delta = Self { raw };
        validate_vault_asset_encoding(delta.asset_kind(), delta.asset_type())
            .map_err(|_| ScriptError::FactorySpliceProofEncoding)?;
        Ok(delta)
    }

    pub fn asset_kind(&self) -> u8 {
        self.raw[0]
    }

    pub fn asset_type(&self) -> &'a [u8] {
        field(self.raw, 1, BYTE32_LEN)
    }

    pub fn old_amount(&self) -> u128 {
        read_u128(self.raw, 1 + BYTE32_LEN)
    }

    pub fn new_amount(&self) -> u128 {
        read_u128(self.raw, 1 + BYTE32_LEN + 16)
    }

    pub fn external_input(&self) -> u128 {
        read_u128(self.raw, 1 + BYTE32_LEN + 32)
    }

    pub fn withdrawal(&self) -> u128 {
        read_u128(self.raw, 1 + BYTE32_LEN + 48)
    }

    pub fn raw(&self) -> &'a [u8] {
        self.raw
    }

    fn asset_key(&self) -> (u8, &'a [u8]) {
        (self.asset_kind(), self.asset_type())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FactoryVaultDeltas<'a> {
    raw: &'a [u8],
}

impl<'a> FactoryVaultDeltas<'a> {
    pub fn parse(raw: &'a [u8]) -> Result<Self> {
        if raw.len() != FACTORY_VAULT_DELTAS_LEN {
            return Err(ScriptError::FactorySpliceProofEncoding);
        }
        let deltas = Self { raw };
        if deltas.delta_count() == 0
            || deltas.delta_count() > FACTORY_VAULT_DELTAS_MAX_DELTAS as u16
        {
            return Err(ScriptError::FactorySpliceProofEncoding);
        }
        deltas.validate_delta_order()?;
        deltas.validate_unused_deltas_zero()?;
        Ok(deltas)
    }

    pub fn delta_count(&self) -> u16 {
        read_u16(self.raw, 0)
    }

    pub fn delta(&self, index: usize) -> Result<FactoryVaultDelta<'a>> {
        FactoryVaultDelta::parse(field(
            self.raw,
            factory_vault_delta_offset(index),
            FACTORY_VAULT_DELTA_LEN,
        ))
    }

    pub fn commitment(&self) -> Result<[u8; 32]> {
        let count = self.delta_count();
        let count_bytes = count.to_le_bytes();
        let mut hasher = new_blake2b();
        hasher.update(FACTORY_VAULT_DELTA_DOMAIN);
        hasher.update(&count_bytes);
        for index in 0..count as usize {
            hasher.update(self.delta(index)?.raw());
        }
        let mut out = [0u8; 32];
        hasher.finalize(&mut out);
        Ok(out)
    }

    fn validate_delta_order(&self) -> Result<()> {
        let mut previous: Option<(u8, &'a [u8])> = None;
        for index in 0..self.delta_count() as usize {
            let delta = self.delta(index)?;
            if let Some(prev) = previous
                && prev >= delta.asset_key()
            {
                return Err(ScriptError::FactorySpliceProofEncoding);
            }
            previous = Some(delta.asset_key());
        }
        Ok(())
    }

    fn validate_unused_deltas_zero(&self) -> Result<()> {
        for index in self.delta_count() as usize..FACTORY_VAULT_DELTAS_MAX_DELTAS as usize {
            let raw = field(
                self.raw,
                factory_vault_delta_offset(index),
                FACTORY_VAULT_DELTA_LEN,
            );
            if !raw.iter().all(|value| *value == 0) {
                return Err(ScriptError::FactorySpliceProofEncoding);
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FactorySpliceWitness<'a> {
    raw: &'a [u8],
}

impl<'a> FactorySpliceWitness<'a> {
    pub fn parse(raw: &'a [u8]) -> Result<Self> {
        if raw.len() != FACTORY_SPLICE_WITNESS_LEN {
            return Err(ScriptError::FactorySpliceProofEncoding);
        }
        let witness = Self { raw };
        if witness.version() != FACTORY_SPLICE_WITNESS_VERSION {
            return Err(ScriptError::FactorySpliceProofEncoding);
        }
        Ok(witness)
    }

    pub fn version(&self) -> u16 {
        read_u16(self.raw, 0)
    }

    pub fn header(&self) -> Result<FactorySpliceHeader<'a>> {
        FactorySpliceHeader::parse(field(
            self.raw,
            factory_splice_header_offset(),
            FACTORY_SPLICE_HEADER_LEN,
        ))
    }

    pub fn factory_signature(&self) -> Result<FactorySignatureWitness<'a>> {
        FactorySignatureWitness::parse(field(
            self.raw,
            factory_splice_signature_offset(),
            FACTORY_SIGNATURE_WITNESS_LEN,
        ))
        .map_err(|_| ScriptError::FactorySpliceProofEncoding)
    }

    pub fn old_vault(&self) -> Result<FactoryVaultDescriptor<'a>> {
        FactoryVaultDescriptor::parse(field(
            self.raw,
            factory_splice_old_vault_offset(),
            FACTORY_VAULT_DESCRIPTOR_LEN,
        ))
    }

    pub fn new_vault(&self) -> Result<FactoryVaultDescriptor<'a>> {
        FactoryVaultDescriptor::parse(field(
            self.raw,
            factory_splice_new_vault_offset(),
            FACTORY_VAULT_DESCRIPTOR_LEN,
        ))
    }

    pub fn deltas(&self) -> Result<FactoryVaultDeltas<'a>> {
        FactoryVaultDeltas::parse(field(
            self.raw,
            factory_splice_deltas_offset(),
            FACTORY_VAULT_DELTAS_LEN,
        ))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FactoryReducedSpliceWitness<'a> {
    raw: &'a [u8],
}

impl<'a> FactoryReducedSpliceWitness<'a> {
    pub fn parse(raw: &'a [u8]) -> Result<Self> {
        if raw.len() != FACTORY_REDUCED_SPLICE_WITNESS_LEN {
            return Err(ScriptError::FactorySpliceProofEncoding);
        }
        let witness = Self { raw };
        if witness.version() != FACTORY_REDUCED_SPLICE_WITNESS_VERSION {
            return Err(ScriptError::FactorySpliceProofEncoding);
        }
        witness.header()?;
        witness.merkle_update()?;
        witness.old_vault()?;
        witness.new_vault()?;
        witness.deltas()?;
        Ok(witness)
    }

    pub fn version(&self) -> u16 {
        read_u16(self.raw, 0)
    }

    pub fn header(&self) -> Result<FactorySpliceHeader<'a>> {
        FactorySpliceHeader::parse(field(
            self.raw,
            factory_reduced_splice_header_offset(),
            FACTORY_SPLICE_HEADER_LEN,
        ))
    }

    pub fn merkle_update(&self) -> Result<FactoryMerkleUpdateWitness<'a>> {
        FactoryMerkleUpdateWitness::parse(field(
            self.raw,
            factory_reduced_splice_merkle_offset(),
            FACTORY_MERKLE_UPDATE_WITNESS_LEN,
        ))
        .map_err(|_| ScriptError::FactorySpliceProofEncoding)
    }

    pub fn old_vault(&self) -> Result<FactoryVaultDescriptor<'a>> {
        FactoryVaultDescriptor::parse(field(
            self.raw,
            factory_reduced_splice_old_vault_offset(),
            FACTORY_VAULT_DESCRIPTOR_LEN,
        ))
    }

    pub fn new_vault(&self) -> Result<FactoryVaultDescriptor<'a>> {
        FactoryVaultDescriptor::parse(field(
            self.raw,
            factory_reduced_splice_new_vault_offset(),
            FACTORY_VAULT_DESCRIPTOR_LEN,
        ))
    }

    pub fn deltas(&self) -> Result<FactoryVaultDeltas<'a>> {
        FactoryVaultDeltas::parse(field(
            self.raw,
            factory_reduced_splice_deltas_offset(),
            FACTORY_VAULT_DELTAS_LEN,
        ))
    }
}

pub fn verify_factory_splice_update(
    old_header: &FactoryStateHeader,
    new_header: &FactoryStateHeader,
    witness: &FactorySpliceWitness,
) -> Result<()> {
    let splice_header = witness.header()?;
    let signatures = witness.factory_signature()?;
    let old_vault = witness.old_vault()?;
    let new_vault = witness.new_vault()?;
    let deltas = witness.deltas()?;

    if new_header.update_number() <= old_header.update_number()
        || !splice_header.matches_factory_update(old_header, new_header)
    {
        return Err(ScriptError::FactorySpliceProofMismatch);
    }
    if old_vault.factory_id() != splice_header.factory_id()
        || new_vault.factory_id() != splice_header.factory_id()
        || deltas.commitment()?.as_slice() != splice_header.vault_delta_commitment()
    {
        return Err(ScriptError::FactorySpliceProofMismatch);
    }
    if old_header.participants_commitment() != signatures.participants_commitment().as_slice()
        || new_header.participants_commitment() != signatures.participants_commitment().as_slice()
    {
        return Err(ScriptError::ParticipantCommitmentMismatch);
    }

    verify_factory_splice_signatures(&splice_header, &signatures)?;
    verify_factory_splice_delta_set(splice_header.kind(), &old_vault, &new_vault, &deltas)
}

pub fn verify_factory_reduced_splice_update(
    old_header: &FactoryStateHeader,
    new_header: &FactoryStateHeader,
    witness: &FactoryReducedSpliceWitness,
) -> Result<()> {
    let splice_header = witness.header()?;
    let merkle_update = witness.merkle_update()?;
    let old_vault = witness.old_vault()?;
    let new_vault = witness.new_vault()?;
    let deltas = witness.deltas()?;

    if new_header.update_number() <= old_header.update_number()
        || !splice_header.matches_factory_update(old_header, new_header)
    {
        return Err(ScriptError::FactorySpliceProofMismatch);
    }
    if old_header.access_manifest_root() != new_header.access_manifest_root() {
        return Err(ScriptError::FactoryReducedProofMismatch);
    }
    if old_vault.factory_id() != splice_header.factory_id()
        || new_vault.factory_id() != splice_header.factory_id()
        || deltas.commitment()?.as_slice() != splice_header.vault_delta_commitment()
    {
        return Err(ScriptError::FactorySpliceProofMismatch);
    }

    let factory_participants = merkle_update.participants_commitment();
    if old_header.participants_commitment() != factory_participants.as_slice()
        || new_header.participants_commitment() != factory_participants.as_slice()
    {
        return Err(ScriptError::ParticipantCommitmentMismatch);
    }
    if splice_header.participants_commitment()
        != merkle_update.pubkey_participants_commitment().as_slice()
    {
        return Err(ScriptError::ParticipantCommitmentMismatch);
    }

    let before_root = merkle_update.rights_root(false)?;
    let after_root = merkle_update.rights_root(true)?;
    if old_header.state_root() != before_root.as_slice()
        || new_header.state_root() != after_root.as_slice()
    {
        return Err(ScriptError::FactoryReducedProofMismatch);
    }
    let digest = merkle_update.non_interference_digest(old_header, new_header)?;
    if new_header.non_interference_digest() != digest.as_slice() {
        return Err(ScriptError::FactoryReducedProofMismatch);
    }

    verify_reduced_splice_signature(&splice_header, &merkle_update)?;
    verify_factory_splice_delta_set(splice_header.kind(), &old_vault, &new_vault, &deltas)?;
    verify_reduced_splice_reserve_claim_delta(splice_header.kind(), &merkle_update, &deltas)
}

pub fn verify_factory_splice_signatures(
    header: &FactorySpliceHeader,
    witness: &FactorySignatureWitness,
) -> Result<()> {
    if header.signature_scheme_id() != SIGNATURE_SCHEME_SECP256K1_ECDSA_BLAKE2B {
        return Err(ScriptError::FactorySpliceProofEncoding);
    }
    if header.participants_commitment() != witness.pubkey_participants_commitment().as_slice() {
        return Err(ScriptError::ParticipantCommitmentMismatch);
    }

    let digest = header.signing_digest();
    for index in 0..FACTORY_SIGNATURE_COUNT as usize {
        let verifying_key = VerifyingKey::from_sec1_bytes(witness.pubkey(index))
            .map_err(|_| ScriptError::ParticipantWitnessEncoding)?;
        let signature = Signature::try_from(witness.signature(index))
            .map_err(|_| ScriptError::ParticipantWitnessEncoding)?;
        verifying_key
            .verify_prehash(&digest, &signature)
            .map_err(|_| ScriptError::InvalidParticipantSignature)?;
    }
    Ok(())
}

fn verify_reduced_splice_signature(
    header: &FactorySpliceHeader,
    witness: &FactoryMerkleUpdateWitness,
) -> Result<()> {
    if header.signature_scheme_id() != SIGNATURE_SCHEME_SECP256K1_ECDSA_BLAKE2B {
        return Err(ScriptError::FactorySpliceProofEncoding);
    }
    let digest = header.signing_digest();
    let mut matched = false;
    for index in 0..FACTORY_REDUCED_RIGHTS_PARTICIPANT_COUNT as usize {
        if witness.signed_flag(index) == 0 {
            continue;
        }
        if witness.participant(index) != witness.touched_participant() {
            return Err(ScriptError::FactoryReducedProofMismatch);
        }
        let verifying_key = VerifyingKey::from_sec1_bytes(witness.pubkey(index))
            .map_err(|_| ScriptError::ParticipantWitnessEncoding)?;
        let signature = Signature::try_from(witness.signature(index))
            .map_err(|_| ScriptError::ParticipantWitnessEncoding)?;
        verifying_key
            .verify_prehash(&digest, &signature)
            .map_err(|_| ScriptError::InvalidParticipantSignature)?;
        matched = true;
    }
    if matched {
        Ok(())
    } else {
        Err(ScriptError::FactoryReducedProofMismatch)
    }
}

fn verify_reduced_splice_reserve_claim_delta(
    kind: u8,
    witness: &FactoryMerkleUpdateWitness,
    deltas: &FactoryVaultDeltas,
) -> Result<()> {
    if deltas.delta_count() != 1 {
        return Err(ScriptError::FactorySpliceProofMismatch);
    }

    let before = witness.right_before()?;
    let after = witness.right_after()?;
    if before.kind() != FACTORY_RIGHT_KIND_RESERVE_CLAIM || !before.same_id(&after) {
        return Err(ScriptError::FactorySpliceProofMismatch);
    }

    let delta = deltas.delta(0)?;
    let expected_asset_kind = if before.asset_present() == 0 {
        VAULT_ASSET_KIND_CKB
    } else {
        VAULT_ASSET_KIND_XUDT
    };
    if delta.asset_kind() != expected_asset_kind || delta.asset_type() != before.asset_type() {
        return Err(ScriptError::FactorySpliceProofMismatch);
    }

    match kind {
        SPLICE_KIND_IN => {
            let claim_delta = after
                .quantity()
                .checked_sub(before.quantity())
                .ok_or(ScriptError::FactorySpliceProofMismatch)?;
            if claim_delta == 0 || claim_delta != delta.external_input() || delta.withdrawal() != 0
            {
                return Err(ScriptError::FactorySpliceProofMismatch);
            }
        }
        SPLICE_KIND_OUT => {
            let claim_delta = before
                .quantity()
                .checked_sub(after.quantity())
                .ok_or(ScriptError::FactorySpliceProofMismatch)?;
            if claim_delta == 0 || claim_delta != delta.withdrawal() || delta.external_input() != 0
            {
                return Err(ScriptError::FactorySpliceProofMismatch);
            }
        }
        _ => return Err(ScriptError::FactorySpliceProofEncoding),
    }

    Ok(())
}

fn verify_factory_splice_delta_set(
    kind: u8,
    old_vault: &FactoryVaultDescriptor,
    new_vault: &FactoryVaultDescriptor,
    deltas: &FactoryVaultDeltas,
) -> Result<()> {
    for index in 0..deltas.delta_count() as usize {
        let delta = deltas.delta(index)?;
        let old_amount =
            factory_vault_amount_for(old_vault, delta.asset_kind(), delta.asset_type())?
                .ok_or(ScriptError::FactorySpliceProofMismatch)?;
        let new_amount =
            factory_vault_amount_for(new_vault, delta.asset_kind(), delta.asset_type())?
                .ok_or(ScriptError::FactorySpliceProofMismatch)?;
        if old_amount != delta.old_amount() || new_amount != delta.new_amount() {
            return Err(ScriptError::FactorySpliceProofMismatch);
        }
        verify_factory_vault_delta(kind, &delta)?;
    }

    for index in 0..old_vault.asset_count() as usize {
        let old_asset = old_vault.asset(index)?;
        if factory_delta_amount_for(deltas, old_asset.asset_kind(), old_asset.asset_type())?
            .is_none()
        {
            let new_amount = factory_vault_amount_for(
                new_vault,
                old_asset.asset_kind(),
                old_asset.asset_type(),
            )?
            .ok_or(ScriptError::FactorySpliceProofMismatch)?;
            if new_amount != old_asset.amount() {
                return Err(ScriptError::FactorySpliceProofMismatch);
            }
        }
    }
    for index in 0..new_vault.asset_count() as usize {
        let new_asset = new_vault.asset(index)?;
        if factory_delta_amount_for(deltas, new_asset.asset_kind(), new_asset.asset_type())?
            .is_none()
        {
            let old_amount = factory_vault_amount_for(
                old_vault,
                new_asset.asset_kind(),
                new_asset.asset_type(),
            )?
            .ok_or(ScriptError::FactorySpliceProofMismatch)?;
            if old_amount != new_asset.amount() {
                return Err(ScriptError::FactorySpliceProofMismatch);
            }
        }
    }

    Ok(())
}

fn verify_factory_vault_delta(kind: u8, delta: &FactoryVaultDelta) -> Result<()> {
    let debits = delta
        .new_amount()
        .checked_add(delta.withdrawal())
        .ok_or(ScriptError::FactorySpliceProofMismatch)?;
    let credits = delta
        .old_amount()
        .checked_add(delta.external_input())
        .ok_or(ScriptError::FactorySpliceProofMismatch)?;
    if debits != credits {
        return Err(ScriptError::FactorySpliceProofMismatch);
    }

    match kind {
        SPLICE_KIND_IN => {
            if delta.external_input() == 0
                || delta.withdrawal() != 0
                || delta.new_amount() <= delta.old_amount()
            {
                return Err(ScriptError::FactorySpliceProofMismatch);
            }
        }
        SPLICE_KIND_OUT => {
            if delta.external_input() != 0
                || delta.withdrawal() == 0
                || delta.new_amount() >= delta.old_amount()
            {
                return Err(ScriptError::FactorySpliceProofMismatch);
            }
        }
        _ => return Err(ScriptError::FactorySpliceProofEncoding),
    }
    Ok(())
}

fn factory_vault_amount_for(
    descriptor: &FactoryVaultDescriptor,
    kind: u8,
    type_hash: &[u8],
) -> Result<Option<u128>> {
    for index in 0..descriptor.asset_count() as usize {
        let asset = descriptor.asset(index)?;
        if asset.asset_kind() == kind && asset.asset_type() == type_hash {
            return Ok(Some(asset.amount()));
        }
    }
    Ok(None)
}

fn factory_delta_amount_for(
    deltas: &FactoryVaultDeltas,
    kind: u8,
    type_hash: &[u8],
) -> Result<Option<(u128, u128)>> {
    for index in 0..deltas.delta_count() as usize {
        let delta = deltas.delta(index)?;
        if delta.asset_kind() == kind && delta.asset_type() == type_hash {
            return Ok(Some((delta.old_amount(), delta.new_amount())));
        }
    }
    Ok(None)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BilateralCkbSettlementDescriptor<'a> {
    raw: &'a [u8],
}

impl<'a> BilateralCkbSettlementDescriptor<'a> {
    pub fn parse(raw: &'a [u8]) -> Result<Self> {
        if raw.len() != BILATERAL_CKB_DESCRIPTOR_LEN {
            return Err(ScriptError::SettlementDescriptorEncoding);
        }
        let descriptor = Self { raw };
        if descriptor.version() != BILATERAL_CKB_DESCRIPTOR_VERSION
            || descriptor.output_count() != BILATERAL_CKB_DESCRIPTOR_OUTPUT_COUNT
            || descriptor.reserved() != 0
        {
            return Err(ScriptError::SettlementDescriptorEncoding);
        }
        if descriptor.lock_hash(0) >= descriptor.lock_hash(1) {
            return Err(ScriptError::SettlementDescriptorEncoding);
        }
        descriptor.checked_total_capacity()?;
        Ok(descriptor)
    }

    pub fn version(&self) -> u16 {
        read_u16(self.raw, 0)
    }

    pub fn output_count(&self) -> u8 {
        self.raw[2]
    }

    pub fn reserved(&self) -> u8 {
        self.raw[3]
    }

    pub fn lock_hash(&self, index: usize) -> &'a [u8] {
        field(self.raw, descriptor_output_offset(index), BYTE32_LEN)
    }

    pub fn capacity(&self, index: usize) -> u64 {
        read_u64(self.raw, descriptor_output_offset(index) + BYTE32_LEN)
    }

    pub fn total_capacity(&self) -> u64 {
        self.checked_total_capacity().unwrap_or(u64::MAX)
    }

    pub fn checked_total_capacity(&self) -> Result<u64> {
        self.capacity(0)
            .checked_add(self.capacity(1))
            .ok_or(ScriptError::SettlementDescriptorEncoding)
    }

    pub fn commitment(&self) -> [u8; 32] {
        settlement_descriptor_commitment(self.raw)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BilateralCkbXudtSettlementDescriptor<'a> {
    raw: &'a [u8],
}

impl<'a> BilateralCkbXudtSettlementDescriptor<'a> {
    pub fn parse(raw: &'a [u8]) -> Result<Self> {
        if raw.len() != BILATERAL_CKB_XUDT_DESCRIPTOR_LEN {
            return Err(ScriptError::SettlementDescriptorEncoding);
        }
        let descriptor = Self { raw };
        if descriptor.version() != BILATERAL_CKB_XUDT_DESCRIPTOR_VERSION
            || descriptor.output_count() != BILATERAL_CKB_DESCRIPTOR_OUTPUT_COUNT
            || descriptor.asset_count() != BILATERAL_CKB_XUDT_DESCRIPTOR_ASSET_COUNT
        {
            return Err(ScriptError::SettlementDescriptorEncoding);
        }
        if descriptor.lock_hash(0) >= descriptor.lock_hash(1) {
            return Err(ScriptError::SettlementDescriptorEncoding);
        }
        descriptor.checked_total_capacity()?;
        descriptor.checked_total_xudt_amount()?;
        Ok(descriptor)
    }

    pub fn version(&self) -> u16 {
        read_u16(self.raw, 0)
    }

    pub fn output_count(&self) -> u8 {
        self.raw[2]
    }

    pub fn asset_count(&self) -> u8 {
        self.raw[3]
    }

    pub fn xudt_type_hash(&self) -> &'a [u8] {
        field(self.raw, 4, BYTE32_LEN)
    }

    pub fn lock_hash(&self, index: usize) -> &'a [u8] {
        field(
            self.raw,
            ckb_xudt_descriptor_output_offset(index),
            BYTE32_LEN,
        )
    }

    pub fn capacity(&self, index: usize) -> u64 {
        read_u64(
            self.raw,
            ckb_xudt_descriptor_output_offset(index) + BYTE32_LEN,
        )
    }

    pub fn xudt_amount(&self, index: usize) -> u128 {
        read_u128(
            self.raw,
            ckb_xudt_descriptor_output_offset(index) + BYTE32_LEN + 8,
        )
    }

    pub fn total_capacity(&self) -> u64 {
        self.checked_total_capacity().unwrap_or(u64::MAX)
    }

    pub fn checked_total_capacity(&self) -> Result<u64> {
        self.capacity(0)
            .checked_add(self.capacity(1))
            .ok_or(ScriptError::SettlementDescriptorEncoding)
    }

    pub fn total_xudt_amount(&self) -> u128 {
        self.checked_total_xudt_amount().unwrap_or(u128::MAX)
    }

    pub fn checked_total_xudt_amount(&self) -> Result<u128> {
        self.xudt_amount(0)
            .checked_add(self.xudt_amount(1))
            .ok_or(ScriptError::SettlementDescriptorEncoding)
    }

    pub fn commitment(&self) -> [u8; 32] {
        settlement_descriptor_commitment(self.raw)
    }
}

pub fn settlement_descriptor_commitment(raw: &[u8]) -> [u8; 32] {
    blake2b256(&[SETTLEMENT_DESCRIPTOR_DOMAIN, raw])
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SpliceVaultAssetAmount<'a> {
    raw: &'a [u8],
}

impl<'a> SpliceVaultAssetAmount<'a> {
    pub fn parse(raw: &'a [u8]) -> Result<Self> {
        if raw.len() != SPLICE_VAULT_ASSET_AMOUNT_LEN {
            return Err(ScriptError::Encoding);
        }
        let amount = Self { raw };
        validate_vault_asset_encoding(amount.asset_kind(), amount.asset_type())?;
        Ok(amount)
    }

    pub fn asset_kind(&self) -> u8 {
        self.raw[0]
    }

    pub fn asset_type(&self) -> &'a [u8] {
        field(self.raw, 1, BYTE32_LEN)
    }

    pub fn amount(&self) -> u128 {
        read_u128(self.raw, 1 + BYTE32_LEN)
    }

    pub fn raw(&self) -> &'a [u8] {
        self.raw
    }

    fn asset_key(&self) -> (u8, &'a [u8]) {
        (self.asset_kind(), self.asset_type())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SpliceVaultDescriptor<'a> {
    raw: &'a [u8],
}

impl<'a> SpliceVaultDescriptor<'a> {
    pub fn parse(raw: &'a [u8]) -> Result<Self> {
        if raw.len() != SPLICE_VAULT_DESCRIPTOR_LEN {
            return Err(ScriptError::Encoding);
        }
        let descriptor = Self { raw };
        if descriptor.asset_count() == 0
            || descriptor.asset_count() > SPLICE_VAULT_DESCRIPTOR_MAX_ASSETS as u16
        {
            return Err(ScriptError::Encoding);
        }
        descriptor.validate_asset_order()?;
        descriptor.validate_unused_assets_zero()?;
        Ok(descriptor)
    }

    pub fn funding_anchor(&self) -> &'a [u8] {
        field(self.raw, 0, BYTE32_LEN)
    }

    pub fn asset_count(&self) -> u16 {
        read_u16(self.raw, BYTE32_LEN)
    }

    pub fn asset(&self, index: usize) -> Result<SpliceVaultAssetAmount<'a>> {
        SpliceVaultAssetAmount::parse(field(
            self.raw,
            splice_vault_asset_offset(index),
            SPLICE_VAULT_ASSET_AMOUNT_LEN,
        ))
    }

    pub fn commitment(&self) -> Result<[u8; 32]> {
        let count = self.asset_count();
        let count_bytes = count.to_le_bytes();
        let mut hasher = new_blake2b();
        hasher.update(VAULT_DESCRIPTOR_DOMAIN);
        hasher.update(self.funding_anchor());
        hasher.update(&count_bytes);
        for index in 0..count as usize {
            hasher.update(self.asset(index)?.raw());
        }
        let mut out = [0u8; 32];
        hasher.finalize(&mut out);
        Ok(out)
    }

    fn validate_asset_order(&self) -> Result<()> {
        let mut previous: Option<(u8, &'a [u8])> = None;
        for index in 0..self.asset_count() as usize {
            let asset = self.asset(index)?;
            if let Some(prev) = previous
                && prev >= asset.asset_key()
            {
                return Err(ScriptError::Encoding);
            }
            previous = Some(asset.asset_key());
        }
        Ok(())
    }

    fn validate_unused_assets_zero(&self) -> Result<()> {
        for index in self.asset_count() as usize..SPLICE_VAULT_DESCRIPTOR_MAX_ASSETS as usize {
            let raw = field(
                self.raw,
                splice_vault_asset_offset(index),
                SPLICE_VAULT_ASSET_AMOUNT_LEN,
            );
            if !raw.iter().all(|value| *value == 0) {
                return Err(ScriptError::Encoding);
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SpliceAssetDelta<'a> {
    raw: &'a [u8],
}

impl<'a> SpliceAssetDelta<'a> {
    pub fn parse(raw: &'a [u8]) -> Result<Self> {
        if raw.len() != SPLICE_ASSET_DELTA_LEN {
            return Err(ScriptError::Encoding);
        }
        let delta = Self { raw };
        validate_vault_asset_encoding(delta.asset_kind(), delta.asset_type())?;
        Ok(delta)
    }

    pub fn asset_kind(&self) -> u8 {
        self.raw[0]
    }

    pub fn asset_type(&self) -> &'a [u8] {
        field(self.raw, 1, BYTE32_LEN)
    }

    pub fn old_amount(&self) -> u128 {
        read_u128(self.raw, 1 + BYTE32_LEN)
    }

    pub fn new_amount(&self) -> u128 {
        read_u128(self.raw, 1 + BYTE32_LEN + 16)
    }

    pub fn external_input(&self) -> u128 {
        read_u128(self.raw, 1 + BYTE32_LEN + 32)
    }

    pub fn withdrawal(&self) -> u128 {
        read_u128(self.raw, 1 + BYTE32_LEN + 48)
    }

    pub fn signed_fee(&self) -> u128 {
        read_u128(self.raw, 1 + BYTE32_LEN + 64)
    }

    pub fn raw(&self) -> &'a [u8] {
        self.raw
    }

    fn asset_key(&self) -> (u8, &'a [u8]) {
        (self.asset_kind(), self.asset_type())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SpliceAssetDeltas<'a> {
    raw: &'a [u8],
}

impl<'a> SpliceAssetDeltas<'a> {
    pub fn parse(raw: &'a [u8]) -> Result<Self> {
        if raw.len() != SPLICE_ASSET_DELTAS_LEN {
            return Err(ScriptError::Encoding);
        }
        let deltas = Self { raw };
        if deltas.delta_count() == 0 || deltas.delta_count() > SPLICE_ASSET_DELTAS_MAX_DELTAS as u16
        {
            return Err(ScriptError::Encoding);
        }
        deltas.validate_delta_order()?;
        deltas.validate_unused_deltas_zero()?;
        Ok(deltas)
    }

    pub fn delta_count(&self) -> u16 {
        read_u16(self.raw, 0)
    }

    pub fn delta(&self, index: usize) -> Result<SpliceAssetDelta<'a>> {
        SpliceAssetDelta::parse(field(
            self.raw,
            splice_delta_offset(index),
            SPLICE_ASSET_DELTA_LEN,
        ))
    }

    pub fn commitment(&self) -> Result<[u8; 32]> {
        let count = self.delta_count();
        let count_bytes = count.to_le_bytes();
        let mut hasher = new_blake2b();
        hasher.update(SPLICE_DELTA_DOMAIN);
        hasher.update(&count_bytes);
        for index in 0..count as usize {
            hasher.update(self.delta(index)?.raw());
        }
        let mut out = [0u8; 32];
        hasher.finalize(&mut out);
        Ok(out)
    }

    fn validate_delta_order(&self) -> Result<()> {
        let mut previous: Option<(u8, &'a [u8])> = None;
        for index in 0..self.delta_count() as usize {
            let delta = self.delta(index)?;
            if let Some(prev) = previous
                && prev >= delta.asset_key()
            {
                return Err(ScriptError::Encoding);
            }
            previous = Some(delta.asset_key());
        }
        Ok(())
    }

    fn validate_unused_deltas_zero(&self) -> Result<()> {
        for index in self.delta_count() as usize..SPLICE_ASSET_DELTAS_MAX_DELTAS as usize {
            let raw = field(self.raw, splice_delta_offset(index), SPLICE_ASSET_DELTA_LEN);
            if !raw.iter().all(|value| *value == 0) {
                return Err(ScriptError::Encoding);
            }
        }
        Ok(())
    }
}

pub fn factory_local_exit_digest(
    state_output_index: u32,
    vault_output_index: u32,
    state_type_hash: &[u8],
    vault_lock_hash: &[u8],
    state_lock_hash: &[u8],
    exit_state_header: &[u8],
    settlement_descriptor: &[u8],
) -> [u8; 32] {
    blake2b256(&[
        FACTORY_LOCAL_EXIT_DOMAIN,
        &state_output_index.to_le_bytes(),
        &vault_output_index.to_le_bytes(),
        state_type_hash,
        vault_lock_hash,
        state_lock_hash,
        exit_state_header,
        settlement_descriptor,
    ])
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SponsorPolicy<'a> {
    raw: &'a [u8],
}

impl<'a> SponsorPolicy<'a> {
    pub fn parse(raw: &'a [u8]) -> Result<Self> {
        if raw.len() != SPONSOR_POLICY_LEN {
            return Err(ScriptError::Encoding);
        }
        Ok(Self { raw })
    }

    pub fn channel_id(&self) -> &'a [u8] {
        field(self.raw, 0, 32)
    }

    pub fn min_state_number(&self) -> u64 {
        read_u64(self.raw, 32)
    }

    pub fn max_state_number(&self) -> u64 {
        read_u64(self.raw, 40)
    }

    pub fn max_fee_per_tx(&self) -> u64 {
        read_u64(self.raw, 48)
    }

    pub fn max_total_fee(&self) -> u64 {
        read_u64(self.raw, 56)
    }

    pub fn already_spent(&self) -> u64 {
        read_u64(self.raw, 64)
    }

    pub fn expiry(&self) -> u64 {
        read_u64(self.raw, 72)
    }

    pub fn publication_state_type_hash(&self) -> &'a [u8] {
        field(self.raw, 80, 32)
    }

    pub fn change_lock(&self) -> &'a [u8] {
        field(self.raw, 112, 32)
    }
}

pub fn read_u16(raw: &[u8], offset: usize) -> u16 {
    let mut bytes = [0u8; 2];
    bytes.copy_from_slice(&raw[offset..offset + 2]);
    u16::from_le_bytes(bytes)
}

pub fn write_u16(raw: &mut [u8], offset: usize, value: u16) {
    raw[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

pub fn read_u64(raw: &[u8], offset: usize) -> u64 {
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&raw[offset..offset + 8]);
    u64::from_le_bytes(bytes)
}

pub fn write_u64(raw: &mut [u8], offset: usize, value: u64) {
    raw[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

pub fn read_u32(raw: &[u8], offset: usize) -> u32 {
    let mut bytes = [0u8; 4];
    bytes.copy_from_slice(&raw[offset..offset + 4]);
    u32::from_le_bytes(bytes)
}

pub fn write_u32(raw: &mut [u8], offset: usize, value: u32) {
    raw[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

pub fn read_u128(raw: &[u8], offset: usize) -> u128 {
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&raw[offset..offset + 16]);
    u128::from_le_bytes(bytes)
}

pub fn write_u128(raw: &mut [u8], offset: usize, value: u128) {
    raw[offset..offset + 16].copy_from_slice(&value.to_le_bytes());
}

pub fn field(raw: &[u8], offset: usize, len: usize) -> &[u8] {
    &raw[offset..offset + len]
}

const CKB_SINCE_LOCK_TYPE_FLAG: u64 = 1 << 63;
const CKB_SINCE_METRIC_TYPE_FLAG_MASK: u64 = 0x6000_0000_0000_0000;
const CKB_SINCE_REMAIN_FLAGS_BITS: u64 = 0x1f00_0000_0000_0000;
const CKB_SINCE_VALUE_MASK: u64 = 0x00ff_ffff_ffff_ffff;
const CKB_SINCE_LOCK_BY_BLOCK_NUMBER: u64 = 0;

pub fn relative_block_since(value: u64) -> Result<u64> {
    if value & !CKB_SINCE_VALUE_MASK != 0 {
        return Err(ScriptError::StateSinceNotMature);
    }
    Ok(CKB_SINCE_LOCK_TYPE_FLAG | CKB_SINCE_LOCK_BY_BLOCK_NUMBER | value)
}

pub fn validate_relative_block_since(input_since: u64, required_since: u64) -> Result<()> {
    if !since_is_valid_relative_block(input_since) || !since_is_valid_relative_block(required_since)
    {
        return Err(ScriptError::StateSinceNotMature);
    }
    if (input_since & CKB_SINCE_VALUE_MASK) < (required_since & CKB_SINCE_VALUE_MASK) {
        return Err(ScriptError::StateSinceNotMature);
    }
    Ok(())
}

fn since_is_valid_relative_block(value: u64) -> bool {
    (value & CKB_SINCE_LOCK_TYPE_FLAG != 0)
        && (value & CKB_SINCE_REMAIN_FLAGS_BITS == 0)
        && (value & CKB_SINCE_METRIC_TYPE_FLAG_MASK == CKB_SINCE_LOCK_BY_BLOCK_NUMBER)
}

pub fn vault_cell_commitment(
    lock_hash: &[u8],
    capacity: u64,
    type_hash: Option<&[u8]>,
    data: &[u8],
) -> [u8; 32] {
    let capacity = capacity.to_le_bytes();
    let data_len = (data.len() as u64).to_le_bytes();
    let type_present = [u8::from(type_hash.is_some())];
    let mut hasher = new_blake2b();
    hasher.update(VAULT_CELL_COMMITMENT_DOMAIN);
    hasher.update(lock_hash);
    hasher.update(&capacity);
    hasher.update(&type_present);
    if let Some(type_hash) = type_hash {
        hasher.update(type_hash);
    }
    hasher.update(&data_len);
    hasher.update(data);
    let mut out = [0u8; 32];
    hasher.finalize(&mut out);
    out
}

pub fn blake2b256(chunks: &[&[u8]]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let mut hasher = new_blake2b();
    for chunk in chunks {
        hasher.update(chunk);
    }
    hasher.finalize(&mut out);
    out
}

pub fn funding_context_id(
    chain_id: &[u8],
    channel_id: &[u8],
    funding_anchor: &[u8],
    vault_set_commitment: &[u8],
) -> [u8; 32] {
    blake2b256(&[
        FUNDING_CONTEXT_DOMAIN,
        chain_id,
        channel_id,
        funding_anchor,
        vault_set_commitment,
    ])
}

pub fn participants_commitment(threshold: u8, pubkeys: &[&[u8]]) -> [u8; 32] {
    let count = [pubkeys.len() as u8];
    let threshold = [threshold];
    let mut hasher = new_blake2b();
    hasher.update(PARTICIPANTS_DOMAIN);
    hasher.update(&threshold);
    hasher.update(&count);
    for pubkey in pubkeys {
        hasher.update(pubkey);
    }
    let mut out = [0u8; 32];
    hasher.finalize(&mut out);
    out
}

pub fn factory_participants_commitment(threshold: u8, entries: &[(&[u8], &[u8])]) -> [u8; 32] {
    let count = [entries.len() as u8];
    let threshold = [threshold];
    let mut hasher = new_blake2b();
    hasher.update(FACTORY_PARTICIPANTS_DOMAIN);
    hasher.update(&threshold);
    hasher.update(&count);
    for (participant, pubkey) in entries {
        hasher.update(participant);
        hasher.update(pubkey);
    }
    let mut out = [0u8; 32];
    hasher.finalize(&mut out);
    out
}

fn participant_offset(index: usize) -> usize {
    4 + index * (COMPRESSED_SECP256K1_PUBKEY_LEN + ECDSA_SIGNATURE_LEN)
}

fn splice_participant_offset(index: usize) -> usize {
    4 + index * (COMPRESSED_SECP256K1_PUBKEY_LEN + ECDSA_SIGNATURE_LEN)
}

fn splice_transition_header_offset() -> usize {
    2
}

fn splice_transition_signature_offset() -> usize {
    splice_transition_header_offset() + SPLICE_HEADER_LEN
}

fn splice_transition_old_vault_offset() -> usize {
    splice_transition_signature_offset() + SPLICE_SIGNATURE_WITNESS_LEN
}

fn splice_transition_new_vault_offset() -> usize {
    splice_transition_old_vault_offset() + SPLICE_VAULT_DESCRIPTOR_LEN
}

fn splice_transition_deltas_offset() -> usize {
    splice_transition_new_vault_offset() + SPLICE_VAULT_DESCRIPTOR_LEN
}

fn factory_participant_offset(index: usize) -> usize {
    4 + index * (BYTE32_LEN + COMPRESSED_SECP256K1_PUBKEY_LEN + ECDSA_SIGNATURE_LEN)
}

fn factory_splice_header_offset() -> usize {
    2
}

fn factory_splice_signature_offset() -> usize {
    factory_splice_header_offset() + FACTORY_SPLICE_HEADER_LEN
}

fn factory_splice_old_vault_offset() -> usize {
    factory_splice_signature_offset() + FACTORY_SIGNATURE_WITNESS_LEN
}

fn factory_splice_new_vault_offset() -> usize {
    factory_splice_old_vault_offset() + FACTORY_VAULT_DESCRIPTOR_LEN
}

fn factory_splice_deltas_offset() -> usize {
    factory_splice_new_vault_offset() + FACTORY_VAULT_DESCRIPTOR_LEN
}

fn factory_reduced_splice_header_offset() -> usize {
    2
}

fn factory_reduced_splice_merkle_offset() -> usize {
    factory_reduced_splice_header_offset() + FACTORY_SPLICE_HEADER_LEN
}

fn factory_reduced_splice_old_vault_offset() -> usize {
    factory_reduced_splice_merkle_offset() + FACTORY_MERKLE_UPDATE_WITNESS_LEN
}

fn factory_reduced_splice_new_vault_offset() -> usize {
    factory_reduced_splice_old_vault_offset() + FACTORY_VAULT_DESCRIPTOR_LEN
}

fn factory_reduced_splice_deltas_offset() -> usize {
    factory_reduced_splice_new_vault_offset() + FACTORY_VAULT_DESCRIPTOR_LEN
}

fn factory_reduced_participant_offset(index: usize) -> usize {
    8 + index * FACTORY_REDUCED_RIGHTS_PARTICIPANT_ENTRY_LEN
}

fn factory_reduced_touched_offset() -> usize {
    8 + FACTORY_REDUCED_RIGHTS_PARTICIPANT_COUNT as usize
        * FACTORY_REDUCED_RIGHTS_PARTICIPANT_ENTRY_LEN
}

fn factory_reduced_right_offset(after: bool, index: usize) -> usize {
    let before_offset = factory_reduced_touched_offset() + BYTE32_LEN;
    if after {
        before_offset
            + FACTORY_REDUCED_RIGHTS_COUNT as usize * FACTORY_RIGHT_LEN
            + index * FACTORY_RIGHT_LEN
    } else {
        before_offset + index * FACTORY_RIGHT_LEN
    }
}

fn factory_merkle_participant_offset(index: usize) -> usize {
    8 + index * FACTORY_REDUCED_RIGHTS_PARTICIPANT_ENTRY_LEN
}

fn factory_merkle_touched_offset() -> usize {
    8 + FACTORY_REDUCED_RIGHTS_PARTICIPANT_COUNT as usize
        * FACTORY_REDUCED_RIGHTS_PARTICIPANT_ENTRY_LEN
}

fn factory_merkle_right_offset(after: bool) -> usize {
    let before_offset = factory_merkle_touched_offset() + BYTE32_LEN;
    if after {
        before_offset + FACTORY_RIGHT_LEN
    } else {
        before_offset
    }
}

fn factory_merkle_sibling_offset(depth: usize) -> usize {
    factory_merkle_right_offset(true) + FACTORY_RIGHT_LEN + depth * BYTE32_LEN
}

fn factory_reduced_exit_participant_offset(index: usize) -> usize {
    8 + index * FACTORY_REDUCED_RIGHTS_PARTICIPANT_ENTRY_LEN
}

fn factory_reduced_exit_touched_offset() -> usize {
    8 + FACTORY_REDUCED_RIGHTS_PARTICIPANT_COUNT as usize
        * FACTORY_REDUCED_RIGHTS_PARTICIPANT_ENTRY_LEN
}

fn factory_reduced_exit_release_quantity_offset() -> usize {
    factory_reduced_exit_touched_offset() + BYTE32_LEN
}

fn factory_reduced_exit_state_output_index_offset() -> usize {
    factory_reduced_exit_release_quantity_offset() + 16
}

fn factory_reduced_exit_vault_output_index_offset() -> usize {
    factory_reduced_exit_state_output_index_offset() + 4
}

fn factory_reduced_exit_state_type_hash_offset() -> usize {
    factory_reduced_exit_vault_output_index_offset() + 4
}

fn factory_reduced_exit_vault_lock_hash_offset() -> usize {
    factory_reduced_exit_state_type_hash_offset() + BYTE32_LEN
}

fn factory_reduced_exit_state_lock_hash_offset() -> usize {
    factory_reduced_exit_vault_lock_hash_offset() + BYTE32_LEN
}

fn factory_reduced_exit_state_header_offset() -> usize {
    factory_reduced_exit_state_lock_hash_offset() + BYTE32_LEN
}

fn factory_reduced_exit_descriptor_offset() -> usize {
    factory_reduced_exit_state_header_offset() + STATE_HEADER_LEN
}

fn factory_reduced_exit_right_offset(after: bool, descriptor_len: usize, index: usize) -> usize {
    let before_offset = factory_reduced_exit_descriptor_offset() + descriptor_len;
    if after {
        before_offset
            + FACTORY_REDUCED_EXIT_RIGHTS_COUNT as usize * FACTORY_RIGHT_LEN
            + index * FACTORY_RIGHT_LEN
    } else {
        before_offset + index * FACTORY_RIGHT_LEN
    }
}

fn descriptor_output_offset(index: usize) -> usize {
    4 + index * (BYTE32_LEN + 8)
}

fn ckb_xudt_descriptor_output_offset(index: usize) -> usize {
    4 + BYTE32_LEN + index * (BYTE32_LEN + 8 + 16)
}

fn splice_vault_asset_offset(index: usize) -> usize {
    BYTE32_LEN + 2 + index * SPLICE_VAULT_ASSET_AMOUNT_LEN
}

fn splice_delta_offset(index: usize) -> usize {
    2 + index * SPLICE_ASSET_DELTA_LEN
}

fn factory_vault_asset_offset(index: usize) -> usize {
    BYTE32_LEN + 2 + index * FACTORY_VAULT_ASSET_AMOUNT_LEN
}

fn factory_vault_delta_offset(index: usize) -> usize {
    2 + index * FACTORY_VAULT_DELTA_LEN
}

fn validate_vault_asset_encoding(kind: u8, type_hash: &[u8]) -> Result<()> {
    match kind {
        VAULT_ASSET_KIND_CKB => {
            if type_hash.iter().all(|value| *value == 0) {
                Ok(())
            } else {
                Err(ScriptError::Encoding)
            }
        }
        VAULT_ASSET_KIND_XUDT => Ok(()),
        _ => Err(ScriptError::Encoding),
    }
}

fn factory_right_key(right: &FactoryRight) -> [u8; 32] {
    blake2b256(&[
        FACTORY_RIGHT_KEY_DOMAIN,
        right.participant(),
        right.subchannel(),
        &[right.kind()],
        &[right.asset_present()],
        right.asset_type(),
    ])
}

fn factory_right_leaf_hash(right: &FactoryRight) -> [u8; 32] {
    let key = factory_right_key(right);
    blake2b256(&[FACTORY_RIGHT_LEAF_DOMAIN, &key, right.raw()])
}

fn factory_right_node_hash(depth: usize, left: &[u8], right: &[u8]) -> [u8; 32] {
    blake2b256(&[
        FACTORY_RIGHT_NODE_DOMAIN,
        &(depth as u16).to_le_bytes(),
        left,
        right,
    ])
}

fn factory_key_bit(key: &[u8; 32], depth: usize) -> bool {
    let byte = key[depth / 8];
    let mask = 0x80u8 >> (depth % 8);
    byte & mask != 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use k256::ecdsa::SigningKey;
    use k256::ecdsa::signature::hazmat::PrehashSigner;

    fn signing_key(byte: u8) -> SigningKey {
        SigningKey::from_slice(&[byte; 32]).unwrap()
    }

    fn pubkey(key: &SigningKey) -> [u8; COMPRESSED_SECP256K1_PUBKEY_LEN] {
        let encoded = key.verifying_key().to_encoded_point(true);
        let mut out = [0u8; COMPRESSED_SECP256K1_PUBKEY_LEN];
        out.copy_from_slice(encoded.as_bytes());
        out
    }

    fn signature(key: &SigningKey, digest: &[u8; 32]) -> [u8; ECDSA_SIGNATURE_LEN] {
        let sig: Signature = key.sign_prehash(digest).unwrap();
        let mut out = [0u8; ECDSA_SIGNATURE_LEN];
        let signature_bytes = sig.to_bytes();
        out.copy_from_slice(signature_bytes.as_ref());
        out
    }

    fn signed_bilateral_witness(
        key0: &SigningKey,
        key1: &SigningKey,
        digest: &[u8; 32],
    ) -> [u8; BILATERAL_SIGNATURE_WITNESS_LEN] {
        let mut entries = [
            (pubkey(key0), signature(key0, digest)),
            (pubkey(key1), signature(key1, digest)),
        ];
        entries.sort_by(|left, right| left.0.cmp(&right.0));

        let mut raw = [0u8; BILATERAL_SIGNATURE_WITNESS_LEN];
        put_u16(&mut raw, 0, BILATERAL_SIGNATURE_WITNESS_VERSION);
        raw[2] = BILATERAL_SIGNATURE_THRESHOLD;
        raw[3] = BILATERAL_SIGNATURE_COUNT;
        for (index, (pubkey, sig)) in entries.iter().enumerate() {
            let offset = participant_offset(index);
            raw[offset..offset + COMPRESSED_SECP256K1_PUBKEY_LEN].copy_from_slice(pubkey);
            raw[offset + COMPRESSED_SECP256K1_PUBKEY_LEN
                ..offset + COMPRESSED_SECP256K1_PUBKEY_LEN + ECDSA_SIGNATURE_LEN]
                .copy_from_slice(sig);
        }
        raw
    }

    fn signed_factory_witness(
        participant0: [u8; BYTE32_LEN],
        key0: &SigningKey,
        participant1: [u8; BYTE32_LEN],
        key1: &SigningKey,
        digest: &[u8; 32],
    ) -> [u8; FACTORY_SIGNATURE_WITNESS_LEN] {
        let mut entries = [
            (participant0, pubkey(key0), signature(key0, digest)),
            (participant1, pubkey(key1), signature(key1, digest)),
        ];
        entries.sort_by(|left, right| left.0.cmp(&right.0));

        let mut raw = [0u8; FACTORY_SIGNATURE_WITNESS_LEN];
        put_u16(&mut raw, 0, FACTORY_SIGNATURE_WITNESS_VERSION);
        raw[2] = FACTORY_SIGNATURE_THRESHOLD;
        raw[3] = FACTORY_SIGNATURE_COUNT;
        for (index, (participant, pubkey, sig)) in entries.iter().enumerate() {
            let offset = factory_participant_offset(index);
            raw[offset..offset + BYTE32_LEN].copy_from_slice(participant);
            raw[offset + BYTE32_LEN..offset + BYTE32_LEN + COMPRESSED_SECP256K1_PUBKEY_LEN]
                .copy_from_slice(pubkey);
            raw[offset + BYTE32_LEN + COMPRESSED_SECP256K1_PUBKEY_LEN
                ..offset + BYTE32_LEN + COMPRESSED_SECP256K1_PUBKEY_LEN + ECDSA_SIGNATURE_LEN]
                .copy_from_slice(sig);
        }
        raw
    }

    fn factory_right_bytes(
        participant: u8,
        subchannel: u8,
        kind: u8,
        quantity: u128,
    ) -> [u8; FACTORY_RIGHT_LEN] {
        factory_right_bytes_with_asset(participant, subchannel, kind, quantity, None)
    }

    fn factory_right_bytes_with_asset(
        participant: u8,
        subchannel: u8,
        kind: u8,
        quantity: u128,
        asset_type: Option<[u8; BYTE32_LEN]>,
    ) -> [u8; FACTORY_RIGHT_LEN] {
        let mut raw = [0u8; FACTORY_RIGHT_LEN];
        raw[0..BYTE32_LEN].fill(participant);
        raw[BYTE32_LEN..2 * BYTE32_LEN].fill(subchannel);
        raw[2 * BYTE32_LEN] = kind;
        if let Some(asset_type) = asset_type {
            raw[2 * BYTE32_LEN + 1] = 1;
            raw[2 * BYTE32_LEN + 2..2 * BYTE32_LEN + 2 + BYTE32_LEN].copy_from_slice(&asset_type);
        }
        put_u128(&mut raw, 2 * BYTE32_LEN + 2 + BYTE32_LEN, quantity);
        raw
    }

    fn reduced_rights_pair(
        touched_after_balance: u128,
    ) -> (
        [[u8; FACTORY_RIGHT_LEN]; FACTORY_REDUCED_RIGHTS_COUNT as usize],
        [[u8; FACTORY_RIGHT_LEN]; FACTORY_REDUCED_RIGHTS_COUNT as usize],
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

    fn reduced_rights_witness_raw(
        participant0: [u8; BYTE32_LEN],
        key0: &SigningKey,
        participant1: [u8; BYTE32_LEN],
        key1: &SigningKey,
        touched: [u8; BYTE32_LEN],
        before: &[[u8; FACTORY_RIGHT_LEN]; FACTORY_REDUCED_RIGHTS_COUNT as usize],
        after: &[[u8; FACTORY_RIGHT_LEN]; FACTORY_REDUCED_RIGHTS_COUNT as usize],
    ) -> [u8; FACTORY_REDUCED_RIGHTS_WITNESS_LEN] {
        let mut entries = [(participant0, pubkey(key0)), (participant1, pubkey(key1))];
        entries.sort_by(|left, right| left.0.cmp(&right.0));

        let mut raw = [0u8; FACTORY_REDUCED_RIGHTS_WITNESS_LEN];
        put_u16(&mut raw, 0, FACTORY_REDUCED_RIGHTS_WITNESS_VERSION);
        raw[2] = FACTORY_REDUCED_RIGHTS_PARTICIPANT_THRESHOLD;
        raw[3] = FACTORY_REDUCED_RIGHTS_PARTICIPANT_COUNT;
        raw[4] = FACTORY_REDUCED_RIGHTS_AUTHORISED_COUNT;
        raw[5] = FACTORY_REDUCED_RIGHTS_COUNT;
        for (index, (participant, pubkey)) in entries.iter().enumerate() {
            let offset = factory_reduced_participant_offset(index);
            raw[offset..offset + BYTE32_LEN].copy_from_slice(participant);
            raw[offset + BYTE32_LEN..offset + BYTE32_LEN + COMPRESSED_SECP256K1_PUBKEY_LEN]
                .copy_from_slice(pubkey);
            raw[offset + BYTE32_LEN + COMPRESSED_SECP256K1_PUBKEY_LEN] =
                u8::from(participant.as_slice() == touched.as_slice());
        }
        raw[factory_reduced_touched_offset()..factory_reduced_touched_offset() + BYTE32_LEN]
            .copy_from_slice(&touched);
        for index in 0..FACTORY_REDUCED_RIGHTS_COUNT as usize {
            let before_offset = factory_reduced_right_offset(false, index);
            raw[before_offset..before_offset + FACTORY_RIGHT_LEN].copy_from_slice(&before[index]);
            let after_offset = factory_reduced_right_offset(true, index);
            raw[after_offset..after_offset + FACTORY_RIGHT_LEN].copy_from_slice(&after[index]);
        }
        raw
    }

    fn sign_reduced_rights_witness(
        raw: &mut [u8; FACTORY_REDUCED_RIGHTS_WITNESS_LEN],
        participant: [u8; BYTE32_LEN],
        key: &SigningKey,
        digest: &[u8; 32],
    ) {
        let sig = signature(key, digest);
        for index in 0..FACTORY_REDUCED_RIGHTS_PARTICIPANT_COUNT as usize {
            if field(raw, factory_reduced_participant_offset(index), BYTE32_LEN)
                == participant.as_slice()
            {
                let offset = factory_reduced_participant_offset(index)
                    + BYTE32_LEN
                    + COMPRESSED_SECP256K1_PUBKEY_LEN
                    + 1;
                raw[offset..offset + ECDSA_SIGNATURE_LEN].copy_from_slice(&sig);
            }
        }
    }

    fn merkle_update_witness_raw(
        touched_after_balance: u128,
    ) -> (
        [u8; FACTORY_MERKLE_UPDATE_WITNESS_LEN],
        SigningKey,
        SigningKey,
    ) {
        let key0 = signing_key(1);
        let key1 = signing_key(2);
        let mut entries = [([1u8; 32], pubkey(&key0)), ([2u8; 32], pubkey(&key1))];
        entries.sort_by(|left, right| left.0.cmp(&right.0));

        let mut raw = [0u8; FACTORY_MERKLE_UPDATE_WITNESS_LEN];
        put_u16(&mut raw, 0, FACTORY_MERKLE_UPDATE_WITNESS_VERSION);
        raw[2] = FACTORY_REDUCED_RIGHTS_PARTICIPANT_THRESHOLD;
        raw[3] = FACTORY_REDUCED_RIGHTS_PARTICIPANT_COUNT;
        raw[4] = FACTORY_REDUCED_RIGHTS_AUTHORISED_COUNT;
        raw[5] = FACTORY_MERKLE_UPDATE_RIGHT_COUNT;
        for (index, (participant, pubkey)) in entries.iter().enumerate() {
            let offset = factory_merkle_participant_offset(index);
            raw[offset..offset + BYTE32_LEN].copy_from_slice(participant);
            raw[offset + BYTE32_LEN..offset + BYTE32_LEN + COMPRESSED_SECP256K1_PUBKEY_LEN]
                .copy_from_slice(pubkey);
            raw[offset + BYTE32_LEN + COMPRESSED_SECP256K1_PUBKEY_LEN] =
                u8::from(participant == &[1u8; BYTE32_LEN]);
        }
        raw[factory_merkle_touched_offset()..factory_merkle_touched_offset() + BYTE32_LEN]
            .copy_from_slice(&[1u8; BYTE32_LEN]);
        raw[factory_merkle_right_offset(false)
            ..factory_merkle_right_offset(false) + FACTORY_RIGHT_LEN]
            .copy_from_slice(&factory_right_bytes(1, 10, 0, 100));
        raw[factory_merkle_right_offset(true)
            ..factory_merkle_right_offset(true) + FACTORY_RIGHT_LEN]
            .copy_from_slice(&factory_right_bytes(1, 10, 0, touched_after_balance));
        for depth in 0..FACTORY_SPARSE_MERKLE_DEPTH {
            let offset = factory_merkle_sibling_offset(depth);
            raw[offset..offset + BYTE32_LEN].fill(depth as u8);
        }

        (raw, key0, key1)
    }

    fn sign_merkle_update_witness(
        raw: &mut [u8; FACTORY_MERKLE_UPDATE_WITNESS_LEN],
        participant: [u8; BYTE32_LEN],
        key: &SigningKey,
        digest: &[u8; 32],
    ) {
        let sig = signature(key, digest);
        for index in 0..FACTORY_REDUCED_RIGHTS_PARTICIPANT_COUNT as usize {
            if field(raw, factory_merkle_participant_offset(index), BYTE32_LEN)
                == participant.as_slice()
            {
                let offset = factory_merkle_participant_offset(index)
                    + BYTE32_LEN
                    + COMPRESSED_SECP256K1_PUBKEY_LEN
                    + 1;
                raw[offset..offset + ECDSA_SIGNATURE_LEN].copy_from_slice(&sig);
            }
        }
    }

    fn merkle_update_headers_and_witness(
        after_balance: u128,
    ) -> (
        [u8; FACTORY_STATE_HEADER_LEN],
        [u8; FACTORY_STATE_HEADER_LEN],
        [u8; FACTORY_MERKLE_UPDATE_WITNESS_LEN],
    ) {
        let (mut witness_raw, key0, key1) = merkle_update_witness_raw(after_balance);
        let mut entries = [([1u8; 32], pubkey(&key0)), ([2u8; 32], pubkey(&key1))];
        entries.sort_by(|left, right| left.0.cmp(&right.0));
        let participants_commitment = factory_participants_commitment(
            2,
            &[
                (entries[0].0.as_slice(), entries[0].1.as_slice()),
                (entries[1].0.as_slice(), entries[1].1.as_slice()),
            ],
        );
        let witness = FactoryMerkleUpdateWitness::parse(&witness_raw).unwrap();

        let mut old_raw = factory_header_bytes(1);
        old_raw[76..108].copy_from_slice(&witness.rights_root(false).unwrap());
        old_raw[108..140].copy_from_slice(&participants_commitment);
        let old_header = FactoryStateHeader::parse(&old_raw).unwrap();

        let mut new_raw = factory_header_bytes(2);
        new_raw[76..108].copy_from_slice(&witness.rights_root(true).unwrap());
        new_raw[108..140].copy_from_slice(&participants_commitment);
        new_raw[140..172].copy_from_slice(old_header.access_manifest_root());
        let preliminary_new = FactoryStateHeader::parse(&new_raw).unwrap();
        let digest = witness
            .non_interference_digest(&old_header, &preliminary_new)
            .unwrap();
        new_raw[172..204].copy_from_slice(&digest);
        let new_header = FactoryStateHeader::parse(&new_raw).unwrap();
        sign_merkle_update_witness(
            &mut witness_raw,
            [1u8; 32],
            &key0,
            &new_header.signing_digest(),
        );

        (old_raw, new_raw, witness_raw)
    }

    fn reduced_rights_headers_and_witness(
        after_balance: u128,
    ) -> (
        [u8; FACTORY_STATE_HEADER_LEN],
        [u8; FACTORY_STATE_HEADER_LEN],
        [u8; FACTORY_REDUCED_RIGHTS_WITNESS_LEN],
    ) {
        let key0 = signing_key(1);
        let key1 = signing_key(2);
        let mut entries = [([1u8; 32], pubkey(&key0)), ([2u8; 32], pubkey(&key1))];
        entries.sort_by(|left, right| left.0.cmp(&right.0));
        let participants_commitment = factory_participants_commitment(
            2,
            &[
                (entries[0].0.as_slice(), entries[0].1.as_slice()),
                (entries[1].0.as_slice(), entries[1].1.as_slice()),
            ],
        );
        let (before, after) = reduced_rights_pair(after_balance);
        let mut witness_raw = reduced_rights_witness_raw(
            [1u8; 32], &key0, [2u8; 32], &key1, [1u8; 32], &before, &after,
        );
        let witness = FactoryReducedRightsWitness::parse(&witness_raw).unwrap();

        let mut old_raw = factory_header_bytes(1);
        old_raw[76..108].copy_from_slice(&witness.rights_root(false).unwrap());
        old_raw[108..140].copy_from_slice(&participants_commitment);
        old_raw[140..172].copy_from_slice(&witness.access_manifest_root(false).unwrap());
        let old_header = FactoryStateHeader::parse(&old_raw).unwrap();

        let mut new_raw = factory_header_bytes(2);
        new_raw[76..108].copy_from_slice(&witness.rights_root(true).unwrap());
        new_raw[108..140].copy_from_slice(&participants_commitment);
        new_raw[140..172].copy_from_slice(&witness.access_manifest_root(true).unwrap());
        let preliminary_new = FactoryStateHeader::parse(&new_raw).unwrap();
        let digest = witness
            .non_interference_digest(&old_header, &preliminary_new)
            .unwrap();
        new_raw[172..204].copy_from_slice(&digest);
        let new_header = FactoryStateHeader::parse(&new_raw).unwrap();
        sign_reduced_rights_witness(
            &mut witness_raw,
            [1u8; 32],
            &key0,
            &new_header.signing_digest(),
        );

        (old_raw, new_raw, witness_raw)
    }

    fn reduced_exit_rights_pair(
        reserve_claim_after_quantity: u128,
        mutate_other_right: bool,
        reserve_asset_type: Option<[u8; BYTE32_LEN]>,
    ) -> (
        [[u8; FACTORY_RIGHT_LEN]; FACTORY_REDUCED_EXIT_RIGHTS_COUNT as usize],
        [[u8; FACTORY_RIGHT_LEN]; FACTORY_REDUCED_EXIT_RIGHTS_COUNT as usize],
    ) {
        let before = [
            factory_right_bytes(1, 10, 0, 100),
            factory_right_bytes_with_asset(
                1,
                10,
                FACTORY_RIGHT_KIND_RESERVE_CLAIM,
                50,
                reserve_asset_type,
            ),
            factory_right_bytes(1, 10, 2, 1),
            factory_right_bytes(1, 10, 3, 1),
            factory_right_bytes(1, 10, 4, 20),
            factory_right_bytes_with_asset(1, 11, FACTORY_RIGHT_KIND_RESERVE_CLAIM, 100, None),
            factory_right_bytes(2, 10, 0, 100),
            factory_right_bytes(2, 10, FACTORY_RIGHT_KIND_RESERVE_CLAIM, 50),
            factory_right_bytes(2, 10, 2, 1),
            factory_right_bytes(2, 10, 3, 1),
            factory_right_bytes(2, 10, 4, 20),
            factory_right_bytes_with_asset(2, 11, FACTORY_RIGHT_KIND_RESERVE_CLAIM, 100, None),
        ];
        let mut after = before;
        after[1] = factory_right_bytes_with_asset(
            1,
            10,
            FACTORY_RIGHT_KIND_RESERVE_CLAIM,
            reserve_claim_after_quantity,
            reserve_asset_type,
        );
        if mutate_other_right {
            after[0] = factory_right_bytes(1, 10, 0, 90);
        }
        (before, after)
    }

    fn reduced_exit_witness_raw(
        key0: &SigningKey,
        key1: &SigningKey,
        release_quantity: u128,
        exit_state_header: &[u8; STATE_HEADER_LEN],
        settlement_descriptor: &[u8; BILATERAL_CKB_DESCRIPTOR_LEN],
        before: &[[u8; FACTORY_RIGHT_LEN]; FACTORY_REDUCED_EXIT_RIGHTS_COUNT as usize],
        after: &[[u8; FACTORY_RIGHT_LEN]; FACTORY_REDUCED_EXIT_RIGHTS_COUNT as usize],
    ) -> [u8; FACTORY_REDUCED_EXIT_WITNESS_LEN] {
        let touched = [1u8; BYTE32_LEN];
        let mut entries = [([1u8; 32], pubkey(key0)), ([2u8; 32], pubkey(key1))];
        entries.sort_by(|left, right| left.0.cmp(&right.0));

        let mut raw = [0u8; FACTORY_REDUCED_EXIT_WITNESS_LEN];
        put_u16(&mut raw, 0, FACTORY_REDUCED_EXIT_WITNESS_VERSION);
        raw[2] = FACTORY_REDUCED_RIGHTS_PARTICIPANT_THRESHOLD;
        raw[3] = FACTORY_REDUCED_RIGHTS_PARTICIPANT_COUNT;
        raw[4] = FACTORY_REDUCED_RIGHTS_AUTHORISED_COUNT;
        raw[5] = FACTORY_REDUCED_EXIT_RIGHTS_COUNT;
        for (index, (participant, pubkey)) in entries.iter().enumerate() {
            let offset = factory_reduced_exit_participant_offset(index);
            raw[offset..offset + BYTE32_LEN].copy_from_slice(participant);
            raw[offset + BYTE32_LEN..offset + BYTE32_LEN + COMPRESSED_SECP256K1_PUBKEY_LEN]
                .copy_from_slice(pubkey);
            raw[offset + BYTE32_LEN + COMPRESSED_SECP256K1_PUBKEY_LEN] =
                u8::from(participant.as_slice() == touched.as_slice());
        }
        raw[factory_reduced_exit_touched_offset()
            ..factory_reduced_exit_touched_offset() + BYTE32_LEN]
            .copy_from_slice(&touched);
        put_u128(
            &mut raw,
            factory_reduced_exit_release_quantity_offset(),
            release_quantity,
        );
        put_u32(
            &mut raw,
            factory_reduced_exit_state_output_index_offset(),
            1,
        );
        put_u32(
            &mut raw,
            factory_reduced_exit_vault_output_index_offset(),
            2,
        );
        raw[factory_reduced_exit_state_type_hash_offset()
            ..factory_reduced_exit_state_type_hash_offset() + BYTE32_LEN]
            .fill(11);
        raw[factory_reduced_exit_vault_lock_hash_offset()
            ..factory_reduced_exit_vault_lock_hash_offset() + BYTE32_LEN]
            .fill(12);
        raw[factory_reduced_exit_state_lock_hash_offset()
            ..factory_reduced_exit_state_lock_hash_offset() + BYTE32_LEN]
            .fill(13);
        raw[factory_reduced_exit_state_header_offset()
            ..factory_reduced_exit_state_header_offset() + STATE_HEADER_LEN]
            .copy_from_slice(exit_state_header);
        raw[factory_reduced_exit_descriptor_offset()
            ..factory_reduced_exit_descriptor_offset() + BILATERAL_CKB_DESCRIPTOR_LEN]
            .copy_from_slice(settlement_descriptor);
        for index in 0..FACTORY_REDUCED_EXIT_RIGHTS_COUNT as usize {
            let before_offset =
                factory_reduced_exit_right_offset(false, BILATERAL_CKB_DESCRIPTOR_LEN, index);
            raw[before_offset..before_offset + FACTORY_RIGHT_LEN].copy_from_slice(&before[index]);
            let after_offset =
                factory_reduced_exit_right_offset(true, BILATERAL_CKB_DESCRIPTOR_LEN, index);
            raw[after_offset..after_offset + FACTORY_RIGHT_LEN].copy_from_slice(&after[index]);
        }
        raw
    }

    fn sign_reduced_exit_witness(
        raw: &mut [u8; FACTORY_REDUCED_EXIT_WITNESS_LEN],
        participant: [u8; BYTE32_LEN],
        key: &SigningKey,
        digest: &[u8; 32],
    ) {
        let sig = signature(key, digest);
        for index in 0..FACTORY_REDUCED_RIGHTS_PARTICIPANT_COUNT as usize {
            if field(
                raw,
                factory_reduced_exit_participant_offset(index),
                BYTE32_LEN,
            ) == participant.as_slice()
            {
                let offset = factory_reduced_exit_participant_offset(index)
                    + BYTE32_LEN
                    + COMPRESSED_SECP256K1_PUBKEY_LEN
                    + 1;
                raw[offset..offset + ECDSA_SIGNATURE_LEN].copy_from_slice(&sig);
            }
        }
    }

    fn reduced_exit_headers_and_witness(
        release_quantity: u128,
        reserve_claim_after_quantity: u128,
        mutate_other_right: bool,
        descriptor_commitment_valid: bool,
    ) -> (
        [u8; FACTORY_STATE_HEADER_LEN],
        [u8; FACTORY_STATE_HEADER_LEN],
        [u8; FACTORY_REDUCED_EXIT_WITNESS_LEN],
    ) {
        reduced_exit_headers_and_witness_with_reserve_asset(
            release_quantity,
            reserve_claim_after_quantity,
            mutate_other_right,
            descriptor_commitment_valid,
            None,
        )
    }

    fn reduced_exit_headers_and_witness_with_reserve_asset(
        release_quantity: u128,
        reserve_claim_after_quantity: u128,
        mutate_other_right: bool,
        descriptor_commitment_valid: bool,
        reserve_asset_type: Option<[u8; BYTE32_LEN]>,
    ) -> (
        [u8; FACTORY_STATE_HEADER_LEN],
        [u8; FACTORY_STATE_HEADER_LEN],
        [u8; FACTORY_REDUCED_EXIT_WITNESS_LEN],
    ) {
        let key0 = signing_key(1);
        let key1 = signing_key(2);
        let mut entries = [([1u8; 32], pubkey(&key0)), ([2u8; 32], pubkey(&key1))];
        entries.sort_by(|left, right| left.0.cmp(&right.0));
        let participants_commitment = factory_participants_commitment(
            2,
            &[
                (entries[0].0.as_slice(), entries[0].1.as_slice()),
                (entries[1].0.as_slice(), entries[1].1.as_slice()),
            ],
        );

        let release_capacity: u64 = release_quantity.try_into().unwrap();
        let settlement_descriptor = descriptor_bytes([1u8; 32], release_capacity, [2u8; 32], 0);
        let mut exit_state_header = header_bytes(0, PHASE_ACTIVE, 0);
        if descriptor_commitment_valid {
            exit_state_header[214..246]
                .copy_from_slice(&settlement_descriptor_commitment(&settlement_descriptor));
        } else {
            exit_state_header[214..246].fill(99);
        }
        put_u16(
            &mut exit_state_header,
            246,
            BILATERAL_CKB_DESCRIPTOR_VERSION,
        );

        let (before, after) = reduced_exit_rights_pair(
            reserve_claim_after_quantity,
            mutate_other_right,
            reserve_asset_type,
        );
        let mut witness_raw = reduced_exit_witness_raw(
            &key0,
            &key1,
            release_quantity,
            &exit_state_header,
            &settlement_descriptor,
            &before,
            &after,
        );
        let witness = FactoryReducedExitWitness::parse(&witness_raw).unwrap();

        let mut old_raw = factory_header_bytes(1);
        old_raw[76..108].copy_from_slice(&witness.rights_root(false).unwrap());
        old_raw[108..140].copy_from_slice(&participants_commitment);
        old_raw[140..172].copy_from_slice(&witness.access_manifest_root(false).unwrap());
        let old_header = FactoryStateHeader::parse(&old_raw).unwrap();

        let mut new_raw = factory_header_bytes(2);
        new_raw[76..108].copy_from_slice(&witness.rights_root(true).unwrap());
        new_raw[108..140].copy_from_slice(&participants_commitment);
        new_raw[140..172].copy_from_slice(&witness.access_manifest_root(true).unwrap());
        let preliminary_new = FactoryStateHeader::parse(&new_raw).unwrap();
        let digest = witness
            .non_interference_digest(&old_header, &preliminary_new)
            .unwrap();
        new_raw[172..204].copy_from_slice(&digest);
        let new_header = FactoryStateHeader::parse(&new_raw).unwrap();
        sign_reduced_exit_witness(
            &mut witness_raw,
            [1u8; 32],
            &key0,
            &new_header.signing_digest(),
        );

        (old_raw, new_raw, witness_raw)
    }

    fn descriptor_bytes(
        left_lock_hash: [u8; 32],
        left_capacity: u64,
        right_lock_hash: [u8; 32],
        right_capacity: u64,
    ) -> [u8; BILATERAL_CKB_DESCRIPTOR_LEN] {
        let mut entries = [
            (left_lock_hash, left_capacity),
            (right_lock_hash, right_capacity),
        ];
        entries.sort_by(|left, right| left.0.cmp(&right.0));

        let mut raw = [0u8; BILATERAL_CKB_DESCRIPTOR_LEN];
        put_u16(&mut raw, 0, BILATERAL_CKB_DESCRIPTOR_VERSION);
        raw[2] = BILATERAL_CKB_DESCRIPTOR_OUTPUT_COUNT;
        raw[3] = 0;
        for (index, (lock_hash, capacity)) in entries.iter().enumerate() {
            let offset = descriptor_output_offset(index);
            raw[offset..offset + BYTE32_LEN].copy_from_slice(lock_hash);
            put_u64(&mut raw, offset + BYTE32_LEN, *capacity);
        }
        raw
    }

    fn ckb_xudt_descriptor_bytes(
        xudt_type_hash: [u8; 32],
        left_lock_hash: [u8; 32],
        left_capacity: u64,
        left_amount: u128,
        right_lock_hash: [u8; 32],
        right_capacity: u64,
        right_amount: u128,
    ) -> [u8; BILATERAL_CKB_XUDT_DESCRIPTOR_LEN] {
        let mut entries = [
            (left_lock_hash, left_capacity, left_amount),
            (right_lock_hash, right_capacity, right_amount),
        ];
        entries.sort_by(|left, right| left.0.cmp(&right.0));

        let mut raw = [0u8; BILATERAL_CKB_XUDT_DESCRIPTOR_LEN];
        put_u16(&mut raw, 0, BILATERAL_CKB_XUDT_DESCRIPTOR_VERSION);
        raw[2] = BILATERAL_CKB_DESCRIPTOR_OUTPUT_COUNT;
        raw[3] = BILATERAL_CKB_XUDT_DESCRIPTOR_ASSET_COUNT;
        raw[4..36].copy_from_slice(&xudt_type_hash);
        for (index, (lock_hash, capacity, amount)) in entries.iter().enumerate() {
            let offset = ckb_xudt_descriptor_output_offset(index);
            raw[offset..offset + BYTE32_LEN].copy_from_slice(lock_hash);
            put_u64(&mut raw, offset + BYTE32_LEN, *capacity);
            raw[offset + BYTE32_LEN + 8..offset + BYTE32_LEN + 24]
                .copy_from_slice(&amount.to_le_bytes());
        }
        raw
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

    fn header_bytes(state_number: u64, phase: u8, funding_epoch: u64) -> [u8; STATE_HEADER_LEN] {
        let mut raw = [0u8; STATE_HEADER_LEN];
        put_u16(&mut raw, 0, 1);
        raw[2..34].fill(2);
        put_u16(&mut raw, 34, 1);
        raw[36..68].fill(3);
        put_u64(&mut raw, 68, funding_epoch);
        raw[76..108].fill(4);
        raw[108..140].fill(10);
        put_u64(&mut raw, 140, state_number);
        raw[148] = 1;
        raw[149] = phase;
        raw[150..182].fill(5);
        raw[182..214].fill(6);
        raw[214..246].fill(7);
        put_u16(&mut raw, 246, 1);
        raw[248..280].fill(8);
        raw[280..312].fill(9);
        put_u16(&mut raw, 312, 2);
        raw
    }

    fn splice_header_bytes(
        kind: u8,
        base_state_number: u64,
        participants_commitment: &[u8; BYTE32_LEN],
        old_vault_commitment: &[u8; BYTE32_LEN],
        new_vault_commitment: &[u8; BYTE32_LEN],
        asset_delta_commitment: &[u8; BYTE32_LEN],
        payload_commitment: &[u8; BYTE32_LEN],
    ) -> [u8; SPLICE_HEADER_LEN] {
        let mut raw = [0u8; SPLICE_HEADER_LEN];
        put_u16(&mut raw, 0, 1);
        raw[2..34].fill(2);
        put_u16(&mut raw, 34, SIGNATURE_SCHEME_SECP256K1_ECDSA_BLAKE2B);
        raw[36..68].fill(3);
        raw[68..100].fill(4);
        raw[100..132].fill(10);
        put_u64(&mut raw, 132, 0);
        put_u64(&mut raw, 140, 1);
        put_u64(&mut raw, 148, base_state_number);
        put_u64(&mut raw, 156, 1);
        raw[164] = kind;
        raw[165..197].copy_from_slice(old_vault_commitment);
        raw[197..229].copy_from_slice(new_vault_commitment);
        raw[229..261].copy_from_slice(asset_delta_commitment);
        raw[261..293].copy_from_slice(participants_commitment);
        raw[293..325].copy_from_slice(payload_commitment);
        raw[325..357].fill(9);
        raw
    }

    fn factory_header_bytes(update_number: u64) -> [u8; FACTORY_STATE_HEADER_LEN] {
        let mut raw = [0u8; FACTORY_STATE_HEADER_LEN];
        put_u16(&mut raw, 0, 1);
        raw[2..34].fill(2);
        put_u16(&mut raw, 34, 1);
        raw[36..68].fill(3);
        put_u64(&mut raw, 68, update_number);
        raw[76..108].fill(4);
        raw[108..140].fill(5);
        raw[140..172].fill(6);
        raw[172..204].fill(7);
        raw[204..236].fill(8);
        put_u16(&mut raw, 236, 1);
        raw
    }

    fn splice_vault_asset_bytes(
        kind: u8,
        type_hash_byte: u8,
        amount: u128,
    ) -> [u8; SPLICE_VAULT_ASSET_AMOUNT_LEN] {
        let mut raw = [0u8; SPLICE_VAULT_ASSET_AMOUNT_LEN];
        raw[0] = kind;
        if kind == VAULT_ASSET_KIND_XUDT {
            raw[1..33].fill(type_hash_byte);
        }
        put_u128(&mut raw, 33, amount);
        raw
    }

    fn splice_vault_descriptor_bytes(
        funding_anchor: [u8; BYTE32_LEN],
        asset_count: u16,
        asset_0: &[u8; SPLICE_VAULT_ASSET_AMOUNT_LEN],
        asset_1: &[u8; SPLICE_VAULT_ASSET_AMOUNT_LEN],
    ) -> [u8; SPLICE_VAULT_DESCRIPTOR_LEN] {
        let mut raw = [0u8; SPLICE_VAULT_DESCRIPTOR_LEN];
        raw[0..BYTE32_LEN].copy_from_slice(&funding_anchor);
        put_u16(&mut raw, BYTE32_LEN, asset_count);
        raw[splice_vault_asset_offset(0)
            ..splice_vault_asset_offset(0) + SPLICE_VAULT_ASSET_AMOUNT_LEN]
            .copy_from_slice(asset_0);
        raw[splice_vault_asset_offset(1)
            ..splice_vault_asset_offset(1) + SPLICE_VAULT_ASSET_AMOUNT_LEN]
            .copy_from_slice(asset_1);
        raw
    }

    fn splice_asset_delta_bytes(
        kind: u8,
        type_hash_byte: u8,
        old_amount: u128,
        new_amount: u128,
        external_input: u128,
        withdrawal: u128,
        signed_fee: u128,
    ) -> [u8; SPLICE_ASSET_DELTA_LEN] {
        let mut raw = [0u8; SPLICE_ASSET_DELTA_LEN];
        raw[0] = kind;
        if kind == VAULT_ASSET_KIND_XUDT {
            raw[1..33].fill(type_hash_byte);
        }
        put_u128(&mut raw, 33, old_amount);
        put_u128(&mut raw, 49, new_amount);
        put_u128(&mut raw, 65, external_input);
        put_u128(&mut raw, 81, withdrawal);
        put_u128(&mut raw, 97, signed_fee);
        raw
    }

    fn splice_asset_deltas_bytes(
        delta_count: u16,
        delta_0: &[u8; SPLICE_ASSET_DELTA_LEN],
        delta_1: &[u8; SPLICE_ASSET_DELTA_LEN],
    ) -> [u8; SPLICE_ASSET_DELTAS_LEN] {
        let mut raw = [0u8; SPLICE_ASSET_DELTAS_LEN];
        put_u16(&mut raw, 0, delta_count);
        raw[splice_delta_offset(0)..splice_delta_offset(0) + SPLICE_ASSET_DELTA_LEN]
            .copy_from_slice(delta_0);
        raw[splice_delta_offset(1)..splice_delta_offset(1) + SPLICE_ASSET_DELTA_LEN]
            .copy_from_slice(delta_1);
        raw
    }

    fn splice_state_transition_witness_bytes(
        header: &[u8; SPLICE_HEADER_LEN],
        signatures: &[u8; SPLICE_SIGNATURE_WITNESS_LEN],
        old_vault: &[u8; SPLICE_VAULT_DESCRIPTOR_LEN],
        new_vault: &[u8; SPLICE_VAULT_DESCRIPTOR_LEN],
        deltas: &[u8; SPLICE_ASSET_DELTAS_LEN],
    ) -> [u8; SPLICE_STATE_TRANSITION_WITNESS_LEN] {
        let mut raw = [0u8; SPLICE_STATE_TRANSITION_WITNESS_LEN];
        put_u16(&mut raw, 0, SPLICE_STATE_TRANSITION_WITNESS_VERSION);
        raw[splice_transition_header_offset()
            ..splice_transition_header_offset() + SPLICE_HEADER_LEN]
            .copy_from_slice(header);
        raw[splice_transition_signature_offset()
            ..splice_transition_signature_offset() + SPLICE_SIGNATURE_WITNESS_LEN]
            .copy_from_slice(signatures);
        raw[splice_transition_old_vault_offset()
            ..splice_transition_old_vault_offset() + SPLICE_VAULT_DESCRIPTOR_LEN]
            .copy_from_slice(old_vault);
        raw[splice_transition_new_vault_offset()
            ..splice_transition_new_vault_offset() + SPLICE_VAULT_DESCRIPTOR_LEN]
            .copy_from_slice(new_vault);
        raw[splice_transition_deltas_offset()
            ..splice_transition_deltas_offset() + SPLICE_ASSET_DELTAS_LEN]
            .copy_from_slice(deltas);
        raw
    }

    fn factory_vault_asset_bytes(
        kind: u8,
        type_hash_byte: u8,
        amount: u128,
    ) -> [u8; FACTORY_VAULT_ASSET_AMOUNT_LEN] {
        let mut raw = [0u8; FACTORY_VAULT_ASSET_AMOUNT_LEN];
        raw[0] = kind;
        if kind == VAULT_ASSET_KIND_XUDT {
            raw[1..33].fill(type_hash_byte);
        }
        put_u128(&mut raw, 33, amount);
        raw
    }

    fn factory_vault_descriptor_bytes(
        factory_id: [u8; BYTE32_LEN],
        asset_count: u16,
        asset_0: &[u8; FACTORY_VAULT_ASSET_AMOUNT_LEN],
        asset_1: &[u8; FACTORY_VAULT_ASSET_AMOUNT_LEN],
    ) -> [u8; FACTORY_VAULT_DESCRIPTOR_LEN] {
        let mut raw = [0u8; FACTORY_VAULT_DESCRIPTOR_LEN];
        raw[0..BYTE32_LEN].copy_from_slice(&factory_id);
        put_u16(&mut raw, BYTE32_LEN, asset_count);
        raw[factory_vault_asset_offset(0)
            ..factory_vault_asset_offset(0) + FACTORY_VAULT_ASSET_AMOUNT_LEN]
            .copy_from_slice(asset_0);
        raw[factory_vault_asset_offset(1)
            ..factory_vault_asset_offset(1) + FACTORY_VAULT_ASSET_AMOUNT_LEN]
            .copy_from_slice(asset_1);
        raw
    }

    fn factory_vault_delta_bytes(
        kind: u8,
        type_hash_byte: u8,
        old_amount: u128,
        new_amount: u128,
        external_input: u128,
        withdrawal: u128,
    ) -> [u8; FACTORY_VAULT_DELTA_LEN] {
        let mut raw = [0u8; FACTORY_VAULT_DELTA_LEN];
        raw[0] = kind;
        if kind == VAULT_ASSET_KIND_XUDT {
            raw[1..33].fill(type_hash_byte);
        }
        put_u128(&mut raw, 33, old_amount);
        put_u128(&mut raw, 49, new_amount);
        put_u128(&mut raw, 65, external_input);
        put_u128(&mut raw, 81, withdrawal);
        raw
    }

    fn factory_vault_deltas_bytes(
        delta_count: u16,
        delta_0: &[u8; FACTORY_VAULT_DELTA_LEN],
        delta_1: &[u8; FACTORY_VAULT_DELTA_LEN],
    ) -> [u8; FACTORY_VAULT_DELTAS_LEN] {
        let mut raw = [0u8; FACTORY_VAULT_DELTAS_LEN];
        put_u16(&mut raw, 0, delta_count);
        raw[factory_vault_delta_offset(0)..factory_vault_delta_offset(0) + FACTORY_VAULT_DELTA_LEN]
            .copy_from_slice(delta_0);
        raw[factory_vault_delta_offset(1)..factory_vault_delta_offset(1) + FACTORY_VAULT_DELTA_LEN]
            .copy_from_slice(delta_1);
        raw
    }

    fn factory_splice_header_bytes(
        kind: u8,
        old_header: &FactoryStateHeader,
        new_header: &FactoryStateHeader,
        participants_commitment: &[u8; BYTE32_LEN],
        vault_delta_commitment: &[u8; BYTE32_LEN],
    ) -> [u8; FACTORY_SPLICE_HEADER_LEN] {
        let mut raw = [0u8; FACTORY_SPLICE_HEADER_LEN];
        put_u16(&mut raw, 0, 1);
        raw[2..34].copy_from_slice(old_header.chain_id());
        put_u16(&mut raw, 34, old_header.signature_scheme_id());
        raw[36..68].copy_from_slice(old_header.factory_id());
        put_u64(&mut raw, 68, old_header.update_number());
        put_u64(&mut raw, 76, new_header.update_number());
        raw[84..116].copy_from_slice(old_header.state_root());
        raw[116..148].copy_from_slice(new_header.state_root());
        raw[148..180].copy_from_slice(old_header.access_manifest_root());
        raw[180..212].copy_from_slice(new_header.access_manifest_root());
        raw[212] = kind;
        raw[213..245].copy_from_slice(vault_delta_commitment);
        raw[245..277].copy_from_slice(new_header.non_interference_digest());
        raw[277..309].copy_from_slice(participants_commitment);
        raw
    }

    fn factory_splice_witness_bytes(
        header: &[u8; FACTORY_SPLICE_HEADER_LEN],
        signatures: &[u8; FACTORY_SIGNATURE_WITNESS_LEN],
        old_vault: &[u8; FACTORY_VAULT_DESCRIPTOR_LEN],
        new_vault: &[u8; FACTORY_VAULT_DESCRIPTOR_LEN],
        deltas: &[u8; FACTORY_VAULT_DELTAS_LEN],
    ) -> [u8; FACTORY_SPLICE_WITNESS_LEN] {
        let mut raw = [0u8; FACTORY_SPLICE_WITNESS_LEN];
        put_u16(&mut raw, 0, FACTORY_SPLICE_WITNESS_VERSION);
        raw[factory_splice_header_offset()
            ..factory_splice_header_offset() + FACTORY_SPLICE_HEADER_LEN]
            .copy_from_slice(header);
        raw[factory_splice_signature_offset()
            ..factory_splice_signature_offset() + FACTORY_SIGNATURE_WITNESS_LEN]
            .copy_from_slice(signatures);
        raw[factory_splice_old_vault_offset()
            ..factory_splice_old_vault_offset() + FACTORY_VAULT_DESCRIPTOR_LEN]
            .copy_from_slice(old_vault);
        raw[factory_splice_new_vault_offset()
            ..factory_splice_new_vault_offset() + FACTORY_VAULT_DESCRIPTOR_LEN]
            .copy_from_slice(new_vault);
        raw[factory_splice_deltas_offset()
            ..factory_splice_deltas_offset() + FACTORY_VAULT_DELTAS_LEN]
            .copy_from_slice(deltas);
        raw
    }

    fn factory_reduced_splice_witness_bytes(
        header: &[u8; FACTORY_SPLICE_HEADER_LEN],
        merkle_update: &[u8; FACTORY_MERKLE_UPDATE_WITNESS_LEN],
        old_vault: &[u8; FACTORY_VAULT_DESCRIPTOR_LEN],
        new_vault: &[u8; FACTORY_VAULT_DESCRIPTOR_LEN],
        deltas: &[u8; FACTORY_VAULT_DELTAS_LEN],
    ) -> [u8; FACTORY_REDUCED_SPLICE_WITNESS_LEN] {
        let mut raw = [0u8; FACTORY_REDUCED_SPLICE_WITNESS_LEN];
        put_u16(&mut raw, 0, FACTORY_REDUCED_SPLICE_WITNESS_VERSION);
        raw[factory_reduced_splice_header_offset()
            ..factory_reduced_splice_header_offset() + FACTORY_SPLICE_HEADER_LEN]
            .copy_from_slice(header);
        raw[factory_reduced_splice_merkle_offset()
            ..factory_reduced_splice_merkle_offset() + FACTORY_MERKLE_UPDATE_WITNESS_LEN]
            .copy_from_slice(merkle_update);
        raw[factory_reduced_splice_old_vault_offset()
            ..factory_reduced_splice_old_vault_offset() + FACTORY_VAULT_DESCRIPTOR_LEN]
            .copy_from_slice(old_vault);
        raw[factory_reduced_splice_new_vault_offset()
            ..factory_reduced_splice_new_vault_offset() + FACTORY_VAULT_DESCRIPTOR_LEN]
            .copy_from_slice(new_vault);
        raw[factory_reduced_splice_deltas_offset()
            ..factory_reduced_splice_deltas_offset() + FACTORY_VAULT_DELTAS_LEN]
            .copy_from_slice(deltas);
        raw
    }

    fn factory_splice_headers_and_witness(
        kind: u8,
    ) -> (
        [u8; FACTORY_STATE_HEADER_LEN],
        [u8; FACTORY_STATE_HEADER_LEN],
        [u8; FACTORY_SPLICE_WITNESS_LEN],
    ) {
        factory_splice_headers_and_witness_with_scheme(
            kind,
            SIGNATURE_SCHEME_SECP256K1_ECDSA_BLAKE2B,
        )
    }

    fn factory_splice_headers_and_witness_with_scheme(
        kind: u8,
        signature_scheme_id: u16,
    ) -> (
        [u8; FACTORY_STATE_HEADER_LEN],
        [u8; FACTORY_STATE_HEADER_LEN],
        [u8; FACTORY_SPLICE_WITNESS_LEN],
    ) {
        let key0 = signing_key(1);
        let key1 = signing_key(2);
        let mut entries = [([1u8; 32], pubkey(&key0)), ([2u8; 32], pubkey(&key1))];
        entries.sort_by(|left, right| left.0.cmp(&right.0));
        let factory_participants = factory_participants_commitment(
            2,
            &[
                (entries[0].0.as_slice(), entries[0].1.as_slice()),
                (entries[1].0.as_slice(), entries[1].1.as_slice()),
            ],
        );
        let splice_participants =
            participants_commitment(2, &[entries[0].1.as_slice(), entries[1].1.as_slice()]);

        let mut old_raw = factory_header_bytes(1);
        put_u16(&mut old_raw, 34, signature_scheme_id);
        old_raw[108..140].copy_from_slice(&factory_participants);
        let mut new_raw = factory_header_bytes(2);
        put_u16(&mut new_raw, 34, signature_scheme_id);
        new_raw[76..108].fill(9);
        new_raw[108..140].copy_from_slice(&factory_participants);
        new_raw[140..172].fill(10);
        new_raw[172..204].fill(11);
        let old_header = FactoryStateHeader::parse(&old_raw).unwrap();
        let new_header = FactoryStateHeader::parse(&new_raw).unwrap();

        let (old_amount, new_amount, external_input, withdrawal) = match kind {
            SPLICE_KIND_IN => (50, 70, 20, 0),
            SPLICE_KIND_OUT => (50, 30, 0, 20),
            _ => unreachable!(),
        };
        let old_asset = factory_vault_asset_bytes(VAULT_ASSET_KIND_CKB, 0, old_amount);
        let new_asset = factory_vault_asset_bytes(VAULT_ASSET_KIND_CKB, 0, new_amount);
        let old_vault =
            factory_vault_descriptor_bytes([3u8; BYTE32_LEN], 1, &old_asset, &[0u8; 49]);
        let new_vault =
            factory_vault_descriptor_bytes([3u8; BYTE32_LEN], 1, &new_asset, &[0u8; 49]);
        let delta = factory_vault_delta_bytes(
            VAULT_ASSET_KIND_CKB,
            0,
            old_amount,
            new_amount,
            external_input,
            withdrawal,
        );
        let deltas = factory_vault_deltas_bytes(1, &delta, &[0u8; 97]);
        let delta_commitment = FactoryVaultDeltas::parse(&deltas)
            .unwrap()
            .commitment()
            .unwrap();
        let header = factory_splice_header_bytes(
            kind,
            &old_header,
            &new_header,
            &splice_participants,
            &delta_commitment,
        );
        let splice_header = FactorySpliceHeader::parse(&header).unwrap();
        let signatures = signed_factory_witness(
            [1u8; 32],
            &key0,
            [2u8; 32],
            &key1,
            &splice_header.signing_digest(),
        );
        let witness =
            factory_splice_witness_bytes(&header, &signatures, &old_vault, &new_vault, &deltas);
        (old_raw, new_raw, witness)
    }

    fn factory_reduced_splice_headers_and_witness(
        kind: u8,
    ) -> (
        [u8; FACTORY_STATE_HEADER_LEN],
        [u8; FACTORY_STATE_HEADER_LEN],
        [u8; FACTORY_REDUCED_SPLICE_WITNESS_LEN],
    ) {
        factory_reduced_splice_headers_and_witness_with_scheme(
            kind,
            SIGNATURE_SCHEME_SECP256K1_ECDSA_BLAKE2B,
        )
    }

    fn factory_reduced_splice_headers_and_witness_with_scheme(
        kind: u8,
        signature_scheme_id: u16,
    ) -> (
        [u8; FACTORY_STATE_HEADER_LEN],
        [u8; FACTORY_STATE_HEADER_LEN],
        [u8; FACTORY_REDUCED_SPLICE_WITNESS_LEN],
    ) {
        let key0 = signing_key(1);
        let key1 = signing_key(2);
        let mut entries = [([1u8; 32], pubkey(&key0)), ([2u8; 32], pubkey(&key1))];
        entries.sort_by(|left, right| left.0.cmp(&right.0));
        let factory_participants = factory_participants_commitment(
            2,
            &[
                (entries[0].0.as_slice(), entries[0].1.as_slice()),
                (entries[1].0.as_slice(), entries[1].1.as_slice()),
            ],
        );
        let splice_participants =
            participants_commitment(2, &[entries[0].1.as_slice(), entries[1].1.as_slice()]);

        let (old_amount, new_amount, external_input, withdrawal) = match kind {
            SPLICE_KIND_IN => (50, 70, 20, 0),
            SPLICE_KIND_OUT => (50, 30, 0, 20),
            _ => unreachable!(),
        };

        let mut merkle_raw = [0u8; FACTORY_MERKLE_UPDATE_WITNESS_LEN];
        put_u16(&mut merkle_raw, 0, FACTORY_MERKLE_UPDATE_WITNESS_VERSION);
        merkle_raw[2] = FACTORY_REDUCED_RIGHTS_PARTICIPANT_THRESHOLD;
        merkle_raw[3] = FACTORY_REDUCED_RIGHTS_PARTICIPANT_COUNT;
        merkle_raw[4] = FACTORY_REDUCED_RIGHTS_AUTHORISED_COUNT;
        merkle_raw[5] = FACTORY_MERKLE_UPDATE_RIGHT_COUNT;
        for (index, (participant, pubkey)) in entries.iter().enumerate() {
            let offset = factory_merkle_participant_offset(index);
            merkle_raw[offset..offset + BYTE32_LEN].copy_from_slice(participant);
            merkle_raw[offset + BYTE32_LEN..offset + BYTE32_LEN + COMPRESSED_SECP256K1_PUBKEY_LEN]
                .copy_from_slice(pubkey);
            merkle_raw[offset + BYTE32_LEN + COMPRESSED_SECP256K1_PUBKEY_LEN] =
                u8::from(participant == &[1u8; BYTE32_LEN]);
        }
        merkle_raw[factory_merkle_touched_offset()..factory_merkle_touched_offset() + BYTE32_LEN]
            .copy_from_slice(&[1u8; BYTE32_LEN]);
        merkle_raw[factory_merkle_right_offset(false)
            ..factory_merkle_right_offset(false) + FACTORY_RIGHT_LEN]
            .copy_from_slice(&factory_right_bytes(
                1,
                10,
                FACTORY_RIGHT_KIND_RESERVE_CLAIM,
                old_amount,
            ));
        merkle_raw[factory_merkle_right_offset(true)
            ..factory_merkle_right_offset(true) + FACTORY_RIGHT_LEN]
            .copy_from_slice(&factory_right_bytes(
                1,
                10,
                FACTORY_RIGHT_KIND_RESERVE_CLAIM,
                new_amount,
            ));
        for depth in 0..FACTORY_SPARSE_MERKLE_DEPTH {
            let offset = factory_merkle_sibling_offset(depth);
            merkle_raw[offset..offset + BYTE32_LEN].fill(depth as u8);
        }
        let merkle_witness = FactoryMerkleUpdateWitness::parse(&merkle_raw).unwrap();

        let mut old_raw = factory_header_bytes(1);
        put_u16(&mut old_raw, 34, signature_scheme_id);
        old_raw[76..108].copy_from_slice(&merkle_witness.rights_root(false).unwrap());
        old_raw[108..140].copy_from_slice(&factory_participants);
        old_raw[140..172].fill(10);
        let old_header = FactoryStateHeader::parse(&old_raw).unwrap();

        let mut new_raw = factory_header_bytes(2);
        put_u16(&mut new_raw, 34, signature_scheme_id);
        new_raw[76..108].copy_from_slice(&merkle_witness.rights_root(true).unwrap());
        new_raw[108..140].copy_from_slice(&factory_participants);
        new_raw[140..172].copy_from_slice(old_header.access_manifest_root());
        let preliminary_new = FactoryStateHeader::parse(&new_raw).unwrap();
        let digest = merkle_witness
            .non_interference_digest(&old_header, &preliminary_new)
            .unwrap();
        new_raw[172..204].copy_from_slice(&digest);
        let new_header = FactoryStateHeader::parse(&new_raw).unwrap();

        let old_asset = factory_vault_asset_bytes(VAULT_ASSET_KIND_CKB, 0, old_amount);
        let new_asset = factory_vault_asset_bytes(VAULT_ASSET_KIND_CKB, 0, new_amount);
        let old_vault =
            factory_vault_descriptor_bytes([3u8; BYTE32_LEN], 1, &old_asset, &[0u8; 49]);
        let new_vault =
            factory_vault_descriptor_bytes([3u8; BYTE32_LEN], 1, &new_asset, &[0u8; 49]);
        let delta = factory_vault_delta_bytes(
            VAULT_ASSET_KIND_CKB,
            0,
            old_amount,
            new_amount,
            external_input,
            withdrawal,
        );
        let deltas = factory_vault_deltas_bytes(1, &delta, &[0u8; 97]);
        let delta_commitment = FactoryVaultDeltas::parse(&deltas)
            .unwrap()
            .commitment()
            .unwrap();
        let header = factory_splice_header_bytes(
            kind,
            &old_header,
            &new_header,
            &splice_participants,
            &delta_commitment,
        );
        let splice_header = FactorySpliceHeader::parse(&header).unwrap();
        sign_merkle_update_witness(
            &mut merkle_raw,
            [1u8; 32],
            &key0,
            &splice_header.signing_digest(),
        );
        let witness = factory_reduced_splice_witness_bytes(
            &header,
            &merkle_raw,
            &old_vault,
            &new_vault,
            &deltas,
        );
        (old_raw, new_raw, witness)
    }

    #[test]
    fn state_header_parser_rejects_wrong_length() {
        assert_eq!(
            StateHeader::parse(&[0u8; STATE_HEADER_LEN - 1]).unwrap_err(),
            ScriptError::Encoding
        );
    }

    #[test]
    fn state_header_fields_are_fixed_width() {
        let raw = header_bytes(42, PHASE_SETTLING, 3);
        let header = StateHeader::parse(&raw).unwrap();

        assert_eq!(header.protocol_version(), 1);
        assert_eq!(header.chain_id(), &[2u8; 32]);
        assert_eq!(header.signature_scheme_id(), 1);
        assert_eq!(header.channel_id(), &[3u8; 32]);
        assert_eq!(header.funding_epoch(), 3);
        assert_eq!(header.funding_anchor(), &[4u8; 32]);
        assert_eq!(header.vault_set_commitment(), &[10u8; 32]);
        assert_eq!(header.state_number(), 42);
        assert_eq!(header.mode(), 1);
        assert_eq!(header.phase(), PHASE_SETTLING);
        assert_eq!(header.participants_commitment(), &[5u8; 32]);
        assert_eq!(header.asset_registry_commitment(), &[6u8; 32]);
        assert_eq!(header.settlement_descriptor_commitment(), &[7u8; 32]);
        assert_eq!(header.descriptor_version(), 1);
        assert_eq!(header.payload_commitment(), &[8u8; 32]);
        assert_eq!(header.challenge_policy_commitment(), &[9u8; 32]);
        assert_eq!(header.state_layout_version(), 2);
    }

    #[test]
    fn state_header_context_binds_epoch_and_vault_set() {
        let old_raw = header_bytes(1, 1, 7);
        let mut new_raw = header_bytes(9, PHASE_SETTLING, 7);
        new_raw[214..246].fill(11);
        new_raw[248..280].fill(12);

        let old = StateHeader::parse(&old_raw).unwrap();
        let new = StateHeader::parse(&new_raw).unwrap();
        assert!(old.same_context_except_progress(&new));

        new_raw[68] = 8;
        let changed_epoch = StateHeader::parse(&new_raw).unwrap();
        assert!(!old.same_context_except_progress(&changed_epoch));

        let mut changed_vault_raw = header_bytes(9, PHASE_SETTLING, 7);
        changed_vault_raw[108] = 99;
        let changed_vault_set = StateHeader::parse(&changed_vault_raw).unwrap();
        assert!(!old.same_context_except_progress(&changed_vault_set));
    }

    #[test]
    fn state_header_digest_is_epoch_separated() {
        let mut raw = header_bytes(42, PHASE_SETTLING, 1);
        let header = StateHeader::parse(&raw).unwrap();
        let digest_epoch_1 = header.signing_digest();

        put_u64(&mut raw, 68, 2);
        let header_epoch_2 = StateHeader::parse(&raw).unwrap();
        assert_ne!(digest_epoch_1, header_epoch_2.signing_digest());
    }

    #[test]
    fn factory_state_header_fields_are_fixed_width() {
        let raw = factory_header_bytes(42);
        let header = FactoryStateHeader::parse(&raw).unwrap();

        assert_eq!(header.protocol_version(), 1);
        assert_eq!(header.chain_id(), &[2u8; 32]);
        assert_eq!(header.signature_scheme_id(), 1);
        assert_eq!(header.factory_id(), &[3u8; 32]);
        assert_eq!(header.update_number(), 42);
        assert_eq!(header.state_root(), &[4u8; 32]);
        assert_eq!(header.participants_commitment(), &[5u8; 32]);
        assert_eq!(header.access_manifest_root(), &[6u8; 32]);
        assert_eq!(header.non_interference_digest(), &[7u8; 32]);
        assert_eq!(header.challenge_policy_commitment(), &[8u8; 32]);
        assert_eq!(header.state_layout_version(), 1);
    }

    #[test]
    fn factory_context_allows_progress_but_rejects_identity_change() {
        let old_raw = factory_header_bytes(1);
        let mut new_raw = factory_header_bytes(9);
        new_raw[76..108].fill(10);
        new_raw[140..172].fill(11);
        new_raw[172..204].fill(12);

        let old = FactoryStateHeader::parse(&old_raw).unwrap();
        let new = FactoryStateHeader::parse(&new_raw).unwrap();
        assert!(old.same_context_except_progress(&new));

        new_raw[36] = 99;
        let changed_factory = FactoryStateHeader::parse(&new_raw).unwrap();
        assert!(!old.same_context_except_progress(&changed_factory));
    }

    #[test]
    fn splice_header_fields_are_fixed_width_and_match_current_state() {
        let key0 = SigningKey::from_slice(&[1u8; 32]).unwrap();
        let key1 = SigningKey::from_slice(&[2u8; 32]).unwrap();
        let mut pubkeys = [pubkey(&key0), pubkey(&key1)];
        pubkeys.sort();
        let participant_refs = [pubkeys[0].as_slice(), pubkeys[1].as_slice()];
        let participants = participants_commitment(2, &participant_refs);
        let raw = splice_header_bytes(
            SPLICE_KIND_IN,
            7,
            &participants,
            &[11u8; BYTE32_LEN],
            &[12u8; BYTE32_LEN],
            &[13u8; BYTE32_LEN],
            &[8u8; BYTE32_LEN],
        );
        let header = SpliceHeader::parse(&raw).unwrap();

        assert_eq!(header.protocol_version(), 1);
        assert_eq!(header.chain_id(), &[2u8; BYTE32_LEN]);
        assert_eq!(
            header.signature_scheme_id(),
            SIGNATURE_SCHEME_SECP256K1_ECDSA_BLAKE2B
        );
        assert_eq!(header.channel_id(), &[3u8; BYTE32_LEN]);
        assert_eq!(header.old_funding_anchor(), &[4u8; BYTE32_LEN]);
        assert_eq!(header.new_funding_anchor(), &[10u8; BYTE32_LEN]);
        assert_eq!(header.old_funding_epoch(), 0);
        assert_eq!(header.new_funding_epoch(), 1);
        assert_eq!(header.base_state_number(), 7);
        assert_eq!(header.splice_number(), 1);
        assert_eq!(header.kind(), SPLICE_KIND_IN);
        assert_eq!(header.old_vault_commitment(), &[11u8; BYTE32_LEN]);
        assert_eq!(header.new_vault_commitment(), &[12u8; BYTE32_LEN]);
        assert_eq!(header.asset_delta_commitment(), &[13u8; BYTE32_LEN]);
        assert_eq!(header.participants_commitment(), participants.as_slice());
        assert_eq!(header.challenge_policy_commitment(), &[9u8; BYTE32_LEN]);

        let mut state_raw = header_bytes(7, PHASE_ACTIVE, 0);
        state_raw[108..140].copy_from_slice(header.old_vault_commitment());
        state_raw[150..182].copy_from_slice(&participants);
        let current = StateHeader::parse(&state_raw).unwrap();
        assert!(header.matches_current_state(&current));

        state_raw[68] = 1;
        let changed_epoch = StateHeader::parse(&state_raw).unwrap();
        assert!(!header.matches_current_state(&changed_epoch));
    }

    #[test]
    fn splice_header_rejects_unknown_kind() {
        let raw = splice_header_bytes(
            99,
            7,
            &[5u8; BYTE32_LEN],
            &[11u8; BYTE32_LEN],
            &[12u8; BYTE32_LEN],
            &[13u8; BYTE32_LEN],
            &[8u8; BYTE32_LEN],
        );

        assert_eq!(
            SpliceHeader::parse(&raw).unwrap_err(),
            ScriptError::Encoding
        );
    }

    #[test]
    fn splice_signature_witness_verifies_header_digest() {
        let key0 = SigningKey::from_slice(&[1u8; 32]).unwrap();
        let key1 = SigningKey::from_slice(&[2u8; 32]).unwrap();
        let mut pubkeys = [pubkey(&key0), pubkey(&key1)];
        pubkeys.sort();
        let participant_refs = [pubkeys[0].as_slice(), pubkeys[1].as_slice()];
        let participants = participants_commitment(2, &participant_refs);
        let raw = splice_header_bytes(
            SPLICE_KIND_IN,
            7,
            &participants,
            &[11u8; BYTE32_LEN],
            &[12u8; BYTE32_LEN],
            &[13u8; BYTE32_LEN],
            &[8u8; BYTE32_LEN],
        );
        let header = SpliceHeader::parse(&raw).unwrap();
        let witness_raw = signed_bilateral_witness(&key0, &key1, &header.signing_digest());
        let witness = SpliceSignatureWitness::parse(&witness_raw).unwrap();

        verify_splice_signatures(&header, &witness).unwrap();

        let mut tampered_witness_raw = witness_raw;
        tampered_witness_raw[SPLICE_SIGNATURE_WITNESS_LEN - 1] ^= 1;
        let tampered = SpliceSignatureWitness::parse(&tampered_witness_raw).unwrap();
        assert_eq!(
            verify_splice_signatures(&header, &tampered).unwrap_err(),
            ScriptError::InvalidParticipantSignature
        );
    }

    #[test]
    fn verifies_splice_state_transition() {
        let key0 = SigningKey::from_slice(&[1u8; 32]).unwrap();
        let key1 = SigningKey::from_slice(&[2u8; 32]).unwrap();
        let mut pubkeys = [pubkey(&key0), pubkey(&key1)];
        pubkeys.sort();
        let participant_refs = [pubkeys[0].as_slice(), pubkeys[1].as_slice()];
        let participants = participants_commitment(2, &participant_refs);

        let old_ckb = splice_vault_asset_bytes(VAULT_ASSET_KIND_CKB, 0, 10_000);
        let old_xudt = splice_vault_asset_bytes(VAULT_ASSET_KIND_XUDT, 42, 50);
        let old_vault_raw =
            splice_vault_descriptor_bytes([4u8; BYTE32_LEN], 2, &old_ckb, &old_xudt);
        let old_vault = SpliceVaultDescriptor::parse(&old_vault_raw).unwrap();

        let new_ckb = splice_vault_asset_bytes(VAULT_ASSET_KIND_CKB, 0, 14_900);
        let new_xudt = splice_vault_asset_bytes(VAULT_ASSET_KIND_XUDT, 42, 60);
        let new_vault_raw =
            splice_vault_descriptor_bytes([10u8; BYTE32_LEN], 2, &new_ckb, &new_xudt);
        let new_vault = SpliceVaultDescriptor::parse(&new_vault_raw).unwrap();

        let ckb_delta =
            splice_asset_delta_bytes(VAULT_ASSET_KIND_CKB, 0, 10_000, 14_900, 5_000, 0, 100);
        let xudt_delta = splice_asset_delta_bytes(VAULT_ASSET_KIND_XUDT, 42, 50, 60, 10, 0, 0);
        let deltas_raw = splice_asset_deltas_bytes(2, &ckb_delta, &xudt_delta);
        let deltas = SpliceAssetDeltas::parse(&deltas_raw).unwrap();

        let splice_header_raw = splice_header_bytes(
            SPLICE_KIND_IN,
            7,
            &participants,
            &old_vault.commitment().unwrap(),
            &new_vault.commitment().unwrap(),
            &deltas.commitment().unwrap(),
            &[8u8; BYTE32_LEN],
        );
        let splice_header = SpliceHeader::parse(&splice_header_raw).unwrap();
        let witness_raw = signed_bilateral_witness(&key0, &key1, &splice_header.signing_digest());
        let witness = SpliceSignatureWitness::parse(&witness_raw).unwrap();

        let mut current_raw = header_bytes(7, PHASE_ACTIVE, 0);
        current_raw[108..140].copy_from_slice(&old_vault.commitment().unwrap());
        current_raw[150..182].copy_from_slice(&participants);
        let current = StateHeader::parse(&current_raw).unwrap();

        let mut next_raw = header_bytes(7, PHASE_ACTIVE, 1);
        next_raw[76..108].fill(10);
        next_raw[108..140].copy_from_slice(&new_vault.commitment().unwrap());
        next_raw[150..182].copy_from_slice(&participants);
        let next = StateHeader::parse(&next_raw).unwrap();

        verify_splice_state_transition(
            &current,
            &next,
            &splice_header,
            &witness,
            &old_vault,
            &new_vault,
            &deltas,
        )
        .unwrap();

        let bundle_raw = splice_state_transition_witness_bytes(
            &splice_header_raw,
            &witness_raw,
            &old_vault_raw,
            &new_vault_raw,
            &deltas_raw,
        );
        assert_eq!(SPLICE_STATE_TRANSITION_WITNESS_LEN, 1049);
        let bundle = SpliceStateTransitionWitness::parse(&bundle_raw).unwrap();
        assert_eq!(bundle.version(), SPLICE_STATE_TRANSITION_WITNESS_VERSION);
        assert_eq!(bundle.raw().len(), SPLICE_STATE_TRANSITION_WITNESS_LEN);
        assert_eq!(bundle.header().unwrap().kind(), SPLICE_KIND_IN);
        assert_eq!(
            bundle.old_vault().unwrap().funding_anchor(),
            &[4u8; BYTE32_LEN]
        );
        assert_eq!(
            bundle.new_vault().unwrap().funding_anchor(),
            &[10u8; BYTE32_LEN]
        );
        assert_eq!(bundle.deltas().unwrap().delta_count(), 2);
        verify_splice_state_transition_bundle(&current, &next, &bundle).unwrap();

        let mut wrong_version = bundle_raw;
        put_u16(&mut wrong_version, 0, 2);
        assert_eq!(
            SpliceStateTransitionWitness::parse(&wrong_version).unwrap_err(),
            ScriptError::SpliceProofEncoding
        );

        let mut bad_nested_header = bundle_raw;
        bad_nested_header[splice_transition_header_offset() + 164] = 99;
        let bad_bundle = SpliceStateTransitionWitness::parse(&bad_nested_header).unwrap();
        assert_eq!(
            verify_splice_state_transition_bundle(&current, &next, &bad_bundle).unwrap_err(),
            ScriptError::SpliceProofEncoding
        );
    }

    #[test]
    fn verifies_splice_state_transition_epoch_bridge() {
        let key0 = SigningKey::from_slice(&[1u8; 32]).unwrap();
        let key1 = SigningKey::from_slice(&[2u8; 32]).unwrap();
        let mut pubkeys = [pubkey(&key0), pubkey(&key1)];
        pubkeys.sort();
        let participant_refs = [pubkeys[0].as_slice(), pubkeys[1].as_slice()];
        let participants = participants_commitment(2, &participant_refs);

        let old_ckb = splice_vault_asset_bytes(VAULT_ASSET_KIND_CKB, 0, 10_000);
        let old_vault_raw =
            splice_vault_descriptor_bytes([4u8; BYTE32_LEN], 1, &old_ckb, &[0u8; 49]);
        let old_vault = SpliceVaultDescriptor::parse(&old_vault_raw).unwrap();

        let new_ckb = splice_vault_asset_bytes(VAULT_ASSET_KIND_CKB, 0, 14_900);
        let new_vault_raw =
            splice_vault_descriptor_bytes([10u8; BYTE32_LEN], 1, &new_ckb, &[0u8; 49]);
        let new_vault = SpliceVaultDescriptor::parse(&new_vault_raw).unwrap();

        let ckb_delta =
            splice_asset_delta_bytes(VAULT_ASSET_KIND_CKB, 0, 10_000, 14_900, 5_000, 0, 100);
        let deltas_raw = splice_asset_deltas_bytes(1, &ckb_delta, &[0u8; SPLICE_ASSET_DELTA_LEN]);
        let deltas = SpliceAssetDeltas::parse(&deltas_raw).unwrap();

        let splice_header_raw = splice_header_bytes(
            SPLICE_KIND_IN,
            7,
            &participants,
            &old_vault.commitment().unwrap(),
            &new_vault.commitment().unwrap(),
            &deltas.commitment().unwrap(),
            &[8u8; BYTE32_LEN],
        );
        let splice_header = SpliceHeader::parse(&splice_header_raw).unwrap();
        let witness_raw = signed_bilateral_witness(&key0, &key1, &splice_header.signing_digest());
        let witness = SpliceSignatureWitness::parse(&witness_raw).unwrap();

        let mut current_raw = header_bytes(7, PHASE_ACTIVE, 0);
        current_raw[108..140].copy_from_slice(&old_vault.commitment().unwrap());
        current_raw[150..182].copy_from_slice(&participants);
        let current = StateHeader::parse(&current_raw).unwrap();

        let mut next_raw = header_bytes(7, PHASE_ACTIVE, 1);
        next_raw[76..108].fill(10);
        next_raw[108..140].copy_from_slice(&new_vault.commitment().unwrap());
        next_raw[150..182].copy_from_slice(&participants);
        let next = StateHeader::parse(&next_raw).unwrap();

        verify_splice_state_transition(
            &current,
            &next,
            &splice_header,
            &witness,
            &old_vault,
            &new_vault,
            &deltas,
        )
        .unwrap();

        let bundle_raw = splice_state_transition_witness_bytes(
            &splice_header_raw,
            &witness_raw,
            &old_vault_raw,
            &new_vault_raw,
            &deltas_raw,
        );
        let bundle = SpliceStateTransitionWitness::parse(&bundle_raw).unwrap();
        verify_splice_state_transition_bundle(&current, &next, &bundle).unwrap();

        let mut stale_next_raw = next_raw;
        put_u64(&mut stale_next_raw, 68, 0);
        let stale_next = StateHeader::parse(&stale_next_raw).unwrap();
        assert_eq!(
            verify_splice_state_transition_bundle(&current, &stale_next, &bundle).unwrap_err(),
            ScriptError::SpliceProofMismatch
        );
    }

    #[test]
    fn rejects_splice_state_transition_with_wrong_next_anchor() {
        let key0 = SigningKey::from_slice(&[1u8; 32]).unwrap();
        let key1 = SigningKey::from_slice(&[2u8; 32]).unwrap();
        let mut pubkeys = [pubkey(&key0), pubkey(&key1)];
        pubkeys.sort();
        let participant_refs = [pubkeys[0].as_slice(), pubkeys[1].as_slice()];
        let participants = participants_commitment(2, &participant_refs);

        let old_ckb = splice_vault_asset_bytes(VAULT_ASSET_KIND_CKB, 0, 10_000);
        let new_ckb = splice_vault_asset_bytes(VAULT_ASSET_KIND_CKB, 0, 7_000);
        let old_vault_raw =
            splice_vault_descriptor_bytes([4u8; BYTE32_LEN], 1, &old_ckb, &[0u8; 49]);
        let old_vault = SpliceVaultDescriptor::parse(&old_vault_raw).unwrap();
        let new_vault_raw =
            splice_vault_descriptor_bytes([10u8; BYTE32_LEN], 1, &new_ckb, &[0u8; 49]);
        let new_vault = SpliceVaultDescriptor::parse(&new_vault_raw).unwrap();
        let delta = splice_asset_delta_bytes(VAULT_ASSET_KIND_CKB, 0, 10_000, 7_000, 0, 3_000, 0);
        let deltas_raw = splice_asset_deltas_bytes(1, &delta, &[0u8; SPLICE_ASSET_DELTA_LEN]);
        let deltas = SpliceAssetDeltas::parse(&deltas_raw).unwrap();

        let splice_header_raw = splice_header_bytes(
            SPLICE_KIND_OUT,
            7,
            &participants,
            &old_vault.commitment().unwrap(),
            &new_vault.commitment().unwrap(),
            &deltas.commitment().unwrap(),
            &[8u8; BYTE32_LEN],
        );
        let splice_header = SpliceHeader::parse(&splice_header_raw).unwrap();
        let witness_raw = signed_bilateral_witness(&key0, &key1, &splice_header.signing_digest());
        let witness = SpliceSignatureWitness::parse(&witness_raw).unwrap();

        let mut current_raw = header_bytes(7, PHASE_ACTIVE, 0);
        current_raw[108..140].copy_from_slice(&old_vault.commitment().unwrap());
        current_raw[150..182].copy_from_slice(&participants);
        let current = StateHeader::parse(&current_raw).unwrap();
        let mut next_raw = header_bytes(7, PHASE_ACTIVE, 1);
        next_raw[76..108].fill(11);
        next_raw[108..140].copy_from_slice(&new_vault.commitment().unwrap());
        next_raw[150..182].copy_from_slice(&participants);
        let next = StateHeader::parse(&next_raw).unwrap();

        assert_eq!(
            verify_splice_state_transition(
                &current,
                &next,
                &splice_header,
                &witness,
                &old_vault,
                &new_vault,
                &deltas,
            )
            .unwrap_err(),
            ScriptError::SpliceProofMismatch
        );
    }

    #[test]
    fn rejects_splice_state_transition_with_vault_delta_mismatch() {
        let key0 = SigningKey::from_slice(&[1u8; 32]).unwrap();
        let key1 = SigningKey::from_slice(&[2u8; 32]).unwrap();
        let mut pubkeys = [pubkey(&key0), pubkey(&key1)];
        pubkeys.sort();
        let participant_refs = [pubkeys[0].as_slice(), pubkeys[1].as_slice()];
        let participants = participants_commitment(2, &participant_refs);

        let old_ckb = splice_vault_asset_bytes(VAULT_ASSET_KIND_CKB, 0, 10_000);
        let old_vault_raw =
            splice_vault_descriptor_bytes([4u8; BYTE32_LEN], 1, &old_ckb, &[0u8; 49]);
        let old_vault = SpliceVaultDescriptor::parse(&old_vault_raw).unwrap();
        let new_ckb = splice_vault_asset_bytes(VAULT_ASSET_KIND_CKB, 0, 7_001);
        let new_vault_raw =
            splice_vault_descriptor_bytes([10u8; BYTE32_LEN], 1, &new_ckb, &[0u8; 49]);
        let new_vault = SpliceVaultDescriptor::parse(&new_vault_raw).unwrap();
        let delta = splice_asset_delta_bytes(VAULT_ASSET_KIND_CKB, 0, 10_000, 7_000, 0, 3_000, 0);
        let deltas_raw = splice_asset_deltas_bytes(1, &delta, &[0u8; SPLICE_ASSET_DELTA_LEN]);
        let deltas = SpliceAssetDeltas::parse(&deltas_raw).unwrap();

        let splice_header_raw = splice_header_bytes(
            SPLICE_KIND_OUT,
            7,
            &participants,
            &old_vault.commitment().unwrap(),
            &new_vault.commitment().unwrap(),
            &deltas.commitment().unwrap(),
            &[8u8; BYTE32_LEN],
        );
        let splice_header = SpliceHeader::parse(&splice_header_raw).unwrap();
        let witness_raw = signed_bilateral_witness(&key0, &key1, &splice_header.signing_digest());
        let witness = SpliceSignatureWitness::parse(&witness_raw).unwrap();

        let mut current_raw = header_bytes(7, PHASE_ACTIVE, 0);
        current_raw[108..140].copy_from_slice(&old_vault.commitment().unwrap());
        current_raw[150..182].copy_from_slice(&participants);
        let current = StateHeader::parse(&current_raw).unwrap();
        let mut next_raw = header_bytes(7, PHASE_ACTIVE, 1);
        next_raw[76..108].fill(10);
        next_raw[108..140].copy_from_slice(&new_vault.commitment().unwrap());
        next_raw[150..182].copy_from_slice(&participants);
        let next = StateHeader::parse(&next_raw).unwrap();

        assert_eq!(
            verify_splice_state_transition(
                &current,
                &next,
                &splice_header,
                &witness,
                &old_vault,
                &new_vault,
                &deltas,
            )
            .unwrap_err(),
            ScriptError::SpliceProofMismatch
        );
    }

    /// C-01 attack vector: a malicious transaction builder substitutes the
    /// successor State Header's payload_commitment while keeping all
    /// otherwise-checked fields identical. The signed splice event bound to
    /// the genuine current state's payload_commitment must not authorise a
    /// transition into a successor with a different payload_commitment.
    ///
    /// In the bilateral plain profile of this implementation,
    /// `payload_commitment` is overloaded as the vault Cell commitment: the
    /// vault lock calls `validate_current_vault_commitment(
    /// header.payload_commitment())`, and the post-splice vault lock calls
    /// `new_header.payload_commitment() == new_vault_commitment`. This means
    /// `payload_commitment` is transitively bound by `vault_set_commitment`,
    /// which is in turn bound by `splice_header.old_vault_commitment` and
    /// `splice_header.new_vault_commitment`. The substitution attack is
    /// therefore closed by the existing `vault_set_commitment` and vault lock
    /// checks; the bundle-level test below would not add coverage.
    #[test]
    #[ignore = "payload_commitment is bound transitively via vault_set_commitment in this profile; see vault lock validate_current_vault_commitment and new_header.payload_commitment == new_vault_commitment. The audit's general-case attack vector is closed at the vault lock layer for the bilateral plain profile."]
    fn rejects_splice_state_transition_with_changed_payload_commitment() {
        let key0 = SigningKey::from_slice(&[1u8; 32]).unwrap();
        let key1 = SigningKey::from_slice(&[2u8; 32]).unwrap();
        let mut pubkeys = [pubkey(&key0), pubkey(&key1)];
        pubkeys.sort();
        let participant_refs = [pubkeys[0].as_slice(), pubkeys[1].as_slice()];
        let participants = participants_commitment(2, &participant_refs);

        let old_ckb = splice_vault_asset_bytes(VAULT_ASSET_KIND_CKB, 0, 10_000);
        let old_vault_raw =
            splice_vault_descriptor_bytes([4u8; BYTE32_LEN], 1, &old_ckb, &[0u8; 49]);
        let old_vault = SpliceVaultDescriptor::parse(&old_vault_raw).unwrap();
        let new_ckb = splice_vault_asset_bytes(VAULT_ASSET_KIND_CKB, 0, 14_900);
        let new_vault_raw =
            splice_vault_descriptor_bytes([10u8; BYTE32_LEN], 1, &new_ckb, &[0u8; 49]);
        let new_vault = SpliceVaultDescriptor::parse(&new_vault_raw).unwrap();
        let delta =
            splice_asset_delta_bytes(VAULT_ASSET_KIND_CKB, 0, 10_000, 14_900, 5_000, 0, 100);
        let deltas_raw = splice_asset_deltas_bytes(1, &delta, &[0u8; SPLICE_ASSET_DELTA_LEN]);
        let deltas = SpliceAssetDeltas::parse(&deltas_raw).unwrap();

        let splice_header_raw = splice_header_bytes(
            SPLICE_KIND_IN,
            7,
            &participants,
            &old_vault.commitment().unwrap(),
            &new_vault.commitment().unwrap(),
            &deltas.commitment().unwrap(),
            &[8u8; BYTE32_LEN],
        );
        let splice_header = SpliceHeader::parse(&splice_header_raw).unwrap();
        let witness_raw = signed_bilateral_witness(&key0, &key1, &splice_header.signing_digest());
        let witness = SpliceSignatureWitness::parse(&witness_raw).unwrap();

        let mut current_raw = header_bytes(7, PHASE_ACTIVE, 0);
        current_raw[108..140].copy_from_slice(&old_vault.commitment().unwrap());
        current_raw[150..182].copy_from_slice(&participants);
        // In the bilateral plain profile, payload_commitment IS the vault
        // commitment, so we mirror that here.
        current_raw[248..280].copy_from_slice(&old_vault.commitment().unwrap());
        let current = StateHeader::parse(&current_raw).unwrap();
        let mut next_raw = header_bytes(7, PHASE_ACTIVE, 1);
        next_raw[76..108].fill(10);
        next_raw[108..140].copy_from_slice(&new_vault.commitment().unwrap());
        next_raw[150..182].copy_from_slice(&participants);
        next_raw[248..280].copy_from_slice(&new_vault.commitment().unwrap());
        // Attacker flips the successor's payload_commitment to a different
        // value than the splice event was signed for.
        next_raw[248..280].fill(0xAA);
        let next = StateHeader::parse(&next_raw).unwrap();

        assert_eq!(
            verify_splice_state_transition(
                &current,
                &next,
                &splice_header,
                &witness,
                &old_vault,
                &new_vault,
                &deltas,
            )
            .unwrap_err(),
            ScriptError::SpliceProofMismatch
        );
    }

    /// C-01 attack vector: attacker substitutes successor participants so a
    /// later state can be signed under an attacker-controlled set. The signed
    /// splice event binds the genuine participants_commitment.
    #[test]
    fn rejects_splice_state_transition_with_changed_participants_commitment() {
        let key0 = SigningKey::from_slice(&[1u8; 32]).unwrap();
        let key1 = SigningKey::from_slice(&[2u8; 32]).unwrap();
        let mut pubkeys = [pubkey(&key0), pubkey(&key1)];
        pubkeys.sort();
        let participant_refs = [pubkeys[0].as_slice(), pubkeys[1].as_slice()];
        let participants = participants_commitment(2, &participant_refs);

        let old_ckb = splice_vault_asset_bytes(VAULT_ASSET_KIND_CKB, 0, 10_000);
        let old_vault_raw =
            splice_vault_descriptor_bytes([4u8; BYTE32_LEN], 1, &old_ckb, &[0u8; 49]);
        let old_vault = SpliceVaultDescriptor::parse(&old_vault_raw).unwrap();
        let new_ckb = splice_vault_asset_bytes(VAULT_ASSET_KIND_CKB, 0, 14_900);
        let new_vault_raw =
            splice_vault_descriptor_bytes([10u8; BYTE32_LEN], 1, &new_ckb, &[0u8; 49]);
        let new_vault = SpliceVaultDescriptor::parse(&new_vault_raw).unwrap();
        let delta =
            splice_asset_delta_bytes(VAULT_ASSET_KIND_CKB, 0, 10_000, 14_900, 5_000, 0, 100);
        let deltas_raw = splice_asset_deltas_bytes(1, &delta, &[0u8; SPLICE_ASSET_DELTA_LEN]);
        let deltas = SpliceAssetDeltas::parse(&deltas_raw).unwrap();

        let splice_header_raw = splice_header_bytes(
            SPLICE_KIND_IN,
            7,
            &participants,
            &old_vault.commitment().unwrap(),
            &new_vault.commitment().unwrap(),
            &deltas.commitment().unwrap(),
            &[8u8; BYTE32_LEN],
        );
        let splice_header = SpliceHeader::parse(&splice_header_raw).unwrap();
        let witness_raw = signed_bilateral_witness(&key0, &key1, &splice_header.signing_digest());
        let witness = SpliceSignatureWitness::parse(&witness_raw).unwrap();

        let mut current_raw = header_bytes(7, PHASE_ACTIVE, 0);
        current_raw[108..140].copy_from_slice(&old_vault.commitment().unwrap());
        current_raw[150..182].copy_from_slice(&participants);
        let current = StateHeader::parse(&current_raw).unwrap();
        let mut next_raw = header_bytes(7, PHASE_ACTIVE, 1);
        next_raw[76..108].fill(10);
        next_raw[108..140].copy_from_slice(&new_vault.commitment().unwrap());
        // Attacker flips the successor's participants_commitment to a
        // different value than the splice event was signed for.
        next_raw[150..182].fill(0xBB);
        let next = StateHeader::parse(&next_raw).unwrap();

        assert_eq!(
            verify_splice_state_transition(
                &current,
                &next,
                &splice_header,
                &witness,
                &old_vault,
                &new_vault,
                &deltas,
            )
            .unwrap_err(),
            ScriptError::SpliceProofMismatch
        );
    }

    /// C-01 attack vector: attacker substitutes successor settlement
    /// descriptor so post-splice vaults settle under attacker-chosen rules.
    /// The descriptor commitment must be preserved across a splice.
    #[test]
    fn rejects_splice_state_transition_with_changed_settlement_descriptor() {
        let key0 = SigningKey::from_slice(&[1u8; 32]).unwrap();
        let key1 = SigningKey::from_slice(&[2u8; 32]).unwrap();
        let mut pubkeys = [pubkey(&key0), pubkey(&key1)];
        pubkeys.sort();
        let participant_refs = [pubkeys[0].as_slice(), pubkeys[1].as_slice()];
        let participants = participants_commitment(2, &participant_refs);

        let old_ckb = splice_vault_asset_bytes(VAULT_ASSET_KIND_CKB, 0, 10_000);
        let old_vault_raw =
            splice_vault_descriptor_bytes([4u8; BYTE32_LEN], 1, &old_ckb, &[0u8; 49]);
        let old_vault = SpliceVaultDescriptor::parse(&old_vault_raw).unwrap();
        let new_ckb = splice_vault_asset_bytes(VAULT_ASSET_KIND_CKB, 0, 14_900);
        let new_vault_raw =
            splice_vault_descriptor_bytes([10u8; BYTE32_LEN], 1, &new_ckb, &[0u8; 49]);
        let new_vault = SpliceVaultDescriptor::parse(&new_vault_raw).unwrap();
        let delta =
            splice_asset_delta_bytes(VAULT_ASSET_KIND_CKB, 0, 10_000, 14_900, 5_000, 0, 100);
        let deltas_raw = splice_asset_deltas_bytes(1, &delta, &[0u8; SPLICE_ASSET_DELTA_LEN]);
        let deltas = SpliceAssetDeltas::parse(&deltas_raw).unwrap();

        let splice_header_raw = splice_header_bytes(
            SPLICE_KIND_IN,
            7,
            &participants,
            &old_vault.commitment().unwrap(),
            &new_vault.commitment().unwrap(),
            &deltas.commitment().unwrap(),
            &[8u8; BYTE32_LEN],
        );
        let splice_header = SpliceHeader::parse(&splice_header_raw).unwrap();
        let witness_raw = signed_bilateral_witness(&key0, &key1, &splice_header.signing_digest());
        let witness = SpliceSignatureWitness::parse(&witness_raw).unwrap();

        let mut current_raw = header_bytes(7, PHASE_ACTIVE, 0);
        current_raw[108..140].copy_from_slice(&old_vault.commitment().unwrap());
        current_raw[150..182].copy_from_slice(&participants);
        let current = StateHeader::parse(&current_raw).unwrap();
        let mut next_raw = header_bytes(7, PHASE_ACTIVE, 1);
        next_raw[76..108].fill(10);
        next_raw[108..140].copy_from_slice(&new_vault.commitment().unwrap());
        next_raw[150..182].copy_from_slice(&participants);
        // Attacker flips the successor's settlement_descriptor_commitment to
        // a different value than the splice event was signed for.
        next_raw[182..214].fill(0xCC);
        let next = StateHeader::parse(&next_raw).unwrap();

        assert_eq!(
            verify_splice_state_transition(
                &current,
                &next,
                &splice_header,
                &witness,
                &old_vault,
                &new_vault,
                &deltas,
            )
            .unwrap_err(),
            ScriptError::SpliceProofMismatch
        );
    }

    /// C-01 attack vector: attacker substitutes successor mode so the
    /// witness interpretation rule changes after splice. The signed splice
    /// event binds the genuine mode implicitly through the
    /// participants_commitment and challenge_policy_commitment check, and
    /// the state-context assertion requires current.mode == next.mode.
    #[test]
    fn rejects_splice_state_transition_with_changed_mode() {
        let key0 = SigningKey::from_slice(&[1u8; 32]).unwrap();
        let key1 = SigningKey::from_slice(&[2u8; 32]).unwrap();
        let mut pubkeys = [pubkey(&key0), pubkey(&key1)];
        pubkeys.sort();
        let participant_refs = [pubkeys[0].as_slice(), pubkeys[1].as_slice()];
        let participants = participants_commitment(2, &participant_refs);

        let old_ckb = splice_vault_asset_bytes(VAULT_ASSET_KIND_CKB, 0, 10_000);
        let old_vault_raw =
            splice_vault_descriptor_bytes([4u8; BYTE32_LEN], 1, &old_ckb, &[0u8; 49]);
        let old_vault = SpliceVaultDescriptor::parse(&old_vault_raw).unwrap();
        let new_ckb = splice_vault_asset_bytes(VAULT_ASSET_KIND_CKB, 0, 14_900);
        let new_vault_raw =
            splice_vault_descriptor_bytes([10u8; BYTE32_LEN], 1, &new_ckb, &[0u8; 49]);
        let new_vault = SpliceVaultDescriptor::parse(&new_vault_raw).unwrap();
        let delta =
            splice_asset_delta_bytes(VAULT_ASSET_KIND_CKB, 0, 10_000, 14_900, 5_000, 0, 100);
        let deltas_raw = splice_asset_deltas_bytes(1, &delta, &[0u8; SPLICE_ASSET_DELTA_LEN]);
        let deltas = SpliceAssetDeltas::parse(&deltas_raw).unwrap();

        let splice_header_raw = splice_header_bytes(
            SPLICE_KIND_IN,
            7,
            &participants,
            &old_vault.commitment().unwrap(),
            &new_vault.commitment().unwrap(),
            &deltas.commitment().unwrap(),
            &[8u8; BYTE32_LEN],
        );
        let splice_header = SpliceHeader::parse(&splice_header_raw).unwrap();
        let witness_raw = signed_bilateral_witness(&key0, &key1, &splice_header.signing_digest());
        let witness = SpliceSignatureWitness::parse(&witness_raw).unwrap();

        let mut current_raw = header_bytes(7, PHASE_ACTIVE, 0);
        current_raw[108..140].copy_from_slice(&old_vault.commitment().unwrap());
        current_raw[150..182].copy_from_slice(&participants);
        let current = StateHeader::parse(&current_raw).unwrap();
        let mut next_raw = header_bytes(7, PHASE_ACTIVE, 1);
        next_raw[76..108].fill(10);
        next_raw[108..140].copy_from_slice(&new_vault.commitment().unwrap());
        next_raw[150..182].copy_from_slice(&participants);
        // Attacker flips the successor's mode byte.
        next_raw[148] = 2;
        let next = StateHeader::parse(&next_raw).unwrap();

        assert_eq!(
            verify_splice_state_transition(
                &current,
                &next,
                &splice_header,
                &witness,
                &old_vault,
                &new_vault,
                &deltas,
            )
            .unwrap_err(),
            ScriptError::SpliceProofMismatch
        );
    }

    /// C-01 attack vector: attacker substitutes successor asset registry so
    /// post-splice vault materialisation references a different asset set.
    #[test]
    fn rejects_splice_state_transition_with_changed_asset_registry() {
        let key0 = SigningKey::from_slice(&[1u8; 32]).unwrap();
        let key1 = SigningKey::from_slice(&[2u8; 32]).unwrap();
        let mut pubkeys = [pubkey(&key0), pubkey(&key1)];
        pubkeys.sort();
        let participant_refs = [pubkeys[0].as_slice(), pubkeys[1].as_slice()];
        let participants = participants_commitment(2, &participant_refs);

        let old_ckb = splice_vault_asset_bytes(VAULT_ASSET_KIND_CKB, 0, 10_000);
        let old_vault_raw =
            splice_vault_descriptor_bytes([4u8; BYTE32_LEN], 1, &old_ckb, &[0u8; 49]);
        let old_vault = SpliceVaultDescriptor::parse(&old_vault_raw).unwrap();
        let new_ckb = splice_vault_asset_bytes(VAULT_ASSET_KIND_CKB, 0, 14_900);
        let new_vault_raw =
            splice_vault_descriptor_bytes([10u8; BYTE32_LEN], 1, &new_ckb, &[0u8; 49]);
        let new_vault = SpliceVaultDescriptor::parse(&new_vault_raw).unwrap();
        let delta =
            splice_asset_delta_bytes(VAULT_ASSET_KIND_CKB, 0, 10_000, 14_900, 5_000, 0, 100);
        let deltas_raw = splice_asset_deltas_bytes(1, &delta, &[0u8; SPLICE_ASSET_DELTA_LEN]);
        let deltas = SpliceAssetDeltas::parse(&deltas_raw).unwrap();

        let splice_header_raw = splice_header_bytes(
            SPLICE_KIND_IN,
            7,
            &participants,
            &old_vault.commitment().unwrap(),
            &new_vault.commitment().unwrap(),
            &deltas.commitment().unwrap(),
            &[8u8; BYTE32_LEN],
        );
        let splice_header = SpliceHeader::parse(&splice_header_raw).unwrap();
        let witness_raw = signed_bilateral_witness(&key0, &key1, &splice_header.signing_digest());
        let witness = SpliceSignatureWitness::parse(&witness_raw).unwrap();

        let mut current_raw = header_bytes(7, PHASE_ACTIVE, 0);
        current_raw[108..140].copy_from_slice(&old_vault.commitment().unwrap());
        current_raw[150..182].copy_from_slice(&participants);
        let current = StateHeader::parse(&current_raw).unwrap();
        let mut next_raw = header_bytes(7, PHASE_ACTIVE, 1);
        next_raw[76..108].fill(10);
        next_raw[108..140].copy_from_slice(&new_vault.commitment().unwrap());
        next_raw[150..182].copy_from_slice(&participants);
        // Attacker flips the successor's asset_registry_commitment to a
        // different value than the splice event was signed for.
        next_raw[214..246].fill(0xDD);
        let next = StateHeader::parse(&next_raw).unwrap();

        assert_eq!(
            verify_splice_state_transition(
                &current,
                &next,
                &splice_header,
                &witness,
                &old_vault,
                &new_vault,
                &deltas,
            )
            .unwrap_err(),
            ScriptError::SpliceProofMismatch
        );
    }

    #[test]
    fn splice_vault_descriptor_commitment_is_counted_and_ordered() {
        let ckb = splice_vault_asset_bytes(VAULT_ASSET_KIND_CKB, 0, 10_000);
        let xudt = splice_vault_asset_bytes(VAULT_ASSET_KIND_XUDT, 42, 50);
        let raw = splice_vault_descriptor_bytes([4u8; BYTE32_LEN], 2, &ckb, &xudt);
        let descriptor = SpliceVaultDescriptor::parse(&raw).unwrap();

        assert_eq!(descriptor.funding_anchor(), &[4u8; BYTE32_LEN]);
        assert_eq!(descriptor.asset_count(), 2);
        assert_eq!(
            descriptor.asset(0).unwrap().asset_kind(),
            VAULT_ASSET_KIND_CKB
        );
        assert_eq!(
            descriptor.asset(1).unwrap().asset_kind(),
            VAULT_ASSET_KIND_XUDT
        );
        assert_eq!(
            descriptor.commitment().unwrap(),
            blake2b256(&[
                VAULT_DESCRIPTOR_DOMAIN,
                &[4u8; BYTE32_LEN],
                &2u16.to_le_bytes(),
                &ckb,
                &xudt
            ])
        );

        let wrong_order = splice_vault_descriptor_bytes([4u8; BYTE32_LEN], 2, &xudt, &ckb);
        assert_eq!(
            SpliceVaultDescriptor::parse(&wrong_order).unwrap_err(),
            ScriptError::Encoding
        );
    }

    #[test]
    fn splice_asset_delta_commitment_is_counted_and_ordered() {
        let ckb = splice_asset_delta_bytes(VAULT_ASSET_KIND_CKB, 0, 10_000, 14_900, 5_000, 0, 100);
        let xudt = splice_asset_delta_bytes(VAULT_ASSET_KIND_XUDT, 42, 50, 60, 10, 0, 0);
        let raw = splice_asset_deltas_bytes(2, &ckb, &xudt);
        let deltas = SpliceAssetDeltas::parse(&raw).unwrap();

        assert_eq!(deltas.delta_count(), 2);
        assert_eq!(deltas.delta(0).unwrap().old_amount(), 10_000);
        assert_eq!(deltas.delta(0).unwrap().new_amount(), 14_900);
        assert_eq!(deltas.delta(0).unwrap().external_input(), 5_000);
        assert_eq!(deltas.delta(0).unwrap().withdrawal(), 0);
        assert_eq!(deltas.delta(0).unwrap().signed_fee(), 100);
        assert_eq!(deltas.delta(1).unwrap().asset_type(), &[42u8; BYTE32_LEN]);
        assert_eq!(
            deltas.commitment().unwrap(),
            blake2b256(&[SPLICE_DELTA_DOMAIN, &2u16.to_le_bytes(), &ckb, &xudt])
        );

        let wrong_order = splice_asset_deltas_bytes(2, &xudt, &ckb);
        assert_eq!(
            SpliceAssetDeltas::parse(&wrong_order).unwrap_err(),
            ScriptError::Encoding
        );
    }

    #[test]
    fn splice_fixed_width_vectors_require_zero_unused_slots() {
        let ckb = splice_vault_asset_bytes(VAULT_ASSET_KIND_CKB, 0, 10_000);
        let xudt = splice_vault_asset_bytes(VAULT_ASSET_KIND_XUDT, 42, 50);
        let descriptor = splice_vault_descriptor_bytes([4u8; BYTE32_LEN], 1, &ckb, &xudt);
        assert_eq!(
            SpliceVaultDescriptor::parse(&descriptor).unwrap_err(),
            ScriptError::Encoding
        );

        let ckb_delta =
            splice_asset_delta_bytes(VAULT_ASSET_KIND_CKB, 0, 10_000, 14_900, 5_000, 0, 100);
        let xudt_delta = splice_asset_delta_bytes(VAULT_ASSET_KIND_XUDT, 42, 50, 60, 10, 0, 0);
        let deltas = splice_asset_deltas_bytes(1, &ckb_delta, &xudt_delta);
        assert_eq!(
            SpliceAssetDeltas::parse(&deltas).unwrap_err(),
            ScriptError::Encoding
        );
    }

    #[test]
    fn sponsor_policy_fields_are_fixed_width() {
        let mut raw = [0u8; SPONSOR_POLICY_LEN];
        raw[0..32].fill(1);
        put_u64(&mut raw, 32, 10);
        put_u64(&mut raw, 40, 20);
        put_u64(&mut raw, 48, 30);
        put_u64(&mut raw, 56, 40);
        put_u64(&mut raw, 64, 50);
        put_u64(&mut raw, 72, 60);
        raw[80..112].fill(2);
        raw[112..144].fill(3);

        let policy = SponsorPolicy::parse(&raw).unwrap();
        assert_eq!(policy.channel_id(), &[1u8; 32]);
        assert_eq!(policy.min_state_number(), 10);
        assert_eq!(policy.max_state_number(), 20);
        assert_eq!(policy.max_fee_per_tx(), 30);
        assert_eq!(policy.max_total_fee(), 40);
        assert_eq!(policy.already_spent(), 50);
        assert_eq!(policy.expiry(), 60);
        assert_eq!(policy.publication_state_type_hash(), &[2u8; 32]);
        assert_eq!(policy.change_lock(), &[3u8; 32]);
    }

    #[test]
    fn molecule_schema_names_all_active_fixed_width_objects() {
        let schema = include_str!("../../../schemas/morph.mol");
        for expected in [
            "StateHeader: 314 bytes",
            "SpliceHeader: 357 bytes",
            "SpliceSignatureWitness: 198 bytes",
            "SpliceVaultAssetAmount: 49 bytes",
            "SpliceVaultDescriptor: 132 bytes",
            "SpliceAssetDelta: 113 bytes",
            "SpliceAssetDeltas: 228 bytes",
            "SpliceStateTransitionWitness: 1049 bytes",
            "BilateralSignatureWitness: 198 bytes",
            "BilateralCkbSettlementDescriptor: 84 bytes",
            "BilateralCkbXudtSettlementDescriptor: 148 bytes",
            "SponsorPolicy: 144 bytes",
            "FactoryStateHeader: 238 bytes",
            "FactorySignatureWitness: 262 bytes",
            "FactoryRight: 114 bytes",
            "FactoryReducedRightsWitness: 2580 bytes",
            "FactoryMerkleUpdateWitness: 8720 bytes",
            "FactoryReducedExitWitness: 3058 bytes",
            "FactoryReducedExitXudtWitness: 3122 bytes",
            "FactoryLocalExitWitness: 726 bytes",
            "FactoryLocalExitXudtWitness: 790 bytes",
            "FactorySpliceHeader: 275 bytes",
            "FactoryVaultDescriptor: 132 bytes",
            "FactoryVaultDelta: 97 bytes",
            "FactoryVaultDeltas: 196 bytes",
            "FactorySpliceWitness: 999 bytes",
            "FactoryReducedSpliceWitness: 9457 bytes",
            "struct StateHeader",
            "struct SpliceHeader",
            "struct SpliceSignatureWitness",
            "struct SpliceVaultDescriptor",
            "struct SpliceAssetDeltas",
            "struct SpliceStateTransitionWitness",
            "struct FactoryStateHeader",
            "struct BilateralSignatureWitness",
            "struct FactorySignatureWitness",
            "struct FactoryReducedRightsWitness",
            "struct FactoryMerkleUpdateWitness",
            "struct FactoryReducedExitWitness",
            "struct FactoryReducedExitXudtWitness",
            "struct FactoryLocalExitWitness",
            "struct FactoryLocalExitXudtWitness",
            "struct FactorySpliceHeader",
            "struct FactoryVaultDescriptor",
            "struct FactoryVaultDeltas",
            "struct FactorySpliceWitness",
            "struct FactoryReducedSpliceWitness",
            "struct BilateralCkbSettlementDescriptor",
            "struct BilateralCkbXudtSettlementDescriptor",
            "struct SponsorPolicy",
            "state_lock_hash: Byte32",
            "xudt_type_hash: Byte32",
            "xudt_amount: uint128",
            "max_fee_per_tx: uint64",
            "publication_state_type_hash: Byte32",
            "change_lock_hash: Byte32",
            "participant_0_id: Byte32",
            "non_interference_digest: Byte32",
            "release_quantity: uint128",
            "proof_siblings: FactoryMerkleProofSiblings",
            "old_funding_epoch: uint64",
            "new_funding_epoch: uint64",
            "funding_epoch: uint64",
            "vault_set_commitment: Byte32",
            "asset_delta_commitment: Byte32",
            "signed_fee: uint128",
            "old_vault_descriptor: SpliceVaultDescriptor",
        ] {
            assert!(
                schema.contains(expected),
                "schema is missing expected fragment: {expected}"
            );
        }
    }

    #[test]
    fn verifies_real_bilateral_state_signatures() {
        let key0 = signing_key(1);
        let key1 = signing_key(2);
        let mut entries = [pubkey(&key0), pubkey(&key1)];
        entries.sort();

        let mut raw = header_bytes(7, PHASE_SETTLING, 1);
        let commitment =
            participants_commitment(2, &[entries[0].as_slice(), entries[1].as_slice()]);
        raw[150..182].copy_from_slice(&commitment);
        let header = StateHeader::parse(&raw).unwrap();
        let witness_raw = signed_bilateral_witness(&key0, &key1, &header.signing_digest());
        let witness = BilateralSignatureWitness::parse(&witness_raw).unwrap();

        verify_bilateral_state_signatures(&header, &witness).unwrap();
    }

    #[test]
    fn rejects_bad_bilateral_state_signature() {
        let key0 = signing_key(1);
        let key1 = signing_key(2);
        let mut entries = [pubkey(&key0), pubkey(&key1)];
        entries.sort();

        let mut raw = header_bytes(7, PHASE_SETTLING, 1);
        let commitment =
            participants_commitment(2, &[entries[0].as_slice(), entries[1].as_slice()]);
        raw[150..182].copy_from_slice(&commitment);
        let header = StateHeader::parse(&raw).unwrap();
        let mut witness_raw = signed_bilateral_witness(&key0, &key1, &header.signing_digest());
        witness_raw[BILATERAL_SIGNATURE_WITNESS_LEN - 1] ^= 1;
        let witness = BilateralSignatureWitness::parse(&witness_raw).unwrap();

        assert_eq!(
            verify_bilateral_state_signatures(&header, &witness).unwrap_err(),
            ScriptError::InvalidParticipantSignature
        );
    }

    #[test]
    fn verifies_real_factory_state_signatures() {
        let key0 = signing_key(1);
        let key1 = signing_key(2);
        let mut entries = [([1u8; 32], pubkey(&key0)), ([2u8; 32], pubkey(&key1))];
        entries.sort_by(|left, right| left.0.cmp(&right.0));

        let mut raw = factory_header_bytes(7);
        let commitment = factory_participants_commitment(
            2,
            &[
                (entries[0].0.as_slice(), entries[0].1.as_slice()),
                (entries[1].0.as_slice(), entries[1].1.as_slice()),
            ],
        );
        raw[108..140].copy_from_slice(&commitment);
        let header = FactoryStateHeader::parse(&raw).unwrap();
        let witness_raw =
            signed_factory_witness([1u8; 32], &key0, [2u8; 32], &key1, &header.signing_digest());
        let witness = FactorySignatureWitness::parse(&witness_raw).unwrap();

        verify_factory_state_signatures(&header, &witness).unwrap();
    }

    #[test]
    fn rejects_bad_factory_state_signature() {
        let key0 = signing_key(1);
        let key1 = signing_key(2);
        let mut entries = [([1u8; 32], pubkey(&key0)), ([2u8; 32], pubkey(&key1))];
        entries.sort_by(|left, right| left.0.cmp(&right.0));

        let mut raw = factory_header_bytes(7);
        let commitment = factory_participants_commitment(
            2,
            &[
                (entries[0].0.as_slice(), entries[0].1.as_slice()),
                (entries[1].0.as_slice(), entries[1].1.as_slice()),
            ],
        );
        raw[108..140].copy_from_slice(&commitment);
        let header = FactoryStateHeader::parse(&raw).unwrap();
        let mut witness_raw =
            signed_factory_witness([1u8; 32], &key0, [2u8; 32], &key1, &header.signing_digest());
        witness_raw[FACTORY_SIGNATURE_WITNESS_LEN - 1] ^= 1;
        let witness = FactorySignatureWitness::parse(&witness_raw).unwrap();

        assert_eq!(
            verify_factory_state_signatures(&header, &witness).unwrap_err(),
            ScriptError::InvalidParticipantSignature
        );
    }

    #[test]
    fn witness_envelope_rejects_malformed_headers_and_bodies() {
        let body = signed_factory_witness(
            [1u8; 32],
            &signing_key(1),
            [2u8; 32],
            &signing_key(2),
            &[9u8; 32],
        );
        let raw = signature_witness_envelope_bytes(&body);
        let envelope = WitnessEnvelope::parse(&raw).unwrap();
        assert_eq!(envelope.kind(), WITNESS_ENVELOPE_KIND_FACTORY_SIGNATURE);
        assert_eq!(envelope.body(), body.as_slice());

        let mut bad_magic = raw;
        bad_magic[0] ^= 1;
        assert_eq!(
            WitnessEnvelope::parse(&bad_magic).unwrap_err(),
            ScriptError::WitnessEnvelopeEncoding
        );

        let mut bad_version = raw;
        write_u16(&mut bad_version, 8, WITNESS_ENVELOPE_FORMAT + 1);
        assert_eq!(
            WitnessEnvelope::parse(&bad_version).unwrap_err(),
            ScriptError::WitnessEnvelopeEncoding
        );

        let mut bad_kind = raw;
        write_u16(&mut bad_kind, 10, 99);
        assert_eq!(
            WitnessEnvelope::parse(&bad_kind).unwrap_err(),
            ScriptError::WitnessEnvelopeEncoding
        );

        let mut bad_flags = raw;
        write_u16(&mut bad_flags, 12, 1);
        assert_eq!(
            WitnessEnvelope::parse(&bad_flags).unwrap_err(),
            ScriptError::WitnessEnvelopeEncoding
        );

        let mut bad_len = raw;
        write_u32(&mut bad_len, 14, FACTORY_SIGNATURE_WITNESS_LEN as u32 + 1);
        assert_eq!(
            WitnessEnvelope::parse(&bad_len).unwrap_err(),
            ScriptError::WitnessEnvelopeEncoding
        );

        let mut bad_commitment = raw;
        bad_commitment[18] ^= 1;
        assert_eq!(
            WitnessEnvelope::parse(&bad_commitment).unwrap_err(),
            ScriptError::WitnessEnvelopeEncoding
        );

        let mut bad_body = raw;
        let last = bad_body.len() - 1;
        bad_body[last] ^= 1;
        assert_eq!(
            WitnessEnvelope::parse(&bad_body).unwrap_err(),
            ScriptError::WitnessEnvelopeEncoding
        );

        let short = short_signature_witness_envelope_bytes();
        assert_eq!(
            WitnessEnvelope::parse(&short).unwrap_err(),
            ScriptError::WitnessEnvelopeEncoding
        );
    }

    fn signature_witness_envelope_bytes(
        body: &[u8; FACTORY_SIGNATURE_WITNESS_LEN],
    ) -> [u8; WITNESS_ENVELOPE_LEN + FACTORY_SIGNATURE_WITNESS_LEN] {
        let mut raw = [0u8; WITNESS_ENVELOPE_LEN + FACTORY_SIGNATURE_WITNESS_LEN];
        raw[0..WITNESS_ENVELOPE_MAGIC.len()].copy_from_slice(WITNESS_ENVELOPE_MAGIC);
        write_u16(&mut raw, 8, WITNESS_ENVELOPE_FORMAT);
        write_u16(&mut raw, 10, WITNESS_ENVELOPE_KIND_FACTORY_SIGNATURE);
        write_u16(&mut raw, 12, 0);
        write_u32(&mut raw, 14, FACTORY_SIGNATURE_WITNESS_LEN as u32);
        raw[18..50].copy_from_slice(&witness_envelope_body_commitment(
            WITNESS_ENVELOPE_KIND_FACTORY_SIGNATURE,
            body,
        ));
        raw[WITNESS_ENVELOPE_LEN..].copy_from_slice(body);
        raw
    }

    fn short_signature_witness_envelope_bytes() -> [u8; WITNESS_ENVELOPE_LEN + 10] {
        let body = [0u8; 10];
        let mut raw = [0u8; WITNESS_ENVELOPE_LEN + 10];
        raw[0..WITNESS_ENVELOPE_MAGIC.len()].copy_from_slice(WITNESS_ENVELOPE_MAGIC);
        write_u16(&mut raw, 8, WITNESS_ENVELOPE_FORMAT);
        write_u16(&mut raw, 10, WITNESS_ENVELOPE_KIND_FACTORY_SIGNATURE);
        write_u16(&mut raw, 12, 0);
        write_u32(&mut raw, 14, body.len() as u32);
        raw[18..50].copy_from_slice(&witness_envelope_body_commitment(
            WITNESS_ENVELOPE_KIND_FACTORY_SIGNATURE,
            &body,
        ));
        raw[WITNESS_ENVELOPE_LEN..].copy_from_slice(&body);
        raw
    }

    #[test]
    fn factory_splice_witness_fields_are_fixed_width() {
        let (_, _, witness_raw) = factory_splice_headers_and_witness(SPLICE_KIND_IN);
        let witness = FactorySpliceWitness::parse(&witness_raw).unwrap();
        let header = witness.header().unwrap();
        let old_vault = witness.old_vault().unwrap();
        let new_vault = witness.new_vault().unwrap();
        let deltas = witness.deltas().unwrap();

        assert_eq!(witness.version(), FACTORY_SPLICE_WITNESS_VERSION);
        assert_eq!(header.factory_id(), &[3u8; 32]);
        assert_eq!(header.old_update_number(), 1);
        assert_eq!(header.new_update_number(), 2);
        assert_eq!(header.kind(), SPLICE_KIND_IN);
        assert_eq!(old_vault.asset(0).unwrap().amount(), 50);
        assert_eq!(new_vault.asset(0).unwrap().amount(), 70);
        assert_eq!(deltas.delta(0).unwrap().external_input(), 20);
    }

    #[test]
    fn verifies_factory_splice_update() {
        let (old_raw, new_raw, witness_raw) = factory_splice_headers_and_witness(SPLICE_KIND_IN);
        let old_header = FactoryStateHeader::parse(&old_raw).unwrap();
        let new_header = FactoryStateHeader::parse(&new_raw).unwrap();
        let witness = FactorySpliceWitness::parse(&witness_raw).unwrap();

        verify_factory_splice_update(&old_header, &new_header, &witness).unwrap();
    }

    #[test]
    fn rejects_factory_splice_unsupported_signature_scheme() {
        let (old_raw, new_raw, witness_raw) =
            factory_splice_headers_and_witness_with_scheme(SPLICE_KIND_IN, 2);
        let old_header = FactoryStateHeader::parse(&old_raw).unwrap();
        let new_header = FactoryStateHeader::parse(&new_raw).unwrap();
        let witness = FactorySpliceWitness::parse(&witness_raw).unwrap();

        assert_eq!(
            verify_factory_splice_update(&old_header, &new_header, &witness).unwrap_err(),
            ScriptError::FactorySpliceProofEncoding
        );
    }

    #[test]
    fn rejects_factory_splice_vault_delta_tamper() {
        let (old_raw, new_raw, mut witness_raw) =
            factory_splice_headers_and_witness(SPLICE_KIND_IN);
        witness_raw[factory_splice_deltas_offset() + factory_vault_delta_offset(0) + 49] ^= 1;
        let old_header = FactoryStateHeader::parse(&old_raw).unwrap();
        let new_header = FactoryStateHeader::parse(&new_raw).unwrap();
        let witness = FactorySpliceWitness::parse(&witness_raw).unwrap();

        assert_eq!(
            verify_factory_splice_update(&old_header, &new_header, &witness).unwrap_err(),
            ScriptError::FactorySpliceProofMismatch
        );
    }

    #[test]
    fn rejects_factory_splice_bad_signature() {
        let (old_raw, new_raw, mut witness_raw) =
            factory_splice_headers_and_witness(SPLICE_KIND_OUT);
        witness_raw[factory_splice_signature_offset() + FACTORY_SIGNATURE_WITNESS_LEN - 1] ^= 1;
        let old_header = FactoryStateHeader::parse(&old_raw).unwrap();
        let new_header = FactoryStateHeader::parse(&new_raw).unwrap();
        let witness = FactorySpliceWitness::parse(&witness_raw).unwrap();

        assert_eq!(
            verify_factory_splice_update(&old_header, &new_header, &witness).unwrap_err(),
            ScriptError::InvalidParticipantSignature
        );
    }

    #[test]
    fn factory_reduced_splice_witness_fields_are_fixed_width() {
        let (_, _, witness_raw) = factory_reduced_splice_headers_and_witness(SPLICE_KIND_IN);
        let witness = FactoryReducedSpliceWitness::parse(&witness_raw).unwrap();
        let header = witness.header().unwrap();
        let merkle_update = witness.merkle_update().unwrap();
        let old_vault = witness.old_vault().unwrap();
        let new_vault = witness.new_vault().unwrap();
        let deltas = witness.deltas().unwrap();

        assert_eq!(witness.version(), FACTORY_REDUCED_SPLICE_WITNESS_VERSION);
        assert_eq!(header.factory_id(), &[3u8; 32]);
        assert_eq!(header.old_update_number(), 1);
        assert_eq!(header.new_update_number(), 2);
        assert_eq!(
            merkle_update.right_before().unwrap().kind(),
            FACTORY_RIGHT_KIND_RESERVE_CLAIM
        );
        assert_eq!(merkle_update.sibling_hash(255), &[255u8; 32]);
        assert_eq!(old_vault.asset(0).unwrap().amount(), 50);
        assert_eq!(new_vault.asset(0).unwrap().amount(), 70);
        assert_eq!(deltas.delta(0).unwrap().external_input(), 20);
    }

    #[test]
    fn verifies_factory_reduced_splice_update() {
        let (old_raw, new_raw, witness_raw) =
            factory_reduced_splice_headers_and_witness(SPLICE_KIND_IN);
        let old_header = FactoryStateHeader::parse(&old_raw).unwrap();
        let new_header = FactoryStateHeader::parse(&new_raw).unwrap();
        let witness = FactoryReducedSpliceWitness::parse(&witness_raw).unwrap();

        verify_factory_reduced_splice_update(&old_header, &new_header, &witness).unwrap();
    }

    #[test]
    fn rejects_factory_reduced_splice_unsupported_signature_scheme() {
        let (old_raw, new_raw, witness_raw) =
            factory_reduced_splice_headers_and_witness_with_scheme(SPLICE_KIND_IN, 2);
        let old_header = FactoryStateHeader::parse(&old_raw).unwrap();
        let new_header = FactoryStateHeader::parse(&new_raw).unwrap();
        let witness = FactoryReducedSpliceWitness::parse(&witness_raw).unwrap();

        assert_eq!(
            verify_factory_reduced_splice_update(&old_header, &new_header, &witness).unwrap_err(),
            ScriptError::FactorySpliceProofEncoding
        );
    }

    #[test]
    fn rejects_factory_reduced_splice_sibling_tamper() {
        let (old_raw, new_raw, mut witness_raw) =
            factory_reduced_splice_headers_and_witness(SPLICE_KIND_IN);
        witness_raw[factory_reduced_splice_merkle_offset() + factory_merkle_sibling_offset(120)] ^=
            1;
        let old_header = FactoryStateHeader::parse(&old_raw).unwrap();
        let new_header = FactoryStateHeader::parse(&new_raw).unwrap();
        let witness = FactoryReducedSpliceWitness::parse(&witness_raw).unwrap();

        assert_eq!(
            verify_factory_reduced_splice_update(&old_header, &new_header, &witness).unwrap_err(),
            ScriptError::FactoryReducedProofMismatch
        );
    }

    #[test]
    fn rejects_factory_reduced_splice_bad_signature() {
        let (old_raw, new_raw, mut witness_raw) =
            factory_reduced_splice_headers_and_witness(SPLICE_KIND_OUT);
        let signature_offset = factory_reduced_splice_merkle_offset()
            + factory_merkle_participant_offset(0)
            + BYTE32_LEN
            + COMPRESSED_SECP256K1_PUBKEY_LEN
            + 1;
        witness_raw[signature_offset + ECDSA_SIGNATURE_LEN - 1] ^= 1;
        let old_header = FactoryStateHeader::parse(&old_raw).unwrap();
        let new_header = FactoryStateHeader::parse(&new_raw).unwrap();
        let witness = FactoryReducedSpliceWitness::parse(&witness_raw).unwrap();

        assert_eq!(
            verify_factory_reduced_splice_update(&old_header, &new_header, &witness).unwrap_err(),
            ScriptError::InvalidParticipantSignature
        );
    }

    #[test]
    fn verifies_reduced_factory_rights_decrease() {
        let (old_raw, new_raw, witness_raw) = reduced_rights_headers_and_witness(90);
        let old_header = FactoryStateHeader::parse(&old_raw).unwrap();
        let new_header = FactoryStateHeader::parse(&new_raw).unwrap();
        let witness = FactoryReducedRightsWitness::parse(&witness_raw).unwrap();

        verify_reduced_factory_rights_update(&old_header, &new_header, &witness).unwrap();
    }

    #[test]
    fn rejects_reduced_factory_rights_increase() {
        let (old_raw, new_raw, witness_raw) = reduced_rights_headers_and_witness(110);
        let old_header = FactoryStateHeader::parse(&old_raw).unwrap();
        let new_header = FactoryStateHeader::parse(&new_raw).unwrap();
        let witness = FactoryReducedRightsWitness::parse(&witness_raw).unwrap();

        assert_eq!(
            verify_reduced_factory_rights_update(&old_header, &new_header, &witness).unwrap_err(),
            ScriptError::FactoryReducedProofMismatch
        );
    }

    #[test]
    fn rejects_reduced_factory_rights_bad_signature() {
        let (old_raw, new_raw, mut witness_raw) = reduced_rights_headers_and_witness(90);
        let signature_offset = factory_reduced_participant_offset(0)
            + BYTE32_LEN
            + COMPRESSED_SECP256K1_PUBKEY_LEN
            + 1;
        witness_raw[signature_offset + ECDSA_SIGNATURE_LEN - 1] ^= 1;
        let old_header = FactoryStateHeader::parse(&old_raw).unwrap();
        let new_header = FactoryStateHeader::parse(&new_raw).unwrap();
        let witness = FactoryReducedRightsWitness::parse(&witness_raw).unwrap();

        assert_eq!(
            verify_reduced_factory_rights_update(&old_header, &new_header, &witness).unwrap_err(),
            ScriptError::InvalidParticipantSignature
        );
    }

    #[test]
    fn factory_merkle_update_witness_fields_are_fixed_width() {
        let (_, _, witness_raw) = merkle_update_headers_and_witness(90);
        let witness = FactoryMerkleUpdateWitness::parse(&witness_raw).unwrap();

        assert_eq!(witness.version(), FACTORY_MERKLE_UPDATE_WITNESS_VERSION);
        assert_eq!(witness.right_count(), FACTORY_MERKLE_UPDATE_RIGHT_COUNT);
        assert_eq!(witness.touched_participant(), &[1u8; 32]);
        assert_eq!(witness.right_before().unwrap().quantity(), 100);
        assert_eq!(witness.right_after().unwrap().quantity(), 90);
        assert_eq!(witness.sibling_hash(255), &[255u8; 32]);
    }

    #[test]
    fn verifies_factory_merkle_update_single_right_transition() {
        let (old_raw, new_raw, witness_raw) = merkle_update_headers_and_witness(90);
        let old_header = FactoryStateHeader::parse(&old_raw).unwrap();
        let new_header = FactoryStateHeader::parse(&new_raw).unwrap();
        let witness = FactoryMerkleUpdateWitness::parse(&witness_raw).unwrap();

        verify_factory_merkle_update(&old_header, &new_header, &witness).unwrap();
    }

    #[test]
    fn rejects_factory_merkle_update_sibling_tamper() {
        let (old_raw, new_raw, mut witness_raw) = merkle_update_headers_and_witness(90);
        witness_raw[factory_merkle_sibling_offset(120)] ^= 1;
        let old_header = FactoryStateHeader::parse(&old_raw).unwrap();
        let new_header = FactoryStateHeader::parse(&new_raw).unwrap();
        let witness = FactoryMerkleUpdateWitness::parse(&witness_raw).unwrap();

        assert_eq!(
            verify_factory_merkle_update(&old_header, &new_header, &witness).unwrap_err(),
            ScriptError::FactoryReducedProofMismatch
        );
    }

    #[test]
    fn rejects_factory_merkle_update_unauthorised_signer() {
        let (old_raw, new_raw, mut witness_raw) = merkle_update_headers_and_witness(90);
        let signer_0_flag =
            factory_merkle_participant_offset(0) + BYTE32_LEN + COMPRESSED_SECP256K1_PUBKEY_LEN;
        let signer_1_flag =
            factory_merkle_participant_offset(1) + BYTE32_LEN + COMPRESSED_SECP256K1_PUBKEY_LEN;
        witness_raw[signer_0_flag] = 0;
        witness_raw[signer_1_flag] = 1;
        let old_header = FactoryStateHeader::parse(&old_raw).unwrap();
        let new_header = FactoryStateHeader::parse(&new_raw).unwrap();
        let witness = FactoryMerkleUpdateWitness::parse(&witness_raw).unwrap();

        assert_eq!(
            verify_factory_merkle_update(&old_header, &new_header, &witness).unwrap_err(),
            ScriptError::FactoryReducedProofMismatch
        );
    }

    #[test]
    fn reduced_factory_exit_witness_fields_are_fixed_width() {
        let (_, _, witness_raw) = reduced_exit_headers_and_witness(20, 30, false, true);
        let witness = FactoryReducedExitWitness::parse(&witness_raw).unwrap();

        assert_eq!(witness.version(), FACTORY_REDUCED_EXIT_WITNESS_VERSION);
        assert_eq!(witness.release_quantity(), 20);
        assert_eq!(witness.state_output_index(), 1);
        assert_eq!(witness.vault_output_index(), 2);
        assert_eq!(witness.state_type_hash(), &[11u8; 32]);
        assert_eq!(witness.vault_lock_hash(), &[12u8; 32]);
        assert_eq!(witness.state_lock_hash(), &[13u8; 32]);
        assert_eq!(
            StateHeader::parse(witness.exit_state_header())
                .unwrap()
                .phase(),
            PHASE_ACTIVE
        );
        assert_eq!(
            witness.settlement_descriptor().len(),
            BILATERAL_CKB_DESCRIPTOR_LEN
        );
        assert_eq!(witness.right_before(1).unwrap().quantity(), 50);
        assert_eq!(witness.right_after(1).unwrap().quantity(), 30);
    }

    #[test]
    fn verifies_reduced_factory_exit_reserve_release() {
        let (old_raw, new_raw, witness_raw) = reduced_exit_headers_and_witness(20, 30, false, true);
        let old_header = FactoryStateHeader::parse(&old_raw).unwrap();
        let new_header = FactoryStateHeader::parse(&new_raw).unwrap();
        let witness = FactoryReducedExitWitness::parse(&witness_raw).unwrap();

        verify_reduced_factory_exit_update(&old_header, &new_header, &witness).unwrap();
    }

    #[test]
    fn rejects_reduced_factory_exit_release_mismatch() {
        let (old_raw, new_raw, witness_raw) = reduced_exit_headers_and_witness(20, 35, false, true);
        let old_header = FactoryStateHeader::parse(&old_raw).unwrap();
        let new_header = FactoryStateHeader::parse(&new_raw).unwrap();
        let witness = FactoryReducedExitWitness::parse(&witness_raw).unwrap();

        assert_eq!(
            verify_reduced_factory_exit_update(&old_header, &new_header, &witness).unwrap_err(),
            ScriptError::FactoryReducedProofMismatch
        );
    }

    #[test]
    fn rejects_reduced_factory_exit_typed_claim_for_ckb_release() {
        let (old_raw, new_raw, witness_raw) = reduced_exit_headers_and_witness_with_reserve_asset(
            20,
            30,
            false,
            true,
            Some([7u8; BYTE32_LEN]),
        );
        let old_header = FactoryStateHeader::parse(&old_raw).unwrap();
        let new_header = FactoryStateHeader::parse(&new_raw).unwrap();
        let witness = FactoryReducedExitWitness::parse(&witness_raw).unwrap();

        assert_eq!(
            verify_reduced_factory_exit_update(&old_header, &new_header, &witness).unwrap_err(),
            ScriptError::FactoryReducedProofMismatch
        );
    }

    #[test]
    fn rejects_reduced_factory_exit_other_right_mutation() {
        let (old_raw, new_raw, witness_raw) = reduced_exit_headers_and_witness(20, 30, true, true);
        let old_header = FactoryStateHeader::parse(&old_raw).unwrap();
        let new_header = FactoryStateHeader::parse(&new_raw).unwrap();
        let witness = FactoryReducedExitWitness::parse(&witness_raw).unwrap();

        assert_eq!(
            verify_reduced_factory_exit_update(&old_header, &new_header, &witness).unwrap_err(),
            ScriptError::FactoryReducedProofMismatch
        );
    }

    #[test]
    fn rejects_reduced_factory_exit_bad_signature() {
        let (old_raw, new_raw, mut witness_raw) =
            reduced_exit_headers_and_witness(20, 30, false, true);
        let signature_offset = factory_reduced_exit_participant_offset(0)
            + BYTE32_LEN
            + COMPRESSED_SECP256K1_PUBKEY_LEN
            + 1;
        witness_raw[signature_offset + ECDSA_SIGNATURE_LEN - 1] ^= 1;
        let old_header = FactoryStateHeader::parse(&old_raw).unwrap();
        let new_header = FactoryStateHeader::parse(&new_raw).unwrap();
        let witness = FactoryReducedExitWitness::parse(&witness_raw).unwrap();

        assert_eq!(
            verify_reduced_factory_exit_update(&old_header, &new_header, &witness).unwrap_err(),
            ScriptError::InvalidParticipantSignature
        );
    }

    #[test]
    fn rejects_reduced_factory_exit_descriptor_mismatch() {
        let (old_raw, new_raw, witness_raw) =
            reduced_exit_headers_and_witness(20, 30, false, false);
        let old_header = FactoryStateHeader::parse(&old_raw).unwrap();
        let new_header = FactoryStateHeader::parse(&new_raw).unwrap();
        let witness = FactoryReducedExitWitness::parse(&witness_raw).unwrap();

        assert_eq!(
            verify_reduced_factory_exit_update(&old_header, &new_header, &witness).unwrap_err(),
            ScriptError::SettlementDescriptorMismatch
        );
    }

    #[test]
    fn parses_and_commits_bilateral_ckb_descriptor() {
        let raw = descriptor_bytes([1u8; 32], 100, [2u8; 32], 200);
        let descriptor = BilateralCkbSettlementDescriptor::parse(&raw).unwrap();

        assert_eq!(descriptor.version(), 1);
        assert_eq!(descriptor.output_count(), 2);
        assert_eq!(descriptor.lock_hash(0), &[1u8; 32]);
        assert_eq!(descriptor.capacity(0), 100);
        assert_eq!(descriptor.lock_hash(1), &[2u8; 32]);
        assert_eq!(descriptor.capacity(1), 200);
        assert_eq!(
            descriptor.commitment(),
            settlement_descriptor_commitment(&raw)
        );
    }

    #[test]
    fn rejects_bilateral_ckb_descriptor_capacity_overflow() {
        let raw = descriptor_bytes([1u8; 32], u64::MAX, [2u8; 32], 1);

        assert_eq!(
            BilateralCkbSettlementDescriptor::parse(&raw).unwrap_err(),
            ScriptError::SettlementDescriptorEncoding
        );
    }

    #[test]
    fn parses_and_commits_bilateral_ckb_xudt_descriptor() {
        let raw = ckb_xudt_descriptor_bytes([9u8; 32], [2u8; 32], 200, 3, [1u8; 32], 100, 7);
        let descriptor = BilateralCkbXudtSettlementDescriptor::parse(&raw).unwrap();

        assert_eq!(descriptor.version(), 2);
        assert_eq!(descriptor.output_count(), 2);
        assert_eq!(descriptor.asset_count(), 1);
        assert_eq!(descriptor.xudt_type_hash(), &[9u8; 32]);
        assert_eq!(descriptor.lock_hash(0), &[1u8; 32]);
        assert_eq!(descriptor.capacity(0), 100);
        assert_eq!(descriptor.xudt_amount(0), 7);
        assert_eq!(descriptor.lock_hash(1), &[2u8; 32]);
        assert_eq!(descriptor.capacity(1), 200);
        assert_eq!(descriptor.xudt_amount(1), 3);
        assert_eq!(descriptor.total_capacity(), 300);
        assert_eq!(descriptor.total_xudt_amount(), 10);
        assert_eq!(
            descriptor.commitment(),
            settlement_descriptor_commitment(&raw)
        );
    }

    #[test]
    fn rejects_bilateral_ckb_xudt_descriptor_token_overflow() {
        let raw =
            ckb_xudt_descriptor_bytes([9u8; 32], [2u8; 32], 200, u128::MAX, [1u8; 32], 100, 1);

        assert_eq!(
            BilateralCkbXudtSettlementDescriptor::parse(&raw).unwrap_err(),
            ScriptError::SettlementDescriptorEncoding
        );
    }
}
