#![no_std]

use ckb_hash::new_blake2b;
use k256::ecdsa::signature::hazmat::PrehashVerifier;
use k256::ecdsa::{Signature, VerifyingKey};

pub const BYTE32_LEN: usize = 32;
pub const STATE_HEADER_V1_LEN: usize = 274;
pub const STATE_HEADER_V2_LEN: usize = 314;
pub const FACTORY_STATE_HEADER_V1_LEN: usize = 238;
pub const SPONSOR_POLICY_V1_LEN: usize = 144;
pub const SPLICE_HEADER_V1_LEN: usize = 325;
pub const BILATERAL_CKB_DESCRIPTOR_V1_LEN: usize = 2 + 1 + 1 + 2 * (BYTE32_LEN + 8);
pub const BILATERAL_CKB_XUDT_DESCRIPTOR_V1_LEN: usize =
    2 + 1 + 1 + BYTE32_LEN + 2 * (BYTE32_LEN + 8 + 16);
pub const COMPRESSED_SECP256K1_PUBKEY_LEN: usize = 33;
pub const ECDSA_SIGNATURE_LEN: usize = 64;
pub const BILATERAL_SIGNATURE_WITNESS_V1_LEN: usize =
    2 + 1 + 1 + (2 * (COMPRESSED_SECP256K1_PUBKEY_LEN + ECDSA_SIGNATURE_LEN));
pub const SPLICE_SIGNATURE_WITNESS_V1_LEN: usize =
    2 + 1 + 1 + (2 * (COMPRESSED_SECP256K1_PUBKEY_LEN + ECDSA_SIGNATURE_LEN));
pub const FACTORY_SIGNATURE_WITNESS_V1_LEN: usize =
    2 + 1 + 1 + (2 * (BYTE32_LEN + COMPRESSED_SECP256K1_PUBKEY_LEN + ECDSA_SIGNATURE_LEN));
pub const FACTORY_RIGHT_V1_LEN: usize = BYTE32_LEN + BYTE32_LEN + 1 + 1 + BYTE32_LEN + 16;
pub const SPLICE_VAULT_ASSET_AMOUNT_V2_LEN: usize = 1 + BYTE32_LEN + 16;
pub const SPLICE_VAULT_DESCRIPTOR_V2_MAX_ASSETS: u8 = 2;
pub const SPLICE_VAULT_DESCRIPTOR_V2_LEN: usize =
    BYTE32_LEN + 2 + 2 * SPLICE_VAULT_ASSET_AMOUNT_V2_LEN;
pub const SPLICE_ASSET_DELTA_V1_LEN: usize = 1 + BYTE32_LEN + 5 * 16;
pub const SPLICE_ASSET_DELTAS_V1_MAX_DELTAS: u8 = 2;
pub const SPLICE_ASSET_DELTAS_V1_LEN: usize = 2 + 2 * SPLICE_ASSET_DELTA_V1_LEN;
pub const SPLICE_STATE_TRANSITION_WITNESS_V1_LEN: usize = 2
    + SPLICE_HEADER_V1_LEN
    + SPLICE_SIGNATURE_WITNESS_V1_LEN
    + 2 * SPLICE_VAULT_DESCRIPTOR_V2_LEN
    + SPLICE_ASSET_DELTAS_V1_LEN;
pub const FACTORY_REDUCED_RIGHTS_PARTICIPANT_ENTRY_V1_LEN: usize =
    BYTE32_LEN + COMPRESSED_SECP256K1_PUBKEY_LEN + 1 + ECDSA_SIGNATURE_LEN;
pub const FACTORY_REDUCED_RIGHTS_COUNT_V1: u8 = 10;
pub const FACTORY_MERKLE_UPDATE_RIGHT_COUNT_V1: u8 = 1;
pub const FACTORY_SPARSE_MERKLE_DEPTH_V1: usize = 256;
pub const FACTORY_REDUCED_RIGHTS_WITNESS_V1_LEN: usize = 8
    + 2 * FACTORY_REDUCED_RIGHTS_PARTICIPANT_ENTRY_V1_LEN
    + BYTE32_LEN
    + 2 * FACTORY_REDUCED_RIGHTS_COUNT_V1 as usize * FACTORY_RIGHT_V1_LEN;
pub const FACTORY_MERKLE_UPDATE_WITNESS_V1_LEN: usize = 8
    + 2 * FACTORY_REDUCED_RIGHTS_PARTICIPANT_ENTRY_V1_LEN
    + BYTE32_LEN
    + 2 * FACTORY_RIGHT_V1_LEN
    + FACTORY_SPARSE_MERKLE_DEPTH_V1 * BYTE32_LEN;
pub const FACTORY_REDUCED_EXIT_COMMON_V1_LEN: usize = 8
    + 2 * FACTORY_REDUCED_RIGHTS_PARTICIPANT_ENTRY_V1_LEN
    + BYTE32_LEN
    + 16
    + 4
    + 4
    + BYTE32_LEN
    + BYTE32_LEN
    + BYTE32_LEN
    + STATE_HEADER_V1_LEN;
pub const FACTORY_REDUCED_EXIT_WITNESS_V1_LEN: usize = FACTORY_REDUCED_EXIT_COMMON_V1_LEN
    + BILATERAL_CKB_DESCRIPTOR_V1_LEN
    + 2 * FACTORY_REDUCED_RIGHTS_COUNT_V1 as usize * FACTORY_RIGHT_V1_LEN;
pub const FACTORY_REDUCED_EXIT_XUDT_WITNESS_V1_LEN: usize = FACTORY_REDUCED_EXIT_COMMON_V1_LEN
    + BILATERAL_CKB_XUDT_DESCRIPTOR_V1_LEN
    + 2 * FACTORY_REDUCED_RIGHTS_COUNT_V1 as usize * FACTORY_RIGHT_V1_LEN;
pub const FACTORY_LOCAL_EXIT_WITNESS_V1_LEN: usize = 2
    + FACTORY_SIGNATURE_WITNESS_V1_LEN
    + 4
    + 4
    + BYTE32_LEN
    + BYTE32_LEN
    + BYTE32_LEN
    + STATE_HEADER_V1_LEN
    + BILATERAL_CKB_DESCRIPTOR_V1_LEN;
pub const FACTORY_LOCAL_EXIT_XUDT_WITNESS_V1_LEN: usize = 2
    + FACTORY_SIGNATURE_WITNESS_V1_LEN
    + 4
    + 4
    + BYTE32_LEN
    + BYTE32_LEN
    + BYTE32_LEN
    + STATE_HEADER_V1_LEN
    + BILATERAL_CKB_XUDT_DESCRIPTOR_V1_LEN;
pub const FACTORY_SPLICE_HEADER_V1_LEN: usize = 275;
pub const FACTORY_VAULT_ASSET_AMOUNT_V1_LEN: usize = 1 + BYTE32_LEN + 16;
pub const FACTORY_VAULT_DESCRIPTOR_V1_MAX_ASSETS: u8 = 2;
pub const FACTORY_VAULT_DESCRIPTOR_V1_LEN: usize =
    BYTE32_LEN + 2 + 2 * FACTORY_VAULT_ASSET_AMOUNT_V1_LEN;
pub const FACTORY_VAULT_DELTA_V1_LEN: usize = 1 + BYTE32_LEN + 4 * 16;
pub const FACTORY_VAULT_DELTAS_V1_MAX_DELTAS: u8 = 2;
pub const FACTORY_VAULT_DELTAS_V1_LEN: usize = 2 + 2 * FACTORY_VAULT_DELTA_V1_LEN;
pub const FACTORY_SPLICE_WITNESS_V1_LEN: usize = 2
    + FACTORY_SPLICE_HEADER_V1_LEN
    + FACTORY_SIGNATURE_WITNESS_V1_LEN
    + 2 * FACTORY_VAULT_DESCRIPTOR_V1_LEN
    + FACTORY_VAULT_DELTAS_V1_LEN;
pub const FACTORY_REDUCED_SPLICE_WITNESS_V1_LEN: usize = 2
    + FACTORY_SPLICE_HEADER_V1_LEN
    + FACTORY_MERKLE_UPDATE_WITNESS_V1_LEN
    + 2 * FACTORY_VAULT_DESCRIPTOR_V1_LEN
    + FACTORY_VAULT_DELTAS_V1_LEN;

pub const PHASE_ACTIVE: u8 = 1;
pub const PHASE_SETTLING: u8 = 2;
pub const SIGNATURE_SCHEME_SECP256K1_ECDSA_BLAKE2B_V1: u16 = 1;
pub const BILATERAL_SIGNATURE_WITNESS_VERSION_V1: u16 = 1;
pub const BILATERAL_SIGNATURE_THRESHOLD_V1: u8 = 2;
pub const BILATERAL_SIGNATURE_COUNT_V1: u8 = 2;
pub const SPLICE_SIGNATURE_WITNESS_VERSION_V1: u16 = 1;
pub const SPLICE_SIGNATURE_THRESHOLD_V1: u8 = 2;
pub const SPLICE_SIGNATURE_COUNT_V1: u8 = 2;
pub const SPLICE_STATE_TRANSITION_WITNESS_VERSION_V1: u16 = 1;
pub const FACTORY_SIGNATURE_WITNESS_VERSION_V1: u16 = 1;
pub const FACTORY_SIGNATURE_THRESHOLD_V1: u8 = 2;
pub const FACTORY_SIGNATURE_COUNT_V1: u8 = 2;
pub const FACTORY_REDUCED_RIGHTS_WITNESS_VERSION_V1: u16 = 2;
pub const FACTORY_REDUCED_RIGHTS_PARTICIPANT_THRESHOLD_V1: u8 = 2;
pub const FACTORY_REDUCED_RIGHTS_PARTICIPANT_COUNT_V1: u8 = 2;
pub const FACTORY_REDUCED_RIGHTS_AUTHORISED_COUNT_V1: u8 = 1;
pub const FACTORY_REDUCED_EXIT_WITNESS_VERSION_V1: u16 = 3;
pub const FACTORY_MERKLE_UPDATE_WITNESS_VERSION_V1: u16 = 4;
pub const FACTORY_RIGHT_KIND_RESERVE_CLAIM: u8 = 1;
pub const FACTORY_LOCAL_EXIT_WITNESS_VERSION_V1: u16 = 1;
pub const FACTORY_SPLICE_WITNESS_VERSION_V1: u16 = 1;
pub const FACTORY_REDUCED_SPLICE_WITNESS_VERSION_V1: u16 = 5;
pub const STATE_DOMAIN_V1: &[u8] = b"CKB_MORPH_CHANNEL_STATE_V1";
pub const STATE_DOMAIN_V2: &[u8] = b"CKB_MORPH_CHANNEL_STATE_V2";
pub const SPLICE_HEADER_DOMAIN_V1: &[u8] = b"CKB_MORPH_SPLICE_HEADER_V1";
pub const SPLICE_DELTA_DOMAIN_V1: &[u8] = b"CKB_MORPH_SPLICE_DELTA_V1";
pub const VAULT_DESCRIPTOR_DOMAIN_V2: &[u8] = b"CKB_MORPH_VAULT_DESCRIPTOR_V2";
pub const FACTORY_SPLICE_HEADER_DOMAIN_V1: &[u8] = b"CKB_MORPH_FACTORY_SPLICE_HEADER_V1";
pub const FACTORY_VAULT_DESCRIPTOR_DOMAIN_V1: &[u8] = b"CKB_MORPH_FACTORY_VAULT_DESCRIPTOR_V1";
pub const FACTORY_VAULT_DELTA_DOMAIN_V1: &[u8] = b"CKB_MORPH_FACTORY_VAULT_DELTA_V1";
pub const PARTICIPANTS_DOMAIN_V1: &[u8] = b"CKB_MORPH_PARTICIPANTS_V1";
pub const FACTORY_STATE_DOMAIN_V1: &[u8] = b"CKB_MORPH_FACTORY_STATE_V1";
pub const FACTORY_PARTICIPANTS_DOMAIN_V1: &[u8] = b"CKB_MORPH_FACTORY_PARTICIPANTS_V1";
pub const FACTORY_RIGHTS_ROOT_DOMAIN_V1: &[u8] = b"CKB_MORPH_FACTORY_RIGHTS_ROOT_V1";
pub const FACTORY_ACCESS_MANIFEST_ROOT_DOMAIN_V1: &[u8] =
    b"CKB_MORPH_FACTORY_ACCESS_MANIFEST_ROOT_V1";
pub const FACTORY_REDUCED_RIGHTS_DOMAIN_V1: &[u8] = b"CKB_MORPH_FACTORY_REDUCED_RIGHTS_V1";
pub const FACTORY_REDUCED_EXIT_DOMAIN_V1: &[u8] = b"CKB_MORPH_FACTORY_REDUCED_EXIT_V1";
pub const FACTORY_MERKLE_UPDATE_DOMAIN_V1: &[u8] = b"CKB_MORPH_FACTORY_MERKLE_UPDATE_V1";
pub const FACTORY_RIGHT_KEY_DOMAIN_V1: &[u8] = b"CKB_MORPH_FACTORY_RIGHT_KEY_V1";
pub const FACTORY_RIGHT_LEAF_DOMAIN_V1: &[u8] = b"CKB_MORPH_FACTORY_RIGHT_LEAF_V1";
pub const FACTORY_RIGHT_NODE_DOMAIN_V1: &[u8] = b"CKB_MORPH_FACTORY_RIGHT_NODE_V1";
pub const FACTORY_LOCAL_EXIT_DOMAIN_V1: &[u8] = b"CKB_MORPH_FACTORY_LOCAL_EXIT_V1";
pub const SETTLEMENT_DESCRIPTOR_DOMAIN_V1: &[u8] = b"CKB_MORPH_SETTLEMENT_DESCRIPTOR_V1";
pub const BILATERAL_CKB_DESCRIPTOR_VERSION_V1: u16 = 1;
pub const BILATERAL_CKB_XUDT_DESCRIPTOR_VERSION_V1: u16 = 2;
pub const BILATERAL_CKB_DESCRIPTOR_OUTPUT_COUNT_V1: u8 = 2;
pub const BILATERAL_CKB_XUDT_DESCRIPTOR_ASSET_COUNT_V1: u8 = 1;
pub const SPLICE_KIND_IN_V1: u8 = 0;
pub const SPLICE_KIND_OUT_V1: u8 = 1;
pub const VAULT_ASSET_KIND_CKB_V1: u8 = 0;
pub const VAULT_ASSET_KIND_XUDT_V1: u8 = 1;

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
}

pub type Result<T> = core::result::Result<T, ScriptError>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StateHeaderV1<'a> {
    raw: &'a [u8],
}

impl<'a> StateHeaderV1<'a> {
    pub fn parse(raw: &'a [u8]) -> Result<Self> {
        if raw.len() != STATE_HEADER_V1_LEN {
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

    pub fn funding_anchor(&self) -> &'a [u8] {
        field(self.raw, 68, 32)
    }

    pub fn state_number(&self) -> u64 {
        read_u64(self.raw, 100)
    }

    pub fn mode(&self) -> u8 {
        self.raw[108]
    }

    pub fn phase(&self) -> u8 {
        self.raw[109]
    }

    pub fn participants_commitment(&self) -> &'a [u8] {
        field(self.raw, 110, 32)
    }

    pub fn asset_registry_commitment(&self) -> &'a [u8] {
        field(self.raw, 142, 32)
    }

    pub fn settlement_descriptor_commitment(&self) -> &'a [u8] {
        field(self.raw, 174, 32)
    }

    pub fn descriptor_version(&self) -> u16 {
        read_u16(self.raw, 206)
    }

    pub fn payload_commitment(&self) -> &'a [u8] {
        field(self.raw, 208, 32)
    }

    pub fn challenge_policy_commitment(&self) -> &'a [u8] {
        field(self.raw, 240, 32)
    }

    pub fn state_layout_version(&self) -> u16 {
        read_u16(self.raw, 272)
    }

    pub fn signing_digest(&self) -> [u8; 32] {
        blake2b256(&[STATE_DOMAIN_V1, self.raw])
    }

    pub fn same_context_except_progress(&self, next: &Self) -> bool {
        self.protocol_version() == next.protocol_version()
            && self.chain_id() == next.chain_id()
            && self.signature_scheme_id() == next.signature_scheme_id()
            && self.channel_id() == next.channel_id()
            && self.funding_anchor() == next.funding_anchor()
            && self.mode() == next.mode()
            && self.participants_commitment() == next.participants_commitment()
            && self.asset_registry_commitment() == next.asset_registry_commitment()
            && self.challenge_policy_commitment() == next.challenge_policy_commitment()
            && self.state_layout_version() == next.state_layout_version()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StateHeaderV2<'a> {
    raw: &'a [u8],
}

impl<'a> StateHeaderV2<'a> {
    pub fn parse(raw: &'a [u8]) -> Result<Self> {
        if raw.len() != STATE_HEADER_V2_LEN {
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
        blake2b256(&[STATE_DOMAIN_V2, self.raw])
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
pub struct FactoryStateHeaderV1<'a> {
    raw: &'a [u8],
}

impl<'a> FactoryStateHeaderV1<'a> {
    pub fn parse(raw: &'a [u8]) -> Result<Self> {
        if raw.len() != FACTORY_STATE_HEADER_V1_LEN {
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
        blake2b256(&[FACTORY_STATE_DOMAIN_V1, self.raw])
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
pub struct SpliceHeaderV1<'a> {
    raw: &'a [u8],
}

impl<'a> SpliceHeaderV1<'a> {
    pub fn parse(raw: &'a [u8]) -> Result<Self> {
        if raw.len() != SPLICE_HEADER_V1_LEN {
            return Err(ScriptError::Encoding);
        }
        let header = Self { raw };
        if header.kind() != SPLICE_KIND_IN_V1 && header.kind() != SPLICE_KIND_OUT_V1 {
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

    pub fn challenge_policy_commitment(&self) -> &'a [u8] {
        field(self.raw, 293, BYTE32_LEN)
    }

    pub fn signing_digest(&self) -> [u8; 32] {
        blake2b256(&[SPLICE_HEADER_DOMAIN_V1, self.raw])
    }

    pub fn matches_current_state(&self, current: &StateHeaderV1) -> bool {
        self.protocol_version() == current.protocol_version()
            && self.chain_id() == current.chain_id()
            && self.signature_scheme_id() == current.signature_scheme_id()
            && self.channel_id() == current.channel_id()
            && self.old_funding_anchor() == current.funding_anchor()
            && self.base_state_number() == current.state_number()
            && self.participants_commitment() == current.participants_commitment()
            && self.challenge_policy_commitment() == current.challenge_policy_commitment()
    }

    pub fn matches_current_state_v2(&self, current: &StateHeaderV2) -> bool {
        self.protocol_version() == current.protocol_version()
            && self.chain_id() == current.chain_id()
            && self.signature_scheme_id() == current.signature_scheme_id()
            && self.channel_id() == current.channel_id()
            && self.old_funding_epoch() == current.funding_epoch()
            && self.old_funding_anchor() == current.funding_anchor()
            && self.old_vault_commitment() == current.vault_set_commitment()
            && self.base_state_number() == current.state_number()
            && self.participants_commitment() == current.participants_commitment()
            && self.challenge_policy_commitment() == current.challenge_policy_commitment()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BilateralSignatureWitnessV1<'a> {
    raw: &'a [u8],
}

impl<'a> BilateralSignatureWitnessV1<'a> {
    pub fn parse(raw: &'a [u8]) -> Result<Self> {
        if raw.len() != BILATERAL_SIGNATURE_WITNESS_V1_LEN {
            return Err(ScriptError::ParticipantWitnessEncoding);
        }
        let witness = Self { raw };
        if witness.version() != BILATERAL_SIGNATURE_WITNESS_VERSION_V1
            || witness.threshold() != BILATERAL_SIGNATURE_THRESHOLD_V1
            || witness.count() != BILATERAL_SIGNATURE_COUNT_V1
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
        participants_commitment_v1(self.threshold(), &[self.pubkey(0), self.pubkey(1)])
    }
}

pub fn verify_bilateral_state_signatures(
    header: &StateHeaderV1,
    witness: &BilateralSignatureWitnessV1,
) -> Result<()> {
    if header.signature_scheme_id() != SIGNATURE_SCHEME_SECP256K1_ECDSA_BLAKE2B_V1 {
        return Err(ScriptError::ParticipantWitnessEncoding);
    }
    if header.participants_commitment() != witness.participants_commitment().as_slice() {
        return Err(ScriptError::ParticipantCommitmentMismatch);
    }

    let digest = header.signing_digest();
    for index in 0..BILATERAL_SIGNATURE_COUNT_V1 as usize {
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
pub struct SpliceSignatureWitnessV1<'a> {
    raw: &'a [u8],
}

impl<'a> SpliceSignatureWitnessV1<'a> {
    pub fn parse(raw: &'a [u8]) -> Result<Self> {
        if raw.len() != SPLICE_SIGNATURE_WITNESS_V1_LEN {
            return Err(ScriptError::ParticipantWitnessEncoding);
        }
        let witness = Self { raw };
        if witness.version() != SPLICE_SIGNATURE_WITNESS_VERSION_V1
            || witness.threshold() != SPLICE_SIGNATURE_THRESHOLD_V1
            || witness.count() != SPLICE_SIGNATURE_COUNT_V1
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
        participants_commitment_v1(self.threshold(), &[self.pubkey(0), self.pubkey(1)])
    }
}

pub fn verify_splice_signatures(
    header: &SpliceHeaderV1,
    witness: &SpliceSignatureWitnessV1,
) -> Result<()> {
    if header.signature_scheme_id() != SIGNATURE_SCHEME_SECP256K1_ECDSA_BLAKE2B_V1 {
        return Err(ScriptError::ParticipantWitnessEncoding);
    }
    if header.participants_commitment() != witness.participants_commitment().as_slice() {
        return Err(ScriptError::ParticipantCommitmentMismatch);
    }

    let digest = header.signing_digest();
    for index in 0..SPLICE_SIGNATURE_COUNT_V1 as usize {
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
    current_state: &StateHeaderV1,
    next_state: &StateHeaderV1,
    splice_header: &SpliceHeaderV1,
    witness: &SpliceSignatureWitnessV1,
    old_vault: &SpliceVaultDescriptorV2,
    new_vault: &SpliceVaultDescriptorV2,
    deltas: &SpliceAssetDeltasV1,
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

pub fn verify_splice_state_transition_v2(
    current_state: &StateHeaderV2,
    next_state: &StateHeaderV2,
    splice_header: &SpliceHeaderV1,
    witness: &SpliceSignatureWitnessV1,
    old_vault: &SpliceVaultDescriptorV2,
    new_vault: &SpliceVaultDescriptorV2,
    deltas: &SpliceAssetDeltasV1,
) -> Result<()> {
    if current_state.phase() != PHASE_ACTIVE || next_state.phase() != PHASE_ACTIVE {
        return Err(ScriptError::SpliceProofMismatch);
    }
    if !splice_header.matches_current_state_v2(current_state) {
        return Err(ScriptError::SpliceProofMismatch);
    }
    if !state_context_matches_splice_next_v2(current_state, next_state, splice_header) {
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
pub struct SpliceStateTransitionWitnessV1<'a> {
    raw: &'a [u8],
}

impl<'a> SpliceStateTransitionWitnessV1<'a> {
    pub fn parse(raw: &'a [u8]) -> Result<Self> {
        if raw.len() != SPLICE_STATE_TRANSITION_WITNESS_V1_LEN {
            return Err(ScriptError::SpliceProofEncoding);
        }
        let witness = Self { raw };
        if witness.version() != SPLICE_STATE_TRANSITION_WITNESS_VERSION_V1 {
            return Err(ScriptError::SpliceProofEncoding);
        }
        Ok(witness)
    }

    pub fn version(&self) -> u16 {
        read_u16(self.raw, 0)
    }

    pub fn header(&self) -> Result<SpliceHeaderV1<'a>> {
        SpliceHeaderV1::parse(field(
            self.raw,
            splice_transition_header_offset(),
            SPLICE_HEADER_V1_LEN,
        ))
        .map_err(|_| ScriptError::SpliceProofEncoding)
    }

    pub fn signatures(&self) -> Result<SpliceSignatureWitnessV1<'a>> {
        SpliceSignatureWitnessV1::parse(field(
            self.raw,
            splice_transition_signature_offset(),
            SPLICE_SIGNATURE_WITNESS_V1_LEN,
        ))
        .map_err(|_| ScriptError::SpliceProofEncoding)
    }

    pub fn old_vault(&self) -> Result<SpliceVaultDescriptorV2<'a>> {
        SpliceVaultDescriptorV2::parse(field(
            self.raw,
            splice_transition_old_vault_offset(),
            SPLICE_VAULT_DESCRIPTOR_V2_LEN,
        ))
        .map_err(|_| ScriptError::SpliceProofEncoding)
    }

    pub fn new_vault(&self) -> Result<SpliceVaultDescriptorV2<'a>> {
        SpliceVaultDescriptorV2::parse(field(
            self.raw,
            splice_transition_new_vault_offset(),
            SPLICE_VAULT_DESCRIPTOR_V2_LEN,
        ))
        .map_err(|_| ScriptError::SpliceProofEncoding)
    }

    pub fn deltas(&self) -> Result<SpliceAssetDeltasV1<'a>> {
        SpliceAssetDeltasV1::parse(field(
            self.raw,
            splice_transition_deltas_offset(),
            SPLICE_ASSET_DELTAS_V1_LEN,
        ))
        .map_err(|_| ScriptError::SpliceProofEncoding)
    }

    pub fn raw(&self) -> &'a [u8] {
        self.raw
    }
}

pub fn verify_splice_state_transition_bundle(
    current_state: &StateHeaderV1,
    next_state: &StateHeaderV1,
    witness: &SpliceStateTransitionWitnessV1,
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

pub fn verify_splice_state_transition_bundle_v2(
    current_state: &StateHeaderV2,
    next_state: &StateHeaderV2,
    witness: &SpliceStateTransitionWitnessV1,
) -> Result<()> {
    let splice_header = witness.header()?;
    let signatures = witness.signatures()?;
    let old_vault = witness.old_vault()?;
    let new_vault = witness.new_vault()?;
    let deltas = witness.deltas()?;
    verify_splice_state_transition_v2(
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
    current_state: &StateHeaderV1,
    next_state: &StateHeaderV1,
    splice_header: &SpliceHeaderV1,
) -> bool {
    current_state.protocol_version() == next_state.protocol_version()
        && current_state.chain_id() == next_state.chain_id()
        && current_state.signature_scheme_id() == next_state.signature_scheme_id()
        && current_state.channel_id() == next_state.channel_id()
        && next_state.funding_anchor() == splice_header.new_funding_anchor()
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

fn state_context_matches_splice_next_v2(
    current_state: &StateHeaderV2,
    next_state: &StateHeaderV2,
    splice_header: &SpliceHeaderV1,
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
    old_vault: &SpliceVaultDescriptorV2,
    new_vault: &SpliceVaultDescriptorV2,
    deltas: &SpliceAssetDeltasV1,
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

fn verify_splice_delta(kind: u8, delta: &SpliceAssetDeltaV1) -> Result<()> {
    if delta.asset_kind() == VAULT_ASSET_KIND_XUDT_V1 && delta.signed_fee() != 0 {
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
        SPLICE_KIND_IN_V1 => {
            if delta.external_input() == 0
                || delta.withdrawal() != 0
                || delta.new_amount() <= delta.old_amount()
            {
                return Err(ScriptError::SpliceProofMismatch);
            }
        }
        SPLICE_KIND_OUT_V1 => {
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
    descriptor: &SpliceVaultDescriptorV2,
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
    deltas: &SpliceAssetDeltasV1,
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
pub struct FactorySignatureWitnessV1<'a> {
    raw: &'a [u8],
}

impl<'a> FactorySignatureWitnessV1<'a> {
    pub fn parse(raw: &'a [u8]) -> Result<Self> {
        if raw.len() != FACTORY_SIGNATURE_WITNESS_V1_LEN {
            return Err(ScriptError::ParticipantWitnessEncoding);
        }
        let witness = Self { raw };
        if witness.version() != FACTORY_SIGNATURE_WITNESS_VERSION_V1
            || witness.threshold() != FACTORY_SIGNATURE_THRESHOLD_V1
            || witness.count() != FACTORY_SIGNATURE_COUNT_V1
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
        factory_participants_commitment_v1(
            self.threshold(),
            &[
                (self.participant(0), self.pubkey(0)),
                (self.participant(1), self.pubkey(1)),
            ],
        )
    }

    pub fn pubkey_participants_commitment(&self) -> [u8; 32] {
        participants_commitment_v1(self.threshold(), &[self.pubkey(0), self.pubkey(1)])
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FactoryRightV1<'a> {
    raw: &'a [u8],
}

impl<'a> FactoryRightV1<'a> {
    pub fn parse(raw: &'a [u8]) -> Result<Self> {
        if raw.len() != FACTORY_RIGHT_V1_LEN {
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
pub struct FactoryReducedRightsWitnessV1<'a> {
    raw: &'a [u8],
}

impl<'a> FactoryReducedRightsWitnessV1<'a> {
    pub fn parse(raw: &'a [u8]) -> Result<Self> {
        if raw.len() != FACTORY_REDUCED_RIGHTS_WITNESS_V1_LEN {
            return Err(ScriptError::FactoryReducedProofEncoding);
        }
        let witness = Self { raw };
        if witness.version() != FACTORY_REDUCED_RIGHTS_WITNESS_VERSION_V1
            || witness.participant_threshold() != FACTORY_REDUCED_RIGHTS_PARTICIPANT_THRESHOLD_V1
            || witness.participant_count() != FACTORY_REDUCED_RIGHTS_PARTICIPANT_COUNT_V1
            || witness.authorised_count() != FACTORY_REDUCED_RIGHTS_AUTHORISED_COUNT_V1
            || witness.right_count() != FACTORY_REDUCED_RIGHTS_COUNT_V1
            || read_u16(raw, 6) != 0
        {
            return Err(ScriptError::FactoryReducedProofEncoding);
        }
        if witness.participant(0) >= witness.participant(1)
            || witness.pubkey(0) == witness.pubkey(1)
        {
            return Err(ScriptError::FactoryReducedProofEncoding);
        }
        if witness.signed_count() != FACTORY_REDUCED_RIGHTS_AUTHORISED_COUNT_V1 {
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

    pub fn right_before(&self, index: usize) -> Result<FactoryRightV1<'a>> {
        FactoryRightV1::parse(field(
            self.raw,
            factory_reduced_right_offset(false, index),
            FACTORY_RIGHT_V1_LEN,
        ))
    }

    pub fn right_after(&self, index: usize) -> Result<FactoryRightV1<'a>> {
        FactoryRightV1::parse(field(
            self.raw,
            factory_reduced_right_offset(true, index),
            FACTORY_RIGHT_V1_LEN,
        ))
    }

    pub fn participants_commitment(&self) -> [u8; 32] {
        factory_participants_commitment_v1(
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
        hasher.update(FACTORY_RIGHTS_ROOT_DOMAIN_V1);
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
        hasher.update(FACTORY_ACCESS_MANIFEST_ROOT_DOMAIN_V1);
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
        old_header: &FactoryStateHeaderV1,
        new_header: &FactoryStateHeaderV1,
    ) -> Result<[u8; 32]> {
        let old_update_number = old_header.update_number().to_le_bytes();
        let new_update_number = new_header.update_number().to_le_bytes();
        let before_root = self.rights_root(false)?;
        let after_root = self.rights_root(true)?;
        let before_access_root = self.access_manifest_root(false)?;
        let after_access_root = self.access_manifest_root(true)?;
        Ok(blake2b256(&[
            FACTORY_REDUCED_RIGHTS_DOMAIN_V1,
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
        for index in 0..FACTORY_REDUCED_RIGHTS_PARTICIPANT_COUNT_V1 as usize {
            match self.signed_flag(index) {
                0 => {}
                1 => count = count.saturating_add(1),
                _ => return u8::MAX,
            }
        }
        count
    }

    fn validate_right_order(&self, after: bool) -> Result<()> {
        let mut previous: Option<FactoryRightV1> = None;
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
    old_header: &FactoryStateHeaderV1,
    new_header: &FactoryStateHeaderV1,
    witness: &FactoryReducedRightsWitnessV1,
) -> Result<()> {
    if new_header.signature_scheme_id() != SIGNATURE_SCHEME_SECP256K1_ECDSA_BLAKE2B_V1 {
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

fn validate_reduced_rights_non_interference(witness: &FactoryReducedRightsWitnessV1) -> Result<()> {
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

fn verify_reduced_rights_signature(
    header: &FactoryStateHeaderV1,
    witness: &FactoryReducedRightsWitnessV1,
) -> Result<()> {
    let digest = header.signing_digest();
    let mut matched = false;
    for index in 0..FACTORY_REDUCED_RIGHTS_PARTICIPANT_COUNT_V1 as usize {
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
pub struct FactoryMerkleUpdateWitnessV1<'a> {
    raw: &'a [u8],
}

impl<'a> FactoryMerkleUpdateWitnessV1<'a> {
    pub fn parse(raw: &'a [u8]) -> Result<Self> {
        if raw.len() != FACTORY_MERKLE_UPDATE_WITNESS_V1_LEN {
            return Err(ScriptError::FactoryReducedProofEncoding);
        }
        let witness = Self { raw };
        if witness.version() != FACTORY_MERKLE_UPDATE_WITNESS_VERSION_V1
            || witness.participant_threshold() != FACTORY_REDUCED_RIGHTS_PARTICIPANT_THRESHOLD_V1
            || witness.participant_count() != FACTORY_REDUCED_RIGHTS_PARTICIPANT_COUNT_V1
            || witness.authorised_count() != FACTORY_REDUCED_RIGHTS_AUTHORISED_COUNT_V1
            || witness.right_count() != FACTORY_MERKLE_UPDATE_RIGHT_COUNT_V1
            || read_u16(raw, 6) != 0
        {
            return Err(ScriptError::FactoryReducedProofEncoding);
        }
        if witness.participant(0) >= witness.participant(1)
            || witness.pubkey(0) == witness.pubkey(1)
        {
            return Err(ScriptError::FactoryReducedProofEncoding);
        }
        if witness.signed_count() != FACTORY_REDUCED_RIGHTS_AUTHORISED_COUNT_V1 {
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

    pub fn right_before(&self) -> Result<FactoryRightV1<'a>> {
        FactoryRightV1::parse(field(
            self.raw,
            factory_merkle_right_offset(false),
            FACTORY_RIGHT_V1_LEN,
        ))
    }

    pub fn right_after(&self) -> Result<FactoryRightV1<'a>> {
        FactoryRightV1::parse(field(
            self.raw,
            factory_merkle_right_offset(true),
            FACTORY_RIGHT_V1_LEN,
        ))
    }

    pub fn sibling_hash(&self, depth: usize) -> &'a [u8] {
        field(self.raw, factory_merkle_sibling_offset(depth), BYTE32_LEN)
    }

    pub fn participants_commitment(&self) -> [u8; 32] {
        factory_participants_commitment_v1(
            self.participant_threshold(),
            &[
                (self.participant(0), self.pubkey(0)),
                (self.participant(1), self.pubkey(1)),
            ],
        )
    }

    pub fn pubkey_participants_commitment(&self) -> [u8; 32] {
        participants_commitment_v1(
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
        for depth in (0..FACTORY_SPARSE_MERKLE_DEPTH_V1).rev() {
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
        old_header: &FactoryStateHeaderV1,
        new_header: &FactoryStateHeaderV1,
    ) -> Result<[u8; 32]> {
        let old_update_number = old_header.update_number().to_le_bytes();
        let new_update_number = new_header.update_number().to_le_bytes();
        Ok(blake2b256(&[
            FACTORY_MERKLE_UPDATE_DOMAIN_V1,
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
        for index in 0..FACTORY_REDUCED_RIGHTS_PARTICIPANT_COUNT_V1 as usize {
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
    old_header: &FactoryStateHeaderV1,
    new_header: &FactoryStateHeaderV1,
    witness: &FactoryMerkleUpdateWitnessV1,
) -> Result<()> {
    if new_header.signature_scheme_id() != SIGNATURE_SCHEME_SECP256K1_ECDSA_BLAKE2B_V1 {
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

fn verify_merkle_update_signature(
    header: &FactoryStateHeaderV1,
    witness: &FactoryMerkleUpdateWitnessV1,
) -> Result<()> {
    let digest = header.signing_digest();
    let mut matched = false;
    for index in 0..FACTORY_REDUCED_RIGHTS_PARTICIPANT_COUNT_V1 as usize {
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
pub struct FactoryReducedExitWitnessV1<'a> {
    raw: &'a [u8],
}

impl<'a> FactoryReducedExitWitnessV1<'a> {
    pub fn parse(raw: &'a [u8]) -> Result<Self> {
        if raw.len() != FACTORY_REDUCED_EXIT_WITNESS_V1_LEN
            && raw.len() != FACTORY_REDUCED_EXIT_XUDT_WITNESS_V1_LEN
        {
            return Err(ScriptError::FactoryReducedProofEncoding);
        }
        let witness = Self { raw };
        if witness.version() != FACTORY_REDUCED_EXIT_WITNESS_VERSION_V1
            || witness.participant_threshold() != FACTORY_REDUCED_RIGHTS_PARTICIPANT_THRESHOLD_V1
            || witness.participant_count() != FACTORY_REDUCED_RIGHTS_PARTICIPANT_COUNT_V1
            || witness.authorised_count() != FACTORY_REDUCED_RIGHTS_AUTHORISED_COUNT_V1
            || witness.right_count() != FACTORY_REDUCED_RIGHTS_COUNT_V1
            || read_u16(raw, 6) != 0
        {
            return Err(ScriptError::FactoryReducedProofEncoding);
        }
        if witness.participant(0) >= witness.participant(1)
            || witness.pubkey(0) == witness.pubkey(1)
        {
            return Err(ScriptError::FactoryReducedProofEncoding);
        }
        if witness.signed_count() != FACTORY_REDUCED_RIGHTS_AUTHORISED_COUNT_V1 {
            return Err(ScriptError::FactoryReducedProofEncoding);
        }
        StateHeaderV1::parse(witness.exit_state_header())?;
        match witness.settlement_descriptor().len() {
            BILATERAL_CKB_DESCRIPTOR_V1_LEN => {
                BilateralCkbSettlementDescriptorV1::parse(witness.settlement_descriptor())?;
            }
            BILATERAL_CKB_XUDT_DESCRIPTOR_V1_LEN => {
                BilateralCkbXudtSettlementDescriptorV1::parse(witness.settlement_descriptor())?;
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
            STATE_HEADER_V1_LEN,
        )
    }

    pub fn settlement_descriptor(&self) -> &'a [u8] {
        let offset = factory_reduced_exit_descriptor_offset();
        let len = if self.raw.len() == FACTORY_REDUCED_EXIT_WITNESS_V1_LEN {
            BILATERAL_CKB_DESCRIPTOR_V1_LEN
        } else {
            BILATERAL_CKB_XUDT_DESCRIPTOR_V1_LEN
        };
        field(self.raw, offset, len)
    }

    pub fn right_before(&self, index: usize) -> Result<FactoryRightV1<'a>> {
        FactoryRightV1::parse(field(
            self.raw,
            factory_reduced_exit_right_offset(false, self.settlement_descriptor().len(), index),
            FACTORY_RIGHT_V1_LEN,
        ))
    }

    pub fn right_after(&self, index: usize) -> Result<FactoryRightV1<'a>> {
        FactoryRightV1::parse(field(
            self.raw,
            factory_reduced_exit_right_offset(true, self.settlement_descriptor().len(), index),
            FACTORY_RIGHT_V1_LEN,
        ))
    }

    pub fn local_exit_digest(&self) -> [u8; 32] {
        factory_local_exit_digest_v1(
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
        factory_participants_commitment_v1(
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
        hasher.update(FACTORY_RIGHTS_ROOT_DOMAIN_V1);
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
        hasher.update(FACTORY_ACCESS_MANIFEST_ROOT_DOMAIN_V1);
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
        old_header: &FactoryStateHeaderV1,
        new_header: &FactoryStateHeaderV1,
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
            FACTORY_REDUCED_EXIT_DOMAIN_V1,
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
        for index in 0..FACTORY_REDUCED_RIGHTS_PARTICIPANT_COUNT_V1 as usize {
            match self.signed_flag(index) {
                0 => {}
                1 => count = count.saturating_add(1),
                _ => return u8::MAX,
            }
        }
        count
    }

    fn validate_right_order(&self, after: bool) -> Result<()> {
        let mut previous: Option<FactoryRightV1> = None;
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
    old_header: &FactoryStateHeaderV1,
    new_header: &FactoryStateHeaderV1,
    witness: &FactoryReducedExitWitnessV1,
) -> Result<()> {
    if new_header.signature_scheme_id() != SIGNATURE_SCHEME_SECP256K1_ECDSA_BLAKE2B_V1 {
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

fn validate_reduced_exit_local_evidence(witness: &FactoryReducedExitWitnessV1) -> Result<()> {
    let exit_header = StateHeaderV1::parse(witness.exit_state_header())?;
    if exit_header.state_number() != 0 || exit_header.phase() != PHASE_ACTIVE {
        return Err(ScriptError::FactoryLocalExitMismatch);
    }
    if exit_header.settlement_descriptor_commitment()
        != settlement_descriptor_commitment_v1(witness.settlement_descriptor()).as_slice()
    {
        return Err(ScriptError::SettlementDescriptorMismatch);
    }
    match witness.settlement_descriptor().len() {
        BILATERAL_CKB_DESCRIPTOR_V1_LEN => {
            if exit_header.descriptor_version() != BILATERAL_CKB_DESCRIPTOR_VERSION_V1 {
                return Err(ScriptError::SettlementDescriptorMismatch);
            }
        }
        BILATERAL_CKB_XUDT_DESCRIPTOR_V1_LEN => {
            if exit_header.descriptor_version() != BILATERAL_CKB_XUDT_DESCRIPTOR_VERSION_V1 {
                return Err(ScriptError::SettlementDescriptorMismatch);
            }
        }
        _ => return Err(ScriptError::SettlementDescriptorEncoding),
    }
    Ok(())
}

fn validate_reduced_exit_non_interference(witness: &FactoryReducedExitWitnessV1) -> Result<()> {
    if witness.release_quantity() == 0 {
        return Err(ScriptError::FactoryReducedProofMismatch);
    }
    let touched = witness.touched_participant();
    let release_quantity = witness.release_quantity();
    let mut consumed_claims = 0u8;

    for index in 0..witness.right_count() as usize {
        let before = witness.right_before(index)?;
        let after = witness.right_after(index)?;
        if !before.same_id(&after) {
            return Err(ScriptError::FactoryReducedProofMismatch);
        }

        if before.participant() == touched
            && before.kind() == FACTORY_RIGHT_KIND_RESERVE_CLAIM
            && before.quantity() >= release_quantity
            && before.quantity() - release_quantity == after.quantity()
        {
            consumed_claims = consumed_claims.saturating_add(1);
        } else if after.quantity() != before.quantity() {
            return Err(ScriptError::FactoryReducedProofMismatch);
        }
    }

    if consumed_claims == 1 {
        Ok(())
    } else {
        Err(ScriptError::FactoryReducedProofMismatch)
    }
}

fn verify_reduced_exit_signature(
    header: &FactoryStateHeaderV1,
    witness: &FactoryReducedExitWitnessV1,
) -> Result<()> {
    let digest = header.signing_digest();
    let mut matched = false;
    for index in 0..FACTORY_REDUCED_RIGHTS_PARTICIPANT_COUNT_V1 as usize {
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
pub struct FactoryLocalExitWitnessV1<'a> {
    raw: &'a [u8],
}

impl<'a> FactoryLocalExitWitnessV1<'a> {
    pub fn parse(raw: &'a [u8]) -> Result<Self> {
        if raw.len() != FACTORY_LOCAL_EXIT_WITNESS_V1_LEN
            && raw.len() != FACTORY_LOCAL_EXIT_XUDT_WITNESS_V1_LEN
        {
            return Err(ScriptError::ParticipantWitnessEncoding);
        }
        let witness = Self { raw };
        if witness.version() != FACTORY_LOCAL_EXIT_WITNESS_VERSION_V1 {
            return Err(ScriptError::ParticipantWitnessEncoding);
        }
        FactorySignatureWitnessV1::parse(witness.factory_signature_bytes())?;
        StateHeaderV1::parse(witness.exit_state_header())?;
        match witness.settlement_descriptor().len() {
            BILATERAL_CKB_DESCRIPTOR_V1_LEN => {
                BilateralCkbSettlementDescriptorV1::parse(witness.settlement_descriptor())?;
            }
            BILATERAL_CKB_XUDT_DESCRIPTOR_V1_LEN => {
                BilateralCkbXudtSettlementDescriptorV1::parse(witness.settlement_descriptor())?;
            }
            _ => return Err(ScriptError::SettlementDescriptorEncoding),
        }
        Ok(witness)
    }

    pub fn version(&self) -> u16 {
        read_u16(self.raw, 0)
    }

    pub fn factory_signature_bytes(&self) -> &'a [u8] {
        field(self.raw, 2, FACTORY_SIGNATURE_WITNESS_V1_LEN)
    }

    pub fn factory_signature(&self) -> Result<FactorySignatureWitnessV1<'a>> {
        FactorySignatureWitnessV1::parse(self.factory_signature_bytes())
    }

    pub fn state_output_index(&self) -> u32 {
        read_u32(self.raw, 2 + FACTORY_SIGNATURE_WITNESS_V1_LEN)
    }

    pub fn vault_output_index(&self) -> u32 {
        read_u32(self.raw, 2 + FACTORY_SIGNATURE_WITNESS_V1_LEN + 4)
    }

    pub fn state_type_hash(&self) -> &'a [u8] {
        field(
            self.raw,
            2 + FACTORY_SIGNATURE_WITNESS_V1_LEN + 8,
            BYTE32_LEN,
        )
    }

    pub fn vault_lock_hash(&self) -> &'a [u8] {
        field(
            self.raw,
            2 + FACTORY_SIGNATURE_WITNESS_V1_LEN + 8 + BYTE32_LEN,
            BYTE32_LEN,
        )
    }

    pub fn state_lock_hash(&self) -> &'a [u8] {
        field(
            self.raw,
            2 + FACTORY_SIGNATURE_WITNESS_V1_LEN + 8 + 2 * BYTE32_LEN,
            BYTE32_LEN,
        )
    }

    pub fn exit_state_header(&self) -> &'a [u8] {
        field(
            self.raw,
            2 + FACTORY_SIGNATURE_WITNESS_V1_LEN + 8 + 3 * BYTE32_LEN,
            STATE_HEADER_V1_LEN,
        )
    }

    pub fn settlement_descriptor(&self) -> &'a [u8] {
        let offset =
            2 + FACTORY_SIGNATURE_WITNESS_V1_LEN + 8 + 3 * BYTE32_LEN + STATE_HEADER_V1_LEN;
        field(self.raw, offset, self.raw.len() - offset)
    }

    pub fn exit_digest(&self) -> [u8; 32] {
        factory_local_exit_digest_v1(
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
    header: &FactoryStateHeaderV1,
    witness: &FactorySignatureWitnessV1,
) -> Result<()> {
    if header.signature_scheme_id() != SIGNATURE_SCHEME_SECP256K1_ECDSA_BLAKE2B_V1 {
        return Err(ScriptError::ParticipantWitnessEncoding);
    }
    if header.participants_commitment() != witness.participants_commitment().as_slice() {
        return Err(ScriptError::ParticipantCommitmentMismatch);
    }

    let digest = header.signing_digest();
    for index in 0..FACTORY_SIGNATURE_COUNT_V1 as usize {
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
pub struct FactorySpliceHeaderV1<'a> {
    raw: &'a [u8],
}

impl<'a> FactorySpliceHeaderV1<'a> {
    pub fn parse(raw: &'a [u8]) -> Result<Self> {
        if raw.len() != FACTORY_SPLICE_HEADER_V1_LEN {
            return Err(ScriptError::FactorySpliceProofEncoding);
        }
        let header = Self { raw };
        if header.kind() != SPLICE_KIND_IN_V1 && header.kind() != SPLICE_KIND_OUT_V1 {
            return Err(ScriptError::FactorySpliceProofEncoding);
        }
        Ok(header)
    }

    pub fn protocol_version(&self) -> u16 {
        read_u16(self.raw, 0)
    }

    pub fn factory_id(&self) -> &'a [u8] {
        field(self.raw, 2, BYTE32_LEN)
    }

    pub fn old_update_number(&self) -> u64 {
        read_u64(self.raw, 34)
    }

    pub fn new_update_number(&self) -> u64 {
        read_u64(self.raw, 42)
    }

    pub fn old_state_root(&self) -> &'a [u8] {
        field(self.raw, 50, BYTE32_LEN)
    }

    pub fn new_state_root(&self) -> &'a [u8] {
        field(self.raw, 82, BYTE32_LEN)
    }

    pub fn old_access_manifest_root(&self) -> &'a [u8] {
        field(self.raw, 114, BYTE32_LEN)
    }

    pub fn new_access_manifest_root(&self) -> &'a [u8] {
        field(self.raw, 146, BYTE32_LEN)
    }

    pub fn kind(&self) -> u8 {
        self.raw[178]
    }

    pub fn vault_delta_commitment(&self) -> &'a [u8] {
        field(self.raw, 179, BYTE32_LEN)
    }

    pub fn non_interference_digest(&self) -> &'a [u8] {
        field(self.raw, 211, BYTE32_LEN)
    }

    pub fn participants_commitment(&self) -> &'a [u8] {
        field(self.raw, 243, BYTE32_LEN)
    }

    pub fn signing_digest(&self) -> [u8; 32] {
        blake2b256(&[FACTORY_SPLICE_HEADER_DOMAIN_V1, self.raw])
    }

    pub fn matches_factory_update(
        &self,
        old_header: &FactoryStateHeaderV1,
        new_header: &FactoryStateHeaderV1,
    ) -> bool {
        old_header.same_context_except_progress(new_header)
            && self.protocol_version() == old_header.protocol_version()
            && self.protocol_version() == new_header.protocol_version()
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
pub struct FactoryVaultAssetAmountV1<'a> {
    raw: &'a [u8],
}

impl<'a> FactoryVaultAssetAmountV1<'a> {
    pub fn parse(raw: &'a [u8]) -> Result<Self> {
        if raw.len() != FACTORY_VAULT_ASSET_AMOUNT_V1_LEN {
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
pub struct FactoryVaultDescriptorV1<'a> {
    raw: &'a [u8],
}

impl<'a> FactoryVaultDescriptorV1<'a> {
    pub fn parse(raw: &'a [u8]) -> Result<Self> {
        if raw.len() != FACTORY_VAULT_DESCRIPTOR_V1_LEN {
            return Err(ScriptError::FactorySpliceProofEncoding);
        }
        let descriptor = Self { raw };
        if descriptor.asset_count() == 0
            || descriptor.asset_count() > FACTORY_VAULT_DESCRIPTOR_V1_MAX_ASSETS as u16
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

    pub fn asset(&self, index: usize) -> Result<FactoryVaultAssetAmountV1<'a>> {
        FactoryVaultAssetAmountV1::parse(field(
            self.raw,
            factory_vault_asset_offset(index),
            FACTORY_VAULT_ASSET_AMOUNT_V1_LEN,
        ))
    }

    pub fn commitment(&self) -> Result<[u8; 32]> {
        let count = self.asset_count();
        let count_bytes = count.to_le_bytes();
        let mut hasher = new_blake2b();
        hasher.update(FACTORY_VAULT_DESCRIPTOR_DOMAIN_V1);
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
        for index in self.asset_count() as usize..FACTORY_VAULT_DESCRIPTOR_V1_MAX_ASSETS as usize {
            let raw = field(
                self.raw,
                factory_vault_asset_offset(index),
                FACTORY_VAULT_ASSET_AMOUNT_V1_LEN,
            );
            if !raw.iter().all(|value| *value == 0) {
                return Err(ScriptError::FactorySpliceProofEncoding);
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FactoryVaultDeltaV1<'a> {
    raw: &'a [u8],
}

impl<'a> FactoryVaultDeltaV1<'a> {
    pub fn parse(raw: &'a [u8]) -> Result<Self> {
        if raw.len() != FACTORY_VAULT_DELTA_V1_LEN {
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
pub struct FactoryVaultDeltasV1<'a> {
    raw: &'a [u8],
}

impl<'a> FactoryVaultDeltasV1<'a> {
    pub fn parse(raw: &'a [u8]) -> Result<Self> {
        if raw.len() != FACTORY_VAULT_DELTAS_V1_LEN {
            return Err(ScriptError::FactorySpliceProofEncoding);
        }
        let deltas = Self { raw };
        if deltas.delta_count() == 0
            || deltas.delta_count() > FACTORY_VAULT_DELTAS_V1_MAX_DELTAS as u16
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

    pub fn delta(&self, index: usize) -> Result<FactoryVaultDeltaV1<'a>> {
        FactoryVaultDeltaV1::parse(field(
            self.raw,
            factory_vault_delta_offset(index),
            FACTORY_VAULT_DELTA_V1_LEN,
        ))
    }

    pub fn commitment(&self) -> Result<[u8; 32]> {
        let count = self.delta_count();
        let count_bytes = count.to_le_bytes();
        let mut hasher = new_blake2b();
        hasher.update(FACTORY_VAULT_DELTA_DOMAIN_V1);
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
        for index in self.delta_count() as usize..FACTORY_VAULT_DELTAS_V1_MAX_DELTAS as usize {
            let raw = field(
                self.raw,
                factory_vault_delta_offset(index),
                FACTORY_VAULT_DELTA_V1_LEN,
            );
            if !raw.iter().all(|value| *value == 0) {
                return Err(ScriptError::FactorySpliceProofEncoding);
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FactorySpliceWitnessV1<'a> {
    raw: &'a [u8],
}

impl<'a> FactorySpliceWitnessV1<'a> {
    pub fn parse(raw: &'a [u8]) -> Result<Self> {
        if raw.len() != FACTORY_SPLICE_WITNESS_V1_LEN {
            return Err(ScriptError::FactorySpliceProofEncoding);
        }
        let witness = Self { raw };
        if witness.version() != FACTORY_SPLICE_WITNESS_VERSION_V1 {
            return Err(ScriptError::FactorySpliceProofEncoding);
        }
        Ok(witness)
    }

    pub fn version(&self) -> u16 {
        read_u16(self.raw, 0)
    }

    pub fn header(&self) -> Result<FactorySpliceHeaderV1<'a>> {
        FactorySpliceHeaderV1::parse(field(
            self.raw,
            factory_splice_header_offset(),
            FACTORY_SPLICE_HEADER_V1_LEN,
        ))
    }

    pub fn factory_signature(&self) -> Result<FactorySignatureWitnessV1<'a>> {
        FactorySignatureWitnessV1::parse(field(
            self.raw,
            factory_splice_signature_offset(),
            FACTORY_SIGNATURE_WITNESS_V1_LEN,
        ))
        .map_err(|_| ScriptError::FactorySpliceProofEncoding)
    }

    pub fn old_vault(&self) -> Result<FactoryVaultDescriptorV1<'a>> {
        FactoryVaultDescriptorV1::parse(field(
            self.raw,
            factory_splice_old_vault_offset(),
            FACTORY_VAULT_DESCRIPTOR_V1_LEN,
        ))
    }

    pub fn new_vault(&self) -> Result<FactoryVaultDescriptorV1<'a>> {
        FactoryVaultDescriptorV1::parse(field(
            self.raw,
            factory_splice_new_vault_offset(),
            FACTORY_VAULT_DESCRIPTOR_V1_LEN,
        ))
    }

    pub fn deltas(&self) -> Result<FactoryVaultDeltasV1<'a>> {
        FactoryVaultDeltasV1::parse(field(
            self.raw,
            factory_splice_deltas_offset(),
            FACTORY_VAULT_DELTAS_V1_LEN,
        ))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FactoryReducedSpliceWitnessV1<'a> {
    raw: &'a [u8],
}

impl<'a> FactoryReducedSpliceWitnessV1<'a> {
    pub fn parse(raw: &'a [u8]) -> Result<Self> {
        if raw.len() != FACTORY_REDUCED_SPLICE_WITNESS_V1_LEN {
            return Err(ScriptError::FactorySpliceProofEncoding);
        }
        let witness = Self { raw };
        if witness.version() != FACTORY_REDUCED_SPLICE_WITNESS_VERSION_V1 {
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

    pub fn header(&self) -> Result<FactorySpliceHeaderV1<'a>> {
        FactorySpliceHeaderV1::parse(field(
            self.raw,
            factory_reduced_splice_header_offset(),
            FACTORY_SPLICE_HEADER_V1_LEN,
        ))
    }

    pub fn merkle_update(&self) -> Result<FactoryMerkleUpdateWitnessV1<'a>> {
        FactoryMerkleUpdateWitnessV1::parse(field(
            self.raw,
            factory_reduced_splice_merkle_offset(),
            FACTORY_MERKLE_UPDATE_WITNESS_V1_LEN,
        ))
        .map_err(|_| ScriptError::FactorySpliceProofEncoding)
    }

    pub fn old_vault(&self) -> Result<FactoryVaultDescriptorV1<'a>> {
        FactoryVaultDescriptorV1::parse(field(
            self.raw,
            factory_reduced_splice_old_vault_offset(),
            FACTORY_VAULT_DESCRIPTOR_V1_LEN,
        ))
    }

    pub fn new_vault(&self) -> Result<FactoryVaultDescriptorV1<'a>> {
        FactoryVaultDescriptorV1::parse(field(
            self.raw,
            factory_reduced_splice_new_vault_offset(),
            FACTORY_VAULT_DESCRIPTOR_V1_LEN,
        ))
    }

    pub fn deltas(&self) -> Result<FactoryVaultDeltasV1<'a>> {
        FactoryVaultDeltasV1::parse(field(
            self.raw,
            factory_reduced_splice_deltas_offset(),
            FACTORY_VAULT_DELTAS_V1_LEN,
        ))
    }
}

pub fn verify_factory_splice_update(
    old_header: &FactoryStateHeaderV1,
    new_header: &FactoryStateHeaderV1,
    witness: &FactorySpliceWitnessV1,
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
    old_header: &FactoryStateHeaderV1,
    new_header: &FactoryStateHeaderV1,
    witness: &FactoryReducedSpliceWitnessV1,
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
    header: &FactorySpliceHeaderV1,
    witness: &FactorySignatureWitnessV1,
) -> Result<()> {
    if header.participants_commitment() != witness.pubkey_participants_commitment().as_slice() {
        return Err(ScriptError::ParticipantCommitmentMismatch);
    }

    let digest = header.signing_digest();
    for index in 0..FACTORY_SIGNATURE_COUNT_V1 as usize {
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
    header: &FactorySpliceHeaderV1,
    witness: &FactoryMerkleUpdateWitnessV1,
) -> Result<()> {
    let digest = header.signing_digest();
    let mut matched = false;
    for index in 0..FACTORY_REDUCED_RIGHTS_PARTICIPANT_COUNT_V1 as usize {
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
    witness: &FactoryMerkleUpdateWitnessV1,
    deltas: &FactoryVaultDeltasV1,
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
        VAULT_ASSET_KIND_CKB_V1
    } else {
        VAULT_ASSET_KIND_XUDT_V1
    };
    if delta.asset_kind() != expected_asset_kind || delta.asset_type() != before.asset_type() {
        return Err(ScriptError::FactorySpliceProofMismatch);
    }

    match kind {
        SPLICE_KIND_IN_V1 => {
            let claim_delta = after
                .quantity()
                .checked_sub(before.quantity())
                .ok_or(ScriptError::FactorySpliceProofMismatch)?;
            if claim_delta == 0 || claim_delta != delta.external_input() || delta.withdrawal() != 0
            {
                return Err(ScriptError::FactorySpliceProofMismatch);
            }
        }
        SPLICE_KIND_OUT_V1 => {
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
    old_vault: &FactoryVaultDescriptorV1,
    new_vault: &FactoryVaultDescriptorV1,
    deltas: &FactoryVaultDeltasV1,
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

fn verify_factory_vault_delta(kind: u8, delta: &FactoryVaultDeltaV1) -> Result<()> {
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
        SPLICE_KIND_IN_V1 => {
            if delta.external_input() == 0
                || delta.withdrawal() != 0
                || delta.new_amount() <= delta.old_amount()
            {
                return Err(ScriptError::FactorySpliceProofMismatch);
            }
        }
        SPLICE_KIND_OUT_V1 => {
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
    descriptor: &FactoryVaultDescriptorV1,
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
    deltas: &FactoryVaultDeltasV1,
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
pub struct BilateralCkbSettlementDescriptorV1<'a> {
    raw: &'a [u8],
}

impl<'a> BilateralCkbSettlementDescriptorV1<'a> {
    pub fn parse(raw: &'a [u8]) -> Result<Self> {
        if raw.len() != BILATERAL_CKB_DESCRIPTOR_V1_LEN {
            return Err(ScriptError::SettlementDescriptorEncoding);
        }
        let descriptor = Self { raw };
        if descriptor.version() != BILATERAL_CKB_DESCRIPTOR_VERSION_V1
            || descriptor.output_count() != BILATERAL_CKB_DESCRIPTOR_OUTPUT_COUNT_V1
            || descriptor.reserved() != 0
        {
            return Err(ScriptError::SettlementDescriptorEncoding);
        }
        if descriptor.lock_hash(0) >= descriptor.lock_hash(1) {
            return Err(ScriptError::SettlementDescriptorEncoding);
        }
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
        self.capacity(0).saturating_add(self.capacity(1))
    }

    pub fn commitment(&self) -> [u8; 32] {
        settlement_descriptor_commitment_v1(self.raw)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BilateralCkbXudtSettlementDescriptorV1<'a> {
    raw: &'a [u8],
}

impl<'a> BilateralCkbXudtSettlementDescriptorV1<'a> {
    pub fn parse(raw: &'a [u8]) -> Result<Self> {
        if raw.len() != BILATERAL_CKB_XUDT_DESCRIPTOR_V1_LEN {
            return Err(ScriptError::SettlementDescriptorEncoding);
        }
        let descriptor = Self { raw };
        if descriptor.version() != BILATERAL_CKB_XUDT_DESCRIPTOR_VERSION_V1
            || descriptor.output_count() != BILATERAL_CKB_DESCRIPTOR_OUTPUT_COUNT_V1
            || descriptor.asset_count() != BILATERAL_CKB_XUDT_DESCRIPTOR_ASSET_COUNT_V1
        {
            return Err(ScriptError::SettlementDescriptorEncoding);
        }
        if descriptor.lock_hash(0) >= descriptor.lock_hash(1) {
            return Err(ScriptError::SettlementDescriptorEncoding);
        }
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
        self.capacity(0).saturating_add(self.capacity(1))
    }

    pub fn total_xudt_amount(&self) -> u128 {
        self.xudt_amount(0).saturating_add(self.xudt_amount(1))
    }

    pub fn commitment(&self) -> [u8; 32] {
        settlement_descriptor_commitment_v1(self.raw)
    }
}

pub fn settlement_descriptor_commitment_v1(raw: &[u8]) -> [u8; 32] {
    blake2b256(&[SETTLEMENT_DESCRIPTOR_DOMAIN_V1, raw])
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SpliceVaultAssetAmountV2<'a> {
    raw: &'a [u8],
}

impl<'a> SpliceVaultAssetAmountV2<'a> {
    pub fn parse(raw: &'a [u8]) -> Result<Self> {
        if raw.len() != SPLICE_VAULT_ASSET_AMOUNT_V2_LEN {
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
pub struct SpliceVaultDescriptorV2<'a> {
    raw: &'a [u8],
}

impl<'a> SpliceVaultDescriptorV2<'a> {
    pub fn parse(raw: &'a [u8]) -> Result<Self> {
        if raw.len() != SPLICE_VAULT_DESCRIPTOR_V2_LEN {
            return Err(ScriptError::Encoding);
        }
        let descriptor = Self { raw };
        if descriptor.asset_count() == 0
            || descriptor.asset_count() > SPLICE_VAULT_DESCRIPTOR_V2_MAX_ASSETS as u16
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

    pub fn asset(&self, index: usize) -> Result<SpliceVaultAssetAmountV2<'a>> {
        SpliceVaultAssetAmountV2::parse(field(
            self.raw,
            splice_vault_asset_offset(index),
            SPLICE_VAULT_ASSET_AMOUNT_V2_LEN,
        ))
    }

    pub fn commitment(&self) -> Result<[u8; 32]> {
        let count = self.asset_count();
        let count_bytes = count.to_le_bytes();
        let mut hasher = new_blake2b();
        hasher.update(VAULT_DESCRIPTOR_DOMAIN_V2);
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
        for index in self.asset_count() as usize..SPLICE_VAULT_DESCRIPTOR_V2_MAX_ASSETS as usize {
            let raw = field(
                self.raw,
                splice_vault_asset_offset(index),
                SPLICE_VAULT_ASSET_AMOUNT_V2_LEN,
            );
            if !raw.iter().all(|value| *value == 0) {
                return Err(ScriptError::Encoding);
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SpliceAssetDeltaV1<'a> {
    raw: &'a [u8],
}

impl<'a> SpliceAssetDeltaV1<'a> {
    pub fn parse(raw: &'a [u8]) -> Result<Self> {
        if raw.len() != SPLICE_ASSET_DELTA_V1_LEN {
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
pub struct SpliceAssetDeltasV1<'a> {
    raw: &'a [u8],
}

impl<'a> SpliceAssetDeltasV1<'a> {
    pub fn parse(raw: &'a [u8]) -> Result<Self> {
        if raw.len() != SPLICE_ASSET_DELTAS_V1_LEN {
            return Err(ScriptError::Encoding);
        }
        let deltas = Self { raw };
        if deltas.delta_count() == 0
            || deltas.delta_count() > SPLICE_ASSET_DELTAS_V1_MAX_DELTAS as u16
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

    pub fn delta(&self, index: usize) -> Result<SpliceAssetDeltaV1<'a>> {
        SpliceAssetDeltaV1::parse(field(
            self.raw,
            splice_delta_offset(index),
            SPLICE_ASSET_DELTA_V1_LEN,
        ))
    }

    pub fn commitment(&self) -> Result<[u8; 32]> {
        let count = self.delta_count();
        let count_bytes = count.to_le_bytes();
        let mut hasher = new_blake2b();
        hasher.update(SPLICE_DELTA_DOMAIN_V1);
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
        for index in self.delta_count() as usize..SPLICE_ASSET_DELTAS_V1_MAX_DELTAS as usize {
            let raw = field(
                self.raw,
                splice_delta_offset(index),
                SPLICE_ASSET_DELTA_V1_LEN,
            );
            if !raw.iter().all(|value| *value == 0) {
                return Err(ScriptError::Encoding);
            }
        }
        Ok(())
    }
}

pub fn factory_local_exit_digest_v1(
    state_output_index: u32,
    vault_output_index: u32,
    state_type_hash: &[u8],
    vault_lock_hash: &[u8],
    state_lock_hash: &[u8],
    exit_state_header: &[u8],
    settlement_descriptor: &[u8],
) -> [u8; 32] {
    blake2b256(&[
        FACTORY_LOCAL_EXIT_DOMAIN_V1,
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
pub struct SponsorPolicyV1<'a> {
    raw: &'a [u8],
}

impl<'a> SponsorPolicyV1<'a> {
    pub fn parse(raw: &'a [u8]) -> Result<Self> {
        if raw.len() != SPONSOR_POLICY_V1_LEN {
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

pub fn read_u64(raw: &[u8], offset: usize) -> u64 {
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&raw[offset..offset + 8]);
    u64::from_le_bytes(bytes)
}

pub fn read_u32(raw: &[u8], offset: usize) -> u32 {
    let mut bytes = [0u8; 4];
    bytes.copy_from_slice(&raw[offset..offset + 4]);
    u32::from_le_bytes(bytes)
}

pub fn read_u128(raw: &[u8], offset: usize) -> u128 {
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&raw[offset..offset + 16]);
    u128::from_le_bytes(bytes)
}

pub fn field(raw: &[u8], offset: usize, len: usize) -> &[u8] {
    &raw[offset..offset + len]
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

pub fn participants_commitment_v1(threshold: u8, pubkeys: &[&[u8]]) -> [u8; 32] {
    let count = [pubkeys.len() as u8];
    let threshold = [threshold];
    let mut hasher = new_blake2b();
    hasher.update(PARTICIPANTS_DOMAIN_V1);
    hasher.update(&threshold);
    hasher.update(&count);
    for pubkey in pubkeys {
        hasher.update(pubkey);
    }
    let mut out = [0u8; 32];
    hasher.finalize(&mut out);
    out
}

pub fn factory_participants_commitment_v1(threshold: u8, entries: &[(&[u8], &[u8])]) -> [u8; 32] {
    let count = [entries.len() as u8];
    let threshold = [threshold];
    let mut hasher = new_blake2b();
    hasher.update(FACTORY_PARTICIPANTS_DOMAIN_V1);
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
    splice_transition_header_offset() + SPLICE_HEADER_V1_LEN
}

fn splice_transition_old_vault_offset() -> usize {
    splice_transition_signature_offset() + SPLICE_SIGNATURE_WITNESS_V1_LEN
}

fn splice_transition_new_vault_offset() -> usize {
    splice_transition_old_vault_offset() + SPLICE_VAULT_DESCRIPTOR_V2_LEN
}

fn splice_transition_deltas_offset() -> usize {
    splice_transition_new_vault_offset() + SPLICE_VAULT_DESCRIPTOR_V2_LEN
}

fn factory_participant_offset(index: usize) -> usize {
    4 + index * (BYTE32_LEN + COMPRESSED_SECP256K1_PUBKEY_LEN + ECDSA_SIGNATURE_LEN)
}

fn factory_splice_header_offset() -> usize {
    2
}

fn factory_splice_signature_offset() -> usize {
    factory_splice_header_offset() + FACTORY_SPLICE_HEADER_V1_LEN
}

fn factory_splice_old_vault_offset() -> usize {
    factory_splice_signature_offset() + FACTORY_SIGNATURE_WITNESS_V1_LEN
}

fn factory_splice_new_vault_offset() -> usize {
    factory_splice_old_vault_offset() + FACTORY_VAULT_DESCRIPTOR_V1_LEN
}

fn factory_splice_deltas_offset() -> usize {
    factory_splice_new_vault_offset() + FACTORY_VAULT_DESCRIPTOR_V1_LEN
}

fn factory_reduced_splice_header_offset() -> usize {
    2
}

fn factory_reduced_splice_merkle_offset() -> usize {
    factory_reduced_splice_header_offset() + FACTORY_SPLICE_HEADER_V1_LEN
}

fn factory_reduced_splice_old_vault_offset() -> usize {
    factory_reduced_splice_merkle_offset() + FACTORY_MERKLE_UPDATE_WITNESS_V1_LEN
}

fn factory_reduced_splice_new_vault_offset() -> usize {
    factory_reduced_splice_old_vault_offset() + FACTORY_VAULT_DESCRIPTOR_V1_LEN
}

fn factory_reduced_splice_deltas_offset() -> usize {
    factory_reduced_splice_new_vault_offset() + FACTORY_VAULT_DESCRIPTOR_V1_LEN
}

fn factory_reduced_participant_offset(index: usize) -> usize {
    8 + index * FACTORY_REDUCED_RIGHTS_PARTICIPANT_ENTRY_V1_LEN
}

fn factory_reduced_touched_offset() -> usize {
    8 + FACTORY_REDUCED_RIGHTS_PARTICIPANT_COUNT_V1 as usize
        * FACTORY_REDUCED_RIGHTS_PARTICIPANT_ENTRY_V1_LEN
}

fn factory_reduced_right_offset(after: bool, index: usize) -> usize {
    let before_offset = factory_reduced_touched_offset() + BYTE32_LEN;
    if after {
        before_offset
            + FACTORY_REDUCED_RIGHTS_COUNT_V1 as usize * FACTORY_RIGHT_V1_LEN
            + index * FACTORY_RIGHT_V1_LEN
    } else {
        before_offset + index * FACTORY_RIGHT_V1_LEN
    }
}

fn factory_merkle_participant_offset(index: usize) -> usize {
    8 + index * FACTORY_REDUCED_RIGHTS_PARTICIPANT_ENTRY_V1_LEN
}

fn factory_merkle_touched_offset() -> usize {
    8 + FACTORY_REDUCED_RIGHTS_PARTICIPANT_COUNT_V1 as usize
        * FACTORY_REDUCED_RIGHTS_PARTICIPANT_ENTRY_V1_LEN
}

fn factory_merkle_right_offset(after: bool) -> usize {
    let before_offset = factory_merkle_touched_offset() + BYTE32_LEN;
    if after {
        before_offset + FACTORY_RIGHT_V1_LEN
    } else {
        before_offset
    }
}

fn factory_merkle_sibling_offset(depth: usize) -> usize {
    factory_merkle_right_offset(true) + FACTORY_RIGHT_V1_LEN + depth * BYTE32_LEN
}

fn factory_reduced_exit_participant_offset(index: usize) -> usize {
    8 + index * FACTORY_REDUCED_RIGHTS_PARTICIPANT_ENTRY_V1_LEN
}

fn factory_reduced_exit_touched_offset() -> usize {
    8 + FACTORY_REDUCED_RIGHTS_PARTICIPANT_COUNT_V1 as usize
        * FACTORY_REDUCED_RIGHTS_PARTICIPANT_ENTRY_V1_LEN
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
    factory_reduced_exit_state_header_offset() + STATE_HEADER_V1_LEN
}

fn factory_reduced_exit_right_offset(after: bool, descriptor_len: usize, index: usize) -> usize {
    let before_offset = factory_reduced_exit_descriptor_offset() + descriptor_len;
    if after {
        before_offset
            + FACTORY_REDUCED_RIGHTS_COUNT_V1 as usize * FACTORY_RIGHT_V1_LEN
            + index * FACTORY_RIGHT_V1_LEN
    } else {
        before_offset + index * FACTORY_RIGHT_V1_LEN
    }
}

fn descriptor_output_offset(index: usize) -> usize {
    4 + index * (BYTE32_LEN + 8)
}

fn ckb_xudt_descriptor_output_offset(index: usize) -> usize {
    4 + BYTE32_LEN + index * (BYTE32_LEN + 8 + 16)
}

fn splice_vault_asset_offset(index: usize) -> usize {
    BYTE32_LEN + 2 + index * SPLICE_VAULT_ASSET_AMOUNT_V2_LEN
}

fn splice_delta_offset(index: usize) -> usize {
    2 + index * SPLICE_ASSET_DELTA_V1_LEN
}

fn factory_vault_asset_offset(index: usize) -> usize {
    BYTE32_LEN + 2 + index * FACTORY_VAULT_ASSET_AMOUNT_V1_LEN
}

fn factory_vault_delta_offset(index: usize) -> usize {
    2 + index * FACTORY_VAULT_DELTA_V1_LEN
}

fn validate_vault_asset_encoding(kind: u8, type_hash: &[u8]) -> Result<()> {
    match kind {
        VAULT_ASSET_KIND_CKB_V1 => {
            if type_hash.iter().all(|value| *value == 0) {
                Ok(())
            } else {
                Err(ScriptError::Encoding)
            }
        }
        VAULT_ASSET_KIND_XUDT_V1 => Ok(()),
        _ => Err(ScriptError::Encoding),
    }
}

fn factory_right_key(right: &FactoryRightV1) -> [u8; 32] {
    blake2b256(&[
        FACTORY_RIGHT_KEY_DOMAIN_V1,
        right.participant(),
        right.subchannel(),
        &[right.kind()],
        &[right.asset_present()],
        right.asset_type(),
    ])
}

fn factory_right_leaf_hash(right: &FactoryRightV1) -> [u8; 32] {
    let key = factory_right_key(right);
    blake2b256(&[FACTORY_RIGHT_LEAF_DOMAIN_V1, &key, right.raw()])
}

fn factory_right_node_hash(depth: usize, left: &[u8], right: &[u8]) -> [u8; 32] {
    blake2b256(&[
        FACTORY_RIGHT_NODE_DOMAIN_V1,
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
        out.copy_from_slice(sig.to_bytes().as_slice());
        out
    }

    fn signed_bilateral_witness(
        key0: &SigningKey,
        key1: &SigningKey,
        digest: &[u8; 32],
    ) -> [u8; BILATERAL_SIGNATURE_WITNESS_V1_LEN] {
        let mut entries = [
            (pubkey(key0), signature(key0, digest)),
            (pubkey(key1), signature(key1, digest)),
        ];
        entries.sort_by(|left, right| left.0.cmp(&right.0));

        let mut raw = [0u8; BILATERAL_SIGNATURE_WITNESS_V1_LEN];
        put_u16(&mut raw, 0, BILATERAL_SIGNATURE_WITNESS_VERSION_V1);
        raw[2] = BILATERAL_SIGNATURE_THRESHOLD_V1;
        raw[3] = BILATERAL_SIGNATURE_COUNT_V1;
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
    ) -> [u8; FACTORY_SIGNATURE_WITNESS_V1_LEN] {
        let mut entries = [
            (participant0, pubkey(key0), signature(key0, digest)),
            (participant1, pubkey(key1), signature(key1, digest)),
        ];
        entries.sort_by(|left, right| left.0.cmp(&right.0));

        let mut raw = [0u8; FACTORY_SIGNATURE_WITNESS_V1_LEN];
        put_u16(&mut raw, 0, FACTORY_SIGNATURE_WITNESS_VERSION_V1);
        raw[2] = FACTORY_SIGNATURE_THRESHOLD_V1;
        raw[3] = FACTORY_SIGNATURE_COUNT_V1;
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
    ) -> [u8; FACTORY_RIGHT_V1_LEN] {
        let mut raw = [0u8; FACTORY_RIGHT_V1_LEN];
        raw[0..BYTE32_LEN].fill(participant);
        raw[BYTE32_LEN..2 * BYTE32_LEN].fill(subchannel);
        raw[2 * BYTE32_LEN] = kind;
        raw[2 * BYTE32_LEN + 1] = 0;
        put_u128(&mut raw, 2 * BYTE32_LEN + 2 + BYTE32_LEN, quantity);
        raw
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

    fn reduced_rights_witness_raw(
        participant0: [u8; BYTE32_LEN],
        key0: &SigningKey,
        participant1: [u8; BYTE32_LEN],
        key1: &SigningKey,
        touched: [u8; BYTE32_LEN],
        before: &[[u8; FACTORY_RIGHT_V1_LEN]; FACTORY_REDUCED_RIGHTS_COUNT_V1 as usize],
        after: &[[u8; FACTORY_RIGHT_V1_LEN]; FACTORY_REDUCED_RIGHTS_COUNT_V1 as usize],
    ) -> [u8; FACTORY_REDUCED_RIGHTS_WITNESS_V1_LEN] {
        let mut entries = [(participant0, pubkey(key0)), (participant1, pubkey(key1))];
        entries.sort_by(|left, right| left.0.cmp(&right.0));

        let mut raw = [0u8; FACTORY_REDUCED_RIGHTS_WITNESS_V1_LEN];
        put_u16(&mut raw, 0, FACTORY_REDUCED_RIGHTS_WITNESS_VERSION_V1);
        raw[2] = FACTORY_REDUCED_RIGHTS_PARTICIPANT_THRESHOLD_V1;
        raw[3] = FACTORY_REDUCED_RIGHTS_PARTICIPANT_COUNT_V1;
        raw[4] = FACTORY_REDUCED_RIGHTS_AUTHORISED_COUNT_V1;
        raw[5] = FACTORY_REDUCED_RIGHTS_COUNT_V1;
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
        for index in 0..FACTORY_REDUCED_RIGHTS_COUNT_V1 as usize {
            let before_offset = factory_reduced_right_offset(false, index);
            raw[before_offset..before_offset + FACTORY_RIGHT_V1_LEN]
                .copy_from_slice(&before[index]);
            let after_offset = factory_reduced_right_offset(true, index);
            raw[after_offset..after_offset + FACTORY_RIGHT_V1_LEN].copy_from_slice(&after[index]);
        }
        raw
    }

    fn sign_reduced_rights_witness(
        raw: &mut [u8; FACTORY_REDUCED_RIGHTS_WITNESS_V1_LEN],
        participant: [u8; BYTE32_LEN],
        key: &SigningKey,
        digest: &[u8; 32],
    ) {
        let sig = signature(key, digest);
        for index in 0..FACTORY_REDUCED_RIGHTS_PARTICIPANT_COUNT_V1 as usize {
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
        [u8; FACTORY_MERKLE_UPDATE_WITNESS_V1_LEN],
        SigningKey,
        SigningKey,
    ) {
        let key0 = signing_key(1);
        let key1 = signing_key(2);
        let mut entries = [([1u8; 32], pubkey(&key0)), ([2u8; 32], pubkey(&key1))];
        entries.sort_by(|left, right| left.0.cmp(&right.0));

        let mut raw = [0u8; FACTORY_MERKLE_UPDATE_WITNESS_V1_LEN];
        put_u16(&mut raw, 0, FACTORY_MERKLE_UPDATE_WITNESS_VERSION_V1);
        raw[2] = FACTORY_REDUCED_RIGHTS_PARTICIPANT_THRESHOLD_V1;
        raw[3] = FACTORY_REDUCED_RIGHTS_PARTICIPANT_COUNT_V1;
        raw[4] = FACTORY_REDUCED_RIGHTS_AUTHORISED_COUNT_V1;
        raw[5] = FACTORY_MERKLE_UPDATE_RIGHT_COUNT_V1;
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
            ..factory_merkle_right_offset(false) + FACTORY_RIGHT_V1_LEN]
            .copy_from_slice(&factory_right_bytes(1, 10, 0, 100));
        raw[factory_merkle_right_offset(true)
            ..factory_merkle_right_offset(true) + FACTORY_RIGHT_V1_LEN]
            .copy_from_slice(&factory_right_bytes(1, 10, 0, touched_after_balance));
        for depth in 0..FACTORY_SPARSE_MERKLE_DEPTH_V1 {
            let offset = factory_merkle_sibling_offset(depth);
            raw[offset..offset + BYTE32_LEN].fill(depth as u8);
        }

        (raw, key0, key1)
    }

    fn sign_merkle_update_witness(
        raw: &mut [u8; FACTORY_MERKLE_UPDATE_WITNESS_V1_LEN],
        participant: [u8; BYTE32_LEN],
        key: &SigningKey,
        digest: &[u8; 32],
    ) {
        let sig = signature(key, digest);
        for index in 0..FACTORY_REDUCED_RIGHTS_PARTICIPANT_COUNT_V1 as usize {
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
        [u8; FACTORY_STATE_HEADER_V1_LEN],
        [u8; FACTORY_STATE_HEADER_V1_LEN],
        [u8; FACTORY_MERKLE_UPDATE_WITNESS_V1_LEN],
    ) {
        let (mut witness_raw, key0, key1) = merkle_update_witness_raw(after_balance);
        let mut entries = [([1u8; 32], pubkey(&key0)), ([2u8; 32], pubkey(&key1))];
        entries.sort_by(|left, right| left.0.cmp(&right.0));
        let participants_commitment = factory_participants_commitment_v1(
            2,
            &[
                (entries[0].0.as_slice(), entries[0].1.as_slice()),
                (entries[1].0.as_slice(), entries[1].1.as_slice()),
            ],
        );
        let witness = FactoryMerkleUpdateWitnessV1::parse(&witness_raw).unwrap();

        let mut old_raw = factory_header_bytes(1);
        old_raw[76..108].copy_from_slice(&witness.rights_root(false).unwrap());
        old_raw[108..140].copy_from_slice(&participants_commitment);
        let old_header = FactoryStateHeaderV1::parse(&old_raw).unwrap();

        let mut new_raw = factory_header_bytes(2);
        new_raw[76..108].copy_from_slice(&witness.rights_root(true).unwrap());
        new_raw[108..140].copy_from_slice(&participants_commitment);
        new_raw[140..172].copy_from_slice(old_header.access_manifest_root());
        let preliminary_new = FactoryStateHeaderV1::parse(&new_raw).unwrap();
        let digest = witness
            .non_interference_digest(&old_header, &preliminary_new)
            .unwrap();
        new_raw[172..204].copy_from_slice(&digest);
        let new_header = FactoryStateHeaderV1::parse(&new_raw).unwrap();
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
        [u8; FACTORY_STATE_HEADER_V1_LEN],
        [u8; FACTORY_STATE_HEADER_V1_LEN],
        [u8; FACTORY_REDUCED_RIGHTS_WITNESS_V1_LEN],
    ) {
        let key0 = signing_key(1);
        let key1 = signing_key(2);
        let mut entries = [([1u8; 32], pubkey(&key0)), ([2u8; 32], pubkey(&key1))];
        entries.sort_by(|left, right| left.0.cmp(&right.0));
        let participants_commitment = factory_participants_commitment_v1(
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
        let witness = FactoryReducedRightsWitnessV1::parse(&witness_raw).unwrap();

        let mut old_raw = factory_header_bytes(1);
        old_raw[76..108].copy_from_slice(&witness.rights_root(false).unwrap());
        old_raw[108..140].copy_from_slice(&participants_commitment);
        old_raw[140..172].copy_from_slice(&witness.access_manifest_root(false).unwrap());
        let old_header = FactoryStateHeaderV1::parse(&old_raw).unwrap();

        let mut new_raw = factory_header_bytes(2);
        new_raw[76..108].copy_from_slice(&witness.rights_root(true).unwrap());
        new_raw[108..140].copy_from_slice(&participants_commitment);
        new_raw[140..172].copy_from_slice(&witness.access_manifest_root(true).unwrap());
        let preliminary_new = FactoryStateHeaderV1::parse(&new_raw).unwrap();
        let digest = witness
            .non_interference_digest(&old_header, &preliminary_new)
            .unwrap();
        new_raw[172..204].copy_from_slice(&digest);
        let new_header = FactoryStateHeaderV1::parse(&new_raw).unwrap();
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
    ) -> (
        [[u8; FACTORY_RIGHT_V1_LEN]; FACTORY_REDUCED_RIGHTS_COUNT_V1 as usize],
        [[u8; FACTORY_RIGHT_V1_LEN]; FACTORY_REDUCED_RIGHTS_COUNT_V1 as usize],
    ) {
        let before = [
            factory_right_bytes(1, 10, 0, 100),
            factory_right_bytes(1, 10, FACTORY_RIGHT_KIND_RESERVE_CLAIM, 50),
            factory_right_bytes(1, 10, 2, 1),
            factory_right_bytes(1, 10, 3, 1),
            factory_right_bytes(1, 10, 4, 20),
            factory_right_bytes(2, 10, 0, 100),
            factory_right_bytes(2, 10, FACTORY_RIGHT_KIND_RESERVE_CLAIM, 50),
            factory_right_bytes(2, 10, 2, 1),
            factory_right_bytes(2, 10, 3, 1),
            factory_right_bytes(2, 10, 4, 20),
        ];
        let mut after = before;
        after[1] = factory_right_bytes(
            1,
            10,
            FACTORY_RIGHT_KIND_RESERVE_CLAIM,
            reserve_claim_after_quantity,
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
        exit_state_header: &[u8; STATE_HEADER_V1_LEN],
        settlement_descriptor: &[u8; BILATERAL_CKB_DESCRIPTOR_V1_LEN],
        before: &[[u8; FACTORY_RIGHT_V1_LEN]; FACTORY_REDUCED_RIGHTS_COUNT_V1 as usize],
        after: &[[u8; FACTORY_RIGHT_V1_LEN]; FACTORY_REDUCED_RIGHTS_COUNT_V1 as usize],
    ) -> [u8; FACTORY_REDUCED_EXIT_WITNESS_V1_LEN] {
        let touched = [1u8; BYTE32_LEN];
        let mut entries = [([1u8; 32], pubkey(key0)), ([2u8; 32], pubkey(key1))];
        entries.sort_by(|left, right| left.0.cmp(&right.0));

        let mut raw = [0u8; FACTORY_REDUCED_EXIT_WITNESS_V1_LEN];
        put_u16(&mut raw, 0, FACTORY_REDUCED_EXIT_WITNESS_VERSION_V1);
        raw[2] = FACTORY_REDUCED_RIGHTS_PARTICIPANT_THRESHOLD_V1;
        raw[3] = FACTORY_REDUCED_RIGHTS_PARTICIPANT_COUNT_V1;
        raw[4] = FACTORY_REDUCED_RIGHTS_AUTHORISED_COUNT_V1;
        raw[5] = FACTORY_REDUCED_RIGHTS_COUNT_V1;
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
            ..factory_reduced_exit_state_header_offset() + STATE_HEADER_V1_LEN]
            .copy_from_slice(exit_state_header);
        raw[factory_reduced_exit_descriptor_offset()
            ..factory_reduced_exit_descriptor_offset() + BILATERAL_CKB_DESCRIPTOR_V1_LEN]
            .copy_from_slice(settlement_descriptor);
        for index in 0..FACTORY_REDUCED_RIGHTS_COUNT_V1 as usize {
            let before_offset =
                factory_reduced_exit_right_offset(false, BILATERAL_CKB_DESCRIPTOR_V1_LEN, index);
            raw[before_offset..before_offset + FACTORY_RIGHT_V1_LEN]
                .copy_from_slice(&before[index]);
            let after_offset =
                factory_reduced_exit_right_offset(true, BILATERAL_CKB_DESCRIPTOR_V1_LEN, index);
            raw[after_offset..after_offset + FACTORY_RIGHT_V1_LEN].copy_from_slice(&after[index]);
        }
        raw
    }

    fn sign_reduced_exit_witness(
        raw: &mut [u8; FACTORY_REDUCED_EXIT_WITNESS_V1_LEN],
        participant: [u8; BYTE32_LEN],
        key: &SigningKey,
        digest: &[u8; 32],
    ) {
        let sig = signature(key, digest);
        for index in 0..FACTORY_REDUCED_RIGHTS_PARTICIPANT_COUNT_V1 as usize {
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
        [u8; FACTORY_STATE_HEADER_V1_LEN],
        [u8; FACTORY_STATE_HEADER_V1_LEN],
        [u8; FACTORY_REDUCED_EXIT_WITNESS_V1_LEN],
    ) {
        let key0 = signing_key(1);
        let key1 = signing_key(2);
        let mut entries = [([1u8; 32], pubkey(&key0)), ([2u8; 32], pubkey(&key1))];
        entries.sort_by(|left, right| left.0.cmp(&right.0));
        let participants_commitment = factory_participants_commitment_v1(
            2,
            &[
                (entries[0].0.as_slice(), entries[0].1.as_slice()),
                (entries[1].0.as_slice(), entries[1].1.as_slice()),
            ],
        );

        let settlement_descriptor = descriptor_bytes([1u8; 32], 100, [2u8; 32], 200);
        let mut exit_state_header = header_bytes(0, PHASE_ACTIVE);
        if descriptor_commitment_valid {
            exit_state_header[174..206]
                .copy_from_slice(&settlement_descriptor_commitment_v1(&settlement_descriptor));
        } else {
            exit_state_header[174..206].fill(99);
        }
        put_u16(
            &mut exit_state_header,
            206,
            BILATERAL_CKB_DESCRIPTOR_VERSION_V1,
        );

        let (before, after) =
            reduced_exit_rights_pair(reserve_claim_after_quantity, mutate_other_right);
        let mut witness_raw = reduced_exit_witness_raw(
            &key0,
            &key1,
            release_quantity,
            &exit_state_header,
            &settlement_descriptor,
            &before,
            &after,
        );
        let witness = FactoryReducedExitWitnessV1::parse(&witness_raw).unwrap();

        let mut old_raw = factory_header_bytes(1);
        old_raw[76..108].copy_from_slice(&witness.rights_root(false).unwrap());
        old_raw[108..140].copy_from_slice(&participants_commitment);
        old_raw[140..172].copy_from_slice(&witness.access_manifest_root(false).unwrap());
        let old_header = FactoryStateHeaderV1::parse(&old_raw).unwrap();

        let mut new_raw = factory_header_bytes(2);
        new_raw[76..108].copy_from_slice(&witness.rights_root(true).unwrap());
        new_raw[108..140].copy_from_slice(&participants_commitment);
        new_raw[140..172].copy_from_slice(&witness.access_manifest_root(true).unwrap());
        let preliminary_new = FactoryStateHeaderV1::parse(&new_raw).unwrap();
        let digest = witness
            .non_interference_digest(&old_header, &preliminary_new)
            .unwrap();
        new_raw[172..204].copy_from_slice(&digest);
        let new_header = FactoryStateHeaderV1::parse(&new_raw).unwrap();
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
    ) -> [u8; BILATERAL_CKB_DESCRIPTOR_V1_LEN] {
        let mut entries = [
            (left_lock_hash, left_capacity),
            (right_lock_hash, right_capacity),
        ];
        entries.sort_by(|left, right| left.0.cmp(&right.0));

        let mut raw = [0u8; BILATERAL_CKB_DESCRIPTOR_V1_LEN];
        put_u16(&mut raw, 0, BILATERAL_CKB_DESCRIPTOR_VERSION_V1);
        raw[2] = BILATERAL_CKB_DESCRIPTOR_OUTPUT_COUNT_V1;
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
    ) -> [u8; BILATERAL_CKB_XUDT_DESCRIPTOR_V1_LEN] {
        let mut entries = [
            (left_lock_hash, left_capacity, left_amount),
            (right_lock_hash, right_capacity, right_amount),
        ];
        entries.sort_by(|left, right| left.0.cmp(&right.0));

        let mut raw = [0u8; BILATERAL_CKB_XUDT_DESCRIPTOR_V1_LEN];
        put_u16(&mut raw, 0, BILATERAL_CKB_XUDT_DESCRIPTOR_VERSION_V1);
        raw[2] = BILATERAL_CKB_DESCRIPTOR_OUTPUT_COUNT_V1;
        raw[3] = BILATERAL_CKB_XUDT_DESCRIPTOR_ASSET_COUNT_V1;
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

    fn header_bytes(state_number: u64, phase: u8) -> [u8; STATE_HEADER_V1_LEN] {
        let mut raw = [0u8; STATE_HEADER_V1_LEN];
        put_u16(&mut raw, 0, 1);
        raw[2..34].fill(2);
        put_u16(&mut raw, 34, 1);
        raw[36..68].fill(3);
        raw[68..100].fill(4);
        put_u64(&mut raw, 100, state_number);
        raw[108] = 1;
        raw[109] = phase;
        raw[110..142].fill(5);
        raw[142..174].fill(6);
        raw[174..206].fill(7);
        put_u16(&mut raw, 206, 1);
        raw[208..240].fill(8);
        raw[240..272].fill(9);
        put_u16(&mut raw, 272, 1);
        raw
    }

    fn header_v2_bytes(
        state_number: u64,
        phase: u8,
        funding_epoch: u64,
    ) -> [u8; STATE_HEADER_V2_LEN] {
        let mut raw = [0u8; STATE_HEADER_V2_LEN];
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
    ) -> [u8; SPLICE_HEADER_V1_LEN] {
        let mut raw = [0u8; SPLICE_HEADER_V1_LEN];
        put_u16(&mut raw, 0, 1);
        raw[2..34].fill(2);
        put_u16(&mut raw, 34, SIGNATURE_SCHEME_SECP256K1_ECDSA_BLAKE2B_V1);
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
        raw[293..325].fill(9);
        raw
    }

    fn factory_header_bytes(update_number: u64) -> [u8; FACTORY_STATE_HEADER_V1_LEN] {
        let mut raw = [0u8; FACTORY_STATE_HEADER_V1_LEN];
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
    ) -> [u8; SPLICE_VAULT_ASSET_AMOUNT_V2_LEN] {
        let mut raw = [0u8; SPLICE_VAULT_ASSET_AMOUNT_V2_LEN];
        raw[0] = kind;
        if kind == VAULT_ASSET_KIND_XUDT_V1 {
            raw[1..33].fill(type_hash_byte);
        }
        put_u128(&mut raw, 33, amount);
        raw
    }

    fn splice_vault_descriptor_bytes(
        funding_anchor: [u8; BYTE32_LEN],
        asset_count: u16,
        asset_0: &[u8; SPLICE_VAULT_ASSET_AMOUNT_V2_LEN],
        asset_1: &[u8; SPLICE_VAULT_ASSET_AMOUNT_V2_LEN],
    ) -> [u8; SPLICE_VAULT_DESCRIPTOR_V2_LEN] {
        let mut raw = [0u8; SPLICE_VAULT_DESCRIPTOR_V2_LEN];
        raw[0..BYTE32_LEN].copy_from_slice(&funding_anchor);
        put_u16(&mut raw, BYTE32_LEN, asset_count);
        raw[splice_vault_asset_offset(0)
            ..splice_vault_asset_offset(0) + SPLICE_VAULT_ASSET_AMOUNT_V2_LEN]
            .copy_from_slice(asset_0);
        raw[splice_vault_asset_offset(1)
            ..splice_vault_asset_offset(1) + SPLICE_VAULT_ASSET_AMOUNT_V2_LEN]
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
    ) -> [u8; SPLICE_ASSET_DELTA_V1_LEN] {
        let mut raw = [0u8; SPLICE_ASSET_DELTA_V1_LEN];
        raw[0] = kind;
        if kind == VAULT_ASSET_KIND_XUDT_V1 {
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
        delta_0: &[u8; SPLICE_ASSET_DELTA_V1_LEN],
        delta_1: &[u8; SPLICE_ASSET_DELTA_V1_LEN],
    ) -> [u8; SPLICE_ASSET_DELTAS_V1_LEN] {
        let mut raw = [0u8; SPLICE_ASSET_DELTAS_V1_LEN];
        put_u16(&mut raw, 0, delta_count);
        raw[splice_delta_offset(0)..splice_delta_offset(0) + SPLICE_ASSET_DELTA_V1_LEN]
            .copy_from_slice(delta_0);
        raw[splice_delta_offset(1)..splice_delta_offset(1) + SPLICE_ASSET_DELTA_V1_LEN]
            .copy_from_slice(delta_1);
        raw
    }

    fn splice_state_transition_witness_bytes(
        header: &[u8; SPLICE_HEADER_V1_LEN],
        signatures: &[u8; SPLICE_SIGNATURE_WITNESS_V1_LEN],
        old_vault: &[u8; SPLICE_VAULT_DESCRIPTOR_V2_LEN],
        new_vault: &[u8; SPLICE_VAULT_DESCRIPTOR_V2_LEN],
        deltas: &[u8; SPLICE_ASSET_DELTAS_V1_LEN],
    ) -> [u8; SPLICE_STATE_TRANSITION_WITNESS_V1_LEN] {
        let mut raw = [0u8; SPLICE_STATE_TRANSITION_WITNESS_V1_LEN];
        put_u16(&mut raw, 0, SPLICE_STATE_TRANSITION_WITNESS_VERSION_V1);
        raw[splice_transition_header_offset()
            ..splice_transition_header_offset() + SPLICE_HEADER_V1_LEN]
            .copy_from_slice(header);
        raw[splice_transition_signature_offset()
            ..splice_transition_signature_offset() + SPLICE_SIGNATURE_WITNESS_V1_LEN]
            .copy_from_slice(signatures);
        raw[splice_transition_old_vault_offset()
            ..splice_transition_old_vault_offset() + SPLICE_VAULT_DESCRIPTOR_V2_LEN]
            .copy_from_slice(old_vault);
        raw[splice_transition_new_vault_offset()
            ..splice_transition_new_vault_offset() + SPLICE_VAULT_DESCRIPTOR_V2_LEN]
            .copy_from_slice(new_vault);
        raw[splice_transition_deltas_offset()
            ..splice_transition_deltas_offset() + SPLICE_ASSET_DELTAS_V1_LEN]
            .copy_from_slice(deltas);
        raw
    }

    fn factory_vault_asset_bytes(
        kind: u8,
        type_hash_byte: u8,
        amount: u128,
    ) -> [u8; FACTORY_VAULT_ASSET_AMOUNT_V1_LEN] {
        let mut raw = [0u8; FACTORY_VAULT_ASSET_AMOUNT_V1_LEN];
        raw[0] = kind;
        if kind == VAULT_ASSET_KIND_XUDT_V1 {
            raw[1..33].fill(type_hash_byte);
        }
        put_u128(&mut raw, 33, amount);
        raw
    }

    fn factory_vault_descriptor_bytes(
        factory_id: [u8; BYTE32_LEN],
        asset_count: u16,
        asset_0: &[u8; FACTORY_VAULT_ASSET_AMOUNT_V1_LEN],
        asset_1: &[u8; FACTORY_VAULT_ASSET_AMOUNT_V1_LEN],
    ) -> [u8; FACTORY_VAULT_DESCRIPTOR_V1_LEN] {
        let mut raw = [0u8; FACTORY_VAULT_DESCRIPTOR_V1_LEN];
        raw[0..BYTE32_LEN].copy_from_slice(&factory_id);
        put_u16(&mut raw, BYTE32_LEN, asset_count);
        raw[factory_vault_asset_offset(0)
            ..factory_vault_asset_offset(0) + FACTORY_VAULT_ASSET_AMOUNT_V1_LEN]
            .copy_from_slice(asset_0);
        raw[factory_vault_asset_offset(1)
            ..factory_vault_asset_offset(1) + FACTORY_VAULT_ASSET_AMOUNT_V1_LEN]
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
    ) -> [u8; FACTORY_VAULT_DELTA_V1_LEN] {
        let mut raw = [0u8; FACTORY_VAULT_DELTA_V1_LEN];
        raw[0] = kind;
        if kind == VAULT_ASSET_KIND_XUDT_V1 {
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
        delta_0: &[u8; FACTORY_VAULT_DELTA_V1_LEN],
        delta_1: &[u8; FACTORY_VAULT_DELTA_V1_LEN],
    ) -> [u8; FACTORY_VAULT_DELTAS_V1_LEN] {
        let mut raw = [0u8; FACTORY_VAULT_DELTAS_V1_LEN];
        put_u16(&mut raw, 0, delta_count);
        raw[factory_vault_delta_offset(0)
            ..factory_vault_delta_offset(0) + FACTORY_VAULT_DELTA_V1_LEN]
            .copy_from_slice(delta_0);
        raw[factory_vault_delta_offset(1)
            ..factory_vault_delta_offset(1) + FACTORY_VAULT_DELTA_V1_LEN]
            .copy_from_slice(delta_1);
        raw
    }

    fn factory_splice_header_bytes(
        kind: u8,
        old_header: &FactoryStateHeaderV1,
        new_header: &FactoryStateHeaderV1,
        participants_commitment: &[u8; BYTE32_LEN],
        vault_delta_commitment: &[u8; BYTE32_LEN],
    ) -> [u8; FACTORY_SPLICE_HEADER_V1_LEN] {
        let mut raw = [0u8; FACTORY_SPLICE_HEADER_V1_LEN];
        put_u16(&mut raw, 0, 1);
        raw[2..34].copy_from_slice(old_header.factory_id());
        put_u64(&mut raw, 34, old_header.update_number());
        put_u64(&mut raw, 42, new_header.update_number());
        raw[50..82].copy_from_slice(old_header.state_root());
        raw[82..114].copy_from_slice(new_header.state_root());
        raw[114..146].copy_from_slice(old_header.access_manifest_root());
        raw[146..178].copy_from_slice(new_header.access_manifest_root());
        raw[178] = kind;
        raw[179..211].copy_from_slice(vault_delta_commitment);
        raw[211..243].copy_from_slice(new_header.non_interference_digest());
        raw[243..275].copy_from_slice(participants_commitment);
        raw
    }

    fn factory_splice_witness_bytes(
        header: &[u8; FACTORY_SPLICE_HEADER_V1_LEN],
        signatures: &[u8; FACTORY_SIGNATURE_WITNESS_V1_LEN],
        old_vault: &[u8; FACTORY_VAULT_DESCRIPTOR_V1_LEN],
        new_vault: &[u8; FACTORY_VAULT_DESCRIPTOR_V1_LEN],
        deltas: &[u8; FACTORY_VAULT_DELTAS_V1_LEN],
    ) -> [u8; FACTORY_SPLICE_WITNESS_V1_LEN] {
        let mut raw = [0u8; FACTORY_SPLICE_WITNESS_V1_LEN];
        put_u16(&mut raw, 0, FACTORY_SPLICE_WITNESS_VERSION_V1);
        raw[factory_splice_header_offset()
            ..factory_splice_header_offset() + FACTORY_SPLICE_HEADER_V1_LEN]
            .copy_from_slice(header);
        raw[factory_splice_signature_offset()
            ..factory_splice_signature_offset() + FACTORY_SIGNATURE_WITNESS_V1_LEN]
            .copy_from_slice(signatures);
        raw[factory_splice_old_vault_offset()
            ..factory_splice_old_vault_offset() + FACTORY_VAULT_DESCRIPTOR_V1_LEN]
            .copy_from_slice(old_vault);
        raw[factory_splice_new_vault_offset()
            ..factory_splice_new_vault_offset() + FACTORY_VAULT_DESCRIPTOR_V1_LEN]
            .copy_from_slice(new_vault);
        raw[factory_splice_deltas_offset()
            ..factory_splice_deltas_offset() + FACTORY_VAULT_DELTAS_V1_LEN]
            .copy_from_slice(deltas);
        raw
    }

    fn factory_reduced_splice_witness_bytes(
        header: &[u8; FACTORY_SPLICE_HEADER_V1_LEN],
        merkle_update: &[u8; FACTORY_MERKLE_UPDATE_WITNESS_V1_LEN],
        old_vault: &[u8; FACTORY_VAULT_DESCRIPTOR_V1_LEN],
        new_vault: &[u8; FACTORY_VAULT_DESCRIPTOR_V1_LEN],
        deltas: &[u8; FACTORY_VAULT_DELTAS_V1_LEN],
    ) -> [u8; FACTORY_REDUCED_SPLICE_WITNESS_V1_LEN] {
        let mut raw = [0u8; FACTORY_REDUCED_SPLICE_WITNESS_V1_LEN];
        put_u16(&mut raw, 0, FACTORY_REDUCED_SPLICE_WITNESS_VERSION_V1);
        raw[factory_reduced_splice_header_offset()
            ..factory_reduced_splice_header_offset() + FACTORY_SPLICE_HEADER_V1_LEN]
            .copy_from_slice(header);
        raw[factory_reduced_splice_merkle_offset()
            ..factory_reduced_splice_merkle_offset() + FACTORY_MERKLE_UPDATE_WITNESS_V1_LEN]
            .copy_from_slice(merkle_update);
        raw[factory_reduced_splice_old_vault_offset()
            ..factory_reduced_splice_old_vault_offset() + FACTORY_VAULT_DESCRIPTOR_V1_LEN]
            .copy_from_slice(old_vault);
        raw[factory_reduced_splice_new_vault_offset()
            ..factory_reduced_splice_new_vault_offset() + FACTORY_VAULT_DESCRIPTOR_V1_LEN]
            .copy_from_slice(new_vault);
        raw[factory_reduced_splice_deltas_offset()
            ..factory_reduced_splice_deltas_offset() + FACTORY_VAULT_DELTAS_V1_LEN]
            .copy_from_slice(deltas);
        raw
    }

    fn factory_splice_headers_and_witness(
        kind: u8,
    ) -> (
        [u8; FACTORY_STATE_HEADER_V1_LEN],
        [u8; FACTORY_STATE_HEADER_V1_LEN],
        [u8; FACTORY_SPLICE_WITNESS_V1_LEN],
    ) {
        let key0 = signing_key(1);
        let key1 = signing_key(2);
        let mut entries = [([1u8; 32], pubkey(&key0)), ([2u8; 32], pubkey(&key1))];
        entries.sort_by(|left, right| left.0.cmp(&right.0));
        let factory_participants = factory_participants_commitment_v1(
            2,
            &[
                (entries[0].0.as_slice(), entries[0].1.as_slice()),
                (entries[1].0.as_slice(), entries[1].1.as_slice()),
            ],
        );
        let splice_participants =
            participants_commitment_v1(2, &[entries[0].1.as_slice(), entries[1].1.as_slice()]);

        let mut old_raw = factory_header_bytes(1);
        old_raw[108..140].copy_from_slice(&factory_participants);
        let mut new_raw = factory_header_bytes(2);
        new_raw[76..108].fill(9);
        new_raw[108..140].copy_from_slice(&factory_participants);
        new_raw[140..172].fill(10);
        new_raw[172..204].fill(11);
        let old_header = FactoryStateHeaderV1::parse(&old_raw).unwrap();
        let new_header = FactoryStateHeaderV1::parse(&new_raw).unwrap();

        let (old_amount, new_amount, external_input, withdrawal) = match kind {
            SPLICE_KIND_IN_V1 => (50, 70, 20, 0),
            SPLICE_KIND_OUT_V1 => (50, 30, 0, 20),
            _ => unreachable!(),
        };
        let old_asset = factory_vault_asset_bytes(VAULT_ASSET_KIND_CKB_V1, 0, old_amount);
        let new_asset = factory_vault_asset_bytes(VAULT_ASSET_KIND_CKB_V1, 0, new_amount);
        let old_vault =
            factory_vault_descriptor_bytes([3u8; BYTE32_LEN], 1, &old_asset, &[0u8; 49]);
        let new_vault =
            factory_vault_descriptor_bytes([3u8; BYTE32_LEN], 1, &new_asset, &[0u8; 49]);
        let delta = factory_vault_delta_bytes(
            VAULT_ASSET_KIND_CKB_V1,
            0,
            old_amount,
            new_amount,
            external_input,
            withdrawal,
        );
        let deltas = factory_vault_deltas_bytes(1, &delta, &[0u8; 97]);
        let delta_commitment = FactoryVaultDeltasV1::parse(&deltas)
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
        let splice_header = FactorySpliceHeaderV1::parse(&header).unwrap();
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
        [u8; FACTORY_STATE_HEADER_V1_LEN],
        [u8; FACTORY_STATE_HEADER_V1_LEN],
        [u8; FACTORY_REDUCED_SPLICE_WITNESS_V1_LEN],
    ) {
        let key0 = signing_key(1);
        let key1 = signing_key(2);
        let mut entries = [([1u8; 32], pubkey(&key0)), ([2u8; 32], pubkey(&key1))];
        entries.sort_by(|left, right| left.0.cmp(&right.0));
        let factory_participants = factory_participants_commitment_v1(
            2,
            &[
                (entries[0].0.as_slice(), entries[0].1.as_slice()),
                (entries[1].0.as_slice(), entries[1].1.as_slice()),
            ],
        );
        let splice_participants =
            participants_commitment_v1(2, &[entries[0].1.as_slice(), entries[1].1.as_slice()]);

        let (old_amount, new_amount, external_input, withdrawal) = match kind {
            SPLICE_KIND_IN_V1 => (50, 70, 20, 0),
            SPLICE_KIND_OUT_V1 => (50, 30, 0, 20),
            _ => unreachable!(),
        };

        let mut merkle_raw = [0u8; FACTORY_MERKLE_UPDATE_WITNESS_V1_LEN];
        put_u16(&mut merkle_raw, 0, FACTORY_MERKLE_UPDATE_WITNESS_VERSION_V1);
        merkle_raw[2] = FACTORY_REDUCED_RIGHTS_PARTICIPANT_THRESHOLD_V1;
        merkle_raw[3] = FACTORY_REDUCED_RIGHTS_PARTICIPANT_COUNT_V1;
        merkle_raw[4] = FACTORY_REDUCED_RIGHTS_AUTHORISED_COUNT_V1;
        merkle_raw[5] = FACTORY_MERKLE_UPDATE_RIGHT_COUNT_V1;
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
            ..factory_merkle_right_offset(false) + FACTORY_RIGHT_V1_LEN]
            .copy_from_slice(&factory_right_bytes(
                1,
                10,
                FACTORY_RIGHT_KIND_RESERVE_CLAIM,
                old_amount,
            ));
        merkle_raw[factory_merkle_right_offset(true)
            ..factory_merkle_right_offset(true) + FACTORY_RIGHT_V1_LEN]
            .copy_from_slice(&factory_right_bytes(
                1,
                10,
                FACTORY_RIGHT_KIND_RESERVE_CLAIM,
                new_amount,
            ));
        for depth in 0..FACTORY_SPARSE_MERKLE_DEPTH_V1 {
            let offset = factory_merkle_sibling_offset(depth);
            merkle_raw[offset..offset + BYTE32_LEN].fill(depth as u8);
        }
        let merkle_witness = FactoryMerkleUpdateWitnessV1::parse(&merkle_raw).unwrap();

        let mut old_raw = factory_header_bytes(1);
        old_raw[76..108].copy_from_slice(&merkle_witness.rights_root(false).unwrap());
        old_raw[108..140].copy_from_slice(&factory_participants);
        old_raw[140..172].fill(10);
        let old_header = FactoryStateHeaderV1::parse(&old_raw).unwrap();

        let mut new_raw = factory_header_bytes(2);
        new_raw[76..108].copy_from_slice(&merkle_witness.rights_root(true).unwrap());
        new_raw[108..140].copy_from_slice(&factory_participants);
        new_raw[140..172].copy_from_slice(old_header.access_manifest_root());
        let preliminary_new = FactoryStateHeaderV1::parse(&new_raw).unwrap();
        let digest = merkle_witness
            .non_interference_digest(&old_header, &preliminary_new)
            .unwrap();
        new_raw[172..204].copy_from_slice(&digest);
        let new_header = FactoryStateHeaderV1::parse(&new_raw).unwrap();

        let old_asset = factory_vault_asset_bytes(VAULT_ASSET_KIND_CKB_V1, 0, old_amount);
        let new_asset = factory_vault_asset_bytes(VAULT_ASSET_KIND_CKB_V1, 0, new_amount);
        let old_vault =
            factory_vault_descriptor_bytes([3u8; BYTE32_LEN], 1, &old_asset, &[0u8; 49]);
        let new_vault =
            factory_vault_descriptor_bytes([3u8; BYTE32_LEN], 1, &new_asset, &[0u8; 49]);
        let delta = factory_vault_delta_bytes(
            VAULT_ASSET_KIND_CKB_V1,
            0,
            old_amount,
            new_amount,
            external_input,
            withdrawal,
        );
        let deltas = factory_vault_deltas_bytes(1, &delta, &[0u8; 97]);
        let delta_commitment = FactoryVaultDeltasV1::parse(&deltas)
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
        let splice_header = FactorySpliceHeaderV1::parse(&header).unwrap();
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
            StateHeaderV1::parse(&[0u8; STATE_HEADER_V1_LEN - 1]).unwrap_err(),
            ScriptError::Encoding
        );
    }

    #[test]
    fn state_header_fields_are_fixed_width() {
        let raw = header_bytes(42, PHASE_SETTLING);
        let header = StateHeaderV1::parse(&raw).unwrap();

        assert_eq!(header.protocol_version(), 1);
        assert_eq!(header.chain_id(), &[2u8; 32]);
        assert_eq!(header.signature_scheme_id(), 1);
        assert_eq!(header.channel_id(), &[3u8; 32]);
        assert_eq!(header.funding_anchor(), &[4u8; 32]);
        assert_eq!(header.state_number(), 42);
        assert_eq!(header.mode(), 1);
        assert_eq!(header.phase(), PHASE_SETTLING);
        assert_eq!(header.participants_commitment(), &[5u8; 32]);
        assert_eq!(header.asset_registry_commitment(), &[6u8; 32]);
        assert_eq!(header.settlement_descriptor_commitment(), &[7u8; 32]);
        assert_eq!(header.descriptor_version(), 1);
        assert_eq!(header.payload_commitment(), &[8u8; 32]);
        assert_eq!(header.challenge_policy_commitment(), &[9u8; 32]);
        assert_eq!(header.state_layout_version(), 1);
    }

    #[test]
    fn state_header_v2_parser_rejects_wrong_length() {
        assert_eq!(
            StateHeaderV2::parse(&[0u8; STATE_HEADER_V2_LEN - 1]).unwrap_err(),
            ScriptError::Encoding
        );
    }

    #[test]
    fn state_header_v2_fields_are_fixed_width() {
        let raw = header_v2_bytes(42, PHASE_SETTLING, 3);
        let header = StateHeaderV2::parse(&raw).unwrap();

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
    fn state_context_allows_progress_but_rejects_identity_change() {
        let old_raw = header_bytes(1, 1);
        let mut new_raw = header_bytes(9, PHASE_SETTLING);
        new_raw[208..240].fill(10);

        let old = StateHeaderV1::parse(&old_raw).unwrap();
        let new = StateHeaderV1::parse(&new_raw).unwrap();
        assert!(old.same_context_except_progress(&new));

        new_raw[174] = 11;
        let changed_descriptor = StateHeaderV1::parse(&new_raw).unwrap();
        assert!(old.same_context_except_progress(&changed_descriptor));

        new_raw[68] = 99;
        let changed_anchor = StateHeaderV1::parse(&new_raw).unwrap();
        assert!(!old.same_context_except_progress(&changed_anchor));
    }

    #[test]
    fn state_header_v2_context_binds_epoch_and_vault_set() {
        let old_raw = header_v2_bytes(1, 1, 7);
        let mut new_raw = header_v2_bytes(9, PHASE_SETTLING, 7);
        new_raw[214..246].fill(11);
        new_raw[248..280].fill(12);

        let old = StateHeaderV2::parse(&old_raw).unwrap();
        let new = StateHeaderV2::parse(&new_raw).unwrap();
        assert!(old.same_context_except_progress(&new));

        new_raw[68] = 8;
        let changed_epoch = StateHeaderV2::parse(&new_raw).unwrap();
        assert!(!old.same_context_except_progress(&changed_epoch));

        let mut changed_vault_raw = header_v2_bytes(9, PHASE_SETTLING, 7);
        changed_vault_raw[108] = 99;
        let changed_vault_set = StateHeaderV2::parse(&changed_vault_raw).unwrap();
        assert!(!old.same_context_except_progress(&changed_vault_set));
    }

    #[test]
    fn state_header_v2_digest_is_domain_and_epoch_separated() {
        let mut raw = header_v2_bytes(42, PHASE_SETTLING, 1);
        let header = StateHeaderV2::parse(&raw).unwrap();
        let digest_epoch_1 = header.signing_digest();

        put_u64(&mut raw, 68, 2);
        let header_epoch_2 = StateHeaderV2::parse(&raw).unwrap();
        assert_ne!(digest_epoch_1, header_epoch_2.signing_digest());

        let v1 = header_bytes(42, PHASE_SETTLING);
        let v1_header = StateHeaderV1::parse(&v1).unwrap();
        assert_ne!(digest_epoch_1, v1_header.signing_digest());
    }

    #[test]
    fn factory_state_header_fields_are_fixed_width() {
        let raw = factory_header_bytes(42);
        let header = FactoryStateHeaderV1::parse(&raw).unwrap();

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

        let old = FactoryStateHeaderV1::parse(&old_raw).unwrap();
        let new = FactoryStateHeaderV1::parse(&new_raw).unwrap();
        assert!(old.same_context_except_progress(&new));

        new_raw[36] = 99;
        let changed_factory = FactoryStateHeaderV1::parse(&new_raw).unwrap();
        assert!(!old.same_context_except_progress(&changed_factory));
    }

    #[test]
    fn splice_header_fields_are_fixed_width_and_match_current_state() {
        let key0 = SigningKey::from_slice(&[1u8; 32]).unwrap();
        let key1 = SigningKey::from_slice(&[2u8; 32]).unwrap();
        let mut pubkeys = [pubkey(&key0), pubkey(&key1)];
        pubkeys.sort();
        let participant_refs = [pubkeys[0].as_slice(), pubkeys[1].as_slice()];
        let participants = participants_commitment_v1(2, &participant_refs);
        let raw = splice_header_bytes(
            SPLICE_KIND_IN_V1,
            7,
            &participants,
            &[11u8; BYTE32_LEN],
            &[12u8; BYTE32_LEN],
            &[13u8; BYTE32_LEN],
        );
        let header = SpliceHeaderV1::parse(&raw).unwrap();

        assert_eq!(header.protocol_version(), 1);
        assert_eq!(header.chain_id(), &[2u8; BYTE32_LEN]);
        assert_eq!(
            header.signature_scheme_id(),
            SIGNATURE_SCHEME_SECP256K1_ECDSA_BLAKE2B_V1
        );
        assert_eq!(header.channel_id(), &[3u8; BYTE32_LEN]);
        assert_eq!(header.old_funding_anchor(), &[4u8; BYTE32_LEN]);
        assert_eq!(header.new_funding_anchor(), &[10u8; BYTE32_LEN]);
        assert_eq!(header.old_funding_epoch(), 0);
        assert_eq!(header.new_funding_epoch(), 1);
        assert_eq!(header.base_state_number(), 7);
        assert_eq!(header.splice_number(), 1);
        assert_eq!(header.kind(), SPLICE_KIND_IN_V1);
        assert_eq!(header.old_vault_commitment(), &[11u8; BYTE32_LEN]);
        assert_eq!(header.new_vault_commitment(), &[12u8; BYTE32_LEN]);
        assert_eq!(header.asset_delta_commitment(), &[13u8; BYTE32_LEN]);
        assert_eq!(header.participants_commitment(), participants.as_slice());
        assert_eq!(header.challenge_policy_commitment(), &[9u8; BYTE32_LEN]);

        let mut state_raw = header_bytes(7, PHASE_ACTIVE);
        state_raw[110..142].copy_from_slice(&participants);
        let current = StateHeaderV1::parse(&state_raw).unwrap();
        assert!(header.matches_current_state(&current));

        let mut state_v2_raw = header_v2_bytes(7, PHASE_ACTIVE, 0);
        state_v2_raw[108..140].copy_from_slice(header.old_vault_commitment());
        state_v2_raw[150..182].copy_from_slice(&participants);
        let current_v2 = StateHeaderV2::parse(&state_v2_raw).unwrap();
        assert!(header.matches_current_state_v2(&current_v2));

        state_v2_raw[68] = 1;
        let changed_epoch_v2 = StateHeaderV2::parse(&state_v2_raw).unwrap();
        assert!(!header.matches_current_state_v2(&changed_epoch_v2));

        state_raw[68] = 99;
        let changed_anchor = StateHeaderV1::parse(&state_raw).unwrap();
        assert!(!header.matches_current_state(&changed_anchor));
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
        );

        assert_eq!(
            SpliceHeaderV1::parse(&raw).unwrap_err(),
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
        let participants = participants_commitment_v1(2, &participant_refs);
        let raw = splice_header_bytes(
            SPLICE_KIND_IN_V1,
            7,
            &participants,
            &[11u8; BYTE32_LEN],
            &[12u8; BYTE32_LEN],
            &[13u8; BYTE32_LEN],
        );
        let header = SpliceHeaderV1::parse(&raw).unwrap();
        let witness_raw = signed_bilateral_witness(&key0, &key1, &header.signing_digest());
        let witness = SpliceSignatureWitnessV1::parse(&witness_raw).unwrap();

        verify_splice_signatures(&header, &witness).unwrap();

        let mut tampered_witness_raw = witness_raw;
        tampered_witness_raw[SPLICE_SIGNATURE_WITNESS_V1_LEN - 1] ^= 1;
        let tampered = SpliceSignatureWitnessV1::parse(&tampered_witness_raw).unwrap();
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
        let participants = participants_commitment_v1(2, &participant_refs);

        let old_ckb = splice_vault_asset_bytes(VAULT_ASSET_KIND_CKB_V1, 0, 10_000);
        let old_xudt = splice_vault_asset_bytes(VAULT_ASSET_KIND_XUDT_V1, 42, 50);
        let old_vault_raw =
            splice_vault_descriptor_bytes([4u8; BYTE32_LEN], 2, &old_ckb, &old_xudt);
        let old_vault = SpliceVaultDescriptorV2::parse(&old_vault_raw).unwrap();

        let new_ckb = splice_vault_asset_bytes(VAULT_ASSET_KIND_CKB_V1, 0, 14_900);
        let new_xudt = splice_vault_asset_bytes(VAULT_ASSET_KIND_XUDT_V1, 42, 60);
        let new_vault_raw =
            splice_vault_descriptor_bytes([10u8; BYTE32_LEN], 2, &new_ckb, &new_xudt);
        let new_vault = SpliceVaultDescriptorV2::parse(&new_vault_raw).unwrap();

        let ckb_delta =
            splice_asset_delta_bytes(VAULT_ASSET_KIND_CKB_V1, 0, 10_000, 14_900, 5_000, 0, 100);
        let xudt_delta = splice_asset_delta_bytes(VAULT_ASSET_KIND_XUDT_V1, 42, 50, 60, 10, 0, 0);
        let deltas_raw = splice_asset_deltas_bytes(2, &ckb_delta, &xudt_delta);
        let deltas = SpliceAssetDeltasV1::parse(&deltas_raw).unwrap();

        let splice_header_raw = splice_header_bytes(
            SPLICE_KIND_IN_V1,
            7,
            &participants,
            &old_vault.commitment().unwrap(),
            &new_vault.commitment().unwrap(),
            &deltas.commitment().unwrap(),
        );
        let splice_header = SpliceHeaderV1::parse(&splice_header_raw).unwrap();
        let witness_raw = signed_bilateral_witness(&key0, &key1, &splice_header.signing_digest());
        let witness = SpliceSignatureWitnessV1::parse(&witness_raw).unwrap();

        let mut current_raw = header_bytes(7, PHASE_ACTIVE);
        current_raw[110..142].copy_from_slice(&participants);
        let current = StateHeaderV1::parse(&current_raw).unwrap();

        let mut next_raw = header_bytes(7, PHASE_ACTIVE);
        next_raw[68..100].fill(10);
        next_raw[110..142].copy_from_slice(&participants);
        let next = StateHeaderV1::parse(&next_raw).unwrap();

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
        assert_eq!(SPLICE_STATE_TRANSITION_WITNESS_V1_LEN, 1017);
        let bundle = SpliceStateTransitionWitnessV1::parse(&bundle_raw).unwrap();
        assert_eq!(bundle.version(), SPLICE_STATE_TRANSITION_WITNESS_VERSION_V1);
        assert_eq!(bundle.raw().len(), SPLICE_STATE_TRANSITION_WITNESS_V1_LEN);
        assert_eq!(bundle.header().unwrap().kind(), SPLICE_KIND_IN_V1);
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
            SpliceStateTransitionWitnessV1::parse(&wrong_version).unwrap_err(),
            ScriptError::SpliceProofEncoding
        );

        let mut bad_nested_header = bundle_raw;
        bad_nested_header[splice_transition_header_offset() + 164] = 99;
        let bad_bundle = SpliceStateTransitionWitnessV1::parse(&bad_nested_header).unwrap();
        assert_eq!(
            verify_splice_state_transition_bundle(&current, &next, &bad_bundle).unwrap_err(),
            ScriptError::SpliceProofEncoding
        );
    }

    #[test]
    fn verifies_splice_state_transition_v2_epoch_bridge() {
        let key0 = SigningKey::from_slice(&[1u8; 32]).unwrap();
        let key1 = SigningKey::from_slice(&[2u8; 32]).unwrap();
        let mut pubkeys = [pubkey(&key0), pubkey(&key1)];
        pubkeys.sort();
        let participant_refs = [pubkeys[0].as_slice(), pubkeys[1].as_slice()];
        let participants = participants_commitment_v1(2, &participant_refs);

        let old_ckb = splice_vault_asset_bytes(VAULT_ASSET_KIND_CKB_V1, 0, 10_000);
        let old_vault_raw =
            splice_vault_descriptor_bytes([4u8; BYTE32_LEN], 1, &old_ckb, &[0u8; 49]);
        let old_vault = SpliceVaultDescriptorV2::parse(&old_vault_raw).unwrap();

        let new_ckb = splice_vault_asset_bytes(VAULT_ASSET_KIND_CKB_V1, 0, 14_900);
        let new_vault_raw =
            splice_vault_descriptor_bytes([10u8; BYTE32_LEN], 1, &new_ckb, &[0u8; 49]);
        let new_vault = SpliceVaultDescriptorV2::parse(&new_vault_raw).unwrap();

        let ckb_delta =
            splice_asset_delta_bytes(VAULT_ASSET_KIND_CKB_V1, 0, 10_000, 14_900, 5_000, 0, 100);
        let deltas_raw =
            splice_asset_deltas_bytes(1, &ckb_delta, &[0u8; SPLICE_ASSET_DELTA_V1_LEN]);
        let deltas = SpliceAssetDeltasV1::parse(&deltas_raw).unwrap();

        let splice_header_raw = splice_header_bytes(
            SPLICE_KIND_IN_V1,
            7,
            &participants,
            &old_vault.commitment().unwrap(),
            &new_vault.commitment().unwrap(),
            &deltas.commitment().unwrap(),
        );
        let splice_header = SpliceHeaderV1::parse(&splice_header_raw).unwrap();
        let witness_raw = signed_bilateral_witness(&key0, &key1, &splice_header.signing_digest());
        let witness = SpliceSignatureWitnessV1::parse(&witness_raw).unwrap();

        let mut current_raw = header_v2_bytes(7, PHASE_ACTIVE, 0);
        current_raw[108..140].copy_from_slice(&old_vault.commitment().unwrap());
        current_raw[150..182].copy_from_slice(&participants);
        let current = StateHeaderV2::parse(&current_raw).unwrap();

        let mut next_raw = header_v2_bytes(7, PHASE_ACTIVE, 1);
        next_raw[76..108].fill(10);
        next_raw[108..140].copy_from_slice(&new_vault.commitment().unwrap());
        next_raw[150..182].copy_from_slice(&participants);
        let next = StateHeaderV2::parse(&next_raw).unwrap();

        verify_splice_state_transition_v2(
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
        let bundle = SpliceStateTransitionWitnessV1::parse(&bundle_raw).unwrap();
        verify_splice_state_transition_bundle_v2(&current, &next, &bundle).unwrap();

        let mut stale_next_raw = next_raw;
        put_u64(&mut stale_next_raw, 68, 0);
        let stale_next = StateHeaderV2::parse(&stale_next_raw).unwrap();
        assert_eq!(
            verify_splice_state_transition_bundle_v2(&current, &stale_next, &bundle).unwrap_err(),
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
        let participants = participants_commitment_v1(2, &participant_refs);

        let old_ckb = splice_vault_asset_bytes(VAULT_ASSET_KIND_CKB_V1, 0, 10_000);
        let new_ckb = splice_vault_asset_bytes(VAULT_ASSET_KIND_CKB_V1, 0, 7_000);
        let old_vault_raw =
            splice_vault_descriptor_bytes([4u8; BYTE32_LEN], 1, &old_ckb, &[0u8; 49]);
        let old_vault = SpliceVaultDescriptorV2::parse(&old_vault_raw).unwrap();
        let new_vault_raw =
            splice_vault_descriptor_bytes([10u8; BYTE32_LEN], 1, &new_ckb, &[0u8; 49]);
        let new_vault = SpliceVaultDescriptorV2::parse(&new_vault_raw).unwrap();
        let delta =
            splice_asset_delta_bytes(VAULT_ASSET_KIND_CKB_V1, 0, 10_000, 7_000, 0, 3_000, 0);
        let deltas_raw = splice_asset_deltas_bytes(1, &delta, &[0u8; SPLICE_ASSET_DELTA_V1_LEN]);
        let deltas = SpliceAssetDeltasV1::parse(&deltas_raw).unwrap();

        let splice_header_raw = splice_header_bytes(
            SPLICE_KIND_OUT_V1,
            7,
            &participants,
            &old_vault.commitment().unwrap(),
            &new_vault.commitment().unwrap(),
            &deltas.commitment().unwrap(),
        );
        let splice_header = SpliceHeaderV1::parse(&splice_header_raw).unwrap();
        let witness_raw = signed_bilateral_witness(&key0, &key1, &splice_header.signing_digest());
        let witness = SpliceSignatureWitnessV1::parse(&witness_raw).unwrap();

        let mut current_raw = header_bytes(7, PHASE_ACTIVE);
        current_raw[110..142].copy_from_slice(&participants);
        let current = StateHeaderV1::parse(&current_raw).unwrap();
        let mut next_raw = header_bytes(7, PHASE_ACTIVE);
        next_raw[68..100].fill(11);
        next_raw[110..142].copy_from_slice(&participants);
        let next = StateHeaderV1::parse(&next_raw).unwrap();

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
        let participants = participants_commitment_v1(2, &participant_refs);

        let old_ckb = splice_vault_asset_bytes(VAULT_ASSET_KIND_CKB_V1, 0, 10_000);
        let old_vault_raw =
            splice_vault_descriptor_bytes([4u8; BYTE32_LEN], 1, &old_ckb, &[0u8; 49]);
        let old_vault = SpliceVaultDescriptorV2::parse(&old_vault_raw).unwrap();
        let new_ckb = splice_vault_asset_bytes(VAULT_ASSET_KIND_CKB_V1, 0, 7_001);
        let new_vault_raw =
            splice_vault_descriptor_bytes([10u8; BYTE32_LEN], 1, &new_ckb, &[0u8; 49]);
        let new_vault = SpliceVaultDescriptorV2::parse(&new_vault_raw).unwrap();
        let delta =
            splice_asset_delta_bytes(VAULT_ASSET_KIND_CKB_V1, 0, 10_000, 7_000, 0, 3_000, 0);
        let deltas_raw = splice_asset_deltas_bytes(1, &delta, &[0u8; SPLICE_ASSET_DELTA_V1_LEN]);
        let deltas = SpliceAssetDeltasV1::parse(&deltas_raw).unwrap();

        let splice_header_raw = splice_header_bytes(
            SPLICE_KIND_OUT_V1,
            7,
            &participants,
            &old_vault.commitment().unwrap(),
            &new_vault.commitment().unwrap(),
            &deltas.commitment().unwrap(),
        );
        let splice_header = SpliceHeaderV1::parse(&splice_header_raw).unwrap();
        let witness_raw = signed_bilateral_witness(&key0, &key1, &splice_header.signing_digest());
        let witness = SpliceSignatureWitnessV1::parse(&witness_raw).unwrap();

        let mut current_raw = header_bytes(7, PHASE_ACTIVE);
        current_raw[110..142].copy_from_slice(&participants);
        let current = StateHeaderV1::parse(&current_raw).unwrap();
        let mut next_raw = header_bytes(7, PHASE_ACTIVE);
        next_raw[68..100].fill(10);
        next_raw[110..142].copy_from_slice(&participants);
        let next = StateHeaderV1::parse(&next_raw).unwrap();

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
        let ckb = splice_vault_asset_bytes(VAULT_ASSET_KIND_CKB_V1, 0, 10_000);
        let xudt = splice_vault_asset_bytes(VAULT_ASSET_KIND_XUDT_V1, 42, 50);
        let raw = splice_vault_descriptor_bytes([4u8; BYTE32_LEN], 2, &ckb, &xudt);
        let descriptor = SpliceVaultDescriptorV2::parse(&raw).unwrap();

        assert_eq!(descriptor.funding_anchor(), &[4u8; BYTE32_LEN]);
        assert_eq!(descriptor.asset_count(), 2);
        assert_eq!(
            descriptor.asset(0).unwrap().asset_kind(),
            VAULT_ASSET_KIND_CKB_V1
        );
        assert_eq!(
            descriptor.asset(1).unwrap().asset_kind(),
            VAULT_ASSET_KIND_XUDT_V1
        );
        assert_eq!(
            descriptor.commitment().unwrap(),
            blake2b256(&[
                VAULT_DESCRIPTOR_DOMAIN_V2,
                &[4u8; BYTE32_LEN],
                &2u16.to_le_bytes(),
                &ckb,
                &xudt
            ])
        );

        let wrong_order = splice_vault_descriptor_bytes([4u8; BYTE32_LEN], 2, &xudt, &ckb);
        assert_eq!(
            SpliceVaultDescriptorV2::parse(&wrong_order).unwrap_err(),
            ScriptError::Encoding
        );
    }

    #[test]
    fn splice_asset_delta_commitment_is_counted_and_ordered() {
        let ckb =
            splice_asset_delta_bytes(VAULT_ASSET_KIND_CKB_V1, 0, 10_000, 14_900, 5_000, 0, 100);
        let xudt = splice_asset_delta_bytes(VAULT_ASSET_KIND_XUDT_V1, 42, 50, 60, 10, 0, 0);
        let raw = splice_asset_deltas_bytes(2, &ckb, &xudt);
        let deltas = SpliceAssetDeltasV1::parse(&raw).unwrap();

        assert_eq!(deltas.delta_count(), 2);
        assert_eq!(deltas.delta(0).unwrap().old_amount(), 10_000);
        assert_eq!(deltas.delta(0).unwrap().new_amount(), 14_900);
        assert_eq!(deltas.delta(0).unwrap().external_input(), 5_000);
        assert_eq!(deltas.delta(0).unwrap().withdrawal(), 0);
        assert_eq!(deltas.delta(0).unwrap().signed_fee(), 100);
        assert_eq!(deltas.delta(1).unwrap().asset_type(), &[42u8; BYTE32_LEN]);
        assert_eq!(
            deltas.commitment().unwrap(),
            blake2b256(&[SPLICE_DELTA_DOMAIN_V1, &2u16.to_le_bytes(), &ckb, &xudt])
        );

        let wrong_order = splice_asset_deltas_bytes(2, &xudt, &ckb);
        assert_eq!(
            SpliceAssetDeltasV1::parse(&wrong_order).unwrap_err(),
            ScriptError::Encoding
        );
    }

    #[test]
    fn splice_fixed_width_vectors_require_zero_unused_slots() {
        let ckb = splice_vault_asset_bytes(VAULT_ASSET_KIND_CKB_V1, 0, 10_000);
        let xudt = splice_vault_asset_bytes(VAULT_ASSET_KIND_XUDT_V1, 42, 50);
        let descriptor = splice_vault_descriptor_bytes([4u8; BYTE32_LEN], 1, &ckb, &xudt);
        assert_eq!(
            SpliceVaultDescriptorV2::parse(&descriptor).unwrap_err(),
            ScriptError::Encoding
        );

        let ckb_delta =
            splice_asset_delta_bytes(VAULT_ASSET_KIND_CKB_V1, 0, 10_000, 14_900, 5_000, 0, 100);
        let xudt_delta = splice_asset_delta_bytes(VAULT_ASSET_KIND_XUDT_V1, 42, 50, 60, 10, 0, 0);
        let deltas = splice_asset_deltas_bytes(1, &ckb_delta, &xudt_delta);
        assert_eq!(
            SpliceAssetDeltasV1::parse(&deltas).unwrap_err(),
            ScriptError::Encoding
        );
    }

    #[test]
    fn sponsor_policy_fields_are_fixed_width() {
        let mut raw = [0u8; SPONSOR_POLICY_V1_LEN];
        raw[0..32].fill(1);
        put_u64(&mut raw, 32, 10);
        put_u64(&mut raw, 40, 20);
        put_u64(&mut raw, 48, 30);
        put_u64(&mut raw, 56, 40);
        put_u64(&mut raw, 64, 50);
        put_u64(&mut raw, 72, 60);
        raw[80..112].fill(2);
        raw[112..144].fill(3);

        let policy = SponsorPolicyV1::parse(&raw).unwrap();
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
    fn molecule_schema_names_all_active_fixed_width_v1_objects() {
        let schema = include_str!("../../../schemas/morph.mol");
        for expected in [
            "StateHeaderV1: 274 bytes",
            "StateHeaderV2: 314 bytes",
            "SpliceHeaderV1: 325 bytes",
            "SpliceSignatureWitnessV1: 198 bytes",
            "SpliceVaultAssetAmountV2: 49 bytes",
            "SpliceVaultDescriptorV2: 132 bytes",
            "SpliceAssetDeltaV1: 113 bytes",
            "SpliceAssetDeltasV1: 228 bytes",
            "SpliceStateTransitionWitnessV1: 1017 bytes",
            "BilateralSignatureWitnessV1: 198 bytes",
            "BilateralCkbSettlementDescriptorV1: 84 bytes",
            "BilateralCkbXudtSettlementDescriptorV1: 148 bytes",
            "SponsorPolicyV1: 144 bytes",
            "FactoryStateHeaderV1: 238 bytes",
            "FactorySignatureWitnessV1: 262 bytes",
            "FactoryRightV1: 114 bytes",
            "FactoryReducedRightsWitnessV1: 2580 bytes",
            "FactoryMerkleUpdateWitnessV1: 8720 bytes",
            "FactoryReducedExitWitnessV1: 3058 bytes",
            "FactoryReducedExitXudtWitnessV1: 3122 bytes",
            "FactoryLocalExitWitnessV1: 726 bytes",
            "FactoryLocalExitXudtWitnessV1: 790 bytes",
            "FactorySpliceHeaderV1: 275 bytes",
            "FactoryVaultDescriptorV1: 132 bytes",
            "FactoryVaultDeltaV1: 97 bytes",
            "FactoryVaultDeltasV1: 196 bytes",
            "FactorySpliceWitnessV1: 999 bytes",
            "FactoryReducedSpliceWitnessV1: 9457 bytes",
            "struct StateHeaderV1",
            "struct StateHeaderV2",
            "struct SpliceHeaderV1",
            "struct SpliceSignatureWitnessV1",
            "struct SpliceVaultDescriptorV2",
            "struct SpliceAssetDeltasV1",
            "struct SpliceStateTransitionWitnessV1",
            "struct FactoryStateHeaderV1",
            "struct BilateralSignatureWitnessV1",
            "struct FactorySignatureWitnessV1",
            "struct FactoryReducedRightsWitnessV1",
            "struct FactoryMerkleUpdateWitnessV1",
            "struct FactoryReducedExitWitnessV1",
            "struct FactoryReducedExitXudtWitnessV1",
            "struct FactoryLocalExitWitnessV1",
            "struct FactoryLocalExitXudtWitnessV1",
            "struct FactorySpliceHeaderV1",
            "struct FactoryVaultDescriptorV1",
            "struct FactoryVaultDeltasV1",
            "struct FactorySpliceWitnessV1",
            "struct FactoryReducedSpliceWitnessV1",
            "struct BilateralCkbSettlementDescriptorV1",
            "struct BilateralCkbXudtSettlementDescriptorV1",
            "struct SponsorPolicyV1",
            "state_lock_hash: Byte32",
            "xudt_type_hash: Byte32",
            "xudt_amount: uint128",
            "max_fee_per_tx: uint64",
            "publication_state_type_hash: Byte32",
            "change_lock_hash: Byte32",
            "participant_0_id: Byte32",
            "non_interference_digest: Byte32",
            "release_quantity: uint128",
            "proof_siblings: FactoryMerkleProofSiblingsV1",
            "old_funding_epoch: uint64",
            "new_funding_epoch: uint64",
            "funding_epoch: uint64",
            "vault_set_commitment: Byte32",
            "asset_delta_commitment: Byte32",
            "signed_fee: uint128",
            "old_vault_descriptor: SpliceVaultDescriptorV2",
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

        let mut raw = header_bytes(7, PHASE_SETTLING);
        let commitment =
            participants_commitment_v1(2, &[entries[0].as_slice(), entries[1].as_slice()]);
        raw[110..142].copy_from_slice(&commitment);
        let header = StateHeaderV1::parse(&raw).unwrap();
        let witness_raw = signed_bilateral_witness(&key0, &key1, &header.signing_digest());
        let witness = BilateralSignatureWitnessV1::parse(&witness_raw).unwrap();

        verify_bilateral_state_signatures(&header, &witness).unwrap();
    }

    #[test]
    fn rejects_bad_bilateral_state_signature() {
        let key0 = signing_key(1);
        let key1 = signing_key(2);
        let mut entries = [pubkey(&key0), pubkey(&key1)];
        entries.sort();

        let mut raw = header_bytes(7, PHASE_SETTLING);
        let commitment =
            participants_commitment_v1(2, &[entries[0].as_slice(), entries[1].as_slice()]);
        raw[110..142].copy_from_slice(&commitment);
        let header = StateHeaderV1::parse(&raw).unwrap();
        let mut witness_raw = signed_bilateral_witness(&key0, &key1, &header.signing_digest());
        witness_raw[BILATERAL_SIGNATURE_WITNESS_V1_LEN - 1] ^= 1;
        let witness = BilateralSignatureWitnessV1::parse(&witness_raw).unwrap();

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
        let commitment = factory_participants_commitment_v1(
            2,
            &[
                (entries[0].0.as_slice(), entries[0].1.as_slice()),
                (entries[1].0.as_slice(), entries[1].1.as_slice()),
            ],
        );
        raw[108..140].copy_from_slice(&commitment);
        let header = FactoryStateHeaderV1::parse(&raw).unwrap();
        let witness_raw =
            signed_factory_witness([1u8; 32], &key0, [2u8; 32], &key1, &header.signing_digest());
        let witness = FactorySignatureWitnessV1::parse(&witness_raw).unwrap();

        verify_factory_state_signatures(&header, &witness).unwrap();
    }

    #[test]
    fn rejects_bad_factory_state_signature() {
        let key0 = signing_key(1);
        let key1 = signing_key(2);
        let mut entries = [([1u8; 32], pubkey(&key0)), ([2u8; 32], pubkey(&key1))];
        entries.sort_by(|left, right| left.0.cmp(&right.0));

        let mut raw = factory_header_bytes(7);
        let commitment = factory_participants_commitment_v1(
            2,
            &[
                (entries[0].0.as_slice(), entries[0].1.as_slice()),
                (entries[1].0.as_slice(), entries[1].1.as_slice()),
            ],
        );
        raw[108..140].copy_from_slice(&commitment);
        let header = FactoryStateHeaderV1::parse(&raw).unwrap();
        let mut witness_raw =
            signed_factory_witness([1u8; 32], &key0, [2u8; 32], &key1, &header.signing_digest());
        witness_raw[FACTORY_SIGNATURE_WITNESS_V1_LEN - 1] ^= 1;
        let witness = FactorySignatureWitnessV1::parse(&witness_raw).unwrap();

        assert_eq!(
            verify_factory_state_signatures(&header, &witness).unwrap_err(),
            ScriptError::InvalidParticipantSignature
        );
    }

    #[test]
    fn factory_splice_witness_fields_are_fixed_width() {
        let (_, _, witness_raw) = factory_splice_headers_and_witness(SPLICE_KIND_IN_V1);
        let witness = FactorySpliceWitnessV1::parse(&witness_raw).unwrap();
        let header = witness.header().unwrap();
        let old_vault = witness.old_vault().unwrap();
        let new_vault = witness.new_vault().unwrap();
        let deltas = witness.deltas().unwrap();

        assert_eq!(witness.version(), FACTORY_SPLICE_WITNESS_VERSION_V1);
        assert_eq!(header.factory_id(), &[3u8; 32]);
        assert_eq!(header.old_update_number(), 1);
        assert_eq!(header.new_update_number(), 2);
        assert_eq!(header.kind(), SPLICE_KIND_IN_V1);
        assert_eq!(old_vault.asset(0).unwrap().amount(), 50);
        assert_eq!(new_vault.asset(0).unwrap().amount(), 70);
        assert_eq!(deltas.delta(0).unwrap().external_input(), 20);
    }

    #[test]
    fn verifies_factory_splice_update() {
        let (old_raw, new_raw, witness_raw) = factory_splice_headers_and_witness(SPLICE_KIND_IN_V1);
        let old_header = FactoryStateHeaderV1::parse(&old_raw).unwrap();
        let new_header = FactoryStateHeaderV1::parse(&new_raw).unwrap();
        let witness = FactorySpliceWitnessV1::parse(&witness_raw).unwrap();

        verify_factory_splice_update(&old_header, &new_header, &witness).unwrap();
    }

    #[test]
    fn rejects_factory_splice_vault_delta_tamper() {
        let (old_raw, new_raw, mut witness_raw) =
            factory_splice_headers_and_witness(SPLICE_KIND_IN_V1);
        witness_raw[factory_splice_deltas_offset() + factory_vault_delta_offset(0) + 49] ^= 1;
        let old_header = FactoryStateHeaderV1::parse(&old_raw).unwrap();
        let new_header = FactoryStateHeaderV1::parse(&new_raw).unwrap();
        let witness = FactorySpliceWitnessV1::parse(&witness_raw).unwrap();

        assert_eq!(
            verify_factory_splice_update(&old_header, &new_header, &witness).unwrap_err(),
            ScriptError::FactorySpliceProofMismatch
        );
    }

    #[test]
    fn rejects_factory_splice_bad_signature() {
        let (old_raw, new_raw, mut witness_raw) =
            factory_splice_headers_and_witness(SPLICE_KIND_OUT_V1);
        witness_raw[factory_splice_signature_offset() + FACTORY_SIGNATURE_WITNESS_V1_LEN - 1] ^= 1;
        let old_header = FactoryStateHeaderV1::parse(&old_raw).unwrap();
        let new_header = FactoryStateHeaderV1::parse(&new_raw).unwrap();
        let witness = FactorySpliceWitnessV1::parse(&witness_raw).unwrap();

        assert_eq!(
            verify_factory_splice_update(&old_header, &new_header, &witness).unwrap_err(),
            ScriptError::InvalidParticipantSignature
        );
    }

    #[test]
    fn factory_reduced_splice_witness_fields_are_fixed_width() {
        let (_, _, witness_raw) = factory_reduced_splice_headers_and_witness(SPLICE_KIND_IN_V1);
        let witness = FactoryReducedSpliceWitnessV1::parse(&witness_raw).unwrap();
        let header = witness.header().unwrap();
        let merkle_update = witness.merkle_update().unwrap();
        let old_vault = witness.old_vault().unwrap();
        let new_vault = witness.new_vault().unwrap();
        let deltas = witness.deltas().unwrap();

        assert_eq!(witness.version(), FACTORY_REDUCED_SPLICE_WITNESS_VERSION_V1);
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
            factory_reduced_splice_headers_and_witness(SPLICE_KIND_IN_V1);
        let old_header = FactoryStateHeaderV1::parse(&old_raw).unwrap();
        let new_header = FactoryStateHeaderV1::parse(&new_raw).unwrap();
        let witness = FactoryReducedSpliceWitnessV1::parse(&witness_raw).unwrap();

        verify_factory_reduced_splice_update(&old_header, &new_header, &witness).unwrap();
    }

    #[test]
    fn rejects_factory_reduced_splice_sibling_tamper() {
        let (old_raw, new_raw, mut witness_raw) =
            factory_reduced_splice_headers_and_witness(SPLICE_KIND_IN_V1);
        witness_raw[factory_reduced_splice_merkle_offset() + factory_merkle_sibling_offset(120)] ^=
            1;
        let old_header = FactoryStateHeaderV1::parse(&old_raw).unwrap();
        let new_header = FactoryStateHeaderV1::parse(&new_raw).unwrap();
        let witness = FactoryReducedSpliceWitnessV1::parse(&witness_raw).unwrap();

        assert_eq!(
            verify_factory_reduced_splice_update(&old_header, &new_header, &witness).unwrap_err(),
            ScriptError::FactoryReducedProofMismatch
        );
    }

    #[test]
    fn rejects_factory_reduced_splice_bad_signature() {
        let (old_raw, new_raw, mut witness_raw) =
            factory_reduced_splice_headers_and_witness(SPLICE_KIND_OUT_V1);
        let signature_offset = factory_reduced_splice_merkle_offset()
            + factory_merkle_participant_offset(0)
            + BYTE32_LEN
            + COMPRESSED_SECP256K1_PUBKEY_LEN
            + 1;
        witness_raw[signature_offset + ECDSA_SIGNATURE_LEN - 1] ^= 1;
        let old_header = FactoryStateHeaderV1::parse(&old_raw).unwrap();
        let new_header = FactoryStateHeaderV1::parse(&new_raw).unwrap();
        let witness = FactoryReducedSpliceWitnessV1::parse(&witness_raw).unwrap();

        assert_eq!(
            verify_factory_reduced_splice_update(&old_header, &new_header, &witness).unwrap_err(),
            ScriptError::InvalidParticipantSignature
        );
    }

    #[test]
    fn verifies_reduced_factory_rights_decrease() {
        let (old_raw, new_raw, witness_raw) = reduced_rights_headers_and_witness(90);
        let old_header = FactoryStateHeaderV1::parse(&old_raw).unwrap();
        let new_header = FactoryStateHeaderV1::parse(&new_raw).unwrap();
        let witness = FactoryReducedRightsWitnessV1::parse(&witness_raw).unwrap();

        verify_reduced_factory_rights_update(&old_header, &new_header, &witness).unwrap();
    }

    #[test]
    fn rejects_reduced_factory_rights_increase() {
        let (old_raw, new_raw, witness_raw) = reduced_rights_headers_and_witness(110);
        let old_header = FactoryStateHeaderV1::parse(&old_raw).unwrap();
        let new_header = FactoryStateHeaderV1::parse(&new_raw).unwrap();
        let witness = FactoryReducedRightsWitnessV1::parse(&witness_raw).unwrap();

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
        let old_header = FactoryStateHeaderV1::parse(&old_raw).unwrap();
        let new_header = FactoryStateHeaderV1::parse(&new_raw).unwrap();
        let witness = FactoryReducedRightsWitnessV1::parse(&witness_raw).unwrap();

        assert_eq!(
            verify_reduced_factory_rights_update(&old_header, &new_header, &witness).unwrap_err(),
            ScriptError::InvalidParticipantSignature
        );
    }

    #[test]
    fn factory_merkle_update_witness_fields_are_fixed_width() {
        let (_, _, witness_raw) = merkle_update_headers_and_witness(90);
        let witness = FactoryMerkleUpdateWitnessV1::parse(&witness_raw).unwrap();

        assert_eq!(witness.version(), FACTORY_MERKLE_UPDATE_WITNESS_VERSION_V1);
        assert_eq!(witness.right_count(), FACTORY_MERKLE_UPDATE_RIGHT_COUNT_V1);
        assert_eq!(witness.touched_participant(), &[1u8; 32]);
        assert_eq!(witness.right_before().unwrap().quantity(), 100);
        assert_eq!(witness.right_after().unwrap().quantity(), 90);
        assert_eq!(witness.sibling_hash(255), &[255u8; 32]);
    }

    #[test]
    fn verifies_factory_merkle_update_single_right_transition() {
        let (old_raw, new_raw, witness_raw) = merkle_update_headers_and_witness(90);
        let old_header = FactoryStateHeaderV1::parse(&old_raw).unwrap();
        let new_header = FactoryStateHeaderV1::parse(&new_raw).unwrap();
        let witness = FactoryMerkleUpdateWitnessV1::parse(&witness_raw).unwrap();

        verify_factory_merkle_update(&old_header, &new_header, &witness).unwrap();
    }

    #[test]
    fn rejects_factory_merkle_update_sibling_tamper() {
        let (old_raw, new_raw, mut witness_raw) = merkle_update_headers_and_witness(90);
        witness_raw[factory_merkle_sibling_offset(120)] ^= 1;
        let old_header = FactoryStateHeaderV1::parse(&old_raw).unwrap();
        let new_header = FactoryStateHeaderV1::parse(&new_raw).unwrap();
        let witness = FactoryMerkleUpdateWitnessV1::parse(&witness_raw).unwrap();

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
        let old_header = FactoryStateHeaderV1::parse(&old_raw).unwrap();
        let new_header = FactoryStateHeaderV1::parse(&new_raw).unwrap();
        let witness = FactoryMerkleUpdateWitnessV1::parse(&witness_raw).unwrap();

        assert_eq!(
            verify_factory_merkle_update(&old_header, &new_header, &witness).unwrap_err(),
            ScriptError::FactoryReducedProofMismatch
        );
    }

    #[test]
    fn reduced_factory_exit_witness_fields_are_fixed_width() {
        let (_, _, witness_raw) = reduced_exit_headers_and_witness(20, 30, false, true);
        let witness = FactoryReducedExitWitnessV1::parse(&witness_raw).unwrap();

        assert_eq!(witness.version(), FACTORY_REDUCED_EXIT_WITNESS_VERSION_V1);
        assert_eq!(witness.release_quantity(), 20);
        assert_eq!(witness.state_output_index(), 1);
        assert_eq!(witness.vault_output_index(), 2);
        assert_eq!(witness.state_type_hash(), &[11u8; 32]);
        assert_eq!(witness.vault_lock_hash(), &[12u8; 32]);
        assert_eq!(witness.state_lock_hash(), &[13u8; 32]);
        assert_eq!(
            StateHeaderV1::parse(witness.exit_state_header())
                .unwrap()
                .phase(),
            PHASE_ACTIVE
        );
        assert_eq!(
            witness.settlement_descriptor().len(),
            BILATERAL_CKB_DESCRIPTOR_V1_LEN
        );
        assert_eq!(witness.right_before(1).unwrap().quantity(), 50);
        assert_eq!(witness.right_after(1).unwrap().quantity(), 30);
    }

    #[test]
    fn verifies_reduced_factory_exit_reserve_release() {
        let (old_raw, new_raw, witness_raw) = reduced_exit_headers_and_witness(20, 30, false, true);
        let old_header = FactoryStateHeaderV1::parse(&old_raw).unwrap();
        let new_header = FactoryStateHeaderV1::parse(&new_raw).unwrap();
        let witness = FactoryReducedExitWitnessV1::parse(&witness_raw).unwrap();

        verify_reduced_factory_exit_update(&old_header, &new_header, &witness).unwrap();
    }

    #[test]
    fn rejects_reduced_factory_exit_release_mismatch() {
        let (old_raw, new_raw, witness_raw) = reduced_exit_headers_and_witness(20, 35, false, true);
        let old_header = FactoryStateHeaderV1::parse(&old_raw).unwrap();
        let new_header = FactoryStateHeaderV1::parse(&new_raw).unwrap();
        let witness = FactoryReducedExitWitnessV1::parse(&witness_raw).unwrap();

        assert_eq!(
            verify_reduced_factory_exit_update(&old_header, &new_header, &witness).unwrap_err(),
            ScriptError::FactoryReducedProofMismatch
        );
    }

    #[test]
    fn rejects_reduced_factory_exit_other_right_mutation() {
        let (old_raw, new_raw, witness_raw) = reduced_exit_headers_and_witness(20, 30, true, true);
        let old_header = FactoryStateHeaderV1::parse(&old_raw).unwrap();
        let new_header = FactoryStateHeaderV1::parse(&new_raw).unwrap();
        let witness = FactoryReducedExitWitnessV1::parse(&witness_raw).unwrap();

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
        let old_header = FactoryStateHeaderV1::parse(&old_raw).unwrap();
        let new_header = FactoryStateHeaderV1::parse(&new_raw).unwrap();
        let witness = FactoryReducedExitWitnessV1::parse(&witness_raw).unwrap();

        assert_eq!(
            verify_reduced_factory_exit_update(&old_header, &new_header, &witness).unwrap_err(),
            ScriptError::InvalidParticipantSignature
        );
    }

    #[test]
    fn rejects_reduced_factory_exit_descriptor_mismatch() {
        let (old_raw, new_raw, witness_raw) =
            reduced_exit_headers_and_witness(20, 30, false, false);
        let old_header = FactoryStateHeaderV1::parse(&old_raw).unwrap();
        let new_header = FactoryStateHeaderV1::parse(&new_raw).unwrap();
        let witness = FactoryReducedExitWitnessV1::parse(&witness_raw).unwrap();

        assert_eq!(
            verify_reduced_factory_exit_update(&old_header, &new_header, &witness).unwrap_err(),
            ScriptError::SettlementDescriptorMismatch
        );
    }

    #[test]
    fn parses_and_commits_bilateral_ckb_descriptor() {
        let raw = descriptor_bytes([1u8; 32], 100, [2u8; 32], 200);
        let descriptor = BilateralCkbSettlementDescriptorV1::parse(&raw).unwrap();

        assert_eq!(descriptor.version(), 1);
        assert_eq!(descriptor.output_count(), 2);
        assert_eq!(descriptor.lock_hash(0), &[1u8; 32]);
        assert_eq!(descriptor.capacity(0), 100);
        assert_eq!(descriptor.lock_hash(1), &[2u8; 32]);
        assert_eq!(descriptor.capacity(1), 200);
        assert_eq!(
            descriptor.commitment(),
            settlement_descriptor_commitment_v1(&raw)
        );
    }

    #[test]
    fn parses_and_commits_bilateral_ckb_xudt_descriptor() {
        let raw = ckb_xudt_descriptor_bytes([9u8; 32], [2u8; 32], 200, 3, [1u8; 32], 100, 7);
        let descriptor = BilateralCkbXudtSettlementDescriptorV1::parse(&raw).unwrap();

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
            settlement_descriptor_commitment_v1(&raw)
        );
    }
}
