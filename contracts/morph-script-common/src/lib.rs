#![no_std]

use ckb_hash::new_blake2b;
use k256::ecdsa::signature::hazmat::PrehashVerifier;
use k256::ecdsa::{Signature, VerifyingKey};

pub const BYTE32_LEN: usize = 32;
pub const STATE_HEADER_V1_LEN: usize = 274;
pub const SPONSOR_POLICY_V1_LEN: usize = 144;
pub const BILATERAL_CKB_DESCRIPTOR_V1_LEN: usize = 2 + 1 + 1 + 2 * (BYTE32_LEN + 8);
pub const COMPRESSED_SECP256K1_PUBKEY_LEN: usize = 33;
pub const ECDSA_SIGNATURE_LEN: usize = 64;
pub const BILATERAL_SIGNATURE_WITNESS_V1_LEN: usize =
    2 + 1 + 1 + (2 * (COMPRESSED_SECP256K1_PUBKEY_LEN + ECDSA_SIGNATURE_LEN));

pub const PHASE_SETTLING: u8 = 2;
pub const SIGNATURE_SCHEME_SECP256K1_ECDSA_BLAKE2B_V1: u16 = 1;
pub const BILATERAL_SIGNATURE_WITNESS_VERSION_V1: u16 = 1;
pub const BILATERAL_SIGNATURE_THRESHOLD_V1: u8 = 2;
pub const BILATERAL_SIGNATURE_COUNT_V1: u8 = 2;
pub const STATE_DOMAIN_V1: &[u8] = b"CKB_MORPH_CHANNEL_STATE_V1";
pub const PARTICIPANTS_DOMAIN_V1: &[u8] = b"CKB_MORPH_PARTICIPANTS_V1";
pub const SETTLEMENT_DESCRIPTOR_DOMAIN_V1: &[u8] = b"CKB_MORPH_SETTLEMENT_DESCRIPTOR_V1";
pub const BILATERAL_CKB_DESCRIPTOR_VERSION_V1: u16 = 1;
pub const BILATERAL_CKB_DESCRIPTOR_OUTPUT_COUNT_V1: u8 = 2;

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
            && self.settlement_descriptor_commitment() == next.settlement_descriptor_commitment()
            && self.descriptor_version() == next.descriptor_version()
            && self.challenge_policy_commitment() == next.challenge_policy_commitment()
            && self.state_layout_version() == next.state_layout_version()
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

pub fn settlement_descriptor_commitment_v1(raw: &[u8]) -> [u8; 32] {
    blake2b256(&[SETTLEMENT_DESCRIPTOR_DOMAIN_V1, raw])
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

    pub fn allowed_sponsor_source(&self) -> &'a [u8] {
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

fn participant_offset(index: usize) -> usize {
    4 + index * (COMPRESSED_SECP256K1_PUBKEY_LEN + ECDSA_SIGNATURE_LEN)
}

fn descriptor_output_offset(index: usize) -> usize {
    4 + index * (BYTE32_LEN + 8)
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

    fn put_u16(raw: &mut [u8], offset: usize, value: u16) {
        raw[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    }

    fn put_u64(raw: &mut [u8], offset: usize, value: u64) {
        raw[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
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
    fn state_context_allows_progress_but_rejects_identity_change() {
        let old_raw = header_bytes(1, 1);
        let mut new_raw = header_bytes(9, PHASE_SETTLING);
        new_raw[208..240].fill(10);

        let old = StateHeaderV1::parse(&old_raw).unwrap();
        let new = StateHeaderV1::parse(&new_raw).unwrap();
        assert!(old.same_context_except_progress(&new));

        new_raw[68] = 99;
        let changed_anchor = StateHeaderV1::parse(&new_raw).unwrap();
        assert!(!old.same_context_except_progress(&changed_anchor));
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
        assert_eq!(policy.allowed_sponsor_source(), &[2u8; 32]);
        assert_eq!(policy.change_lock(), &[3u8; 32]);
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
}
