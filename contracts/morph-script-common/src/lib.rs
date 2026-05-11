#![no_std]

pub const BYTE32_LEN: usize = 32;
pub const STATE_HEADER_V1_LEN: usize = 274;
pub const SPONSOR_POLICY_V1_LEN: usize = 144;

pub const PHASE_SETTLING: u8 = 2;

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

#[cfg(test)]
mod tests {
    use super::*;

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
}
