use blake2b_rs::Blake2bBuilder;

use crate::types::{Mode, Phase, StateHeader};

pub const STATE_DOMAIN_V1: &[u8] = b"CKB_MORPH_CHANNEL_STATE_V1";

pub trait SigningBytes {
    fn encode_signing_bytes(&self, out: &mut Vec<u8>);
}

pub fn blake2b256(data: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let mut hasher = Blake2bBuilder::new(32)
        .personal(b"ckb-default-hash")
        .build();
    hasher.update(data);
    hasher.finalize(&mut out);
    out
}

impl SigningBytes for StateHeader {
    fn encode_signing_bytes(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(STATE_DOMAIN_V1);
        out.extend_from_slice(&self.protocol_version.to_le_bytes());
        out.extend_from_slice(&self.chain_id);
        out.extend_from_slice(&self.signature_scheme_id.to_le_bytes());
        out.extend_from_slice(&self.channel_id);
        out.extend_from_slice(&self.funding_anchor);
        out.extend_from_slice(&self.state_number.to_le_bytes());
        out.push(self.mode.as_u8());
        out.push(self.phase.as_u8());
        out.extend_from_slice(&self.participants_commitment);
        out.extend_from_slice(&self.asset_registry_commitment);
        out.extend_from_slice(&self.settlement_descriptor_commitment);
        out.extend_from_slice(&self.descriptor_version.to_le_bytes());
        out.extend_from_slice(&self.payload_commitment);
        out.extend_from_slice(&self.challenge_policy_commitment);
        out.extend_from_slice(&self.state_layout_version.to_le_bytes());
    }
}

impl StateHeader {
    pub fn signing_digest(&self) -> [u8; 32] {
        let mut bytes = Vec::with_capacity(256);
        self.encode_signing_bytes(&mut bytes);
        blake2b256(&bytes)
    }
}

impl Mode {
    pub const fn as_u8(self) -> u8 {
        match self {
            Self::BilateralPlain => 0,
            Self::FactoryProof => 1,
        }
    }
}

impl Phase {
    pub const fn as_u8(self) -> u8 {
        match self {
            Self::Funding => 0,
            Self::Active => 1,
            Self::Settling => 2,
            Self::Closed => 3,
        }
    }
}
