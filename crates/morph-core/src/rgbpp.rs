//! RGB++ asset identity and proof-boundary types.
//!
//! Ordinary xUDT identity is not, by itself, proof of an RGB++ isomorphic
//! binding.  Morph therefore keeps the CKB asset identity, the Bitcoin seal,
//! and the trusted proof-program identity as separate committed fields.

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{Bytes32, blake2b256};

const RGBPP_ASSET_ID_DOMAIN: &[u8] = b"CKB_MORPH_RGBPP_ASSET_ID_V1";
const RGBPP_BINDING_DOMAIN: &[u8] = b"CKB_MORPH_RGBPP_BINDING_V1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum BitcoinNetwork {
    Mainnet,
    Testnet,
    Signet,
    Regtest,
}

impl BitcoinNetwork {
    const fn as_u8(self) -> u8 {
        match self {
            Self::Mainnet => 0,
            Self::Testnet => 1,
            Self::Signet => 2,
            Self::Regtest => 3,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct BitcoinOutPoint {
    pub txid: Bytes32,
    pub vout: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct CkbOutPoint {
    pub tx_hash: Bytes32,
    pub index: u32,
}

/// Consensus-relevant RGB++ asset identity. `symbol` and `decimals` are
/// deliberately absent because display metadata cannot authorize value.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct RgbppAssetId {
    pub ckb_genesis_hash: Bytes32,
    pub xudt_type_script_hash: Bytes32,
    pub bitcoin_network: BitcoinNetwork,
    /// Code hash of the lock/profile that binds the CKB Cell to a Bitcoin seal.
    pub binding_code_hash: Bytes32,
}

impl RgbppAssetId {
    pub fn validate(&self) -> RgbppResult<()> {
        require_nonzero(&self.ckb_genesis_hash)?;
        require_nonzero(&self.xudt_type_script_hash)?;
        require_nonzero(&self.binding_code_hash)
    }

    pub fn commitment(&self) -> RgbppResult<Bytes32> {
        self.validate()?;
        let mut raw = Vec::with_capacity(RGBPP_ASSET_ID_DOMAIN.len() + 97);
        raw.extend_from_slice(RGBPP_ASSET_ID_DOMAIN);
        raw.extend_from_slice(&self.ckb_genesis_hash);
        raw.extend_from_slice(&self.xudt_type_script_hash);
        raw.push(self.bitcoin_network.as_u8());
        raw.extend_from_slice(&self.binding_code_hash);
        Ok(blake2b256(&raw))
    }
}

/// Evidence emitted by an allowlisted RGB++ proof program or light-client
/// bridge. Morph validates its identity and freshness here; the cryptographic
/// Bitcoin inclusion proof remains the responsibility of that pinned program.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RgbppBindingEvidence {
    pub asset_id: RgbppAssetId,
    pub bitcoin_seal: BitcoinOutPoint,
    pub ckb_asset_cell: CkbOutPoint,
    pub amount: u128,
    pub bitcoin_block_hash: Bytes32,
    pub bitcoin_block_height: u64,
    pub observed_bitcoin_tip_height: u64,
    pub proof_program_type_hash: Bytes32,
    pub proof_cell: CkbOutPoint,
    /// Commitment to the proof payload verified by `proof_program_type_hash`.
    pub proof_payload_commitment: Bytes32,
}

impl RgbppBindingEvidence {
    pub fn confirmations(&self) -> RgbppResult<u64> {
        self.observed_bitcoin_tip_height
            .checked_sub(self.bitcoin_block_height)
            .and_then(|depth| depth.checked_add(1))
            .ok_or(RgbppError::TipBehindProof)
    }

    pub fn commitment(&self) -> RgbppResult<Bytes32> {
        self.validate_shape()?;
        let mut raw = Vec::with_capacity(RGBPP_BINDING_DOMAIN.len() + 320);
        raw.extend_from_slice(RGBPP_BINDING_DOMAIN);
        raw.extend_from_slice(&self.asset_id.commitment()?);
        raw.extend_from_slice(&self.bitcoin_seal.txid);
        raw.extend_from_slice(&self.bitcoin_seal.vout.to_le_bytes());
        raw.extend_from_slice(&self.ckb_asset_cell.tx_hash);
        raw.extend_from_slice(&self.ckb_asset_cell.index.to_le_bytes());
        raw.extend_from_slice(&self.amount.to_le_bytes());
        raw.extend_from_slice(&self.bitcoin_block_hash);
        raw.extend_from_slice(&self.bitcoin_block_height.to_le_bytes());
        raw.extend_from_slice(&self.observed_bitcoin_tip_height.to_le_bytes());
        raw.extend_from_slice(&self.proof_program_type_hash);
        raw.extend_from_slice(&self.proof_cell.tx_hash);
        raw.extend_from_slice(&self.proof_cell.index.to_le_bytes());
        raw.extend_from_slice(&self.proof_payload_commitment);
        Ok(blake2b256(&raw))
    }

    fn validate_shape(&self) -> RgbppResult<()> {
        self.asset_id.validate()?;
        require_nonzero(&self.bitcoin_seal.txid)?;
        require_nonzero(&self.ckb_asset_cell.tx_hash)?;
        require_nonzero(&self.bitcoin_block_hash)?;
        require_nonzero(&self.proof_program_type_hash)?;
        require_nonzero(&self.proof_cell.tx_hash)?;
        require_nonzero(&self.proof_payload_commitment)?;
        if self.amount == 0 {
            return Err(RgbppError::ZeroAmount);
        }
        self.confirmations()?;
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RgbppVerificationPolicy {
    pub ckb_genesis_hash: Bytes32,
    pub bitcoin_network: BitcoinNetwork,
    pub trusted_binding_code_hashes: Vec<Bytes32>,
    pub trusted_proof_program_type_hashes: Vec<Bytes32>,
    pub minimum_confirmations: u64,
    /// Reject evidence observed too far behind the independently known tip.
    pub maximum_tip_lag: u64,
}

impl RgbppVerificationPolicy {
    pub fn verify(
        &self,
        evidence: &RgbppBindingEvidence,
        known_bitcoin_tip_height: u64,
    ) -> RgbppResult<Bytes32> {
        evidence.validate_shape()?;
        if self.minimum_confirmations == 0
            || is_zero(&self.ckb_genesis_hash)
            || self.trusted_binding_code_hashes.is_empty()
            || self.trusted_binding_code_hashes.iter().any(is_zero)
            || self.trusted_proof_program_type_hashes.is_empty()
            || self.trusted_proof_program_type_hashes.iter().any(is_zero)
        {
            return Err(RgbppError::InvalidPolicy);
        }
        if evidence.asset_id.ckb_genesis_hash != self.ckb_genesis_hash
            || evidence.asset_id.bitcoin_network != self.bitcoin_network
        {
            return Err(RgbppError::WrongNetwork);
        }
        if !self
            .trusted_binding_code_hashes
            .contains(&evidence.asset_id.binding_code_hash)
        {
            return Err(RgbppError::UntrustedBindingProgram);
        }
        if !self
            .trusted_proof_program_type_hashes
            .contains(&evidence.proof_program_type_hash)
        {
            return Err(RgbppError::UntrustedProofProgram);
        }
        if evidence.confirmations()? < self.minimum_confirmations {
            return Err(RgbppError::InsufficientConfirmations);
        }
        let tip_lag = known_bitcoin_tip_height
            .checked_sub(evidence.observed_bitcoin_tip_height)
            .ok_or(RgbppError::EvidenceAheadOfKnownTip)?;
        if tip_lag > self.maximum_tip_lag {
            return Err(RgbppError::StaleEvidence);
        }
        evidence.commitment()
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum RgbppError {
    #[error("RGB++ identity or proof contains a zero identifier")]
    ZeroIdentifier,
    #[error("RGB++ amount must be positive")]
    ZeroAmount,
    #[error("RGB++ verification policy is invalid")]
    InvalidPolicy,
    #[error("RGB++ evidence belongs to another CKB or Bitcoin network")]
    WrongNetwork,
    #[error("RGB++ proof program is not trusted by the deployment policy")]
    UntrustedProofProgram,
    #[error("RGB++ binding lock/profile is not trusted by the deployment policy")]
    UntrustedBindingProgram,
    #[error("RGB++ proof has too few Bitcoin confirmations")]
    InsufficientConfirmations,
    #[error("RGB++ proof tip is behind its claimed inclusion block")]
    TipBehindProof,
    #[error("RGB++ evidence claims a tip ahead of the independently known tip")]
    EvidenceAheadOfKnownTip,
    #[error("RGB++ evidence is stale relative to the independently known tip")]
    StaleEvidence,
}

pub type RgbppResult<T> = Result<T, RgbppError>;

fn is_zero(value: &Bytes32) -> bool {
    value.iter().all(|byte| *byte == 0)
}

fn require_nonzero(value: &Bytes32) -> RgbppResult<()> {
    if is_zero(value) {
        Err(RgbppError::ZeroIdentifier)
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn evidence() -> RgbppBindingEvidence {
        RgbppBindingEvidence {
            asset_id: RgbppAssetId {
                ckb_genesis_hash: [1; 32],
                xudt_type_script_hash: [2; 32],
                bitcoin_network: BitcoinNetwork::Testnet,
                binding_code_hash: [3; 32],
            },
            bitcoin_seal: BitcoinOutPoint {
                txid: [4; 32],
                vout: 1,
            },
            ckb_asset_cell: CkbOutPoint {
                tx_hash: [5; 32],
                index: 2,
            },
            amount: 42,
            bitcoin_block_hash: [6; 32],
            bitcoin_block_height: 100,
            observed_bitcoin_tip_height: 105,
            proof_program_type_hash: [7; 32],
            proof_cell: CkbOutPoint {
                tx_hash: [8; 32],
                index: 0,
            },
            proof_payload_commitment: [9; 32],
        }
    }

    fn policy() -> RgbppVerificationPolicy {
        RgbppVerificationPolicy {
            ckb_genesis_hash: [1; 32],
            bitcoin_network: BitcoinNetwork::Testnet,
            trusted_binding_code_hashes: vec![[3; 32]],
            trusted_proof_program_type_hashes: vec![[7; 32]],
            minimum_confirmations: 6,
            maximum_tip_lag: 2,
        }
    }

    #[test]
    fn proof_policy_binds_network_program_confirmations_and_tip() {
        let evidence = evidence();
        assert_eq!(
            policy().verify(&evidence, 106).unwrap(),
            evidence.commitment().unwrap()
        );

        let mut wrong_program = evidence.clone();
        wrong_program.proof_program_type_hash = [10; 32];
        assert_eq!(
            policy().verify(&wrong_program, 106),
            Err(RgbppError::UntrustedProofProgram)
        );

        let mut wrong_binding = evidence.clone();
        wrong_binding.asset_id.binding_code_hash = [11; 32];
        assert_eq!(
            policy().verify(&wrong_binding, 106),
            Err(RgbppError::UntrustedBindingProgram)
        );

        let mut shallow = evidence;
        shallow.observed_bitcoin_tip_height = 104;
        assert_eq!(
            policy().verify(&shallow, 104),
            Err(RgbppError::InsufficientConfirmations)
        );
    }

    #[test]
    fn display_metadata_cannot_alias_asset_identity() {
        let first = evidence().asset_id;
        let mut second = first.clone();
        second.xudt_type_script_hash = [11; 32];
        assert_ne!(first.commitment().unwrap(), second.commitment().unwrap());
    }
}
