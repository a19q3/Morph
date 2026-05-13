//! Core Morph Channel protocol objects and validation invariants.
//!
//! This crate is deliberately host-side Rust for now. It provides executable
//! protocol semantics that can be ported into fixed-width no-std CKB scripts.

pub mod hash;
pub mod types;
pub mod validation;

pub use hash::{
    SigningBytes, blake2b256, factory_vault_delta_commitment_v1,
    factory_vault_descriptor_commitment_v1, participants_commitment,
    splice_asset_delta_commitment_v1, vault_descriptor_commitment_v2,
};
pub use types::*;
pub use validation::*;
