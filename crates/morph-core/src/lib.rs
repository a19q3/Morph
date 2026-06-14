//! Core Morph Channel protocol objects and validation invariants.
//!
//! This crate is deliberately host-side Rust for now. It provides executable
//! protocol semantics for the no-std CKB script boundary, including fixed-layout
//! body schemas and current-envelope-carried factory authorisation.

pub mod hash;
pub mod types;
pub mod validation;

pub use hash::{
    SigningBytes, blake2b256, factory_vault_delta_commitment, factory_vault_descriptor_commitment,
    funding_context_id, participants_commitment, splice_asset_delta_commitment,
    vault_descriptor_commitment,
};
pub use types::*;
pub use validation::*;
