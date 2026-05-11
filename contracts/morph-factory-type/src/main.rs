#![cfg_attr(target_arch = "riscv64", no_std)]
#![cfg_attr(target_arch = "riscv64", no_main)]

#[cfg(target_arch = "riscv64")]
use ckb_std::ckb_constants::Source;
#[cfg(target_arch = "riscv64")]
use ckb_std::ckb_types::prelude::*;
#[cfg(target_arch = "riscv64")]
use ckb_std::error::SysError;
#[cfg(target_arch = "riscv64")]
use ckb_std::high_level::{
    QueryIter, load_cell_capacity, load_cell_data, load_cell_lock_hash,
    load_cell_occupied_capacity, load_cell_type_hash, load_input, load_script, load_script_hash,
    load_witness_args,
};
#[cfg(target_arch = "riscv64")]
use ckb_std::{default_alloc, entry};
#[cfg(target_arch = "riscv64")]
use morph_script_common::{
    BYTE32_LEN, BilateralCkbSettlementDescriptorV1, FACTORY_SIGNATURE_WITNESS_V1_LEN,
    FactoryLocalExitWitnessV1, FactorySignatureWitnessV1, FactoryStateHeaderV1, PHASE_ACTIVE,
    Result, ScriptError, StateHeaderV1, blake2b256, verify_factory_state_signatures,
};

#[cfg(target_arch = "riscv64")]
entry!(program_entry);
#[cfg(target_arch = "riscv64")]
default_alloc!();

#[cfg(target_arch = "riscv64")]
fn program_entry() -> i8 {
    match main() {
        Ok(()) => 0,
        Err(err) => err as i8,
    }
}

#[cfg(not(target_arch = "riscv64"))]
fn main() {}

#[cfg(target_arch = "riscv64")]
fn main() -> Result<()> {
    let script = load_script().map_err(|_| ScriptError::Encoding)?;
    let args = script.args().raw_data();
    if args.len() != BYTE32_LEN {
        return Err(ScriptError::WrongArgsLength);
    }
    let expected_factory_id = &args.as_ref()[..BYTE32_LEN];

    match (
        zero_or_one_group_cell_data(Source::GroupInput)?,
        zero_or_one_group_cell_data(Source::GroupOutput)?,
    ) {
        (None, Some(new_data)) => validate_create(&new_data, expected_factory_id)?,
        (Some(old_data), Some(new_data)) => {
            let old_header = FactoryStateHeaderV1::parse(&old_data)?;
            if old_header.factory_id() != expected_factory_id {
                return Err(ScriptError::FactoryIdMismatch);
            }
            validate_update(&old_header, &new_data, expected_factory_id)?;
        }
        _ => return Err(ScriptError::WrongGroupShape),
    }

    Ok(())
}

#[cfg(target_arch = "riscv64")]
fn validate_create(new_data: &[u8], expected_factory_id: &[u8]) -> Result<()> {
    let new_header = FactoryStateHeaderV1::parse(new_data)?;
    if new_header.factory_id() != expected_factory_id {
        return Err(ScriptError::FactoryIdMismatch);
    }
    if new_header.update_number() != 0 {
        return Err(ScriptError::NonMonotonicStateNumber);
    }
    validate_factory_id_derivation(expected_factory_id)?;
    validate_output_capacity()?;
    Ok(())
}

#[cfg(target_arch = "riscv64")]
fn validate_update(
    old_header: &FactoryStateHeaderV1,
    new_data: &[u8],
    expected_factory_id: &[u8],
) -> Result<()> {
    let new_header = FactoryStateHeaderV1::parse(new_data)?;
    if new_header.factory_id() != expected_factory_id {
        return Err(ScriptError::FactoryIdMismatch);
    }
    if new_header.update_number() <= old_header.update_number() {
        return Err(ScriptError::NonMonotonicStateNumber);
    }
    if !old_header.same_context_except_progress(&new_header) {
        return Err(ScriptError::HeaderContextChanged);
    }
    validate_participant_authorisation(&new_header)?;
    validate_output_capacity()?;
    Ok(())
}

#[cfg(target_arch = "riscv64")]
fn validate_participant_authorisation(header: &FactoryStateHeaderV1) -> Result<()> {
    let witness_args = load_witness_args(0, Source::GroupInput)
        .map_err(|_| ScriptError::ParticipantWitnessMissing)?;
    let input_type = witness_args
        .input_type()
        .to_opt()
        .ok_or(ScriptError::ParticipantWitnessMissing)?;
    let raw = input_type.raw_data();
    if raw.len() == FACTORY_SIGNATURE_WITNESS_V1_LEN {
        let witness = FactorySignatureWitnessV1::parse(raw.as_ref())?;
        verify_factory_state_signatures(header, &witness)
    } else {
        let witness = FactoryLocalExitWitnessV1::parse(raw.as_ref())?;
        let signatures = witness.factory_signature()?;
        verify_factory_state_signatures(header, &signatures)?;
        validate_local_exit(header, &witness)
    }
}

#[cfg(target_arch = "riscv64")]
fn validate_local_exit(
    header: &FactoryStateHeaderV1,
    witness: &FactoryLocalExitWitnessV1,
) -> Result<()> {
    if header.non_interference_digest() != witness.exit_digest().as_slice() {
        return Err(ScriptError::FactoryLocalExitMismatch);
    }

    let state_index = witness.state_output_index() as usize;
    let vault_index = witness.vault_output_index() as usize;
    if state_index == vault_index {
        return Err(ScriptError::FactoryLocalExitMismatch);
    }

    let state_data =
        load_cell_data(state_index, Source::Output).map_err(|_| ScriptError::StateCellMissing)?;
    if state_data.as_slice() != witness.exit_state_header() {
        return Err(ScriptError::FactoryLocalExitMismatch);
    }
    let state_type_hash = load_cell_type_hash(state_index, Source::Output)
        .map_err(|_| ScriptError::FactoryLocalExitMismatch)?
        .ok_or(ScriptError::FactoryLocalExitMismatch)?;
    if state_type_hash.as_slice() != witness.state_type_hash() {
        return Err(ScriptError::FactoryLocalExitMismatch);
    }
    let state_lock_hash =
        load_cell_lock_hash(state_index, Source::Output).map_err(|_| ScriptError::Encoding)?;
    if state_lock_hash.as_slice() != witness.state_lock_hash() {
        return Err(ScriptError::FactoryLocalExitMismatch);
    }

    let exit_header = StateHeaderV1::parse(witness.exit_state_header())?;
    if exit_header.state_number() != 0 || exit_header.phase() != PHASE_ACTIVE {
        return Err(ScriptError::FactoryLocalExitMismatch);
    }
    let descriptor = BilateralCkbSettlementDescriptorV1::parse(witness.settlement_descriptor())?;
    if exit_header.settlement_descriptor_commitment() != descriptor.commitment().as_slice() {
        return Err(ScriptError::SettlementDescriptorMismatch);
    }

    let input = load_input(0, Source::Input).map_err(|_| ScriptError::Encoding)?;
    let state_index_bytes = (state_index as u64).to_le_bytes();
    let expected_anchor = blake2b256(&[input.as_slice(), &state_index_bytes]);
    if exit_header.funding_anchor() != expected_anchor.as_slice() {
        return Err(ScriptError::FundingAnchorMismatch);
    }

    let vault_lock_hash =
        load_cell_lock_hash(vault_index, Source::Output).map_err(|_| ScriptError::Encoding)?;
    if vault_lock_hash.as_slice() != witness.vault_lock_hash() {
        return Err(ScriptError::FactoryLocalExitMismatch);
    }
    let vault_data =
        load_cell_data(vault_index, Source::Output).map_err(|_| ScriptError::Encoding)?;
    if !vault_data.is_empty() {
        return Err(ScriptError::FactoryLocalExitMismatch);
    }
    let vault_type =
        load_cell_type_hash(vault_index, Source::Output).map_err(|_| ScriptError::Encoding)?;
    if vault_type.is_some() {
        return Err(ScriptError::XudtTypeMismatch);
    }
    let expected_vault_capacity = descriptor
        .capacity(0)
        .checked_add(descriptor.capacity(1))
        .ok_or(ScriptError::CapacityUnderflow)?;
    let vault_capacity =
        load_cell_capacity(vault_index, Source::Output).map_err(|_| ScriptError::Encoding)?;
    if vault_capacity != expected_vault_capacity {
        return Err(ScriptError::SettlementOutputMismatch);
    }

    Ok(())
}

#[cfg(target_arch = "riscv64")]
fn validate_output_capacity() -> Result<()> {
    let cap = load_cell_capacity(0, Source::GroupOutput).map_err(|_| ScriptError::Encoding)?;
    let occupied =
        load_cell_occupied_capacity(0, Source::GroupOutput).map_err(|_| ScriptError::Encoding)?;
    if cap < occupied {
        return Err(ScriptError::OutputBelowOccupiedCapacity);
    }
    Ok(())
}

#[cfg(target_arch = "riscv64")]
fn validate_factory_id_derivation(expected_factory_id: &[u8]) -> Result<()> {
    let script_hash = load_script_hash().map_err(|_| ScriptError::Encoding)?;
    let output_index = QueryIter::new(load_cell_type_hash, Source::Output)
        .position(|type_hash| type_hash == Some(script_hash))
        .ok_or(ScriptError::FactoryIdMismatch)? as u64;
    let input = load_input(0, Source::Input).map_err(|_| ScriptError::Encoding)?;
    let index = output_index.to_le_bytes();
    let derived = blake2b256(&[input.as_slice(), &index]);
    if derived.as_slice() != expected_factory_id {
        return Err(ScriptError::FactoryIdMismatch);
    }
    Ok(())
}

#[cfg(target_arch = "riscv64")]
fn zero_or_one_group_cell_data(source: Source) -> Result<Option<alloc::vec::Vec<u8>>> {
    let data = match load_cell_data(0, source) {
        Ok(data) => data,
        Err(SysError::IndexOutOfBound) | Err(SysError::ItemMissing) => return Ok(None),
        Err(_) => return Err(ScriptError::WrongGroupShape),
    };
    match load_cell_data(1, source) {
        Err(SysError::IndexOutOfBound) | Err(SysError::ItemMissing) => Ok(Some(data)),
        Err(_) => Err(ScriptError::Encoding),
        Ok(_) => Err(ScriptError::WrongGroupShape),
    }
}
