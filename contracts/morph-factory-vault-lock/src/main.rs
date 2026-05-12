#![cfg_attr(target_arch = "riscv64", no_std)]
#![cfg_attr(target_arch = "riscv64", no_main)]

#[cfg(target_arch = "riscv64")]
use ckb_std::ckb_constants::Source;
#[cfg(target_arch = "riscv64")]
use ckb_std::error::SysError;
#[cfg(target_arch = "riscv64")]
use ckb_std::high_level::{
    load_cell_capacity, load_cell_data, load_cell_lock_hash, load_cell_type_hash, load_script,
    load_script_hash, load_witness_args,
};
#[cfg(target_arch = "riscv64")]
use ckb_std::{default_alloc, entry};
#[cfg(target_arch = "riscv64")]
use morph_script_common::{
    BILATERAL_CKB_DESCRIPTOR_V1_LEN, BILATERAL_CKB_XUDT_DESCRIPTOR_V1_LEN, BYTE32_LEN,
    BilateralCkbSettlementDescriptorV1, BilateralCkbXudtSettlementDescriptorV1,
    FACTORY_LOCAL_EXIT_WITNESS_V1_LEN, FACTORY_LOCAL_EXIT_XUDT_WITNESS_V1_LEN,
    FACTORY_REDUCED_EXIT_WITNESS_V1_LEN, FACTORY_REDUCED_EXIT_XUDT_WITNESS_V1_LEN,
    FactoryLocalExitWitnessV1, FactoryReducedExitWitnessV1, FactoryStateHeaderV1, Result,
    ScriptError, read_u128,
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
    if args.len() != 2 * BYTE32_LEN {
        return Err(ScriptError::WrongArgsLength);
    }
    let factory_id = &args.as_ref()[..BYTE32_LEN];
    let factory_type_hash = &args.as_ref()[BYTE32_LEN..2 * BYTE32_LEN];

    let witness_args = load_witness_args(0, Source::GroupInput)
        .map_err(|_| ScriptError::ParticipantWitnessMissing)?;
    let input_type = witness_args
        .input_type()
        .to_opt()
        .ok_or(ScriptError::ParticipantWitnessMissing)?;
    let input_type_raw = input_type.raw_data();

    let old_header = find_unique_factory_state(Source::Input, factory_id, factory_type_hash)?;
    let new_header = find_unique_factory_state(Source::Output, factory_id, factory_type_hash)?;
    if new_header.update_number() <= old_header.update_number() {
        return Err(ScriptError::NonMonotonicStateNumber);
    }
    let child_vault_capacity = if input_type_raw.len() == FACTORY_LOCAL_EXIT_WITNESS_V1_LEN
        || input_type_raw.len() == FACTORY_LOCAL_EXIT_XUDT_WITNESS_V1_LEN
    {
        let witness = FactoryLocalExitWitnessV1::parse(input_type_raw.as_ref())?;
        if new_header.non_interference_digest() != witness.exit_digest().as_slice() {
            return Err(ScriptError::FactoryLocalExitMismatch);
        }
        validate_child_vault(
            witness.vault_output_index(),
            witness.vault_lock_hash(),
            witness.settlement_descriptor(),
        )?
    } else if input_type_raw.len() == FACTORY_REDUCED_EXIT_WITNESS_V1_LEN
        || input_type_raw.len() == FACTORY_REDUCED_EXIT_XUDT_WITNESS_V1_LEN
    {
        let witness = FactoryReducedExitWitnessV1::parse(input_type_raw.as_ref())?;
        let digest = witness.non_interference_digest(&old_header, &new_header)?;
        if new_header.non_interference_digest() != digest.as_slice() {
            return Err(ScriptError::FactoryReducedProofMismatch);
        }
        validate_child_vault(
            witness.vault_output_index(),
            witness.vault_lock_hash(),
            witness.settlement_descriptor(),
        )?
    } else {
        return Err(ScriptError::ParticipantWitnessEncoding);
    };
    validate_factory_reserve_conservation(child_vault_capacity)?;
    Ok(())
}

#[cfg(target_arch = "riscv64")]
fn find_unique_factory_state(
    source: Source,
    expected_factory_id: &[u8],
    expected_type_hash: &[u8],
) -> Result<FactoryStateHeaderV1<'static>> {
    let mut found: Option<alloc::vec::Vec<u8>> = None;
    let mut index = 0;
    loop {
        match load_cell_type_hash(index, source) {
            Ok(Some(type_hash)) => {
                if type_hash.as_slice() == expected_type_hash {
                    let data = load_cell_data(index, source).map_err(|_| ScriptError::Encoding)?;
                    let header = FactoryStateHeaderV1::parse(&data)?;
                    if header.factory_id() != expected_factory_id {
                        return Err(ScriptError::FactoryIdMismatch);
                    }
                    if found.is_some() {
                        return Err(ScriptError::StateCellAmbiguous);
                    }
                    found = Some(data);
                }
                index += 1;
            }
            Ok(None) => index += 1,
            Err(SysError::IndexOutOfBound) | Err(SysError::ItemMissing) => break,
            Err(_) => return Err(ScriptError::Encoding),
        }
    }

    let data = found.ok_or(ScriptError::StateCellMissing)?;
    let leaked: &'static [u8] = alloc::boxed::Box::leak(data.into_boxed_slice());
    FactoryStateHeaderV1::parse(leaked)
}

#[cfg(target_arch = "riscv64")]
fn validate_child_vault(
    vault_output_index: u32,
    expected_vault_lock_hash: &[u8],
    settlement_descriptor: &[u8],
) -> Result<u64> {
    let vault_index = vault_output_index as usize;
    let vault_lock_hash =
        load_cell_lock_hash(vault_index, Source::Output).map_err(|_| ScriptError::Encoding)?;
    if vault_lock_hash.as_slice() != expected_vault_lock_hash {
        return Err(ScriptError::FactoryLocalExitMismatch);
    }
    match settlement_descriptor.len() {
        BILATERAL_CKB_DESCRIPTOR_V1_LEN => {
            validate_ckb_child_vault(settlement_descriptor, vault_index)
        }
        BILATERAL_CKB_XUDT_DESCRIPTOR_V1_LEN => {
            validate_xudt_child_vault(settlement_descriptor, vault_index)
        }
        _ => Err(ScriptError::SettlementDescriptorEncoding),
    }
}

#[cfg(target_arch = "riscv64")]
fn validate_ckb_child_vault(settlement_descriptor: &[u8], vault_index: usize) -> Result<u64> {
    let descriptor = BilateralCkbSettlementDescriptorV1::parse(settlement_descriptor)?;
    let expected_capacity = descriptor.total_capacity();
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
    let vault_capacity =
        load_cell_capacity(vault_index, Source::Output).map_err(|_| ScriptError::Encoding)?;
    if vault_capacity != expected_capacity {
        return Err(ScriptError::SettlementOutputMismatch);
    }
    Ok(expected_capacity)
}

#[cfg(target_arch = "riscv64")]
fn validate_xudt_child_vault(settlement_descriptor: &[u8], vault_index: usize) -> Result<u64> {
    let descriptor = BilateralCkbXudtSettlementDescriptorV1::parse(settlement_descriptor)?;
    let vault_type =
        load_cell_type_hash(vault_index, Source::Output).map_err(|_| ScriptError::Encoding)?;
    let vault_type = vault_type.ok_or(ScriptError::XudtTypeMismatch)?;
    if vault_type.as_slice() != descriptor.xudt_type_hash() {
        return Err(ScriptError::XudtTypeMismatch);
    }
    let vault_data =
        load_cell_data(vault_index, Source::Output).map_err(|_| ScriptError::Encoding)?;
    if vault_data.len() != 16 {
        return Err(ScriptError::XudtAmountEncoding);
    }
    if read_u128(&vault_data, 0) != descriptor.total_xudt_amount() {
        return Err(ScriptError::SettlementOutputMismatch);
    }
    let expected_capacity = descriptor.total_capacity();
    let vault_capacity =
        load_cell_capacity(vault_index, Source::Output).map_err(|_| ScriptError::Encoding)?;
    if vault_capacity != expected_capacity {
        return Err(ScriptError::SettlementOutputMismatch);
    }
    Ok(expected_capacity)
}

#[cfg(target_arch = "riscv64")]
fn validate_factory_reserve_conservation(child_vault_capacity: u64) -> Result<()> {
    let input_capacity = single_group_capacity(Source::GroupInput)?;
    let current_lock_hash = load_script_hash().map_err(|_| ScriptError::Encoding)?;
    let output_capacity = single_output_capacity_by_lock_hash(&current_lock_hash)?;
    let expected_input = output_capacity
        .checked_add(child_vault_capacity)
        .ok_or(ScriptError::CapacityUnderflow)?;
    if input_capacity != expected_input {
        return Err(ScriptError::FactoryReserveMismatch);
    }
    Ok(())
}

#[cfg(target_arch = "riscv64")]
fn single_output_capacity_by_lock_hash(expected_lock_hash: &[u8]) -> Result<u64> {
    let mut found = None;
    let mut index = 0;
    loop {
        match load_cell_lock_hash(index, Source::Output) {
            Ok(lock_hash) => {
                if lock_hash.as_slice() == expected_lock_hash {
                    let capacity = load_cell_capacity(index, Source::Output)
                        .map_err(|_| ScriptError::Encoding)?;
                    if found.is_some() {
                        return Err(ScriptError::FactoryReserveMismatch);
                    }
                    found = Some(capacity);
                }
                index += 1;
            }
            Err(SysError::IndexOutOfBound) | Err(SysError::ItemMissing) => break,
            Err(_) => return Err(ScriptError::Encoding),
        }
    }
    found.ok_or(ScriptError::FactoryReserveMismatch)
}

#[cfg(target_arch = "riscv64")]
fn single_group_capacity(source: Source) -> Result<u64> {
    let capacity = load_cell_capacity(0, source).map_err(|_| ScriptError::Encoding)?;
    match load_cell_capacity(1, source) {
        Err(SysError::IndexOutOfBound) | Err(SysError::ItemMissing) => Ok(capacity),
        Err(_) => Err(ScriptError::Encoding),
        Ok(_) => Err(ScriptError::FactoryReserveMismatch),
    }
}
