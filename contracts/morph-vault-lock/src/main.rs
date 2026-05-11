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
    load_cell_capacity, load_cell_data, load_cell_lock_hash, load_input, load_script,
    load_witness_args,
};
#[cfg(target_arch = "riscv64")]
use ckb_std::{default_alloc, entry};
#[cfg(target_arch = "riscv64")]
use morph_script_common::{
    BYTE32_LEN, BilateralCkbSettlementDescriptorV1, PHASE_SETTLING, Result, ScriptError,
    StateHeaderV1, read_u64,
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
    if args.len() != BYTE32_LEN + 8 {
        return Err(ScriptError::WrongArgsLength);
    }
    let expected_funding_anchor = &args.as_ref()[..BYTE32_LEN];
    let min_since = read_u64(args.as_ref(), BYTE32_LEN);

    let (state_index, state_data) = find_unique_state_input(expected_funding_anchor)?;
    let header = StateHeaderV1::parse(&state_data)?;
    if header.phase() != PHASE_SETTLING {
        return Err(ScriptError::NewStateNotSettling);
    }

    let input = load_input(state_index, Source::Input).map_err(|_| ScriptError::Encoding)?;
    let since: u64 = input.since().unpack();
    if since < min_since {
        return Err(ScriptError::StateSinceNotMature);
    }

    let witness_args = load_witness_args(0, Source::GroupInput)
        .map_err(|_| ScriptError::SettlementWitnessMissing)?;
    let input_type = witness_args
        .input_type()
        .to_opt()
        .ok_or(ScriptError::SettlementWitnessMissing)?;
    let descriptor_raw = input_type.raw_data();
    let descriptor = BilateralCkbSettlementDescriptorV1::parse(descriptor_raw.as_ref())?;
    if header.settlement_descriptor_commitment() != descriptor.commitment().as_slice() {
        return Err(ScriptError::SettlementDescriptorMismatch);
    }
    let vault_capacity = sum_group_capacity(Source::GroupInput)?;
    if descriptor.total_capacity() != vault_capacity {
        return Err(ScriptError::SettlementOutputMismatch);
    }
    verify_descriptor_outputs(&descriptor)?;

    Ok(())
}

#[cfg(target_arch = "riscv64")]
fn sum_group_capacity(source: Source) -> Result<u64> {
    let mut sum = 0u64;
    let mut index = 0;
    loop {
        match load_cell_capacity(index, source) {
            Ok(capacity) => {
                sum = sum.saturating_add(capacity);
                index += 1;
            }
            Err(SysError::IndexOutOfBound) | Err(SysError::ItemMissing) => break,
            Err(_) => return Err(ScriptError::Encoding),
        }
    }
    Ok(sum)
}

#[cfg(target_arch = "riscv64")]
fn verify_descriptor_outputs(descriptor: &BilateralCkbSettlementDescriptorV1) -> Result<()> {
    for entry in 0..2 {
        let actual = sum_outputs_by_lock_hash(descriptor.lock_hash(entry))?;
        if actual != descriptor.capacity(entry) {
            return Err(ScriptError::SettlementOutputMismatch);
        }
    }
    Ok(())
}

#[cfg(target_arch = "riscv64")]
fn sum_outputs_by_lock_hash(expected: &[u8]) -> Result<u64> {
    let mut sum = 0u64;
    let mut index = 0;
    loop {
        match load_cell_lock_hash(index, Source::Output) {
            Ok(lock_hash) => {
                if lock_hash.as_slice() == expected {
                    let capacity = load_cell_capacity(index, Source::Output)
                        .map_err(|_| ScriptError::Encoding)?;
                    sum = sum.saturating_add(capacity);
                }
                index += 1;
            }
            Err(SysError::IndexOutOfBound) | Err(SysError::ItemMissing) => break,
            Err(_) => return Err(ScriptError::Encoding),
        }
    }
    Ok(sum)
}

#[cfg(target_arch = "riscv64")]
fn find_unique_state_input(expected_funding_anchor: &[u8]) -> Result<(usize, alloc::vec::Vec<u8>)> {
    let mut found: Option<(usize, alloc::vec::Vec<u8>)> = None;
    let mut index = 0;
    loop {
        match load_cell_data(index, Source::Input) {
            Ok(data) => {
                if let Ok(header) = StateHeaderV1::parse(&data) {
                    if header.funding_anchor() == expected_funding_anchor {
                        if found.is_some() {
                            return Err(ScriptError::StateCellAmbiguous);
                        }
                        found = Some((index, data));
                    }
                }
                index += 1;
            }
            Err(SysError::IndexOutOfBound) | Err(SysError::ItemMissing) => break,
            Err(_) => return Err(ScriptError::Encoding),
        }
    }
    found.ok_or(ScriptError::StateCellMissing)
}
