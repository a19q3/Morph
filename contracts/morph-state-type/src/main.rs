#![cfg_attr(target_arch = "riscv64", no_std)]
#![cfg_attr(target_arch = "riscv64", no_main)]

#[cfg(target_arch = "riscv64")]
use ckb_std::ckb_constants::Source;
#[cfg(target_arch = "riscv64")]
use ckb_std::error::SysError;
#[cfg(target_arch = "riscv64")]
use ckb_std::high_level::{
    load_cell_capacity, load_cell_data, load_cell_occupied_capacity, load_script,
};
#[cfg(target_arch = "riscv64")]
use ckb_std::{default_alloc, entry};
#[cfg(target_arch = "riscv64")]
use morph_script_common::{BYTE32_LEN, PHASE_SETTLING, Result, ScriptError, StateHeaderV1};

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
    let expected_funding_anchor = args.as_ref();

    let old_data = only_group_cell_data(Source::GroupInput)?;
    let new_data = only_group_cell_data(Source::GroupOutput)?;
    let old_header = StateHeaderV1::parse(&old_data)?;
    let new_header = StateHeaderV1::parse(&new_data)?;

    if old_header.funding_anchor() != expected_funding_anchor
        || new_header.funding_anchor() != expected_funding_anchor
    {
        return Err(ScriptError::FundingAnchorMismatch);
    }
    if new_header.state_number() <= old_header.state_number() {
        return Err(ScriptError::NonMonotonicStateNumber);
    }
    if new_header.phase() != PHASE_SETTLING {
        return Err(ScriptError::NewStateNotSettling);
    }
    if !old_header.same_context_except_progress(&new_header) {
        return Err(ScriptError::HeaderContextChanged);
    }

    let cap = load_cell_capacity(0, Source::GroupOutput).map_err(|_| ScriptError::Encoding)?;
    let occupied =
        load_cell_occupied_capacity(0, Source::GroupOutput).map_err(|_| ScriptError::Encoding)?;
    if cap < occupied {
        return Err(ScriptError::OutputBelowOccupiedCapacity);
    }

    Ok(())
}

#[cfg(target_arch = "riscv64")]
fn only_group_cell_data(source: Source) -> Result<alloc::vec::Vec<u8>> {
    let data = load_cell_data(0, source).map_err(|_| ScriptError::WrongGroupShape)?;
    match load_cell_data(1, source) {
        Err(SysError::IndexOutOfBound) | Err(SysError::ItemMissing) => Ok(data),
        Err(_) => Err(ScriptError::Encoding),
        Ok(_) => Err(ScriptError::WrongGroupShape),
    }
}
