#![cfg_attr(target_arch = "riscv64", no_std)]
#![cfg_attr(target_arch = "riscv64", no_main)]

#[cfg(target_arch = "riscv64")]
use ckb_std::ckb_constants::Source;
#[cfg(target_arch = "riscv64")]
use ckb_std::error::SysError;
#[cfg(target_arch = "riscv64")]
use ckb_std::high_level::{load_cell_capacity, load_cell_lock_hash, load_script};
#[cfg(target_arch = "riscv64")]
use ckb_std::{default_alloc, entry};
#[cfg(target_arch = "riscv64")]
use morph_script_common::{Result, ScriptError, SponsorPolicyV1};

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
    let policy = SponsorPolicyV1::parse(args.as_ref())?;

    let sponsor_in = sum_group_capacity(Source::GroupInput)?;
    let sponsor_out = sum_outputs_by_lock_hash(policy.change_lock())?;
    let fee = sponsor_in
        .checked_sub(sponsor_out)
        .ok_or(ScriptError::CapacityUnderflow)?;

    if fee > policy.max_fee_per_tx() {
        return Err(ScriptError::SponsorFeeTooHigh);
    }
    if policy.already_spent().saturating_add(fee) > policy.max_total_fee() {
        return Err(ScriptError::SponsorBudgetExceeded);
    }
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
