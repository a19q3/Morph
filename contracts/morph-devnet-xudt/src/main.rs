#![cfg_attr(target_arch = "riscv64", no_std)]
#![cfg_attr(target_arch = "riscv64", no_main)]

#[cfg(target_arch = "riscv64")]
use ckb_std::ckb_constants::Source;
#[cfg(target_arch = "riscv64")]
use ckb_std::error::SysError;
#[cfg(target_arch = "riscv64")]
use ckb_std::high_level::{load_cell_data, load_cell_lock_hash, load_script};
#[cfg(target_arch = "riscv64")]
use ckb_std::{default_alloc, entry};
#[cfg(target_arch = "riscv64")]
use morph_script_common::{BYTE32_LEN, Result, ScriptError, read_u128};

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

    let (input_count, input_amount) = sum_group_amount(Source::GroupInput)?;
    let (_, output_amount) = sum_group_amount(Source::GroupOutput)?;

    if input_count == 0 {
        let owner_lock_hash =
            load_cell_lock_hash(0, Source::Input).map_err(|_| ScriptError::XudtMintUnauthorised)?;
        if owner_lock_hash.as_slice() != args.as_ref() {
            return Err(ScriptError::XudtMintUnauthorised);
        }
        return Ok(());
    }

    if input_amount != output_amount {
        return Err(ScriptError::XudtConservationMismatch);
    }
    Ok(())
}

#[cfg(target_arch = "riscv64")]
fn sum_group_amount(source: Source) -> Result<(usize, u128)> {
    let mut count = 0usize;
    let mut amount = 0u128;
    let mut index = 0usize;
    loop {
        match load_cell_data(index, source) {
            Ok(data) => {
                if data.len() != 16 {
                    return Err(ScriptError::XudtAmountEncoding);
                }
                count += 1;
                amount = amount
                    .checked_add(read_u128(&data, 0))
                    .ok_or(ScriptError::XudtConservationMismatch)?;
                index += 1;
            }
            Err(SysError::IndexOutOfBound) | Err(SysError::ItemMissing) => break,
            Err(_) => return Err(ScriptError::Encoding),
        }
    }
    Ok((count, amount))
}
