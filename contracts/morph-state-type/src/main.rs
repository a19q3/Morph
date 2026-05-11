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
    QueryIter, load_cell_capacity, load_cell_data, load_cell_occupied_capacity,
    load_cell_type_hash, load_input, load_script, load_script_hash, load_witness_args,
};
#[cfg(target_arch = "riscv64")]
use ckb_std::{default_alloc, entry};
#[cfg(target_arch = "riscv64")]
use morph_script_common::{
    BYTE32_LEN, BilateralSignatureWitnessV1, PHASE_ACTIVE, PHASE_SETTLING, Result, ScriptError,
    StateHeaderV1, blake2b256, read_u64, verify_bilateral_state_signatures,
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
    if args.len() != BYTE32_LEN && args.len() != BYTE32_LEN + 8 {
        return Err(ScriptError::WrongArgsLength);
    }
    let expected_funding_anchor = &args.as_ref()[..BYTE32_LEN];
    let finalise_since = if args.len() == BYTE32_LEN + 8 {
        Some(read_u64(args.as_ref(), BYTE32_LEN))
    } else {
        None
    };

    match (
        zero_or_one_group_cell_data(Source::GroupInput)?,
        zero_or_one_group_cell_data(Source::GroupOutput)?,
    ) {
        (None, Some(new_data)) => validate_create(&new_data, expected_funding_anchor)?,
        (Some(old_data), Some(new_data)) => {
            let old_header = StateHeaderV1::parse(&old_data)?;
            if old_header.funding_anchor() != expected_funding_anchor {
                return Err(ScriptError::FundingAnchorMismatch);
            }
            validate_supersede(&old_header, &new_data, expected_funding_anchor)?;
        }
        (Some(old_data), None) => {
            let old_header = StateHeaderV1::parse(&old_data)?;
            if old_header.funding_anchor() != expected_funding_anchor {
                return Err(ScriptError::FundingAnchorMismatch);
            }
            validate_finalise(&old_header, finalise_since)?;
        }
        (None, None) => return Err(ScriptError::WrongGroupShape),
    }

    Ok(())
}

#[cfg(target_arch = "riscv64")]
fn validate_create(new_data: &[u8], expected_funding_anchor: &[u8]) -> Result<()> {
    let new_header = StateHeaderV1::parse(new_data)?;

    if new_header.funding_anchor() != expected_funding_anchor {
        return Err(ScriptError::FundingAnchorMismatch);
    }
    if new_header.state_number() != 0 {
        return Err(ScriptError::NonMonotonicStateNumber);
    }
    if new_header.phase() != PHASE_ACTIVE {
        return Err(ScriptError::NewStateNotSettling);
    }
    validate_anchor_derivation(expected_funding_anchor)?;

    let cap = load_cell_capacity(0, Source::GroupOutput).map_err(|_| ScriptError::Encoding)?;
    let occupied =
        load_cell_occupied_capacity(0, Source::GroupOutput).map_err(|_| ScriptError::Encoding)?;
    if cap < occupied {
        return Err(ScriptError::OutputBelowOccupiedCapacity);
    }

    Ok(())
}

#[cfg(target_arch = "riscv64")]
fn validate_anchor_derivation(expected_funding_anchor: &[u8]) -> Result<()> {
    let script_hash = load_script_hash().map_err(|_| ScriptError::Encoding)?;
    let output_index = QueryIter::new(load_cell_type_hash, Source::Output)
        .position(|type_hash| type_hash == Some(script_hash))
        .ok_or(ScriptError::FundingAnchorMismatch)? as u64;
    let input = load_input(0, Source::Input).map_err(|_| ScriptError::Encoding)?;
    let index = output_index.to_le_bytes();
    let derived = blake2b256(&[input.as_slice(), &index]);
    if derived.as_slice() != expected_funding_anchor {
        return Err(ScriptError::FundingAnchorMismatch);
    }
    Ok(())
}

#[cfg(target_arch = "riscv64")]
fn validate_supersede(
    old_header: &StateHeaderV1,
    new_data: &[u8],
    expected_funding_anchor: &[u8],
) -> Result<()> {
    let new_header = StateHeaderV1::parse(new_data)?;

    if new_header.funding_anchor() != expected_funding_anchor {
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
    validate_participant_authorisation(&new_header)?;

    let cap = load_cell_capacity(0, Source::GroupOutput).map_err(|_| ScriptError::Encoding)?;
    let occupied =
        load_cell_occupied_capacity(0, Source::GroupOutput).map_err(|_| ScriptError::Encoding)?;
    if cap < occupied {
        return Err(ScriptError::OutputBelowOccupiedCapacity);
    }

    Ok(())
}

#[cfg(target_arch = "riscv64")]
fn validate_participant_authorisation(header: &StateHeaderV1) -> Result<()> {
    let witness_args = load_witness_args(0, Source::GroupInput)
        .map_err(|_| ScriptError::ParticipantWitnessMissing)?;
    let input_type = witness_args
        .input_type()
        .to_opt()
        .ok_or(ScriptError::ParticipantWitnessMissing)?;
    let raw = input_type.raw_data();
    let witness = BilateralSignatureWitnessV1::parse(raw.as_ref())?;
    verify_bilateral_state_signatures(header, &witness)
}

#[cfg(target_arch = "riscv64")]
fn validate_finalise(old_header: &StateHeaderV1, finalise_since: Option<u64>) -> Result<()> {
    if old_header.phase() != PHASE_SETTLING {
        return Err(ScriptError::NewStateNotSettling);
    }

    let required_since = finalise_since.ok_or(ScriptError::StateSinceNotMature)?;
    let input = load_input(0, Source::GroupInput).map_err(|_| ScriptError::Encoding)?;
    let since: u64 = input.since().unpack();
    if since < required_since {
        return Err(ScriptError::StateSinceNotMature);
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
