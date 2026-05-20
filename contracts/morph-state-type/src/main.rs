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
    load_cell_occupied_capacity, load_cell_type, load_cell_type_hash, load_input, load_script,
    load_script_hash, load_witness_args,
};
#[cfg(target_arch = "riscv64")]
use ckb_std::{default_alloc, entry};
#[cfg(target_arch = "riscv64")]
use morph_script_common::{
    BYTE32_LEN, BilateralSignatureWitnessV1, PHASE_ACTIVE, PHASE_SETTLING, Result, ScriptError,
    SpliceStateTransitionWitnessV1, StateHeaderV1, blake2b256, read_u64,
    validate_relative_block_since, vault_cell_commitment_v1, verify_bilateral_state_signatures,
    verify_splice_state_transition_bundle,
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
        (None, Some(new_data)) => validate_create(&script, &new_data, expected_funding_anchor)?,
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
            if old_header.phase() == PHASE_ACTIVE {
                validate_splice_retire(&script, &old_header, expected_funding_anchor)?;
            } else {
                validate_finalise(&old_header, finalise_since)?;
            }
        }
        (None, None) => return Err(ScriptError::WrongGroupShape),
    }

    Ok(())
}

#[cfg(target_arch = "riscv64")]
fn validate_create(
    current_script: &ckb_std::ckb_types::packed::Script,
    new_data: &[u8],
    expected_funding_anchor: &[u8],
) -> Result<()> {
    let new_header = StateHeaderV1::parse(new_data)?;

    if new_header.funding_anchor() != expected_funding_anchor {
        return Err(ScriptError::FundingAnchorMismatch);
    }
    if new_header.phase() != PHASE_ACTIVE {
        return Err(ScriptError::NewStateNotSettling);
    }
    if new_header.state_number() != 0
        || find_splice_witness_raw(expected_funding_anchor, false).is_ok()
    {
        validate_splice_create(current_script, &new_header, expected_funding_anchor)?;
        validate_group_output_capacity()?;
        return Ok(());
    }
    validate_anchor_derivation(expected_funding_anchor)?;
    validate_group_output_capacity()
}

#[cfg(target_arch = "riscv64")]
fn validate_group_output_capacity() -> Result<()> {
    let cap = load_cell_capacity(0, Source::GroupOutput).map_err(|_| ScriptError::Encoding)?;
    let occupied =
        load_cell_occupied_capacity(0, Source::GroupOutput).map_err(|_| ScriptError::Encoding)?;
    if cap < occupied {
        return Err(ScriptError::OutputBelowOccupiedCapacity);
    }

    Ok(())
}

#[cfg(target_arch = "riscv64")]
fn validate_splice_create(
    current_script: &ckb_std::ckb_types::packed::Script,
    new_header: &StateHeaderV1,
    expected_funding_anchor: &[u8],
) -> Result<()> {
    let witness_raw = find_splice_witness_raw(expected_funding_anchor, false)?;
    let witness = SpliceStateTransitionWitnessV1::parse(&witness_raw)
        .map_err(|_| ScriptError::SpliceProofEncoding)?;
    let splice_header = witness.header()?;
    let (old_index, old_data) = find_unique_state_cell(
        Source::Input,
        current_script,
        splice_header.old_funding_anchor(),
    )?;
    validate_peer_state_type_script(
        current_script,
        old_index,
        Source::Input,
        splice_header.old_funding_anchor(),
    )?;
    let old_header = StateHeaderV1::parse(&old_data)?;
    verify_splice_state_transition_bundle(&old_header, new_header, &witness)
}

#[cfg(target_arch = "riscv64")]
fn validate_splice_retire(
    current_script: &ckb_std::ckb_types::packed::Script,
    old_header: &StateHeaderV1,
    expected_funding_anchor: &[u8],
) -> Result<()> {
    find_unique_input_by_vault_commitment(old_header.payload_commitment())?;
    let witness_raw = find_splice_witness_raw(expected_funding_anchor, true)?;
    let witness = SpliceStateTransitionWitnessV1::parse(&witness_raw)
        .map_err(|_| ScriptError::SpliceProofEncoding)?;
    let splice_header = witness.header()?;
    let (new_index, new_data) = find_unique_state_cell(
        Source::Output,
        current_script,
        splice_header.new_funding_anchor(),
    )?;
    validate_peer_state_type_script(
        current_script,
        new_index,
        Source::Output,
        splice_header.new_funding_anchor(),
    )?;
    let new_header = StateHeaderV1::parse(&new_data)?;
    verify_splice_state_transition_bundle(old_header, &new_header, &witness)
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
    validate_relative_block_since(since, required_since)?;
    find_unique_input_by_vault_commitment(old_header.payload_commitment())?;

    Ok(())
}

#[cfg(target_arch = "riscv64")]
fn find_unique_input_by_vault_commitment(expected: &[u8]) -> Result<usize> {
    let mut found = None;
    let mut index = 0;
    loop {
        match load_cell_capacity(index, Source::Input) {
            Ok(capacity) => {
                let lock_hash =
                    load_cell_lock_hash(index, Source::Input).map_err(|_| ScriptError::Encoding)?;
                let type_hash =
                    load_cell_type_hash(index, Source::Input).map_err(|_| ScriptError::Encoding)?;
                let data =
                    load_cell_data(index, Source::Input).map_err(|_| ScriptError::Encoding)?;
                let commitment = vault_cell_commitment_v1(
                    lock_hash.as_slice(),
                    capacity,
                    type_hash.as_ref().map(|hash| hash.as_slice()),
                    data.as_slice(),
                );
                if commitment.as_slice() == expected {
                    if found.is_some() {
                        return Err(ScriptError::StateCellAmbiguous);
                    }
                    found = Some(index);
                }
                index += 1;
            }
            Err(SysError::IndexOutOfBound) | Err(SysError::ItemMissing) => break,
            Err(_) => return Err(ScriptError::Encoding),
        }
    }
    found.ok_or(ScriptError::StateCellMissing)
}

#[cfg(target_arch = "riscv64")]
fn find_splice_witness_raw(
    expected_funding_anchor: &[u8],
    match_old_anchor: bool,
) -> Result<alloc::vec::Vec<u8>> {
    let mut found: Option<alloc::vec::Vec<u8>> = None;
    let mut index = 0;
    loop {
        match load_witness_args(index, Source::Input) {
            Ok(witness_args) => {
                if let Some(input_type) = witness_args.input_type().to_opt() {
                    let raw = input_type.raw_data();
                    if let Ok(witness) = SpliceStateTransitionWitnessV1::parse(raw.as_ref()) {
                        let header = witness.header()?;
                        let anchor = if match_old_anchor {
                            header.old_funding_anchor()
                        } else {
                            header.new_funding_anchor()
                        };
                        if anchor == expected_funding_anchor {
                            if found.is_some() {
                                return Err(ScriptError::SpliceProofEncoding);
                            }
                            found = Some(raw.as_ref().to_vec());
                        }
                    }
                }
                index += 1;
            }
            Err(SysError::IndexOutOfBound) | Err(SysError::ItemMissing) => break,
            Err(_) => return Err(ScriptError::Encoding),
        }
    }
    found.ok_or(ScriptError::SpliceProofEncoding)
}

#[cfg(target_arch = "riscv64")]
fn find_unique_state_cell(
    source: Source,
    current_script: &ckb_std::ckb_types::packed::Script,
    expected_funding_anchor: &[u8],
) -> Result<(usize, alloc::vec::Vec<u8>)> {
    let mut found: Option<(usize, alloc::vec::Vec<u8>)> = None;
    let mut index = 0;
    loop {
        match load_cell_data(index, source) {
            Ok(data) => {
                if let Ok(header) = StateHeaderV1::parse(&data)
                    && header.funding_anchor() == expected_funding_anchor
                    && state_type_script_matches_anchor(
                        current_script,
                        index,
                        source,
                        expected_funding_anchor,
                    )?
                {
                    if found.is_some() {
                        return Err(ScriptError::StateCellAmbiguous);
                    }
                    found = Some((index, data));
                }
                index += 1;
            }
            Err(SysError::IndexOutOfBound) | Err(SysError::ItemMissing) => break,
            Err(_) => return Err(ScriptError::Encoding),
        }
    }
    found.ok_or(ScriptError::StateCellMissing)
}

#[cfg(target_arch = "riscv64")]
fn validate_peer_state_type_script(
    current_script: &ckb_std::ckb_types::packed::Script,
    index: usize,
    source: Source,
    expected_funding_anchor: &[u8],
) -> Result<()> {
    if state_type_script_matches_anchor(current_script, index, source, expected_funding_anchor)? {
        Ok(())
    } else {
        Err(ScriptError::StateTypeMismatch)
    }
}

#[cfg(target_arch = "riscv64")]
fn state_type_script_matches_anchor(
    current_script: &ckb_std::ckb_types::packed::Script,
    index: usize,
    source: Source,
    expected_funding_anchor: &[u8],
) -> Result<bool> {
    let Some(candidate) = load_cell_type(index, source).map_err(|_| ScriptError::Encoding)? else {
        return Ok(false);
    };
    if candidate.code_hash() != current_script.code_hash()
        || candidate.hash_type() != current_script.hash_type()
    {
        return Ok(false);
    }
    let current_args = current_script.args().raw_data();
    let candidate_args = candidate.args().raw_data();
    if candidate_args.len() != current_args.len() || candidate_args.len() < BYTE32_LEN {
        return Ok(false);
    }
    if &candidate_args.as_ref()[..BYTE32_LEN] != expected_funding_anchor {
        return Ok(false);
    }
    Ok(candidate_args.as_ref()[BYTE32_LEN..] == current_args.as_ref()[BYTE32_LEN..])
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
