# Security Fixes Closeout

This note records the local P0/P1 safety-boundary fixes for the V1 safety
kernel candidate. It is intended as reviewer context for the security-fix
baseline commit.

Current status: the known local P0/P1 safety-kernel blockers are addressed in
the implementation baseline, making this a V1 safety-kernel audit candidate.
This is not a mainnet-ready or production-ready claim; value limits still
require external diff review, mainnet-like evidence, supply-chain gates, and
operational readiness sign-off.

Implementation safety-boundary baseline: `8944bf7`.

## Authentic StateCell authority

- Issue: Vault and sponsor paths must not treat bytes that decode as a
  `StateHeader` as protocol authority.
- Attack model: an attacker publishes an ordinary cell whose data parses as a
  Morph state header and points settlement or sponsor publication at their own
  outputs.
- Fix: Vault finalisation now requires exactly one authentic StateCell input
  with the expected StateType and StateLock identity. Watchtower detection also
  filters StateCells by StateType/StateLock identity instead of data alone.
- Negative tests: `vault_lock_rejects_fake_state_header_without_state_type`,
  `sponsor_lock_rejects_fake_state_header_without_state_type`,
  `watchtower_state_detection_requires_authentic_state_scripts`.
- Remaining limitation: this closes the V1 authenticity boundary for the
  implemented fixed-width state scripts; future descriptor runtimes or new
  state script versions must add equivalent authenticity tests before use.

## Canonical relative since

- Issue: raw `u64` comparison does not implement CKB `since` semantics.
- Attack model: a raw absolute value such as `4` can mature immediately once
  the chain height is above that value.
- Fix: finalisation uses canonical relative-block `since`; CLI arguments remain
  relative block counts and are encoded before transaction construction.
- Negative tests: `vault_lock_rejects_raw_absolute_since`,
  `finalise-since-negative-smoke`.
- Remaining limitation: V1 intentionally supports only relative block-number
  maturity. Epoch or timestamp maturity remains future work.

## State retirement cannot orphan value

- Issue: retiring a StateCell without consuming the bound VaultCell can remove
  the current state evidence while leaving value locked.
- Attack model: a standalone settling close or active splice retire consumes
  the StateCell but leaves the VaultCell without usable current-state evidence.
- Fix: StateType finalise and active splice-retire paths require an input whose
  VaultCell commitment matches `StateHeader.payload_commitment`.
- Negative tests:
  `state_type_rejects_standalone_settling_close_without_matching_vault`,
  `state_type_rejects_standalone_active_splice_retire_without_matching_vault`.
- Remaining limitation: this uses the current V1 vault commitment shape; any
  future multi-vault set must update the commitment and tests together.

## Merkle locality is not mint authority

- Issue: a single-right sparse Merkle proof proves locality, not economic
  validity.
- Attack model: an authorised participant uses the generic Merkle update path
  to increase a value-bearing right without a matching FactoryVault delta or
  full-participant consent.
- Fix: the plain single-right Merkle update path accepts only authorised
  value-right decreases. Increases remain available only through full consent
  or dedicated vault-delta-bound splice paths.
- Negative tests: `factory_sparse_merkle_update_rejects_value_right_increase`,
  `factory_type_rejects_sparse_merkle_right_increase`.
- Remaining limitation: generic multi-right or variable-depth reduced proofs
  are still deferred; unknown proof shapes must remain rejected.

## Reduced exit release binding

- Issue: reserve-claim reduction must be tied to the actual child-vault asset
  release.
- Attack model: a reduced exit decreases the claim by a smaller amount than the
  child vault receives.
- Fix: CKB reduced-exit V1 requires the consumed ReserveClaim to be an
  untyped CKB claim, requires child vault capacity to equal
  `release_quantity`, and keeps FactoryVault conservation checks in the
  factory vault lock.
- Negative tests: `factory_type_and_vault_accept_reduced_exit_reserve_release`,
  `rejects_reduced_factory_exit_release_mismatch`,
  `factory_type_rejects_reduced_exit_typed_claim_for_ckb_release`.
- Remaining limitation: the active reduced-exit path is CKB-only. Typed assets
  require the disabled xUDT path to be restored with full typed binding.

## xUDT reduced-exit limitation

- Current status: CKB reduced-exit V1 is active. xUDT reduced-exit V1 is
  disabled pending complete typed release binding across child-vault type hash,
  child amount, settlement descriptor, and FactoryVault typed change.
- Rationale: a disabled typed reduced-exit path is safer than a partially bound
  value-bearing release path.
- Negative test: `factory_type_rejects_reduced_exit_xudt_reserve_release_v1_disabled`.
- Remaining limitation: typed reduced exits require a future witness and script
  path that binds child-vault type hash, token amount, descriptor commitment,
  and FactoryVault typed change in the same proof.

## Sponsor policy boundary

- Issue: sponsor `expiry` and `allowed_sponsor_source` are meaningful operator
  policy fields, but the current sponsor lock has no verifiable clock/source
  evidence for enforcing them on chain.
- Attack model: documentation overstates script-enforced sponsor safety and a
  reviewer assumes operator-only policy fields are consensus checks.
- Fix: V1 documents the script-enforced sponsor boundary as state type,
  channel/state-number range, fee caps, and clean change. Expiry, sponsor
  source, cadence, webhook policy, and similar runtime bounds are
  operator/watchtower policy until a future script-verifiable design exists.
- Negative tests: `sponsor_lock_rejects_fee_above_per_tx_limit`,
  `sponsor_lock_rejects_state_number_outside_policy_range`,
  `rejects_fee_above_operator_limit`,
  `rejects_explicit_sponsor_when_policy_forbids_it`.
- Remaining limitation: expiry/source are not V1 script-enforced fields.

## Evidence run

The local verification run for this closeout passed:

- `make test`
- `make lint`
- `make fixture-checks`
- `make contract-tests`
- `make fmt-check`
- `git diff --check`

Supply-chain status: `make supply-chain` was attempted twice during closeout,
but `cargo audit` could not fetch the RustSec advisory database because the
GitHub request failed with an IO error. This remains a mainnet-readiness
blocker, not a V1 safety-kernel audit-candidate blocker.
