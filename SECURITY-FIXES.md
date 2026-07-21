# Security Fixes Closeout

This is a historical safety-kernel closeout for baseline `8944bf7`. It is
superseded for current devnet release-candidate status by the stateful closeout
at `3814453` in
[`docs/devnet-stateful-acceptance-closeout.md`](docs/devnet-stateful-acceptance-closeout.md).

This note records the local P0/P1 safety-boundary fixes for the current safety
kernel candidate. It is intended as reviewer context for the security-fix
baseline commit.

Status at this closeout: the known local P0/P1 safety-kernel blockers were
addressed in the implementation baseline, making this a current safety-kernel audit
candidate. This was not a mainnet-ready or production-ready claim; value limits
still required external diff review, mainnet-like evidence, supply-chain
revalidation, operational readiness sign-off, and value-limit policy.

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
- Remaining limitation: this closes the current authenticity boundary for the
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
- Remaining limitation: current intentionally supports only relative block-number
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
- Remaining limitation: this uses the current current vault commitment shape; any
  future multi-vault set must update the commitment and tests together.

## FactoryVault materialisation authority

- Issue: the original `FactoryStateHeader` committed rights and reserve-policy
  roots, but not the actual shared-pool Cell. Factory creation signatures and
  ordinary updates therefore did not bind the FactoryVault lock, capacity,
  type, or data, and Factory splice signatures bound descriptors/deltas without
  binding their concrete old/new Cell materialisations.
- Attack model: a host or transaction builder substitutes a different reserve
  Cell while presenting otherwise valid Factory rights, exit, or splice
  evidence; a bridge cannot derive the current pool materialisation from the
  canonical Factory state alone.
- Fix: `FactoryStateHeader` now includes
  `vault_materialisation_root = H(lock_hash, capacity, type_hash, data)`.
  Factory creation requires exactly one matching FactoryVault output. Ordinary
  signature, reduced-rights, and sparse-Merkle updates must preserve the root.
  Local/reduced exits and full/reduced splices require matching old input and
  new output materialisations. `FactorySpliceHeader` additionally signs both
  roots, and `morph-factory-vault-lock` independently checks its group input and
  output against the old/new Factory headers.
- Negative tests:
  `factory_type_rejects_initial_state_without_committed_factory_vault`,
  `factory_type_rejects_initial_state_with_wrong_factory_vault_commitment`,
  `factory_type_rejects_initial_state_with_ambiguous_factory_vaults`,
  `factory_type_rejects_signed_ordinary_update_with_factory_vault_root_drift`,
  plus the existing Factory splice/exit capacity, type, and amount mismatch
  families.
- Remaining limitation: the root commits Cell content, not its exact OutPoint.
  A separately funded byte-identical clone has the same commitment. Exact
  provenance binding is therefore an open mainnet blocker, not closed by this
  materialisation fix.

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
- Fix: reduced-exit current now checks the ReserveClaim asset domain. CKB releases
  require an untyped claim and bind `release_quantity` to child vault capacity.
  xUDT releases require a typed claim whose asset type matches the descriptor
  and bind `release_quantity` to the child vault token amount.
- Negative tests: `factory_type_and_vault_accept_reduced_exit_reserve_release`,
  `rejects_reduced_factory_exit_release_mismatch`,
  `factory_type_rejects_reduced_exit_typed_claim_for_ckb_release`,
  `factory_type_and_vault_accept_reduced_exit_xudt_reserve_release`,
  `factory_type_and_vault_accept_reduced_exit_xudt_full_release_without_typed_change`,
  `factory_type_rejects_reduced_exit_xudt_claim_asset_type_mismatch`.
- Devnet evidence: CKB and xUDT reduced-exit smoke paths are active. The xUDT
  smoke covers partial typed FactoryVault change, full release with CKB-only
  change, one-sided child settlement, and child token amount mismatch rejection.

## xUDT reduced-exit typed binding

- Current status: contract, CKB-VM, and devnet smoke coverage are active for
  xUDT reduced-exit current. The witness reuses the fixed-width xUDT descriptor
  variant; no new schema is introduced.
- Fix: the factory type checks child-vault type hash, token amount, capacity,
  descriptor version, and descriptor commitment. The factory vault lock checks
  FactoryVault capacity conservation and typed xUDT change amount.
- Negative tests:
  `factory_type_rejects_reduced_exit_xudt_amount_mismatch`,
  `factory_type_rejects_reduced_exit_xudt_type_mismatch`,
  `factory_vault_rejects_reduced_exit_xudt_change_amount_mismatch`,
  `factory_vault_rejects_reduced_exit_xudt_missing_typed_change`,
  `factory_type_rejects_reduced_exit_xudt_capacity_mismatch`.
- Devnet negative smoke:
  `factory-reduced-xudt-negative-exit-smoke` rejects child token amount mismatch
  even when the FactoryVault change preserves total token supply.

## Sponsor policy boundary

- Issue: sponsor `expiry` and `allowed_sponsor_source` are meaningful operator
  policy fields, but the current sponsor lock has no verifiable clock/source
  evidence for enforcing them on chain.
- Attack model: documentation overstates script-enforced sponsor safety and a
  reviewer assumes operator-only policy fields are consensus checks.
- Fix: current documents the script-enforced sponsor boundary as state type,
  channel/state-number range, fee caps, and clean change. The sponsor lock now
  rejects finite script-level `expiry` values instead of silently accepting an
  unenforceable deadline. Expiry windows, sponsor source, cadence, webhook
  policy, and similar runtime bounds are operator/watchtower policy until a
  future script-verifiable design exists.
- Negative tests: `sponsor_lock_rejects_fee_above_per_tx_limit`,
  `sponsor_lock_rejects_state_number_outside_policy_range`,
  `sponsor_lock_rejects_finite_expiry_policy`,
  `rejects_fee_above_operator_limit`,
  `rejects_explicit_sponsor_when_policy_forbids_it`.
- Remaining limitation: finite expiry windows and sponsor source are not current
  script-enforced fields; finite script-level expiry is rejected.

## Evidence run

The local verification run for this closeout passed:

- `make test`
- `make lint`
- `make fixture-checks`
- `make contract-tests`
- `make fmt-check`
- `git diff --check`

Historical supply-chain status for this closeout: `make supply-chain` was
attempted twice, but `cargo audit` could not fetch the RustSec advisory
database because the GitHub request failed with an IO error. Later evidence:
`make supply-chain` passed in the devnet stateful closeout at `3814453`.
Mainnet release still requires release/CI supply-chain revalidation.
