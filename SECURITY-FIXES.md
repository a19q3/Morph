# Security Fixes And Trust-Boundary Closeout

This is the living reviewer index for security-boundary fixes and explicitly
accepted trust boundaries. The earliest safety-kernel closeout was baseline
`8944bf7`; current executable acceptance commands and release posture are
tracked in [`docs/devnet.md`](docs/devnet.md) and
[`docs/mainnet-readiness.md`](docs/mainnet-readiness.md). Superseded closeout
snapshots remain available from git history rather than the current docs tree.

The 2026-08-15 swarm audit was performed at `9ab9ec1` and is preserved in
[`docs/swarm-audit-glm-2026-08-15.md`](docs/swarm-audit-glm-2026-08-15.md).
Commit `1cc830f` closes AUD-01, AUD-03, AUD-04, and AUD-05. AUD-02 is an
explicit code-identity trust boundary rather than a hidden signature check: a
FactoryProof child delegates creation authority to the exact FactoryType hash
in its StateType args, so deployments must pin the audited FactoryType code.

None of these closeouts is a mainnet-ready or production-ready claim. External
review, mainnet-like fee/reorg evidence, independent release verification,
multi-operator rehearsal, and a real-asset value policy remain required.

## Factory-materialised State authority binding (2026-08-13)

- Issue: a FactoryProof State creation parsed the Factory exit envelope from
  input zero but did not bind that carrier to the exact FactoryType script
  authorised by the child transaction.
- Fix: FactoryProof StateType args now commit the 32-byte FactoryType script
  hash between the funding anchor and required relative `since`. Creation
  rejects bilateral witnesses with Factory args, rejects Factory witnesses
  without those args, and requires input zero's Type Script hash to match the
  committed FactoryType identity before accepting the materialised child.
- Negative test:
  `state_type_rejects_factory_exit_without_bound_factory_authority`.
- Current boundary: bilateral StateType args are exactly 40 bytes and Factory
  child args are exactly 72 bytes. Unpublished shorter forms are rejected.
- Trust boundary: the child StateType delegates authorisation to the exact
  FactoryType script hash committed in those 72-byte args; it does not
  independently repeat the Factory witness signature checks. Deployments must
  therefore pin an audited FactoryType code identity. Committing a permissive
  script can create only a fresh, separately addressed child authority and does
  not grant access to children committed to the audited FactoryType.

## Signed splice withdrawal destinations (2026-08-15)

- Issue: bilateral, full-factory, and reduced-factory splice-out signatures
  committed withdrawal amounts but not the output lock, allowing a transaction
  assembler to redirect the payout.
- Fix: `SpliceHeader` and `FactorySpliceHeader` now include a signed
  `withdrawal_lock_hash`. Vault scripts require every nonzero CKB/xUDT
  withdrawal delta to have exactly one output with that lock, asset type, and
  amount. Splice-in requires a zero target; splice-out requires a nonzero
  target. This is an intentional unpublished wire-format break: header lengths
  are now 485/469 bytes and the affected witness body versions are 2.
- Negative tests:
  `vault_lock_rejects_splice_out_with_substituted_withdrawal_lock` and
  `factory_vault_rejects_reduced_splice_out_with_substituted_withdrawal_lock`.

## Settlement and host/script parity fixes (2026-08-15)

- Plain CKB settlement rejects typed Vault inputs, matching the CKB-only
  descriptor profile. Negative test:
  `vault_lock_rejects_ckb_only_settlement_with_typed_vault_input`.
- Host splice validation now requires both current and successor states to be
  Active, and reduced Factory splice validation requires a bound old Vault
  outpoint plus an unbound successor, matching the on-chain scripts.

## Agent and remote HTTP boundaries (2026-08-13)

- Issue: Agent/Fiber/Gateway/hook clients admitted remote cleartext HTTP,
  response limits were applied only after whole-body buffering, durable public
  challenge and offer creation was unbounded, and the payment index exposed
  raw provider metadata.
- Fix: remote service URLs require HTTPS while loopback HTTP remains available
  for local devnet. Response readers enforce limits incrementally. Non-loopback
  Agent listeners require a minimum-length API bearer token; the token gates
  durable creation and operator-observability routes. Transient records have
  count and serialized-size reserves, expired records are pruned, creation is
  rate limited, raw payment metadata is size bounded, and the public response
  is a redacted projection.
- Tests: `plaintext_http_is_loopback_only`,
  `chunked_response_is_rejected_as_soon_as_the_limit_is_crossed`,
  `outstanding_challenge_quota_rejects_without_corrupting_existing_state`,
  `payment_index_requires_auth_and_redacts_raw_fiber_metadata`, and the
  Agent/Fiber/hook TLS constructor tests.

## Watchtower alert egress and file privacy (2026-08-13)

- Issue: a validated webhook could redirect to an unvalidated destination and
  JSONL alert files inherited ambient process permissions.
- Fix: webhook redirects are disabled, including for loopback development
  URLs. On Unix, alert files are created and tightened to mode `0600` on every
  append.
- Tests: `webhook_does_not_follow_redirects` and `appends_jsonl_alerts`.

## Post-baseline sovereign Factory hardening (2026-07-22)

- Issue: the devnet transaction layer placed FactoryStateCells under an
  operator secp lock. Participant/reduced proof acceptance was therefore not
  sufficient to spend the cell without the fee payer's private key.
- Fix: newly created FactoryStateCells use `morph-state-lock` with the exact
  FactoryType hash as lock args. Factory protocol evidence remains in
  `input_type`; the operator secp signature signs only a distinct fee-input
  lock group. Update, full/reduced splice, exit, and activation paths validate
  the type-bound lock before building a transaction. Reduced exit can use the
  non-signing counterparty's compressed public key instead of their private
  key.
- Tests: `factory_fee_signature_does_not_gate_the_factory_state_witness`,
  `reduced_exit_witness_needs_only_counterparty_public_key`, and
  `factory_type_and_vault_accept_reduced_exit_reserve_release` using the real
  StateLock.
- Pre-release policy: no owner-locked Factory shape is supported; no-value
  devnet state is discarded and recreated after a boundary change.

## Exact State/Factory carrier conservation (2026-07-22)

- Issue: the State and Factory type scripts rejected outputs below occupied
  capacity but did not require the remaining carrier capacity to stay in the
  successor. A valid protocol witness could therefore accompany a carrier
  drain.
- Fix: ordinary updates preserve capacity exactly. Deterministic Vault binding
  consumes exactly `STATE_CARRIER_ACTIVATION_FEE = 10_000` shannons, while
  splice/exit creates the next unbound carrier with exactly that reserve added.
- Negative tests:
  `state_type_rejects_signed_supersede_carrier_drain`,
  `factory_type_rejects_signed_factory_update_carrier_drain`,
  `state_type_rejects_vault_activation_carrier_drain`,
  `factory_type_rejects_vault_activation_carrier_drain`,
  `state_type_rejects_splice_without_carrier_activation_reserve`, and
  `factory_type_rejects_splice_without_carrier_activation_reserve`.

## Bilateral backend commit deadline (2026-07-22)

- Issue: payment preparation rejected expired intents, but commit did not bind
  a commit time and could accept a previously prepared intent after expiry.
- Fix: `ChannelBackend::commit_payment` requires `committed_at_unix` and accepts
  only `prepared_at_unix <= committed_at_unix < expires_at_unix`.
- Negative test: `commit_rejects_times_outside_the_prepared_intent_window`.

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
- Fix: StateType finalise and active splice-retire paths require the exact
  VaultCell input named by `StateHeader.vault_outpoint_commitment`, and also
  require its content to match `vault_materialisation_root`.
- Negative tests:
  `state_type_rejects_standalone_settling_close_without_matching_vault`,
  `state_type_rejects_standalone_active_splice_retire_without_matching_vault`.
- Remaining limitation: any future multi-vault set must version the locator
  commitment and tests together.

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
- Fix: `FactoryStateHeader` includes
  `vault_materialisation_root = H(lock_hash, capacity, type_hash, data)`.
  Creation emits an unbound State/Factory plus exactly one matching Vault. A
  separate activation transaction must preserve every signed field and bind
  `vault_outpoint_commitment = H("CKB_MORPH_VAULT_OUTPOINT_V1", tx_hash,
  u32_le(index))` to the exact live Vault presented as the first direct
  CellDep. Ordinary signature, reduced-rights, and sparse-Merkle updates must
  preserve both commitments. Local/reduced exits and full/reduced splices
  require the exact old Vault input, emit an unbound reserve-changing
  successor, and reactivate it before later use. `FactorySpliceHeader` signs
  both old/new content roots and OutPoint locators. The Factory type and vault
  lock check these boundaries independently.
- Negative tests:
  `factory_type_rejects_initial_state_without_committed_factory_vault`,
  `factory_type_rejects_initial_state_with_wrong_factory_vault_commitment`,
  `factory_type_rejects_initial_state_with_ambiguous_factory_vaults`,
  `factory_type_rejects_signed_ordinary_update_with_factory_vault_root_drift`,
  `state_type_rejects_byte_identical_clone_vault_activation`,
  `factory_type_rejects_byte_identical_clone_vault_activation`,
  `state_type_rejects_vault_activation_lock_drift`,
  `factory_type_rejects_vault_activation_lock_drift`,
  `factory_type_rejects_noncanonical_vault_activation_dep`,
  plus the existing Factory splice/exit capacity, type, and amount mismatch
  families.
- Remaining limitation: this closes the known clone/substitution path in the
  implemented single-Vault profile, but still requires independent review and
  an explicit deployment policy before mainnet deployment.

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

- Issue: expiry, sponsor-source, and cadence are meaningful operator policy,
  but the current sponsor lock has no verifiable clock/source evidence for
  enforcing them on chain.
- Attack model: documentation overstates script-enforced sponsor safety and a
  reviewer assumes operator-only policy fields are consensus checks.
- Fix: current documents the script-enforced sponsor boundary as state type,
  channel/state-number range, per-cell fee caps, exact fee attribution, and
  clean change. The current 136-byte `SponsorPolicy` has no expiry or sponsor
  source field. Expiry windows, sponsor source, cadence, webhook policy, and
  similar runtime bounds are operator/watchtower policy until a future
  script-verifiable design exists.
- Negative tests: `sponsor_lock_rejects_fee_above_per_tx_limit`,
  `sponsor_lock_rejects_state_number_outside_policy_range`,
  `sponsor_lock_rejects_third_party_capacity_diversion`,
  `rejects_fee_above_operator_limit`,
  `rejects_explicit_sponsor_when_policy_forbids_it`.
- Remaining limitation: expiry windows and sponsor source are not current
  script-enforced fields.

## Evidence run

The local verification run for this closeout passed:

- `make test`
- `make lint`
- `make fixture-checks`
- `make contract-tests`
- `make fmt-check`
- `git diff --check`

Historical supply-chain status for the earliest closeout: `cargo audit` could
not fetch the RustSec advisory database because the GitHub request failed with
an IO error. Later cached and CI runs passed the repository's narrow reviewed
waiver policy. Every release candidate must still rerun `make supply-chain` and
record fresh CI/independent-build evidence.
