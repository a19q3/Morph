# Executable Audit Matrix

The paper's audit matrix is represented in `crates/morph-core/tests/invariants.rs`.

| Invariant | Current executable check |
| --- | --- |
| One live State Cell controls the channel pointer | `accepts_valid_state_supersession`, `rejects_stale_or_equal_state_number` |
| Funding anchor identity is canonical | `rejects_wrong_funding_anchor_reference`, `rejects_changed_header_context` |
| StateHeaderV2 funding epoch and vault-set commitments are signed state semantics | `state_header_v2_digest_binds_epoch_and_vault_set`, `state_header_v2_context_rejects_epoch_and_vault_set_changes`, `state_header_v2_fields_are_fixed_width`, `verifies_splice_state_transition_v2_epoch_bridge` |
| State numbers are strictly monotonic | `rejects_stale_or_equal_state_number` |
| State evidence is signed by participants | `rejects_invalid_state_signature`, `state_type_rejects_invalid_participant_signature` |
| Factory state evidence is signed by all factory participants | `factory_type_accepts_signed_factory_update`, `factory_type_rejects_invalid_participant_signature` |
| Factory state pointer is unique and monotonic | `factory_type_accepts_canonical_initial_factory_state`, `factory_type_accepts_signed_factory_update`, `factory_type_rejects_equal_update_number` |
| Factory reserve is conserved during child-channel exit | `factory_type_and_vault_accept_local_exit_materialisation`, `factory_type_and_vault_accept_local_exit_xudt_materialisation`, `factory_type_and_vault_accept_reduced_exit_reserve_release`, `factory_type_rejects_reduced_exit_xudt_reserve_release_v1_disabled`, `factory_type_rejects_local_exit_digest_mismatch`, `factory_type_rejects_local_exit_state_lock_mismatch`, `factory_type_rejects_local_exit_xudt_amount_mismatch`, `factory_type_rejects_local_exit_xudt_type_mismatch` |
| Factory splice reserve claims match exact vault deltas | `accepts_valid_factory_splice_in_transition`, `accepts_valid_factory_xudt_splice_out_transition`, `factory_splice_rejects_reserve_claim_without_vault_input`, `factory_splice_rejects_vault_release_without_rights_decrease`, `factory_splice_rejects_xudt_type_mismatch`, `factory_splice_rejects_invalid_signature`, `validates_factory_splice_package`, `validates_factory_xudt_splice_out_package`, `writes_reads_and_validates_factory_splice_package`, `rejects_factory_splice_vault_delta_mismatch`, `factory_splice_witness_fields_are_fixed_width`, `verifies_factory_splice_update`, `rejects_factory_splice_vault_delta_tamper`, `factory_type_and_vault_accept_factory_splice_in`, `factory_vault_rejects_factory_splice_capacity_mismatch` |
| Vault value follows current state evidence | `vault_spend_accepts_finalise_after_since`, `vault_spend_rejects_unmatured_finalise`, `vault_lock_accepts_finalise_with_current_state` |
| Vault outputs match the signed settlement descriptor | `accepts_signed_settlement_descriptor_update`, `state_type_accepts_signed_descriptor_update`, `vault_lock_accepts_finalise_with_current_state`, `vault_lock_rejects_descriptor_output_mismatch` |
| Splice transitions preserve StateCell/VaultCell funding epochs | `state_and_vault_accept_splice_in_bridge`, `state_and_vault_accept_splice_out_bridge`, `state_and_vault_reject_splice_wrong_channel_header`, `vault_lock_rejects_splice_new_vault_capacity_mismatch` |
| Authentic StateCell authority gates value and monitoring | `vault_lock_rejects_fake_state_header_without_state_type`, `state_type_rejects_standalone_settling_close_without_matching_vault`, `state_type_rejects_standalone_active_splice_retire_without_matching_vault`, `watchtower_state_detection_requires_authentic_state_scripts` |
| Splice-out payouts stay participant-owned in V1 | `validates_splice_out_fixture`, `validates_xudt_splice_out_fixture`, `participant_pubkey_lock_matches_private_key_lock` |
| Channel-owned capacity never pays publication fees | `rejects_channel_paid_fee_leakage` |
| Reserve and business CKB are not confused | `rejects_business_ckb_confusion` |
| xUDT value is conserved by canonical type script | `rejects_xudt_type_mismatch`, `rejects_xudt_amount_mismatch` |
| Sponsor change is uncontaminated | `rejects_sponsor_change_contamination` |
| Unrelated Cells cannot influence channel validity | `rejects_unrelated_cell_used_for_channel_semantics` |
| Sponsor budget cannot be drained | `sponsor_policy_rejects_drain_attempt` |
| Sponsor fee pays a real Morph state publication, not an arbitrary transfer | `sponsor_lock_accepts_bounded_fee_with_wallet_change`, `sponsor_lock_rejects_fee_without_state_publication`, `sponsor_lock_rejects_fake_state_header_without_state_type` |
| Sponsor policy bounds are enforced by script | `sponsor_lock_rejects_fee_above_per_tx_limit`, `sponsor_lock_rejects_state_number_outside_policy_range` |
| Watchtower operator bounds are checked before publication | `accepts_fixture_policy_run`, `rejects_shallow_detection_depth`, `rejects_fee_above_operator_limit`, `rejects_explicit_sponsor_when_policy_forbids_it`, `rejects_wrong_channel_policy`, `rejects_webhook_when_policy_forbids_it` |
| Watchtower multi-channel config is canonical and key-free | `validates_fixture_config`, `rejects_duplicate_channels`, `rejects_channel_without_sponsor_path`, `resolves_channel_options_relative_to_config_file`, `rejects_zero_loop_options` |
| Watchtower runtime key material stays outside the config | `resolves_private_key_from_file`, `rejects_ambiguous_private_key_sources`, `rejects_multi_token_private_key_file`, `falls_back_to_devnet_key_for_local_watchers` |
| Watchtower service has bounded operational control | `service_stops_before_rpc_when_stop_file_exists`, `service_stops_after_bounded_errors_and_writes_health`, `rejects_invalid_service_options`, `rejects_missing_watchtower_service_coverage`, `rejects_unhealthy_watchtower_service_coverage` |
| Watchtower alerts are structured and deliverable | `appends_jsonl_alerts`, `posts_alert_to_webhook` |
| Smoke evidence contains watchtower detection, publication, service, and health records | `summarises_smoke_metrics_and_script_failures`, `rejects_missing_watchtower_alert_coverage`, `rejects_missing_watchtower_service_coverage`, `rejects_unhealthy_watchtower_service_coverage` |
| Smoke comparison can be used as a regression gate | `comparison_limits_reject_metric_regressions`, `comparison_limits_reject_set_and_status_changes` |
| Generated host-side fixtures are CI-validated | `make fixture-checks` |
| Factory local update does not disturb unrelated rights | `factory_non_interference_accepts_authorised_local_right_change`, `factory_non_interference_rejects_untouched_balance_change`, `factory_non_interference_rejects_untouched_exit_right_removal`, `factory_non_interference_rejects_untouched_sponsor_right_creation` |
| Factory touched set is authorised and unambiguous | `factory_non_interference_requires_touched_participant_authorisation`, `factory_non_interference_rejects_duplicate_right_ids` |
| Factory full-consent state authority is signed | `validates_factory_state_package`, `rejects_missing_factory_state_signature`, `rejects_factory_state_missing_participant_key`, `rejects_invalid_factory_state_signature`, `rejects_non_all_participant_factory_threshold` |
| Factory reduced host package signs only authorised participants | `validates_reduced_factory_state_package`, `rejects_reduced_factory_state_missing_authorised_signature`, `rejects_reduced_factory_state_extra_participant` |
| Factory reduced on-chain proof can only decrease touched rights | `verifies_reduced_factory_rights_decrease`, `rejects_reduced_factory_rights_increase`, `factory_type_accepts_reduced_rights_update`, `factory_type_rejects_reduced_rights_increase` |
| Reduced factory exit can only consume the authorised participant's reserve claim | `reduced_factory_exit_accepts_authorised_reserve_claim_release`, `reduced_factory_exit_accepts_full_reserve_claim_consumption`, `reduced_factory_exit_rejects_release_amount_mismatch`, `reduced_factory_exit_rejects_other_touched_right_changes`, `reduced_factory_exit_requires_exiting_participant_authorisation`, `reduced_factory_exit_rejects_extra_authorised_participant` |

Implemented devnet-level checks:

- real CKB transaction construction for deploy, open, publish, supersede,
  sponsor top-up, and finalise;
- CKB-VM factory type execution for canonical factory creation and signed
  monotonic factory updates;
- CKB-VM factory type execution for a bounded reduced-rights update where one
  authorised participant can decrease only their own committed rights;
- devnet publication of a bounded reduced-rights factory package through
  `devnet factory-reduced-rights-smoke`;
- CKB-VM factory local-exit execution with a FactoryVaultCell, committed
  child-channel evidence, reserve conservation, and CKB+xUDT child-vault
  materialisation;
- CKB-VM reduced factory-exit execution for the active CKB child-vault path,
  typed ReserveClaim rejection on that CKB-only path, plus disabled-path
  rejection for xUDT reduced-exit V1;
- finalise-since rejection and maturity-block finalisation through
  `devnet finalise-since-negative-smoke`;
- CKB+xUDT vault publication and settlement on devnet through
  `devnet xudt-smoke`;
- CKB+xUDT factory child-channel materialisation and finalisation on devnet
  through `devnet factory-xudt-smoke`;
- factory CKB+xUDT child-vault amount rejection on devnet through
  `devnet factory-xudt-negative-smoke`;
- CKB+xUDT tampered settlement rejection on devnet through
  `devnet xudt-negative-smoke`;
- competing StateCell publication rejection from the node's tx-pool-aware
  live-cell view, followed by rebuilt publication against the confirmed
  live StateCell, through
  `devnet competing-spend-smoke`;
- sponsor fee-cap rejection and fresh SponsorCell rotation through
  `devnet sponsor-budget-negative-smoke`;
- sponsor state-number range rejection through
  `devnet sponsor-policy-negative-smoke`;
- watchtower policy checking for confirmation depth, fee, sponsor mode, and
  automatic sponsor capacity before confirmed-block scanning starts;
- bounded multi-channel watchtower config loops that reuse persisted cursors
  between passes;
- foreground watchtower service mode with health-file output, stop-file
  shutdown, error backoff, and consecutive-error limits;
- watchtower JSONL and HTTP webhook alerts for older-state detection,
  submitted publication, confirmed splice detection, stale splice package
  selection, splice-aware publication, and idle scans;
- splice negative smoke coverage for stale funding epoch, wrong channel id,
  wrong vault type, insufficient remaining vault value, tampered xUDT delta, and
  signed-fee leakage rejections;
- conservative splice V1 policy: quiescent base state number, explicit
  funding-epoch semantics, fixed-width typed deltas, and participant-owned
  splice-out payouts;
- smoke assertions that require older-state detection, publication-submitted,
  splice-detected, and stale splice-package watchtower alert evidence in the
  default smoke run;
- smoke assertions that require watchtower service and health-file evidence for
  the bounded stop-file path in the default smoke run;
- node-reported cycle measurement and transaction size reporting, summarised by
  `devnet-smoke-report`;
- semantic smoke coverage assertions for the expected negative-path script
  failures, deployed script set, local contract binary hashes, and factory
  local-exit evidence through `devnet-smoke-assert`;
- optional smoke comparison gates for transaction-set, status, cycle, and
  byte-size regressions through `devnet-smoke-compare`;
- absolute smoke budget gates for total, per-transaction, and proof-profile
  cycle/byte ceilings through `devnet-smoke-assert`;
- JSON smoke budget profiles for named critical transactions and proof shapes,
  such as `factory-reduced-rights-smoke $.update`;
- CI fixture checks for bilateral fixtures, factory update packages, factory
  state packages, reduced host-side factory packages, reduced-rights factory
  packages, reduced-exit host packages, local-exit evidence, watchtower policy
  JSON, and multi-channel watchtower config JSON;
- durable signed state-package storage with signature validation and latest
  package selection;
- confirmation-depth block scanning for older Morph StateCells;
- conservative factory local exit on devnet through `factory-exit-channel`,
  followed by ordinary child-channel publication and finalisation in
  `scripts/devnet-smoke.sh`.
- bounded reduced factory exits on devnet through `factory-reduced-exit-smoke`,
  followed by ordinary child-channel publication and finalisation in
  `scripts/devnet-smoke.sh`.
- xUDT reduced-exit V1 is disabled pending typed release binding; the active
  executable checks are
  `factory_type_rejects_reduced_exit_typed_claim_for_ckb_release` and
  `factory_type_rejects_reduced_exit_xudt_reserve_release_v1_disabled`.

Deferred devnet-level checks:

- typed reduced-exit variants pending complete child-vault type hash, amount,
  settlement descriptor, and FactoryVault typed-change binding.

Implemented factory checks:

- rights-dependency model for balances, reserve claims, membership, exit paths,
  and sponsor budget claims;
- local update acceptance only for declared touched participants with matching
  authorisation;
- rejection of balance changes, exit-right removals, and sponsor-budget
  creations outside the touched set;
- duplicate right-id rejection before proof evaluation.
- host-level reduced factory-exit validation for the narrow reserve-claim
  consumption case: one authorised participant may release only their own
  committed reserve claim, and every other right must remain unchanged.
- serialisable reduced factory-exit package fixture and CLI validation for the
  same host-level reserve-claim consumption predicate.
- serialisable sparse Merkle factory update fixture and CLI validation for a
  single-right transition inside a larger rights tree.
- script-level sparse Merkle factory update witness for the same single-right
  transition, with CKB-VM accept/reject coverage.
- devnet smoke coverage for the sparse Merkle factory update witness, including
  package evidence and proof-shape budget profile evidence in the smoke
  summary assertion.
- smoke-summary proof profile coverage for the bounded reduced-rights update,
  sparse Merkle update, and CKB reduced-exit proof shapes.
- script-level reduced factory-exit validation for the same reserve-claim
  release predicate, with factory type and factory vault lock CKB-VM coverage.
- serialisable factory update package with canonical roots, canonical
  participant sets, non-interference digest checking, and CLI validation through
  `print-factory-fixture` / `validate-factory-package`.
- conservative all-participant factory state package with nested
  non-interference digest checking, participant-id/public-key bindings,
  domain-separated factory-state digest, and secp256k1 signature validation
  through `print-factory-state-fixture` / `validate-factory-state-package`.
