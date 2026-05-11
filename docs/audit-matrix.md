# Executable Audit Matrix

The paper's audit matrix is represented in `crates/morph-core/tests/invariants.rs`.

| Invariant | Current executable check |
| --- | --- |
| One live State Cell controls the channel pointer | `accepts_valid_state_supersession`, `rejects_stale_or_equal_state_number` |
| Funding anchor identity is canonical | `rejects_wrong_funding_anchor_reference`, `rejects_changed_header_context` |
| State numbers are strictly monotonic | `rejects_stale_or_equal_state_number` |
| State evidence is signed by participants | `rejects_invalid_state_signature`, `state_type_rejects_invalid_participant_signature` |
| Vault value follows current state evidence | `vault_spend_accepts_finalise_after_since`, `vault_spend_rejects_unmatured_finalise`, `vault_lock_accepts_finalise_with_current_state` |
| Vault outputs match the signed settlement descriptor | `vault_lock_accepts_finalise_with_current_state`, `vault_lock_rejects_descriptor_output_mismatch` |
| Channel-owned capacity never pays publication fees | `rejects_channel_paid_fee_leakage` |
| Reserve and business CKB are not confused | `rejects_business_ckb_confusion` |
| xUDT value is conserved by canonical type script | `rejects_xudt_type_mismatch`, `rejects_xudt_amount_mismatch` |
| Sponsor change is uncontaminated | `rejects_sponsor_change_contamination` |
| Unrelated Cells cannot influence channel validity | `rejects_unrelated_cell_used_for_channel_semantics` |
| Sponsor budget cannot be drained | `sponsor_policy_rejects_drain_attempt` |
| Sponsor fee pays a Morph state publication, not an arbitrary transfer | `sponsor_lock_accepts_bounded_fee_with_wallet_change`, `sponsor_lock_rejects_fee_without_state_publication` |

Missing devnet-level checks:

- real CKB transaction construction and cycle measurement;
- mempool/rebuild behaviour against a live devnet node;
- factory non-interference proof predicates.
