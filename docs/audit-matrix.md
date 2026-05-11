# Executable Audit Matrix

The paper's audit matrix is represented in `crates/morph-core/tests/invariants.rs`.

| Invariant | Current executable check |
| --- | --- |
| One live State Cell controls the channel pointer | `accepts_valid_state_supersession`, `rejects_stale_or_equal_state_number` |
| Funding anchor identity is canonical | `rejects_wrong_funding_anchor_reference`, `rejects_changed_header_context` |
| State numbers are strictly monotonic | `rejects_stale_or_equal_state_number` |
| Vault value follows current state evidence | `vault_spend_accepts_finalise_after_since`, `vault_spend_rejects_unmatured_finalise` |
| Channel-owned capacity never pays publication fees | `rejects_channel_paid_fee_leakage` |
| Reserve and business CKB are not confused | `rejects_business_ckb_confusion` |
| xUDT value is conserved by canonical type script | `rejects_xudt_type_mismatch`, `rejects_xudt_amount_mismatch` |
| Sponsor change is uncontaminated | `rejects_sponsor_change_contamination` |
| Unrelated Cells cannot influence channel validity | `rejects_unrelated_cell_used_for_channel_semantics` |
| Sponsor budget cannot be drained | `sponsor_policy_rejects_drain_attempt` |

Missing devnet-level checks:

- real CKB transaction construction and cycle measurement;
- actual script witnesses and Molecule decoding;
- mempool/rebuild behaviour against a live devnet node;
- factory non-interference proof predicates.

