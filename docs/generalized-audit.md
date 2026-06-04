# Generalized Devnet Audit Layer

Status: executable acceptance taxonomy for devnet stateful evidence.

The stateful suite does not treat a single smoke as a complete security
argument. It maps each bug class found during review into an audit family with
required scenario tags, committed transactions, exact expected failures, and
budget evidence. `devnet-stateful-report` summarises the family status, and
`devnet-stateful-assert` fails if any family is missing evidence.

The default profile is
[`docs/devnet-audit-profile.example.json`](devnet-audit-profile.example.json)
with schema `morph.devnet_audit_profile.v1`.

The `.v1` suffix here is only the audit-profile schema version. It is not a
protocol or witness-version label. On the current post-V1 implementation line,
factory authorisation is read through the bounded `WitnessEnvelopeV2`
kind/body/digest envelope.

## Found Issue To Executable Family

| Found issue | Generalized invariant | Audit family |
| --- | --- | --- |
| Vault or monitor accepts bytes that decode as `StateHeader` | Value and monitoring authority comes from an authentic Morph StateCell identity | `state_authority_authenticity` |
| Raw `u64` since comparison weakens challenge maturity | Finalisation maturity is a canonical relative CKB since condition | `canonical_relative_maturity` |
| StateCell can be retired while value remains locked | State-track retirement cannot orphan channel or child-channel value | `state_retirement_non_orphaning` |
| Descriptor changes can drift away from signed state | Descriptor evolution is signed and finalise uses the current authentic commitment | `signed_descriptor_evolution` |
| Merkle locality proof is treated as minting authority | Non-interference proves locality only, not value creation | `non_interference_not_authorisation` |
| Reserve claim delta and child-vault release are not equal | Factory value-bearing rights, FactoryVault, and child vault deltas are bound | `factory_value_delta_binding` |
| FactoryVault splice checks signed token delta but not the full materialised Cell shape | Signed FactoryVault descriptors bind actual lock, capacity, type, and amount on-chain | `factory_value_delta_binding`, `typed_asset_binding` |
| xUDT amount/type/change can mismatch while total supply appears conserved | Typed asset identity, amount, descriptor, child vault, and FactoryVault change agree | `typed_asset_binding` |
| Sponsor script policy and operator policy are conflated | Script-enforced sponsor bounds are separated from watchtower/operator policy | `sponsor_policy_boundary` |
| Watchtower selects stale or fake authority after restart or splice | Watchtower detection and cursor recovery are funding-anchor aware | `watchtower_authority_and_cursor` |
| A negative path rejects but leaves later valid state unproven | Expected failures are exact and the system continues to commit later valid transitions | `negative_recovery_continuity` |
| Proof/witness growth silently exceeds release budgets | Cycles, bytes, witness length, and proof profiles are budget-gated | `budget_regression` |

## Assertion Rules

`devnet-stateful-assert` loads the audit profile by default and rejects:

- a profile with the wrong schema or duplicate family id;
- scenario coverage tags that no family declares;
- missing required scenario ids;
- missing required committed transaction checks;
- missing exact expected failures, including Morph error name and code;
- a `budget_regression` family without a stateful budget profile.

`devnet-stateful-compare --fail-on-status-change` also compares audit-family
pass/fail status, so a candidate run can fail even when the scenario set stays
unchanged.

This layer complements, but does not replace, unit and CKB-VM invariant tests.
Contract-level tests still own exact script predicates and error behavior;
stateful audit families prove that the same risk classes appear in real devnet
lifecycle evidence.
