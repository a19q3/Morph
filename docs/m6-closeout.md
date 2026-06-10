# M6 Closeout

M6 closes the conservative host/package layer for factory reserve
repartitioning.

## Supersession Note

This is a historical M6 closeout document. It records the conservative
factory-splice milestone and should not be read as the current factory witness
dispatch design.

The current witness-envelope implementation line at commit `a2059ba` wraps factory
authorisation bodies in `WitnessEnvelope`. The `*current` names below remain useful
as package/body schema names and evidence labels, but factory contracts now
dispatch by envelope kind and checked body digest rather than by the old
top-level fixed-length witness convention.

## Done

- `morph-core` models signed `FactorySpliceHeader`,
  `FactoryVaultDescriptor`, and typed factory vault deltas.
- Host validation accepts CKB and xUDT factory splice-in/out only when one
  participant reserve claim changes by exactly the signed FactoryVaultCell
  delta.
- Negative invariants reject reserve-claim inflation without vault input, vault
  release without rights decrease, xUDT type mismatch, tampered vault change,
  stale update numbers, and invalid signatures.
- `morph-cli` prints and validates `morph.factory_splice_package` fixtures
  for CKB splice-in/out and xUDT splice-in/out.
- Devnet smoke reports decode factory splice packages as auditable evidence.
- `schemas/morph.mol` records the M6 body schemas and the later
  `WitnessEnvelope` factory witness envelope.

## M6.1/M6.2 Contract Closeout

- `morph-script-common` now parses and verifies bounded
  `FactorySpliceWitness` bodies carried by `WitnessEnvelope`.
- `morph-cli validate-factory-splice-package` derives the same
  `WitnessEnvelope`-wrapped `FactorySpliceWitness` bytes as
  `contract_witness_hex`.
- `devnet save-factory-splice-package` captures a live conservative
  FactoryStateCell/FactoryVaultCell pair into the signed package format.
- `devnet apply-factory-splice` consumes a validated package against the live
  FactoryStateCell/FactoryVaultCell pair and feeds the
  `WitnessEnvelope`-wrapped `FactorySpliceWitness` body to both factory
  scripts.
- `devnet factory-splice-in-smoke` and `devnet factory-splice-out-smoke` now
  run open, live package capture, factory splice apply, and a post-splice
  full-participant child-channel materialisation.
- `devnet factory-xudt-splice-in-smoke` and
  `devnet factory-xudt-splice-out-smoke` run the same flow for typed
  FactoryVaultCells, including an external participant-owned xUDT input for
  splice-in.
- Smoke summaries now derive all-participant factory-splice proof profiles for
  CKB and xUDT apply transactions, binding `FactorySpliceWitness` body
  length, node-estimated cycles, and transaction bytes to the budget profile.
- `morph-core` validates a reduced sparse-Merkle factory splice transition where
  one reserve claim is proved by a single-right Merkle proof and only the
  authorised participant signs the factory splice header.
- `morph-cli` prints and validates `morph.factory_reduced_splice_package`
  fixtures for CKB and xUDT factory splice-in/out, including 256 proof siblings,
  full participant key commitment, one authorised participant signature, and the
  `WitnessEnvelope`-wrapped `FactoryReducedSpliceWitness` as
  `contract_witness_hex`.
- `devnet save-factory-reduced-splice-package` captures a live conservative
  FactoryStateCell/FactoryVaultCell pair into the reduced sparse-Merkle package
  shape, and `devnet apply-factory-reduced-splice` applies that package with
  the `WitnessEnvelope`-wrapped `FactoryReducedSpliceWitness` body.
- `devnet factory-reduced-splice-in-smoke` and
  `devnet factory-reduced-splice-out-smoke` now run the CKB reduced splice
  lifecycle through open, live package capture, apply, and post-splice child
  materialisation.
- `devnet factory-reduced-xudt-splice-in-smoke` and
  `devnet factory-reduced-xudt-splice-out-smoke` run the typed xUDT reduced
  splice lifecycle through the same sparse-Merkle witness path.
- Smoke summaries and budget profiles distinguish all-participant factory
  splice proofs from reduced sparse-Merkle factory splice proofs for both CKB
  and xUDT assets.
- `morph-script-common` parses and verifies the reduced factory splice witness,
  binding the sparse Merkle right transition, unchanged access roots, splice
  header signature, and exact reserve-claim/vault delta.
- `morph-factory-type` accepts signed all-participant and reduced factory splice
  bridges.
- `morph-factory-vault-lock` checks the touched CKB/xUDT FactoryVaultCell input
  and recreated output against the signed delta for both witness shapes.
- CKB-VM coverage now exercises the reduced sparse-Merkle factory splice bridge
  end to end: type+vault accept a valid CKB reserve splice-in, reject a tampered
  Merkle sibling, and reject a recreated FactoryVaultCell capacity mismatch.
- The ignored contract suite now covers 44 script-level paths across state,
  vault, sponsor, factory update, all-participant splice, reduced exit, and
  reduced splice behavior.

## Production Posture

M6 closed the production-shaped evidence for the conservative historical body
scope: quiescent factory splice, typed CKB/CKB+xUDT vault deltas,
all-participant or one-authorised reserve-claim proof shapes,
participant-owned splice-out policy, and explicit package-to-contract witness
bytes. Current release posture must be read through the active current envelope
documents and mainnet-readiness gates.

Still intentionally out of scope for that conservative body scope:

- concurrent unconfirmed splice updates;
- arbitrary payout locks;
- generic descriptor runtimes;
- multi-right or variable-depth reduced splice witnesses beyond the fixed
  single reserve-claim sparse-Merkle proof.

## Verification

```sh
cargo fmt --all --check
cargo test --workspace --all-targets
cargo clippy --workspace --all-targets -- -D warnings
make fixture-checks
make contract-tests
git diff --check
```
