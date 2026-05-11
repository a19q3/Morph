# Roadmap

## M0: Protocol Semantics

Status: implemented.

- State header signing domain.
- State transition monotonicity.
- Funding-anchor binding.
- Sponsor policy bounds.
- Vault finalisation conditions.
- Partition conservation across reserve, business CKB, xUDT, and sponsor cells.

## M1: Devnet Bilateral Channel

Status: in progress. The three script ELFs build and offline CKB-VM tests cover
state publication, stale-state rejection, invalid state signatures,
state-bound sponsor fees, descriptor-bound vault finalisation, and
descriptor-output mismatch rejection.

Required deliverables:

- Fixed-width V1 wire types, later replaced or generated from Molecule.
- `morph-state-type` contract.
- `morph-vault-lock` contract.
- `morph-sponsor-lock` contract.
- RPC transaction builder.
- Devnet deploy script.
- Publish, supersede, and finalise integration test.

Acceptance criteria:

- the stale-state transaction is superseded by a newer state before `since`;
- channel reserve cannot pay fees;
- sponsor policy cannot spend outside its budget;
- xUDT type mismatch is rejected;
- cycle counts are recorded.

## M2: Watchtower

- State package persistence.
- Detection-depth polling.
- Rebuild publication carrier with fresh sponsor inputs.
- Emergency fee budget policy.

## M3: Conservative Factory Mode

- Factory state roots and access manifest.
- Full-participant signature mode.
- Local exit without reduced signing set.

## M4: Reduced-Signature Factory Mode

This remains blocked until a formal rights-dependency proof predicate exists.
