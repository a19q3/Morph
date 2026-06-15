# Paper / Implementation Alignment Audit

This audit compares the current implementation in this repository with the
current paper draft at
`/Users/arthur/RustroverProjects/Research-a19q3/morph_channel/paper.tex`.

The implementation is a conservative devnet profile. It does not need to
implement every paper branch immediately, but each difference should be either
closed in code or explicitly called out as a deployment-profile restriction in
the paper and docs.

## High-Level Status

| Area | Implementation status | Paper status | Required update |
| --- | --- | --- | --- |
| State Header context | `StateHeader` binds chain, channel, funding epoch, funding anchor identity, vault set, mode, participants, asset registry, descriptor, challenge policy, and layout version. Tooling derives `funding_context_id` from chain, channel, funding anchor identity, and vault-set commitment for integration and audit. | Aligned with the same signed-context fields. | Aligned for the current signing domain. `funding_context_id` is derived metadata, not a new minimal safety primitive. |
| Funding anchor identity | Implemented as a Type-ID-style derivation from the first funding input and output index in the State type script and devnet tooling. Implementation docs state that `funding_anchor` is the signed anchor identity, not an output locator. | Defines a script-derivable funding anchor identity, warns against same-transaction outpoint self-reference, and documents the current devnet derivation profile. | Aligned for the current devnet profile. |
| Operation taxonomy | Core has `Fund`, `Publish`, `Supersede`, `Finalise`, `CooperativeClose`, `Splice`, and `Materialise`. Contracts represent `FUND` as State type creation rather than a witness-carried operation tag. | Paper defines closed `ChannelOperation = {FUND, PUBLISH, SUPERSEDE, FINALIZE, COOPERATIVE_CLOSE, SPLICE, MATERIALIZE}`. | Aligned at host taxonomy level; the contract-level FUND shape is a documented profile detail. |
| Mode enum | Core has `BilateralPlain` and `FactoryProof`; host signing bytes and wire parsing now use bytes `1` and `2`. Bilateral commitment is not emitted by current package or devnet flows. | Paper now maps those implementation names to the current `bilateral_plaintext` and factory commitment/proof profiles, and marks bilateral commitment as reserved. | Aligned as a documented devnet profile. A future public API cleanup may add paper-name aliases without changing the current wire bytes. |
| Phase semantics | Scripts accept initial active creation, settling publication, active splice retirement/creation, and settling finalisation. | Paper's phase table matches this shape and treats `phase` as on-chain carrier semantics. | Aligned; docs now avoid using "latest state" where it could mean highest signed state rather than live pointer. |
| FUND authority | Scripts verify canonical anchor derivation, active phase, state number zero, lock/type binding, and capacity. Participant approval of initial config is wallet, host, and package policy today. | Paper now distinguishes the full protocol profile from the current devnet profile, where initial configuration approval is not a separate script-checked signature object. | Aligned as a documented profile restriction. Add explicit host/package or script signature evidence only if the implementation adopts the stricter FUND profile. |
| PUBLISH / SUPERSEDE | Implemented by State type supersession, participant signatures, monotonic state number, same context, settling phase, sponsor publication, and package tooling. | Paper matches this as the ordinary unilateral publication path. | Strongly aligned. |
| FINALIZE | Implemented as conservative atomic finalisation against a current settling State Cell, relative `since`, vault commitment, and descriptor outputs. Implementation docs state that this profile is atomic and does not create terminal receipt Cells. | Paper allows conservative atomic finalisation, defines `TerminalReceipt` only for non-atomic profiles, and states that the current devnet implementation does not implement terminal receipts. | Aligned for the current bilateral finalisation profile. |
| COOPERATIVE_CLOSE | Present in the core enum and host-side vault operation switch, but not implemented as a complete State type, vault contract, CLI, and devnet flow. | Paper now marks cooperative close as a protocol branch and future deployment profile, not current executable evidence. | Aligned as a documented profile restriction. Implementation work remains if cooperative close enters the milestone. |
| SPLICE | Implemented in core, scripts, CLI, package storage, and devnet smoke paths for CKB/xUDT splice-in/out. | Paper treats splice as signed re-anchor with funding epoch and vault-set updates, and documents the current implementation anchor derivation profile. | Aligned for the current devnet profile. |
| MATERIALIZE | Implemented through factory local/reduced exits that materialise child State/Vault outputs while the factory State Cell is updated. Implementation docs now state that value-bearing materialisation consumes and recreates the parent Factory State Cell. | Paper defines a `FactoryTransitionResult` parent-state rule, disallows `unchanged_reference` for value-bearing materialisation in the conservative profile, and maps the current implementation to `updated_successor`. | Aligned for the current conservative factory profile. |
| Partition conservation | Core now tracks State carrier capacity independently, plus reserve, business CKB, xUDT, sponsor fee, and unrelated-cell exclusion. | Paper has the same lanes and calls for `partition_conservation(tx, resolved, op)`. | Aligned at invariant level. Core still exposes `validate_partition_conservation(tx, registry)` rather than a named resolved context, which is acceptable for host invariants. |
| Sponsor policy | Sponsor lock enforces channel id, state range, max fee, max total fee, publication state type hash, clean change, and rejects finite script expiry. It currently sponsors settling State Cell outputs only. | Paper now states that the current devnet profile sponsors only publication and supersession carrier fees; wider operation-scoped budgets are deployment profiles. | Aligned as a documented profile restriction. Add explicit allowed-operation policy only if sponsors will pay non-publication operations. |
| Resolved state context | Implementation resolves data through fixed-layout parsers and witness/package validators rather than a named `ResolvedStateContext` struct. Implementation docs now map each paper resolution role to `morph-script-common`, channel scripts, sponsor script, factory scripts, and package validators. | Paper names `ResolvedStateContext` and requires all commitments to be resolved before validation. | Aligned as an abstraction-to-code mapping. A shared host struct is optional, not required for the current CKB-VM profile. |
| StatePackage | CLI `StoredStatePackage` stores signed State Header bytes, bilateral signature witness bytes, channel id, funding anchor, derived funding context id, state number, signing digest, source State outpoint, and descriptor commitment/version metadata; it validates signatures and metadata and selects latest packages by channel/state number. Watchtower package matching prefers funding context id and falls back to funding anchor for older stores. | Paper now distinguishes the abstract `StatePackage` requirement from the narrower current bilateral devnet package. | Aligned for the plaintext bilateral devnet profile. Generic asset-registry/challenge-policy bytes and commitment-only proof material remain future representation-profile work. |
| Factory witness envelope | Implemented with `WitnessEnvelope` magic/version/kind/flags/body length/body digest and fixed kind dispatch. | Paper calls for bounded envelope-first factory admission. | Strongly aligned. |
| Factory non-interference | Implemented for reduced-rights, Merkle update, reduced exit, reduced splice, and touched participant authorization. | Paper requires rights-dependency schema, conservative fallback, and acceptance/negative evidence for each admitted proof family. | Aligned for the implemented proof families; broader reduced signing remains future work until additional proof families have exact acceptance and rejection evidence. |

## Implementation Updates To Consider

1. Optional public API cleanup: preserve current mode wire bytes `1` and `2`,
   while adding paper-name aliases in future JSON/package output if external
   consumers need `bilateral_plaintext` and `factory_commitment` vocabulary.

2. Add explicit host/package or script validation for initial configuration
   signatures only if the implementation adopts the stricter `FUND` authority
   profile. The current devnet boundary is documented as normal funding-wallet
   authority plus script-enforced anchor uniqueness and shape checks.

3. Decide whether cooperative close is in scope for this implementation
   milestone. Today it is modelled in core and documented as a future
   deployment profile, not as a complete script and devnet flow.

4. If sponsors are intended to pay finalisation, materialisation, or splice
   transactions, extend `SponsorPolicy` with an explicit allowed-operation set
   and make the sponsor script parse authoritative operation context. The paper
   and docs now narrow the current profile to publication/supersession
   sponsorship.

5. Consider introducing a host-level `ResolvedStateContext` struct only if it
   reduces duplicated parser plumbing. The contracts already use fixed-layout
   parsers directly, which is a reasonable CKB-VM profile.

6. Add generic StatePackage fields for explicit asset-registry bytes,
   challenge-policy bytes, and commitment-only proof material only when those
   representation profiles move from paper profile to implemented devnet flow.

## Paper Updates To Consider

1. Keep sponsor-budget text split between the implemented publication-only
   profile and future operation-scoped deployment profiles.

2. Keep cooperative close marked as a future deployment profile unless its exact
   State type, vault, CLI, and devnet branches are implemented.

3. Keep package text split between the current bilateral `StoredStatePackage`
   and the broader abstract `StatePackage` required for future representation
   profiles.

## Evidence Checked

- `crates/morph-core/src/types.rs`: State Header, mode, phase, operation enum,
  sponsor policy, vault spend, partition model.
- `crates/morph-core/src/validation.rs`: state transition, sponsor policy,
  vault spend, splice, factory, and partition checks.
- `contracts/morph-state-type/src/main.rs`: initial state creation,
  Type-ID-style funding anchor derivation, supersession, splice, and finalise
  State Cell rules.
- `contracts/morph-vault-lock/src/main.rs`: current State Cell lookup, relative
  `since`, descriptor output checks, and splice vault branch.
- `contracts/morph-sponsor-lock/src/main.rs`: bounded publication sponsor policy
  and clean-change enforcement.
- `contracts/morph-factory-type/src/main.rs`: witness-envelope dispatch,
  factory update, local exit, reduced exit, and materialised child State/Vault
  checks.
- `contracts/morph-script-common/src/lib.rs`: fixed-layout State Header,
  context equality, witness envelope, signature, descriptor, and factory proof
  parsers.
- `crates/morph-core/tests/invariants.rs` and
  `crates/morph-core/tests/contract_scripts.rs`: host and CKB-VM evidence for
  key invariants.
