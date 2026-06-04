# Roadmap

## M0: Protocol Semantics

Status: implemented.

- State header signing domain.
- State transition monotonicity.
- Funding-anchor binding.
- Script-enforced sponsor fee/state bounds plus operator/watchtower policy
  bounds.
- Vault finalisation conditions.
- Partition conservation across reserve, business CKB, xUDT, and sponsor cells.

## M1: Devnet Bilateral Channel

Status: implemented for the bilateral CKB-only path, the devnet CKB+xUDT
settlement path, and conservative factory-local exit materialisation. The seven
script ELFs build, offline CKB-VM tests cover
state-lock delegation, state publication, stale-state rejection, invalid state
signatures, state-bound sponsor fees, descriptor-bound vault finalisation,
descriptor-output mismatch rejection, devnet xUDT conservation, and
conservative factory type and factory vault progression. The CLI can check/mine
a local CKB devnet, deploy the Morph contract binaries, open a channel, publish
a signed settling state, top up sponsor capacity, publish a newer signed state
over the old settling state, finalise the vault, materialise a child channel
from a conservative factory reserve, materialise a CKB+xUDT child channel from
a typed factory reserve, and run a competing-spend smoke, a
finalise-since negative smoke, a sponsor-budget negative smoke, a CKB+xUDT
settlement smoke, a tampered-settlement xUDT negative smoke, a conservative
factory open/package/update/exit smoke, and a factory xUDT child-channel smoke
plus a factory xUDT child-vault negative smoke through native JSON-RPC. Each
transaction report includes node-estimated cycles and serialized transaction
size.
SponsorCells can carry explicit state-number and fee-budget bounds. Smoke runs
also produce Markdown and machine-readable benchmark summaries from the
collected transaction reports.

Required deliverables:

- Fixed-width V1 wire types, later replaced or generated from Molecule.
- Draft Molecule schema covering all active devnet V1 wire objects.
- `morph-state-lock` contract.
- `morph-state-type` contract.
- `morph-factory-type` contract.
- `morph-factory-vault-lock` contract.
- `morph-vault-lock` contract.
- `morph-sponsor-lock` contract.
- `morph-devnet-xudt` contract.
- Native devnet RPC check/mine/wait commands.
- Devnet contract deployment transaction.
- RPC transaction builder.
- Publish, supersede, and finalise devnet path.
- Per-transaction cycle and size reporting from the devnet node.
- Devnet smoke summary report for cycle, size, status, and expected script
  failure review.
- Devnet smoke comparison report for cycle and transaction-size deltas between
  runs.
- Configurable SponsorCell state-number and fee-budget policy.

Acceptance criteria:

- a canonical StateCell is created from the funding input and output index;
- a newer signed state can replace the active StateCell and enter settling;
- a newer signed state can replace an already settling StateCell;
- finalisation before the required relative `since` is rejected on devnet, then
  succeeds after explicit maturity blocks;
- sponsor capacity pays publication fees without touching vault value;
- finalisation consumes the settling StateCell and vault, then materialises the
  descriptor outputs;
- channel reserve cannot pay publication fees;
- sponsor policy cannot spend outside its budget;
- sponsor policy rejects publication outside its state-number range;
- a devnet SponsorCell with a too-low fee cap is rejected, then a fresh
  SponsorCell can publish the same state with a sufficient cap;
- xUDT type mismatch is rejected in host-side invariants;
- a devnet CKB+xUDT channel can open, publish, and finalise with exact token
  conservation;
- a devnet CKB+xUDT channel rejects a tampered recipient-level token
  distribution even when total token supply is unchanged.
- a devnet factory CKB+xUDT local exit rejects a tampered child vault token
  amount even when total token supply is conserved by factory-vault change.
- a competing publication against an already pending StateCell spend is
  rejected by the node's tx-pool-aware live-cell view, then the newer state can
  be rebuilt against the confirmed live StateCell.
- JSON devnet reports expose `estimated_cycles` and `tx_size_bytes` for every
  lifecycle transaction.
- completed smoke directories can be summarised into `summary.md` and
  `summary.json`, including deployed script records, watchtower alerts,
  factory local-exit evidence, and factory proof-shape budget profiles.
- completed smoke directories can be compared with optional regression gates
  for transaction set, status, cycles, and byte size.
- completed smoke directories can be checked against absolute cycle/byte,
  per-transaction, and factory proof-profile budgets in the same assertion
  command used for semantic smoke coverage.
- CI validates generated bilateral fixtures, factory packages, factory
  local-exit evidence, reduced host-side factory packages, reduced-exit host
  packages, and watchtower policies.
- a conservative FactoryStateCell can be opened, signed as a reusable package,
  selected as the latest package, advanced on devnet without draining the
  factory state carrier for fees, and used with a FactoryVaultCell to
  materialise a child bilateral channel, including a CKB+xUDT child vault when
  the FactoryVaultCell carries the same devnet xUDT type.

## M2: Watchtower

Status: implemented for durable state package persistence, latest package
selection, publish-from-latest-package rebuilding, confirmation-depth block
polling, persisted scan cursors, conservative auto-funded sponsor rotation,
JSON operator policy, multi-channel watchtower config, bounded config loops,
local JSONL alerts, and policy-gated HTTP webhook alerts.

- State package persistence.
- Detection-depth polling.
- Rebuild publication carrier with fresh sponsor inputs.
- Emergency fee budget policy.
- Persisted scan cursor.
- Conservative auto-funded SponsorCell rotation.
- Operator policy for confirmation depth, fee, sponsor mode, and auto-sponsor
  capacity.
- Multi-channel watchtower config with private keys supplied only at runtime.
- Bounded multi-pass watchtower runner that reuses persisted cursors.
- Runtime watchtower key files so sponsor keys do not need to appear in the
  config, shell history, or process list.
- Foreground service mode with health-file updates, stop-file shutdown, error
  backoff, and consecutive-error limits.
- JSONL and HTTP webhook alert sinks for older-state detection, publication
  submission, and idle scans.
- Smoke summary assertions for the older-state and publication-submitted alert
  path.

## M3: Conservative Factory Mode

Status: host-level non-interference predicate implemented, conservative
full-participant factory state packages implemented at the CLI layer, and a
host-side authorised-participant reduced package implemented for the same
predicate. A conservative factory type script and factory vault lock execute in
CKB-VM tests. The factory type script now also verifies a bounded on-chain
reduced-rights proof for claim-reducing updates: one authorised participant may
decrease only their own committed rights, while every other right remains
unchanged and the old/new state roots, access roots, non-interference digest,
full participant commitment, and reduced signature are checked. The CLI can
open a FactoryStateCell plus FactoryVaultCell, save a reusable signed
factory-state-cell package, select the latest package, publish a signed
monotonic update on devnet, and materialise a bilateral child channel from the
factory reserve. The same conservative exit path supports a typed factory
reserve that releases a CKB+xUDT child vault and then uses the ordinary xUDT
finalisation path.

- Factory state roots and access manifest.
- Full-participant signature mode.
- Local exit without reduced signing set.
- Rights-dependency checks for balances, reserves, membership, exit paths, and
  sponsor budget claims.
- Serialisable factory update package with non-interference digest and CLI
  validation.
- Conservative all-participant and host-side authorised-participant factory
  state packages with domain-separated digests and secp256k1 signature
  validation.
- Conservative factory type script for one-live-FactoryStateCell monotonic
  updates under full-participant signatures.
- Bounded reduced-rights witness for one-signer, claim-reducing factory updates
  with script-level root and non-interference checks.
- Bounded reduced-exit witness for one-signer reserve-claim release with
  script-level root checks, local-exit evidence binding, child materialisation
  checks, and factory reserve conservation in CKB-VM tests.
- CLI package generation and `update-factory --factory-state-package`
  publication support for the bounded reduced-rights witness.
- Devnet `open-factory`, `save-factory-state-package`, `update-factory`,
  `factory-exit-channel`, `factory-smoke`, and
  `factory-reduced-rights-smoke` commands.
- Devnet `factory-reduced-exit-smoke` command for the bounded reserve-claim
  reduced-exit path, followed by ordinary child-channel publication and
  finalisation.
- CKB-VM and devnet smoke coverage for xUDT reduced-exit V1 with typed
  child-vault and FactoryVault change binding.

## M4: Reduced-Signature Factory Mode

Status: implemented for the current fixed-width claim-reducing update,
single-right sparse Merkle update, reserve-claim reduced-exit, and devnet
smoke-budget scope.

Implemented:

- fixed-width `FactoryReducedRightsWitnessV1`;
- script-level verification of full participant membership commitment;
- old/new rights-root and access-manifest-root checks;
- non-interference digest binding;
- one authorised signature over the new FactoryStateHeader;
- devnet smoke coverage for reduced-rights package publication;
- host-level reduced factory-exit predicate requiring one authorised
  participant to consume only their own reserve claim while every other right
  remains unchanged;
- serialisable reduced factory-exit package fixture and CLI validation for the
  host-level reserve-claim consumption predicate;
- fixed-width `FactoryReducedExitWitnessV1` schema entry;
- script-level reduced factory-exit verification in `morph-factory-type` and
  `morph-factory-vault-lock`, including local child-channel evidence and
  reserve-conservation checks;
- CKB-VM coverage for a reserve-claim reduced exit that materialises a child
  channel from the factory vault;
- devnet smoke coverage for CKB reserve-claim reduced-exit publication,
  child-state publication, and child-vault finalisation;
- CKB-VM coverage for xUDT reserve-claim reduced-exit publication, including
  token amount, type hash, claim asset-type, and FactoryVault typed-change
  rejection cases;
- devnet smoke coverage for xUDT reserve-claim reduced-exit publication,
  including partial typed FactoryVault change, full release with CKB-only change,
  one-sided child settlement, and tampered child-token amount rejection;
- host-level sparse Merkle update package for a single-right transition inside
  an arbitrary factory rights tree, including CLI fixture and validation;
- script-level fixed-width sparse Merkle update witness for the same
  single-right transition, including CKB-VM accept/reject coverage;
- devnet smoke coverage for the sparse Merkle factory update witness, including
  smoke-summary evidence and per-transaction budget profile entry;
- smoke-summary proof profile binding for the bounded reduced-rights update,
  sparse Merkle update, CKB reduced-exit, and xUDT reduced-exit proof shapes,
  including proof
  sibling count where applicable, witness length, node-estimated cycles, and
  transaction byte size;
- absolute smoke budget gates for cycle and transaction-size ceilings;
- per-transaction smoke budget profiles for critical proof paths, including
  bounded reduced-rights publication and sparse Merkle factory update
  publication;
- per-proof-profile smoke budget gates for proof sibling count, witness length,
  node-estimated cycles, and transaction byte size;
- rejection of touched-right inflation and unrelated participant mutation in
  CKB-VM tests.

Deferred beyond the current roadmap:

- empirical budget profiles for larger, multi-right, or variable-depth proof
  shapes beyond the current fixed-width smoke witnesses.

## M4.5: Devnet Stateful Acceptance

Status: implemented as the devnet acceptance layer, not as mainnet readiness.

- `scripts/devnet-stateful-e2e.sh` and
  `scripts/devnet-stateful-scenarios.sh` group the real devnet smoke evidence
  into production-shaped lifecycle scenarios.
- `devnet-stateful-report`, `devnet-stateful-assert`, and
  `devnet-stateful-compare` summarise scenario status, enforce required
  committed checks and exact expected failures, and detect audit-family status
  regressions.
- `docs/devnet-audit-profile.example.json` maps discovered protocol risk
  classes to required coverage tags, scenarios, committed checks, expected
  failures, and budget gates.
- The closeout is recorded in
  [`docs/devnet-stateful-acceptance-closeout.md`](devnet-stateful-acceptance-closeout.md).
  Mainnet-like fee/reorg evidence, external xUDT compatibility, external
  review, production watchtower operations, and value-limit policy remain in
  [`docs/mainnet-readiness.md`](mainnet-readiness.md).

## M5: Bilateral Splicing And Dynamic Funding

Status: implemented for the conservative V1 scope. The core crate now models
`SpliceHeader`, `SpliceWitness`, `VaultDescriptorV2`, and signed CKB/xUDT asset
deltas, and validates splice-in/splice-out funding-epoch transitions against
the current active StateCell. The CLI can print and validate a reusable
`morph.splice_package.v1` fixture for splice-in, CKB splice-out, and xUDT
splice-out, and
`morph-script-common` now records the fixed-width splice header, signature
witness, vault descriptor, and asset-delta parser/digest shapes plus a
fixed-width `SpliceStateTransitionWitnessV1` proof bundle and shared verifier.
The CLI derives that 1017-byte contract witness from validated JSON packages
and reports it as `contract_witness_hex`, alongside fixed-width current/next
StateHeader bytes, for future transaction builders.
`morph-state-type` now has the old/new funding-anchor script-group bridge for
StateCell splice transitions, and `morph-vault-lock` now accepts active old
vault spends only when the same splice witness proves the post-splice
StateCell and exact old/new CKB/xUDT vault descriptors. CKB-VM tests cover
valid CKB splice-in and splice-out bridges, wrong-channel splice header
rejection, and a tampered new-vault capacity rejection.
`devnet save-splice-package` now creates live-matching CKB splice packages and
live xUDT splice-in/out packages, and `devnet apply-splice --splice-package
<path>` builds and submits the corresponding live splice transaction. Signed
state publication can now update the settlement descriptor, and the splice
smoke commands cover CKB splice-in, CKB splice-out, xUDT splice-in, and xUDT
splice-out through post-splice sponsor funding, descriptor-updated state
publication, and finalisation. Splice-out withdrawals are V1-conservative:
outputs are derived from a participant signature pubkey rather than an arbitrary
operator payout lock, and package/apply JSON reports expose that payout policy,
participant pubkey, and live withdrawal lock hash. The default smoke assertion
requires that payout evidence on every splice apply artifact and fails if
splice-out drifts away from `participant_signature_pubkey`. The watchtower
scanner is now funding-anchor aware: saved state packages carry descriptor
metadata, cursors remember the last observed anchor, and stale cross-anchor
package selection is alerted instead of published. The default devnet smoke now
includes a splice guard path that applies a splice, scans from the post-splice
block with an old-anchor cursor, and verifies the pre-splice package is not
published.
The closure checklist is recorded in `docs/m5-closeout.md`.
This milestone expands the paper's channel-continuity goal: participants should
be able to add or remove on-chain value without closing the channel, while
preserving the channel identity, signed-state ordering, sponsor policy, and
vault settlement safety already implemented in M0-M2.

Design target:

- splice-in adds CKB and/or xUDT value to an existing channel vault while the
  channel id and off-chain participant set remain unchanged;
- splice-out withdraws CKB and/or xUDT value from an existing channel vault
  without forcing a cooperative finalisation of the whole channel;
- every accepted post-splice state is bound to the current funding epoch so an
  old signed state cannot settle against a newer vault shape, and a new state
  cannot settle against the pre-splice vault;
- the splice transaction may pay fees through ordinary owner or SponsorCell
  inputs, but channel reserve, business CKB, xUDT balance, and sponsor capacity
  remain distinct partitions;
- xUDT splice-in/out must preserve the canonical type hash and exact token
  deltas for every asset touched by the splice;
- watchtower publication remains deterministic: a watchtower must know which
  state package belongs to which funding epoch before it can publish.

Protocol objects to add:

- `SpliceHeaderV1`: channel id, old funding anchor, new funding anchor or
  funding epoch, old/new vault commitments, base state number, splice number,
  asset delta commitment, challenge policy commitment, and signing digest.
- `SpliceWitnessV1`: participant public keys and signatures over the
  `SpliceHeaderV1` digest.
- `SpliceStateTransitionWitnessV1`: fixed-width contract witness bundling the
  splice header, participant signatures, old/new vault descriptors, and asset
  deltas for one state/vault funding transition.
- `SplicePackageV1`: reusable JSON package containing the splice header,
  witness, current StateCell out point, old vault out point, expected new vault
  descriptor, and optional sponsor policy hints.
- `StateHeaderV2` with an explicit `funding_epoch` field plus funding/vault-set
  commitments, so state signatures bind both the stable channel id and the
  current funding configuration.
- `VaultDescriptorV2`: typed vector of CKB and xUDT vault partitions so splice
  deltas can be checked without ad hoc per-asset fields.

Host-level validation:

- accept splice-in only when new vault value equals old vault value plus the
  signed external contribution minus explicitly signed splice fees;
- accept splice-out only when withdrawn outputs target participant-owned locks
  in V1, later widening only to explicitly pre-authorised payout locks, and when
  the remaining vault value still covers the latest signed settlement
  descriptor;
- reject channel id, participant set, funding epoch, challenge policy, or
  descriptor-version drift not committed by the splice header;
- reject CKB reserve/business confusion and sponsor-fee leakage during splice
  transactions;
- reject xUDT splice deltas that preserve total supply but change the committed
  participant-level allocation or type hash;
- require a base state number or quiescence marker so a splice package cannot
  be applied on top of an incompatible newer state.

Contract work:

- teach `morph-state-type` to accept a splice transition that consumes the
  current StateCell and recreates a StateCell with the same channel id and a
  strictly newer funding epoch, using `SpliceStateTransitionWitnessV1` as the
  loaded proof shape; implemented for the old/new type-script bridge, requiring
  matching code hash/hash type and args suffix;
- teach `morph-vault-lock` to accept an old vault spend into a new vault plus
  signed splice-in/splice-out outputs only when the current StateCell carries
  the matching splice commitment; implemented for exact old group-input and
  new vault-lock-output CKB/xUDT descriptor enforcement;
- keep ordinary finalisation unchanged except that it must verify the settling
  StateCell and VaultCell are from the same funding epoch;
- extend `morph-sponsor-lock` tests so sponsor capacity can pay splice
  publication fees without being counted as channel value;
- add CKB+xUDT splice checks to ensure the devnet xUDT script conserves supply
  while Morph scripts enforce the participant-level splice descriptor.

CLI and package workflow:

- `print-splice-fixture` and `validate-splice-package` for deterministic
  host-side review, StateHeader byte derivation, and contract-witness
  derivation; implemented for the reusable JSON package layer, including typed
  xUDT splice-out.
- `devnet save-splice-package` to build a reusable package from the live
  StateCell/VaultCell pair and explicit CKB/xUDT deltas; implemented for
  CKB splice-in/splice-out packages and xUDT splice-in/splice-out packages;
- `devnet apply-splice --splice-package <path>` to rebuild the transaction with
  fresh fee inputs and submit it; implemented for validated CKB and xUDT
  splice-in/splice-out packages against a live active StateCell/VaultCell pair;
- `devnet splice-in-smoke` for adding CKB to an active channel and then
  publishing/finalising a post-splice state; implemented through post-splice
  sponsor funding, descriptor-updated settling-state publication, and
  finalisation;
- `devnet splice-out-smoke` for withdrawing CKB while the channel continues;
  implemented through post-splice sponsor funding, descriptor-updated
  settling-state publication, and finalisation;
- `devnet xudt-splice-in-smoke` for typed external-input deltas; implemented
  through post-splice sponsor funding, descriptor-updated settling-state
  publication, and finalisation;
- `devnet xudt-splice-out-smoke` for typed withdrawal deltas; implemented
  through post-splice sponsor funding, descriptor-updated settling-state
  publication, and finalisation;
- `devnet splice-negative-smoke` cases for stale funding epoch, wrong channel
  id, wrong vault type, insufficient remaining vault value, tampered xUDT
  amount, and sponsor fee leakage; implemented as live package/preflight
  rejection coverage and included in the default devnet smoke script.

Watchtower and operator impact:

- state package records include the funding anchor, optional funding epoch, and
  settlement descriptor commitment/version metadata;
- watchtower latest-package selection now chooses the newest package matching
  the confirmed StateCell funding anchor instead of blindly using the global
  highest state package;
- scan cursors record the last observed funding anchor, state number, and
  outpoint so a watcher can resume after a confirmed splice without replaying
  obsolete packages;
- JSONL/webhook alerts include `splice_detected`, `splice_package_stale`, and
  `splice_publication_submitted` events.

Acceptance criteria:

- CKB-VM tests accept a valid CKB splice-in and splice-out transition;
  implemented for the StateCell/VaultCell bridge;
- CKB-VM tests reject wrong-channel splice headers and tampered new-vault
  outputs; `StateHeaderV2` parser/verifier tests bind explicit funding epochs
  and old/new vault-set commitments for the active channel wire target;
- CKB+xUDT tests reject same-supply but wrong-recipient/token-amount splice
  outputs;
- devnet smoke demonstrates splice-in, post-splice state publication, and
  finalisation from the new funding epoch;
- devnet smoke demonstrates splice-out and proves the remaining channel value
  can still settle correctly;
- devnet negative smoke rejects stale funding epochs, wrong channel ids, wrong
  vault type applications, insufficient remaining value, tampered xUDT deltas,
  and signed-fee leakage before any malformed splice is accepted;
- smoke summary records splice transaction metrics and budget profiles by
  splice kind;
- watchtower smoke proves an older pre-splice package is not published after a
  confirmed splice unless it is valid for the current funding epoch; implemented
  for the stale-package guard path.

Closed V1 splice decisions:

- V1 splice is quiescent: a package commits to one explicit base state number,
  and ordinary off-chain updates for the old funding epoch are paused or
  isolated until the splice confirms or is abandoned.
- Funding epoch is explicit state semantics. The final V1 wire target is
  `StateHeaderV2 { funding_epoch, funding_anchor, vault_set_commitment, ... }`;
  deriving an epoch from the vault out point may be used as a commitment input
  but not as the only semantic source.
- Multi-asset deltas stay fixed-width and typed. V1 supports the narrow CKB and
  CKB+xUDT splice shapes already exercised by package/devnet coverage; generic
  descriptor runtime remains future work.
- Splice-out payouts are participant-owned in V1. Explicit signed payout-lock
  allowlists are a V1.1 candidate; arbitrary signed payout locks are deferred to
  V2 policy work.

## M6: Factory Splicing And Reserve Repartition

Status: implemented for the conservative host/package scope. `morph-core` now
models `FactorySpliceHeader`, `FactoryVaultDescriptorV1`, fixed factory vault
deltas, and signed all-participant factory splice transitions. The validator
accepts CKB and xUDT splice-in/out only when exactly one participant reserve
claim changes by the same amount as the FactoryVaultCell delta, and rejects
reserve-claim inflation without vault input, vault release without a rights
decrease, xUDT type drift, tampered vault change, stale update numbers, and
invalid signatures. `morph-cli` can print and validate
`morph.factory_splice_package.v1` fixtures, and smoke summaries decode those
packages as auditable factory-splice evidence. The validator now derives
`WitnessEnvelopeV2` bytes containing a `FactorySpliceWitnessV1` body as
`contract_witness_hex`, giving transaction builders a direct bridge from
package evidence to script witness encoding. `devnet
save-factory-splice-package` now captures a live
conservative FactoryStateCell/FactoryVaultCell pair into that package format,
and `devnet apply-factory-splice` applies the package with the envelope witness
against both factory scripts. `devnet factory-splice-in-smoke` and
`devnet factory-splice-out-smoke` wrap the CKB path end-to-end: open a factory,
capture a live splice package, apply it, and then materialise a child channel
from the post-splice FactoryVaultCell. `devnet factory-xudt-splice-in-smoke`
and `devnet factory-xudt-splice-out-smoke` now run the same flow for typed
FactoryVaultCells, including an external participant-owned xUDT input for
splice-in and participant-owned withdrawal output for splice-out.
The Molecule schema records the bounded M6 wire target, and the M6 contract
witness bridge is closed for the conservative V1 body scope:
`morph-script-common` now parses `WitnessEnvelopeV2` and verifies the
`FactorySpliceWitnessV1` body,
`morph-factory-type` accepts signed all-participant factory splice updates, and
`morph-factory-vault-lock` checks the touched CKB/xUDT FactoryVaultCell delta
against the signed witness. Smoke summaries now emit all-participant
factory-splice proof profiles for CKB and xUDT apply transactions, so budget
profiles can gate `FactorySpliceWitnessV1` length, node-estimated cycles, and
transaction bytes. The host/package reduced sparse-Merkle splice path now
exists as `FactoryReducedSpliceTransition` plus
`morph.factory_reduced_splice_package.v1`: one reserve claim is proved by a
single-right Merkle proof, the package carries the full participant key
commitment, and only the authorised participant signs the factory splice header.
The contract bridge now parses `WitnessEnvelopeV2` carrying
`FactoryReducedSpliceWitnessV1` bytes, verifies the sparse Merkle right
transition, and keeps access roots unchanged for this reduced proof path.
CKB-VM tests exercise the reduced
factory splice bridge end to end: valid type+vault acceptance, sparse-Merkle
sibling tamper rejection, and FactoryVaultCell capacity-mismatch rejection.

Design target:

- factory splice-in adds CKB or xUDT reserve to the FactoryVaultCell and mints
  or increases the corresponding participant reserve claim;
- factory splice-out decreases a participant reserve claim and releases the
  signed amount from the FactoryVaultCell;
- child-channel materialisation continues to work after a factory splice
  without confusing factory reserve change with child vault value;
- sparse Merkle and reduced-rights proof shapes can eventually prove one or
  more reserve-claim deltas without carrying the full factory rights set.

Protocol and contract work:

- `FactorySpliceHeaderV1` binding factory id, old/new update number,
  old/new state roots, old/new access roots, vault delta commitment, and
  non-interference digest; implemented in host types and schema;
- host validation for reserve-claim increase/decrease paired with exact
  FactoryVaultCell CKB/xUDT delta; implemented for one touched participant;
- conservative all-participant factory splice witness first, followed by a
  reduced sparse-Merkle factory splice witness for one touched participant;
  all-participant and reduced package/no-std contract witness parsing
  implemented;
- `morph-factory-type` accepts the signed all-participant factory splice bridge
  and the reduced sparse-Merkle bridge; reduced package validation proves that
  only one declared reserve-claim right changed;
- `morph-factory-vault-lock` checks the touched CKB/xUDT FactoryVaultCell input
  and recreated output against the signed factory splice delta.

CLI and smoke work:

- `print-factory-splice-fixture` and `validate-factory-splice-package`;
  implemented for CKB and xUDT splice-in/out fixtures;
- `print-factory-reduced-splice-fixture` and
  `validate-factory-reduced-splice-package`; implemented for CKB and xUDT
  splice-in/out host packages with 256 sparse-Merkle siblings and one
  authorised participant signature, and now emitting
  `FactoryReducedSpliceWitnessV1` contract witness bytes;
- `devnet save-factory-splice-package`; implemented for conservative live
  package capture from a FactoryStateCell/FactoryVaultCell pair;
- `devnet apply-factory-splice`; implemented for applying a validated package
  against the live FactoryStateCell/FactoryVaultCell pair;
- `devnet save-factory-reduced-splice-package` and
  `devnet apply-factory-reduced-splice`; implemented for applying the same live
  FactoryStateCell/FactoryVaultCell transaction shape with the reduced
  sparse-Merkle `FactoryReducedSpliceWitnessV1`;
- `devnet factory-splice-in-smoke` for CKB reserve addition;
  implemented through live apply and post-splice child-channel materialisation;
- `devnet factory-splice-out-smoke` for CKB reserve withdrawal;
  implemented through live apply and post-splice child-channel materialisation;
- `devnet factory-reduced-splice-in-smoke` and
  `devnet factory-reduced-splice-out-smoke`; implemented for the CKB reduced
  sparse-Merkle splice lifecycle, including smoke-summary proof-profile budget
  gates;
- `devnet factory-reduced-xudt-splice-in-smoke` and
  `devnet factory-reduced-xudt-splice-out-smoke`; implemented for the typed
  xUDT reduced sparse-Merkle splice lifecycle with the same proof-profile
  gates;
- `devnet factory-xudt-splice-in-smoke` and
  `devnet factory-xudt-splice-out-smoke` for typed reserve deltas;
  implemented through live apply and post-splice typed child-channel
  materialisation;
- negative smokes for reserve-claim inflation without vault input, vault
  release without rights decrease, xUDT type mismatch, and tampered
  factory-vault change.

Acceptance criteria:

- host invariants reject every rights/vault delta mismatch; implemented;
- package validation rejects invalid signatures and tampered vault deltas;
- CKB live smoke proves a factory can splice reserve value and then materialise
  a child channel from the post-splice FactoryVaultCell;
- xUDT live smoke proves the same path for typed FactoryVaultCells;
- smoke summaries decode factory splice package evidence and bind factory
  splice apply transactions to proof-profile budget gates.
- CKB-VM tests accept valid all-participant and reduced factory splice bridges
  and reject tampered reduced Merkle proofs and mismatched factory-vault
  outputs.
