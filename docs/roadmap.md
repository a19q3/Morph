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
- Devnet `factory-reduced-xudt-exit-smoke` command for the typed
  reserve-claim reduced-exit path into a CKB+xUDT child vault.

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
- fixed-width `FactoryReducedExitWitnessV1` and
  `FactoryReducedExitXudtWitnessV1` schema entries;
- script-level reduced factory-exit verification in `morph-factory-type` and
  `morph-factory-vault-lock`, including local child-channel evidence and
  reserve-conservation checks;
- CKB-VM coverage for a reserve-claim reduced exit that materialises a child
  channel from the factory vault, including the CKB+xUDT child-vault shape and
  typed amount/type mismatch rejection;
- devnet smoke coverage for CKB and CKB+xUDT reserve-claim reduced-exit
  publication, child-state publication, and child-vault finalisation;
- devnet smoke coverage for a surplus-preserving CKB+xUDT reduced exit where
  typed xUDT change remains in the FactoryVaultCell;
- devnet smoke coverage for a one-sided CKB+xUDT reduced exit where one child
  participant receives all xUDT and the other receives zero tokens;
- devnet negative smoke coverage for a reduced CKB+xUDT exit whose child vault
  xUDT amount is tampered while total xUDT supply remains conserved;
- host-level sparse Merkle update package for a single-right transition inside
  an arbitrary factory rights tree, including CLI fixture and validation;
- script-level fixed-width sparse Merkle update witness for the same
  single-right transition, including CKB-VM accept/reject coverage;
- devnet smoke coverage for the sparse Merkle factory update witness, including
  smoke-summary evidence and per-transaction budget profile entry;
- smoke-summary proof profile binding for the bounded reduced-rights update,
  sparse Merkle update, CKB reduced-exit, and balanced, one-sided, and
  typed-change CKB+xUDT reduced-exit proof shapes, including proof sibling
  count where applicable, witness length, node-estimated cycles, and
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

- generalized typed reduced-exit variants beyond the current fixed-width
  balanced, one-sided, typed-change, and tampered-amount negative CKB+xUDT
  reserve-claim smokes;
- empirical budget profiles for larger, multi-right, or variable-depth proof
  shapes beyond the current fixed-width smoke witnesses.

## M5: Bilateral Splicing And Dynamic Funding

Status: planned. This milestone expands the paper's channel-continuity goal:
participants should be able to add or remove on-chain value without closing the
channel, while preserving the channel identity, signed-state ordering, sponsor
policy, and vault settlement safety already implemented in M0-M2.

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
- `SplicePackageV1`: reusable JSON package containing the splice header,
  witness, current StateCell out point, old vault out point, expected new vault
  descriptor, and optional sponsor policy hints.
- `StateHeaderV2` or an equivalent extension field that binds state evidence to
  a funding epoch while keeping the stable channel id visible.
- `VaultDescriptorV2`: typed vector of CKB and xUDT vault partitions so splice
  deltas can be checked without ad hoc per-asset fields.

Host-level validation:

- accept splice-in only when new vault value equals old vault value plus the
  signed external contribution minus explicitly signed splice fees;
- accept splice-out only when withdrawn outputs match the signed participant
  withdrawal descriptor and the remaining vault value still covers the latest
  signed settlement descriptor;
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
  strictly newer funding epoch;
- teach `morph-vault-lock` to accept an old vault spend into a new vault plus
  signed splice-in/splice-out outputs only when the current StateCell carries
  the matching splice commitment;
- keep ordinary finalisation unchanged except that it must verify the settling
  StateCell and VaultCell are from the same funding epoch;
- extend `morph-sponsor-lock` tests so sponsor capacity can pay splice
  publication fees without being counted as channel value;
- add CKB+xUDT splice checks to ensure the devnet xUDT script conserves supply
  while Morph scripts enforce the participant-level splice descriptor.

CLI and package workflow:

- `print-splice-fixture` and `validate-splice-package` for deterministic
  host-side review;
- `devnet save-splice-package` to build a reusable package from the live
  StateCell/VaultCell pair and explicit CKB/xUDT deltas;
- `devnet apply-splice --splice-package <path>` to rebuild the transaction with
  fresh fee inputs and submit it;
- `devnet splice-in-smoke` for adding CKB to an active channel and then
  publishing/finalising a post-splice state;
- `devnet splice-out-smoke` for withdrawing CKB while the channel continues;
- `devnet xudt-splice-in-smoke` and `devnet xudt-splice-out-smoke` for typed
  asset deltas;
- `devnet splice-negative-smoke` cases for stale funding epoch, wrong channel
  id, wrong vault type, insufficient remaining vault value, tampered xUDT
  amount, and sponsor fee leakage.

Watchtower and operator impact:

- state package records must include funding epoch and vault descriptor hash;
- watchtower latest-package selection must reject packages for superseded
  funding epochs unless an accompanying splice package updates the epoch first;
- scan cursors should record splice transactions so a watcher can resume from a
  confirmed splice without replaying obsolete packages;
- JSONL/webhook alerts should include `splice_detected`,
  `splice_package_stale`, and `splice_publication_submitted` events.

Acceptance criteria:

- CKB-VM tests accept a valid CKB splice-in and splice-out transition;
- CKB-VM tests reject stale-epoch finalisation, mismatched StateCell/VaultCell
  epochs, wrong-channel splice headers, and tampered withdrawal outputs;
- CKB+xUDT tests reject same-supply but wrong-recipient/token-amount splice
  outputs;
- devnet smoke demonstrates splice-in, post-splice state publication, and
  finalisation from the new funding epoch;
- devnet smoke demonstrates splice-out and proves the remaining channel value
  can still settle correctly;
- smoke summary records splice transaction metrics and budget profiles by
  splice kind;
- watchtower smoke proves an older pre-splice package is not published after a
  confirmed splice unless it is valid for the current funding epoch.

Open design decisions:

- whether V1 splice requires a quiescent base state number or supports
  concurrent off-chain updates while the splice transaction is unconfirmed;
- whether funding epoch is a new StateHeader version field or a commitment
  derived from a stable channel id plus current vault out point;
- how to represent multi-asset deltas before a generic descriptor runtime is
  introduced;
- whether splice-out withdrawal outputs must be participant-owned only or can
  target arbitrary signed payout locks.

## M6: Factory Splicing And Reserve Repartition

Status: planned. This milestone applies the splice model to factories: the
FactoryVaultCell should be able to receive new reserve value or release value
without materialising every child channel, while FactoryStateCell rights remain
auditable.

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
  non-interference digest;
- host validation for reserve-claim increase/decrease paired with exact
  FactoryVaultCell CKB/xUDT delta;
- conservative all-participant factory splice witness first, followed by a
  reduced sparse-Merkle factory splice witness for one touched participant;
- `morph-factory-type` checks that only declared reserve-claim rights change;
- `morph-factory-vault-lock` checks that factory vault input equals recreated
  factory vault plus signed splice-out outputs or external splice-in inputs.

CLI and smoke work:

- `print-factory-splice-fixture` and `validate-factory-splice-package`;
- `devnet factory-splice-in-smoke` for CKB reserve addition;
- `devnet factory-splice-out-smoke` for CKB reserve withdrawal;
- `devnet factory-xudt-splice-in-smoke` and
  `devnet factory-xudt-splice-out-smoke` for typed reserve deltas;
- negative smokes for reserve-claim inflation without vault input, vault
  release without rights decrease, xUDT type mismatch, and tampered
  factory-vault change.

Acceptance criteria:

- host invariants reject every rights/vault delta mismatch;
- CKB-VM tests accept conservative factory splice-in/out and reject stale update
  numbers or invalid participant signatures;
- devnet smoke proves a factory can splice reserve value and later materialise
  a child channel from the post-splice FactoryVaultCell;
- smoke budget profiles bind factory splice proof shape, witness size, cycles,
  and transaction bytes.
