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
  `summary.json`, including deployed script records, watchtower alerts, and
  factory local-exit evidence.
- completed smoke directories can be compared with optional regression gates
  for transaction set, status, cycles, and byte size.
- CI validates generated bilateral fixtures, factory packages, factory
  local-exit evidence, reduced host-side factory packages, and watchtower
  policies.
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
- CLI package generation and `update-factory --factory-state-package`
  publication support for the bounded reduced-rights witness.
- Devnet `open-factory`, `save-factory-state-package`, `update-factory`,
  `factory-exit-channel`, `factory-smoke`, and
  `factory-reduced-rights-smoke` commands.

## M4: Reduced-Signature Factory Mode

Status: partially implemented for the narrow claim-reducing update case.

Implemented:

- fixed-width `FactoryReducedRightsWitnessV1`;
- script-level verification of full participant membership commitment;
- old/new rights-root and access-manifest-root checks;
- non-interference digest binding;
- one authorised signature over the new FactoryStateHeader;
- devnet smoke coverage for reduced-rights package publication;
- rejection of touched-right inflation and unrelated participant mutation in
  CKB-VM tests.

Still open:

- reduced-signature value-releasing factory exits;
- general Merkle proof bundles for larger factories;
- benchmarked cycle limits for larger proof shapes.
