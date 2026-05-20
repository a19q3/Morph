# Implementation Notes

## Production Boundary

The implementation has three security boundaries:

1. State authority: participant signatures over the canonical state header.
2. Value authority: vault locks that accept only current-state settlement.
3. Fee authority: sponsor policies that can pay publication fees but cannot
   touch channel-owned value.

The core crate models those boundaries without assuming CKB mempool replacement
semantics. A publication transaction is a reconstructible carrier for state
evidence and sponsor authorisation.

The contract crates now implement the fixed-width V1 subset for devnet:

- State type: consumes exactly one State Cell and recreates exactly one newer
  settling State Cell under the same funding anchor and channel context; it can
  also close the state track after the configured relative `since` has matured.
- Factory type: consumes exactly one FactoryStateCell and recreates exactly one
  newer FactoryStateCell under the same factory id and participant context; the
  devnet V1 path is deliberately conservative and requires signatures from all
  two factory participants for ordinary updates. It also accepts a bounded
  reduced-rights proof where one authorised participant may decrease only their
  own committed rights, while every other right remains unchanged and both the
  old and new roots are verified. For local exits, it still requires the
  conservative signature path and checks that the updated factory header commits
  to the child-channel materialisation evidence.
- Factory vault lock: holds factory reserve capacity and permits only a
  conservative local exit that recreates the factory reserve while releasing
  exactly the child-channel vault capacity committed by the same exit evidence.
- Vault lock: permits vault spend only when a unique settling State Cell with
  the expected funding anchor is present, its relative `since` has matured, and
  the settlement outputs match the descriptor commitment in the signed state.
- Sponsor lock: permits fee payment only within an explicit sponsor policy and
  counts only outputs returning to the authorised change lock as sponsor change;
  it also requires a real settling Morph State Cell whose type hash, channel,
  and state number are admitted by the policy.

The state type script verifies the bilateral V1 participant witness: two sorted
compressed secp256k1 public keys, two ECDSA signatures over the canonical state
header digest, and a participant commitment that must match the signed header.
The factory type script verifies a related but stricter V1 witness: two sorted
participant ids, their compressed secp256k1 public keys, and one signature per
participant over the canonical factory-state digest. Sponsor inputs and fee
selection remain outside those state-signature domains.

The draft Molecule schema in `schemas/morph.mol` now names every active
fixed-width V1 object used by the devnet contracts: `StateHeaderV1`,
`FactoryStateHeaderV1`, `BilateralSignatureWitnessV1`,
`FactorySignatureWitnessV1`, `FactoryRightV1`,
`FactoryReducedRightsWitnessV1`, `FactoryLocalExitWitnessV1`, CKB and CKB+xUDT
settlement descriptors, and `SponsorPolicyV1`. The contracts still parse
fixed-width bytes directly; the schema is treated as the public wire-boundary
record until generated Molecule code is introduced.

The first bilateral splicing layer is host-side. `morph-core` models a signed
`SpliceHeader` with old/new funding anchors, old/new funding epochs, vault
descriptor commitments, a base state number, and an asset-delta commitment.
`VaultDescriptorV2` carries canonical CKB and xUDT vault balances, and
`SpliceAssetDelta` makes external contribution, withdrawal, and signed CKB fee
amounts explicit. The validator accepts CKB splice-in/splice-out and xUDT
splice-in/splice-out fixtures only when the current active StateCell context
matches the signed header, the funding epoch advances, participant signatures
verify, the old and new vault descriptors match the signed deltas, withdrawal
outputs match the delta descriptor, and the remaining post-splice vault still
covers the latest settlement descriptor. `morph-cli` exposes this as
`print-splice-fixture --kind splice-in|splice-out|xudt-splice-in|xudt-splice-out`
and `validate-splice-package` for deterministic review. `morph-script-common` also
has fixed-width parsers and digest helpers for `SpliceHeaderV1`,
`SpliceSignatureWitnessV1`, `SpliceVaultDescriptorV2`, and
`SpliceAssetDeltasV1`, matching the draft Molecule schema.
`SpliceStateTransitionWitnessV1` packages those pieces into one fixed-width
1017-byte witness blob, and `verify_splice_state_transition_bundle` checks the
current active StateHeader, post-splice active StateHeader, splice header,
signatures, old/new vault descriptors, and asset deltas together. The CLI
validation path derives the same 1017-byte contract witness from the structured
JSON package and exposes it as `contract_witness_hex`. The splice package now
also carries the complete current StateHeader fields, letting the CLI derive
`current_state_header_hex` and the post-splice `next_state_header_hex` with the
new funding anchor. Transaction builders can therefore reuse one encoding path
for both StateHeader bytes and the splice witness. `morph-state-type` now has a
conservative two-group splice bridge: the old funding-anchor type script can
retire an active StateCell only when a `SpliceStateTransitionWitnessV1` proves
the post-splice active StateHeader, and the new funding-anchor type script can
create a nonzero active StateCell only when it finds the matching old input and
the same proof verifies. The bridge requires the peer StateCell type script to
have the same code hash and hash type, the same args suffix, and only the first
32-byte funding anchor changed. `morph-vault-lock` applies the matching vault
side bridge for active-state spends: it loads the same splice witness, finds the
post-splice StateCell under the peer funding anchor, verifies the bundled
state transition, requires old vault group inputs to equal the old CKB/xUDT
vault descriptor, and requires outputs locked by the new vault script anchor to
equal the new vault descriptor. CKB-VM coverage now exercises valid CKB
splice-in and splice-out bridges, rejects a wrong-channel splice header, and
rejects a transaction that preserves total capacity while underfunding the new
vault. `devnet save-splice-package` now creates signed CKB splice-in/splice-out
packages and live xUDT splice-in/splice-out packages from an active
StateCell/VaultCell pair. `devnet apply-splice --splice-package
<path>` checks that package against the same live cells, recreates the new
StateCell and VaultCell under the new funding anchor, preserves typed xUDT
vault data when present, inserts the fixed-width splice witness, pays external
CKB/fees and typed withdrawal carrier capacity from an owner cell, and reports
the post-splice out points. For splice-out, the package and apply reports expose
`withdrawal_payout_policy: participant_signature_pubkey`, the selected
participant pubkey, and the actual withdrawal lock hash, making the
participant-owned payout rule reviewable from JSON artifacts. The smoke
assertion treats that payout evidence as mandatory for splice-out apply
artifacts. `devnet splice-in-smoke`, `devnet splice-out-smoke`,
`devnet xudt-splice-in-smoke`, and `devnet xudt-splice-out-smoke` now exercise
those live paths through post-splice sponsor funding and settling-state
publication. The xUDT splice-in smoke mints the external owner-controlled typed
input first, then consumes it during splice apply. Signed StateCell publication
now permits participant-authorised settlement descriptor updates, so those
smokes publish a descriptor matching the post-splice vault and finalise the
channel. `devnet splice-negative-smoke` now derives live signed splice packages
and confirms rejection for stale funding epochs, wrong channel ids, wrong vault
type applications, insufficient remaining value, tampered xUDT deltas, and
signed-fee leakage before any malformed splice reaches acceptance. The V1 splice
rule set is intentionally conservative: splice packages are based on a
quiescent base state number, use fixed-width CKB/CKB+xUDT typed deltas, and
send splice-out withdrawals to participant-derived secp256k1 locks rather than
arbitrary operator payout locks. Funding epoch is treated as explicit state
semantics; the final V1 wire target is a `StateHeaderV2` with `funding_epoch`
and vault-set commitments, while the current StateHeaderV1 bridge remains the
compatibility path exercised by devnet evidence. `morph-script-common` already
exposes the fixed-width `StateHeaderV2` parser and
`verify_splice_state_transition_bundle_v2`, which requires the current header's
epoch/vault-set commitment to match the old splice side and the next header's
epoch/vault-set commitment to match the new splice side. `morph-core` mirrors
that target with `StateHeaderV2` signing bytes and invariant coverage for epoch
and vault-set binding.

The vault lock verifies the bilateral CKB settlement descriptor: two sorted
recipient lock hashes and exact output capacities. It also supports the devnet
CKB+xUDT descriptor, which binds the canonical xUDT type hash and exact token
amount for each recipient. The descriptor hash is bound inside
`settlement_descriptor_commitment`, so a finalisation transaction cannot change
the settlement recipients, capacities, asset type, or token amounts without
invalidating the signed state.

The sponsor lock is not a general wallet lock. It will pay only transactions
that produce a settling Morph State Cell for the policy's channel, authorised
state-number interval, and expected StateType hash. Arbitrary output data that
looks like a StateHeader is not enough. This keeps sponsor capacity out of
arbitrary transfers and out of fake-publication fee drains.

The current safety-kernel candidate closes the local P0/P1 boundary gaps that
were previously documented as target properties. Vault finalisation is
authorised by an authentic current Morph StateCell with the expected StateType
and StateLock identity, not by bytes that decode as a `StateHeader`. State
finalisation and active splice retirement require an input whose VaultCell
commitment matches the retiring StateHeader payload commitment, so StateCells
cannot be retired while orphaning channel value. Finalisation maturity uses
canonical relative-block CKB `since`; CLI options are relative block counts and
are encoded before transaction construction. A single-right sparse Merkle proof
proves locality only, so the plain reduced Merkle update path accepts
value-right decreases; value-right increases need full consent or a
vault-delta-bound splice path. See [`../SECURITY-FIXES.md`](../SECURITY-FIXES.md)
for the closeout matrix and negative tests.

Factory mode now has both a host-side predicate and a conservative devnet state
track. A factory-local update is described as changes to a set of participant
rights: balance, reserve claim, membership, exit path, and sponsor budget
claim. Any right outside the declared touched participant set must be
byte-for-byte unchanged, and every touched participant must appear in the
authorisation set.

There is now a bounded on-chain reduced-rights proof for the narrow safe case:
two factory participants, ten fixed-width rights, one touched participant, and
one signature. The proof verifies the full participant commitment, old/new
rights roots, old/new access-manifest roots, the non-interference digest, and
the touched participant's signature. It only allows the touched participant's
own right quantities to decrease; inflation, unrelated participant changes, and
digest/root mismatches are rejected. This is intentionally not a general
Merkle factory proof and not a reduced-signature factory exit.

The reduced factory-exit safety predicate is now represented both at the host
layer and in a fixed-width on-chain witness. In the narrow reserve-claim case,
exactly one authorised participant may release their own `ReserveClaim`; the
release amount must match the before/after delta, and every other factory
right must remain unchanged. The CLI can serialise this predicate as a
`morph.factory_reduced_exit_package.v1` fixture and validate it independently.
On chain, `FactoryReducedExitWitnessV1` binds the rights-root transition, the
one-signer reduced signature, the local child StateCell evidence, the
settlement descriptor, and the factory vault release. `morph-factory-type`
checks the FactoryStateHeader transition and child materialisation, while
`morph-factory-vault-lock` enforces reserve conservation.
CKB-VM tests cover the active CKB reduced-exit child-vault shape, the
release-quantity binding, and rejection of typed ReserveClaim releases through
the CKB-only path. The xUDT reduced-exit V1 path is disabled pending complete
typed release binding across child-vault type hash, child amount, settlement
descriptor, and FactoryVault typed change. `factory-reduced-exit-smoke`
publishes the active CKB path on devnet, then uses the ordinary child-channel
publication and finalisation flow.

The CLI can now serialise that predicate as a deterministic factory update
package. `print-factory-fixture` emits a sample package with a
`non_interference_digest`; `validate-factory-package` checks canonical roots,
canonical participant sets, digest consistency, and the host-side
non-interference predicate. `print-factory-merkle-update-fixture` emits the
first general proof-bundle shape: a sparse Merkle proof for one changed right
inside an arbitrary factory rights tree, with identical sibling frontier before
and after to prove no unlisted subtree changed. `FactoryMerkleUpdateWitnessV1`
uses the same single-right proof shape on chain with a fixed 256-sibling
frontier, and `morph-factory-type` verifies the old/new sparse roots,
unchanged access-manifest root, header digest, and one authorised participant
signature in CKB-VM tests.
The next factory layer is a signed state package. `print-factory-state-fixture`
wraps the update package, computes a domain-separated factory-state digest, and
signs it with every participant key. `print-reduced-factory-state-fixture`
emits the narrower host-side form: after the non-interference predicate passes,
only the authorised participants sign the same style of digest.
`validate-factory-state-package` verifies the nested update package, the
participant-id/public-key bindings, the selected signature mode, the threshold,
and every secp256k1 signature. This reduced factory-state fixture remains a
host-side package; on-chain reduced publication uses the dedicated fixed-width
reduced-rights and reduced-exit witnesses.

For chain publication, the CLI also supports a narrower factory-state-cell
package. It stores the exact `FactoryStateHeaderV1` bytes and the
`FactorySignatureWitnessV1` bytes expected by `morph-factory-type`, so the
state evidence can be reused while the transaction body, fee input, and owner
change are rebuilt later. The same `update-factory --factory-state-package`
entry point now also recognises `FactoryReducedRightsPackage` JSON, which
stores old header, new header, and the reduced-rights witness. For reduced
packages the CLI checks that the package's old header matches the currently
live FactoryStateCell before rebuilding the transaction. In both modes, the
FactoryStateCell capacity stays unchanged and fees are paid from a normal owner
cell.

The conservative M6 factory-splice layer starts at the host/package boundary
and now has an initial M6.1 contract witness bridge. `morph-core` models a
signed factory splice header, factory vault descriptors, and fixed CKB/xUDT
vault deltas. Validation requires exactly one participant reserve claim to move
by the same amount as the FactoryVaultCell delta: splice-in adds external
reserve and increases the claim, while splice-out decreases the claim and
releases the same amount. The CLI exposes this through
`print-factory-splice-fixture --kind splice-in|splice-out|xudt-splice-in|xudt-splice-out`
and `validate-factory-splice-package`. Smoke reports decode
`morph.factory_splice_package.v1` artifacts as factory-splice evidence, and the
validator derives the contract-facing `FactorySpliceWitnessV1` bytes as
`contract_witness_hex`. `devnet save-factory-splice-package` can capture a live
conservative FactoryStateCell/FactoryVaultCell pair into the same signed
package format when the live state root matches the V1 reserve-claim shape, and
`devnet apply-factory-splice` consumes that package with the fixed witness
against the live factory state/vault pair. The CKB factory splice smoke
wrappers now run live package capture, apply the splice, and then materialise a
child channel from the post-splice FactoryVaultCell with full-participant
authorisation. The xUDT factory splice smoke wrappers do the same for typed
FactoryVaultCells, including an external participant-owned xUDT input for
splice-in and participant-owned withdrawal output for splice-out.
The reduced CKB and xUDT factory splice smoke wrappers exercise the same live
flows with `FactoryReducedSpliceWitnessV1`, one authorised participant
signature, and the 256-sibling sparse-Merkle reserve-claim proof.
`morph-script-common` parses the fixed-width `FactorySpliceWitnessV1`,
`morph-factory-type` accepts signed all-participant factory splice updates, and
`morph-factory-vault-lock` checks the touched FactoryVaultCell amount against
the signed delta. Reduced sparse-Merkle factory-splice witnesses are covered by
the same package, devnet smoke, summary, and budget paths.

The conservative factory-local exit path now materialises a bilateral child
channel on devnet without claiming reduced-signature proof mode. The transaction
consumes the current FactoryStateCell, the FactoryVaultCell, and a normal owner
fee input; it recreates the newer FactoryStateCell, returns the remaining
factory reserve, and creates a child StateCell, VaultCell, and SponsorCell. The
child VaultCell may be plain CKB or CKB+xUDT. In the xUDT case, the factory
type checks the child vault type hash and token amount against the committed
settlement descriptor, while the devnet xUDT type script preserves token
supply across the factory vault input, the child vault output, and any factory
vault change. The factory state header commits to the local-exit digest, the
factory type checks the child StateCell type hash, StateCell lock hash, vault
lock hash, and vault shape, and the factory vault lock enforces reserve
conservation:

```text
factory reserve input = factory reserve change + child vault capacity
```

The child channel then uses the ordinary bilateral path: sponsor-paid state
publication followed by relative-`since` vault finalisation.

The watchtower scanner may also be bound by a small operator policy before it
reads blocks or publishes a transaction. The policy is a JSON object generated
by `print-watch-policy-fixture`; it can bind the channel id and constrain
confirmation depth, runtime window, polling interval, fee, explicit sponsor
usage, auto-funded sponsor rotation, auto-sponsor capacity, and devnet mining
requirements. This keeps deployment assumptions in an auditable file rather
than relying only on command-line convention.
The same scanner can append JSONL alerts for older-state detection,
publication submission, confirmed splice detection, stale splice-package
selection, splice-aware publication, and idle scans. It can also POST the same
structured alert to a policy-gated HTTP webhook. The local JSONL sink remains
useful for deterministic devnet review; the webhook path is for operator
integration without changing channel scripts.
The multi-channel config runner has both a single-pass form and a bounded loop
form. The loop does not introduce a separate trust model: every pass uses the
same policy checks, package validation, confirmation-depth scan, cursor file,
and sponsor rules as `watch-latest-package`.
Watchtower private keys are still local devnet keys, but the watchtower entry
points can read them from a file supplied at runtime. The config file remains
key-free, and a key file must contain exactly one hex-encoded private key.
The foreground service runner is deliberately small: it repeats the existing
config pass, writes a JSON health file, uses a configurable backoff after
failed passes, and exits on a stop file, publication, maximum pass count, or
too many consecutive errors. It is intended to be supervised by an external
process manager rather than becoming its own process manager.

## Current Non-Goals

- No routing, gossip, path finding, or liquidity discovery.
- Multi-right and variable-depth reduced-signature proof bundles are deferred
  beyond the current roadmap. The implemented on-chain paths are fixed-width:
  CKB reserve-claim reduced exits and a single-right 256-sibling sparse Merkle
  update. xUDT reduced-exit V1 is disabled until typed release binding is
  restored.
- No generic descriptor runtime.
- No concurrent unconfirmed splice updates. Splice V1 uses a quiescent base
  state number; concurrent splice/off-chain-update interleaving is deferred.
- No arbitrary splice-out payout locks. V1 withdrawals are participant-owned;
  explicit payout-lock allowlists are deferred to V1.1 policy work.
- No base-layer CKB change.
- Watchtower splice integration covers package funding-anchor selection, cursor
  resume metadata, and stale pre-splice package alerts.

## Devnet Acceptance Criteria

A devnet demonstration is acceptable only when it includes:

- at least one successful publish/supersede/finalise path;
- negative transactions for stale state, wrong funding anchor, sponsor drain,
  channel-paid fee leakage, and xUDT type mismatch;
- cycle and transaction-size measurements for each lifecycle transaction;
- a CKB+xUDT vault smoke that mints only under the devnet issuer lock and then
  settles by ordinary xUDT conservation;
- a CKB+xUDT negative smoke proving that unchanged total supply is not enough:
  the vault lock must reject a tampered recipient-level token distribution;
- a finalise-since negative smoke proving that an immature finalisation is
  rejected and that finalisation resumes after explicit maturity blocks;
- a competing-spend smoke proving that a newer state may need to be rebuilt
  against the currently live StateCell after an older publication confirms;
- a sponsor-budget negative smoke proving that a too-low fee cap is rejected
  on-chain and can be resolved by rotating to a fresh SponsorCell;
- reusable signed state packages that can be published without channel signing
  keys;
- a watchtower operator policy that bounds confirmation depth, fees, sponsor
  mode, and automatic sponsor capacity before publication;
- a multi-channel watchtower config format that keeps keys out of the config
  and resolves runtime paths deterministically;
- a bounded multi-channel watchtower loop that reuses persisted cursors between
  passes;
- watchtower key material supplied through runtime flags, environment
  variables, or a single-key file rather than the config;
- a supervisor-friendly watchtower service mode with health-file output,
  stop-file shutdown, error backoff, and consecutive-error limits;
- watchtower JSONL and HTTP webhook alerts for older-state detection,
  publication submission, splice detection, stale splice package selection,
  splice-aware publication, and idle scans;
- a conservative all-participant factory state package with verified nested
  non-interference digest and signatures;
- a conservative factory type script that accepts canonical factory creation,
  signed monotonic updates, and rejects equal-number or invalid-signature
  updates in CKB-VM tests;
- a conservative factory smoke path that opens a FactoryStateCell, saves a
  reusable factory-state-cell package, selects the latest package, and publishes
  a package-backed update without using the state carrier as a fee source;
- a conservative factory-local exit path that releases reserve capacity into a
  bilateral child channel, including a CKB+xUDT child vault path, then
  publishes and finalises that child channel on devnet;
- a factory CKB+xUDT negative smoke proving that conserved token supply is not
  enough when the child vault amount disagrees with the committed local-exit
  descriptor;
- a splice negative smoke proving malformed or mismatched splice packages are
  rejected for stale epoch, wrong channel, wrong vault type, remaining-value
  shortfall, xUDT delta tampering, and signed-fee leakage;
- a reusable factory local-exit evidence package that binds the updated
  FactoryStateHeader, embedded factory signatures, child StateHeader,
  settlement descriptor, output indices, and local-exit digest;
- a sparse Merkle factory-update smoke path that stores the package evidence,
  validates the live old FactoryStateHeader, and publishes a one-right update
  through the fixed 256-sibling proof witness;
- a smoke summary report that preserves cycle, size, status, deployed script
  hashes, deployed script outpoints, watchtower alert events, proof-shape
  budget profiles for reduced-rights, sparse Merkle, and reduced-exit
  witnesses, and expected script-error evidence for review;
- smoke assertions that compare deployed script hashes with the local RISC-V
  contract binaries and require watchtower older-state, publication,
  splice-detected, and stale splice-package alerts before accepting a run as
  current evidence;
- smoke budget assertions that can gate factory proof-profile sibling count,
  witness length, node-estimated cycles, and transaction byte size;
- smoke comparison gates for transaction-set, status, cycle, and byte-size
  regressions between completed devnet runs;
- CI fixture checks for bilateral state fixtures, factory update/state/local
  exit packages, reduced host-side factory packages, watchtower policies, and
  multi-channel watchtower configs;
- a reproducible runbook with deployed script outpoints and transaction hashes.

## Offline Contract Tests

`make contract-tests` uses `ckb-testtool` to execute the compiled RISC-V scripts
inside transaction-shaped fixtures. These tests are not a substitute for a live
devnet run, but they catch script-group mistakes, occupied-capacity mistakes,
and missing finalisation paths before a node is involved.
