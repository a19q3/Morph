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
  two factory participants. For local exits, it also checks that the updated
  factory header commits to the child-channel materialisation evidence.
- Factory vault lock: holds factory reserve capacity and permits only a
  conservative local exit that recreates the factory reserve while releasing
  exactly the child-channel vault capacity committed by the same exit evidence.
- Vault lock: permits vault spend only when a unique settling State Cell with
  the expected funding anchor is present, its relative `since` has matured, and
  the settlement outputs match the descriptor commitment in the signed state.
- Sponsor lock: permits fee payment only within an explicit sponsor policy and
  counts only outputs returning to the authorised change lock as sponsor change;
  it also requires a matching settling StateHeader output whose channel and
  state number are admitted by the policy.

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
`FactorySignatureWitnessV1`, `FactoryLocalExitWitnessV1`, CKB and CKB+xUDT
settlement descriptors, and `SponsorPolicyV1`. The contracts still parse
fixed-width bytes directly; the schema is treated as the public wire-boundary
record until generated Molecule code is introduced.

The vault lock verifies the bilateral CKB settlement descriptor: two sorted
recipient lock hashes and exact output capacities. It also supports the devnet
CKB+xUDT descriptor, which binds the canonical xUDT type hash and exact token
amount for each recipient. The descriptor hash is bound inside
`settlement_descriptor_commitment`, so a finalisation transaction cannot change
the settlement recipients, capacities, asset type, or token amounts without
invalidating the signed state.

The sponsor lock is not a general wallet lock. It will pay only transactions
that produce a settling Morph State Cell for the policy's channel and authorised
state-number interval. This keeps sponsor capacity out of arbitrary transfers.

Factory mode now has both a host-side predicate and a conservative devnet state
track. A factory-local update is described as changes to a set of participant
rights: balance, reserve claim, membership, exit path, and sponsor budget
claim. Any right outside the declared touched participant set must be
byte-for-byte unchanged, and every touched participant must appear in the
authorisation set. This is not yet an on-chain reduced-signature proof system;
it is the executable rule that a future proof bundle must satisfy.

The CLI can now serialise that predicate as a deterministic factory update
package. `print-factory-fixture` emits a sample package with a
`non_interference_digest`; `validate-factory-package` checks canonical roots,
canonical participant sets, digest consistency, and the host-side
non-interference predicate. This remains the data-layer predicate that a future
reduced-signature proof bundle would need to satisfy.
The next factory layer is a signed state package. `print-factory-state-fixture`
wraps the update package, computes a domain-separated factory-state digest, and
signs it with every participant key. `print-reduced-factory-state-fixture`
emits the narrower host-side form: after the non-interference predicate passes,
only the authorised participants sign the same style of digest.
`validate-factory-state-package` verifies the nested update package, the
participant-id/public-key bindings, the selected signature mode, the threshold,
and every secp256k1 signature. The reduced form is still a host-side proof
package, not an on-chain reduced-signature factory exit.

For chain publication, the CLI also supports a narrower factory-state-cell
package. It stores the exact `FactoryStateHeaderV1` bytes and the
`FactorySignatureWitnessV1` bytes expected by `morph-factory-type`, so the
state evidence can be reused while the transaction body, fee input, and owner
change are rebuilt later. `update-factory --factory-state-package` keeps the
FactoryStateCell capacity unchanged and pays fees from a normal owner cell.

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
publication submission, and idle scans. It can also POST the same structured
alert to a policy-gated HTTP webhook. The local JSONL sink remains useful for
deterministic devnet review; the webhook path is for operator integration
without changing channel scripts.

## Current Non-Goals

- No routing, gossip, path finding, or liquidity discovery.
- No reduced-signature factory exits.
- No generic descriptor runtime.
- No base-layer CKB change.

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
- watchtower JSONL and HTTP webhook alerts for older-state detection,
  publication submission, and idle scans;
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
- a reusable factory local-exit evidence package that binds the updated
  FactoryStateHeader, embedded factory signatures, child StateHeader,
  settlement descriptor, output indices, and local-exit digest;
- a smoke summary report that preserves cycle, size, status, deployed script
  hashes, deployed script outpoints, watchtower alert events, and expected
  script-error evidence for review;
- smoke assertions that compare deployed script hashes with the local RISC-V
  contract binaries and require the watchtower older-state/publication alerts
  before accepting a run as current evidence;
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
