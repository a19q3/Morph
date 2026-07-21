# Morph Full-Model Re-audit

Status: baseline audit after restoring the native Factory architecture.

## Verdict

Morph should keep its own protocol authority:

- `FactoryStateCell + FactoryVaultCell` owns shared liquidity, rights,
  non-interference, local/reduced exits, splice, and child materialisation.
- `StateCell + VaultCell` owns bilateral state that CKB can force-enforce.
- Fiber is an optional routing, MPP, invoice, and transport provider.
- Agent/x402/Biscuit/fair-exchange logic is an application sidecar and must not
  become the owner of channel or Factory value.
- A Fiber adapter may export a materialised Morph bilateral channel as a graph
  edge, but Fiber RPC compatibility is not allowed to delete or weaken Morph
  Factory semantics.

The current scripts are a coherent, bounded research profile. They are not yet
production-ready, principally because deployment identity, reorg recovery, and
the real Morph-to-Fiber edge lifecycle are not complete.

## What Was Re-audited

The audit followed the value and authority path through:

1. direct State/Vault creation;
2. signed state publication and settlement;
3. splice retirement/creation;
4. Factory creation, full and reduced rights updates;
5. local/reduced child materialisation;
6. CKB/xUDT settlement and FactoryVault conservation;
7. sponsor and watchtower operation;
8. Hub projection and persistence;
9. existing same-devnet Fiber acceptance.

Host validation, script-common parsing, RISC-V contracts, CKB-VM tests, package
fixtures, and Hub UI semantics were compared as separate trust boundaries.

## Model Defects Fixed In This Baseline

### Signed settlement progress was accidentally frozen

`same_context_except_progress` previously preserved
`settlement_descriptor_commitment` while allowing
`vault_materialisation_root` to change. That inverted the intended model:

- a newer signed state must be able to change participant payouts;
- the live Vault must remain fixed until an explicit signed splice.

Host and script rules now allow a signed descriptor commitment to advance,
preserve descriptor version, and preserve the materialised Vault root. Tests
cover signed acceptance, unsigned rejection, and signed Vault-retarget
rejection.

### Initial Channel configuration lacked script-checked consent

Direct State creation previously checked the Type-ID-style anchor and cell
shape but not bilateral consent over the initial `StateHeader`. A transaction
builder could therefore publish an initial descriptor, registry, participant
set, or challenge policy not jointly authorised.

Direct creation now requires a 2-of-2 bilateral signature witness over the
complete initial header. Factory-created children retain their local/reduced
exit path instead of being forced through bilateral creation consent.

### Initial Factory configuration lacked full consent

Factory creation previously accepted an unsigned update-zero header. The
canonical factory-id input now carries a `FACTORY_SIGNATURE` envelope over the
complete initial header. Reduced and local envelope kinds cannot initialise a
Factory.

### Initial State did not require its committed Vault output

The State type now requires exactly one transaction output whose lock hash,
type hash, capacity, and data match `vault_materialisation_root`. Missing and
ambiguous materialisation are rejected. This prevents a signed initial State
from pointing at a nonexistent or duplicated Vault commitment.

### Direct funding and Factory materialisation were not explicitly separated

Initial authorisation is now mode-separated:

- mode `1` (`BilateralPlain`) requires the bilateral initial signature;
- mode `2` (`FactoryProof`) requires an exact Factory local/reduced-exit
  envelope binding the child State output index, State type hash, and full
  header.

Mode is preserved by ordinary child-channel state progress. This closes the
obvious fake-envelope bypass without sacrificing unilateral reduced exits.

### Host Factory records accepted an impossible participant count

The deployed Factory witness profile is exactly two signers, while Hub/core
records previously accepted arbitrary participant sets. The host and UI now
reject anything other than the executable two-party profile. This does not
remove Factory rights, shared reserve, child materialisation, splice, or local
exit; it makes the current bounded signer limitation honest. Larger signer
sets require a new wire profile.

### Diagnostics and supply chain

- State creation now reports `NewStateNotActive` instead of the contradictory
  `NewStateNotSettling`.
- Missing/ambiguous initial Vaults have distinct script errors.
- Repository-local rustfmt settings prevent parent-workspace formatting drift.
- Rust 1.92 clippy findings in Hub request/cache paths were fixed.
- `anyhow` was updated from 1.0.102 to 1.0.103 for RUSTSEC-2026-0190.

## Findings Rejected Or Reframed

### Competing settling states do not coexist on chain

Two transactions can compete to spend the same live StateCell, but only one can
commit. This is a normal UTXO double-spend race, not two simultaneously live
Morph authorities. Watchtower/package selection still needs to handle mempool
competition, but the chain does not contain two valid descendants of one spent
outpoint.

### Reduced-exit value binding is already enforced

`verify_reduced_factory_exit_update` validates the reserve-claim delta and the
FactoryVault script validates the actual released value. A helper that only
performs output-shape checks is not an independent missing consensus check;
both functions execute in the admitted branch. Existing CKB-VM negative tests
cover amount, asset type, capacity, missing change, and unrelated-right drift.

### Hub actions are projections, not chain transactions

Hub records explicitly expose `source=hub_state_file`,
`chain_status=not_chain_verified`, and `Local only`. The Hub remains useful as
an operator surface, but these records must never be consumed as settlement or
Fiber-edge authority. The future bridge must ingest verified package/on-chain
evidence instead.

## Remaining Production Blockers

### P0: trusted script deployment identity

The initial State now commits the exact Vault output, but the State type does
not itself pin the approved Vault-lock code hash. Participants sign the Vault
commitment and the devnet builder uses the deployed Morph lock, yet a production
profile needs a deployment registry or extended type args that pin State,
StateLock, VaultLock, Factory, and xUDT code identities. The Fiber bridge must
reject channels outside that allowlist.

### P0: Factory-origin proof identity

Mode `FactoryProof` binds the exact Factory exit body and child output, and the
real Factory transaction protects shared reserve. The child State script does
not independently know the trusted Factory code hash. A production deployment
profile must pin it or require an authenticated deployment registry before a
mode-2 child becomes externally advertisable.

### P0: reorg-aware watchtower state

The cursor advances by height but does not retain canonical block hashes or a
rollback window. A reorg can leave the watchtower scanning from a height whose
history was replaced. Production work needs block-hash checkpoints, bounded
rollback, package re-evaluation, and `ReorgDetected`/republication evidence.

### P1: funding identity remains a devnet Type-ID-style profile

`funding_anchor = H(input[0], state_output_index)` is deterministic and unique
for the creating transaction, but it is not a persistent live Fund Cell. The
mainnet-track profile should bind live funding/vault provenance explicitly and
test sibling/output reordering.

### P1: watchtower cannot originate a splice

The watchtower can detect splice context and publish a state package, but it
does not own a complete path for submitting the signed splice bundle itself.
Splice recovery must become a first-class package operation.

### P1: current Factory signer set is only 2-of-2

The rights/proof machinery is richer than a bilateral channel, but the current
full-consent witness contains exactly two participant records. Dynamic larger
sets need a versioned, bounded witness/profile with cycle and fee evidence.

### P1: existing Fiber acceptance proves coexistence, not integration

The current gate runs Morph and Fiber against the same CKB devnet and exercises
Fiber external funding. It does not prove:

- Factory right selection and reservation;
- materialisation of the exact bilateral child;
- graph-edge activation from verified Morph evidence;
- payment/routing over that edge;
- edge disablement on splice, dispute, close, or reorg;
- restart reconciliation without trusting Fiber as source of truth.

These are required for the sovereign adapter.

## Baseline Evidence

The baseline gate includes:

- rustfmt and clippy with warnings denied;
- RustSec and cargo-deny supply-chain checks;
- all workspace unit/property tests;
- generated fixture validation;
- RISC-V contract builds;
- positive and negative CKB-VM tests for State, Vault, Sponsor, Factory,
  FactoryVault, splice, reduced rights, reduced exit, and xUDT;
- Morph Hub TypeScript production build.

Passing these gates establishes an executable model baseline. It does not close
the production blockers above.

## Architectural Decision

Do not implement a second sovereign multi-hop network inside Morph now. Keep a
provider-neutral routing boundary and use Fiber first because routing, MPP,
invoice transport, and gossip are expensive and not Morph's differentiator.
The boundary must remain replaceable:

```text
Factory right
  -> verified reservation
  -> materialised Morph bilateral ChannelBackend
  -> verified edge descriptor
  -> Fiber adapter/hook
  -> Fiber graph + routing
```

Edge activation is downstream of Morph evidence. Fiber may route over an edge;
it may not manufacture, mutate, settle, or delete the underlying Factory right
or Morph channel.
