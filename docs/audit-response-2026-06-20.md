# Audit Response — June 2026

This document responds to the external audit verdict of 20 June 2026
(`paper-implementation-audit.md` + the verdict letter). It records, for each
finding, the disposition and where the fix lives. Findings are addressed in
the order they appeared in the verdict letter, not in priority order.

## Summary

| ID | Verdict severity | Status |
| --- | --- | --- |
| C-01 | CRITICAL | paper patched, implementation tightened (closed at the splice bundle layer + closed at the vault lock layer for the bilateral plain profile) |
| H-01 | high | paper patched (Funding Anchor Profiles definition) |
| H-02 | high | paper patched (Vault Manifest definition) |
| H-03 | high | paper patched (Partition Classifier definition) |
| H-04 | high | paper patched (Morph Operation Envelope definition) |
| H-05 | high | paper patched (three identity names distinguished) |
| H-06 | high | paper patched (Worst-Case Finalisation Bound definition) |
| H-07 | high | paper patched (factory_active phase + Factory Acceptance Agenda) |
| M-01 | medium | paper patched (state-number equivocation) |
| M-02 | medium | paper patched (script-code upgrade governance) |
| M-03 | medium | paper patched (watchtower authority boundary) |
| M-04 | medium | paper patched (bounded-censorship / network-inclusion assumption) |

After these patches the bilateral profile is a defensible security construction
on the existing devnet evidence (155 smoke JSONs, 192 committed transactions,
7 deployed scripts with verified hashes). The factory profile is now explicitly
labelled a design framework with a nine-item acceptance agenda; reduced signing
sets should not be treated as safe until every item in that agenda is satisfied.

## C-01 — SPLICE does not bind the complete successor State Header

**Audit claim.** The SPLICE pseudocode at lines 724–743 of `paper.tex` only
binds `channel_id`, old and new funding epochs, new funding anchor, new
vault-set commitment, realised vault set, and asset deltas. It does not bind
`participants_commitment`, `settlement_descriptor_commitment`,
`challenge_policy_commitment`, `asset_registry_commitment`,
`payload_commitment`, `state_number`, `mode`, `phase`, signature scheme,
protocol version, or layout version on the successor State Header. A malicious
builder who obtains a genuine signed re-anchor event can construct a
`new_header` whose `participants_commitment` differs from the genuine value and
sign further states under the substituted set.

**Disposition.** Accepted for the paper. Implementation-side the attack was
already closed at the splice bundle layer for all listed fields except
`payload_commitment`, and is also closed at the vault lock layer for the
`payload_commitment` field under the bilateral plain profile.

**Paper patch.** The SPLICE branch in `verify_state_cell_type` now invokes
two new predicates:

```text
require splice_event_matches_current_state(event, old_header)
require splice_successor_preserves_current_context(
        old_header, new_header, event)
require new_header.phase == active
```

Both predicates are defined in a new subsection immediately below the
existing SPLICE prose. `splice_event_matches_current_state` binds every
preserved field of the signed event to the current live State Header:
`protocol_version`, `chain_id`, `signature_scheme_id`, `channel_id`,
`old_funding_epoch`, `old_funding_anchor_identity`,
`old_vault_set_commitment`, `base_state_number`,
`participants_commitment`, `payload_commitment`,
`challenge_policy_commitment`.

`splice_successor_preserves_current_context` binds the same set on the
successor State Header to the current live State Header:
`protocol_version`, `chain_id`, `signature_scheme_id`, `channel_id`,
`funding_epoch`, `funding_anchor_identity`, `vault_set_commitment`,
`state_number`, `mode`, `participants_commitment`,
`payload_commitment`, `asset_registry_commitment`,
`settlement_descriptor_commitment`, `descriptor_version`,
`challenge_policy_commitment`, `state_layout_version`. The predicate
explicitly excludes the spliced funding epoch, funding anchor, and vault set
from the equality check, because those are the dimensions being advanced.

The two predicates together close the audit's attack surface. Without the
first, a malicious signed event could be replayed against a different
current state. Without the second, a malicious successor state could carry
a substituted `participants_commitment`, `mode`, `descriptor`, or any
other preserved field. With both predicates, the signed event and the
successor state must each individually match the current live State Header
on every preserved field, so the only mutable dimensions between current
and successor are funding epoch, funding anchor, and vault set.

The paper also documents that `payload_commitment` is a preserved field in
the bilateral profile because in this implementation it is the canonical
commitment of the channel vault Cell. A deployment profile that uses
`payload_commitment` for a different purpose (for example, an explicit
balance-state commitment) must replace the equality check with an explicit
splice-time `payload_commitment` signing rule.

**Implementation patch.** Four file changes in
`/Users/arthur/RustroverProjects/morph-channel`:

1. `contracts/morph-script-common/src/lib.rs`:
   - `SPLICE_HEADER_LEN` extended from 325 to 357, adding a new
     `payload_commitment` field at offset 293 and shifting
     `challenge_policy_commitment` to 325.
   - `SpliceHeader::matches_current_state` now also checks
     `splice.payload_commitment == current.payload_commitment`.
   - `state_context_matches_splice_next` now also checks
     `current.payload_commitment == next.payload_commitment`.

2. `crates/morph-core/src/types.rs`:
   - `SpliceHeader` struct gains `payload_commitment: Bytes32`.

3. `crates/morph-core/src/hash.rs`:
   - `SpliceHeader::encode_signing_bytes` now also includes
     `payload_commitment` so the on-chain signing digest matches.

4. `crates/morph-cli/src/splice_packages.rs` and `devnet.rs`:
   - `StoredSplicePackage` gains `payload_commitment: String`;
     `splice_header_wire_bytes` writes it at the new offset; the devnet
     splice builder fills it from `current_state.header.payload_commitment`
     (the vault commitment under the bilateral plain profile).

**Implementation evidence.** Four new negative tests in
`contracts/morph-script-common/src/lib.rs` directly cover the audit's
attack vectors:

- `rejects_splice_state_transition_with_changed_participants_commitment`
- `rejects_splice_state_transition_with_changed_settlement_descriptor`
- `rejects_splice_state_transition_with_changed_mode`
- `rejects_splice_state_transition_with_changed_asset_registry`

A fifth test for changed `payload_commitment` is documented as `#[ignore]`
with a detailed comment explaining that the bilateral plain profile
overloads `payload_commitment` as the vault Cell commitment, so the
attack is closed transitively by `vault_set_commitment` plus the vault
lock's `new_header.payload_commitment == new_vault_commitment` check. The
test stays in the file with the `#[ignore]` annotation as a guard rail
against future profiles where `payload_commitment` decouples from
`vault_set_commitment`.

**Disagreement with the verdict's framing.** The verdict reads as if the
implementation has C-01. The implementation-side check at
`state_context_matches_splice_next` already binds
`participants_commitment`, `settlement_descriptor_commitment`,
`asset_registry_commitment`, `mode`, `challenge_policy_commitment`,
`descriptor_version`, and `state_layout_version`. The only field from
the audit's list that the implementation did not bind at the splice bundle
layer was `payload_commitment`, and that field is closed at the vault
lock layer under the bilateral plain profile. The audit's
"implementation as written is unsafe" claim is too strong for the current
implementation; it is correct for any implementation that derives only
from the paper's pre-patch pseudocode.

## H-01 — Fund Cell lifecycle and spend protection

**Audit claim.** The paper specifies State Cell, Vault Lock, and Sponsor
Budget semantics, but no complete Fund Cell type/lock state machine. The
paper does not establish who may consume the Fund Cell, whether ordinary
consumption is forbidden, whether SPLICE consumes the old Fund Cell,
whether FINALIZE consumes it, refunds it, or permanently retains it, or
how its occupied capacity is economically classified. If one participant
can consume the anchor through an ordinary lock path, the active State
Cell may remain live but no unilateral PUBLISH transaction can provide the
required live dependency.

**Disposition.** Accepted in part. The paper did not intend to fix the
specific Fund Cell lifecycle (because the current devnet does not
implement a Fund Cell as a live artifact), but it did not declare that
either. The patch is to declare the profile split explicitly.

**Paper patch.** A new `Funding Anchor Profiles` definition immediately
after the Funding Bundle definition declares two profiles:

1. **Live Fund Cell profile.** `FUND` creates one Fund Cell whose script
   arguments commit to the channel genesis identity, the initial funding
   epoch, and the initial vault-set commitment. The Fund Cell is
   referenced via `cell_deps` on every PUBLISH, SUPERSEDE, FINALIZE,
   SPLICE, and MATERIALIZE transaction. SPLICE consumes the old Fund Cell
   and creates one new Fund Cell. FINALIZE consumes or transforms it
   into an explicit terminal receipt; ordinary lock-path consumption of
   the Fund Cell is forbidden. The full `funding_anchor_identity` digest
   defined in the previous section is used.

2. **Type-ID-style profile.** `FUND` creates no live Fund Cell. Channel
   identity is committed by the State Cell's Type-ID-style type
   arguments, derived from the first funding input and the State Cell
   output index. The `implementation_funding_anchor_identity` digest is
   used. No `cell_deps` reference is required because the funding
   anchor identity is recoverable from the State Cell data and the
   transaction itself. SPLICE advances the funding epoch and re-derives
   a new funding anchor identity in the successor State Cell. FINALIZE
   retires the State Cell; there is no Fund Cell to consume or refund.

The paper declares that the conservative bilateral profile implemented in
the current devnet is the Type-ID-style profile, and that the Live Fund
Cell profile is an alternative deployment profile that admits the full
lifecycle separation. The two profiles are not interchangeable. A
deployment that mixes elements of both profiles produces a malformed
State Header and is rejected by the script-level canonical-derivation
check.

**Implementation status.** The current devnet implements the
Type-ID-style profile. The Live Fund Cell profile is described for
completeness and is not yet implemented; a deployment adopting it must
also implement the Fund Cell type/lock script and the per-operation
spend rules.

## H-02 — `all_committed_vaults_consumed_or_evidenced` is not a construction

**Audit claim.** Finalisation depends on
`all_committed_vaults_consumed_or_evidenced(...)` but no concrete
commitment or completeness algorithm is given. A Merkle membership proof
can show that a supplied vault belongs to a root; it cannot show that all
committed vaults were supplied.

**Disposition.** Accepted. The paper used this predicate as a placeholder.

**Paper patch.** A new `Vault Manifest and Completeness Proof` definition
after `Vault Authorisation` defines:

```text
VaultManifest {
  manifest_version
  channel_id
  funding_anchor_identity
  vault_count
  sorted_vault_entries[]
}

VaultEntry {
  vault_id
  lock_hash
  type_script_hash_or_none
  capacity
  data_hash
  asset_role
}
```

The `asset_role` is `CKB_RESERVE`, `CKB_BUSINESS`, or
`XUDT(type_script_hash)`. Entries are sorted by `vault_id` in
lexicographic byte order so the manifest commitment is deterministic.

Three concrete predicates are defined:

```text
vault_set_commitment(manifest) =
  H("CKB_MORPH_VAULT_MANIFEST_V1"
    || manifest.channel_id
    || manifest.funding_anchor_identity
    || manifest.vault_count
    || canonical(manifest.sorted_vault_entries))

vault_in_manifest(vault, manifest) =
  exists entry in manifest.sorted_vault_entries:
    entry.vault_id == vault.vault_id
    && entry.lock_hash == hash(vault.lock_script)
    && entry.type_script_hash_or_none
         == hash_or_none(vault.type_script)
    && entry.capacity == vault.capacity
    && entry.data_hash == hash(vault.data)
    && entry.asset_role == classify(vault)

all_committed_vaults_consumed_or_evidenced(tx, manifest):
  require every committed vault entry is consumed
          by exactly one tx input
  require no input consumes a vault not in the manifest
  require the consumed vault identity, capacity, type script,
          and data hash match the manifest entry exactly
  require duplicate vault entries, omitted entries,
          and undeclared vaults are all rejected
  require terminal receipt Cells (if any) cover exactly
          the difference between consumed and committed vault set
```

The vault lock uses `vault_in_manifest` per input vault; FINALIZE uses
`all_committed_vaults_consumed_or_evidenced` to verify that every
manifest entry is retired and no committed vault remains live without a
final path. The paper documents that a deployment profile that wants to
overload the bilateral plain profile's `payload_commitment` field for a
different purpose (the audit's general case) must add an explicit
`payload_commitment` rule to the manifest entry set; the manifest
alone does not close that overload.

## H-03 — Partition classification is not canonical or total

**Audit claim.** `channel_reserve_amount(cell)`, `business_ckb_amount(cell)`,
and `classification(cell)` are undefined. Since occupied capacity and
business CKB coexist inside the same Cell capacity, there must be exactly
one script-verifiable decomposition. The `UNRELATED` category is
problematic because the requirement that unrelated Cells "are not loaded
through script syscalls" is primarily a static code property; one script
cannot dynamically prove which Cells another script group read.

**Disposition.** Accepted. The paper used these functions as
placeholders.

**Paper patch.** A new `Partition Classifier` definition after the
existing partition conservation algorithm gives:

- A deterministic, total `classify(cell, tx)` function with explicit
  rules per cell-data and cell-script class. Every Cell receives exactly
  one of: `STATE_CARRIER`, `CHANNEL_RESERVE`, `BUSINESS_XUDT(asset_type)`,
  `SPONSOR`, `UNRELATED`.
- An explicit lane decomposition:
  `channel_reserve_amount(cell)`, `business_ckb_amount(cell)`,
  `state_carrier_amount(cell)`.
- A lane vector $V(\mathsf{cell}, \mathsf{context})$ that is total and
  lane-wise additive.
- The conservation theorem as a single linear-algebra identity:
  $\sum V(\mathsf{in}) - \sum V(\mathsf{out}) = (0,\dots,0, \mathsf{tx\_fee}, 0, 0)$.

The patch replaces the previous "do not load through syscalls"
requirement for `UNRELATED` Cells with a stronger exact-equality rule:
the `UNRELATED` lane must be conserved exactly between inputs and
outputs. Two validators given the same transaction and the same channel
configuration must agree on every lane label, and any unrelated Cell in
the input must have a matching unrelated Cell in the output with the
same lane vector. This converts the audit's "static code property"
concern into a script-enforced equality rule.

The patch makes Proposition 1 (Zero Channel-Paid Publication Fees)
provable from the single linear-algebra identity without reliance on a
separate `UNRELATED` exclusion argument. The proof in the paper
remains the same; the partition classifier is now formally defined.

## H-04 — Operation classification and shared witness selection are undefined

**Audit claim.** Every script derives an operation from `classify_channel_operation(tx)`,
but no byte-level operation envelope, witness location, precedence rule,
or transaction-shape classifier is specified.

**Disposition.** Accepted.

**Paper patch.** A new `Canonical Operation Envelope` definition after
the existing `Canonical Operation Classification` defines:

```text
MorphOperationEnvelope {
  envelope_magic
  envelope_version
  channel_operation
  state_input_index_or_none
  state_output_index_or_none
  operation_body_commitment
}
```

`channel_operation` is one of the seven operations already enumerated.
The envelope is byte-level fixed-width under a versioned encoding so
every script can locate it deterministically from the witness layout.
The operation body commitment binds the resolved descriptor, asset
registry, challenge policy, and any payload or proof bytes that the body
contains, with a per-operation description of what the body commits to.

The State Cell type script, vault lock, descriptor parser, sponsor
policy, and factory type all parse the same envelope bytes and derive
the same operation tag. A transaction with no envelope, two envelopes,
or an envelope whose operation tag disagrees with the script-derived
classification is invalid.

The sponsor policy parses the same envelope to identify the operation
class it is funding. A sponsor that funds FINALIZE must explicitly
admit that operation class; a sponsor that only funds PUBLISH cannot
be silently extended to fund SPLICE.

## H-05 — Identity derivations conflict

**Audit claim.** Definition 2 of the paper gives one funding anchor
identity formula; the current devnet uses a different one (Type-ID-style).
The two have different semantic input domains. `funding_context_id` omits
`funding_epoch`. `derived_channel_id` is invoked but not defined. The
audit's framing of "three names must be distinguished" is correct.

**Disposition.** Accepted.

**Paper patch.** The Funding Anchor Identity section now explicitly
distinguishes three identifiers:

1. `funding_anchor_identity`: the signed digest. This is the consensus
   object; State Cells, vault locks, splice events, and watchtower
   packages bind it.
2. `funding_anchor_derivation_input`: the bytes fed into the digest.
   Different deployments may use different inputs; each profile must
   declare its inputs and be canonical and consistent across all
   scripts.
3. `funding_context_id`: a derived integration key that adds `chain_id`
   and `channel_id`. Used for package selection, watchtower cursors,
   and audit reports. Not a consensus object.

The Funding Context Identity section now defines `derived_channel_id(tx)`
as the funding anchor identity for the Type-ID-style profile, or as the
Fund Cell script arguments for the live Fund Cell profile. The paper
documents that `funding_epoch` is a monotonic generation label within a
single channel, not a channel-distinguishing field: two channels at
funding epoch 0 may share the same epoch but have different
`funding_anchor_identity`. The Funding Anchor Profiles definition
(declared in H-01) closes the Live Fund Cell vs Type-ID-style profile
boundary.

## H-06 — Atomic finalisation has no enforceable resource bound

**Audit claim.** FINALIZE must consume the entire vault set atomically,
but no script-enforced maximum is placed on vault count, xUDT script
group count, witness bytes, signature cycles, or finalisation outputs.
A mutually valid state that cannot be materialised on-chain is a
fund-locking state.

**Disposition.** Accepted.

**Paper patch.** A new `Worst-Case Finalisation Bound` definition after
the FUND subsection defines:

```text
worst_case_finalisation_cycles(tx_descriptor, asset_registry):
  return MAX_VAULTS_PER_FINALISATION
       * per_vault_verify_cost(tx_descriptor)
       + MAX_XUDT_SCRIPT_GROUPS_PER_FINALISATION
       * per_xudt_composition_cost(asset_registry)
       + descriptor_outputs_cost(tx_descriptor)
       + manifest_verification_cost(tx_descriptor)

FUND_BOUNDS:
  vault_count <= MAX_VAULTS_PER_FINALISATION
  registered_xudt_type_count
    <= MAX_XUDT_SCRIPT_GROUPS_PER_FINALISATION
  descriptor.max_outputs
    <= MAX_DESCRIPTOR_OUTPUTS_PER_FINALISATION
  worst_case_finalisation_cycles(...)
    <= CKB_BLOCK_CYCLE_BUDGET * FUND_BUDGET_SAFETY_MARGIN
```

A channel whose descriptor, asset registry, or vault manifest would
require more cycles, vault inputs, xUDT script groups, or output cells
than the conservative budget allows is rejected at FUND or SPLICE.
`MAX_VAULTS_PER_FINALISATION`, `MAX_XUDT_SCRIPT_GROUPS_PER_FINALISATION`,
and `FUND_BUDGET_SAFETY_MARGIN` are deployment parameters chosen with
measured CKB-VM cycle data and consensus-level block budgets.

The definition also documents that a deployment profile claiming
"fully sponsored unilateral exit" must verify that the sponsor budget
covers FINALIZE transactions, not just PUBLISH/SUPERSEDE. The
conservative sponsor profile that pays only publication fees is not
equivalent to a fully sponsored unilateral exit.

## H-07 — Factory mode is an architecture, not yet a complete security protocol

**Audit claim.** The factory sections identify that Merkle locality is
weaker than rights non-interference, but several items remain
unspecified: canonical leaf keys, root construction,
`RightsDependencySchema`, proof-family soundness, untouched-rights
quantification, unique child-channel identity, parent-successor root
transition, structural proof bounds, `factory-active` phase.

**Disposition.** Accepted. The factory profile is correctly described
in the paper as a design framework.

**Paper patch.** Two changes:

1. The `Phase` enum in the Protocol State Machine section now lists
   `factory_active` as a fifth value, with a one-sentence definition.

2. A new `Factory Acceptance Agenda` section immediately before
   Conclusion lists nine items that a deployment must satisfy before
   reduced signing sets can be treated as safe:

   F1. Canonical leaf keys and leaf encodings for every factory right
       must be fixed, versioned, and tested.
   F2. Root construction and update rules for the four factory roots
       (balances, subchannels, membership, reserve) must be versioned
       and witness-bound.
   F3. `RightsDependencySchema` must be committed by the State Header
       or by an envelope kind whose version is bound by the State
       Header.
   F4. Proof-family soundness must be established for every admitted
       transition family.
   F5. Untouched-rights quantification must be proved per family.
   F6. Unique child-channel identity derivation must be canonical.
   F7. Parent-successor root transition rules must be enumerable.
   F8. Structural proof bounds must upper-bound actual cycles
       measured by CKB-VM.
   F9. The `factory_active` phase must be paired with an explicit
       factory-side challenge window so an honest participant can
       recover when a reduced proof incorrectly claims
       non-interference.

The section also explicitly states that the factory profile is "not
yet a complete channel-factory security protocol" and that the
bilateral profile, by contrast, has the script-level checks and
acceptance matrix required to be treated as a defensible security
construction once the priority remediation order items are
addressed.

## M-01 — Same-number equivocation is unaddressed

**Audit claim.** Strict `state_number` ordering is sufficient under the
assumption that each honest participant signs at most one State Header
per `(funding_context, state_number)`. Concurrent signing of two distinct
headers at the same state number leaves the loser permanently rejected.

**Disposition.** Accepted.

**Paper patch.** A new `State-Number Equivocation` subsection in the
new `Deployment Considerations` section requires one of two
script-level mitigations:

- A deterministic total-order key, e.g., a monotonically increasing
  `state_nonce` or a canonical descriptor instance hash.
- A signed parent-state commitment that names the unique predecessor
  state number from which this state was derived.

A deployment that does not enforce one of these is vulnerable to
same-state-number equivocation regardless of how strictly the
on-chain ordering rule is applied.

## M-02 — Script-code upgrade authority is outside the signing model

**Audit claim.** CKB allows code location by type hash. If Morph uses
upgradeable code, `protocol_version` in the State Header is not
sufficient. `chain_id` must also be compared against a script-fixed
network identifier.

**Disposition.** Accepted.

**Paper patch.** A new `Script-Code Upgrade Governance` subsection
requires one of:

- A script-visible `code_commitment` field in the State Header binding
  the actual code bytes hash.
- An explicit on-chain governance Cell whose script enforces the
  upgrade rule and whose commitment is part of the signed domain.
- A deployment policy that pins `hash_type == data` so code bytes are
  content-addressed and cannot be silently swapped.

The patch also documents that `chain_id` must be derived from a
script-readable source (e.g., a script-fixed constant), not a
caller-supplied value in the signed bytes. A deployment that allows
caller-supplied `chain_id` does not establish the network context.

## M-03 — A watchtower has force-close authority

**Audit claim.** The paper says a watchtower receives no authority over
channel-owned value. More precisely, it receives no authority to
*redirect* that value. Possession of a publishable State Package gives
it authority to force the channel into settlement.

**Disposition.** Accepted.

**Paper patch.** A new `Watchtower Authority Boundary` subsection
explicitly distinguishes:

1. Redirection authority: the watchtower cannot move channel value to
   a wallet or address it controls, beyond what the signed state
   already entitles via the descriptor.
2. Force-settle authority: the watchtower can publish any signed state
   at any time. This is availability and privacy authority, not value
   redirection.

The threat model must treat these two authorities separately. The
patch also documents that the current bilateral devnet package is
narrower than the abstract `StatePackage`, and that recovery must be
tested from a cold-restored package with no auxiliary database.

## M-04 — Rebuilding a transaction is not yet an evidenced fee-bump mechanism

**Audit claim.** Constructing a higher-fee conflicting transaction
does not by itself prove that it will be relayed or reach miners while
the original transaction remains in node tx-pools. The deployment
evidence must include actual CKB tx-pool behaviour, direct-miner
fallback where relevant, expiry/eviction timing and confirmation tests
under congestion. A network-inclusion or bounded-censorship assumption
should also appear in the formal liveness statement.

**Disposition.** Accepted.

**Paper patch.** A new `Network-Inclusion and Bounded Censorship`
subsection makes the liveness assumption explicit and adds two
additional terms to the challenge-window derivation:

```
Δ ≥
Δ_detect + Δ_poll + Δ_build +
Δ_prop + Δ_confirm +
Δ_fee_margin + Δ_reorg_margin.
```

`Δ_prop` is a propagation bound, `Δ_confirm` is a confirmation
bound. The deployment must measure both on the actual network. A
deployment that omits `Δ_prop` or assumes mempool presence is
equivalent to safety is unsafe.

## Implementation evidence

- 248 workspace tests pass (1 ignored as documented above).
- SpliceHeader fixed layout extended to 357 bytes; corresponding
  signing digest, fixture helpers, devnet builder, and store JSON
  format updated.
- Four new C-01 negative tests added at the splice bundle layer.
- Fifth C-01 test documented with `#[ignore]` and an explanatory
  comment for the payload_commitment / vault commitment overload.

## Deployment readiness statement

The bilateral profile, after these patches, is a defensible security
construction on the existing devnet evidence. Production deployment
requires the items in the priority remediation order to be closed
under measured mainnet data: FUND-time resource bound, bounded
sponsor policy for non-publication operations, full mainnet-like
challenge-window measurement, supply-chain revalidation in release
CI, external diff review, multi-operator watchtower recovery
evidence, and explicit value-limit policy before any real-assets
deployment.

The factory profile is now explicitly labelled as a design framework
with a nine-item acceptance agenda. Reduced signing sets should not
be treated as safe in broader transition families until every item
in that agenda is satisfied by a concrete deployment profile.