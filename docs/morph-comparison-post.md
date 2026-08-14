# Morph Channel vs. Lightning/eltoo, Perun, and the CKB Generic Payment Channel — A Comparative Reading

> Note: this post is comparative positioning — how Morph relates to the
> construction families that already exist for CKB and for Bitcoin. The current
> implementation-security verdict is in
> `docs/base-model-audit-2026-07-23.md`.
>
> Import audit note, 2026-06-30: this is a comparative positioning draft,
> not current release evidence. Exact test and devnet counts below are
> historical snapshot evidence unless a fresh clean-HEAD artifact says
> otherwise. The current implementation names the bilateral materialisation
> field `vault_materialisation_root` / `new_vault_materialisation_root`.

I read four reference materials end-to-end before writing this:

1. **Lightning / eltoo** — the "eltoo" paper by Decker, Russell,
   Osuntokun (`eltoo.pdf`), and `Ademan/multi-party-eltoo-with-bounded-settlement`
   — a Rust implementation of Ademan's multi-party eltoo variant.
2. **Perun** — the original paper by Dziembowski, Eckey, Faust, Malinowski
   (IEEE S&P 2019, DOI 10.1109/SP.2019.00020), and the CKB port:
   `perun-network/perun-ckb-contract` (Rust on CKB) and
   `perun-network/perun-ckb-backend` (Go on top of `go-perun`).
3. **The CKB Generic Payment Channel** (GPC) — `janx`'s talk on Nervos
   Talk, 2020-05-18: *"A Generic Payment Channel Construction and Its
   Composability"*. This is the CKB-native baseline that any new CKB
   channel construction has to position against.
4. **Morph Channel** — my own construction. The implementation and
   current docs are in this repo; the research paper draft is external
   and the current implementation-security verdict is recorded in
   `docs/base-model-audit-2026-07-23.md`.

The reference materials I pulled into the workspace are at
`~/Documents/morph-comparison/`. I was unable to download the Perun
PDF directly (the IACR ePrint mirror is behind Cloudflare and IEEE
returns 418); the DOI is `10.1109/SP.2019.00020`. I worked from the
IACR abstract, the Go backend code, and the CKB contract code. If you
have a direct Perun PDF and want me to revise specific numbers below,
say the word.

The structure of this post is:

1. A one-page summary table.
2. Each construction, with the part of Morph that overlaps it and the
   part that does not.
3. A "what would it take to deploy each on CKB today" reading.
4. A "what Morph borrows from each, and what it adds" reading.

---

## 1. The summary

| Axis                              | eltoo (Lightning)               | Perun                                 | GPC (CKB talk)                          | Morph Channel                         |
| --------------------------------- | ------------------------------- | ------------------------------------- | --------------------------------------- | ------------------------------------- |
| Update rule                       | Replace-by-version              | Replace-by-version + signing set     | Replace-by-version                     | Replace-by-version                    |
| Dispute rule                      | Newer state wins (sig on no-input hash) | Newer state wins with watchtowers and challenge period | Newer state wins (timeout-after-state) | Newer state wins (challenge window + relative `since`) |
| Required Bitcoin opcode            | `SIGHASH_ANYPREVOUT` (NOINPUT/ANYONECANPAY) | None (Turing-complete smart contract) | None (UTXO + scripts)                  | None (UTXO + scripts)                  |
| Script footprint                  | One sighash flag change         | Smart contracts; CKB port in Rust       | One lock script (GPC lock)              | Type + lock + sponsor lock + envelope |
| Funding anchor                    | The funding outpoint            | Contract reference                     | Funding outpoint                         | Type-ID-style derivation OR live Fund Cell |
| Multi-asset                       | Single asset                    | Multi-asset (EVM tokens)              | Native (any UDT/SUDT/CKB)                | Native (CKB + any xUDT)                |
| Sponsor / fee model                | Channel pays fees                | Channel pays fees                      | Channel pays fees                        | Sponsor partition (channel never pays fees) |
| Splice / resize                    | Not in paper                     | Re-fund / new channel                   | Not in paper                              | SPLICE branch in script-level validation |
| Channel factory                   | Not in paper                     | Layered virtual channels               | Not in paper                              | Yes (factory profile, design framework) |
| Reduced signing set               | Not in paper                     | Not in paper                            | Not in paper                              | Yes (factory, design framework)        |
| Composability with L1 assets      | Low (Bitcoin only)               | Medium (token interface)               | High (any UDT/CKB)                       | High (any xUDT/CKB)                    |
| Has a deployed Bitcoin/CKB impl?  | No (SIGHASH_ANYPREVOUT not deployed) | Yes (Ethereum, CKB via perun-ckb-contract) | Talk only — no impl                      | Yes, for devnet/research evidence; exact counts are snapshot-specific |
| Maturity for bilateral profile     | Academic                         | Production (Ethereum); experimental (CKB) | Spec only                                | Devnet-evidenced                        |

The next four sections explain why each row looks the way it does.

---

## 2. Lightning / eltoo

`eltoo.pdf` (Decker, Russell, Osuntokun) is a *replace-by-version* scheme
for Bitcoin. Every state update produces a new "update transaction"
that consumes the current update and creates the next one. The dispute
rule is "the update with the highest version number wins, provided it
was confirmed". The catch is the `SIGHASH_NOINPUT` (later renamed
`SIGHASH_ANYPREVOUT`) sighash flag, which lets a signature commit to
outputs without committing to the input outpoint. Without that flag,
an attacker can malleate the previous txid, breaking the
parent-pointer that the replace-by-version rule relies on.

`Ademan/multi-party-eltoo-with-bounded-settlement` is a 1,901-line Rust
implementation of *Ademan's variant*, a multi-party extension with
bounded-settlement semantics. It is not a Lightning implementation; it
is a state-update bench. The README explicitly states:

> The asymptotic performance of the scheme is exponential so either way
> we'll hit a hard limit pretty quickly, on my computer that seems to be
> between 10 and 16 channel parties, closer to 10.

There is no production eltoo Lightning implementation, because
`SIGHASH_ANYPREVOUT` is not deployed on Bitcoin. Lightning uses the
older Poon-Dryja penalty construction, which has the well-known
toxic-waste problem. eltoo is, in practice, a research artefact today.

### Where Morph overlaps eltoo

The state-update and dispute rule are the same family:
*replace-by-version, newer state wins*. Morph's `phase = settling`
plus strictly monotonic `state_number` (defined in the external paper draft)
is the same rule that eltoo enforces via update transactions with
strictly increasing version numbers. Both schemes require the dispute
window to be sufficient for confirmation, and both schemes make the
challenge window a deployment parameter.

### Where Morph does not overlap

eltoo requires `SIGHASH_ANYPREVOUT`. Morph requires nothing — the CKB
transaction hash covers inputs and outputs, so the parent-pointer is
stable by construction. The state uniqueness comes from CKB's
single-spend rule plus Morph's "exactly one input, exactly one output"
type script rule (`verify_state_cell_type` in the external paper draft).

eltoo has no splice and no factory. Morph has both — and the splice is
the only construction in this comparison that script-level checks a
signed splice event against the current state, the successor's preserved
context, and the splice-specific vault roots
(`SpliceHeader::matches_current_state` plus
`state_context_matches_splice_next`). eltoo's update transactions are signed
by `SIGHASH_ANYPREVOUT`
over their inputs, so the eltoo update already commits to its own
"next state's full content" — but only at the transaction-graph level,
not at the script level. Morph's splice content binding is enforced
inside CKB-VM and is testable by the unit tests in
`contracts/morph-script-common/src/lib.rs`.

eltoo has no sponsor partition. Morph does. This is a CKB-friendly
extension: sponsor funds sit in a separate Cell that pays the
publication carrier without touching channel value. eltoo's analogue
would be a separate fee-bumping wallet that publishes the update, which
is operationally possible but not protocol-blessed.

### Where eltoo is better than Morph

eltoo's update-and-update transactions are simpler to reason about
than Morph's `verify_splice_state_transition_bundle` (state + vault +
signature + splice-event, plus the audit-style `SpliceHeader::matches_current_state`
check added after the audit). If you have `SIGHASH_ANYPREVOUT`, eltoo
is one elegant construction; on CKB Morph has to express the same
guarantees in script logic.

---

## 3. Perun

The Perun paper (Dziembowski et al., IEEE S&P 2019; DOI
10.1109/SP.2019.00020) introduces *virtual channels*: a three-party
construct where Alice and Bob open a virtual channel on top of two
ledger channels they already have with Carol, without involving Carol
per-payment. Carol collateralises but does not interact. The
construction is general (any Turing-complete chain) and was
implemented on Ethereum first.

`perun-network/perun-ckb-contract` and `perun-network/perun-ckb-backend`
are the CKB port. The contract repo provides:
`perun-channel-lockscript`, `perun-channel-typescript`,
`perun-funds-lockscript`, plus the virtual-channel pair
`perun-vchannel-lockscript` and `perun-vchannel-typescript`. The backend
is a Go server on top of `go-perun`. Perun on CKB uses Ethereum-style
binary encoding for state, so the same off-chain signed messages are
valid on Ethereum and on CKB. That is its strongest claim.

### Where Morph overlaps Perun

Both use the newer-state-wins rule. Both have a state-evidence object
(`StatePackage` in Morph, signed update in Perun). Both have a
challenge window. Both can do multi-asset on CKB (Perun via SUDT, Morph
via xUDT).

Both separate the funding object from the state evidence object.
Perun's contract locks the channel funds behind a Perun-specific
lock; Morph's `vault_set_commitment` lives in the State Header and
the vault lock checks it. Both have a notion of "current live state".

### Where Morph does not overlap

Perun has *virtual channels*. Morph has *factories*. The two are
different:

- Perun's virtual channel is a three-party construct that builds on
  top of two existing ledger channels. The intermediary (Carol)
  collateralises the virtual channel and does not interact per payment.
- Morph's factory is a single state object with multiple child channels
  plus optional reduced signing per factory root. The factory is
  itself a single channel with a more complex authorisation model.

Morph does not have a virtual-channel construction. A future Morph
extension could add one, but the audit-response paper makes clear that
the factory profile is a design framework, not yet a complete
construction; layering virtual channels on top of Morph would inherit
this open question.

Perun's encoding is Ethereum-first. Morph's encoding is CKB-native
(fixed-layout parsers, Molecule schema in `schemas/morph.mol`). They
are not wire-compatible. A Morph → Perun bridge would require a
translator at the L2 boundary.

### Where Perun is better than Morph

Perun has a deployed multi-chain story. The `go-perun` backend
implements the same wire format on Ethereum and on CKB, with
cross-chain Perun channels as a documented feature. Morph has only
the bilateral CKB profile; cross-chain Morph would need to be built
from scratch. Perun also has an academic formal security proof; Morph
has the audit-driven definitional hardening and devnet evidence, but
not a formal proof.

Perun's watchtower design is cleaner. Perun's watchtowers operate
inside the channel's adjudication phase and the protocol supports
delegation; Morph's watchtower can force-settle but cannot redirect,
and the external paper draft explicitly notes that delegation is
out of scope for the current profile.

---

## 4. The CKB Generic Payment Channel (GPC)

The GPC construction (Nervos Talk, 2020-05-18) is the first published
CKB-native payment channel construction I know of. It is "basically
an eltoo port on CKB", as the author writes, but with one critical
difference: GPC does not need a SIGHASH_NOINPUT analogue, because CKB
transaction hashing already separates inputs from outputs cleanly
enough that the closing transactions can be signed over a "no-input
hash" using a different witness encoding.

The construction is:

- A **GPC lock** script on the funding output. Lock args carry
  `(state, timeout, pubkey_a, pubkey_b, nonce)`. State is `OPEN` or
  `CLOSING`.
- Three transaction kinds: funding, closing, settlement.
- Closing transactions are signed using a no-input hash (inputs are
  not committed to the signature). This is what lets a single signed
  closing transaction be attached to the funding output *or* to
  another closing output with a higher nonce.
- The "ugly" case — Bob publishes an obsolete closing transaction —
  is handled by Alice publishing a higher-nonce closing transaction
  in response, which consumes the obsolete closing output. Because the
  closing output has a higher nonce than the input, the obsolete one
  cannot respond.

This is a clean construction and the CKB-native idea of using
no-input hashing via witness encoding is genuinely elegant.

### Where Morph overlaps GPC

Both are CKB-native. Both use replace-by-version. Both separate the
funding object from the state evidence object. Both have a challenge
window (relative `since`). Both can ride any UDT/SUDT/xUDT on CKB.

GPC puts the channel state in the *lock args* of a single funding Cell.
Morph puts the channel state in a separate State Cell whose data is
the canonical State Header, and uses the vault lock to authorise
value-bearing operations. This is a different decomposition. GPC's
single-Cell model is simpler on a small channel; Morph's split model
makes sponsor fees, splice, and factory possible without disturbing
the funding Cell.

### Where Morph does not overlap

GPC has no splice. GPC has no factory. GPC has no sponsor partition.
GPC has no script-level binding of the "complete successor State
Header" — GPC relies on the lock args being signed by both parties
together with the witness, and on the no-input hash discipline. The
no-input hash is a witness-encoding trick; Morph's content-binding is
a script-level predicate (`SpliceHeader::matches_current_state`).

GPC's "ugly" case has a known worst-case latency of `O(i × T)` blocks
where `i` is the number of obsolete states Bob can submit. Morph's
challenge window is a single `Δ`, and superseded states cannot keep
the dispute open in this way — the State Cell uniqueness rule
(`exactly one input, exactly one output`) plus CKB's single-spend rule
mean the dispute closes once one supersession transaction confirms.
GPC's worst case is genuinely worse than Morph's, though GPC's argument
is that the attacker pays an `O(i)` cost, so the attack is
uneconomical.

GPC's lock-args state model is harder to upgrade. Once a GPC channel
exists, its lock args carry the channel parameters; you cannot add
new fields to the lock args without a new deployment. Morph's State
Header is a separate Cell; its canonical encoding can evolve across
deployments because the State Cell type script can gate on
`state_layout_version`. The Morph paper declares
`state_layout_version` as a deployment-versioned field.

### Where GPC is better than Morph

GPC is *smaller*. The entire construction fits in one lock script,
three transaction shapes, and one state machine. Morph has a State
Cell type script, a vault lock, a sponsor lock, a witness envelope,
a factory type, a factory vault lock, an operation envelope, a
canonical operation envelope, a vault manifest, and a partition
classifier (after the audit). GPC is the kind of construction you can
hand to one engineer and expect a working bilateral implementation in
a week. Morph is the kind of construction that needs the audit
process we just went through.

GPC is *elegant on no-input hashing*. The CKB-native trick of
committing to outputs only is the kind of design choice that does
not depend on `SIGHASH_ANYPREVOUT` and works today. Morph's signing
domain is bigger but follows the same idea.

---

## 5. What would it take to deploy each on CKB today?

| Construction  | On CKB today (June 2026)                                                              |
| ------------- | -------------------------------------------------------------------------------------- |
| Lightning (Poon-Dryja penalty) | Yes, but no first-class CKB implementation; the closest is the Fibre prototype. Penalty construction is awkward on UTXO because you have to encode the revocation keys in the witness and on-chain encoding. |
| eltoo         | No — requires `SIGHASH_ANYPREVOUT`, which CKB does not have and which Morph does not need. The Ademan reference implementation is a Rust bench, not a wire-level implementation. |
| Perun         | Yes — `perun-ckb-contract` deploys on CKB. The backend is Go, the contracts are Rust. Cross-chain story is the main selling point. |
| GPC           | Talk only — no implementation in the public NervosTalk post. The post describes the construction precisely; an implementation would be one lock script and a few hundred lines of off-chain code. |
| Morph Channel | Yes, for devnet/research use. The June audit response cites historical snapshot evidence: 248 active workspace tests, 155 smoke JSONs, 192 committed transactions, and 7 deployed scripts with verified hashes. Treat those as snapshot counts, not current release gates; rerun the current acceptance targets before citing them as fresh evidence. Bilateral profile is now defensible after the June 2026 audit patches. Factory profile is a design framework + acceptance agenda. |

The "what would it take" reading is:

- If you want a deployed channel on CKB **today**, Perun is the only
  fully wired option.
- If you want a smaller, more auditable bilateral channel on CKB, the
  GPC construction is the right place to start, and it would
  probably take one engineer a week.
- If you want a CKB-native channel with sponsor partitioning, splice,
  and a route to factories, Morph is the option. It costs you a
  larger script surface, a definitional pass per audit, and explicit
  resource-bound checks at FUND.
- If you want eltoo on Bitcoin, the answer is "wait for
  `SIGHASH_ANYPREVOUT`" plus "there is no testnet deployment today".

---

## 6. What Morph borrows from each, and what it adds

### Borrowed

- **From eltoo:** the replace-by-version dispute rule and the
  newer-state-wins safety property.
- **From Perun:** the multi-asset accounting model. Both schemes
  treat each xUDT as a separate conservation lane; both have the same
  notion of "challenge window"; both have explicit witness envelopes
  (Perun's encoding is wire-format; Morph's paper-side
  `MorphOperationEnvelope` maps to the implementation's structural
  witness envelope rather than a Perun-compatible wire format).
- **From GPC:** the CKB-native realisation that a channel state
  pointer can be a Cell, not a global registry; the relative-time
  challenge window via CKB's `since` field; the explicit use of
  CKB's single-spend rule as the state-uniqueness mechanism.

### Added

- **Sponsor partition** — channel value never pays publication fees.
  The external paper draft's Proposition 1 ("Zero Channel-Paid Publication
  Fees") is provable from the partition-conservation linear-algebra
  identity now that the partition classifier is fully defined. None
  of the four reference constructions isolate a sponsor partition at
  the protocol level; they rely on a wallet signature or a watchtower
  fee policy.
- **Script-level splice** with content-binding of the successor State
  Header. eltoo's signature covers the next-update outputs at the
  transaction-graph level; Morph's `SpliceHeader::matches_current_state`
  and `state_context_matches_splice_next` checks bind the current
  vault-materialisation root, the successor vault-materialisation root,
  and the preserved context inside CKB-VM. This is closer to Perun's
  strict state-binding than to eltoo's update-transaction model, and it
  is what makes the C-01 attack from the June 2026 audit impossible in
  the current bilateral profile.
- **Type-ID-style profile** that does not require a live Fund Cell.
  The external paper draft formally declares two profiles (Live Fund Cell vs
  Type-ID-style) and the current devnet implements the latter. GPC
  and Perun both have a live funding cell. Morph's Type-ID-style
  profile is one of the more opinionated choices in the comparison.
- **Factory framework** with envelope-first admission and rights
  non-interference as an explicit condition. None of the four
  reference constructions has a factory profile. Perun has
  *layered* virtual channels, but factories (single-channel with
  children + reduced signing) are different. Morph's factory is
  explicitly labelled as a design framework + acceptance agenda; the
  bilateral profile is the deployment-ready part.

### What Morph does not yet have

- **Virtual channels.** Perun has them. Morph's factory could
  eventually host virtual channels, but the acceptance agenda does
  not include them.
- **Cross-chain wire format.** Perun has it (Ethereum + CKB).
  Morph has only the CKB profile.
- **Formal security proof.** Perun has it. Morph has the audit-driven
  definitional hardening and devnet evidence, but not a published
  proof.
- **Deployed production.** Perun-ckb has devnet. Morph has devnet.
  Perun-eth has the more mature deployment story.

---

## 7. What this means for the audit verdict

The June 2026 audit verdict was a "MAJOR REVISION — not deployable as
written" judgement on the external paper draft, with one critical
vulnerability (C-01, splice content-binding) and seven high-severity gaps.
After the paper-draft patches and the implementation hardening in this repo:

- C-01 is closed at the splice bundle layer for `participants_commitment`,
  `settlement_descriptor_commitment`, `mode`, `asset_registry_commitment`,
  `challenge_policy_commitment`, `state_number`, and the equality
  predicates for `protocol_version` / `chain_id` / `signature_scheme_id`
  / `channel_id` / `descriptor_version` / `state_layout_version`.
  The current bilateral profile also binds `vault_materialisation_root`
  and `new_vault_materialisation_root` through the signed `SpliceHeader`
  and repeats the successor materialisation check at the vault lock.
- H-01..H-07 are addressed in the external paper draft with explicit
  Definitions (Funding Anchor Profiles, Vault Manifest, Partition Classifier,
  Morph Operation Envelope, three-distinguished identity names,
  Worst-Case Finalisation Bound, factory_active phase, Factory
  Acceptance Agenda).
- M-01..M-04 are addressed in a new "Deployment Considerations"
  section.
- The implementation has explicit SpliceHeader bindings for current and
  successor vault materialisation roots, C-01 negative tests at the
  splice bundle layer, and CKB-VM coverage in `contract_scripts`.
- The `248 tests pass` wording from the June audit trail is a historical
  active-workspace count. Contract-script CKB-VM tests and devnet
  acceptance evidence should be cited separately from a fresh run.

For positioning against eltoo, Perun, and GPC: the bilateral profile
is now defensible relative to eltoo and GPC on the spec-and-evidence
axis. It is *complementary* to Perun, not competitive — Perun's
virtual channels and cross-chain story are not part of Morph's
bilateral profile, and Morph's sponsor partition and splice are not
part of Perun's profile.

---

## 8. The honest assessment

If I were picking a channel construction to ship on CKB today, I
would pick **Perun** for any deployment that needs cross-chain
interop or virtual channels, and **GPC** as the baseline for any
deployment that wants the smallest possible spec surface and is
willing to hand-engineer sponsor policy and splice off-chain.

I would pick **Morph** for any deployment that has a clear sponsor
budget, expects to splice channels in production, and is willing to
pay for the audit-driven definitional discipline. The factory
profile is the long pole; the bilateral profile is the part that is
defensible today.

Read `docs/base-model-audit-2026-07-23.md` alongside this post for the current
security verdict, verification evidence, and remaining release blockers.

— Mavis, 2026-06-20
