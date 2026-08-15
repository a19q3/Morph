# Swarm Security Audit — GLM — 2026-08-15

> Current-tree note: superseded audit/closeout documents cited as evidence in
> this frozen baseline were removed from the active docs tree after remediation.
> They remain recoverable from audited commit `9ab9ec1`; line references below
> intentionally describe that historical baseline rather than current HEAD.

A self-contained, evidence-driven **protocol audit** of the Morph Channel
repository, performed by a swarm of eight independent agents (A–H) covering:
the shared wire-format library (`morph-script-common`), the state cell
boundary (`morph-state-type`/`morph-state-lock`), the vault boundary
(`morph-vault-lock`), the dynamic N-party factory
(`morph-factory-type`/`morph-factory-vault-lock`), the sponsor lock and devnet
xUDT issuer, host-side semantics (`morph-core` validation/hashing/invoices),
and cross-layer consistency (fixtures, schema draft, parity tests).

Read-only audit: no source modified, no commits made. Repository revision
reviewed: `9ab9ec122e5174cc59fa1fd1b5350a49bc64e855` (HEAD of
`codex/improve-morph-hub-ux`). This audit supersedes-in-scope
`docs/swarm-audit-glm-2026-08-13.md` (baseline `92879b9`); the delta since
that baseline includes the dynamic N-party factory rewrite
(`9c5b727`), the Factory v1 pre-production boundary hardening (`5d2f19a`),
and compatibility-layer removal (`6297b4e`).

## 0. Executive Summary

| Severity | Count | IDs |
| --- | --- | --- |
| High | 1 | AUD-01 |
| Medium | 4 | AUD-02, AUD-03, AUD-04, AUD-05 |
| Low | 17 | AUD-06 … AUD-22 |
| Info | 22 | not renumbered; see §3 per-agent index |

**Verdict:** no fund-loss path was found in the core bilateral state/vault
boundary; signature schemes, commitment-before-parse envelope dispatch,
N-of-N membership binding, sparse-Merkle depth-256 proofs, conservation
arithmetic (all `checked_*`), and domain separation were verified clean
across all eight scopes. The single High finding is a **missing on-chain
commitment of the splice-out withdrawal destination** (bilateral and
factory): signatures cover the withdrawal *amount* but not *where it is
paid*, so whoever assembles the broadcast transaction can redirect the
payout. The four Medium findings are a delegated-authority gap in
factory-materialised state creation, a settlement descriptor/vault-typedness
mismatch, and two host-vs-script validation divergences introduced by the
reduced factory-splice path.

Wire-format warning: fixing AUD-01 requires adding a field to
`SpliceHeader`/`FactorySpliceHeader`, which per `AGENTS.md` is a
boundary-version break (fixtures, parsers, contract tests, devnet smoke all
depend on the 453/437-byte layouts).

## 1. High

### AUD-01 (was C-01 + D-01) — Splice-out withdrawal destination is signed nowhere; the tx assembler can redirect the payout

- **Severity:** High
- **Files:**
  `contracts/morph-script-common/src/lib.rs:729-811` (SpliceHeader layout,
  453 B), `:2491-2517` (FactorySpliceHeader layout, 437 B),
  `contracts/morph-vault-lock/src/main.rs:377-406` (splice path),
  `contracts/morph-factory-vault-lock/src/main.rs:334-379`,
  `contracts/morph-factory-type/src/main.rs:171-191`
- **Evidence:** `SpliceHeader` commits the withdrawal only through
  `asset_delta_commitment` (offset 229) — amounts, not destinations:
  ```rust
  pub fn asset_delta_commitment(&self) -> &'a [u8] { field(self.raw, 229, BYTE32_LEN) }
  ...
  pub fn signing_digest(&self) -> [u8; 32] {
      blake2b256(&[SPLICE_HEADER_DOMAIN, self.raw])
  }
  ```
  The vault lock's splice path verifies old vault inputs and the single new
  vault output and never inspects the withdrawal output
  (`morph-vault-lock/src/main.rs:398-405`). `morph-state-type`'s
  `validate_splice_create`/`validate_splice_retire` likewise never check it.
  The same holds for `FactorySpliceHeader` (no destination field) and both
  factory scripts. The existing positive test *demonstrates* the gap: it pays
  the withdrawal to an arbitrary always-success lock
  (`crates/morph-core/tests/contract_scripts.rs:7941`, accepted at `:8054`).
  Factory reduced splice (kind 7) is the sharpest exposure: it authorises on
  **exactly one** touched-participant signature
  (`lib.rs:3025`, `:3035-3036`), and the payout lock is constructed only
  client-side (`crates/morph-cli/src/devnet.rs:3492-3495`).
- **Scenario:** a coordinator (or counterparty, or anyone who obtains the
  signed splice package — the normal protocol artefact) rebuilds the
  transaction paying `delta.withdrawal` capacity to their own lock. Every
  on-chain check passes; the participant's reserve claim is consumed while
  the payout is diverted. There is no on-chain recourse for the co-signer.
- **Documented-scope adjudication:** `docs/m5-closeout.md:19` claims
  "participant-owned splice-out withdrawals" as delivered and defers only
  "arbitrary payout locks". The delivered enforcement is **evidence-only**
  (package/apply JSON artifacts expose `withdrawal_payout_policy`,
  `m5-closeout.md:45-51`); nothing binds the destination on-chain. The
  reduced-exit path proves the codebase knows how to do this correctly — it
  commits the child `vault_lock_hash` inside the signed digest
  (`lib.rs:2035-2041`, `:2162-2174`).
- **Fix:** add a per-delta (or single) withdrawal payout lock-hash
  commitment to `SpliceHeader` and `FactorySpliceHeader`, covered by the
  signing digest, and verify the matching tx output in `morph-vault-lock`
  and `morph-factory-vault-lock`. This is a wire-format break — bump
  layout, regenerate fixtures, extend `hash_parity.rs`, and add negative
  tests (destination substitution on both bilateral and factory reduced
  paths).
- **Confidence:** high (layout exhaustion-verified by two independent
  agents; positive test confirms arbitrary destination acceptance).

## 2. Medium

### AUD-02 (was B-01) — Factory-materialised StateType creation delegates all factory authority to the args-committed hash

- **Files:** `contracts/morph-state-type/src/main.rs:439-499`
- **Evidence:** the `STATE_MODE_FACTORY_PROOF` create path parses
  `FactoryLocalExitWitness` and checks the args-committed FactoryType hash
  against input 0's type script (`:484-489`) but performs **no signature
  verification** inside StateType; `factory_signature()` is only parsed
  (`lib.rs:2346`), leaving enforcement to whatever script lives at the
  committed hash.
- **Scenario:** a tx creator places an always-success (or self-authored)
  script at input 0 and its hash in the 72-byte args — StateType then
  accepts a fully attacker-controlled "factory-backed" child state.
  Containment (why Medium): `validate_anchor_derivation` binds the anchor to
  input 0's outpoint (`main.rs:205-230`) so the fake child gets a fresh
  channel identity, and the vault lock pins both the state-type code hash
  and its own committed anchor — no **existing** vault is reachable.
- **Fix:** negative test with a permissive FactoryType hash at child
  creation; either verify the envelope's factory signature in StateType or
  document explicitly that factory authority is enforced solely at the
  factory/factory-vault boundary.
- **Confidence:** high (code fact), medium (containment completeness).

### AUD-03 (was C-02) — CKB-only settlement accepts a typed (xUDT) vault input; token destination unbound

- **Files:** `contracts/morph-vault-lock/src/main.rs:104-116` vs `:602-609`
- **Evidence:** the plain-CKB settlement branch checks only capacity
  conservation; there is no `ensure_no_group_xudt` on the group input and no
  tie between `descriptor_version == 1` and an untyped vault, while the
  splice branch does enforce the asymmetry (`main.rs:608`).
- **Scenario:** a state header signed with `descriptor_version = 1` whose
  `vault_materialisation_root` commits a typed vault finalises CKB per the
  descriptor while the xUDT balance can be routed to any typed output
  elsewhere in the tx. Requires a signed mixed-version state (no host path
  produces one today), hence Medium.
- **Fix:** mirror `ensure_no_group_xudt(Source::GroupInput)` into the
  v1-descriptor branch (or require zero-amount v2 entries for typed roots);
  add a negative test.
- **Confidence:** medium.

### AUD-04 (was E-01) — Host `validate_splice_transition` omits the next-state phase check the script enforces

- **Files:** `crates/morph-core/src/validation.rs:277`, `:379-404` vs
  `contracts/morph-script-common/src/lib.rs:995`
- **Evidence:** host checks only `current.phase != Phase::Active`;
  `state_context_matches_splice_next` compares every preserved field except
  `phase`. The script requires both old **and** new phase `ACTIVE`.
- **Impact:** host-only consumers (e.g. `bridge::derive_edge` evidence
  filtering) can accept a signed splice whose successor phase is
  `Funding`/`Settling`/`Closed`; publication is still rejected on-chain.
  Host/script acceptance divergence, liveness/consistency, not forgery.
- **Fix:** add `splice.next_state.header.phase != Phase::Active` rejection.
- **Confidence:** high.

### AUD-05 (was E-02) — Reduced factory-splice host validation omits vault outpoint binding rules

- **Files:** `crates/morph-core/src/validation.rs:714-799` vs `:613-617`
  (full path) and `contracts/morph-script-common/src/lib.rs:2992-2995`
- **Evidence:** the full factory path rejects an unbound
  `old_vault_outpoint_commitment` or a pre-bound
  `new_vault_outpoint_commitment` (`VaultOutPointBindingInvalid`); the
  reduced path has no equivalent, while the script enforces
  `old_header.vault_is_bound() && !new_header.vault_is_bound()` for both
  variants.
- **Impact:** same class as AUD-04 — host accepts objects the chain
  rejects; broken activation lifecycle in host tooling.
- **Fix:** replicate the binding check in `validate_factory_reduced_splice_transition`.
- **Confidence:** high.

## 3. Low and Info (per-agent index, adjudicated)

| ID | Sev | Summary | Where |
| --- | --- | --- | --- |
| A-01 | Low | `vault_cell_commitment`/`vault_outpoint_commitment`/`funding_context_id` hash inputs without 32-byte length assertions (concatenation-aliasing hardening; no live caller passes variable lengths) | `morph-script-common/src/lib.rs:3743-3800` |
| A-02 | Low | Lib reduced-update verifiers skip `old_header.validate_profile()` + update-number monotonicity (callers compensate; enforce in lib for defense-in-depth) | `lib.rs:2196-2225` vs `:2943-2951` |
| B-02 | Low | `MAX_WITNESS_INPUTS_PER_TX = 64` caps some scans but not `find_unique_state_cell`; >64-input txs fail closed (liveness DoS only) | `morph-state-type/src/main.rs:32,530,573,613,645` |
| C-04 | Low | Splice-witness ambiguity scan capped at 64 witnesses; duplicate-witness rejection incomplete but selected witness still fully verified | `morph-vault-lock/src/main.rs:413-415` |
| C-05 | Low | Non-canonical `min_since` in vault args only detected at settlement (splice still usable; liveness) | `morph-vault-lock/src/main.rs:57,93-95` |
| D-02 | Low | Vault-lock reduced/local exit compare witness participants only against the **new** header; old↔new equality rests entirely on the co-executing factory-type script (composition-safe today) | `morph-factory-vault-lock/src/main.rs:88,102`; `lib.rs:2204` |
| E-03 | Low | `non_interference_digest`/access-manifest roots signed but never re-derived host-side (script enforces; DoS-only divergence) | `validation.rs:605-632` vs `lib.rs:2541-2543` |
| E-04 | Low | `cancel_payment` skips the intent-expiry bound that `commit_payment` enforces | `backend.rs:356-364` |
| E-05 | Low | `SovereignEdgeRegistry::refresh` uses a factory reservation without re-validating its window (unlike `activate`) | `bridge.rs:434-456` |
| E-06 | Low | `hash_parity.rs` misses `funding_context_id`/`vault_outpoint_commitment` outputs and sparse-Merkle primitives; CLI mixes the two crates' implementations in one binary | `tests/hash_parity.rs:17-47` |
| F-01 | Low | High-S ECDSA malleability unenforced in invoice/state/splice/script verifiers while agent paths reject it (`normalize_s`); no bypass, but enforce uniformly | `node.rs:342-358`; `validation.rs:245-931`; `lib.rs:895-1595` |
| F-02 | Low | Invoice expiry bounded only by the Hub (`MAX_INVOICE_EXPIRY_SECS`); core `validate` and CLI `new-invoice` accept arbitrary lifetimes | `node.rs:308-310`; `main.rs:3928-3931` |
| G-01 | Low | Sponsor `already_spent` never advances on-chain (self-referential `change_lock` policies reset it; shipped cells always write 0) — total-budget field is host-tracked only, consistent with SECURITY-FIXES' per-cell claims | `morph-sponsor-lock/src/main.rs:44,165-178` |
| G-02 | Low | Sponsor backing StateCell input matched by type + anchor but not `channel_id` (needs anchor collision to exploit) | `morph-sponsor-lock/src/main.rs:123-134` |
| H-01 | Low | Fixture builders hand-roll wire layouts with hardcoded literals (three builders lack build-then-parse round-trips) | `packages.rs:1555,2085,2109,2421` |
| H-02 | Low | Same as E-06 (two agents independently found the parity-test gap) — includes cross-impl usage in watchtower splice detection | `hash_parity.rs`; `devnet.rs:7581` |
| H-05 | Low | Only 3 proptest cases exist (StateHeader-only); splice conservation/canonicality/envelope parsing unfuzzed | `tests/invariants.rs:721-796` |
| A-03/E-10 | Info | High-S malleability detail (see F-01) | — |
| A-04 | Info | `PARTICIPANTS_DOMAIN` shared by bilateral and factory participant encodings (identical message shape; no cross-forge since signing domains differ) | `lib.rs:3803` vs `:1565-1578` |
| A-05 | Info | `as u8` truncating casts on host-side count fields (bounded 2..=16 on-chain) | `lib.rs:3803,3838` |
| A-06 | Info | `field()` panics fail-closed (abort) rather than erroring; wrap unreachable given bounded offsets | `lib.rs:3709-3711` |
| B-03 | Info | Funding-anchor derivation hashes the full `CellInput` including mutable `since` | `morph-state-type/src/main.rs:210-212` |
| B-04/C-gap/D-gap/G-gap | Info | Negative-test gaps: args-length rejections, bilateral↔factory witness cross-use, supersede anchor rebinding, `WrongGroupShape`, N boundary (N=1/N=17/threshold≠count), unsorted/duplicate participants, cross-kind envelope confusion, sponsor `StateCellAmbiguous`/anchor-mismatch/boundary range, xUDT unauthorised mint/malformed data | `tests/contract_scripts.rs` (see per-agent reports) |
| C-03/G-05 | Info | Shared error codes across distinct failure paths (observability only; all codes non-zero and distinct per variant) | `morph-vault-lock/src/main.rs:319-321` |
| D-03 | Info | One reduced-rights proof may decrease multiple rights of the touched participant in one shot (signer consents; broader than a strict one-right reading) | `lib.rs:1768-1789` |
| D-04 | Info | Two incompatible `state_root` encodings (10-right list hash vs 256-deep sparse root), domain-separated; >10 rights fails closed on kind-2 | `lib.rs:1664-1680` vs `:1866-1882` |
| D-05 | Info | Vault spend of factory A cannot coexist with factory B's state cell in one tx (fail-closed DoS by design) | `morph-factory-vault-lock/src/main.rs:206-236` |
| E-07 | Info | `ProviderEdgeDescriptor::derive_id` omits four freshness fields (intentional; no standalone `validate()` for deserialized descriptors) | `bridge.rs:282-301` |
| E-08 | Info | `FACTORY_RIGHT_EMPTY_DOMAIN` host-only; safe while scripts verify against committed roots only | `validation.rs:21` |
| E-09 | Info | `funding_context_id` omits `funding_epoch` (uniqueness rests on the outpoint commitment) | `hash.rs:65-80` |
| F-03 | Info | `insert_stored` (state restore) skips network/payee binding applied on the live receive path | `node.rs:440-450` |
| F-04 | Info | Non-constant-time compare on two server-side values (hygiene) | `morph-agent/src/service.rs:1079` |
| F-05 | Info | Fiber invoice "signature" presence-checked, never verified (trust anchor is the local Fiber RPC + payment-hash binding) | `service.rs:1334-1338` |
| G-03 | Info | Zero-fee sponsor spend returns all capacity to `change_lock` (sponsorship-cancellation griefing; no theft; documented boundary) | `morph-sponsor-lock/src/main.rs:52-58` |
| G-04 | Info | xUDT mint bound to tx input index 0 and args-named lock; devnet-only status is documentation-only, no in-script guard | `morph-devnet-xudt/src/main.rs:43-49` |
| H-03 | Info | Stale test name in SECURITY-FIXES.md (`..._dep` → actual `..._dep_position`) | `SECURITY-FIXES.md:183` |
| H-04 | Info | Draft `schemas/morph.mol` hardcodes 2 participants for reduced exit and omits the seven envelope-carried witness structs | `schemas/morph.mol:206-258` |
| H-06 | Info | Non-interference digest duplicated host-side without a parity test (on-chain rejection catches drift) | `factory_packages.rs:3045-3071` |

## 4. Verified-Clean Highlights (cross-agent)

- **Envelope dispatch:** commitment (`blake2b256(WITNESS_ENVELOPE_BODY_DOMAIN ‖ kind ‖ body)`) is verified before any body parse; magic/format/flags/kind/length whitelisted; kinds 1–7 only; negative tests present (`lib.rs:478-533, 6612-6726`).
- **Fixed layouts exact:** StateHeader 346 / FactoryStateHeader 302 / SpliceHeader 453 / FactorySpliceHeader 437 / SponsorPolicy 136 / envelope 50+body — all parsers use exact-length equality, canonical ordering, zeroed unused slots; no trailing-byte acceptance.
- **Domain separation:** all 25 script domains + 10 host domains distinct, none a prefix of another; host/script equality tested; every hash domain-prefixed.
- **Arithmetic:** zero wrapping ops in production targets; all sums/differences `checked_*` (vault, factory deltas, sponsor budget, xUDT u128, splice conservation).
- **Signature authority:** bilateral 2-of-2 and factory N-of-N (2..=16, threshold==count) over CKB-personalized blake2b digests covering full headers (all 18/20/18 fields property-tested); pubkeys pinned by `participants_commitment` equality; participant set immutable across every update kind (`same_context_except_progress`); reduced paths authorise exactly one touched participant with non-touched rights frozen.
- **Sparse Merkle:** exactly 256 siblings by construction; participant identity is the tree key; node hashes depth-bound; old and new roots both re-verified against headers.
- **Authentic StateCell:** vault finalisation requires the unique input cell whose own data parses, matching anchor + StateType code/hash_type + StateLock identity + lock-args==type-hash; duplicates/missing rejected.
- **Replay protection:** all three signing digests include channel/factory ids, state/update numbers, epochs, and vault outpoint commitments — cross-channel replay is structurally impossible.
- **Sponsor fee attribution:** `sponsor_fee == Σinputs − Σoutputs` with clean-change enforcement; third-party capacity diversion negative-tested; `already_spent` comes from the executing lock's own args (group semantics prevent lookalike forgery).
- **xUDT:** exact input==output conservation, strict 16-byte LE data, u128 overflow negative test.
- **Invoices:** Bech32m constant/HRP/mixed-case/padding all correct; payee signature covers all fields incl. `payee_node_id` + `payment_hash`; preimage nonzero + hash-checked; OsRng for all secrets; hub token compares constant-time on hashed values.
- **Docs-vs-tests:** 47/48 SECURITY-FIXES-named negative tests exist verbatim (one renamed, H-03); contract tests genuinely run in CI via `make contract-tests`.

## 5. Recommended Remediation Order

1. **AUD-01** — wire-format change; plan the layout bump alongside the next
   scheduled boundary-version break (fixtures, hash-parity, smoke, negative
   tests for destination substitution). Interim hardening: watchtower /
   apply-tooling already records payout evidence — add a *mandatory*
   destination re-verification + alert on the apply path and document the
   residual trust model.
2. **AUD-02..AUD-05** — small, local fixes (one guard each + negative
   tests); no wire impact.
3. **F-01/A-03/E-10** — uniform low-S enforcement (host + script) while a
   consensus-relevant change window is open anyway.
4. **E-06/H-02, H-01, H-05** — parity-test and fixture-builder hygiene plus
   proptest expansion for splice conservation/canonicality and envelope
   parsing.
5. Test-gap backfill (N boundaries, cross-kind confusion, sponsor/xUDT
   negatives) per §3 Info rows.

Methodology note: each finding above was independently evidence-checked by
the originating agent with file:line quotes; the High and all four Medium
findings were re-verified against source by the coordinating reviewer
(SpliceHeader/FactorySpliceHeader field exhaustion, validation.rs guards,
m5-closeout scope claims). Per-agent full reports (including per-invariant
verified-clean evidence) are preserved in this document's sections.
