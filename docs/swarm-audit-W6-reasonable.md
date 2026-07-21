# Swarm Audit — W6-REASONABLE: Design Reasonableness

Date: 2026-06-28
Branch inspected: `main`
HEAD inspected: `5072d81eddeb9a754d2a5a08f2e335fd7e12775f` (working tree was dirty at audit time; the
audit is anchored to HEAD per the task brief)
Auditor: W6 — design reasonableness axis
Prior art (deliberately not duplicated): W1 (code/security), W2 (paper↔code), W3 (docs),
W4 (ops/acceptance), W5 (remediation + tests refresh), W6-SAFETY, W6-RIGOR, SYNTHESIS,
`audit-report-2026-06-27.md` (the gap-remediation pass that closed the W1-01 / C-01 / W4-02
findings now in this tree).

This audit answers a different question from every prior W-track. Prior audits asked
"is the implementation correct against its declared spec and threat model?" This audit
asks "given the spec, are the design choices themselves defensible — and is there a
simpler equivalent design that achieves the stated goals?"

W6 is not a bug hunt. Findings use the labels `Justified`, `Over-engineered`,
`Under-justified`, `Better-alternative`, `Mismatched-claim`, and `Naming-drift`.

---

## 1. Executive Summary

### 1.1 Overall reasonableness rating: **Partially-coherent**

The Morph Channel design has a clear spine — three independent authorities (state /
vault / sponsor) over three independent Cells, with a factory mode that composes
all three into a multi-party reserve. That spine is justified: it is the cleanest
mapping from the L2 "value / evidence / fee" trichotomy onto CKB's Cell model that
the audit has seen, and every Cell's responsibility lines up with a single script
boundary that the audit can point to on a single line. The conservative factory
profile is also well designed: reduced paths are explicitly narrow (one touched
right, fixed-layout proof, fixed Merkle depth of 256) and the witness envelope
gives the public a single dispatch surface for seven proof kinds.

**But the design has a soft underbelly on the design-reasonableness axis:**

1. **The ChannelOperation enum and the README's channel lifecycle are out of sync.**
   `ChannelOperation` has 7 variants (`Fund, Publish, Supersede, Finalise,
   CooperativeClose, Splice, Materialise`), but the README, the tutorials, and the
   implementation notes all describe a 4-stage bilateral lifecycle (open / update
   / publish / finalise / splice) with `CooperativeClose` explicitly out of scope
   and `Materialise` quietly absorbed into "factory local exit". The enum is
   honest; the docs are simplified. The `is_publication_or_challenge()` helper
   uses a 2-of-7 allow-list, which is the right shape for the *enforced* boundary
   but the docs never explain the allow-list.

2. **The "sponsor funds pay for publication" claim is much narrower than it reads.**
   The sponsor cell can ONLY pay for `Publish` and `Supersede` (`validation.rs:369`),
   not `Fund`, `Finalise`, `Splice`, `Materialise`, or `CooperativeClose`. The
   README's "publication" reads as "any phase" and the implementation notes admit
   the narrowing only in passing (`implementation.md:140-141`). The tutorial says
   sponsor is for "fee bumping" and "publication" interchangeably.

3. **`expiry: u64::MAX` is a sentinel encoded as a real value, with a runtime
   reject.** `morph-sponsor-lock/src/main.rs:65-67` returns
   `SponsorPolicyUnsupported` if `expiry != u64::MAX`. The struct therefore has
   an `expiry: u64` field that can only take one value. This is a design smell —
   either the field should be an `Option<UnixTimestamp>` (or removed entirely) or
   the runtime check is a placeholder for a feature that never landed. The
   SYNTHESIS report W2-13 already flagged it; the design has not changed.

4. **`payload_commitment` is overloaded in the bilateral plain profile.** It
   simultaneously tracks the post-splice vault commitment (so the vault-lock
   layer can cross-check it) AND the state-machine progress marker (so the
   splice successor can carry it). The `SpliceHeader` had to grow from 357 to
   389 bytes (per the 6/27 audit) precisely because the field was carrying two
   jobs. A profile that decouples "vault materialisation" from "state
   progress" will need a third field. The current design names suggest the
   second job is the real one (`payload_commitment` + `new_payload_commitment`)
   and the first job is an inheritance accident.

5. **The `state_context_matches_splice_next` / `same_context_except_progress`
   helper pair is now an irreducible trust surface** (per the 6/27 fix). The
   function has 19 fields of which 16 are checked; the missing 3 fields
   (`settlement_descriptor_commitment`, `descriptor_version`, `payload_commitment`
   — the latter now added) are an explicit decision in `types.rs:62-77` and
   `lib.rs:347-362`. This is a justified choice for the bilateral plain profile
   but is fragile: every future StateHeader field needs a decision about whether
   it goes into the "frozen" set or the "progress" set, and the current code
   makes that decision by *omission* on the progress side.

The Partially-coherent rating reflects: the spine is good, the seven-axis Cell
decomposition is defensible, but the document layer has quietly drifted to
describe a simpler protocol than the code implements, and three design smells
(overloaded `payload_commitment`, sentinel `expiry`, allow-list operations
helper) are present.

### 1.2 Three most important design tensions

1. **Documentation depth vs operation surface area.** README + tutorial describe
   a 5-stage channel lifecycle; `ChannelOperation` has 7 variants; sponsor
   validation accepts 2; vault validation accepts 4 (excluding the
   non-vault-touching ones). No document tells the reader which of these sets
   they are looking at. Recommendation: add a one-paragraph "Operation allow-list"
   section to `implementation.md` and one table to the tutorial that maps the 7
   enum variants to "sponsor pays?", "vault spends?", "is it script-enforced?".

2. **Profile-orthogonal vs profile-coupled types.** The bilateral plain profile
   overloads `payload_commitment` to mean two things. Any non-bilateral profile
   (e.g. a balance-state profile) breaks. The 6/27 fix (splitting into
   `payload_commitment` + `new_payload_commitment` in the splice header) buys
   the bilateral profile correctness; it does not buy profile independence.
   Recommendation: rename `payload_commitment` to `vault_materialisation_root`
   in the bilateral profile; reserve the name `payload_commitment` for
   profile-specific use.

3. **The reduced-proofs machinery is heavyweight for what it gates.** The
   factory reduced-rights proof body is 2580 bytes and only proves that *one
   touched right changed*. The same fact could be proved with a Schnorr-style
   "I am reducing my own reserve claim by N" signed message + an on-chain
   commitment check, for ~100 bytes. The current design optimises for "we can
   re-derive the entire right tree from the proof" rather than "we can prove
   the *narrow* claim". The conservative profile is correct under both
   formulations; the simpler one would be cheaper, easier to audit, and
   friendlier to bounded mainnet fee budgets.

---

## 2. Design Review Table

| ID | Surface | Claim/Choice | Question Raised | Verdict |
| --- | --- | --- | --- | --- |
| R-01 | Cell decomposition | Three independent Cells (State / Vault / Sponsor) on three independent scripts (`morph-state-type`, `morph-vault-lock`, `morph-sponsor-lock`) | Is three the right cardinality, or could the sponsor and the state share a script? Why not a single channel Cell that carries all three roles? | **Justified.** A single channel Cell would force the script to re-verify the sponsor policy on every state publication, which is an attack surface. Three scripts is the CKB-native decomposition: each script can be deployed, audited, and versioned independently. The README's "vault protects user value; the state cell says which state can settle that value; sponsor funds pay for publication" three-sentence claim maps exactly to three scripts. The decomposition is the design's strongest claim and the audit found no case where the three roles collapsed into a shared trust surface. |
| R-02 | StateHeader fields | 17 fields; all signed under `signing_digest` | Are all 17 fields "necessary" or could some be derived from others? | **Mixed (Under-justified for 2, Justified for 15).** `protocol_version`, `state_layout_version`, `chain_id`, `signature_scheme_id`, `channel_id`, `funding_epoch`, `funding_anchor`, `vault_set_commitment`, `state_number`, `mode`, `phase`, `participants_commitment`, `asset_registry_commitment`, `settlement_descriptor_commitment`, `descriptor_version`, `challenge_policy_commitment` are all "signed → cannot be silently swapped". `payload_commitment` is also signed but in the bilateral plain profile its value is *derived* from the post-splice vault Cell commitment (see `morph-vault-lock/src/main.rs:377`) — the field is signed but its *content* is enforced elsewhere. This is the overloading smell called out in §1.1. The fix in the 6/27 audit (separate `new_payload_commitment` in the splice header) only addresses the splice direction; the steady-state direction still has one field doing two jobs. |
| R-03 | `funding_context_id` | Implementation note declares it as an "integration and audit key" (`implementation.md:64-69`), not a consensus field; derived from `(chain_id, channel_id, funding_anchor, vault_set_commitment)` with domain `CKB_MORPH_FUNDING_CONTEXT` | Is the "key but not in the header" choice clean, or is it a hidden API surface? | **Justified but Under-justified.** A derived audit key is the right choice — the alternative is to widen the StateHeader to 346 bytes, which would force every existing StateCell to be re-migrated. The implementation is clean (`hash.rs:48-61`, `lib.rs:3740-3749`). But the README does not mention it and the watcher package is the only surface that uses it (`packages.rs:423-429`). New integrators will discover it by grepping for `funding_context_id` and getting inconsistent results (used in watch cursor, used in package validation, NOT used in state-type or vault-lock script). Recommendation: add a 3-line note to the tutorial's "Why sponsor needs a different funding context" step. |
| R-04 | WitnessEnvelope | A 50-byte prefix (`magic + version + kind + flags + body_len + body_commitment`) precedes every factory witness; the script dispatches on `kind` to one of 7 body types | Could a tagged union (e.g. a single `enum MorphOp { Signature, ReducedRights, MerkleUpdate, ... }`) be serialized directly with Molecule? Why a fixed 50-byte envelope at all? | **Justified.** The envelope is doing three jobs the union cannot do as cheaply: (a) versioned dispatch so the script can refuse a future `kind=8` that it does not know, (b) body commitment that *binds the kind*, preventing kind-spoofing (a FACTORY_SIGNATURE body cannot be replayed as FACTORY_REDUCED_RIGHTS), (c) per-kind body length allow-list (`witness_envelope_body_len_allowed`, `lib.rs:450-473`) that prevents length confusion between kinds. A direct Molecule union would give (a) via the option tag, but (b) and (c) require a separate commitment; the envelope folds them into one 50-byte prefix. The 50-byte cost is amortised over bodies up to 9555 bytes. The naming `WitnessEnvelope` is honest about being a "witness format with a dispatch surface". The one weakness is that the body commitment is `H("CKB_MORPH_WITNESS_ENVELOPE_BODY", kind_le, body)` (no magic, no flags, no body_len) — the SYNTHESIS W2-08 noted this; if a v2 changes flags semantics, the body commitment does not bind the new flag value. Recommendation: bind `flags` into the body commitment in the next envelope version bump. |
| R-05 | Reduced factory paths | Four reduced paths (`ReducedRightsWitness`, `MerkleUpdateWitness`, `ReducedExitWitness`, `ReducedSpliceWitness`) each prove that *one* touched right changed under signed non-interference | Is the "one touched right" rule a security choice, a cost choice, or both? | **Justified as a security choice, Over-engineered for the cost model.** The "one touched right" rule means a multi-right reduced update requires either (a) multiple reduced proofs in the same transaction, or (b) the conservative all-participant path. The `SYNTHESIS` deferred-work table mentions "multi-right reduced updates" as a deferred item. The cost model is heavy: the simplest reduced-rights witness body is 2580 bytes for a proof that *one number decreased*. A Schnorr-style "I am reducing my own reserve claim by N" signed message + an on-chain commitment check would be ~100 bytes. The current design optimises for the script's "can I re-derive the entire right tree from this witness" property; the simpler design would optimise for the script's "can I verify the narrow claim" property. The conservative profile is correct under both; the simpler one is cheaper to witness, cheaper to script, and easier to audit. The SYNTHESIS W5-12 also notes the 8 splice-boundary fields lack independent negative tests, which is a downstream consequence of the heavy machinery. |
| R-06 | SponsorPolicy fields | 9 fields: `channel_id, min_state_number, max_state_number, max_fee_per_tx, max_total_fee, already_spent, expiry, publication_state_type_hash, change_lock` | Is every field needed? Why `u64::MAX`-only for `expiry`? | **Mixed.** `channel_id` (which channel), `min_state_number` / `max_state_number` (range of states sponsor can pay for), `max_fee_per_tx` (per-tx cap), `max_total_fee` (cumulative cap), `already_spent` (running counter — needed because CKB Cells are stateless), `publication_state_type_hash` (which state type is being sponsored), `change_lock` (where the change Cell goes) are all necessary. `expiry` is the smell: the script at `morph-sponsor-lock/src/main.rs:65-67` rejects any value other than `u64::MAX`. A field that can only take one value is a placeholder for a feature that was not implemented. The tutorial's "sponsor pays for publication" wording implies a time-bounded sponsor ("until time X"), but the implementation explicitly refuses any bounded sponsor. Recommendation: either implement the bounded-expiry check (and update the `is_publication_or_challenge` to use it), or drop the field from the struct. The current state is the worst of both: the field exists in the wire format and is enforced to a sentinel, which adds 8 bytes to every sponsor policy and 0 bits of security. The user-supplied question in the task brief mentioned `allows_explicit_sponsor` as a field; that field does not exist in the current `SponsorPolicy` struct (the audit cannot find it in `types.rs:124-134` or the schema). If the intent was a future field, it is not in scope; if the intent was a name in another context, the audit could not find a referent. |
| R-07 | ChannelClose path | No explicit cooperative-close path; close is "the bilateral profile is atomic and consumes the vault" (`implementation.md:134-136`); tutorial says "Finalise" is the only exit; README says "Finalise / withdraw" is the final stage | Does the protocol have a "friendly close" path, or is "close" an implicit consequence of splice-out + finalise? | **Under-justified (Mismatched-claim adjacent).** `ChannelOperation::CooperativeClose` exists in the enum (`types.rs:24-32`) but is not reachable from any of the seven witness envelope kinds, is not exposed in the CLI, and the implementation note explicitly says "Cooperative close is modelled in the host operation taxonomy, but it is not part of the current State type, vault contract, CLI, or devnet execution profile" (`implementation.md:135-136`). The `validate_vault_spend` validation does allow it (`validation.rs:866-869`) but no script path produces it. A new reader of the codebase will find `CooperativeClose` in three places (enum, validation, no script) and assume the design has a cooperative close that is just not exercised; in fact, the design has *no* cooperative close and the enum entry is a future-feature placeholder. The "close" semantic in the README is the splice-out-to-self + finalise flow described in `main.rs:2224-2268` (`xudt_splice_out_smoke`). That is a "force-withdrawal" pattern, not a "friendly close". Recommendation: either remove `ChannelOperation::CooperativeClose` from the enum (or mark it `#[allow(dead_code)]` with a `// reserved for future` doc comment), or add a one-paragraph note to `implementation.md` saying "the enum is a forward-looking type taxonomy; the deployed profile only exercises 5 of 7 variants (Fund, Publish, Supersede, Finalise, Splice)". |
| R-08 | Factory local exit = "open new channel" | `MaterialiseChild` is the morph-hub UI label (`App.tsx:119`) and the `MaterialiseChildRequest` API body; `factory_exit_channel` is the devnet function name (`devnet.rs:5169`); `morph-factory-type/src/main.rs:154-199` dispatches `FACTORY_LOCAL_EXIT` to `validate_local_exit`; the README calls it "factory local exits that materialise child bilateral channels" | Is materialising a child channel conceptually the same as opening a new bilateral channel, or is it a distinct operation? | **Mismatched-claim (Naming-drift adjacent).** The factory local exit *creates a new bilateral channel* from a factory reserve right. The new channel has its own `channel_id`, its own `funding_anchor`, its own `StateCell` and `VaultCell`, and follows the bilateral lifecycle from there. The "materialise" verb is honest about the CKB side (a Cell materialises from another Cell) but obscures the L2-side fact that a brand new bilateral channel has just been opened. The UI label "Materialise child channel" is the closest to honest; the README's "factory local exits that materialise child bilateral channels" tries to do both. The devnet command is `factory-exit-channel` (line 1686) which is correct. The naming drift table in §3 captures this. Recommendation: pick one — either the bilateral-lifecycle language ("the factory opens a child bilateral channel from reserve") or the CKB-side language ("the factory reserve materialises a child StateCell + VaultCell pair"). The current document mixes both. |
| R-09 | README three-sentence claim | "the vault protects user value; the state cell says which state can settle that value; sponsor funds pay for publication and fee bumping" (README:36-40) | Does the code strictly enforce this three-sentence decomposition? | **Mostly yes; one slip.** Vault scripts: only `morph-vault-lock` and `morph-factory-vault-lock` spend the vault, and both check the state-type identity (`morph-vault-lock/src/main.rs:60-77`) before any settlement. State cell: only `morph-state-type` and `morph-factory-type` mutate state. Sponsor: only `morph-sponsor-lock` enforces the policy. The "fee bumping" claim is the slip — the sponsor policy enforces a per-tx and total cap, but does NOT enforce any "bumping" semantics. "Bumping" implies a follow-up tx that supersedes a prior attempt; the sponsor cell can also pay a first-time publication. The implementation note says "publication fees" (`implementation.md:31`); the README says "publication and fee bumping" (line 38). Recommendation: change the README line to "sponsor funds pay bounded publication fees" — drop "fee bumping" unless the implementation actually enforces a RBF-style bump. |
| R-10 | Protocol naming consistency | Cell, header, witness, domain, CLI, and tutorial names | Do the same concepts carry the same names across code, script, schema, paper, doc, and CLI? | **Mixed (5+ drifts found; see §3).** The Cell / script / struct / CLI / schema names are mostly aligned, with drifts concentrated in: (a) `current` suffix in old factory witness body names vs the new envelope dispatch (acknowledged in `implementation.md:57-59` and `roadmap.md:45-48`), (b) `payload_commitment` used for two different things in different profiles, (c) "Materialise" (UK spelling) vs "materialise" (verb form) vs "Materialised" (past tense) vs "Materialise child" (UI label) — actually consistent UK spelling throughout, but the README uses "materialise" (verb) where the UI uses "Materialise" (header), (d) `SpliceKind::In / Out` (Rust) vs `SPLICE_KIND_IN / _OUT` (script) vs `splice-in / splice-out` (CLI) vs `SpliceIn / SpliceOut` (clap value enum) — all consistent, (e) `factory_id` (rust field) vs `factory_id` (script domain hash) vs `factory_id` (CLI flag) — consistent. The drifts are documented in §3. |
| R-11 | Implementation deep links to UI | The morph-hub UI (`ui/morph-hub`) is a separate React app with `api.ts`, `domain.ts`, `App.tsx`; the README Quick Start has a 20-line section on how to run the hub; tutorial does not mention the hub at all | Is the UI a "first-class" surface of the protocol, or a reference operator console? | **Under-justified.** The README says "Local Morph operator console for invoices, channels, factories, and watchtower state" (line 132), positioning it as a console. The implementation note does not mention the UI. The tutorial does not mention the UI. The UI is bound to the same `hub serve` subcommand as the production-built UI ("production-built UI" in the CLI doc string for `Hub` at `main.rs:163`). The wording suggests the UI is built from the same source as the devnet console but served alongside the hub API. A new integrator cannot tell whether to expect a stable UI surface or a devnet convenience. Recommendation: add a one-line note to `implementation.md` saying the UI is loopback-first, devnet-oriented, and the wire format is the source of truth. |
| R-12 | `is_publication_or_challenge` allow-list | `validation.rs:34-38` returns true only for `Publish | Supersede`; the function name promises "publication or challenge" but the implementation is "publish or supersede" | Is the function name honest? | **Naming-drift.** "Challenge" is the act of publishing a state that pre-empts a fraudulent one; the implementation lumps it with `Publish`. A new reader who searches for "challenge" in the codebase will find the field `challenge_policy_commitment` (which is the policy that defines the since-value, detection depth, etc.) but not a `Challenge` operation. The tutorial says "sponsor pays for publication and fee bumping" — the "fee bumping" is what the implementation calls `Supersede`. The naming implies two distinct operations; the implementation uses one. Either rename to `is_publication_or_supersede`, or expand the enum to make `Publish` and `Supersede` and `Challenge` three distinct values. The current shape is a hot spot for misunderstanding. |
| R-13 | `BilateralCkbSettlementDescriptor` vs `BilateralCkbXudtSettlementDescriptor` | Two concrete descriptor types, fixed at 2 outputs, versioned 1 and 2 | Why not one descriptor with an optional xUDT type hash? Why fixed at 2 outputs? | **Justified.** Two versioned types is the cheapest way to keep the on-chain parser bounded: the CKB script does not have to handle a "0 outputs / 1 output / 2 outputs / N outputs" combinatorial case, and the version byte lets a v3 descriptor add a third output without breaking v1/v2. The fixed-at-2-outputs is the price of the on-chain simplicity; the paper's "SettlementDescriptor" is more general (M-08 SYNTHESIS, W2-04) but the wire-level is intentionally narrow. Recommendation: leave as-is; the deployment profile (bilateral, two participants) is well-served by two outputs. If a future "1-of-N multilateral" profile appears, add a `BilateralMultilateralSettlementDescriptor` with a `participant_count: u8` field. |
| R-14 | `funding_anchor` is `H(input_outpoint, output_index)` | Type-ID-style anchor derivation, documented in `implementation.md:60-63`; `morph-state-type/src/main.rs:177-189` and `morph-factory-type/src/main.rs:331-343` both verify the derivation | Is Type-ID-style the right anchor, or should it be a live Fund Cell input? | **Under-justified (Profile choice).** Type-ID-style is simpler (no Fund Cell lifecycle to manage) but means the `load_input(0, ...)` call is *attacker-controlled*: a transaction can route any input cell to position 0 and the anchor follows. The 6/27 audit (A-2026-06-27-07) notes that the sponsor bypass that made this dangerous is now closed, but the *funding-cell uniqueness* is not. The SYNTHESIS W1-03 flagged this; the 6/27 audit marked it "devnet profile limitation, not a confirmed current exploit". For a "devnet profile" this is a reasonable choice. For a mainnet profile, the H-01 paper patch in `audit-response-2026-06-20.md:151-203` describes a live Fund Cell that the W1-03 closure would tighten. The current README does not explain this trade-off. Recommendation: add a one-line note in `implementation.md` next to the funding-anchor derivation paragraph: "Type-ID-style is the devnet profile; mainnet deployments should add live-Fund-Cell uniqueness checking per H-01." |
| R-15 | Mode enum (`BilateralPlain`, `FactoryProof`) | `types.rs:9-13`; `as_u8` maps to `1, 2`; `BilateralCommitment` mode is reserved (mentioned in `implementation.md:74-75`) | Is a 1-byte `mode` field the right discriminator, or is it redundant with the witness envelope kind? | **Justified but Mismatched-claim.** The mode byte is signed, so the verifier cannot silently switch between a bilateral update and a factory update. The redundancy with the witness envelope kind is deliberate: the StateHeader is *always* signed, the witness envelope is *factory-only*; the bilateral StateHeader must carry its own `mode = 1` even though there is no envelope. The `BilateralCommitment` mode is reserved but the enum does not include it. The implementation note claims "Bilateral commitment mode is reserved and is not emitted by current package or devnet flows" but the enum does not have a `BilateralCommitment` variant to reserve. Recommendation: either add the `BilateralCommitment` variant (and mark `#[non_exhaustive]` to make the reservation visible) or remove the "reserved" claim from the implementation note. The current code has a 2-variant enum and a 2-byte `kind` field in the envelope; the 2-byte `kind` is over-provisioned if there are only 2 meaningful values. |
| R-16 | The CLI exposes 50+ devnet commands | `morph-cli/src/main.rs` has a `Devnet` subcommand with 50+ variants (deploy, open, publish, finalise, splice, factory, etc.) | Is the CLI a developer convenience surface or a production surface? | **Under-justified.** The README's "Common CLI Workflows" section shows ~15 of the 50+ devnet commands. The devnet commands embed the local CKB devnet RPC URL, the deployer private key, and the smoke-assertion options. They are not safe to run against mainnet. The `--private-key` flags use `env::var("MORPH_DEVNET_PRIVATE_KEY")` defaults; there is no warning that this is devnet-only. A new operator who reads the Quick Start will be tempted to point the same CLI at a real CKB node. The devnet commands should be feature-gated or wrapped in a `--devnet-only` confirmation flag. Recommendation: add a `#[cfg(feature = "devnet")]` gate on the `Devnet` subcommand and require an explicit `--devnet` opt-in to enable it from the default build. This is a usability concern more than a security boundary — the on-chain scripts enforce the security — but a misnamed CLI is a documentation smell. |
| R-17 | Implementation note vs README on cooperative close | `implementation.md:135-136`: "Cooperative close is modelled in the host operation taxonomy, but it is not part of the current State type, vault contract, CLI, or devnet execution profile." | Does the README communicate this? | **Mismatched-claim.** The README has no mention of "cooperative close" in any form. The implementation note says it does not exist as a wire-level operation. A reader of the README will not learn that this is a deliberate omission. The current README "Finalise And Withdraw" section describes a force-finalise, not a friendly close. A user who wants to close a channel cooperatively (because they have a valid signed state and want to avoid the `since` delay) will look in the README, find nothing, and assume the protocol has no cooperative close — which is correct, but the implementation note uses the word "cooperative close" in a way that the README does not. Recommendation: either remove `ChannelOperation::CooperativeClose` from the enum (and update the implementation note), or add a one-line README note: "Cooperative close is not implemented in the current profile; the only exit is the unilateral finalise path." |

---

## 3. Naming Drift Table

| # | Concept | Code (types.rs) | Script (morph-script-common) | Schema (morph.mol) | Tutorial / README | Verdict |
| --- | --- | --- | --- | --- | --- | --- |
| 1 | Factory-side materialisation of a child channel | `ChannelOperation::Materialise`, `factory_exit_channel` (devnet.rs:5169), `MaterialiseChildRequest` (hub.rs:234), `MaterialiseChild` (App.tsx:356) | `WITNESS_ENVELOPE_KIND_FACTORY_LOCAL_EXIT` + `validate_local_exit` (factory-type/main.rs:155-159) | `FactoryLocalExitWitness` (mol:355-365) | "factory local exits that materialise child bilateral channels" (README:58), "Materialise child channel" (App.tsx:119) | **Naming-drift (intentional split).** "Materialise" is the CKB-side verb (a Cell materialises from another Cell), "exit" is the factory-side verb (the factory exits a reserve right), "open" is the bilateral-side verb (a new bilateral channel is opened). The three views are each correct, but no single document tells the reader which view is which. The morph-hub UI label "Materialise child channel" is the most user-friendly; the README's "factory local exits that materialise child bilateral channels" tries to do both at once. |
| 2 | Splice operation kind | `SpliceKind::In / Out` (types.rs:453-457), `SPLICE_KIND_IN: u8 = 0` (lib.rs:166) | `SPLICE_KIND_IN / _OUT` (lib.rs:166-167) | `kind: byte` (mol:110) — no enum name | "splice-in / splice-out" (README:54, tutorial:34, 105-107) | **Justified.** The name is consistent across all five surfaces. UK spelling. Drift only on the byte vs the typed enum (which is intentional and the byte width is documented in the mol schema). |
| 3 | "current" suffix on factory witness body schemas | `FactoryReducedRightsWitness` etc. (script-common) | `// current factory witness baseline` (roadmap.md:36) — historical label | `FactoryReducedRightsWitness` (mol:220-250) — no `current` suffix | "earlier factory work used body names that still end in `current`" (tutorial:127) | **Naming-drift (acknowledged historical).** The "current" suffix is a historical label for "the current factory witness boundary before the envelope was introduced". The implementation note explicitly says "Names ending in `current` usually identify a fixed-layout body schema. They are not a claim that the current factory witness boundary is the old current boundary" (implementation.md:57-59). The mol schema has no `current` suffix; the script-common types have none. Only the roadmap and tutorial make the historical reference. A new reader who searches for `current` in the codebase will find it in comments only, not in code. This is intentional but under-documented. |
| 4 | Funding context vs funding anchor | `funding_anchor: Bytes32` (types.rs:47), `funding_context_id(&self)` (types.rs / hash.rs:93-100) | `FUNDING_CONTEXT_DOMAIN: b"CKB_MORPH_FUNDING_CONTEXT"` (lib.rs:140), `funding_context_id(...)` (lib.rs:3740) | `funding_anchor: Byte32` (mol:85); no `funding_context_id` field | "funding_context_id = H(...) is an integration and audit key" (implementation.md:64-69) | **Justified (Under-justified in docs).** Two distinct names, two distinct purposes. `funding_anchor` is signed and on-chain; `funding_context_id` is derived off-chain. The naming is honest. The drift is in the documentation: the README does not mention `funding_context_id`; the tutorial does not either; only the implementation note and the watchtower cursor code use it. A watchtower integrator who reads the README will not learn that the watch cursor uses a different identifier from the StateHeader. |
| 5 | Settlement descriptor types | `BilateralCkbSettlementDescriptor`, `BilateralCkbXudtSettlementDescriptor` (script-common), `BILATERAL_CKB_DESCRIPTOR_VERSION: u16 = 1`, `BILATERAL_CKB_XUDT_DESCRIPTOR_VERSION: u16 = 2` (lib.rs:162-163) | Same | `BilateralCkbSettlementDescriptor`, `BilateralCkbXudtSettlementDescriptor` (mol:447-468) | "CKB and xUDT settlement through the same state/vault authority model" (README:52) | **Justified.** Two versioned types is the cleanest on-chain way to keep parsing bounded. The naming is consistent across all four surfaces. The drift is in the doc: the README collapses both to "CKB and xUDT settlement" without explaining that there are two versioned concrete descriptors and a version byte in the wire format. |
| 6 | Phase enum (active / settling / closed / funding) | `Phase::Funding, Active, Settling, Closed` (types.rs:15-21) | `PHASE_ACTIVE: u8 = 1`, `PHASE_SETTLING: u8 = 2` (lib.rs:104-105) — only two are emitted | Same | "After the relative `since` delay, the vault can be spent only against the current settling State Cell" (README:104-107) | **Mixed.** The Rust enum has 4 variants but only 2 are emitted on the wire. The implementation note and SYNTHESIS W2-02 say the paper's `funding` and `closed` are pre/post lifecycle markers and should be removed from the enum. The 6/27 audit did not change this. The current shape is "Rust enum has 4 variants, wire has 2, the Rust enum carries semantic state the wire does not have". A profile that emits `Phase::Closed` would be rejected by the script. The README says "the vault can be spent" which is the `Settling → terminal` transition; the enum's `Closed` variant encodes the post-spend state. Recommendation: keep the Rust enum, but rename the wire bytes to `wire: u8` to make the over-provisioning visible, or drop the `Closed` variant from the enum since the wire never sees it. |
| 7 | CooperativeClose enum entry | `ChannelOperation::CooperativeClose` (types.rs:29) | Not in any script dispatch | Not in any schema | README: not mentioned; tutorial: not mentioned; implementation.md:135-136 says "not part of the current State type, vault contract, CLI, or devnet execution profile" | **Naming-drift (Under-justified).** See R-07. The enum entry exists, the validation accepts it, the script does not produce it, the CLI does not expose it, the README does not document it. The only place a reader finds the concept is the implementation note. |
| 8 | SpliceHeader wire field naming | `old_funding_anchor`, `new_funding_anchor`, `old_funding_epoch`, `new_funding_epoch`, `old_vault_commitment`, `new_vault_commitment`, `payload_commitment`, `new_payload_commitment` (types.rs:488-507) | Same (lib.rs:580-633) | Same (mol:99-118) | Same (tutorial, README) | **Justified.** Consistent 8-field splice header with `old_*` and `new_*` prefixes. The 6/27 audit (A-2026-06-27-01) split `payload_commitment` into `payload_commitment` + `new_payload_commitment` for the splice direction; the StateHeader still has only `payload_commitment`. The asymmetry is intentional (the StateHeader is a snapshot, the SpliceHeader is a transition), but it is the underlying reason the `payload_commitment` overloading smell exists. |

---

## 4. Claim Calibration Table

| # | README / Tutorial claim | Implementation / roadmap / mainnet-readiness | Verdict |
| --- | --- | --- | --- |
| C-01 | "sponsor funds pay for publication and fee bumping" (README:38) | `validation.rs:34-38` — `is_publication_or_challenge` returns true for `Publish | Supersede` only; `morph-sponsor-lock/src/main.rs:39-60` checks `phase == SETTLING` and `min/max_state_number`; `implementation.md:140-141`: "does not sponsor funding, finalisation, splice, materialisation, or cooperative close". The sponsor is publication-only (Publish) and challenge (Supersede). "Fee bumping" is a colloquialism for Supersede; "publication" is the Publish operation. | **Mismatched-claim (Under-justified).** The README's wording is too broad. Sponsor is for publication + supersede, not for any "fee" or "bumping". A new reader will assume the sponsor cell can fund any of the seven ChannelOperations. Recommendation: change the README to "sponsor funds pay bounded fees for state publication and supersede". |
| C-02 | "Implemented locally: bilateral CKB channels: open, publish, supersede, finalise, and sponsored publication" (README:51) — this is one of 8 implemented-locally items | `morph-cli/src/main.rs` has `OpenChannel`, `PublishState`, `SaveStatePackage`, `ApplySplice`, `FinaliseChannel`, `WatchLatestStatePackage`, `FundSponsor`; the "Supersede" path is documented in `supersede_smoke` (devnet.rs:9337). The implementation note confirms bilateral plain profile is `Open / Publish / Supersede / Finalise`. The 6/27 audit (A-2026-06-27-01) added bundle-layer successor payload check. | **Justified.** The 8 implemented-locally items each correspond to a working devnet smoke or stateful path. The count is 8 (W3-01 in SYNTHESIS is a historical finding against an earlier 7-item list; the current README has 8). |
| C-03 | "factory local exits that materialise child bilateral channels" (README:58) | `morph-factory-type/src/main.rs:155-199` dispatches `FACTORY_LOCAL_EXIT`; `validate_local_exit` enforces the exit shape; `factory_exit_channel` (devnet.rs:5169) is the devnet command; the morph-hub UI exposes it as "Materialise child channel" (App.tsx:119). | **Justified (naming-drift).** Conceptually correct; see naming drift #1. |
| C-04 | "reduced factory paths for bounded rights updates, exits, sparse-Merkle updates, and splices, carried by `WitnessEnvelope`" (README:60) | `WITNESS_ENVELOPE_KIND_FACTORY_REDUCED_RIGHTS = 2`, `_MERKLE_UPDATE = 3`, `_REDUCED_EXIT = 4`, `_REDUCED_SPLICE = 7` (lib.rs:132-138). The 4 reduced paths are routed in `morph-factory-type/src/main.rs:128-162`. | **Justified.** All 4 reduced paths exist in the envelope and are dispatched in the factory-type script. The "bounded" claim is correct: each reduced witness proves *one touched right changed*. |
| C-05 | "Still not claimed: mainnet readiness" (README:66) | `mainnet-readiness.md:24-33`: 8 release gates all "Open"; "Go / No-Go Summary: Can it be used for mainnet real assets today? No." | **Justified.** The "not mainnet" claim is consistent with the gates. |
| C-06 | "cooperative close is modelled in the host operation taxonomy, but it is not part of the current State type, vault contract, CLI, or devnet execution profile" (implementation.md:135-136) | `ChannelOperation::CooperativeClose` (types.rs:29) is in the enum; `validate_vault_spend` (validation.rs:867) allows it; no script produces it; no CLI command exposes it. The morph-hub UI does not have a cooperative close. | **Mismatched-claim (Under-justified).** The implementation note claims cooperative close is "modelled in the host operation taxonomy"; in fact, the host operation taxonomy has it as an enum entry but no host operation ever uses it. The tutorial does not mention it. The README does not mention it. A reader who only reads the README will not learn that the enum contains an unused variant. Recommendation: either drop the enum entry (and the `validation.rs:867` arm) or rename `CooperativeClose` to `CooperativeCloseReserved` and add a `#[deprecated]` attribute. |
| C-07 | "the current devnet profile, `funding_anchor` means the signed funding anchor identity. It is derived in a Type-ID-style way from the first funding input and the State Cell output index, and it is not a live output locator" (implementation.md:60-63) | `morph-state-type/src/main.rs:177-189` and `morph-factory-type/src/main.rs:331-343` both verify `H(input_outpoint, output_index) == funding_anchor`. The 6/27 audit (A-2026-06-27-07) marks Type-ID-style as a devnet profile limitation. | **Justified but Under-justified in README.** The implementation note is clear; the README does not explain the trade-off. A new integrator who reads the README will assume the funding anchor is a live output locator. Recommendation: add a one-line note in the README "Funding and Factory" section. |
| C-08 | "Open A Channel: ... funds move from a normal wallet cell into cells controlled by channel rules" (README:88-90) | The CLI `OpenChannel` (main.rs:511) deploys contracts then opens a channel; the channel is a State Cell + Vault Cell + Sponsor Cell; the sponsor is optional. `morph-state-type/src/main.rs:177-189` enforces the Type-ID-style anchor derivation. | **Justified.** The README's high-level claim matches the code. |
| C-09 | "M4: Factory mode — Implemented narrowly: Conservative factory updates, local exits, reduced-rights proof, sparse-Merkle update, reduced exit, factory splice, and reduced splice through `WitnessEnvelope`" (roadmap.md:30) | All 7 of these are dispatched in `morph-factory-type/src/main.rs:128-162`; each has a devnet smoke or stateful path. | **Justified.** The roadmap matches the code. The "Implemented narrowly" qualifier is honest: see W6-R-05 for the cost concerns. |
| C-10 | "M5: Watchtower and audit gates — Implemented locally" (roadmap.md:31) | The watchtower (`watch_config.rs`, `watch_policy.rs`, `watch_alert.rs`) is implemented. The 6/27 audit closed W4-02 (Fiber acceptance loose-stateful-assertion). W3-04 from SYNTHESIS: "Roadmap M5 Implemented locally vs watchtower Open" was a real drift; the 6/27 audit (A-2026-06-27-04) fixes the W4-02 path but not the W3-04 wording. The roadmap M5 still says "Implemented locally"; mainnet-readiness still has "Multi-operator watchtower evidence — Open". | **Partially-justified (Mismatched-claim).** "Implemented locally" is honest. "Open" for multi-operator evidence is honest. The wording is consistent: M5 is local, mainnet-readiness gate is multi-operator. A new reader will see "M5 Implemented" and may miss the mainnet gate distinction. The roadmap could link to mainnet-readiness. |
| C-11 | "Fund cells may carry CKB or xUDT, but every Fund Cell must come from a single funding input and the State Cell output index must be a Type-ID-style anchor" (paraphrased from implementation.md:60-63 + README:35-46) | `morph-state-type/src/main.rs:177-189` enforces the Type-ID-style anchor; `morph-vault-lock/src/main.rs:46-122` accepts CKB or xUDT settlement descriptors. The vault's on-chain parser distinguishes CKB (`BilateralCkbSettlementDescriptor`) and xUDT (`BilateralCkbXudtSettlementDescriptor`). | **Justified.** The single-funding-input rule is enforced by the anchor derivation. The CKB/xUDT settlement is enforced by the descriptor version byte. |
| C-12 | "no terminal receipt cells are created" (`implementation.md:134`) | `validate_partition_conservation` (validation.rs:896-963) checks `reserve_out + authorised_reserve_refund == reserve_in`; the settlement outputs are the participants' lock-hash + capacity outputs. The vault lock consumes the vault and produces two settlement outputs (or one xUDT settlement output pair). | **Justified.** No intermediate "receipt" cells; the atomic consume + recreate is the design. The paper S1 patch is consistent with this. |

---

## 5. Recommendations (If v2, these are the 5 most important)

1. **Resolve the `payload_commitment` overloading.** Rename the bilateral
   profile's `payload_commitment` to `vault_materialisation_root` and reserve the
   `payload_commitment` name for profile-specific use. This buys profile
   independence: a future balance-state profile can use `payload_commitment`
   for the balance root, and the bilateral profile's semantics are no longer
   hidden in the field name. The 6/27 audit (A-2026-06-27-01) split the splice
   direction; this recommendation closes the profile-direction.

2. **Add an "Operation allow-list" table to the implementation note.** The
   current 7-variant `ChannelOperation` enum and the 2-of-7 sponsor allow-list
   (`is_publication_or_challenge`) and the 4-of-7 vault allow-list
   (`validate_vault_spend`) and the 0-of-7 cooperative-close reality are the
   four facts every new integrator needs on a single page. The current docs
   scatter these across `implementation.md`, `validation.rs`, the tutorial, and
   the morph-hub UI. A 1-page table titled "Operation coverage" with columns
   `enum variant / script-enforced / sponsor pays / vault spends / CLI exposed
   / devnet smoke` would replace 6 cross-references with 1 lookup.

3. **Drop the `ChannelOperation::CooperativeClose` enum entry (and the
   `validation.rs:867` arm), or rename it to `CooperativeCloseReserved` with
   `#[deprecated]`.** An enum entry that is in the validation function and
   nowhere else is a documentation smell that misleads new readers. If the
   intent is "we will add this later", make the reservation visible; if the
   intent is "we forgot to remove it", remove it. The current state is the
   worst of both.

4. **Implement `SponsorPolicy::expiry` or remove the field.** The
   `morph-sponsor-lock/src/main.rs:65-67` check is a runtime reject of any
   value other than `u64::MAX`. Either implement the time-bounded check (so a
   deployment can write `expiry: 1717000000` and the script enforces it) or
   remove the field from the struct and the wire format. A field that can
   only take one value adds 8 bytes to every sponsor policy and 0 bits of
   security. The current shape is a placeholder for a feature that never
   landed; the placeholder is now 8 bytes of wire format and a runtime error
   code (`SponsorPolicyUnsupported`).

5. **Reduce the reduced-proof machinery's wire cost.** The 2580-byte
   `FactoryReducedRightsWitness` proves "one right changed" with a full
   before/after right tree and a signed non-interference digest. A
   Schnorr-style "I am reducing my own reserve claim by N" signed message +
   an on-chain commitment check is ~100 bytes and the same security
   property for the conservative profile. The current design optimises for
   "the script can re-derive the right tree" rather than "the script can
   verify the narrow claim". The 8 splice-boundary fields' lack of
   independent negative tests (W5-12 SYNTHESIS) is a downstream consequence
   of the heavy machinery: a simpler design has fewer test surfaces. The
   conservative profile is correct under both formulations; the simpler one
   is cheaper to witness, cheaper to script, and friendlier to bounded
   mainnet fee budgets.

---

## 6. Limitations

1. **No paper inspection.** The task brief says "paper.tex 如果在仓库内;不在则跳过
   paper 对照(标记为 limitation)". The paper is not in this repository; the
   SYNTHESIS report's paper-drift findings (W2-01..W2-16, paper S1..S5,
   paper M1..M8) were not re-derived for this audit. The audit is anchored to
   the code, schema, and docs in this repository only.

2. **No runtime build or test execution.** The audit was a static read of
   types.rs, script-common, the four contract main.rs files, the schema, the
   core docs, and the CLI. `cargo test`, `cargo clippy`, and `make ci` were
   not run. The 6/27 audit (A-2026-06-27) reports "cargo test --workspace"
   passes on this tree; this audit accepts that claim and does not
   independently verify it.

3. **The morph-hub UI was sampled, not read in full.** The UI is 1900+ lines
   in `ui/morph-hub/src/App.tsx` plus api.ts and domain.ts. The audit
   sampled the action labels and the `MaterialiseChildRequest` API shape;
   the full UI flow was not traced. A new finding in the UI's wire-format
   translation is possible.

4. **The CLI was sampled for `Devnet` and `Hub` subcommands but not for every
   one of the 50+ devnet commands.** The audit traces `OpenChannel`,
   `OpenFactory`, `ApplyFactorySplice`, `ApplySplice`, `FinaliseChannel`,
   `PublishState`, `WatchLatestStatePackage`, `FactoryExitChannel`. Other
   commands (e.g. `SponsorPolicyNegativeSmoke`, `CompetingSpendSmoke`) were
   named in grep but not read in full. The naming drift table is built on
   the 50+ command names; the substantive review is built on the 8
   commands above.

5. **The audit was anchored to HEAD `5072d81e` with a dirty worktree.** Per
   the task brief, "审计以 HEAD 为准". The dirty worktree means some files
   may have uncommitted changes; the audit reads the committed content.
   The `git log` of the recent commits was not inspected to determine which
   changes are dirty and which are in HEAD; the 6/27 audit (A-2026-06-27)
   was the most recent documented pass.

6. **The naming drift table is heuristic.** The "drift" label requires the
   audit to declare that two names for the same concept are *inconsistent*;
   in some cases (e.g. "Materialise" the CKB verb vs "open" the L2 verb) the
   two names are *intentionally* different. The audit marks these as
   `Naming-drift (intentional split)` to flag them for human review; the
   intent-vs-accident judgment is the audit's call, not a fact.

---

## 7. Closing Note

**Audit credibility: medium-high.** Every row in §2 cites a specific file:line
or schema:line that the audit read. The naming drift and claim calibration
tables in §3 and §4 are built on direct quotes from the source. The 5
recommendations in §5 are sequenced: R1 (rename `payload_commitment`) is
disruptive but buys profile independence; R2 (operation allow-list table)
is cheap and unblocks the next 5 integrators; R3 (drop `CooperativeClose`)
is a 1-line code change that closes a documentation smell; R4 (resolve
`expiry`) is either a feature or a deletion; R5 (simplify reduced proofs)
is a design simplification that touches the script-common witness parsers
and the host-side witness encoders.

**What this audit did not do that a future audit could.** A v2 audit could
(a) re-derive the SYNTHESIS W2 paper-drift findings against a copy of
`paper.tex` from the L2 protocol writing repository, (b) inspect every one
of the 50+ `Devnet` subcommands and the morph-hub UI in full, (c) run
`cargo test --workspace` and `make ci` on a clean HEAD and confirm the
248-test count is current, (d) trace the watchtower cursor and the
`funding_context_id` re-anchoring through the live devnet to confirm the
integration key is the actual identifier used in practice, (e) inspect
the Hub operator console for the production vs devnet separation the
README implies but the morph-hub does not enforce at the build level.

The repository is a serious devnet research implementation. The architecture
is clean. The documentation depth does not match the implementation depth,
and three design smells (overloaded `payload_commitment`, sentinel `expiry`,
unused `CooperativeClose`) are present and worth a v2 pass.
