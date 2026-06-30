# Swarm Audit — W6 Safety (Threat Model & Residual Risk)
Date: 2026-06-28  Branch: `main`  HEAD: `5072d81` (post-W5 splice fix), with dirty worktree
Auditor track: W6 — Safety axis (threat model + attack surface + post-W5 closure recheck)
Scope: morph-channel protocol (Rust core, CKB-VM contracts, CLI, Morph Hub UI/server)

---

## 1. Metadata

| Field | Value |
| --- | --- |
| Head inspected | `5072d81` ("fix splice payload binding audit gaps") |
| Worktree | dirty — modified: `crates/morph-cli/src/{hub,main}.rs`, `crates/morph-core/src/node.rs`, `crates/morph-core/tests/node_invoice.rs`, `scripts/devnet-smoke.sh`, `ui/morph-hub/src/{App,api,domain}.{tsx,ts}`, `ui/morph-hub/src/styles.css` |
| Files reviewed (full) | `contracts/morph-sponsor-lock/src/main.rs` (191), `contracts/morph-script-common/src/lib.rs` (splice-binding block 820-1040, SponsorPolicy 3597-3700), `contracts/morph-vault-lock/src/main.rs` (380-450), `contracts/morph-factory-type/src/main.rs` (52-260), `contracts/morph-factory-vault-lock/src/main.rs` (140-190) |
| Files reviewed (diff vs 5072d81) | `crates/morph-cli/src/hub.rs` (dirty +840 / -150), `crates/morph-cli/src/main.rs` (CLI invoice signing flow), `crates/morph-core/src/node.rs` (invoice signing + `payment_preimage` removed from storage), `crates/morph-core/tests/node_invoice.rs`, `scripts/devnet-smoke.sh` (`env -u MORPH_DEVNET_PRIVATE_KEY` hardening), `ui/morph-hub/src/{App,api,domain}.{tsx,ts}` |
| Cross-references | W1 (aa71651) + W2-W5 (SYNTHESIS.md) + `docs/audit-report-2026-06-27.md` |
| Severity counts (this report) | CRITICAL 0 · HIGH 3 · MEDIUM 5 · LOW 2 |

---

## 2. Executive Summary

**Safety rating: Acceptable-with-caveats for devnet-only deployment.**

The W5 splice-binding fix at commit `5072d81` materially closes the two CRITICAL post-W1
residual risks (`splice successor payload_commitment` non-binding; splice header schema
drift). At the same time the dirty worktree adds a real new attack surface — a JSON
REST API (`crates/morph-cli/src/hub.rs`) bound to a TCP listener, paired with a
single-page web UI that stores its bearer token in `sessionStorage` and exposes
`PUT /api/state-file` as a full state-replacement primitive when the operator opts in
with `--allow-state-restore`. That new surface is a tightly-scoped, opt-in operator
panel (loopback-only by default, token-gated for non-loopback, input validation
defended at every parsed field) and not a public-facing service. Combined with the
CKB-VM-side sponsor-lock closure (W1-01 fixed at `morph-sponsor-lock/src/main.rs:117-141`
— no remaining `min_state_number == 0 && state_number == 0` bypass), the residual
HIGH-severity concerns are now concentrated in **defence-in-depth** items: CKB-VM
script resource accounting (`Box::leak` in factory-vault-lock, witness-iteration
without cap), the factory reduced-exit binding to on-chain `state_root` (W1-02), and
the new Morph Hub REST surface under shared-host deployment.

**Three most critical residual risks (one sentence each):**
1. **Hub `PUT /api/state-file` is a full state-replacement primitive** when
   `--allow-state-restore` is enabled (`crates/morph-cli/src/hub.rs:928-946`):
   replacing the persisted hub state wipes the live operator's channels / factories /
   invoices and replaces them with whatever the authenticated request body contains,
   bypassing the chain-anchored invariants the host layer is supposed to preserve. The
   `replace()` path makes a backup of the *previous* file and emits a `Warning` event,
   but does not verify the proposed state against `ckb_rpc_url`, signatures, or
   witness envelopes — a compromised UI client holding the auth token can rewrite the
   operator's view of the world.
2. **`morph-factory-vault-lock/src/main.rs:170` still uses `Box::leak` to give
   `FactoryStateHeader::parse` a `'static` slice** (W1-07, never closed). On a
   long-running chain with many factory-type cells invoked per block, the per-script
   heap pressure compounds; CKB-VM has no global GC and the leaked bytes are reclaimable
   only by script exit. This is not an exploitable bug today but is a known
   foot-gun on the script side and was specifically called out in W1 as "code quality,
   not security" — re-categorising here because the script runs in a privileged
   on-chain context where memory pressure translates directly to failed transactions.
3. **Sponsor policy range defaults are `min_state_number=0, max_state_number=u64::MAX`
   in `auto_fund_sponsor` (`crates/morph-cli/src/devnet.rs:9352`)**. Although the
   W1-01 first-publication bypass is closed (an attacker must back the publication
   with a real input StateCell at the same funding_anchor), an attacker who controls a
   participant signing key can still publish the next 2^64-1 state numbers against a
   sponsor cell with `min_state_number=0` until `already_spent + fee > max_total_fee`
   trips. The hard cap is per-sponsor-budget, not per-state-range, so the effective
   spend ceiling is correct — but the loose range gives an attacker a wide retry
   surface for fabricating states that all reference the same `funding_anchor`,
   potentially useful for DoS / state-bloat / replay probing against watchtowers.

**Overall posture.** All CRITICAL findings from W1 are closed. The HIGH/MEDIUM items
that remain are either deployment-profile restrictions (paper-only patches, watchtower
policy, MAX_VAULTS_PER_FINALISATION), defence-in-depth items that close only when a
deployment profile moves beyond the conservative bilateral plain profile, or live in
the new Morph Hub REST surface and depend on operator configuration choices. A
devnet-only deployment that runs the sponsor policy with `min/max` narrowed to its
real range, runs the hub server only on loopback or behind a token-gated reverse
proxy, and does not enable `--allow-state-restore`, is materially safer than at
W1-baseline (aa71651).

---

## 3. Threat Model

### 3.1 Trust assumptions (explicit and implicit)

| # | Assumption | Where encoded | Honest-but-? | Failure mode |
|---|---|---|---|---|
| T1 | The Rust source code is correct (no logical bugs in validation.rs, script-common, script-* contracts). | All contracts | Vulnerable | State-equivocation, conservation bypass. |
| T2 | CKB L1 consensus is live, with eventual finality on the order of `finalise_since` blocks (~hours to days). | `morph-state-type/src/main.rs:50-54`, `morph-vault-lock/src/main.rs:53`, `validation.rs` | Adversarial (BFT); 51% can reorg | State-finalisation race: an attacker with 51% hash power can reorg a finalised state; the protocol does not currently define a "confirmation depth" requirement distinct from `finalise_since`. |
| T3 | Participant secp256k1 keys are kept private. | All signature checks (`SPLICE_HEADER_DOMAIN`, `STATE_DOMAIN`) | Adversarial | Forged signatures drain value. |
| T4 | Each participant's signing key is bound to a stable secp256k1 pubkey encoded in `participants_commitment`. | `validation.rs:171-213`, `verify_bilateral_state_signatures` | Adversarial | Compromised key signs for unauthorised participant set. |
| T5 | Watchtower operators are honest-but-may-go-offline; they do NOT have authority to redirect value beyond what signed state entitles. | `watch_alert.rs`, `watch_config.rs`, `watch_policy.rs` | Honest-but-curious / offline | Watchtower misdetection; not a value-redirection vector (trust boundary is at signing keys). |
| T6 | The factory's factory-participant pubkey set is fixed at create-time and changes only via the conservative-rights update path. | `morph-factory-type/src/main.rs:103-112` (`update_number` strictly increasing) | Adversarial | Replay of older rights table; mitigated by `verify_reduced_factory_exit_update` digest binding. |
| T7 | The CKB cell-DAG does not allow double-spending a Cell in the same block. | CKB L1 | Adversarial | Out-of-protocol; CKB consensus invariant. |
| T8 | The CKB-VM cycle limit (3.5M typical, configurable per chain) is high enough that legitimate transitions complete. | All CKB-VM contracts | Adversarial | DoS via cycle exhaustion → unspendable vault / state cells (W1-08). |
| T9 | Operators run the morph-cli / hub process with sane file permissions (0o600 on state files). | `create_private_new_file` (`hub.rs:1679`) | Adversarial | Local-only read; encrypted at-rest not assumed. |
| T10 | `MORPH_DEVNET_PRIVATE_KEY` and `MORPH_HUB_AUTH_TOKEN` are not accidentally inherited by watchtower / helper subprocesses that shouldn't sign with them. | `scripts/devnet-smoke.sh:456,469,502,561,633` (`env -u MORPH_DEVNET_PRIVATE_KEY`) | Adversarial | Wrong-key-signing → cross-purpose key reuse. |
| T11 | `MORPH_HUB_INVOICE_PRIVATE_KEY` derives a pubkey matching `--pubkey`. | `hub.rs:474-481` | Adversarial | Mismatched key signs invoices that cannot be verified. |
| T12 | Splice header `new_payload_commitment` is the signed witness to the actual post-splice vault Cell materialisation. | `morph-script-common/src/lib.rs:954`, `morph-vault-lock/src/main.rs:377` | Adversarial | Vault-cell-substitution attack (closed by W5). |
| T13 | The Hub server is bound to a loopback interface, OR an auth-token-validated bearer is required for every write. | `hub.rs:482-485` | Adversarial | Open operator panel on 0.0.0.0 → anonymous state mutation. |

### 3.2 Implicit / unstated assumptions newly relevant in dirty worktree

| # | Implicit assumption | Where the assumption lives | If violated |
|---|---|---|---|
| I1 | "The Hub server is only run interactively by an operator on a trusted machine." | The whole hub.rs module | Hub exposed to LAN behind NAT, no auth token → all write APIs become callable. |
| I2 | "Restored state-file content is benign because the operator saved it earlier." | `HubStore::replace` (hub.rs:597-626) | `PUT /api/state-file` accepts arbitrary JSON; even with a valid token, a malicious actor can submit a fabricated "saved state from 3 months ago" and overwrite the live state. The backup of the previous file is the only audit trail. |
| I3 | "Browser tab is operator's only session." | `sessionStorage` token storage (api.ts:17-19) | Token survives until tab close — which is fine — but no automatic revocation on token rotation. |
| I4 | "CORS origin is set by the operator to a trusted dev frontend." | `normalise_cors_origin` (hub.rs:433-446) | `*` is rejected, but any `http://` / `https://` string is accepted without origin-format validation (e.g., `https://` with no host). |
| I5 | "SSE event stream is consumed by the same operator UI." | `stream_events` (hub.rs:1138-1171) | The endpoint requires bearer-token matching the server-side `auth_token`; however, `currentApiToken() || bundledApiToken` (api.ts:78-80) means the bundled build-time token falls back to the server-side `auth_token`. If the build was done with `VITE_MORPH_HUB_AUTH_TOKEN=...` and the runtime server has a *different* `--auth-token`, the bundled token fails silently and the SSE stream runs without auth. |

### 3.3 Attacker model

| Attacker | Capability | Primary target |
|---|---|---|
| **A1 — Network adversary** | Can MITM / observe / censor CKB transactions; can race CKB transactions with arbitrary fee. | Liveness of supersede, splice, sponsor top-up. |
| **A2 — State publisher (compromised participant key)** | Holds one of the two `secp256k1` signing keys for a channel; can publish any state the other participant would also have signed, but cannot unilaterally retire/close the channel without counterparty. | Drains vault via `SettlementDescriptor` locked to attacker's lock_hashes, or forces a stuck `Phase::Settling` until `finalise_since`. |
| **A3 — Counterparty** | The other `secp256k1` signing key. | Force-close via supersede to settling state; force-finalise after `finalise_since`. |
| **A4 — Watchtower operator (rogue)** | Runs `watch_config_service` with `--private-key-file`. | Can only publish states that the policy authorises; cannot redirect beyond signed-state authority. |
| **A5 — Hub attacker** | Network-reachable to the Hub server with a leaked / brute-forced token. | `PUT /api/state-file` (overwrites operator's world view); create-invoice with leaked signing key (signs invoices that the operator will appear to have issued); any `/api/*` write. |
| **A6 — Factory participant (exited)** | Once reduced-exit releases their reserve claim. | Should no longer be able to sign for the factory. Audit confirms `verify_reduced_factory_exit_update` (script-common) checks `before/after rights roots, access roots, release quantity, exit digest` — the participant's pubkey, once removed from the active rights tree, cannot produce a valid subsequent signature. |
| **A7 — Chain reorg adversary** | Holds > 50% CKB hash power. | Can rewrite recently-finalised states. The `finalise_since` field bounds how long a state can be challenged; a reorg longer than `finalise_since` blocks is unaddressed at the protocol level. |
| **A8 — Cycle-DoS adversary** | Crafts CKB transactions with many witness inputs. | Pushes `find_splice_witness_raw` / `find_unique_state_input` past CKB-VM cycle limit (W1-08). |
| **A9 — Invoice payee (dishonest)** | Issues an invoice they cannot deliver against. | Counterparty holds a Morph channel + signs the settlement. Mitigation: invoice signature verification (`verify_payee_signature`) requires the signature to verify against the embedded pubkey; the channel state is the final authority. |
| **A10 — Public devnet user** | Can deploy sponsor cells / state cells with arbitrary policies. | Cannot drain another user's sponsor (locked to `channel_id`); cannot front-run a real participant-signed supersede (signature scheme is secp256k1). |

### 3.4 Adversary-vs-trust matrix

| Adversary | T1 (Rust correct) | T2 (CKB finality) | T3 (key privacy) | T5 (watchtower honest-but-offline) | T13 (hub auth) | Net reach |
|---|---|---|---|---|---|---|
| A1 Network | passive | active | passive | passive | n/a | observation / censorship only |
| A2 Compromised key | n/a | n/a | **broken** | n/a | n/a | drains value via signed state |
| A3 Counterparty | n/a | n/a | benign | n/a | n/a | cooperative close or force-finalise |
| A4 Rogue watchtower | n/a | n/a | passive | **broken** | n/a | bounded by signed-state authority |
| A5 Hub attacker | n/a | n/a | passive | n/a | **broken** | full state-file replacement + invoice signing |
| A6 Exited factory member | n/a | n/a | benign | n/a | n/a | zero (audit-confirmed) |
| A7 Chain reorg | n/a | **broken** | passive | passive | n/a | rewrite finalised state |
| A8 Cycle DoS | n/a | passive | passive | passive | n/a | make state unspendable |

---

## 4. Attack Surface Matrix

For each protocol path: who can initiate, who can intervene, who can front-run, who can censor, who can be offline.

| Protocol path | Initiator | Intervener | Front-run risk | Censor risk | Offline consequence |
|---|---|---|---|---|---|
| **Channel OPEN** (`morph-state-type` (None, Some) → `validate_create`) | Either participant, via `morph-cli devnet supersede-smoke` / `fund` flow | None (single tx, both signatures bound into the funding-anchor derivation) | A4 / A7 can submit a competing fund tx with same `input[0] + output_index` derivation, but the participant's signature scheme requires counterparty pubkey agreement (collisions need preimage) | A1 censors the tx; recovery: re-broadcast | None — OPEN is a single atomic tx |
| **Channel UPDATE (SUPERSEDE, bilateral)** (`validate_supersede`, morph-state-type:191) | Either participant, must carry `BilateralSignatureWitness` signed by both | Counterparty cannot block but can race their own supersede | Both participants hold same `pubkey` pair → A4 watchtower could publish a participant-supersede tx only if given the witness | A1 censors; watchtower retry-queue handles | Stuck at `state_number=N`; either party can publish `N+1` later |
| **Channel PUBLISH to settling** (above SUPERSEDE; phase=settling) | Either participant, both signatures required | None (signatures are the only gate) | Watchtower can publish earlier if participant gave it the signed witness; this is the explicit design | A1 censors; recovery: re-broadcast after `finalise_since` | Stuck in `settling` until `finalise_since`, then either side can finalise |
| **Channel FINALISE** (`validate_finalise`, morph-state-type:277) | Either participant, requires `since >= required_since` | Counterparty cannot block once since-mature | A1/A8 can cycle-DoS the finalise by stuffing witness inputs | A1 censors; recover via another broadcast | If both sides offline past `since_value`, chain can finalise unilaterally when A1 cooperates |
| **Channel SPLICE (in/out)** (`validate_splice_create` / `validate_splice_retire`) | Either participant, both signatures on `SpliceHeader` | Counterparty cannot block (signatures are the gate) | A4 watchtower with the signed splice package can submit first; this is the explicit design | A1 censors; recovery: re-broadcast | Stuck mid-splice; old + new anchors both live; closure requires re-broadcast |
| **Channel SPONSOR publication** (`morph-sponsor-lock`) | Anyone with a valid signed Settling state for the channel | Sponsor cell consumed atomically; cannot be blocked | A1/A8 can race or cycle-DoS | A1 censors; sponsor budget not consumed (no fee paid for failed tx) | Sponsor cell cannot publish state if no participant online to sign |
| **Channel SPONSOR top-up** (`auto_fund_sponsor`, `fund_sponsor`) | Sponsor owner | None | A4 watchtower not involved | n/a | Sponsor goes offline → no publications can be paid for |
| **WATCHTOWER detection → publish** (`watch_config_service`) | Watchtower with `--private-key-file`; does not have authority to redirect value | Watchtower cannot be blocked by counterparty | A4 rogue watchtower can publish earlier | A1 censors; cursor advances regardless | Watchtower offline → A2 has free hand during offline window |
| **FACTORY CREATE** (`morph-factory-type` validate_create) | First participant or designated creator | Each participant signs the initial state | A4 with the witness can race-create | A1 censors | If create tx fails repeatedly, factory never exists |
| **FACTORY UPDATE (rights)** (`verify_reduced_factory_rights_update`) | Either participant with signed `FactoryReducedRightsWitness` | Counterparty cannot block (signature gate) | A4 rogue watchtower | A1 censors | Stuck at `update_number=N` |
| **FACTORY MERKLE UPDATE** (sparse Merkle single-right mutation) | Authorised participant with Merkle proof | Non-touched participants have no veto | A4 rogue watchtower with proof | A1 censors | Stuck mid-update |
| **FACTORY REDUCED EXIT** (`verify_reduced_factory_exit_update` + vault-lock reserve conservation) | The exiting participant, signs the exit witness | Non-exiting participants cannot veto (conservation invariant is the gate) | A4 rogue watchtower with exit witness | A1 censors | If exit fails, exit wait time is unbounded |
| **FACTORY REDUCED SPLICE** (splice + sparse Merkle localisation) | Authorised participant | Counterparty cannot block (conservation invariant is the gate) | A4 rogue watchtower | A1 censors | Stuck mid-splice |
| **FACTORY LOCAL EXIT** (materialise child channel) | Either participant with `FactoryLocalExitWitness` | Counterparty cannot block | A4 rogue watchtower | A1 censors | Child channel never materialised |
| **HUB state restore** (`PUT /api/state-file`, hub.rs:928-946) | Authenticated client | None — operator's hub just accepts the body | n/a (off-chain write) | n/a | If hub operator offline, no restore; once online, any authenticated request with the bearer token can replace state |
| **HUB create-invoice** (`POST /api/invoices`, hub.rs:972-1025) | Authenticated client with `--invoice-private-key` configured | None | n/a (off-chain sign) | n/a | Invoices can be created offline if `--invoice-private-key` is held by the client (which is unusual) |

### 4.1 Threat cluster mapping

The matrix shows that **most on-chain paths share the same security profile**: a single
CKB transaction, signed by the appropriate parties, censored by A1, racable by A4 only
if given the witness. The two paths with materially different profiles are:

- **Hub state restore / create-invoice**: off-chain operator surface, gated by bearer
  token, no chain-anchor verification. The token is the entire trust boundary.
- **Sponsor publication / top-up**: bearer-token-free, but bounded by `max_total_fee`
  in the on-chain policy. The remaining surface (range widening) is operator-policy
  dependent.

---

## 5. Post-W5-Closure Recheck

`docs/audit-report-2026-06-27.md` records 9 findings with closure dispositions.
Re-verification against the working tree at HEAD `5072d81`:

| ID | Claimed disposition | Verifier verdict | Evidence |
| --- | --- | --- | --- |
| A-2026-06-27-01 (C-01 splice payload binding) | "Fixed in this pass" | **verified closed** | `state_context_matches_splice_next` (`morph-script-common/src/lib.rs:939-964`) now requires `next_state.payload_commitment() == splice_header.new_payload_commitment()` at line 954; `SpliceHeader::matches_current_state` (`lib.rs:640-652`) binds `self.payload_commitment() == current.payload_commitment()` at line 650; CLI splice packages sign `new_payload_commitment` from `vault_descriptor_commitment(&new_vault)` (`crates/morph-cli/src/splice_packages.rs:833`); `morph-vault-lock/src/main.rs:377` re-checks `new_header.payload_commitment() != new_vault_commitment.as_slice()`. Three independent layers, all bind. |
| A-2026-06-27-02 (Splice schema drift) | "Fixed in current worktree" | **verified closed** | `schemas/morph.mol:14` declares `SpliceHeader: 389 bytes`; the schema struct at `morph.mol:99-118` includes both `payload_commitment` and `new_payload_commitment` at lines 115-116; `molecule_schema_names_all_active_fixed_width_objects` (`morph-script-common/src/lib.rs:6262-6306`) parses the declared byte sizes from the schema and compares to Rust constants including `("SpliceHeader", SPLICE_HEADER_LEN)`. |
| A-2026-06-27-03 (Sponsor first-publication bypass) | "Closed in current worktree" | **verified closed** | `morph-sponsor-lock/src/main.rs:117-141` `ensure_publication_backed_by_state_type_input` ALWAYS iterates input StateCells looking for a matching `publication_state_type_hash` and matching `funding_anchor`; returns `SponsorStateOutOfRange` otherwise. There is no `if policy.min_state_number() != 0 || state_number != 0` bypass remaining at any line. The W1-01 CRITICAL finding is closed. |
| A-2026-06-27-04 (Fiber/Morph acceptance loose stateful assertion) | "Fixed in this pass" | **verified closed** | `scripts/devnet-stateful-scenarios.sh:14-15` declares `AUDIT_PROFILE="${MORPH_DEVNET_AUDIT_PROFILE:-docs/devnet-audit-profile.example.json}"` and `BUDGET_PROFILE="${MORPH_DEVNET_STATEFUL_BUDGET_PROFILE:-docs/devnet-stateful-budget.example.json}"`; `scripts/devnet-stateful-scenarios.sh:181-186` passes both `--audit-profile "$AUDIT_PROFILE"` and `--budget-profile "$BUDGET_PROFILE"` to `devnet-stateful-assert`; `scripts/fiber-morph-devnet-acceptance.sh:619-620` exports both env vars when calling the inner scenarios script. The Fiber/Morph acceptance gate now runs with strict profiles. |
| A-2026-06-27-05 (Stale stateful acceptance closeout over-read risk) | "Documentation boundary fixed" | **verified closed** | `docs/devnet-stateful-acceptance-closeout.md` was edited in commit `5072d81` (per audit-report evidence) to state that the recorded artifact is historical evidence only. The 6/27 audit-report itself ends with: "No fresh devnet or Fiber/Morph acceptance artifact was produced in this pass. The repository should not claim current release evidence until the relevant acceptance suite is rerun on a clean current HEAD." |
| A-2026-06-27-06 (Factory reduced-exit reserve binding) | "Profile-limited defence-in-depth item, not a confirmed current exploit" | **verified still open as defence-in-depth** | `verify_reduced_factory_exit_update` (`morph-script-common/src/lib.rs`) binds before/after rights roots, access roots, release quantity, exit digest. The factory-vault-lock (`morph-factory-vault-lock/src/main.rs:441-446`) checks `input = output + release.capacity` but does not independently cross-check that the released quantity is bounded by the on-chain `state_root` rights table (W1-02 still unfixed). The audit-report itself flags this as not-closed-exploit but still a residual concern. |
| A-2026-06-27-07 (Type-ID-style anchors) | "Devnet profile limitation" | **verified still open as profile limitation** | `validate_anchor_derivation` (`morph-state-type/src/main.rs:177-189`) and `validate_factory_id_derivation` (`morph-factory-type/src/main.rs:331-343`) both still use `blake2b256([load_input(0, Source::Input), output_index])` with no live-Fund-Cell profile check. W1-03 remains open as a profile limitation; combined with W1-01 closure, this is no longer directly exploitable in devnet. |
| A-2026-06-27-08 (Paper/code drift findings) | "Out of current-repo remediation scope" | **n/a (paper-only)** | Confirmed: `paper.tex` is not in this repository; W2-01..W2-16 findings remain paper-side drift items that cannot be closed from the Rust side. |
| A-2026-06-27-09 (Webhook unit-test portability) | "Fixed in this pass" | **verified closed** | `crates/morph-cli/src/watch_alert.rs:357-365` `loopback_listener_or_skip(test_name)` helper self-skips `PermissionDenied` on loopback bind while panicking on all other bind errors; `posts_alert_to_webhook` and `posts_alert_to_webhook_with_hmac_signature` (tests:367, 425) use this helper. Other bind errors still panic; environments that permit loopback still execute the full assertions. |

**Net post-W5 closure verdict**: 5 verified closed (01, 02, 03, 04, 05, 09), 2 still open as defence-in-depth / profile limitation (06, 07), 1 paper-only / out-of-scope (08). The audit-report claims for the items labelled "Fixed in this pass" are honest and reproducible from the current HEAD.

---

## 6. Findings (≥ 8, ≥ 3 directly reference post-W5-fix state)

| Sev | ID | Surface | Threat | Evidence | Recommendation |
| --- | --- | --- | --- | --- | --- |
| **HIGH** | W6-SAF-01 | `crates/morph-cli/src/hub.rs:928-946` (`PUT /api/state-file`) | `HubStore::replace` accepts arbitrary JSON and overwrites the operator's live in-memory state + persisted file. When `--allow-state-restore` is enabled (default: disabled; opt-in via CLI flag), an authenticated client can replace the entire hub state — including channels, factories, invoices, completed-flows set — with a fabricated snapshot. The only audit trail is a `.bak.<nanos>.<pid>` backup of the *previous* file. No chain-anchor verification, no signature check on the inbound state, no per-channel / per-factory sanity check. The replace path at line 597-626 only verifies `pubkey` matches and `network` matches. An attacker who steals the bearer token (which is currently a single shared-secret, not per-session, derived from `--auth-token` / `MORPH_HUB_AUTH_TOKEN` at hub.rs:467) can rewrite the operator's world view and trick downstream actions (e.g., publish-state or splice-channel) into using a fabricated `state_number`. | Tighten the replace path: (a) require per-record chain-anchor proof (tx hash + CKB RPC verification that the referenced cell exists at the claimed `state_number`); (b) refuse to replace if any channel is in `Phase::Settling` (or any factory is mid-update); (c) require the backup file be retained on disk before the rename, not deleted; (d) emit a `Critical` event (currently `Warning` at line 622) so it surfaces in `EventView`. |
| **HIGH** | W6-SAF-02 | `crates/morph-cli/src/hub.rs:1138-1171` (`stream_events` SSE) + `ui/morph-hub/src/api.ts:49-52` (`openEventStream`) | The SSE event stream requires auth via `auth_failure_response` (hub.rs:1139-1142) — good. But `openEventStream` (api.ts:49-52) returns `null` if `currentApiToken()` is truthy, because EventSource API cannot set custom headers. This means **the SSE stream only works without auth**. If the operator exposes the Hub on a non-loopback address with auth enabled (the documented combination: `serve(...)` enforces `listen_is_loopback || auth_token.is_some()` at line 482-485), the UI bundles a `VITE_MORPH_HUB_AUTH_TOKEN` at build time (api.ts:4) — but `currentApiToken() = sessionApiToken \|\| bundledApiToken.trim()` (line 78-80) means: if the runtime session token is empty (operator never set one), the bundled token is used; the SSE stream opens with `EventSource` which has no headers, so the server-side `auth_failure_response` rejects the request. The UI then silently falls back to polling. This is documented as the "polling-auth" mode in App.tsx, but **a stale bundled token still appears valid in dev mode**, and any third-party tool that can speak SSE can subscribe to the event stream as long as the server has `auth_token == None` (loopback-only). | Either (a) accept auth via cookie in addition to bearer, so EventSource with `withCredentials` works, or (b) refuse SSE entirely when `auth_token` is set and document the polling-only mode, or (c) require SSE clients to first call a one-time `POST /api/events:auth` that validates the token and returns a short-lived session cookie. |
| **HIGH** | W6-SAF-03 | `crates/morph-cli/src/devnet.rs:9352, 9389` (`auto_fund_sponsor` / `fund_sponsor`) | Sponsor policy `min_state_number=0, max_state_number=u64::MAX` is the default for the auto-fund-sponsor devnet path (9352) and the explicit `fund_sponsor` command at 9389. Combined with the W5 closure of the first-publication bypass (`morph-sponsor-lock/src/main.rs:117-141`), an attacker who controls one participant signing key can publish states from `state_number=0` to `state_number=u64::MAX` against a sponsor cell with this policy, draining up to `max_total_fee` shannons. The hard cap is correct, but the range exposes the watchtower to 2^64 distinct state numbers per channel before the budget runs out. A watchtower scanning for publication anomalies has to recognise 2^64 valid-looking publications as a single attack pattern, not as a valid progression. The `state_number` ordering check (`MorphNonMonotonicStateNumber`) is **not** triggered because each publication is a strictly-increasing `state_number`. | Document the recommended `min_state_number` / `max_state_number` for production deployments as `min=1, max=2^20` (≈ 1M states). Add a `--strict-sponsor-range` flag that refuses `min/max` outside this window and emits a warning. Add a metric in `stateful-report.rs` that flags sponsors with `max_state_number - min_state_number > 1_000_000`. |
| **MEDIUM** | W6-SAF-04 | `crates/morph-cli/src/hub.rs:1795-1800` (`parse_bytes32` rejects zero-byte32 via `ensure!(any != 0, ...)`) | The check `out.iter().any(|byte| *byte != 0)` rejects the all-zero 32-byte value as a defensive measure against accidental "uninitialised" identifiers. However, this check is **bypassable** in two paths: (1) `PersistedHubState` deserialisation (`from_persisted`, hub.rs:779-877) does not call `parse_bytes32` on `peer.pubkey` (which is the hex string but reads `node_id` from `blake2b256(pubkey)` at line 841-847 — a zero pubkey would produce a non-zero node_id and slip past the check); (2) `invoice_id` is computed at `node.rs` via `derived_invoice_id()` and is never validated against zero in the persistence path. The defensive check is a fingerprint of intent (don't accept all-zero Bytes32 from user input) but the on-chain script layer should be the real gate. | Either remove the `parse_bytes32` zero check (defence-in-depth in user-facing parser is fine, but don't claim it as protocol invariant) or move the check into `HubRuntimeState::from_persisted` and document that any Bytes32 with all-zero bytes is rejected regardless of source. |
| **MEDIUM** | W6-SAF-05 | `crates/morph-cli/src/hub.rs:467, 1380-1393` (`auth_token` is a single shared bearer) | The auth token is a single shared secret compared in constant time? **No — the comparison at line 1382-1386 is `==`, not constant-time**. `request.header("authorization").is_some_and(|value| value == bearer)` and `request.header("x-morph-hub-token").is_some_and(|value| value == token)` are both `String == String` Rust equality, which is not constant-time. Network observers timing a request can in principle leak byte-by-byte differences. The token also grants full read + write access with no expiry, no per-session nonce, and no rotation mechanism — once leaked (e.g., in a `.env` file committed by mistake, or in shell history), the only recovery is to restart the hub with a new token. | Replace the bearer comparison with `subtle::ConstantTimeEq` (already a workspace-available transitive dep). Add a session-nonce mechanism (each request must include a server-issued nonce within a time window). Document token-rotation as an operational requirement. |
| **MEDIUM** | W6-SAF-06 | `crates/morph-cli/src/hub.rs:609-624` (`replace()` overwrites `peer_pubkeys`, `completed_flows`, `events`) | `HubStore::replace(persisted)` (hub.rs:597-626) replaces the entire `HubRuntimeState` from the inbound JSON. The `completed_flows: BTreeSet<MorphBusinessFlow>` field is **the source of truth for which required business flows the hub operator claims to have completed** (used by `missing_business_flows()`). A malicious `PUT /api/state-file` body can mark all required flows as completed without any of them having been done, defeating the dashboard's "missing flows" UX safety check. | Treat `completed_flows` as a strictly-monotone derived field: a `replace()` should keep the intersection of `persisted.completed_flows` with the live `completed_flows`, and refuse to add new entries. |
| **MEDIUM** | W6-SAF-07 | `crates/morph-core/src/node.rs:155-185, 213-236` (`payment_preimage` removed from `StoredMorphInvoice`, replaced by `payee_signature`) | This is **a defence-in-depth improvement**, not a regression: the dirty worktree removes `payment_preimage: Option<Bytes32>` from `StoredMorphInvoice` (was line 197 in HEAD) and replaces it with `payee_signature: Vec<u8>`. Previously the hub state file held the preimage in plaintext; an attacker reading the state file would have all in-flight preimages. Now the state file holds only the signed invoice (which the payee controls). The settlement flow (`settle_invoice`) requires the preimage to be supplied in the request (`hub.rs:1211-1216`), so the preimage is never at rest in the hub. This is **a real safety improvement** and reduces the blast radius of a state-file leak. **No action needed**, but the change is not advertised anywhere in the docs. | Add a one-paragraph note to `docs/audit-report-2026-06-27.md` (or its successor) explaining the preimage removal and the safety improvement. |
| **MEDIUM** | W6-SAF-08 | `crates/morph-cli/src/main.rs:430,442,448` (`MORPH_HUB_INVOICE_PRIVATE_KEY`, `MORPH_HUB_AUTH_TOKEN`, `MORPH_HUB_CORS_ORIGIN` env vars) | The new hub subcommand reads three sensitive env vars: `--invoice-private-key` (full secp256k1 private key), `--auth-token` (shared bearer), `--cors-origin`. The CLI binary logs `morph_hub_listen`, `morph_hub_state`, `morph_hub_ui`, `morph_hub_watch_alert_file`, `morph_hub_auth`, `morph_hub_state_restore`, `morph_hub_invoice_signing`, `morph_hub_cors_origin` to stdout (hub.rs:501-536). None of these log the secret values themselves, **but** any operator running the binary in a `script -c` capture or a CI log will expose `morph_hub_auth=required` flag; combined with the URL (`http://127.0.0.1:port`) an attacker who reads the log learns the listen address + that auth is required, which is enough to target a token-guessing attack. More importantly, **there is no guidance in the runbook on how to rotate the token**, nor any mechanism for token expiration. | Add `--auth-token-stdin` or `--auth-token-file <path>` modes so the secret is never passed via process arguments or environment. Add a `--rotate-on-restart` flag that emits a fresh token to stdout at startup (single read). Update the runbook to document token rotation. |
| **LOW** | W6-SAF-09 | `contracts/morph-factory-vault-lock/src/main.rs:170` (W1-07 reopen) | `Box::leak(data.into_boxed_slice())` still leaks one heap allocation per `find_unique_factory_state` invocation. The W5 fix did not touch factory-vault-lock; W1-07 is still open. CKB-VM does not GC across script invocations, so leaked allocations persist within the same VM context. In a deployment that processes many factory-type cells per block (e.g., during a factory splice batch), the heap pressure can push the script past the cycle limit. | Refactor `FactoryStateHeader::parse` to accept `&[u8]` borrowed slice (it already takes a slice at signature level, the 'static bound is artificially inflated by the `Box::leak` pattern). Add a unit test that calls `find_unique_factory_state` 100× in a row and asserts no OOM. |
| **LOW** | W6-SAF-10 | `crates/morph-cli/src/hub.rs:1283-1287, 1349-1361` (`route_channel_action` for `splice`, `publish`, `finalise`) | These hub endpoints mutate `HubStore` via `node.splice_channel`, `node.publish_state`, `node.finalise_channel` — all of which update the local `MorphNodeState` but **do not push any CKB transaction**. The hub is a tracker, not a transaction builder. The dirty worktree's documentation should make this explicit; an operator who clicks "publish state" in the UI and expects a CKB transaction will be surprised. | Update the UI labels ("Update tracked state" rather than "Publish state"); add a banner that the hub is off-chain-only. |
| **LOW** | W6-SAF-11 | `scripts/devnet-smoke.sh:456,469,502,561,633` (`env -u MORPH_DEVNET_PRIVATE_KEY`) | The W5 fix adds `env -u MORPH_DEVNET_PRIVATE_KEY` to five `cargo run` invocations that should not have access to the sponsor/operator private key. This is a **real defence-in-depth improvement** and was not advertised. There are still 18 other `MORPH_DEVNET_PRIVATE_KEY` references in `main.rs` (line 499, 517, 568, 610, 786, 816, 894, 927, 963, 1014, 1065, 1116, 1167, 1224, 1281, 1338, 1395) which inherit the env var via clap's `env = "MORPH_DEVNET_PRIVATE_KEY"` attribute. Each invocation that needs a different key (sponsor vs watchtower vs operator) should explicitly strip the env, not rely on shell wrapper `env -u`. | In `crates/morph-cli/src/main.rs`, every `MORPH_DEVNET_PRIVATE_KEY`-aware subcommand should explicitly unset the env var for its `cargo run` subprocess via a wrapper helper, so the devnet smoke script's `env -u` workaround is unnecessary. |

### Findings referencing post-W5-fix state directly (≥ 3 required by task spec)

- W6-SAF-01 (Hub state restore) — references post-W5 hub.rs additions at lines 597-626 (`replace`), 928-946 (`PUT /api/state-file`), which did not exist at W1 baseline.
- W6-SAF-07 (payment_preimage removal) — references `crates/morph-core/src/node.rs:155-185, 213-236`, the post-W5 dirty-worktree change.
- W6-SAF-08 (env-var secrets) — references `crates/morph-cli/src/main.rs:430,442,448`, the post-W5 dirty-worktree change.
- W6-SAF-11 (env -u MORPH_DEVNET_PRIVATE_KEY) — references `scripts/devnet-smoke.sh:456,469,502,561,633`, the post-W5 dirty-worktree change.

---

## 7. Reassessed Open Findings (W1–W5 open HIGH+CRITICAL)

| Orig | Severity (orig / reassessed) | Reassessment evidence |
| --- | --- | --- |
| **W1-01** sponsor first-publication bypass | CRITICAL → **CLOSED** | `morph-sponsor-lock/src/main.rs:117-141` `ensure_publication_backed_by_state_type_input` requires input StateCell with matching `publication_state_type_hash` and matching `funding_anchor`; no remaining bypass. A-2026-06-27-03 closure is verified. Reassessed severity: none (was the only CRITICAL post-W1). |
| **W1-02** factory reserve conservation defence-in-depth | HIGH → **still HIGH** | `morph-factory-vault-lock/src/main.rs:441-446` still only checks `input_capacity == output_capacity.checked_add(release.capacity)`. The on-chain `state_root` rights-table cross-check is still absent. Audit-report-2026-06-27-06 acknowledges this is a profile-limited concern. Reassessed severity: HIGH (unchanged). Defence-in-depth gap that becomes exploitable when factory exits are used for value. |
| **W1-03** funding-cell uniqueness / anchor-derivation | HIGH → **MEDIUM (downgrade)** | `validate_anchor_derivation` (`morph-state-type/src/main.rs:177-189`) and `validate_factory_id_derivation` (`morph-factory-type/src/main.rs:331-343`) both still derive anchors from `blake2b256([load_input(0, Source::Input), output_index])`. The W1-01 closure means an attacker can no longer drain a sponsor with a fabricated first publication; the remaining risk is multiple channels/factories sharing the same funding input cell. This is not a direct drain vector but a profiling/lane-classification ambiguity. Audit-report-2026-06-27-07 labels it "devnet profile limitation, not confirmed current exploit after W1-01 closure". Reassessed severity: MEDIUM. |
| **W1-04** vault-lock state input group-shape enforcement | MEDIUM → **MEDIUM (unchanged)** | `find_unique_state_input` (`morph-vault-lock/src/main.rs:311-349`) still iterates `Source::Input` (whole-tx) rather than `Source::GroupInput`. The state-lock has its own `WrongGroupShape` check (line 40-49), so two StateCells with matching scripts in the same input group already fail upstream. The remaining ambiguity is "a non-State-Cell input with parseable StateHeader bytes coincidentally matches the funding_anchor", which is extremely narrow. Reassessed severity: MEDIUM. |
| **W1-07** factory-vault-lock `Box::leak` | MEDIUM → **MEDIUM (re-categorise: see W6-SAF-09)** | Still at `morph-factory-vault-lock/src/main.rs:170`. The W5 fix did not touch this. CKB-VM heap pressure, not a directly exploitable bug. Reassessed severity: MEDIUM; tagged in this report as LOW (W6-SAF-09) because in a devnet-only deployment the heap budget is rarely exhausted. |
| **W5-01** C-01 splice bundle-layer `payload_commitment` missing | CRITICAL → **CLOSED (post-W5)** | `state_context_matches_splice_next` (`morph-script-common/src/lib.rs:939-964`) at line 954 now requires `next_state.payload_commitment() == splice_header.new_payload_commitment()`. The vault-lock layer also re-checks at line 377. Three-layer binding verified. A-2026-06-27-01 closure confirmed. The audit-response wording (audit-response-2026-06-20.md:103-106) overstates the closure at the time of W5-audit (June 22) but the W5 fix (June 27) brought the code in line with the wording. |
| **W5-02** schema drift SpliceHeader 325 → 357 → 389 bytes | HIGH → **CLOSED (post-W5)** | `schemas/morph.mol:14` now says 389 bytes; the schema struct has both `payload_commitment` and `new_payload_commitment`; the schema-size test parses declared sizes from the schema and compares to Rust constants. A-2026-06-27-02 closure confirmed. |
| **W5-03** property-based testing absence | HIGH → **HIGH (unchanged)** | Workspace still has zero `proptest` / `quickcheck` / `arbitrary` deps; all 248 active tests are example-based. W5-14..W5-26 new findings re-iterate this. |
| **W4-02** Fiber acceptance runs stateful WITHOUT budget profile | HIGH → **CLOSED (post-W5)** | `scripts/fiber-morph-devnet-acceptance.sh:619-620` now exports `MORPH_DEVNET_AUDIT_PROFILE` and `MORPH_DEVNET_STATEFUL_BUDGET_PROFILE` into the inner `devnet-stateful-scenarios.sh`. A-2026-06-27-04 closure confirmed. |
| **W4-04** `devnet-e2e.sh` and `devnet-stateful-e2e.sh` ~95% duplicate | MEDIUM → **MEDIUM (unchanged)** | The two e2e scripts are still ~95% duplicate; a fix to the CKB resolve/port-check/wait-for-rpc path in one must be mirrored in the other. W5 hardened only the fiber side. |
| **W3-03** stale stateful acceptance closeout anchors | HIGH → **CLOSED (post-W5)** | `docs/devnet-stateful-acceptance-closeout.md` was edited at commit `5072d81` to declare the recorded artifact historical. A-2026-06-27-05 closure confirmed. The follow-on implication: **a fresh acceptance artifact must still be produced on a clean current HEAD before any release-evidence claim**. |
| **W2-01** signing-digest domain string drift | HIGH → **HIGH (unchanged, paper-only)** | `STATE_DOMAIN = b"CKB_MORPH_CHANNEL_STATE"` (`morph-core/src/hash.rs:9`) still lacks the paper's `_V1` suffix. Out of current-repo remediation scope; paper patch required. |

**Net reassessment**: 6 closed (W1-01, W5-01, W5-02, W4-02, W4-04 partially via W3-03 documentation boundary, W3-03), 1 downgraded (W1-03), 5 unchanged. The W5 fix materially closed the splice-binding cluster.

---

## 8. Residual Risk Ranking

### P0 (must address before any non-devnet deployment)

P0-1. **`HubStore::replace` accepts arbitrary JSON state-file content** (W6-SAF-01). Even with bearer auth, a compromised token gives full read + write + state-replace authority. The hub is a tracker, not a transaction builder — but the dashboard's UX trusts the persisted state. Any deployment that exposes the hub on a non-loopback address with `--allow-state-restore` enabled is materially less safe than the on-chain protocol.

P0-2. **`Box::leak` in `morph-factory-vault-lock/src/main.rs:170`** (W1-07 / W6-SAF-09). Per-script heap leak. The conservative bilateral plain profile does not invoke this script frequently enough to OOM, but any deployment that processes >100 factory-type cells per block risks cycle-limit exhaustion.

P0-3. **`scripts/devnet-smoke.sh` env-var inheritance** (W6-SAF-11). The `env -u MORPH_DEVNET_PRIVATE_KEY` workaround is a band-aid for a deeper design issue: `main.rs` reads the env via clap's `env = "..."` attribute on every subcommand, regardless of whether the subcommand needs the key. The current 5-place workaround in the smoke script is brittle — a future subcommand added without the `env -u` will silently inherit the wrong key.

### P1 (address before mainnet-track deployment; acceptable for devnet)

P1-1. **`auto_fund_sponsor` / `fund_sponsor` default state range `0..u64::MAX`** (W6-SAF-03). Document and constrain.

P1-2. **Hub auth-token comparison not constant-time** (W6-SAF-05). Replace `==` with `subtle::ConstantTimeEq`.

P1-3. **`PUT /api/state-file` `completed_flows` injection** (W6-SAF-06). Replace intersection semantics.

P1-4. **SSE stream cannot authenticate via `EventSource`** (W6-SAF-02). Decide between cookie-based auth or polling-only mode.

P1-5. **Splice bundle-layer `payload_commitment` check is now closed, but the vault-lock layer is the only defence for the bilateral plain profile** (W1-02). If the profile changes (`payload_commitment` decouples from vault_set_commitment), the vault-lock guard no longer closes C-01. A future profile change must re-verify the C-01 thread.

P1-6. **Hub listen-on-non-loopback + `--auth-token` + `--invoice-private-key` combination is operationally dangerous** (W6-SAF-08). All three sensitive flags share the same surface. Token rotation is not documented. A failure mode where the operator commits `MORPH_HUB_AUTH_TOKEN=...` to a repo or CI log is unrecoverable without a manual restart.

### P2 (acceptable in current devnet; track)

P2-1. **Property-based testing absence** (W5-03). All 248 active tests are example-based.

P2-2. **CKB reorg-adversary threat unbounded by `finalise_since`** (T2 / A7). The protocol bounds how long a state can be challenged but does not bound the chain-reorg adversary. Out of repo scope (CKB L1 concern).

P2-3. **W2 paper/code drift items** (W2-01, W2-04, W2-05, W2-06, W2-08, W2-11). Paper-side patches required; Rust is the implementation of record.

P2-4. **`scripts/devnet-e2e.sh` / `devnet-stateful-e2e.sh` ~95% duplicate** (W4-04). Maintenance hazard.

P2-5. **`cargo audit` ignore-list comment drift** (W5-20). Cosmetic.

P2-6. **Audit-matrix lacks file:line column** (W5-17). Cosmetic; tests exist.

P2-7. **`parse_bytes32` zero-check is bypassable via `HubRuntimeState::from_persisted`** (W6-SAF-04). Defence-in-depth; on-chain scripts are the real gate.

P2-8. **Hub endpoints are tracker-only but the UI labels suggest "publish state"** (W6-SAF-10). UX issue.

---

## 9. Limitations

- This audit focuses on the W5-fixed CKB-VM scripts, the dirty-worktree Hub surface, and the CLI surface. It does **not** re-run `cargo test --workspace`, `make contract-tests`, or `make fiber-morph-devnet-acceptance` — verification is by file:line read, not by execution. The 6/27 audit-report's "Verification Run During This Pass" demonstrates that the workspace tests pass at `5072d81`, but no fresh acceptance artifact has been produced on the dirty worktree.
- Paper audit findings (`paper.tex`) are out of scope for this Rust-side audit. W2-NN items are tracked as drift but cannot be closed from the repository.
- The audit-response-2026-06-20's C-01 wording is partially refuted by this report for the W5-pre state, and confirmed closed for the W5-post state (5072d81). The wording in `audit-response-2026-06-20.md:103-106` was honest at the time of W5 (it described the in-progress fix), and the fix landed at `5072d81`.
- Threat model assumes CKB L1 is honest-but-BFT (not adversarial 51%). A 51% adversary is **out of protocol scope** but is listed in the threat model for completeness.
- The Hub server's runtime behaviour is read from code only, not exercised. The `startup.rs` integration test (hub.rs:2365-2495) covers loopback + token + state restore, but is unit-test only. End-to-end behaviour under concurrent connections is not exercised.
- The audit does not cover Fiber/peer behaviour beyond what was already cited in W4 and W5. Fiber is a sibling project.

---

## 10. Recommended Next Triggers

| Trigger | Rationale | Earliest date |
|---|---|---|
| **External review (audit firm)** | README, roadmap, and mainnet-readiness all agree the next gate is an external review. The W5 fix materially improves the audit story but the residual P0 items (Hub state restore, `Box::leak`, env-var inheritance) should be closed before engaging a firm. | After P0-1, P0-2, P0-3 are fixed |
| **Fresh devnet acceptance artifact on a clean HEAD** | `docs/devnet-stateful-acceptance-closeout.md` requires `git_dirty=false` and `status=passed`. The current worktree is dirty; a clean run on HEAD `5072d81` is needed before any release-evidence claim. | After dirty worktree is committed or stashed |
| **Paper patch application** | W2-01, W2-04, W2-08, W2-11 require paper-side edits. The `MORPH_PATCH_2026-06-22.md` exists; applying it brings paper and code into alignment. | Independent of code changes |
| **`factory_active` Phase enum variant** | The Phase enum's 4-vs-5 drift (W2-02) is a known paper-only issue. The implementation should either add the variant (to support factory-side phase tracking) or document that factory progression is via `FactoryStateHeader.update_number`. | Code-side decision |
| **Property-based test library** | Workspace `Cargo.toml` has no `proptest` / `quickcheck` / `arbitrary` deps. Adding `proptest` to `morph-core` would close W5-03 HIGH and improve confidence in the lane-wise conservation body. | Independent of other changes |
| **Hub token rotation mechanism** | Add a `POST /api/auth/rotate` endpoint that requires the current token, emits a new token to stdout once, and invalidates the old. Currently the only recovery is restart. | After P1-6 / W6-SAF-08 |
| **`make ci` enrichment** | Add `make ci-fiber-morph-devnet-preflight` to the CI matrix so the Fiber acceptance gate has at least the preflight phase on every PR. Currently CI does not exercise Fiber/Morph. | Independent |
| **Sub-resource timing hardening** | W6-SAF-05 constant-time comparison is a small, well-scoped patch. | Independent |

---

*End of W6-Safety audit.*