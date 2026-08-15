# Swarm Audit — GLM — v1.11.0 — 2026-08-15

A comprehensive eight-agent (A–H) review of tag `v1.11.0` (commit `cc3efe2`,
clean tree). Scope: regression verification of every finding in
`docs/swarm-audit-glm-2026-08-15.md` (baseline `9ab9ec1`), plus a fresh
review of everything that landed since — the splice withdrawal-destination
binding (`1cc830f`), Factory v1 pre-production hardening (`5d2f19a`), the
dynamic N-party factory (`9c5b727`), compatibility-layer removal (`6297b4e`),
the v1.10.0 publication-reliability controller, and the v1.11.0 fee
convergence follow-up. Read-only audit: no source modified, no commits made.

Local gates re-run at this revision and **all green**: `make fmt-check`,
`make source-hygiene`, `make lint` (clippy `-D warnings`), `make test`
(zero failures across all crates), `make fixture-checks`.

## 0. Executive Summary

| Severity | Count | IDs |
| --- | --- | --- |
| High | 0 | — |
| Medium | 3 | V2-01 … V2-03 |
| Low | 14 | V2-04 … V2-17 |
| Info | 16 | not renumbered; see §4 |

**Verdict:** the previous High (AUD-01) and three Mediums (AUD-03/04/05) are
genuinely **fixed end-to-end** — signed field, on-chain enforcement in both
vault locks, host-side parity, Molecule schema, fixture builders, hash-parity
tests, and real substitution negative tests were each independently verified
by up to four agents. AUD-02 is now a documented, release-manifest-pinned
trust boundary with its hash-mismatch negative test. No new fund-loss path was
found in the contract or core-protocol layer.

The three new Mediums sit in the surfaces this release actually shipped:
two Hub exposure-class issues (slowloris-resistant-by-config only; an
opt-in build path that bakes the API token into the unauthenticated static
bundle) and one accounting flaw in the new publication controller (stale chain
tip during long rescans over-credits the "absolute" challenge deadline,
eating the reorg/failover/safety reserve the changelog advertises).

**Release-note correction required:** CHANGELOG v1.10.0 claims "the seven CKB
contract sources and wire formats are unchanged by this … release", but
`git tag --contains 1cc830f` shows the withdrawal-binding wire break
(`SpliceHeader` 453→485, `FactorySpliceHeader` 437→469, splice witness
versions → 2) **is contained in v1.10.0**, and
`release/factory-preproduction/README.md` itself attributes
withdrawal-binding semantics to the v1.10.0 manifest refresh. See V2-11.

## 1. Regression verification (prior audit @ `9ab9ec1`)

| Prior ID | Sev | Status | Evidence |
| --- | --- | --- | --- |
| AUD-01 | High | **FIXED** | `withdrawal_lock_hash` at `SpliceHeader` offset 453..485 and `FactorySpliceHeader` 437..469, inside both signing digests (`morph-script-common/src/lib.rs:809-815`, `:2530-2536`); kind rules splice-in⇒zero / splice-out⇒non-zero in all three verify paths (`lib.rs:1002-1008`, `:2973-2979`, `:3021-3027`); on-chain output binding with exact amount/shape and uniqueness in `morph-vault-lock/src/main.rs:413-478` and `morph-factory-vault-lock/src/main.rs:379-449` (both kind 6 and 7); host parity `morph-core/src/validation.rs:321-329,627-635,747-755`; negative tests `contract_scripts.rs:8243` (bilateral substitution), `:4294` (factory reduced substitution), `:8250`/`:4302` (typed-CKB withdrawal), `invariants.rs:856`, `:1179`; schema `schemas/morph.mol` updated; witness versions bumped to 2 to prevent cross-version replay. Four agents independently walked the layouts — exactly exhausted, no gaps. |
| AUD-02 | Medium | **ACCEPTED + DOCUMENTED** | Mechanism unchanged by design: `morph-state-type/src/main.rs:471-500` delegates factory authority to the args-committed FactoryType hash (input-0 type check `:484-489`), no in-script signature verification. Since the last audit: trust boundary documented in `SECURITY-FIXES.md:12-40`, audited factory-type data hash frozen in `release/factory-preproduction/contracts.json:24-29`, negative test `state_type_rejects_factory_exit_without_bound_factory_authority` (`contract_scripts.rs:6527`), bilateral/factory args-mode confusion rejected (`main.rs:430-441`), anchor containment re-verified. Residual (self-committed permissive hash ⇒ fresh child identity only) is the documented deployment pinning responsibility. Downgraded to Low/accepted. |
| AUD-03 | Medium | **FIXED** | `morph-vault-lock/src/main.rs:112` — v1-descriptor settlement branch now calls `ensure_no_group_xudt(Source::GroupInput)` plus descriptor-version pin (`:107-111`); XUDT branch strict (`:272-282`). Negative test `vault_lock_rejects_ckb_only_settlement_with_typed_vault_input` (`contract_scripts.rs:7718`) re-commits the header over the typed cell and is still rejected. |
| AUD-04 | Medium | **FIXED** | `morph-core/src/validation.rs:277` — `current.phase != Active || splice.next_state.header.phase != Active` → `SpliceStateNotActive`; test `splice_rejects_non_active_successor` (`invariants.rs:847`). |
| AUD-05 | Medium | **FIXED** | `morph-core/src/validation.rs:742-746` — reduced path rejects unbound old / pre-bound new `vault_outpoint_commitment`, identical to full path and script (`lib.rs:3016-3017`); test `reduced_factory_splice_rejects_unbound_vault_lifecycle` (`invariants.rs:1160`). |
| A-01 | Low | OPEN | `lib.rs:3772-3829` — commitment helpers still hash `&[u8]` inputs without 32-byte length assertions. No variable-length caller today; hardening only. |
| A-02 | Low | **FIXED (splice verifiers)** | `verify_factory_splice_update` (`lib.rs:2958-2966`) and reduced (`:3006-3014`) now run `validate_profile()` + update-number monotonicity; both locks also enforce on-chain (`morph-factory-type/src/main.rs:70,151-152`). Reduced rights/merkle/exit verifiers still rely on the co-executing locks (unchanged, defense-in-depth). |
| B-02 | Low | OPEN | `morph-state-type/src/main.rs:32` — 64-input cap applies to vault-reference scans (`:530,:573,:613`) but not `find_unique_state_cell` (`:645-676`) nor the anchor/dep scans. Fail-closed liveness asymmetry only. |
| C-04 | Low | OPEN | `morph-vault-lock/src/main.rs:485-487` — witness scan still capped at 64; >64-witness splice txs rejected outright (fail-closed, composability limit). |
| C-05 | Low | OPEN | `morph-vault-lock/src/main.rs:58,96` — non-canonical `min_since` in vault args still only detected at settlement; splice paths byte-compare only (`:587-589`). Self-griefing. |
| D-02 | Low | OPEN (exit kinds only) | `morph-factory-vault-lock/src/main.rs:88`, `lib.rs:2215` — exit paths compare witness participants against the new header only; **splice paths now compare against both headers** (`lib.rs:2987-2990`, `:3038-3041`). Composition-safe via factory-type `same_context_except_progress`. |
| E-03 | Low | OPEN, **re-scoped** | The public `morph-core` reduced-splice validator does not independently repeat two package/script checks, but the shipped CLI package path requires unchanged manifest roots and re-derives the contract digest before calling it. No CLI acceptance divergence was demonstrated; see V2-04. |
| E-04 | Low | OPEN | `backend.rs:356-386` — `cancel_payment` still lacks the intent-expiry bound `commit_payment` enforces (`:290-294`). |
| E-05 | Low | OPEN | `bridge.rs:434-480` — `SovereignEdgeRegistry::refresh` still fetches reservations without `reservation.validate(now_unix)` (contrast `activate` `:385-386`) and passes `enforce_reservation_quantity: false`. |
| E-06/H-02 | Low | LARGELY FIXED | `hash_parity.rs` now asserts `VAULT_OUTPOINT_COMMITMENT_DOMAIN` and covers `withdrawal_lock_hash` in both splice digests, descriptor/delta commitments. Residual: no output-level parity for `funding_context_id` (`hash.rs:65-80` vs `lib.rs:3814-3829`), `vault_cell_commitment`, `factory_participants_commitment`, FactoryStateHeader signing digest, and the host's second sparse-Merkle implementation (`validation.rs:970`). |
| F-01 | Low | OPEN | high-S ECDSA still accepted by core verifiers (`validation.rs:247,452,910,960`; `node.rs:354`) and scripts; only agent paths reject (`agent.rs:465-469`, `morph-agent/src/protocol.rs:350`). No bypass; malleability/dedup hygiene. |
| F-02 | Low | PARTIAL | Hub bounds expiry to 7d (`hub.rs:38,1449-1450`); core (`node.rs:250-252,308-310`) and CLI `new-invoice` (`main.rs:3970-3973`) still lower-bound only. |
| G-01 | Low | ACCEPTED (documented) | sponsor `already_spent` host-tracked; matches the documented script/operator policy split. |
| G-02 | Low | OPEN | `morph-sponsor-lock/src/main.rs:117-143` — backing StateCell input still matched by type+anchor without `channel_id`. |
| H-01 | Low | PARTIALLY FIXED | fixture builders still hand-roll offsets but all three now perform build-then-parse round-trips (`splice_packages.rs:1345-1361`, `factory_packages.rs:3005-3057`), so offset drift fails closed. |
| H-05 | Low | OPEN | `invariants.rs:729-804` — still exactly three proptest cases, StateHeader-only; splice conservation/envelope parsing unfuzzed. |

`SECURITY-FIXES.md` boundary spot-checks (6 boundaries) all cite tests that
exist and genuinely assert rejection. Makefile target graph coherent.

## 2. Medium

### V2-01 — Hub: per-read timeout only; a slow request head can pin every connection slot (slowloris)

- **Files:** `crates/morph-cli/src/hub.rs:1291-1298` (timeouts), `:2626-2653`
  (`read_limited_line` loop), auth at `:1302` only after the full head.
- **Evidence:** `set_read_timeout(Some(REQUEST_IO_TIMEOUT))` bounds each
  individual `fill_buf`, not the total request time. `read_limited_line`
  loops `fill_buf` with byte-budget but no deadline; authentication runs only
  after the head completes.
- **Scenario:** hub bound non-loopback with `--auth-token`; an unauthenticated
  remote attacker opens `MAX_CONCURRENT_CONNECTIONS` sockets and trickles one
  byte per interval shorter than the read timeout. All slots are consumed by
  pre-auth connections and every operator request gets 503
  `too_many_connections` indefinitely.
- **Fix:** track a per-request `Instant` deadline across head+body reads and
  reject when exceeded.
- **Confidence:** high.

### V2-02 — Hub UI: build-time token embed ships the API token inside the unauthenticated static bundle

- **Files:** `ui/morph-hub/src/api.ts:23,173`
  (`VITE_MORPH_HUB_AUTH_TOKEN` → `bundledApiToken`), `hub.rs:2148-2161`
  (`route_static` serves `dist/` with no auth).
- **Evidence:** `currentApiToken(): return sessionApiToken ||
  bundledApiToken.trim()`; `route_static` performs no scope/token check.
- **Scenario:** an operator builds the UI with
  `VITE_MORPH_HUB_AUTH_TOKEN=...`; the bearer token is baked into the served
  JavaScript and delivered to anyone who can reach the hub port — page
  visitor equals full-token holder (incl. restore/sign if the token is
  unscoped, see V2-05).
- **Fix:** remove the build-time embed path. Authenticating the static asset
  route is not sufficient because any browser allowed to load the UI would
  still receive the bearer secret.
- **Confidence:** high (code fact; exploitation requires operator opt-in).

### V2-03 — Publication controller: rescans compute confirmations from a stale tip, over-crediting the "absolute" challenge deadline

- **Files:** `crates/morph-cli/src/devnet.rs:7820` (tip fetched once per scan
  batch), `:12097-12105` (`observed_state_cells` derives
  `confirmations = tip − block + 1` from that tip), `:8001`
  (`publication_deadline(&profile, observed.confirmations)`).
- **Evidence:** during a long catch-up scan (restart, `--ignore-cursor`, or
  the v1.10 reorg-recovery rescan from `from_block`), external block
  production advances the chain while the watcher scans under the batch-start
  tip.
- **Scenario:** `observed.confirmations` under-counts by the blocks mined
  during the scan, so `publication_runtime_budget_blocks` over-credits the
  remaining window and the absolute deadline lands later than
  window−reserves — silently consuming the canonical-confirmation/reorg/
  failover/safety reserve the v1.10.0 changelog advertises. Frequent-poll
  incremental scans are nearly unaffected; full rescans can exceed the margin.
- **Fix:** re-fetch `rpc.tip_header()` at the publication site and recompute
  `observed.confirmations` for the actionable cell.
- **Confidence:** high (mechanism), medium (impact).

## 3. Low

| ID | Summary | Where |
| --- | --- | --- |
| V2-04 | **Core-only validation parity:** direct callers of `validate_factory_reduced_splice_transition` do not receive the CLI package layer's unchanged-manifest and contract-digest checks. The shipped CLI path already enforces both before calling core, and the script fails closed, so the previously claimed Medium host-tooling acceptance path is not reachable. Consider moving or duplicating these checks in `morph-core` as defense in depth | `factory_packages.rs:1686-1689,1736-1742`; `validation.rs:732-831`; `lib.rs:3028-3053` |
| V2-05 | Unprefixed `--auth-token` silently mints **all** scopes incl. restore+sign (operator intent `read` requires `scopes:` syntax; forgetting is silent privilege escalation) | `hub.rs:596-621` |
| V2-06 | `panic = "abort"` in release profile: any request-thread panic kills the whole hub; debug builds poison the store lock until restart | `hub.rs:1897-1901`; `Cargo.toml:57` |
| V2-07 | `public_api_error_message` is a blocklist; non-blocklisted internal detail (RPC/watchtower I/O errors, possibly `--ckb-rpc-url` userinfo) echoed to read-scoped clients | `hub.rs:2783-2798`, `:2285-2291` |
| V2-08 | `import packageMetadata from '../package.json'` inlines the **entire** package.json (scripts, deps, overrides) into the public bundle — dependency-inventory disclosure; use a `define`d version constant instead | `ui/morph-hub/src/App.tsx:29,501`; `vite.config.ts` |
| V2-09 | `unreachable!` in a production watcher path (repo convention denies `unwrap`/`expect`/`panic!` only) | `devnet.rs:11758` |
| V2-10 | `docs/devnet.md:211-212` claims the reliability harness proves the non-convergence failure; the harness never injects one — only the unit test covers it | `docs/devnet.md` vs `scripts/devnet-publication-reliability.sh` |
| V2-11 | **Release-note error:** CHANGELOG v1.10.0 states contract sources/wire formats "unchanged", but `1cc830f` (485/469 layouts, witness v2) is contained in v1.10.0; the release README itself attributes withdrawal-binding semantics to the v1.10.0 manifest. Add a boundary-version correction to the next entry | `CHANGELOG.md:59` vs `release/factory-preproduction/README.md:44-53` |
| V2-12 | Full (kind 6) factory splice-out withdrawal substitution has no on-chain negative test — only kind 7 does; both share the enforcement function, so coverage-only gap | `contract_scripts.rs:4200-4362` |
| V2-13 | Withdrawal-output uniqueness check is griefable: any second output with identical lock+asset+amount aborts a valid splice-out (fail-closed liveness) | `morph-vault-lock/src/main.rs:461-466` |
| V2-14 | `funding_context_id` output-level host/script parity test missing (domain string asserted only) | `tests/hash_parity.rs` vs `hash.rs:65-80` |
| V2-15 | Carried open Lows unchanged from prior audit: E-04 (cancel expiry), E-05 (bridge refresh window), F-01 (high-S in 5 core verifiers), F-02 residual (core/CLI invoice expiry), C-05 (late min_since canonicality), B-02/C-04 (64-entry scan caps), A-01 (commitment length asserts), G-02 (sponsor channel_id), H-05 (proptest thinness) | see §1 |
| V2-16 | FactoryStateHeader signing digest and host sparse-Merkle second implementation lack cross-impl parity fixtures | `tests/hash_parity.rs`; `validation.rs:970` |
| V2-17 | `SECURITY-FIXES.md:214` cites test `factory_type_rejects_noncanonical_vault_activation_dep`; actual name `..._dep_position` | `contract_scripts.rs:4038` |

## 4. Info (selected)

- Hub rate limiter is global per-process (any write-scoped client can exhaust
  the shared 120/60s budget; counter consumed by later-failing requests) —
  `hub.rs:1952-1985`.
- `localhost` treated as loopback by string comparison (`/etc/hosts` remap
  binds unauthenticated mode off-box with local control) — `hub.rs:684-700`,
  SDK `index.ts:283-290`.
- `--auth-token <value>` visible in `ps`/cmdline; rotation prints the new
  token to stdout — `main.rs:501,3713-3716`.
- Reconciliation reads `block_by_number` then `tip_header` non-atomically —
  coincident reorg can momentarily overcount depth (self-correcting) —
  `publication.rs:612-629`.
- With `--mine-blocks 0` the watcher returns Ok with a still-pending
  publication (`canonical_confirmed: false`); completion-requires-depth holds
  only on the mined path — `devnet.rs:11664-11674`.
- Single fee-market observation reused across RBF attempts (authoritative
  floor still arrives via `-1111` + caps fail closed) — `devnet.rs:7066`.
- Concurrent watchers can append duplicate reconciled JSONL records
  (deduped next pass; `appended` count only) — `publication.rs:664-690`.
- RBF-rebuild `continue` path omits `replaces_tx_hash` on attempt-2 records —
  `devnet.rs:11573-11584`.
- Attempt-log `0600` only at create; symlink-follow on open —
  `publication.rs:1099-1118`.
- SIGKILL leaves 0600 devnet key temp files behind —
  `scripts/devnet-publication-reliability.sh:232-236`.
- Legacy no-profile publication reports `canonical_confirmed` at depth 1 —
  `devnet.rs:7095-7099`.
- Reduced factory splice restricted to a single delta (intentional asymmetry
  vs full path) — `lib.rs:3064-3066`.
- `PARTICIPANTS_DOMAIN` shared by bilateral and factory pubkey-only
  commitments (identical message shape; no cross-forge found) — `lib.rs:201`.
- Unbounded pub-index accessors panic (fail-closed) on misuse; all current
  loops bounded by parse-validated counts — `lib.rs:868-876` etc.
- `make release-readiness` has an implicit `build-contracts` prerequisite.

## 5. Verified clean (this round)

- **Fee convergence (the v1.11.0 headline):** `verify_initial_fee_convergence`
  is mathematically sound — `fee_for_rate` ceil-rounds, `effective_fee_rate`
  floor-rounds, so no input passes while underpaying the selected market rate;
  it is called on the exact serialized bytes handed to `send_transaction`,
  before broadcast. All fee caps (`max_fee`, `max_fee_rate`,
  SponsorPolicy `max_fee_per_tx` + remaining budget) return `Err`, never
  clamp. Node-supplied RBF floors can only raise fees and remain capped;
  `Indeterminate` floors fail closed. Attempt log: exclusive `File::lock`
  across check-write-`sync_data`, O_APPEND 0600, torn-tail quarantine,
  64 MB rotation bound. Reconciliation never marks `confirmed` below
  configured canonical depth. Deadline arithmetic fully `checked_*`.
  Key isolation: watcher key never on argv/env; `run_without_private_keys`
  scrubbing probe-tested at the launch boundary.
- **Dynamic N-party factory (2..=16):** N-of-N membership binding, sorted-id +
  unique-pubkey validation, exactly-one-signed reduced witnesses authorising
  only the touched participant, depth-256 sparse-Merkle with depth-separated
  node hashes, `factory_id` embedded in every signing digest (no cross-factory
  replay), all conservation arithmetic `checked_*`. No path found where a
  reduced witness moves another participant's rights.
- **WitnessEnvelope dispatch:** blake2b body commitment verified before any
  body parse; exact-length allowlists per kind × N; default-deny dispatch in
  both factory scripts; all 50 error codes unique.
- **Hub otherwise:** constant-time hashed token compare; scope checks on
  every route pre-body; query strings structurally discarded (token-in-URL
  impossible); SSE/authenticated-polling split enforced on both sides; CORS
  echoes only the configured origin, no credentials header; static traversal
  blocked (NUL/`..`/percent/symlink canonicalize); restore path triple-gated
  with confirmation hash; invoice expiry bounded; body limits enforced before
  allocation. UI: no XSS sinks, sessionStorage token, Bearer header only.
  SDK: aligned blake2b personalization and node-id derivation; no wire-layout
  re-implementation to drift.
- **Version alignment:** workspace, all four crates, SDK, UI, CHANGELOG all at
  1.11.0; v1.11.0 diff contains no contract source or wire-format change
  (claim verified against the actual tag diff).

## 6. Recommended actions before the next release

1. Fix V2-03 (stale-tip deadline accounting) — it directly undermines the
   v1.10.0 reserve guarantees on the reorg-recovery path this release added.
2. Fix V2-01/V2-02 before any non-loopback Hub exposure; treat
   `VITE_MORPH_HUB_AUTH_TOKEN` as a footgun to remove.
3. Correct the v1.10.0 release notes (V2-11) — boundary-version history is
   load-bearing per `AGENTS.md`.
4. Optionally move V2-04's reduced-splice checks into `morph-core` so direct
   library callers receive the same defense in depth as the CLI package path.
5. Add the kind-6 substitution negative test (V2-12) and the
   `funding_context_id` parity test (V2-14) — cheap, high evidence value.
