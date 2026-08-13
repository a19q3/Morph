# Swarm Security Audit — GLM — 2026-08-13

A self-contained, evidence-driven security audit of the Morph Channel repository
performed by a swarm of independent agents (A–J). Per the audit brief, this is a
**read-only** audit: no source was modified, no commits/pushes/PRs were made, no
lockfiles were rewritten. Throwaway proof-of-concept tests were written under
`target/` and removed at the end; the working tree is left clean (only the
pre-existing untracked `AGENTS.md` remains).

> **Post-review adjudication (2026-08-13): this notice supersedes the original
> severity counts, RC verdict, remediation plan, and machine-readable appendix
> below.** The original report is retained as audit input and historical
> evidence, but it is not the final triage result. Static re-review found that
> C-01's PoC creates a newly attacker-funded sponsor cell; because
> `sponsor_fee == transaction_fee`, it does not extract additional capacity from
> the consumed sponsor cell. D-04 is also refuted by `k256` 0.13.4's verifier,
> which rejects high-S secp256k1 signatures internally. The corrected
> per-finding disposition is recorded in §0.

## 0. Post-review Adjudication and Remediation

Repository revision reviewed: `92879b91a639608371a920fbf9995c50cde21685`.
There is no repository `SECURITY.md`; the applicable security boundaries were
therefore derived from `README.md`, `SECURITY-FIXES.md`,
`docs/mainnet-readiness.md`, CLI help/configuration, and the reachable product
entrypoints. "Not actionable" below means not a current security vulnerability;
some rows remain useful engineering or release observations.

| ID | Final disposition | Rationale / resolution |
| --- | --- | --- |
| C-01 | **Not actionable** | The recreated sponsor output must be funded by another input. Exact fee attribution prevents capacity diversion from the consumed sponsor cell; the PoC proves cell creation, not sponsor-budget drain. Sponsor documentation was clarified to describe a per-cell policy. |
| H-05 | **Confirmed — fixed** | Both mutable action references are pinned to immutable commit SHAs. |
| H-07 | **Confirmed — fixed** | `make test` and `make lint` now exercise all workspace features, including `devnet`. |
| H-09 | **Confirmed release gate — deferred** | Reproducible signed artifacts remain an explicitly open production-readiness program, not a hidden code vulnerability suitable for a narrow patch. |
| C-03 | **Not actionable — docs fixed** | Two named tests already live in `watch_policy.rs`; two named contract tests exist; the claimed finite-expiry script field does not exist in the 136-byte policy. The stale test list was corrected. |
| D-01 | **Confirmed — fixed** | `AGENTS.md` now records the live 346/302/453/437-byte layouts. |
| D-02 | **Confirmed — fixed** | Host factory-right hashing imports the canonical script-common domain constants; direct host/script domain parity assertions were added. |
| D-03 | **Confirmed — fixed** | The property test now mutates all 18 fields, including `vault_outpoint_commitment`. |
| D-04 | **Not actionable** | `k256` 0.13.4 `VerifyPrimitive<Secp256k1>` rejects `s().is_high()` before verification. The report inspected only call sites, not dependency semantics. |
| E-01 | **Not actionable** | The URL is trusted operator configuration and arbitrary HTTPS webhook destinations are the feature. No less-trusted source-to-SSRF path was found; redirects are disabled. |
| E-02 | **Not actionable** | The path is trusted same-privilege operator configuration. Following that selected path is not a privilege-boundary bypass; the file is forced to mode 0600. |
| F-01 | **Confirmed — fixed** | The parser now rejects duplicate headers, including case-insensitive duplicate `Authorization`. |
| F-02 | **Confirmed — fixed** | Hub parses and authenticates API headers before reading POST/PUT bodies; routes that do not consume a body no longer read one. |
| F-05 | **Not actionable** | Serialising copy-on-write persistence under the store lock is the crash-consistency mechanism. Dropping the lock before fsync would introduce lost-update and disk/memory divergence without a revisioned commit protocol. |
| G-01 | **Confirmed — fixed** | Bearer tokens are hashed to fixed-size values before constant-time comparison; configured and supplied token sizes are bounded. |
| G-02 | **Not actionable** | `make_challenge` stores the same generated 32-byte value as the challenge preimage and offer decryption key. The assumed mismatch is unreachable through the product path. |
| G-03 | **Confirmed — fixed** | `/v1/pay` durably records `PendingSubmission` before invoking Fiber, then replaces it with the returned/terminal status. |
| G-04 | **Not actionable** | `/v1/x402/verify` is intentionally public protocol verification; callers must present a valid payer signature for a live locally stored requirement. Replays replace one bounded payment-map entry. |
| G-05 | **Confirmed — fixed** | The TypeScript SDK now streams responses with the same 2 MiB ceiling as the Rust client and has an oversized-body regression test. |
| B-02 | **Not actionable** | CKB transaction-size limits bound these scans; no exploitable availability path or security-boundary violation was established. |
| F-04 | **Not actionable** | The report found no current secret-leak source-to-sink path. A hypothetical future error string is a hardening note, not a present finding. |

Additional report-listed hardening was completed: CI now has read-only
`contents` permission and a 60-minute timeout (H-06), and all workspace crates
are marked `publish = false` (H-08). The original appendix contains only 19 of
the 21 table entries and duplicated the `severity` key for GLM-007; it is
therefore historical input, not valid machine-readable final output.

---

## 1. Executive Summary

| Field | Value |
| --- | --- |
| Audit commit | `92879b91a639608371a920fbf9995c50cde21685` |
| Branch | `codex/sovereign-rgbpp-audit` |
| Baseline | `origin/main` (2 commits ahead: `0bd0131`, `92879b9`) |
| PR | https://github.com/a19q3/Morph/pull/5 |
| Scope | Full repo: 4 host crates, 8 contract crates (+ 1 empty stub), TypeScript SDK, React UI, CI, supply chain, docs |
| Agents | 10 independent (A threat-model, B State/Vault, C Factory/Sponsor/xUDT, D Wire/crypto, E CLI/Devnet/Watchtower, F Hub, G Agent/Fiber/SDK, H Supply-chain/CI, I Adversarial/fuzz, J independent review) |
| Findings | **1 High, 3 Medium, 15 Low, 2 Informational** (6 candidates refuted) |
| Verdict | **Not ready for RC** |

**Overall risk judgment.** The on-chain safety kernel (state/vault/factory
authenticity, value conservation, witness-envelope safety, monotonicity,
signature completeness) is **sound and well-tested** — every cross-module attack
in the brief (20 scenarios) was attempted and blocked (Agent I, 0 bypasses). The
recent hardening (factory child provenance, exact vault materialisation, Merkle
locality, reduced-exit binding, loopback/TLS gate, incremental response limits,
durable-store caps) **genuinely holds** under independent re-attack.

However, one **documented script-enforced invariant is false**: the sponsor
lock's `max_total_fee` total-budget cap (C-01, High) is bypassable via sponsor-cell
recreation, confirmed by a runnable PoC against the built RISC-V ELF. The
repository's own documentation (`AGENTS.md:110`, `SECURITY-FIXES.md:251`,
`mainnet-readiness.md:59`) advertises this cap as script-enforced; only
`expiry`/`allowed_sponsor_source` are operator-only. This breaks a load-bearing
watchtower/sponsor economic boundary.

Beyond C-01, the cluster of Low findings in the Agent payment/credential flows
(G-01…G-05), the CI coverage gap on the `devnet` feature (H-07), and the
explicitly-open reproducible-build/CHANGELOG/release-signing gates (H-09) should
all be closed before a public RC.

**Recommendations:**

| Question | Recommendation |
| --- | --- |
| Merge PR #5? | **Conditionally** — only after C-01 is fixed and a negative contract test is added. The remainder of the branch's hardening (factory provenance, loopback/TLS, durable-store caps, webhook redirect-None) is sound and should merge. |
| Mark 1.0 RC? | **No** — block on C-01 (High) plus H-07 and the G-series. |
| Mark 1.0 stable? | **No.** |
| Mainnet / real-value deployment? | **No** — mainnet readiness is not established (C-01, reproducible builds, external review, value-limit policy all open). |

---

## 2. Verdict

> **Not ready for RC.**

The codebase is high-quality defensive research code and the on-chain invariant
surface is strong, but a single High-severity sponsor-safety defect (C-01) —
which the project's documentation represents as a script-enforced guarantee —
must be fixed before an RC can be cut. The remaining Medium/Low items are
fixable fast-follow hardening and explicitly-documented release gates; none
individually block an RC, but H-07 (CI never compiles the `devnet` feature,
which includes the sponsor-funding path) means C-01's fix would itself ship
untested unless CI is extended.

---

## 3. Findings Table

| ID | Severity | Confidence | Component | Title | Exploit prerequisites | Impact | Status |
| --- | --- | --- | --- | --- | --- | --- | --- |
| **C-01** | **High** | High | sponsor-lock | `max_total_fee` total budget cap bypassable via sponsor-cell recreation | Channel participant/watchtower able to publish a valid settling state within policy range; can supply a balancing input | Cumulative sponsored fees unbounded beyond `max_total_fee` (bounded only by `max_fee_per_tx × N`); drains sponsor budget | Validated (ELF PoC) |
| H-05 | Medium | High | CI | 2/4 GitHub Actions not SHA-pinned | Supply-chain attacker compromises `dtolnay/rust-toolchain` branch or `Swatinem/rust-cache` tag | CI environment silently altered without repo-level change | Validated |
| H-07 | Medium | High | CI / morph-cli | `devnet` feature never compiled/linted/tested/supply-chain-checked in CI | None (coverage gap) | ~24 `cfg(devnet)` sites incl. RPC, watchtower, devnet orchestration, and the sponsor-funding path ship untested | Validated |
| H-09 | Medium | High | release eng. | No reproducible builds / artifact signing / CHANGELOG | None (process gap) | Cannot produce a verifiable, signed, reproducible release | Validated (documented mainnet gate) |
| C-03 | Low | High | tests/docs | 3 documented sponsor negative tests absent from `contract_scripts.rs` | None | Finite-expiry rejection (the one enforced sponsor policy field) has no negative test | Validated |
| D-01 | Low | High | docs | AGENTS.md fixed-layout length constants stale | None | Integrators/auditors inherit wrong header lengths (314/238/389/309 vs real 346/302/453/437) | Validated |
| D-02 | Low | High | tests | `hash_parity.rs` lacks direct domain-string asserts; factory-right domains are private duplicates | None | Future domain drift in factory Merkle path would be silent | Validated |
| D-03 | Low | High | tests | Signing-digest proptest misses StateHeader field 17 (`vault_outpoint_commitment`) | None | Proptest would pass if the field were dropped from the digest | Validated |
| D-04 | Low | High | crypto | ECDSA high-S malleability accepted on verify | Observer of a broadcast publication | Griefing/tx-pinning only (state_number monotonicity + CKB tx dedup bound it) | Validated |
| E-01 | Low | High | watchtower | Webhook SSRF: `https://` short-circuits host validation | Operator misconfigures `--alert-webhook-url` | Channel-state exfil to arbitrary HTTPS endpoint (incl. cloud metadata) | Validated (self-inflicted) |
| E-02 | Low | High | watchtower | Alert-file append follows symlinks (no `O_NOFOLLOW`) | Operator points `--alert-file` at a symlink | Arbitrary file append as the watchtower user | Validated (self-inflicted) |
| F-01 | Low | High | hub | Duplicate `Authorization` header silently last-wins | Client/proxy injects a 2nd Authorization header | Parser inconsistency; not exploitable without HTTP smuggling (Hub is single-request-per-connection) | Validated |
| F-02 | Low | High | hub | Full request body read before auth | Unauthenticated remote (if listener reachable) | Bounded memory DoS (≤1 MiB × `MAX_CONCURRENT_CONNECTIONS`) | Validated |
| F-05 | Low | High | hub | `mutate()` holds store lock across fsync | Authenticated write/sign scope | Serialised mutations stall reads during fsync | Validated |
| G-01 | Low | High | agent | `constant_time_equal` leaks expected token length via timing | Remote against non-loopback Agent listener | Token-length oracle (weak metadata) | Validated |
| G-02 | Low | Medium | agent | `claim_fair_offer` persists receipt before preimage/key check; no rollback | Valid offer + payload that passes settle yet mismatches decryption key | Paid user locked out of plaintext with orphaned receipt | Validated |
| G-03 | Low | High | agent | `/v1/pay` sends Fiber payment before `record_payment`; failure leaves spend un-indexed | Outgoing payer with large Fiber result | Operator observability/reconciliation gap (no fund loss) | Validated |
| G-04 | Low | High | agent | Unauth `/v1/x402/verify` reaches durable `record_payment` | Remote caller knowing a live `requirement_id` | Bounded durable-write amplification (capped store) | Validated |
| G-05 | Low | High | SDK (TS) | `response.json()` uncapped (Rust caps 2 MiB) | Malicious/buggy Agent endpoint | Client-side memory exhaustion | Validated |
| B-02 | Info | High | contracts | 3 cell-scan loops lack `MAX_WITNESS_INPUTS_PER_TX` bound | None | Consistency nit; CKB tx-size limits already bound it | Validated |
| F-04 | Info | Medium | hub | `public_api_error_message` substring blocklist is brittle | None | No secret-leak path found; future errors may expose internals | Validated |

**Refuted / Not-a-finding (6):** B-03 (no-since args — deliberate design choice),
E-03 (alert file is `0600`; non-secret packages are `target/` artifacts), E-04
(canonical CKB devnet deployer key), F-06 (case-sensitive `Bearer` — interop
nit, not a bypass), G-06 (allocation is capped; trusted upstream), C-02 (merged
into C-01). See §5.

---

## 4. Findings — Full Evidence

### C-01 — Sponsor `max_total_fee` total budget cap bypassable via sponsor-cell recreation (High)

**Files:** `contracts/morph-sponsor-lock/src/main.rs:38-66` (root cause),
`contracts/morph-script-common/src/lib.rs:3750-3789` (`SponsorPolicy`,
`already_spent` at offset 64), `:164-192` (`sum_clean_outputs_by_lock_hash`).
**Docs that claim the invariant:** `AGENTS.md:110`, `SECURITY-FIXES.md:251-252`,
`docs/mainnet-readiness.md:59`.

**Vulnerable code path.** `program_entry` → `main` (sponsor-lock):
1. `policy = SponsorPolicy::parse(load_script().args())` (lines 38-40) —
   `already_spent()` is read **only from the consumed input cell's args**.
2. `sponsor_out = sum_clean_outputs_by_lock_hash(policy.change_lock())` (line 44)
   sums only outputs whose lock hash equals the **change** lock. A recreated
   **sponsor-lock** output is invisible here.
3. `transaction_fee = ΣInput − ΣOutput` (line 50). A recreated sponsor cell
   appears in `ΣOutput` but is funded by a balancing attacker input in `ΣInput`,
   so both net to the same `F`.
4. Budget check `already_spent + transaction_fee <= max_total_fee` (lines 59-66)
   uses the input-only `already_spent`. There is **no `Source::GroupOutput`
   load anywhere in the file**, no output-args comparison, and no per-tx
   output-sponsor-count constraint.

**Attacker capability & preconditions.** A channel participant or watchtower
that can publish a valid settling state within the policy's
`[min_state_number, max_state_number]` range, backed by a real StateType input
with matching funding anchor (the normal sponsored-publication flow — the
standard payment-channel threat model). The attacker must also supply a
balancing input under their own lock (always-success). No private-key theft.

**Source-to-sink / state-transition path.**
- **Tx1:** consume sponsor cell `(already_spent=A, max_total_fee=T,
  max_fee_per_tx=F)` with `A+F == T` (the honest limit), pay fee `F`, AND create
  an output sponsor cell locked by the same sponsor-lock code with
  `already_spent=0`, funded by a separate attacker input so
  `sponsor_fee == transaction_fee == F` still holds. Script accepts.
- **Tx2:** consume the recreated cell (`already_spent=0`), pay another `F`.
  `0 + F <= T` passes. Script accepts.
- Cumulative sponsored fee = `A + F + F > T`, defeating the documented cap.
  Repeat for each valid settling state.

**Broken invariant.** "Sponsor total budget is script-enforced"
(`AGENTS.md:110`: *"The sponsor lock enforces: … per-tx **and total fee caps**,
and clean change."*). The accumulator is non-monotonic and trivially resettable.

**Why existing checks fail.**
- `sponsor_fee == transaction_fee` (line 52) does NOT prevent recreation: the
  recreated cell's capacity is excluded from `sponsor_out` (change-lock-only)
  and cancels in the global sum.
- `sponsor_lock_rejects_third_party_capacity_diversion` (contract_scripts.rs:8609)
  rejects only *unbacked* diversion (`sponsor_fee != transaction_fee`); the
  bypass supplies a balancing input.
- No existing sponsor test recreates the cell — all 12 consume a single sponsor
  cell with no sponsor output.

**Repro / PoC (runnable, confirmed against built ELF).** A standalone
`ckb-testtool` test was written under `target/audit-verify/` mirroring the
existing sponsor-test harness. Four cases all **pass** (i.e., the script
accepts):
```
control_honest_single_sponsor_txn_passes ...... ok
control_honest_rollover_recreation_passes ..... ok   (recreate with already_spent=A+F)
bypass_tx1_recreate_with_reset_accumulator_passes ... ok   (recreate with already_spent=0)
bypass_tx2_consume_recreated_cell_pays_another_fee ... ok  (aggregate A+F+F > T)
```
Constants: `F = MAX_FEE_PER_TX = 1000`, `T = MAX_TOTAL_FEE = 2000`, initial
`A = already_spent = 1000`. The two `bypass_*` cases passing is the
confirmation. (Test artifacts removed after verification.)

**Adjudication of the internal dispute.** Agent I argued C-01 is "documented
operator policy (already_spent is per-cell-only by design), not a script
bypass." Agent J overruled this: the documentation explicitly lists
`max_total_fee` (the total fee cap) as **script-enforced**; only
`expiry`/`allowed_sponsor_source` are relegated to operator policy
(`AGENTS.md:110`, `SECURITY-FIXES.md:244-263`). The code path that checks
`already_spent + fee <= max_total_fee` confirms the script *intends* to enforce
a cumulative cap. The defect is that the accumulator is resettable, not that the
cap is operator-only.

**Impact.** Unbounded aggregate fee extraction from a sponsor budget intended
to be capped at `max_total_fee`. A watchtower/operator offering sponsored
publication can be drained of CKB well beyond the configured total budget, one
`max_fee_per_tx`-sized publication at a time, bounded only by the number of
valid settling states the attacker can publish. The sponsor lock is a
mainnet-intended contract (not devnet-only), so this is mainnet-relevant.

**Minimal fix.** When the sponsor cell is recreated in the output (a
`GroupOutput` cell with the sponsor lock), require the output sponsor cell's
`SponsorPolicy` to equal the input policy **except** `already_spent`, and enforce
`output_already_spent == input_already_spent + transaction_fee` (checked add).
Alternatively, forbid sponsor-lock outputs entirely on spend txns. Either
approach is a sponsor-lock-semantics change, not a wire-format break
(`SPONSOR_POLICY_LEN` and the args layout are unchanged); it requires new
negative contract tests and a `SECURITY-FIXES.md`/`mainnet-readiness.md` update.

**Regression tests.**
- `sponsor_lock_rejects_already_spent_reset_on_recreate` (recreate with
  lower/equal `already_spent` → `Err`).
- `sponsor_lock_accepts_honest_already_spent_rollover` (recreate with
  `already_spent + fee` → `Ok`).
- `sponsor_lock_rejects_total_fee_widening_on_recreate` (recreate with a larger
  `max_total_fee` → `Err`).

---

### H-05 — 2/4 GitHub Actions not SHA-pinned (Medium)

**File:** `.github/workflows/ci.yml:22,25,31,40`.

| Action | Ref | SHA-pinned? |
| --- | --- | --- |
| `actions/checkout` | `3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1` | **Yes** |
| `actions/setup-node` | `249970729cb0ef3589644e2896645e5dc5ba9c38 # v6.5.0` | **Yes** (node24 runtime — PR claim confirmed) |
| `dtolnay/rust-toolchain` | `@1.92.0` (mutable branch) | **No** |
| `Swatinem/rust-cache` | `@v2` (mutable major tag) | **No** |

A compromised upstream tag/branch would alter the CI environment (toolchain
version, cache behaviour) without a repo-level change. `rust-toolchain.toml`
(channel 1.92.0) partially mitigates the toolchain action but not rust-cache.
**Fix:** pin both to full 40-char SHAs with `# <tag>` comments, matching the
checkout/setup-node pattern.

---

### H-07 — `devnet` feature never compiled/linted/tested/supply-chain-checked in CI (Medium)

**Files:** `Makefile:27` (`test: cargo test --workspace`, default features),
`:30` (`lint: cargo clippy --workspace --all-targets`, no `--all-features`);
`.github/workflows/ci.yml` invokes `make lint`/`make test`.

`morph-cli`'s `devnet` feature gates ~24 `cfg(feature = "devnet")` sites in
`main.rs` and **5 entire modules**: `devnet.rs`, `rpc.rs`, `watch_alert.rs`,
`watch_config.rs`, `watch_policy.rs` — the RPC client, watchtower alerting,
devnet orchestration, **and the sponsor-funding path** (`fund_sponsor` in
`devnet.rs:7807`). None of this is compiled, clippy-checked, tested, or
supply-chain-scanned by CI. `cargo audit`/`cargo deny` also run on default
features. **Fix:** add `cargo clippy --workspace --all-features --all-targets`
and `cargo test --workspace --all-features` CI steps (or a dedicated devnet job).

---

### H-09 — No reproducible builds / artifact signing / CHANGELOG (Medium, release blocker)

**Files:** no `CHANGELOG*` exists; `docs/mainnet-readiness.md:35` ("Reproducible
release artefacts … **Open**"), `:40` (operational runbooks), `:97`
("reproducible CKB script binaries and script hash manifest" — unmet);
`docs/roadmap.md:58` ("external release process is **not complete**").

No committed ELF/script-hash manifest, no CI hash-attestation step, no
cross-environment rebuild check. Script hashes are computed at test time
(`calc_script_hash()`) but never recorded or compared across builds. This is a
**documented mainnet gate**, not an undisclosed defect — classify as a release
blocker tracked against `mainnet-readiness.md`.

---

### Low findings (evidence summaries)

- **C-03** — `SECURITY-FIXES.md:257-261` lists
  `sponsor_lock_rejects_finite_expiry_policy`, `rejects_fee_above_operator_limit`,
  `rejects_explicit_sponsor_when_policy_forbids_it`. None are in
  `crates/morph-core/tests/contract_scripts.rs`. The finite-expiry rejection
  (the one script-level sponsor-policy field that IS enforced) has no negative
  test. Fix: add the tests or correct the doc.

- **D-01** — `AGENTS.md:84,88` documents `STATE_HEADER_LEN=314`,
  `FACTORY_STATE_HEADER_LEN=238`, `SPLICE_HEADER_LEN=389`,
  `FACTORY_SPLICE_HEADER_LEN=309`. The code (`contracts/morph-script-common/src/lib.rs:9-14`)
  defines `346/302/453/437` (each +32 bytes — the added `vault_outpoint_commitment` field).
  This audit brief itself inherited the stale numbers. Fix the doc; optionally add a CI grep
  asserting the constants match.

- **D-02** — `crates/morph-core/src/validation.rs:21-24` declares private duplicates
  `FACTORY_RIGHT_KEY_DOMAIN`, `FACTORY_RIGHT_LEAF_DOMAIN`, `FACTORY_RIGHT_NODE_DOMAIN`,
  `FACTORY_RIGHT_EMPTY_DOMAIN`. `hash_parity.rs` tests commitment-function outputs but never
  directly asserts domain-string byte equality; the factory-right domains have no parity test.
  `FACTORY_RIGHT_EMPTY_DOMAIN` is private-only. Fix: add direct `assert_eq!` tests; replace
  private duplicates with imports from `morph_script_common`.

- **D-03** — `StateHeader` has 18 fields (`vault_outpoint_commitment` at index 17).
  `invariants.rs` proptest `prop_state_header_digest_changes_for_single_signed_field`
  iterates `0usize..17`. Field 17 is uncovered. `hash_parity.rs` covers it, but the invariant
  fuzz does not. Fix: extend to `..18` and add the arm.

- **D-04** — `crates/morph-core/src/validation.rs:248-252,443,871,919` verify prehash
  without `normalize_s()`. k256 0.13.4 accepts high-S. Signing side (`agent.rs:467`) does
  normalise, so awareness exists. Impact bounded by `state_number` monotonicity + CKB tx dedup
  → griefing only. Fix: reject `signature.s().is_high()` at all four sites.

- **E-01** — `watch_alert.rs:157-161`: `ensure!(parsed.scheme()=="https" || is_loopback_url(&parsed))`
  — `https` short-circuits before any host check, so `https://169.254.169.254` or
  `https://attacker.example` pass. `is_loopback_url` (line 190) is consulted only for `http`.
  Webhook URL is operator-configured (`--alert-webhook-url` / config) — **self-inflicted** by
  misconfiguration, hence Low not Medium. Fix: apply host validation/allowlist to `https` too.

- **E-02** — `watch_alert.rs:122-128`: `OpenOptions::create(true).append(true)` with no
  `O_NOFOLLOW`; a symlinked alert file is followed, enabling append-through-symlink. Mode `0600`
  is correctly set (lines 124-136) so the world-read vector does not apply. Path is
  operator-configured (`--alert-file`) — self-inflicted. Fix: lstat/O_NOFOLLOW before open.

- **F-01** — `hub.rs:2551`: `headers.insert(name, value)` into `BTreeMap` — duplicate headers
  silently last-wins. Only `Content-Length`/`Transfer-Encoding` duplicates are rejected
  (lines 2553, 2564). Hub is single-request-per-connection with `Connection: close` (no HTTP
  smuggling), so not an exploitable auth bypass. Fix: reject duplicate `authorization`.

- **F-02** — `hub.rs:1296-1310`: `read_request` reads the full body before `route_api` auth.
  Body capped at `MAX_REQUEST_BODY_BYTES`; bounded by `MAX_CONCURRENT_CONNECTIONS` and
  `REQUEST_IO_TIMEOUT`. Low. Fix: authenticate before body read.

- **F-05** — `hub.rs:1843-1868`: `mutate()` acquires the store lock (1861) and holds it across
  `candidate.persist()` (1865, fsync+rename+dir-sync). Bounded by `MAX_CONCURRENT_MUTATIONS`
  and rate limit. Fix: swap in-memory store, drop lock, then persist.

- **G-01** — `service.rs:1273-1283`: `constant_time_equal` returns `false` immediately on
  `left.len() != right.len()`. Token-length timing oracle (weak metadata). Fix: pad to fixed
  length, or use `subtle::ConstantTimeEq`.

- **G-02** — `service.rs:1040-1068`: `settle_requirement` (1053) persists the receipt before
  the `payment_preimage != offer.decryption_key` check (1060); no rollback on mismatch.
  Narrow reachability (requires a valid offer + payload that passes settle yet mismatches the
  key). Fix: check preimage equality inside the `settle_once` closure.

- **G-03** — `service.rs:853-918`: `send_payment` (853) fires before `record_payment` (879/905);
  if record fails, an outgoing spend is committed to Fiber but un-indexed locally. Operator
  observability/reconciliation gap; no fund loss. Fix: record a pending row before send.

- **G-04** — `service.rs:920-932`: `verify` takes no `HeaderMap`, never calls
  `require_api_bearer`, and reaches `record_payment` (506) unconditionally. Bounded by store
  caps. Fix: gate behind bearer or `creation_limiter`, or make record conditional on state
  transition.

- **G-05** — `sdk/typescript/src/index.ts:223-224`: `await response.json()` with no body-size
  bound, while the Rust client caps at 2 MiB (`client.rs:15`). Client-side memory exhaustion
  from a malicious endpoint. Fix: read via `response.body.getReader()` with a hard cap.

---

## 5. Rejected Candidates

| Candidate | Claimed by | Why refuted |
| --- | --- | --- |
| **B-03** no-since StateType args create un-finalisable channels | Agent B | 32-byte args are a deliberate "create without time-lock" path; vault-lock independently enforces `since` when present. No invariant violated. Design choice. |
| **C-02** SponsorPolicy args attacker-controllable across I/O boundary | Agent C | Root-cause framing of C-01; merged into C-01. |
| **E-03** Watch files world-readable (0644) | Agent E | Alert file (`watch_alert.rs:124-136`) explicitly sets `0600`. The cited `packages.rs` writes are devnet smoke artifacts under `target/`, not secrets. |
| **E-04** Hardcoded fallback devnet private key | Agent E | `devnet-smoke.sh:417` falls back to the canonical, well-known CKB devnet chain-spec deployer key (`0xd00c…d2bc`), valid only on devnet. Not a secret. |
| **F-06** Bearer scheme prefix case-sensitive | Agent F | Interop nit (`bearer`/`BEARER` yield 401), not a bypass. |
| **G-06** `read_response_limited` pre-alloc from Content-Length | Agent G | Allocation is capped at `maximum`; chunk accumulation rejects overflow; upstream is trusted. |

---

## 6. Security Invariant Coverage Matrix

| # | Invariant | Status | Evidence |
| --- | --- | --- | --- |
| 1 | State authority authenticity | **Verified** | `vault-lock:333-374` (`find_unique_state_input` filters type-hash + lock-hash); `sponsor-lock:117-143`; tests `vault_lock_rejects_fake_state_header_without_state_type`, `watchtower_state_detection_requires_authentic_state_scripts` |
| 2 | Exact Vault provenance | **Verified** | `state-type:314-359`, `factory-type:319-377` activation cell-dep check binds exact OutPoint + content root; byte-identical clone rejected (`state_type_rejects_byte_identical_clone_vault_activation`) |
| 3 | Value conservation | **Verified** | `vault-lock:157-286`, `factory-vault-lock:333-559`, `devnet-xudt:40-55`; checked arithmetic throughout; carrier conservation `state-type:283-311` |
| 4 | State monotonicity | **Verified** | `state-type:252-254`, `factory-type:151-153` (`<=` rejected); splice epoch/update_number `validation.rs:309`, `lib.rs:3024,3060` |
| 5 | Signature completeness | **Verified** | StateHeader (18 fields), SpliceHeader (20), FactorySpliceHeader (17) all bound into signing digest; host/script byte-identical (`hash_parity.rs:87-228`); `vault_outpoint_commitment` covered (D-03 is a proptest gap, not a wire gap) |
| 6 | Witness envelope safety | **Verified** | `lib.rs:480-503`: magic → version(2) → flags(0) → known kind → exact length → body_len allow-list → body `blake2b256` commitment, all before body parse; unknown rejected |
| 7 | Factory proof authorization (Merkle locality ≠ mint) | **Verified** | `lib.rs:1892-1901`, `:1632-1645`: generic Merkle update accepts authorised value-right **decreases** only; increases require full consent or vault-delta splice; tests `factory_sparse_merkle_update_rejects_value_right_increase`, `factory_type_rejects_sparse_merkle_right_increase` |
| 8 | State retirement non-orphaning | **Verified** | `state-type:176-204,505-520,522-569`: finalise and active splice-retire require exact VaultCell input matching both content root and OutPoint locator; byte-identical clone/wrong OutPoint/substitute vault all rejected |
| 9 | Typed asset identity | **Verified** | `vault-lock:266-295`, `factory-vault-lock:289-323`: exact type-hash matching across descriptor/vault/splice; classification shape validated |
| 10 | Sponsor boundary honesty | **Partially verified** | Per-tx fee cap, state-type/range, change-clean enforced (`sponsor-lock:36-114`). **`max_total_fee` total cap is NOT enforced — see C-01.** `expiry`/`allowed_sponsor_source` honestly operator-only. |
| 11 | Crash/restart consistency | **Partially verified** | Agent durable settle idempotent (`store.rs:245` first-writer, `service.rs:624-628` payer recheck); atomic COW persist + fsync. Fiber-adapter reconciliation disables unbacked edges. **Gaps:** G-02/G-03 ordering; watchtower has no canonical-block rollback (documented open gate). |
| 12 | Release reproducibility | **Not verified** | No reproducible builds, no artifact signing, no hash manifest — explicitly open in `mainnet-readiness.md`. H-09. |

---

## 7. Test and Tool Evidence

All commands run read-only against `92879b9`. The sandbox's cargo proxy mangles
`argv[0]`, so cargo was invoked via the pinned toolchain binary
`~/.rustup/toolchains/1.92.0-x86_64-unknown-linux-gnu/bin/cargo`. The local
cargo registry contained artifacts built by rustc 1.97.1 (newer than the
project's MSRV 1.92.0), so *build/check* commands hit `E0514` stale-cache errors
— a **sandbox environment artifact, not a repo defect** (CI runs clean against a
fresh toolchain). Static analysis and the PoC verification succeeded.

| Command | Exit | Result | Fresh data? |
| --- | --- | --- | --- |
| `git status --short` / `rev-parse HEAD` | 0 | HEAD `92879b9…`, only untracked `AGENTS.md` | n/a |
| `git diff --stat origin/main...HEAD` | 0 | 40 files, +1199/−365; 2 commits ahead | n/a |
| RISC-V ELFs present (`target/riscv64imac-unknown-none-elf/release/`) | 0 | sponsor-lock, state-type, etc. built | n/a |
| C-01 PoC `cargo test --test c01` (4 cases) | 0 | 4 passed (2 bypass + 2 control) — confirms C-01 | yes (fresh build) |
| Agent I adversarial PoCs (`audit_adv.rs`, since removed) | 0 | Attacks 1–20: 19 PASS, 1 INFEASIBLE, 0 BYPASS | yes |
| `cargo audit --no-fetch` (local DB fetched 2026-08-13) | 0 | 5 waived advisories, nothing else | yes |
| `cargo audit` (with fetch) | nonzero | IO error fetching DB (sandbox network) — **not a pass/fail signal** | env error |
| `cargo deny check` | 0 | advisories/bans/licenses/sources ok | yes |
| `cargo tree --all-features -i <pkg>` (lru/memmap2/rand/proc-macro-error2/paste) | 0 | All 5 waivers confirmed test/build-only via CKB 1.1 family | static |
| `cargo tree --all-features \| grep openssl` | 0 | No openssl (deny ban effective) | static |
| `grep -rn catch_unwind crates/ contracts/` | 0 hits | lru advisory trigger genuinely absent | static |
| `cargo package --workspace --no-verify --allow-dirty` | 0 | 12 `.crate` files (incl. all 8 contract crates — H-08) | static |
| `npm audit --audit-level=low` (ui/morph-hub, 121 deps) | 0 | 0 vulnerabilities | yes |
| `npm audit --audit-level=low` (sdk/typescript, 3 deps) | 0 | 0 vulnerabilities | yes |
| `git ls-remote actions/setup-node` | 0 | SHA = v6.5.0 (node24 runtime) — PR claim confirmed | yes |
| `git ls-remote dtolnay/rust-toolchain` | 0 | `@1.92.0` is a movable branch (not SHA) — H-05 | yes |

Existing test suite was not re-run end-to-end because of the sandbox stale-cache
issue; `make ci` passes in CI per the workflow and prior closeout evidence
(`SECURITY-FIXES.md` "Evidence run"; `3814453` stateful closeout). The 113
ignored contract tests + 12 sponsor tests were exercised individually by Agent I
during adversarial PoC construction.

---

## 8. Supply-chain Review

**Advisories (all waived, all verified):**

| ID | Package | Path (verified) | Exposure | Waiver justification | Upgrade path |
| --- | --- | --- | --- | --- | --- |
| RUSTSEC-2026-0253 | lru 0.7.8 | `ckb-verification 1.1.0` → `ckb-testtool` → `morph-core [dev]` | **Test-only** | Cache key is CKB `Byte32` (no panicking Drop); no `catch_unwind` in repo; `panic=abort` in release. Trigger absent. | 0.18.2 blocked by CKB 1.1 pin + Rust 1.92 MSRV (ckb-verification 1.2 needs 1.95) |
| RUSTSEC-2026-0186 | memmap2 0.5.10 | `cacache` → `ckb-chain-spec` → `ckb-testtool` [dev] | **Test-only** | Affected functions not on Morph's call path | 0.9.11 blocked by CKB 1.1 family |
| RUSTSEC-2026-0097 | rand 0.7.3 | `phf_generator`/`includedir` [build] via ckb-resource; `ckb-vm`/`ckb-script`; `numext` via ckb-std | **Build/test-only** | Morph defines no custom logger (trigger absent) | 0.8.6+; workspace uses rand 0.8.6 for own deps; 0.7.3 is CKB-pinned |
| RUSTSEC-2026-0173 | proc-macro-error2 2.0.1 | `biscuit-quote [proc-macro]` → `biscuit-auth` → `morph-agent` | **Compile-time only** | Proc-macro only; no runtime exposure | none; migrate upstream to `manyhow` |
| RUSTSEC-2024-0436 | paste 1.0.15 | `ckb-types` (reaches morph-cli/morph-agent runtime graph as proc-macro) | **Proc-macro only** | No soundness bug; "unmaintained" only | `pastey` drop-in; blocked by CKB 1.1 family |

**Focus item (RUSTSEC-2026-0253 / lru 0.7):** Waiver is **sound and not too
broad**. `cargo tree -i lru@0.7.8` confirms the path is test-only via
`ckb-verification 1.1.0`'s `TxVerificationCache = LruCache<Byte32, CacheEntry>`
(`ckb-verification-1.1.0/src/cache.rs:11`). `Byte32` has no panicking `Drop`,
`grep catch_unwind` returns 0 hits, and `[profile.release] panic = "abort"`
(`Cargo.toml:56`) makes unwinding impossible in release/RISC-V. Upgrade is
infeasible at MSRV 1.92 (ckb-verification 1.2 needs 1.95).

**Other:** `cargo deny check` passes; `multiple-versions = "allow"` is
acceptable (CKB 1.1 family unavoidably duplicates rand/syn/thiserror/sha2
generations); openssl is banned and absent; no git deps; both `npm audit`s clean.
`morph-tlc-lock` is an **empty stub** (no source, not a workspace member,
unreferenced) — a future-work placeholder, not a risk.

**Doc imprecisions (informational):** `Makefile:9` elides `ckb-chain-spec` in
the memmap2 path; `mainnet-readiness.md:36` omits paste + rand 0.7 from the
waiver list (the Makefile comment block covers all 5).

---

## 9. Compatibility and Migration

**Factory StateType 64/72-byte args.** The factory-child provenance hardening
commits the 32-byte FactoryType script hash into the StateType args between the
funding anchor and optional relative `since`. Bilateral args remain 32/40 bytes;
factory child args are 64/72 bytes and **intentionally produce new StateType
script hashes**. **Pre-fix devnet factory children must be recreated** — there is
no in-place migration. This is honestly documented (`SECURITY-FIXES.md:32-34`,
`:80-81`; `mainnet-readiness.md:29,86`). Legacy owner-locked devnet factories
similarly must be recreated (`SECURITY-FIXES.md:80-81`). The bilateral↔factory
mode is mutually exclusive (`state-type:432`/`:441`), so no length-confusion
downgrade is possible (Agent I attack 3, ELF-verified both directions).

**C-01 fix compatibility.** The proposed fix (constrain a recreated output
sponsor cell's args) does **not** change `SPONSOR_POLICY_LEN` or the args layout
— it is a sponsor-lock-semantics change, not a wire-format break. Existing
single-use sponsor cells continue to work; only the recreation vector is closed.

**RGB++ / sovereign.** The branch's "sovereign" architecture (type-bound
`morph-state-lock` for FactoryStateCells; FactoryProof child commits the exact
FactoryType hash; Morph bilateral backend as the CKB-enforceable backend) is
coherent and enforced at the CKB layer for the bilateral+factory model. RGB++
exists only as a **host-side typed stub** (`crates/morph-core/src/rgbpp.rs`,
314 lines) — no on-chain RGB++ script, no Bitcoin SPV/proof-program integration,
no live proof watcher (`rgbpp-agent-fiber-integration-plan.md:426-449`,
Phase E). `morph-tlc-lock` is empty. RGB++ asset admission is
**operator-policy** until the watcher ships (`service.rs:364-370`).

---

## 10. Release Completeness

| Item | Status | Evidence |
| --- | --- | --- |
| Workspace version | `0.1.0` everywhere (consistent) | all 12 Cargo.toml |
| CHANGELOG | **Absent** | no file; `SECURITY-FIXES.md` covers security only |
| Migration notes (Factory 64/72-byte args) | Present, honest | `SECURITY-FIXES.md:32-34,80-81` |
| License consistency | MIT everywhere; LICENSE present; deny.toml clean | all manifests |
| Reproducible RISC-V builds | **Absent — release blocker** | no hash manifest, no CI attestation; `mainnet-readiness.md:35` Open |
| Artifact/release signing | **Absent — release blocker** | `mainnet-readiness.md:35` Open |
| `publish = false` on contracts/internal crates | **Absent** (H-08) | all 12 crates publishable |
| crates.io metadata (keywords/categories/homepage) | Absent | no metadata fields |
| Rollback story | **Absent** (legacy factories cannot migrate in place) | `mainnet-readiness.md:86` |
| Monitoring / incident-response docs | **Absent** | `mainnet-readiness.md:40` Open |
| Operator runbooks | fiber-morph-devnet-runbook.md exists; general ops Open | `mainnet-readiness.md:40` |
| Value-limit policy | **Absent — by design** (no real assets) | `mainnet-readiness.md:41,107-118` |
| CI ↔ `make ci` parity | **Exact** (8 steps, same order) | H parity table |
| Mainnet disclaimer | Present, honest | `README.md:15` |

All "release blocker" items are **explicitly documented as open mainnet gates**
in `docs/mainnet-readiness.md` and `docs/roadmap.md`. The repo honestly positions
itself as devnet research code.

---

## 11. Remaining Release Blockers

### Code vulnerabilities
- **C-01 (High)** — sponsor `max_total_fee` cap bypassable via cell recreation. Must be fixed with a sponsor-lock-semantics change + negative contract tests before any RC.

### Unverified security assumptions
- RGB++ asset admission is operator-policy, not cryptographic (no on-chain script, no SPV watcher) — Phase E work.
- Watchtower has no canonical-block rollback/reorg handling (`mainnet-readiness.md:38`) — a reorg can invalidate a published package with no automatic recovery.
- Agent receipts prove "Fiber paid," not "Morph channel settled on CKB" — the native `morph_state` backend evidence is not yet wired into receipts (`service.rs:583-605` sets `morph_state: None`).

### External audit
- `mainnet-readiness.md:26` lists "Independent protocol review … Open." This audit is one such review but is **not** a substitute for an independent third-party audit of the final post-fix commit.

### Integration evidence
- `mainnet-readiness.md:34` RGB++ reorg/quarantine/rollback pipeline — Open.
- Fiber hook is not upstreamed; current real Fiber route is Fiber-native, not Morph-backed (Phase D pending).
- No `morph-tlc-lock` — Fiber TLCs traversing a Morph edge are not independently CKB-enforceable during their pending window.

### Operational evidence
- Mainnet-like fee evidence (`mainnet-readiness.md:37`) — Open.
- Real network fee behaviour / delay profiles — Open.
- Operator/monitoring/incident-response runbooks — Open.
- Value-limit policy — by design absent (no real assets).

### Release engineering
- **H-09** — reproducible builds, artifact signing, hash manifest, CHANGELOG.
- **H-05** — pin `dtolnay/rust-toolchain` and `Swatinem/rust-cache` to SHAs.
- **H-06** — add CI `permissions:` and `timeout-minutes`.
- **H-07** — CI must compile/lint/test/supply-chain-check the `devnet` feature (includes the sponsor-funding path).
- **H-08** — add `publish = false` to all workspace members.

---

## 12. Prioritized Remediation Plan

### P0 — block RC / real-value deployment
1. **C-01** (sponsor `max_total_fee` bypass) — owner: `contracts/morph-sponsor-lock`.
   - *Minimal change:* when a `GroupOutput` cell with the sponsor lock exists, require its `SponsorPolicy` to equal the input policy except `already_spent`, and enforce `output_already_spent == input_already_spent + transaction_fee` (checked add). Alternatively forbid sponsor-lock outputs on spend txns.
   - *Tests:* `sponsor_lock_rejects_already_spent_reset_on_recreate`, `sponsor_lock_accepts_honest_already_spent_rollover`, `sponsor_lock_rejects_total_fee_widening_on_recreate`. Add the 3 missing tests from C-03.
   - *Definition of done:* PoC in this report fails (rejected) against the rebuilt ELF; SECURITY-FIXES.md + mainnet-readiness.md updated.

### P1 — before public RC
2. **H-07** — CI `--all-features` compile/lint/test/supply-chain step (owner: CI/Makefile). Ensures C-01's fix and the entire devnet/watchtower/sponsor path are tested.
3. **H-05** — SHA-pin the 2 mutable actions.
4. **G-series** (G-01…G-05) — triage as a cluster: token-length timing, fair-exchange ordering, pay-before-record, unauth verify durable write, TS SDK response cap. Each is a small fix; together they close the Agent payment/credential auth/ordering surface.
5. **E-01, E-02** — apply host validation to `https` webhooks; add `O_NOFOLLOW`/lstat to alert-file append.

### P2 — track into RC with explicit limitations
6. **H-09** — reproducible builds, artifact signing, CHANGELOG (documented mainnet gate).
7. **D-01…D-04** — doc/test hardening (stale lengths, hash-parity direct asserts, proptest field 17, low-S enforcement).
8. **F-01, F-02, F-05** — Hub hardening (duplicate Authorization, body-before-auth, lock-during-fsync).
9. **H-06, H-08, C-03** — CI permissions/timeout, `publish = false`, missing sponsor tests.
10. B-02, F-04 (Informational) — defense-in-depth.

---

## 13. Machine-readable Appendix

```json
{
  "audit_commit": "92879b91a639608371a920fbf9995c50cde21685",
  "baseline": "origin/main",
  "verdict": "Not ready for RC",
  "findings": [
    {
      "id": "GLM-001",
      "severity": "High",
      "confidence": "High",
      "status": "Validated",
      "title": "Sponsor max_total_fee cap bypassable via sponsor-cell recreation",
      "files": ["contracts/morph-sponsor-lock/src/main.rs", "contracts/morph-script-common/src/lib.rs", "AGENTS.md", "SECURITY-FIXES.md"],
      "release_blocking": true
    },
    {
      "id": "GLM-002",
      "severity": "Medium",
      "confidence": "High",
      "status": "Validated",
      "title": "2/4 GitHub Actions not SHA-pinned",
      "files": [".github/workflows/ci.yml"],
      "release_blocking": false
    },
    {
      "id": "GLM-003",
      "severity": "Medium",
      "confidence": "High",
      "status": "Validated",
      "title": "devnet feature never compiled/linted/tested/supply-chain-checked in CI",
      "files": ["Makefile", ".github/workflows/ci.yml", "crates/morph-cli/src/main.rs"],
      "release_blocking": false
    },
    {
      "id": "GLM-004",
      "severity": "Medium",
      "confidence": "High",
      "status": "Validated",
      "title": "No reproducible builds / artifact signing / CHANGELOG",
      "files": ["docs/mainnet-readiness.md", "docs/roadmap.md"],
      "release_blocking": true
    },
    {
      "id": "GLM-005",
      "severity": "Low",
      "confidence": "High",
      "status": "Validated",
      "title": "Documented sponsor negative tests absent from contract_scripts.rs",
      "files": ["SECURITY-FIXES.md", "crates/morph-core/tests/contract_scripts.rs"],
      "release_blocking": false
    },
    {
      "id": "GLM-006",
      "severity": "Low",
      "confidence": "High",
      "status": "Validated",
      "title": "AGENTS.md fixed-layout length constants stale (314/238/389/309 vs 346/302/453/437)",
      "files": ["AGENTS.md", "contracts/morph-script-common/src/lib.rs"],
      "release_blocking": false
    },
    {
      "id": "GLM-007",
      "severity": "Low",
      "confidence": "High",
      "status": "Validated",
      "title": "hash_parity.rs lacks direct domain-string asserts; factory-right domains are private duplicates",
      "files": ["crates/morph-core/tests/hash_parity.rs", "crates/morph-core/src/validation.rs"],
      "release_blocking": false
    },
    {
      "id": "GLM-008",
      "severity": "Low",
      "confidence": "High",
      "status": "Validated",
      "title": "Signing-digest proptest misses StateHeader field 17 (vault_outpoint_commitment)",
      "files": ["crates/morph-core/tests/invariants.rs"],
      "release_blocking": false
    },
    {
      "id": "GLM-009",
      "severity": "Low",
      "confidence": "High",
      "status": "Validated",
      "title": "ECDSA high-S malleability accepted on verify",
      "files": ["crates/morph-core/src/validation.rs", "Cargo.toml"],
      "release_blocking": false
    },
    {
      "id": "GLM-010",
      "severity": "Low",
      "confidence": "High",
      "status": "Validated",
      "title": "Watchtower webhook SSRF (https short-circuits host validation)",
      "files": ["crates/morph-cli/src/watch_alert.rs"],
      "release_blocking": false
    },
    {
      "id": "GLM-011",
      "severity": "Low",
      "confidence": "High",
      "status": "Validated",
      "title": "Watchtower alert file append follows symlinks",
      "files": ["crates/morph-cli/src/watch_alert.rs"],
      "release_blocking": false
    },
    {
      "id": "GLM-012",
      "severity": "Low",
      "confidence": "High",
      "status": "Validated",
      "title": "Duplicate Authorization header silently last-wins",
      "files": ["crates/morph-cli/src/hub.rs"],
      "release_blocking": false
    },
    {
      "id": "GLM-013",
      "severity": "Low",
      "confidence": "High",
      "status": "Validated",
      "title": "Hub reads full request body before auth",
      "files": ["crates/morph-cli/src/hub.rs"],
      "release_blocking": false
    },
    {
      "id": "GLM-014",
      "severity": "Low",
      "confidence": "High",
      "status": "Validated",
      "title": "mutate() holds store lock across fsync",
      "files": ["crates/morph-cli/src/hub.rs"],
      "release_blocking": false
    },
    {
      "id": "GLM-015",
      "severity": "Low",
      "confidence": "High",
      "status": "Validated",
      "title": "constant_time_equal leaks expected token length via timing",
      "files": ["crates/morph-agent/src/service.rs"],
      "release_blocking": false
    },
    {
      "id": "GLM-016",
      "severity": "Low",
      "confidence": "Medium",
      "status": "Validated",
      "title": "claim_fair_offer persists receipt before preimage/key check; no rollback",
      "files": ["crates/morph-agent/src/service.rs"],
      "release_blocking": false
    },
    {
      "id": "GLM-017",
      "severity": "Low",
      "confidence": "High",
      "status": "Validated",
      "title": "/v1/pay sends Fiber payment before record_payment; failure leaves spend un-indexed",
      "files": ["crates/morph-agent/src/service.rs"],
      "release_blocking": false
    },
    {
      "id": "GLM-018",
      "severity": "Low",
      "confidence": "High",
      "status": "Validated",
      "title": "Unauthenticated /v1/x402/verify reaches durable record_payment",
      "files": ["crates/morph-agent/src/service.rs"],
      "release_blocking": false
    },
    {
      "id": "GLM-019",
      "severity": "Low",
      "confidence": "High",
      "status": "Validated",
      "title": "TypeScript SDK response.json() uncapped (Rust caps 2 MiB)",
      "files": ["sdk/typescript/src/index.ts"],
      "release_blocking": false
    }
  ],
  "release_blockers": [
    "GLM-001 (High, code): sponsor max_total_fee cap bypassable",
    "GLM-004 (Medium, release eng.): no reproducible builds/artifact signing/CHANGELOG (documented gate)",
    "RGB++ on-chain script + SPV watcher absent (Phase E)",
    "Watchtower reorg/rollback handling absent",
    "Independent third-party audit of post-fix commit",
    "Mainnet-like fee/integration evidence"
  ],
  "commands": [
    {"command": "git rev-parse HEAD", "exit_code": 0, "result": "92879b91a639608371a920fbf9995c50cde21685"},
    {"command": "C-01 PoC: cargo test --test c01 (4 cases)", "exit_code": 0, "result": "4 passed — bypass confirmed"},
    {"command": "cargo audit --no-fetch", "exit_code": 0, "result": "5 waived advisories, nothing else"},
    {"command": "cargo deny check", "exit_code": 0, "result": "advisories/bans/licenses/sources ok"},
    {"command": "cargo tree --all-features -i lru@0.7.8", "exit_code": 0, "result": "test-only via ckb-verification -> ckb-testtool"},
    {"command": "npm audit --audit-level=low (ui + sdk)", "exit_code": 0, "result": "0 vulnerabilities"},
    {"command": "cargo audit (with fetch)", "exit_code": 1, "result": "IO error fetching DB (sandbox network) — not a pass/fail signal"},
    {"command": "Agent I adversarial matrix (20 scenarios)", "exit_code": 0, "result": "19 PASS, 1 INFEASIBLE, 0 BYPASS"}
  ]
}
```

---

*Audit performed by a 10-agent swarm (GLM-5.2). Read-only; no repository source
was modified. The working tree is left clean. This report does not constitute a
mainnet-readiness endorsement; it is a point-in-time assessment of commit
`92879b9` against the stated threat model.*
