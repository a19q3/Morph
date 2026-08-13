# Base-Model Completeness & 1.0 Pre-Production Readiness Audit — GLM — 2026-08-13 (Post-Review Corrected)

An evidence-driven audit of the Morph Channel repository focused on
two questions: (1) is the base protocol model complete, self-consistent, and
implementable, and (2) can the current version enter a controlled "1.0
pre-production" phase. GLM performed the original audit read-only against
`7692eab`; a subsequent static review corrected internal contradictions and
factual errors in this report and hardened Hub bearer-token comparison. The
report distinguishes the scoped on-chain kernel from incomplete Agent/Fiber and
RGB++ product integrations instead of treating them as one readiness claim.

> **Post-review correction:** the current entry status is **not ready**. There
> are zero confirmed code-security blockers in the supplied finding set, but
> four remaining pre-production entry blockers (C1–C4); C0 was satisfied by
> clean-commit Devnet E2E evidence recorded below. `CONDITIONAL GO` means approval
> only after those gates pass; it is not permission to enter pre-production now.

> **Definition of "1.0 pre-production" used here** (per the audit brief):
> deployable to a controlled devnet/testnet or isolated production-like
> environment; capable of limited-user, limited-asset, reversible, monitored
> real-workflow trial runs; the protocol model, state machine, data formats,
> and security boundaries should not require further destructive refactors; it
> is **not** equivalent to open mainnet, uncapped real assets, or the absence of
> external audit. Missing UI richness or non-core features are not blocking
> unless they affect safe operation, recovery, or observability.

## 0. Baseline and Environment Record

| Field | Value |
| --- | --- |
| `git rev-parse HEAD` | `7692eab703400dc313986b3abcd5cb551e00a4dd` |
| `git branch --show-current` | `main` |
| `git status --short` | clean before report generation; the report itself was subsequently added |
| Post-review implementation commit | `55f6bb5cdbb155d949dded8ee894d83330d80ae2` (`git_dirty=false` in both acceptance summaries) |
| Toolchain (pinned) | `rust-toolchain.toml` → `1.92.0`, edition 2024 |
| Toolchain (executed) | `~/.rustup/toolchains/1.92.0-x86_64-unknown-linux-gnu/bin/cargo` (the host `rustup` proxy mangles `argv[0]` as `ZCode-3.7.5-linux-x64`; the pinned toolchain binary was invoked directly — see Evidence log) |
| RISC-V target | `riscv64imac-unknown-none-elf` installed for 1.92.0 |
| Node / npm | v26.7.0 / 12.0.2 |
| `ckb` binary | not on `PATH` during the GLM run; post-review found an executable sibling checkout at `../ckb/target/debug/ckb` (and `../ckb-cli/target/debug/ckb-cli`) |
| `jq` | present |

**Commands actually executed** (full exit codes and counts in §7 Evidence log):
`make fmt-check`, `make lint` (`--all-features`), `make test` (`--all-features`),
`make build-contracts`, `make contract-tests`, `make fixture-checks`,
`make supply-chain` (attempted; `cargo audit` fetch failed), `cargo deny check`, `make sdk-check`,
`make hub-ui-check`. Static source review across all host crates, all eight
contract crates, the TypeScript SDK, the React UI build, and the CI workflow.

**Commands not executed by the original GLM run:** `make devnet-smoke`,
`make devnet-e2e`, `make devnet-stateful-e2e`, and the Fiber acceptance matrix.
Those require a local CKB node. The original run did not discover the available
sibling debug binaries. `make smoke` does **not** require CKB; it is a
local semantic gate and was run during post-review verification. Missing
current-clean-HEAD devnet/stateful evidence was an entry blocker (C0), not a code
failure; C0 was subsequently satisfied on clean implementation commit `55f6bb5`.

---

## 1. Executive Verdict

### `CONDITIONAL GO — CURRENTLY NOT READY TO ENTER`

The scoped base protocol model appears **complete, self-consistent, and
implementable** for the bilateral + factory + splice + sponsor surface it
claims. The on-chain
safety kernel (state/vault/factory authenticity, value conservation, witness
envelope safety, monotonicity, signature completeness, exact OutPoint binding)
has strong local evidence: all 112 contract integration tests pass, all 401
workspace tests pass, all 14 fixture families validate, and every previously
raised candidate vulnerability that implicated this kernel (C-01 sponsor-budget
bypass, D-04 high-S malleability) was independently re-traced and **refuted**
against the audited code. This is not an exhaustive proof, and the production-
shaped matrix is not a substitute for an external security audit. Post-review,
`make devnet-e2e` and `make devnet-stateful-e2e` both passed on clean
implementation commit `55f6bb5`, satisfying C0; their artifact paths and
summary counts are recorded in §7.

The model can enter a controlled 1.0 pre-production phase **only after the
remaining C1–C4 gates are met** (§5): reproducible artefacts and a script-hash
manifest, an explicit value/scope envelope, operator runbooks, and implemented
or explicitly bounded watchtower reorg behaviour. Agent receipts, Morph-backed
Fiber routing, pending conditional-
payment force-close, and RGB++ proof admission are outside the approved 1.0
pre-production scope unless their documented integration gates are completed.

This is explicitly **not** a mainnet/real-asset endorsement. The README, the
mainnet-readiness doc, and the roadmap all honestly position the repository as
devnet research code, and that positioning is accurate.

---

## 2. Verdict Dimensions

| Dimension | Rating | Rationale |
| --- | --- | --- |
| Protocol model completeness | **Ready for the scoped kernel** | State/Vault/Sponsor/Factory/Splice objects form a closed model. Agent/Fiber routed edges, pending conditional-payment force-close, and RGB++ proof lifecycle are explicitly excluded (§3, §4.7). |
| State-machine closure | **Ready** | create / supersede / finalise / splice / factory-update / reduced-rights / reduced-exit / local-exit / factory-splice / reduced-splice / sponsor-publication / xUDT settlement all have defined inputs, authorisers, monotonic fields, invariants, outputs, terminal states, and negative tests (§3.2, §4.2). |
| Value conservation | **Ready** | CKB, xUDT, factory reserve, VaultCell, StateCell carrier, and Sponsor capacity are all conserved with checked arithmetic; retirement cannot orphan value; the one claimed sponsor-budget bypass (C-01) is refuted (§4.3, Finding F-08). |
| Authorisation & cryptographic binding | **Ready** | All 18 StateHeader / 20 SpliceHeader / 17 FactorySpliceHeader fields enter the signing digest; domain separation, personalization, byte order, thresholds, counts, and witness versions are host/script-parity-enforced; high-S is rejected by `k256` 0.13.4 (Finding F-09). |
| Host / script parity | **Ready** | `morph-core` validation and `morph-script-common` parsers share identical domain constants (now directly asserted in `hash_parity.rs`) and produce byte-identical digests; the proptest gap on field 17 is closed (`0usize..18`). |
| Agent / Fiber payment closure | **Not Ready for Morph-backed claims** | Fiber-native invoice/payment flows are tested, but Agent receipts prove "Fiber paid", not "Morph channel settled on CKB" (`morph_state: None`); the Morph-backed external edge and pending conditional-payment force-close are not implemented. These capabilities are excluded unless C5 is completed. |
| Persistence & recovery | **Conditionally Ready** | Hub atomic COW + fsync; Agent durable settle idempotent (`PendingSubmission` recorded before Fiber send); Fiber adapter disables unbacked edges. **Condition:** watchtower has no canonical-block rollback/reorg recovery (documented open gate). |
| Operational observability | **Not Ready** | JSONL/SSE alerting, watch config/policy, redacted payment index, and token-scoped auth exist; but operator runbooks, monitoring, incident-response, and emergency-stop procedures are absent (documented open). |
| Release & supply chain | **Conditionally Ready** | CI now mirrors `make ci` exactly with `--all-features`, SHA-pinned actions, `permissions: contents: read`, `timeout-minutes: 60`, `publish = false` on all 12 crates, and `cargo deny` clean. **Condition:** no reproducible-build manifest, no artefact signing, no CHANGELOG; `cargo audit` could not be run with DB fetch (sandbox network) — see §7. |
| Test evidence | **Ready for the scoped kernel** | 401 workspace + 112 contract tests pass, fixtures validate, SDK/UI checks pass, and clean implementation commit `55f6bb5` passed budget-backed Devnet and stateful E2E. Agent/Fiber/Morph is excluded from this scope unless C5 is completed. |
| Documentation consistency | **Ready after post-review correction** | Sponsor policy is already documented as per-cell; the stale AGENTS workspace count was corrected from two to four host crates. Product claims must retain the scope exclusions above. |

---

## 3. Base-Model Inventory

| Model object | Authority source | Encoding | Validation site | State transitions | Test evidence |
| --- | --- | --- | --- | --- | --- |
| `StateHeader` (18 fields, 346 B) | participant signatures over domain-separated digest | fixed-layout LE, `STATE_DOMAIN` | `morph-state-type` (on-chain), `morph-core::validation` (host) | Active→Settling (supersede), create, finalise, splice-retire | `hash_parity.rs`, 112 contract tests |
| `SpliceHeader` (20 fields, 453 B) | bilateral signatures over `SPLICE_HEADER_DOMAIN` | fixed-layout LE | `morph-state-type` splice path, host validation | Active→Active (resize, funding-epoch bump) | splice contract tests, fixture family |
| `FactorySpliceHeader` (17 fields, 437 B) | factory-participant signatures | fixed-layout LE, `FACTORY_SPLICE_HEADER_DOMAIN` | `morph-factory-type`, host validation | factory reserve in/out | factory-splice + reduced-splice tests |
| `WitnessEnvelope` (48 B + body) | kind/format/exact-len/body blake2b256 commitment | magic `MORPHW!!`, version 2, flags 0 | `morph-script-common::WitnessEnvelope::parse` | carries all factory authorisations | envelope dispatch tests |
| `FactoryStateHeader` (302 B) | factory signatures / reduced proofs | fixed-layout LE | `morph-factory-type` | conservative update, reduced-rights, Merkle update, exits | factory fixture family + tests |
| `SponsorPolicy` (136 B, per-cell) | operator-funded cell args | fixed-layout LE | `morph-sponsor-lock` | bounded per-tx fee spend | 17 sponsor tests |
| `VaultDescriptor` / settlement descriptor | bilateral/factory signatures | commitment-bound | `morph-vault-lock`, `morph-factory-vault-lock` | settling→withdrawal | vault + factory-vault tests |
| Identity objects (`channel_id`, `factory_id`, `node_id`, lock hashes) | derived from commit-bound `Bytes32`; node id from 33-byte compressed pubkey | `Bytes32` | bound into every signing digest & cell-dep activation | immutable per channel/factory | host/script parity tests |

**Identity and participant binding.** `channel_id`, `factory_id`,
`funding_anchor`, `participants_commitment`, and `node_id` are all `Bytes32`
commitments bound into the signing digest and (for vault materialisation) into
the exact-OutPoint activation. The factory-child provenance binding commits the
32-byte FactoryType script hash into the StateType args, making bilateral↔factory
mode mutually exclusive by args length (32/40 vs 64/72) — no length-confusion
downgrade is possible.

---

## 4. Detailed Audit

### 4.1 Identity & participants

- Channel, factory, participant, node, payer, and sponsor identities all derive
  from `Bytes32` commitments that enter the relevant signing digest
  (`hash.rs:88-110` for StateHeader, `:130-154` for SpliceHeader,
  `:164-186` for FactorySpliceHeader).
- Node id is derived from the 33-byte compressed secp256k1 pubkey (README + hub
  `--pubkey` contract); payer authorisation binds `payee_node_id` and
  `payee_pubkey_sec1` (`node.rs:247-248`).
- No cross-channel replay path was found: every digest is domain-separated and
  binds `channel_id`/`factory_id` + `chain_id` + `funding_epoch`. Factory-child
  materialisation additionally binds the exact FactoryType script hash.

### 4.2 State-machine closure

All documented transitions have a defined (input state, authoriser, monotonic
field, invariant, output state, terminal state, illegal-transition rejection,
timeout/recovery). The `state-type` main dispatch
(`morph-state-type/src/main.rs:66-92`) is exhaustive over
`(GroupInput, GroupOutput)` shape: `(None,Some)`=create, `(Some,Some)`=supersede,
`(Some,None)`=finalise/splice-retire. The factory type dispatches by witness
envelope kind (7 kinds, exact-length allow-list). Negative tests cover:
non-monotonic state number, context drift, standalone settling close without
matching vault, active splice-retire without matching vault, byte-identical
clone vault activation, vault activation lock drift, non-canonical vault
activation dep, carrier drain, and factory-vault root drift. No source-less,
sink-less, or unrecoverable intermediate state was found.

### 4.3 Value conservation (source-to-sink)

- **CKB / xUDT / factory reserve:** conserved with checked arithmetic in
  `vault-lock`, `factory-vault-lock`, `devnet-xudt`; the partition model
  (`types.rs:308-446`) classifies every cell and enforces per-class
  conservation. State-carrier capacity is conserved exactly on ordinary updates
  and consumes exactly `STATE_CARRIER_ACTIVATION_FEE = 10_000` on activation.
- **State retirement cannot orphan value:** finalise and active-splice-retire
  require the exact VaultCell input named by
  `StateHeader.vault_outpoint_commitment` (matching both content root and
  OutPoint locator).
- **Merkle locality is not mint authority:** the generic single-right Merkle
  update accepts only authorised value-right **decreases**; increases require
  full consent or vault-delta-bound splice paths.
- **Sponsor fee:** exact fee attribution (`sponsor_fee == transaction_fee`),
  per-tx cap, state-type/range, clean change enforced. The total-budget
  accumulator reset vector (C-01) is structurally present but **not a value
  drain** — see Finding F-08 for the full refutation.
- **Overflow/underflow/truncation:** `u64`/`u128` checked arithmetic throughout
  (`checked_add`/`checked_sub` with explicit `ScriptError` on overflow). No
  truncating cast was found on a value-bearing path.

### 4.4 Authorisation, signatures & commitments

- Every authority field is bound: `STATE_DOMAIN`/`SPLICE_HEADER_DOMAIN`/
  `FACTORY_SPLICE_HEADER_DOMAIN` prefix the digest; `chain_id`, `protocol_version`,
  `signature_scheme_id`, `channel_id`/`factory_id`, `state_number`/`update_number`,
  `participants_commitment`, `funding_anchor`, vault materialisation root,
  `vault_outpoint_commitment`, asset registry, settlement/splice delta, and
  (for envelopes) witness kind/format/length/body commitment are all covered.
- Host/script parity: identical domain constants (now directly asserted in
  `hash_parity.rs:19-43`), identical personalization (`b"ckb-default-hash"`),
  identical byte order (LE), identical fixed widths, identical thresholds/counts.
- High-S malleability: **refuted** — `k256` 0.13.4
`VerifyPrimitive<Secp256k1>::verify_prehashed` (`ecdsa.rs:202-204`) returns
`Err` if `sig.s().is_high()`. See Finding F-09.

### 4.5 Wire format & upgrade boundary

- Fixed-layout encoders are the sole legal encoders; parsers are strict
  (exact-length, exact-magic, exact-version, flags==0, body-len allow-list,
  body-commitment match before body parse — `lib.rs:480-503`).
- Unknown witness kinds, unknown versions, non-zero reserved fields, and
  abnormal proof shapes (multi-right, variable-depth) are rejected.
- JSON aliasing (`vault_materialisation_root` ↔ `payload_commitment`) is
  backwards-compatible with existing fixtures.
- The Molecule schema (`schemas/morph.mol`) is honestly labelled a draft; the
  live wire format is the fixed-layout `morph-script-common` encoders.
- The format is stable enough to freeze as a 1.0 baseline:
  `WITNESS_ENVELOPE_FORMAT = 2`, all `FACTORY_*_WITNESS_VERSION` constants are
  pinned, and every `*_LEN` is a documented fixed layout.

### 4.6 Host / script parity

`morph-core::validation` and `morph-script-common` share identical constants and
produce byte-identical digests (asserted in `hash_parity.rs`). The
`StateHeader`/`SpliceHeader`/`FactorySpliceHeader` signing digests are compared
host-vs-script at test time. The factory-right domain duplicates are now
imported from `morph-script-common` and directly asserted. No divergence was
found.

### 4.7 Agent / Fiber / payment closure

- Invoice parsing binds payment requirements; payer authorisation validates the
  payer signature against a live locally-stored requirement.
- x402 verify/pay and fair-exchange: credential issuance/verification use
  separate commitments; `settle_once` is the atomic first-writer persistence
  point and is gated on `verify_payment` success.
- Fiber submission records `PendingSubmission` **before** `send_payment`
  (`service.rs:865` before `:873`), then replaces with the initial/terminal
  status — the prior observability gap is closed.
- Restart/timeout/duplicate/idempotency: Agent durable settle is idempotent
  (first-writer + payer recheck); `/v1/pay` payment_hash consistency is
  re-verified after Fiber returns.
- **Gap (documented, non-blocking for pre-production):** Agent receipts set
  `morph_state: None` — they prove "Fiber paid", not "Morph channel settled on
  CKB". A real Morph-backed external Fiber edge is not yet implemented
  (`rgbpp-agent-fiber-integration-plan.md` Phase D/E), and pending conditional
  payments do not yet have a CKB force-close/Batch Cell path. These are not
  defects in the explicitly scoped direct-channel kernel, but they exclude
  Agent/Fiber/Morph settlement claims from the 1.0 pre-production envelope.

### 4.8 Hub & operator model

- Auth: scoped tokens (`read,write,restore,sign:<secret>`), hashed before
  constant-time compare, request head authenticated **before** body read
  (`hub.rs:1305-1321`), duplicate headers rejected including case-insensitive
  `Authorization` (`hub.rs:2584-2587`).
- Boundaries: `MAX_REQUEST_BODY_BYTES`, `MAX_REQUEST_LINE_BYTES`,
  `MAX_REQUEST_HEADER_BYTES`, `REQUEST_IO_TIMEOUT`, `MAX_CONCURRENT_CONNECTIONS`,
  `MAX_CONCURRENT_MUTATIONS`, `MAX_CONCURRENT_SSE_STREAMS`, mutation rate limit,
  invoice expiry all explicit.
- CORS requires explicit `--cors-origin`; loopback default; state-restore
  requires `--allow-state-restore`.
- Atomic COW persistence + fsync under the store lock is the documented
  crash-consistency mechanism (intentional, not a defect — dropping the lock
  before fsync would introduce lost-update without a revisioned commit
  protocol).
- Secrets: private-key env vars use `hide_env_values = true`; bearer tokens kept
  out of URLs/logs; watchtower alert files are mode `0600`.

### 4.9 Pre-production engineering gates

See §5 and §6. CI now covers all workspace features, SHA-pins all four actions,
runs with least privilege and a 60-minute timeout, and all 12 crates are
`publish = false`. The remaining gates are reproducible artefacts, a published
script-hash manifest, a CHANGELOG, and operational runbooks — all documented as
open release gates, not hidden remotely exploitable defects. The additional C0
gate required production-shaped acceptance evidence from a clean implementation
commit rather than historical closeout artifacts and is now satisfied.

---

## 5. 1.0 Pre-Production Entry Conditions

Ordered by priority. Each is concrete, finite, and verifiable.

| # | Condition | Owner role | Acceptance command / evidence | Code change? | Blocks entry? |
| --- | --- | --- | --- | --- | --- |
| C0 | Produce current-clean-HEAD production-shaped acceptance evidence. | Protocol / release engineer | `make devnet-e2e` and `make devnet-stateful-e2e` pass with manifests recording the audited implementation commit, `git_dirty=false`, and `status=passed`; run `make fiber-morph-devnet-acceptance-full` if Agent/Fiber is in scope. | No unless failures expose defects | **Satisfied 2026-08-13** — both budget-backed runs passed on clean implementation commit `55f6bb5`; Agent/Fiber/Morph remains excluded. |
| C1 | Publish a reproducible RISC-V build + script-hash manifest for the audited commit, attested in CI. | Release engineer | Clean-environment `make build-contracts` reproduces byte-identical ELFs; committed hash manifest matches. | Yes (CI/release configuration; no protocol semantics) | **Yes** — without a pinned, reproducible script-hash manifest, a deployed pre-production cell cannot prove which code enforces its safety boundary. |
| C2 | Set and document explicit value/asset/pilot caps for the pre-production envelope (per-channel, per-factory, per-sponsor, total pilot). | Release owner | A dated `docs/preproduction-envelope.md` (or mainnet-readiness addition) with concrete numbers. | No (docs/policy) | **Yes** — "no real assets by default" is the correct posture, but a controlled pre-production trial requires an explicit, evidence-tied cap rather than an open-ended "some". |
| C3 | Document operator runbooks: key handling, package retention, alert response, rollback/stop, incident response, upgrade. | Operator / SRE | `docs/runbooks/` covering the above; at least one dry-run rehearsal log. | No (docs) | **Yes** — pre-production implies a reversible, monitored trial; without runbooks and a stop procedure an operator cannot safely respond to the failure modes the model itself documents (e.g. watchtower stale packages, legacy factory migration). |
| C4 | Close the watchtower reorg/rollback gap (or explicitly scope it out of the pre-production envelope). | Protocol engineer | Either a canonical-block rollback path with tests, or an explicit documented statement that pre-production assumes low-reorg devnet/testnet only and watchtower packages are best-effort under reorg. | Possibly (if a rollback path is added) | **Yes** — a reorg can invalidate a published package with no automatic recovery; this must be either implemented or explicitly bounded. |
| C5 | Complete the Agent/Fiber/Morph settlement boundary before bringing it into scope. | Integration engineer | Populate `morph_state` from native channel evidence, implement the Morph-backed external edge and pending conditional-payment force-close, and pass the Fiber/Morph acceptance matrix. | Yes | No while explicitly excluded; **Yes** before any claim that Agent/Fiber payment proves Morph/CKB settlement. |
| C6 | Re-run `cargo audit` with network access in the release environment and record the result. | Release engineer | `cargo audit` exit 0 (with the five documented, reviewed waivers) recorded in the release evidence. | No | No (the five waivers are reviewed and test/build-only; `cargo deny` passes). Required for release hygiene, not for model readiness. |

**Conditions C1–C4 are the remaining pre-production entry-blocking set.** C0 is
satisfied. There are zero confirmed code-security blockers in the supplied
findings; the four remaining entry gates are tracked separately. C5 may be
deferred only by excluding Agent/Fiber/Morph settlement claims; C6 is release
hygiene.

---

## 6. Deployment Envelope (assuming the remaining C1–C4 gates are met)

If the verdict is honoured as `CONDITIONAL GO`, the allowed pre-production
envelope is:

- **Approved feature scope:** direct CKB bilateral/factory/splice/sponsor flows
  only. Agent/Fiber may be exercised as an explicitly Fiber-native experimental
  sidecar, but its receipts are not Morph/CKB settlement evidence. Morph-backed
  routing and pending conditional-payment force-close remain excluded until C5.
- **Allowed networks:** a controlled local CKB devnet or an isolated testnet
  only. **Not** Aggron/CKB mainnet or any public mainnet.
- **Pilot scope:** a small, named set of operators and users; reversible; with
  the runbooks from C3 in place. The release owner must set the exact count —
  the repository contains no established pilot-size number, so this is a
  **release-owner-mandated blocking parameter**, not an invented figure.
- **Asset caps:** CKB-only for the initial trial. xUDT settlement is
  implemented and tested but should be admitted only after a separate
  xUDT-asset cap is set. **RGB++ assets are prohibited** until the on-chain
  proof/binding boundary and Bitcoin SPV/leap/reorg watcher are implemented and
  independently validated (currently `rgbpp.rs` is host policy code and
  no `morph-tlc-lock` contract is tracked). The per-channel / per-factory /
  per-sponsor / total caps are **release-owner-mandated blocking parameters** —
  the repository deliberately defines no real-asset limits.
- **Required controls:** TLS/HTTPS for all non-loopback endpoints
  (Agent/Fiber/Gateway/hook already enforce this); token-scoped Hub auth; backup
  of the durable Hub state file (`--state-path`); JSONL/SSE alert monitoring;
  the C1 script-hash manifest pinned to the deployed cells.
- **Prohibited:** mainnet deployment; RGB++ admission; real-asset exposure beyond the documented
  caps; relying on watchtower packages as final under a reorg (until C4 is
  implemented); treating Agent receipts or Fiber terminal status as proof of
  Morph/CKB settlement (until C5); advertising a Morph-backed Fiber route;
  in-place migration of legacy owner-locked devnet factories (they must be
  recreated — documented).
- **Rollback / stop conditions:** pre-production must be runnable with a
  documented emergency-stop (e.g. cease publishing, let channels settle via the
  existing finalise path, recreate factories under the current type-bound lock).
  The conditions and thresholds for triggering stop are a release-owner
  parameter tied to the C2 caps.
- **What still blocks mainnet/real assets beyond pre-production:** independent
  third-party audit of the final post-condition commit; repeated mainnet-like
  fee/reorg evidence; multi-operator watchtower evidence; reproducible signed
  release artefacts; the RGB++ on-chain script + SPV watcher; the Morph-backed
  Fiber external edge; and a formal value-limit policy tied to observed run
  history.

---

## 7. Evidence Log

The original GLM commands ran against `7692eab`; build, fixture, npm, and test
commands wrote only ignored/generated artifacts. The host `cargo`/`rustc`
proxies were unusable, so GLM invoked the pinned toolchain binary directly.
Post-review commands validate the report corrections and Hub hardening in the
working branch. Generated artifacts are not treated as source mutations.

| Command | Exit | Result |
| --- | --- | --- |
| `git rev-parse HEAD` | 0 | `7692eab703400dc313986b3abcd5cb551e00a4dd` |
| `git status --short` | 0 | clean |
| `cargo fmt --all -- --check` | 0 | clean |
| `cargo clippy --workspace --all-features --all-targets -- -D warnings` | 0 | 0 warnings |
| `cargo test --workspace --all-features` | 0 | **401 passed, 0 failed, 112 ignored** (112 ignored = contract tests needing ELFs) |
| `cargo build --release --target riscv64imac-unknown-none-elf -p <7 contracts>` | 0 | all 7 ELFs built (`Finished release`) |
| `cargo test -p morph-core --test contract_scripts -- --ignored --test-threads=1` | 0 | **112 passed, 0 failed, 0 ignored** |
| `make fixture-checks` (validate-fixture + 14 print/validate families) | 0 | 14 summary JSONs produced; no errors |
| `cargo deny --all-features check` | 0 | advisories/bans/licenses/sources ok |
| `cargo audit --deny warnings <5 ignores>` (with fetch) | nonzero | **IO error fetching RustSec DB** — freshness unverified; the separate `cargo deny check` pass does not substitute for the failed fetch |
| `sdk/typescript`: `npm ci` + `npm run check` + `npm test` (build + smoke.mjs) | 0 | check + build + smoke pass |
| `ui/morph-hub`: `npm ci` + `npm run build` (tsc --noEmit + vite build) | 0 | 1746 modules transformed, `dist/` produced |
| static: `k256-0.13.4/src/ecdsa.rs:202-204` high-S rejection | n/a | confirms D-04 refutation |
| static: sponsor-lock never loads `Source::GroupOutput` | n/a | confirms C-01 structural observation (but refuted as value drain — F-08) |
| post-review `cargo test -p morph-cli hub::tests --all-features` | 0 | **34 passed**, including fixed-size hashed-token comparison |
| post-review `make smoke` | 0 | workspace semantic tests pass; `validate-fixture` reports `fixture ok` |
| post-review `make ci` | nonzero | formatting and all-features Clippy passed; stopped only when the online RustSec fetch returned the same I/O error |
| post-review `cargo audit --no-fetch --deny warnings <5 ignores>` | 0 | cached DB loaded **1,216 advisories** and scanned 415 dependencies; database freshness remains unverified |
| post-review `make deny test fixture-checks sdk-check hub-ui-check contract-tests` | 0 | all-features workspace tests, 14 fixture summaries, SDK/UI audits/builds, and **112 contract tests** pass |
| post-review `CKB_BIN=../ckb/target/debug/ckb make devnet-e2e` | 0 | clean implementation commit `55f6bb5`, `git_dirty=false`, top-level `status=passed`; 323 transactions, 322 committed, 6 expected script failures, 7 deployed script hashes verified; `target/devnet-e2e/20260813T145057Z/` |
| post-review `CKB_BIN=../ckb/target/debug/ckb make devnet-stateful-e2e` | 0 | clean implementation commit `55f6bb5`, `git_dirty=false`, top-level `status=passed`; 9/9 scenarios and 11/11 audit families passed, 62 required committed checks, no unknown coverage tags; `target/devnet-stateful-e2e/20260813T145758Z/` |
| Fiber acceptance | **not run** | Agent/Fiber/Morph settlement claims are excluded from the approved scoped kernel and remain gated by C5 |

---

## 8. Findings

Findings are classified as: Code-security blocker · Pre-production entry gate · Confirmed non-blocker ·
Release/process gate · Documentation defect · Hardening opportunity · Refuted
candidate. **There are zero confirmed code-security blockers and four remaining
pre-production entry blockers (C1–C4); C0 is satisfied.**

### Resolved pre-production evidence gate

#### F-00 — Production-shaped acceptance evidence was initially absent (Resolved)

- **Component:** release evidence; `docs/devnet-stateful-acceptance-closeout.md:3-12`.
- **Issue:** the checked-in stateful and devnet closeouts identify their
  manifests as historical. The original GLM run did not execute devnet E2E,
  stateful E2E, or the Fiber/Morph matrix against `7692eab`.
- **Impact:** unit, fixture, and CKB-VM coverage cannot by themselves establish
  process-level deployment, RPC, watchtower, restart, or cross-stack behaviour.
- **Disposition:** **resolved for the scoped kernel (C0)**. Budget-backed Devnet
  and stateful E2E passed on clean implementation commit `55f6bb5`; the
  manifests and summaries record `git_dirty=false` and `status=passed`.
  Fiber/Morph remains excluded and separately gated by C5. This was missing
  evidence, not proof of a code defect.

### Refuted candidates (re-derived against current HEAD)

#### F-08 — Sponsor `max_total_fee` "budget bypass" via cell recreation (Refuted)

- **Prior ID:** C-01 / GLM-001 (originally High).
- **Component:** `contracts/morph-sponsor-lock/src/main.rs:36-68`.
- **Structural observation (true):** the sponsor lock reads `already_spent`
  only from the consumed input cell (line 60) and never loads
  `Source::GroupOutput`, so an attacker can create an output sponsor cell with
  `already_spent=0` and later consume it with a fresh `0 + F <= T` check.
- **Refutation (independent capacity trace):** For `sponsor_fee ==
  transaction_fee` to hold with a small `transaction_fee = F`, the consumed
  sponsor cell's capacity `C_s` minus `F` **must** flow to a `change_lock`
  output (`sponsor_out` filters on the input policy's `change_lock`). A
  recreated sponsor output is under the sponsor lock, not `change_lock`, so it
  is invisible to `sponsor_out` and cannot capture the `C_s - F` refund. The
  recreated cell must therefore be funded by the attacker's own balancing input.
  In the follow-up transaction the consumed cell is the attacker-funded cell, so
  the fee `F` comes out of the attacker's own CKB, not the operator's budget.
  **Net effect across the chain: the operator pays at most the single `F` from
  the original sponsor cell; every extra publication is attacker-funded.** There
  is no operator-value drain. The resettable accumulator defeats only a
  per-cell *count* cap, which is not a value-safety property. The prior
  adjudication ("Not actionable — `sponsor_fee == transaction_fee` prevents
  capacity diversion") is correct and is re-confirmed here.
- **Disposition:** Refuted candidate. No value leaves the operator beyond the
  intended per-tx fee. Current `AGENTS.md` and `SECURITY-FIXES.md` accurately
  describe the accumulator and exposure as per-cell.

#### F-09 — ECDSA high-S malleability accepted on verify (Refuted)

- **Prior ID:** D-04 / GLM-009.
- **Component:** `crates/morph-core/src/validation.rs:249,444,872,920`.
- **Refutation:** `k256` 0.13.4 `impl VerifyPrimitive<Secp256k1> for
  AffinePoint::verify_prehashed` (`k256-0.13.4/src/ecdsa.rs:202-204`) explicitly
  returns `Err(Error::new())` when `sig.s().is_high()`. The host verify path
  (`verify_prehash` → `verify_prehashed`) therefore rejects high-S signatures
  before verification. The prior report inspected call sites only; inspecting
  the dependency semantics refutes the finding.
- **Disposition:** Refuted candidate.

### Release / process gates (Conditionally blocking pre-production)

#### F-01 — No reproducible-build manifest, artefact signing, or CHANGELOG

- **Component:** release engineering; `docs/mainnet-readiness.md:35` (Open).
- **Issue:** script hashes are computed at test time but never recorded in a
  committed manifest; no CI hash-attestation; no cross-environment rebuild
  check; no CHANGELOG.
- **Why it blocks pre-production (not mainnet only):** a controlled
  pre-production deployment must be able to prove which script code enforces a
  deployed cell's safety boundary. Without a pinned, reproducible manifest, the
  deployment is not auditable. This is **release process**, not a remotely
  exploitable code vulnerability.
- **Minimal fix:** CI step that builds the ELFs in a clean environment,
  computes script/type hashes, and commits/attests them; add a CHANGELOG.
- **Blocking:** entry condition **C1**.

#### F-02 — Comprehensive operational runbooks / incident-response / stop procedure incomplete

- **Component:** `docs/mainnet-readiness.md:40` (Open).
- **Issue:** `docs/fiber-morph-devnet-runbook.md` provides a useful acceptance
  runbook, but there is no complete release-operator set covering production
  key handling, package retention, alert response, rollback, incident response,
  emergency stop, and upgrade.
- **Why it blocks pre-production:** pre-production implies a reversible,
  monitored trial. The model itself documents failure modes (watchtower stale
  packages, legacy factory migration, reorg) that an operator must be able to
  respond to.
- **Blocking:** entry condition **C3**.

#### F-03 — Watchtower reorg / canonical-block rollback handling absent

- **Component:** watchtower; `docs/mainnet-readiness.md:38` (Open).
- **Issue:** a reorg can invalidate a published watch package with no automatic
  recovery.
- **Blocking:** entry condition **C4** (implement, or scope out of the
  pre-production envelope with an explicit low-reorg-network-only statement).

#### F-04 — Explicit value / asset / pilot caps not set

- **Component:** `docs/mainnet-readiness.md:41,107-118` (Open by design).
- **Issue:** the repository deliberately defines no real-asset limits; a
  pre-production trial needs concrete caps.
- **Blocking:** entry condition **C2** (release-owner-mandated parameter).

### Confirmed non-blockers (open integration gaps, documented)

#### F-05 — Agent receipts prove "Fiber paid", not "Morph channel settled on CKB"

- **Component:** `crates/morph-agent/src/service.rs:608` (`morph_state: None`).
- **Issue:** the native `ChannelBackend` settlement evidence is not yet wired
  into Agent receipts.
- **Disposition:** Confirmed non-blocker. This is an integration-completeness
  gap, not a defect in the scoped direct-channel kernel. It becomes blocking if
  Agent/Fiber/Morph settlement is added to the 1.0 scope; otherwise C5 remains
  deferred and the receipt is explicitly Fiber-payment-attestation only.

#### F-06 — RGB++ on-chain script + SPV/leap/reorg watcher absent

- **Component:** `crates/morph-core/src/rgbpp.rs` (host policy boundary, 314
  lines); no `morph-tlc-lock` contract is tracked.
- **Issue:** RGB++ evidence checking is host/operator policy only; no on-chain RGB++
  script, no Bitcoin SPV/proof-program integration, no live proof watcher.
- **Disposition:** Confirmed non-blocker. Honestly documented as Phase E future
  work. RGB++ admission is prohibited in the approved pre-production envelope.

#### F-07 — Morph-backed external Fiber edge not implemented

- **Component:** `crates/morph-fiber-adapter/`; `rgbpp-agent-fiber-integration-plan.md` Phase D.
- **Issue:** the current real Fiber route is Fiber-native, not Morph-backed.
- **Disposition:** Confirmed non-blocker only because Morph-backed routing is
  excluded from the approved 1.0 scope. It becomes blocking before that product
  claim is enabled (C5).

### Post-review documentation corrections (resolved)

- The original F-10 was removed: current `AGENTS.md` and
  `SECURITY-FIXES.md` already describe SponsorPolicy as a per-cell boundary and
  explicitly state that separately funded sponsor cells are new budgets.
- `AGENTS.md` incorrectly listed only two host Rust crates even though the
  workspace contains four; the workspace snapshot now includes `morph-agent`,
  `morph-fiber-adapter`, and the TypeScript SDK.
- The Hub description is now accurate: supplied and configured bearer tokens
  are hashed to fixed-size values before constant-time comparison.

### Hardening opportunities (not blocking)

- **F-11 — `cargo audit` could not complete a fresh DB fetch** in the original environment
  (sandbox network IO error). The five waived advisories are reviewed and
  test/build-only (rand 0.7, memmap2 0.5, proc-macro-error2, lru 0.7, paste);
  `cargo deny check` passed against its available advisory database, but that
  does not prove database freshness or exactly reproduce `cargo audit`'s five
  explicit waivers. Re-run with network access in the release environment
  (entry condition **C6**).
- **F-12 — `morph-tlc-lock` empty placeholder (resolved):** the local empty
  directory was removed during the 2026-08-14 source-hygiene cleanup. It never
  contained a tracked file; the remaining integration gap is accurately
  represented by F-06 rather than a fake contract path.

---

## 9. Machine-Readable Appendix

```json
{
  "commit": "7692eab703400dc313986b3abcd5cb551e00a4dd",
  "post_review_implementation_commit": "55f6bb5cdbb155d949dded8ee894d83330d80ae2",
  "verdict": "CONDITIONAL_GO",
  "current_entry_status": "NOT_READY",
  "model_scope": "direct CKB bilateral, factory, splice, sponsor, and settlement kernel; excludes RGB++, Morph-backed Fiber routing, and pending conditional-payment force-close",
  "model_complete": true,
  "preproduction_ready": false,
  "mainnet_ready": false,
  "security_code_blockers": [],
  "blockers": [
    "C1",
    "C2",
    "C3",
    "C4"
  ],
  "satisfied_conditions": ["C0"],
  "conditions": [
    {
      "id": "C0",
      "title": "Produce production-shaped devnet and stateful acceptance evidence from the current clean implementation commit",
      "blocking": false,
      "status": "satisfied_2026-08-13",
      "code_change": "no_unless_failures_expose_defects",
      "evidence": [
        "target/devnet-e2e/20260813T145057Z/",
        "target/devnet-stateful-e2e/20260813T145758Z/"
      ]
    },
    {
      "id": "C1",
      "title": "Publish reproducible RISC-V build + script-hash manifest, CI-attested",
      "blocking": true,
      "code_change": "ci_release_configuration"
    },
    {
      "id": "C2",
      "title": "Set and document explicit value/asset/pilot caps for the pre-production envelope",
      "blocking": true,
      "code_change": false
    },
    {
      "id": "C3",
      "title": "Document operator runbooks (key handling, package retention, alert response, rollback/stop, incident response, upgrade)",
      "blocking": true,
      "code_change": false
    },
    {
      "id": "C4",
      "title": "Close watchtower reorg/rollback gap or explicitly scope it out of the pre-production envelope",
      "blocking": true,
      "code_change": "possibly"
    },
    {
      "id": "C5",
      "title": "Complete Agent receipt, Morph-backed Fiber edge, and conditional-payment force-close before adding those claims to scope",
      "blocking": false,
      "code_change": true
    },
    {
      "id": "C6",
      "title": "Re-run cargo audit with network access in the release environment and record the result",
      "blocking": false,
      "code_change": false
    }
  ],
  "findings": [
    {
      "id": "F-00",
      "severity": "Informational",
      "confidence": "High",
      "class": "Resolved pre-production evidence gate",
      "title": "Production-shaped acceptance evidence was initially absent and was subsequently produced",
      "files": ["docs/devnet-stateful-acceptance-closeout.md"],
      "release_blocking": false,
      "condition": "C0",
      "status": "resolved"
    },
    {
      "id": "F-01",
      "severity": "Medium",
      "confidence": "High",
      "class": "Release/process gate",
      "title": "No reproducible-build manifest, artefact signing, or CHANGELOG",
      "files": ["docs/mainnet-readiness.md"],
      "release_blocking": true,
      "condition": "C1"
    },
    {
      "id": "F-02",
      "severity": "Medium",
      "confidence": "High",
      "class": "Release/process gate",
      "title": "Comprehensive operational runbooks / incident-response / stop procedure incomplete",
      "files": ["docs/mainnet-readiness.md", "docs/fiber-morph-devnet-runbook.md"],
      "release_blocking": true,
      "condition": "C3"
    },
    {
      "id": "F-03",
      "severity": "Medium",
      "confidence": "High",
      "class": "Release/process gate",
      "title": "Watchtower reorg / canonical-block rollback handling absent",
      "files": ["docs/rgbpp-agent-fiber-integration-plan.md", "docs/mainnet-readiness.md"],
      "release_blocking": true,
      "condition": "C4"
    },
    {
      "id": "F-04",
      "severity": "Medium",
      "confidence": "High",
      "class": "Release/process gate",
      "title": "Explicit value / asset / pilot caps not set (release-owner-mandated parameter)",
      "files": ["docs/mainnet-readiness.md"],
      "release_blocking": true,
      "condition": "C2"
    },
    {
      "id": "F-05",
      "severity": "Low",
      "confidence": "High",
      "class": "Confirmed non-blocker",
      "title": "Agent receipts prove Fiber-paid, not Morph-settled-on-CKB (morph_state: None)",
      "files": ["crates/morph-agent/src/service.rs"],
      "release_blocking": false,
      "condition": "C5"
    },
    {
      "id": "F-06",
      "severity": "Low",
      "confidence": "High",
      "class": "Confirmed non-blocker",
      "title": "RGB++ on-chain script + SPV/leap/reorg watcher absent (host stub only)",
      "files": ["crates/morph-core/src/rgbpp.rs"],
      "release_blocking": false,
      "scope_requirement": "prohibited_from_preproduction"
    },
    {
      "id": "F-07",
      "severity": "Low",
      "confidence": "High",
      "class": "Confirmed non-blocker",
      "title": "Morph-backed external Fiber edge not implemented (Phase D gap)",
      "files": ["crates/morph-fiber-adapter/src/lib.rs"],
      "release_blocking": false,
      "condition": "C5"
    },
    {
      "id": "F-08",
      "severity": "Informational",
      "confidence": "High",
      "class": "Refuted candidate",
      "title": "Sponsor max_total_fee budget bypass via cell recreation (no operator value drain)",
      "files": ["contracts/morph-sponsor-lock/src/main.rs"],
      "release_blocking": false
    },
    {
      "id": "F-09",
      "severity": "Informational",
      "confidence": "High",
      "class": "Refuted candidate",
      "title": "ECDSA high-S malleability accepted on verify (k256 0.13.4 rejects high-S)",
      "files": ["crates/morph-core/src/validation.rs"],
      "release_blocking": false
    },
    {
      "id": "F-11",
      "severity": "Informational",
      "confidence": "High",
      "class": "Hardening opportunity",
      "title": "Original cargo audit could not complete a fresh DB fetch; re-run in release environment",
      "files": ["Makefile"],
      "release_blocking": false,
      "condition": "C6"
    },
    {
      "id": "F-12",
      "severity": "Informational",
      "confidence": "High",
      "class": "Resolved hygiene finding",
      "title": "Local untracked morph-tlc-lock placeholder directory was removed",
      "files": [],
      "release_blocking": false,
      "status": "resolved_2026-08-14"
    }
  ],
  "commands": [
    {"command": "git rev-parse HEAD", "exit_code": 0, "result": "7692eab703400dc313986b3abcd5cb551e00a4dd"},
    {"command": "git status --short", "exit_code": 0, "result": "clean"},
    {"command": "cargo fmt --all -- --check", "exit_code": 0, "result": "clean"},
    {"command": "cargo clippy --workspace --all-features --all-targets -- -D warnings", "exit_code": 0, "result": "0 warnings"},
    {"command": "cargo test --workspace --all-features", "exit_code": 0, "result": "401 passed, 0 failed, 112 ignored"},
    {"command": "cargo build --release --target riscv64imac-unknown-none-elf -p <7 contracts>", "exit_code": 0, "result": "all 7 ELFs built"},
    {"command": "cargo test -p morph-core --test contract_scripts -- --ignored --test-threads=1", "exit_code": 0, "result": "112 passed, 0 failed, 0 ignored"},
    {"command": "make fixture-checks", "exit_code": 0, "result": "14 fixture families validated"},
    {"command": "cargo deny --all-features check", "exit_code": 0, "result": "advisories/bans/licenses/sources ok"},
    {"command": "cargo audit (with fetch)", "exit_code": 1, "result": "IO error fetching RustSec DB (sandbox network) - environment-unverified"},
    {"command": "sdk/typescript npm run check + test", "exit_code": 0, "result": "check + build + smoke pass"},
    {"command": "ui/morph-hub npm run build", "exit_code": 0, "result": "tsc --noEmit + vite build (1746 modules) pass"},
    {"command": "cargo test -p morph-cli hub::tests --all-features", "exit_code": 0, "result": "34 passed, 0 failed"},
    {"command": "make smoke", "exit_code": 0, "result": "workspace semantic tests and validate-fixture pass"},
    {"command": "make ci", "exit_code": 2, "result": "fmt and all-features clippy pass; stopped at online RustSec fetch IO error"},
    {"command": "cargo audit --no-fetch with five reviewed ignores", "exit_code": 0, "result": "cached DB: 1216 advisories, 415 dependencies scanned; freshness unverified"},
    {"command": "make deny test fixture-checks sdk-check hub-ui-check contract-tests", "exit_code": 0, "result": "all remaining CI gates pass, including 112 contract tests"},
    {"command": "CKB_BIN=../ckb/target/debug/ckb make devnet-e2e", "exit_code": 0, "result": "clean implementation commit 55f6bb5; git_dirty=false; status=passed; artifact target/devnet-e2e/20260813T145057Z/"},
    {"command": "CKB_BIN=../ckb/target/debug/ckb make devnet-stateful-e2e", "exit_code": 0, "result": "clean implementation commit 55f6bb5; git_dirty=false; status=passed; 9/9 scenarios and 11/11 audit families; artifact target/devnet-stateful-e2e/20260813T145758Z/"},
    {"command": "make fiber-morph-devnet-acceptance-full", "exit_code": -1, "result": "not run; Agent/Fiber/Morph settlement claims excluded from the scoped kernel and gated by C5"}
  ]
}
```

---

*Original audit evidence was collected against `7692eab`; this corrected report
also records post-review documentation and Hub-auth hardening plus clean
implementation-commit (`55f6bb5`) Devnet/stateful acceptance evidence. The
report-only follow-up does not alter that tested implementation. This remains a
point-in-time assessment and does not constitute mainnet-readiness or a
real-asset endorsement.*
