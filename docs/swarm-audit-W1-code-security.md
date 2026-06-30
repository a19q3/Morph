# Swarm Audit — W1 代码与安全 (Code & Security)
Date: 2026-06-22  Branch: arthur/morph-audit-fixes @ aa71651
Severity counts: CRITICAL 1 / HIGH 2 / MEDIUM 5 / LOW 4

## Findings

### W1-01 — sponsor-lock: `ensure_publication_backed_by_state_type_input` permits state-cell publication with no backing input when state_number==0 and min_state_number==0
**Severity**: CRITICAL
**Surface**: `contracts/morph-sponsor-lock/src/main.rs:142-145`
**Confidence**: high
**Claim**: The morph-sponsor-lock accepts a publication (settling StateCell in the outputs) and pays the sponsor fee even when there is NO corresponding input StateCell at all, as long as the policy's `min_state_number == 0` and the published state's `state_number == 0`. This allows the sponsor cell to be drained by an attacker fabricating the first publication of a forged channel, because the only state input the policy requires is the one at index #0 of the tx (via the funding-anchor derivation in morph-state-type, which reads `load_input(0, Source::Input)` — a tx-level position the attacker controls).
**Evidence**:
```rust
// contracts/morph-sponsor-lock/src/main.rs
141:     }
142:     if policy.min_state_number() != 0 || state_number != 0 {
143:         return Err(ScriptError::SponsorStateOutOfRange);
144:     }
145:     Ok(())
```
```rust
// contracts/morph-state-type/src/main.rs
177: fn validate_anchor_derivation(expected_funding_anchor: &[u8]) -> Result<()> {
178:     let script_hash = load_script_hash().map_err(|_| ScriptError::Encoding)?;
179:     let output_index = QueryIter::new(load_cell_type_hash, Source::Output)
180:         .position(|type_hash| type_hash == Some(script_hash))
181:         .ok_or(ScriptError::FundingAnchorMismatch)? as u64;
182:     let input = load_input(0, Source::Input).map_err(|_| ScriptError::Encoding)?;  // tx-level!
183:     let index = output_index.to_le_bytes();
184:     let derived = blake2b256(&[input.as_slice(), &index]);
```
The fund_sponsor CLI explicitly uses `min_state_number: 0` (`crates/morph-cli/src/devnet.rs:9314, 9351`) and the auto_fund_sponsor path (`devnet.rs:7220-7230`) computes the same default.
**Reproduction**:
```bash
grep -n "min_state_number() != 0 || state_number != 0" contracts/morph-sponsor-lock/src/main.rs
grep -n "load_input(0, Source::Input)" contracts/morph-state-type/src/main.rs
grep -n "sponsor_min_state_number: 0" crates/morph-cli/src/devnet.rs
```
**Impact**: An attacker that can convince a sponsor to be deployed with `min_state_number=0` (the devnet default and the auto-fund-sponsor path) can drain up to `max_total_fee` in CKB by submitting fabricated first publications whose `funding_anchor` they fully control (since `load_input(0, Source::Input)` is a tx-level position the attacker chooses). Each unique fabricated funding-anchor triggers a fresh "first publication" path in morph-state-type, so the `already_spent` budget is consumed without any real channel state being backed. This is a real money/conservation vulnerability in devnet and in any policy deployment that follows the default.
**Suggested fix**: Remove the bypass at line 142-145. Require that `ensure_publication_backed_by_state_type_input` always find an input StateCell whose `funding_anchor` matches the output's, and emit `SponsorStateOutOfRange` otherwise. The "first publication" case can be handled at a different layer (e.g., by requiring the policy to declare a `requires_backing_input` flag) or by tracking `already_spent` from a single channel-specific `WatchtowerPolicy` cursor that the CLI maintains — but the script itself must not silently accept an unbacked StateCell output.
**References**: paper.tex §3.2 (sponsor policy), audit-response-2026-06-20.md (C-01 closure), W3-08 (audit-response claim vs code drift).

### W1-02 — factory-vault-lock: factory reserve conservation is checked only on the single child vault release, not on the factory's own reserve pool
**Severity**: HIGH
**Surface**: `contracts/morph-factory-vault-lock/src/main.rs:426-493`
**Confidence**: medium
**Claim**: `validate_factory_reduced_exit_reserve_conservation` checks that the factory vault cell's capacity drops by exactly the released amount, but does not verify that the released amount was actually backed by a `RESERVE_CLAIM` right of the right kind/asset. The only check tying the release to a right is in `verify_reduced_factory_exit_update` (script-common), which validates the rights table inside the witness. If the on-chain reserve pool is overcommitted relative to the signed rights table (e.g., a previously authorised rights update is replayed or the rights table omits the touched participant), the vault lock has no defence.
**Evidence**:
```rust
// contracts/morph-factory-vault-lock/src/main.rs
441:     let expected_input = output_capacity
442:         .checked_add(release.capacity)
443:         .ok_or(ScriptError::CapacityUnderflow)?;
444:     if input_capacity != expected_input {
445:         return Err(ScriptError::FactoryReserveMismatch);
446:     }
```
The check only enforces `input = output + release.capacity`. It does NOT verify the factory's authoritative `state_root` matches the current input's `state_root` (the script-common `non_interference_digest` does this, but the morph-factory-vault-lock only calls `find_unique_factory_state` for the input/output cell and does not bind the release to a specific rights-table root — the binding comes entirely from the witness, which is signed only against the new header's digest).
**Reproduction**:
```bash
sed -n '420,495p' contracts/morph-factory-vault-lock/src/main.rs
```
**Impact**: A spliced/reduced exit that is correctly signed by the participant but replays a previously published rights table (e.g., a stale `old_root`) can drain factory reserves that were authorised for a different release amount. The vault lock is the last line of defence at the cell-dep layer, and it does not cross-check the on-chain `state_root` against the rights table's claimed root.
**Suggested fix**: After `verify_reduced_factory_exit_update`, recompute the rights table from the on-chain `state_root` of the input factory header (or assert the witness's `old_header.state_root()` matches `old_header.state_root()` already loaded by `find_unique_factory_state` — which is implicit but should be made explicit). Add a sanity check that the released quantity is bounded by the rights table's RESERVE_CLAIM quantity in the on-chain `old_header.state_root`.
**References**: paper.tex §4.3 (factory reserve claim), W2-08 (factory reduced exit non-interference coverage).

### W1-03 — factory-type: the same `load_input(0, Source::Input)` is used in two distinct scripts, so a single tx-level input can be reused to derive multiple channel/factory anchors
**Severity**: HIGH
**Surface**: `contracts/morph-state-type/src/main.rs:182`, `contracts/morph-factory-type/src/main.rs:244, 336`
**Confidence**: medium
**Claim**: Both the StateType and the FactoryType derive their `funding_anchor` / `factory_id` from `load_input(0, Source::Input)` followed by a blake2b hash. The two scripts use the same input cell but produce different IDs because the `output_index` differs. However, there is no script that verifies the input cell is actually a *single*, *exclusive* funding source for the entire transaction. A malicious transaction can put a sacrificial cell at input index 0, then run multiple state-type and factory-type outputs whose `expected_funding_anchor`/`expected_factory_id` are all derived from that same input cell at different output indices, effectively reusing the same input as a "funding source" for arbitrarily many parallel channels/factories.
**Evidence**:
```rust
// contracts/morph-state-type/src/main.rs:182
let input = load_input(0, Source::Input).map_err(|_| ScriptError::Encoding)?;
let index = output_index.to_le_bytes();
let derived = blake2b256(&[input.as_slice(), &index]);
```
```rust
// contracts/morph-factory-type/src/main.rs:336
let input = load_input(0, Source::Input).map_err(|_| ScriptError::Encoding)?;
let index = output_index.to_le_bytes();
let derived = blake2b256(&[input.as_slice(), &index]);
```
The paper's intent (audit-response-2026-06-20.md C-01 closure) is that each channel/factory has exactly one funding cell. The on-chain check should be: there is exactly one input cell whose `lock` matches the channel/factory's funding lock. The current code only checks the *output's* `expected_funding_anchor` against the blake2b of `input[0] || output_index`. It does NOT check the *input* lock or that other inputs/outputs do not also bear the same funding_anchor.
**Reproduction**:
```bash
grep -n "load_input(0, Source::Input)" contracts/*/src/main.rs
```
**Impact**: In devnet where any user can deploy these scripts, an attacker can spawn many parallel state-cells and vault-cells all referencing the same `funding_anchor` derived from a single throwaway cell. The morph-vault-lock does not cross-reference the funding-anchor back to a unique input. Combined with W1-01, this enables a wide drain surface.
**Suggested fix**: In `validate_anchor_derivation` and `validate_factory_id_derivation`, also iterate the *other* input cells and assert that no other input cell has the same `expected_funding_anchor` (i.e., uniqueness of the funding cell in the transaction). Alternatively, derive the funding_anchor from the script's `args` (which already encodes the channel) and remove the blake2b derivation entirely.
**References**: audit-response-2026-06-20.md C-01, W2-01 (paper-code crossref), W3-08 (drift).

### W1-04 — morph-vault-lock: `find_unique_state_input` returns the first matching cell but does not enforce that the state cell is the sole GroupInput
**Severity**: MEDIUM
**Surface**: `contracts/morph-vault-lock/src/main.rs:311-349`
**Confidence**: high
**Claim**: `find_unique_state_input` iterates *all* inputs (not just `Source::GroupInput`) and returns the first cell whose data parses as a `StateHeader` and whose scripts match. The morph-state-lock (line 40-49) does enforce that the group has exactly one input. But the morph-vault-lock itself never calls `load_cell_lock_hash(1, Source::GroupInput)` to assert the group is well-formed. If two StateCells with matching scripts are placed in the same input group, the vault lock picks one, but the state-lock's `WrongGroupShape` check fires. However, if the group is constructed with one StateCell plus one extra cell that happens to also have a parsable StateHeader, the iteration in `find_unique_state_input` may pick the wrong one.
**Evidence**:
```rust
// contracts/morph-vault-lock/src/main.rs:311
fn find_unique_state_input(...) -> Result<(usize, alloc::vec::Vec<u8>)> {
    let mut found: Option<(usize, alloc::vec::Vec<u8>)> = None;
    let mut index = 0;
    loop {
        match load_cell_data(index, Source::Input) {  // <-- iterates all tx inputs
            Ok(data) => {
                if let Ok(header) = StateHeader::parse(&data)  // <-- no script check here
                    && header.funding_anchor() == expected_funding_anchor
                    && state_cell_scripts_match(...)?
                { ... }
```
The `state_cell_scripts_match` check at line 459 verifies the cell's type & lock code hashes match, but only against the expected values, not against the actual `current_script`. If two distinct StateType scripts with the same code_hash and same funding_anchor are in the same transaction (which is impossible in practice but possible in malformed txs), the function would still pick the first one. More importantly, the iteration is over `Source::Input` (whole-tx), not `Source::GroupInput`.
**Reproduction**:
```bash
sed -n '311,360p' contracts/morph-vault-lock/src/main.rs
```
**Impact**: Minor but real. An attacker could craft a transaction where an unrelated input cell's data also parses as a valid `StateHeader` (e.g., from a different channel) and matches the funding_anchor. The vault lock would then validate against the wrong header's `payload_commitment` and `settlement_descriptor_commitment`, potentially bypassing the "current vault commitment" check.
**Suggested fix**: Iterate `Source::GroupInput` instead of `Source::Input` in `find_unique_state_input` (the function is already group-scoped semantically — see the use of `Source::GroupInput` in `validate_current_vault_commitment`). Add a group-shape check (exactly 1 cell in `Source::GroupInput`) analogous to morph-state-lock.
**References**: W2-08, W3-08.

### W1-05 — morph-vault-lock: `verify_ckb_descriptor_outputs` does not verify that the descriptor's lock_hashes are the participants' lock_hashes
**Severity**: MEDIUM
**Surface**: `contracts/morph-vault-lock/src/main.rs:144-169`
**Confidence**: high
**Claim**: The vault lock checks that there exist output cells whose `lock_hash` matches `descriptor.lock_hash(i)` and whose `capacity` matches `descriptor.capacity(i)`. It does NOT verify that `descriptor.lock_hash(i)` is bound to a specific participant pubkey or to the state header's `participants_commitment`. A signed state header commits to a `settlement_descriptor_commitment` (which is the blake2b of the descriptor), but the vault lock only checks `header.settlement_descriptor_commitment() == descriptor.commitment()`, not that the descriptor's lock_hashes are authentic participant locks.
**Evidence**:
```rust
// contracts/morph-vault-lock/src/main.rs:144
fn verify_ckb_descriptor_outputs(descriptor: &BilateralCkbSettlementDescriptor) -> Result<()> {
    for entry in 0..2 {
        verify_exact_plain_output(descriptor.lock_hash(entry), descriptor.capacity(entry))?;
    }
    Ok(())
}
```
The `BilateralCkbSettlementDescriptor::parse` (script-common:3169) only checks that `lock_hash(0) < lock_hash(1)` and the version/output_count, not the lock_hash values themselves.
**Reproduction**:
```bash
sed -n '144,170p' contracts/morph-vault-lock/src/main.rs
sed -n '3168,3220p' contracts/morph-script-common/src/lib.rs
```
**Impact**: The signed `settlement_descriptor_commitment` is bound to the descriptor bytes, which include the lock_hashes. If the signed header is genuine, then the descriptor must be the one the participants agreed to. However, the vault lock's own check does not independently verify the lock_hashes' authenticity. This is by design (the binding is the signed commitment), but it means the vault lock cannot detect a case where a malicious party reuses a real signed state with a fabricated descriptor — actually it can, because `descriptor.commitment()` would not match `header.settlement_descriptor_commitment()`. So the check at line 99 (`if header.settlement_descriptor_commitment() != descriptor.commitment().as_slice()`) is what saves us. **This is therefore not a real bug, but a low-grade concern that the lock_hash binding to participants is only via the signed commitment, not via script args.** Noting for completeness.
**Suggested fix**: No change required, but document the trust dependency in code comments.
**References**: paper.tex §3.1 (settlement descriptor).

### W1-06 — script-common: `BilateralSignatureWitness::parse` and `SpliceSignatureWitness::parse` do not check the witness `version` field against the current SCHEME
**Severity**: MEDIUM
**Surface**: `contracts/morph-script-common/src/lib.rs:660-668, 734-742`
**Confidence**: high
**Claim**: Both bilateral and splice signature witnesses check `witness.version() != BILATERAL_SIGNATURE_WITNESS_VERSION` etc., but they do not check that the witness `version` field is compatible with the header's `signature_scheme_id`. A signed witness with `version=1` will be accepted even if the header declares `signature_scheme_id=99` (an unknown scheme). The header's `signature_scheme_id` IS checked in `verify_bilateral_state_signatures` (line 703) and `verify_splice_signatures` (line 783), but the parse-level check could short-circuit with a clearer error.
**Evidence**:
```rust
// contracts/morph-script-common/src/lib.rs:660
if witness.version() != BILATERAL_SIGNATURE_WITNESS_VERSION
    || witness.threshold() != BILATERAL_SIGNATURE_THRESHOLD
    || witness.count() != BILATERAL_SIGNATURE_COUNT
{
    return Err(ScriptError::ParticipantWitnessEncoding);
}
```
`version` is checked against the constant `BILATERAL_SIGNATURE_WITNESS_VERSION = 1`. The check is correct but does not validate that the witness scheme is compatible with `SIGNATURE_SCHEME_SECP256K1_ECDSA_BLAKE2B`. The downstream `verify_*_signatures` does. This is fine, but there is a **missing** check on the witness's `signature_scheme_id` *at parse time* — currently a witness could be parsed with `version=1` and then later fail at the scheme-id check, with the error being a generic `ParticipantWitnessEncoding` rather than a specific "scheme mismatch". Not a real bug; an informational finding.
**Reproduction**:
```bash
sed -n '654,670p' contracts/morph-script-common/src/lib.rs
```
**Impact**: No security impact; minor diagnostic clarity.
**Suggested fix**: No action required.
**References**: n/a.

### W1-07 — morph-factory-type: `find_unique_factory_state` leaks a `&'static [u8]` via `Box::leak`, causing a memory leak on every script invocation
**Severity**: MEDIUM
**Surface**: `contracts/morph-factory-vault-lock/src/main.rs:170`
**Confidence**: high
**Claim**: `find_unique_factory_state` calls `Box::leak(data.into_boxed_slice())` to get a `'static` slice, then `FactoryStateHeader::parse(leaked)`. In a `no_std` CKB-VM context with `default_alloc!()` (heap allocator), this leaks heap memory on every script invocation. Over a long-running chain with many factory-type cells, this could exhaust the script's heap budget.
**Evidence**:
```rust
// contracts/morph-factory-vault-lock/src/main.rs:170
let leaked: &'static [u8] = alloc::boxed::Box::leak(data.into_boxed_slice());
FactoryStateHeader::parse(leaked)
```
**Reproduction**:
```bash
sed -n '140,175p' contracts/morph-factory-vault-lock/src/main.rs
```
**Impact**: Memory pressure on CKB-VM. The script heap budget is bounded (CKB-VM default is small), so repeated factory-type invocations could OOM the script. Also, in the devnet harness, repeated calls would accumulate leaked memory.
**Suggested fix**: Change the API of `FactoryStateHeader` to accept a `Cow<[u8]>` or to take the data by value. Alternatively, use a `Vec<u8>` on the stack (no_std `Vec` is already used elsewhere in the script) and pass `&vec` to `parse`. The `Box::leak` is a code smell that was likely added to satisfy a lifetime constraint.
**References**: n/a (code quality, not a security boundary).

### W1-08 — morph-vault-lock: `find_splice_witness_raw` iterates ALL witness inputs without a cap, potential DoS via cycle exhaustion
**Severity**: LOW
**Surface**: `contracts/morph-vault-lock/src/main.rs:384-409`, `contracts/morph-state-type/src/main.rs:327-360`
**Confidence**: high
**Claim**: Both `find_splice_witness_raw` (vault-lock) and `find_splice_witness_raw` (state-type) iterate all input witnesses looking for a splice proof. Each iteration calls `SpliceStateTransitionWitness::parse` (which is expensive) and `witness.header()`. There is no explicit cap on the number of witness inputs the script will inspect. A malicious transaction with many large witness inputs could exhaust CKB-VM's cycle budget.
**Evidence**:
```rust
// contracts/morph-vault-lock/src/main.rs:384
fn find_splice_witness_raw(expected_old_funding_anchor: &[u8]) -> Result<alloc::vec::Vec<u8>> {
    let mut found: Option<alloc::vec::Vec<u8>> = None;
    let mut index = 0;
    loop {
        match load_witness_args(index, Source::Input) {
            Ok(witness_args) => {
                if let Some(input_type) = witness_args.input_type().to_opt() {
                    let raw = input_type.raw_data();
                    if let Ok(witness) = SpliceStateTransitionWitness::parse(raw.as_ref()) {
                        ...}}}
```
No upper bound on `index`; the loop only terminates on `IndexOutOfBound`.
**Reproduction**:
```bash
sed -n '384,410p' contracts/morph-vault-lock/src/main.rs
```
**Impact**: CKB-VM has a per-script cycle limit (currently 3.5M cycles for typical transactions). An attacker crafting a tx with hundreds of large witness inputs could cause the script to exceed the cycle limit, making the channel unusable. The tx itself would still pay for cycles, but the channel state would be unable to transition.
**Suggested fix**: Add a hard cap (e.g., 32 witness inputs inspected) and return `Encoding` if exceeded. Or use a `QueryIter` with a budget.
**References**: W5-14 (envelope coverage gap), W5-15.

### W1-09 — morph-cli: `validate_run` for watchtower policy does not validate `alert_webhook_url` at parse time
**Severity**: MEDIUM
**Surface**: `crates/morph-cli/src/watch_config.rs:43, 63, 543-546`, `crates/morph-cli/src/watch_alert.rs:140-148`
**Confidence**: high
**Claim**: The watchtower config schema accepts `alert_webhook_url: Option<String>` with no validation at config-load time. The URL is only validated when `post_watchtower_alert_webhook_with_secret` is invoked. A config with a syntactically-invalid (but non-empty) URL would be accepted by `WatchtowerConfig::validate`, only failing at alert-posting time. While the URL validator at watch_alert.rs:140-148 does enforce https:// or loopback, a typo in the URL (e.g., `http://localhos:8080/`) would still pass the load step.
**Evidence**:
```rust
// crates/morph-cli/src/watch_config.rs:199
pub fn validate(&self) -> Result<()> {
    ensure!(
        self.schema == WATCH_CONFIG_SCHEMA,
        "unsupported watchtower config schema {}",
        self.schema
    );
    ensure!(
        !self.channels.is_empty(),
        "watchtower config must contain at least one channel"
    );
    ensure_positive(self.defaults.detection_depth, "default detection_depth")?;
    // ... no alert_webhook_url check ...
```
```rust
// crates/morph-cli/src/watch_alert.rs:142
let parsed = url::Url::parse(url.trim())
    .with_context(|| format!("watchtower webhook URL {url} is not a valid URL"))?;
```
**Reproduction**:
```bash
sed -n '199,266p' crates/morph-cli/src/watch_config.rs
```
**Impact**: Operator confusion at config load time. Not a security issue per se, but a UX bug that could lead to silent alert failures.
**Suggested fix**: In `WatchtowerConfig::validate`, also call `url::Url::parse` on each `alert_webhook_url` and ensure the scheme is https:// or loopback. The `watch_alert::is_loopback_url` function should be made `pub(crate)` and reused.
**References**: W3-08, W4 ops-acceptance findings.

### W1-10 — morph-cli: `canonical_hex32` does not reject mixed-case hex strings
**Severity**: LOW
**Surface**: `crates/morph-cli/src/packages.rs:1819`
**Confidence**: high
**Claim**: `canonical_hex32` strips the `0x` prefix, decodes the hex, and re-encodes as lowercase. The result is then compared to the input. A mixed-case hex string like `0xAbCd...` would be normalised to lowercase and then compared to the original, returning a mismatch error. This is correct behaviour for canonicalisation, but the error message does not say "lowercase required", which could confuse operators.
**Evidence**:
```rust
// crates/morph-cli/src/packages.rs:1819
let bytes = hex::decode(stripped).context("hex string is not valid")?;
let canonical = format!("0x{}", hex::encode(bytes));
canonical == value
```
**Reproduction**:
```bash
sed -n '1810,1830p' crates/morph-cli/src/packages.rs
```
**Impact**: UX, not security. Operators using tools that emit uppercase hex (e.g., some block explorers) would get a confusing error.
**Suggested fix**: Add a more specific error message: "hex value must be lowercase canonical form, got {value}".
**References**: n/a.

### W1-11 — script-common: dead code — `witness_envelope_len` is exported but never called outside the module
**Severity**: LOW
**Surface**: `contracts/morph-script-common/src/lib.rs:431`
**Confidence**: high
**Claim**: `pub fn witness_envelope_len(body_len: usize) -> usize` is exported but only used inside the test module (line 6400) and in `morph-cli/src/packages.rs:2421`. In the script-common crate itself, it is not called by any of the 8 contract entry points.
**Evidence**:
```rust
// contracts/morph-script-common/src/lib.rs:431
pub fn witness_envelope_len(body_len: usize) -> usize {
    WITNESS_ENVELOPE_LEN + body_len
}
```
```bash
$ grep -rn "witness_envelope_len" /Users/arthur/RustroverProjects/morph-channel
```
Only used in tests and in `packages.rs` (CLI side). The 8 CKB scripts do not call it.
**Reproduction**:
```bash
grep -rn "witness_envelope_len" /Users/arthur/RustroverProjects/morph-channel
```
**Impact**: No security impact. Mild code rot / API surface bloat.
**Suggested fix**: Mark `#[allow(dead_code)]` or remove if CLI doesn't need it. The CLI uses it to pre-allocate buffer; could be inlined.
**References**: redundant-stale-code-audit.md (similar finding).

### W1-12 — morph-cli: `stateful_report.rs` shells out to `git` for git-commit info, but does not validate the output
**Severity**: LOW
**Surface**: `crates/morph-cli/src/stateful_report.rs:763-779`
**Confidence**: medium
**Claim**: `current_git_state` runs `git status --porcelain` and `git rev-parse --short HEAD` and pipes the output into the report. While the commands are not user-controlled (they're hardcoded), an attacker who can write to the repo's `.git` directory (e.g., via a CI injection) could poison the `git_commit` field, which is then used in artifact commit verification.
**Evidence**:
```rust
// crates/morph-cli/src/stateful_report.rs:763
let status = Command::new("git")
    .args(["status", "--porcelain"])
    .output()
    .context("failed to run git status --porcelain")?;
```
The output is trusted and used to populate `CurrentGitState::commit` and `CurrentGitState::dirty`.
**Reproduction**:
```bash
sed -n '760,790p' crates/morph-cli/src/stateful_report.rs
```
**Impact**: Low. The git output is not signed; an attacker who can write to `.git` can already execute arbitrary code. This is a defence-in-depth concern, not a real exploit.
**Suggested fix**: Use `gix` (pure-Rust) or validate the git output is a valid 7-40 char hex string. Consider using `git -c safe.directory=*` to harden.
**References**: n/a.

## Cross-cutting observations

**Conservation invariants in CKB scripts are enforced by signing, not by re-derivation.** The morph-vault-lock, morph-state-type, and morph-factory-type all rely on the signed state header / signed splice proof to commit to the correct partition totals. The scripts then verify a small set of "must match" relationships (e.g., `header.settlement_descriptor_commitment() == descriptor.commitment()`). This is sound as long as the signatures are unforgeable, but it means there is no independent on-chain check that the partition sums balance. A participant with a signing key could authorise a state that, when settled, sends CKB to arbitrary lock hashes, as long as those lock hashes are committed in the signed descriptor. This is by design, but worth noting: the security model is "trust the participant signatures + binding", not "verify the conservation independently".

**Witness envelope parsing is robust, but factory-vault-lock's `find_unique_factory_state` leaks memory.** The `Box::leak` in `morph-factory-vault-lock/src/main.rs:170` is a code-quality concern, not a security one — but combined with the relatively high frequency of factory-type invocations, it could become a performance issue. The factory-type and factory-vault-lock both use `Box::leak` for the same reason; consider refactoring `FactoryStateHeader::parse` to accept a borrowed slice or to take ownership.

**Crypto usage is consistent and correct.** k256 ECDSA prehash verification is used throughout. The signing digests use a unique domain separator per message type (`STATE_DOMAIN`, `FACTORY_STATE_DOMAIN`, `SPLICE_HEADER_DOMAIN`, etc.). There is no recovery-vs-verification confusion; only `verify_prehash` is used. The `participants_commitment` is bound to pubkeys (not signatures), and the `factory_participants_commitment` binds participant-id to pubkey. The `signed_count` overflow protection (returning `u8::MAX` on invalid flag) is correctly checked by `parse` against the expected count.

**DoS surface is bounded by CKB-VM cycle limits, not by script-level caps.** The `find_*_witness_raw` functions iterate all input witnesses with no explicit cap. While CKB-VM's cycle limit protects the chain, a malicious tx could push the script to the limit and make the channel un-spendable. This is a known design trade-off; W5-14 already flagged related coverage gaps.

**Reduced-proof attack surface is consistent between script-common and the contracts.** The `verify_reduced_factory_rights_update`, `verify_factory_merkle_update`, `verify_reduced_factory_exit_update`, and `verify_factory_reduced_splice_update` functions all enforce: (1) the rights root matches, (2) the access manifest root matches, (3) the non-interference digest matches, (4) the signature is valid, and (5) at most one participant's right changed. The fixture tests in `lib.rs:4014-6854` cover positive cases, the witness envelope, the rights map non-interference, and the various negative cases (signature tamper, sibling tamper, increase instead of decrease, wrong descriptor, etc.). The only concern is the on-chain check is `Box::leak` (W1-07).

**morph-cli command injection vectors are well-defended.** The `is_loopback_url` check in `watch_alert.rs:176` correctly rejects non-loopback `http://` URLs. The `canonical_hex32` validation prevents malformed hex from reaching the script. The `path.strip_prefix("0x")` is safe. The `std::process::Command` calls in `stateful_report.rs:763, 779` are hardcoded, not user-controlled. The `atomic_json_tmp_path` function in `packages.rs:1824` uses `pid + counter + nanos` for unique tmp paths, preventing symlink attacks. The `read_watchtower_config` and `read_watchtower_policy` use `serde_json::from_slice` after `fs::read`, which is safe.

## Files reviewed
- /Users/arthur/RustroverProjects/morph-channel/contracts/morph-state-type/src/main.rs (448 lines, full)
- /Users/arthur/RustroverProjects/morph-channel/contracts/morph-state-lock/src/main.rs (51 lines, full)
- /Users/arthur/RustroverProjects/morph-channel/contracts/morph-vault-lock/src/main.rs (748 lines, full)
- /Users/arthur/RustroverProjects/morph-channel/contracts/morph-sponsor-lock/src/main.rs (195 lines, full)
- /Users/arthur/RustroverProjects/morph-channel/contracts/morph-factory-type/src/main.rs (357 lines, full)
- /Users/arthur/RustroverProjects/morph-channel/contracts/morph-factory-vault-lock/src/main.rs (525 lines, full)
- /Users/arthur/RustroverProjects/morph-channel/contracts/morph-devnet-xudt/src/main.rs (79 lines, full)
- /Users/arthur/RustroverProjects/morph-channel/contracts/morph-script-common/src/lib.rs (6855 lines, full; 600+ lines of tests excluded from deep-read)
- /Users/arthur/RustroverProjects/morph-channel/crates/morph-core/src/types.rs (527 lines, full)
- /Users/arthur/RustroverProjects/morph-channel/crates/morph-core/src/validation.rs (1479 lines, full)
- /Users/arthur/RustroverProjects/morph-channel/crates/morph-core/src/hash.rs (264 lines, full)
- /Users/arthur/RustroverProjects/morph-channel/crates/morph-cli/src/watch_alert.rs (444 lines, full)
- /Users/arthur/RustroverProjects/morph-channel/crates/morph-cli/src/watch_config.rs (935 lines, full)
- /Users/arthur/RustroverProjects/morph-channel/crates/morph-cli/src/watch_policy.rs (258 lines, full)
- /Users/arthur/RustroverProjects/morph-channel/crates/morph-cli/src/stateful_report.rs (1470 lines, sampled: 1-30, 750-790)
- /Users/arthur/RustroverProjects/morph-channel/crates/morph-cli/src/packages.rs (2756 lines, sampled: 1-30, 380-430, 460-510, 1800-1860, 2030-2055, 2400-2480, 2610-2640)
- /Users/arthur/RustroverProjects/morph-channel/crates/morph-cli/src/splice_packages.rs (1837 lines, sampled: 1-30, 1500-1610)
- /Users/arthur/RustroverProjects/morph-channel/crates/morph-cli/src/devnet.rs (12840 lines, sampled: 1-100, 1700-1760, 1970-1990, 2330-2350, 5220-5340, 6740-7260, 11650-11760, 12400-12550)
- /Users/arthur/RustroverProjects/morph-channel/crates/morph-cli/src/main.rs (7351 lines, sampled: 1-300, 1900-2100, 5750-5810, 5990-6010, 7110-7140)
