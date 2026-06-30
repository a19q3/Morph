# Host Node & Invoice Audit

Date: 2026-06-27
Branch: `main` (working tree) · 17 commits ahead of `origin/main`
Anchor: `39f0846` + unstaged changes (the `insert_decoded_received` addition)
Scope: `crates/morph-core/src/node.rs`, `crates/morph-core/src/types.rs`, the
invoice subsystem in `crates/morph-core/src/hash.rs`, the integration test
`crates/morph-core/tests/node_invoice.rs`, and the hub layer that drives the
node (`crates/morph-cli/src/hub.rs`).
Out of scope (audited elsewhere): the on-chain consensus scripts
(`morph-state-type`, `morph-factory-type`, `morph-vault-lock`,
`morph-sponsor-lock`, `morph-script-common`), the per-feature wire format in
`schemas/morph.mol`, the watchtower policy layer, the Fiber integration
scripts, the Morph Hub UI, the paper.

---

## 0. Why this audit exists

`docs/swarm-audit-SYNTHESIS.md` is the master audit log. It is anchored at
commit `aa71651` and contains 96 W-track + 13 paper findings. None of those
findings are about `morph-core/src/node.rs` or the invoice layer, because
those surfaces did not exist at that commit:

```
$ git log --oneline --reverse -- crates/morph-core/src/node.rs
c2eb66d Add Morph node invoice layer and hub UI       ← after aa71651
3b70a0f Make Morph Hub flows production ready
c424da9 Make Morph Hub API backed and production ready
39f0846 Make Morph Hub actions and provenance explicit  ← HEAD, ahead of origin
```

The invoice subsystem, the host-side state machine, the HTTP hub, and the
entire `ui/morph-hub/` frontend are all post-`aa71651` work. The swarm audit
did not see any of it. This document is the focused audit for the surfaces
the swarm audit missed.

Anchor to the swarm audit by **finding ID** when cross-referencing (e.g.
"W2-01 domain string drift"). Anchor to this document by **section number**
(e.g. "X-01 domain string inconsistency"). Do not collapse the two.

---

## 1. Scope and architecture

`morph-core/src/node.rs` (929 lines including the unstaged
`insert_decoded_received` addition) defines a host-side state machine for a
single Morph node:

```
MorphNodeState
├── peers:      BTreeMap<NodeId, MorphPeer>                       (line 530)
├── channels:   BTreeMap<ChannelId, MorphChannelRecord>          (line 531)
├── factories:  BTreeMap<FactoryId, MorphFactoryRecord>          (line 532)
├── invoices:   MorphInvoiceBook                                 (line 533)
└── completed_flows: BTreeSet<MorphBusinessFlow>                 (line 534)
```

The layer is **not** the on-chain consensus. The on-chain consensus lives
in `contracts/morph-state-type/` (signed state header + partition
conservation) and `contracts/morph-factory-type/` (factory state root +
reserve Merkle). The host-side state machine here is local bookkeeping
that the operator pushes to a state file via `crates/morph-cli/src/hub.rs`.
The on-chain scripts do not depend on this layer; this layer is what an
operator or a watchtower uses to mirror observed on-chain state.

The invoice subsystem inside this file implements a Lightning-style HTLC
invoice (`MorphInvoice` + `MorphInvoiceBook`):

- Prefix `morph1`, hex payload, 8-byte BLAKE2b checksum
- `invoice_id = BLAKE2b("CKB_MORPH_INVOICE_ID" || fields_without_id)` —
  identifier *is* the digest
- `payment_hash = BLAKE2b(preimage)` — 32-byte preimage, 32-byte hash
- Status machine: `Open → {Received, Cancelled}` and
  `Open | Received → {Paid, Expired}`
- Description capped at 280 bytes; expiry must be strictly after creation
- No amount, network, or peer authentication; the preimage is the only
  possession-based proof of entitlement

`hub.rs` (3061 lines) wraps this with an HTTP API, bearer-token auth, a
mutex-guarded atomic mutate-then-persist loop, and a `/api/state-file`
endpoint that returns the full persisted state (which includes every
stored invoice's `payment_preimage`).

The on-chain↔host trust boundary is: on-chain is the source of truth;
host is a mirror that the operator (or watchtower) is responsible for
keeping honest. **This boundary is not stated in `node.rs`.** It is
implicit. See NODE-01 below.

---

## 2. Consensus node layer findings

### NODE-01 — Host-side transitions do not verify the on-chain witness

**Severity: HIGH.**
**Surface:** `crates/morph-core/src/node.rs:637-770`
(`publish_state`, `splice_channel`, `finalise_channel`,
`materialise_child_channel`, `advance_factory`).

Each transition function checks structural invariants only (epoch advances,
context id differs, channel exists, factory is known). None of them accept
or require the on-chain witness that justifies the transition:

- `publish_state(channel_id, funding_context_id, state_number)` accepts
  any `state_number > channel.state_number` and any matching
  `funding_context_id` (line 637-661). The signed
  `StateHeader.signing_digest()` is not an input.
- `splice_channel(channel_id, new_funding_epoch, new_funding_context_id)`
  (line 715-740) does not require a `SpliceHeader` whose
  `base_state_number == channel.state_number`, and does not require a
  `SpliceHeader.signing_digest()` to be presented.
- `advance_factory(factory_id, new_update_number)` (line 766-783) and
  `materialise_child_channel(...)` (line 785-815) accept any
  monotonic `update_number` and any child whose counterparty is a factory
  participant; they do not require a `FactorySpliceHeader` with
  `old_update_number == factory.update_number`.
- `finalise_channel` (line 700-713) does not require the state being
  finalised to be the highest `state_number` ever published for the
  channel.

A buggy or compromised caller can therefore push the local state to a
posture that does not match the on-chain State Cell set. The on-chain
scripts are unaffected, so no value is at risk; but anything downstream
that trusts the host state (operator dashboard, watchtower, hub's
`/api/state`) will misreport.

**Design intent** (per the swarm audit's framing of host vs on-chain):
the on-chain layer is the source of truth and the host is a mirror. The
code reads this way. The cost is that the API surface gives the
appearance of being able to *publish* a state when the only honest use is
to *record* one.

**Recommendation.** Either:

1. Rename the methods to make the record-vs-publish intent explicit
   (`record_published_state`, `record_splice`, `record_factory_update`)
   and accept a `SignedStateEnvelope` or `SignedSpliceHeader` witness
   that the function verifies; or
2. Add a doc comment at the top of `node.rs` that names the on-chain
   trust boundary, lists the transition functions as
   "operator-must-supply-on-chain-proof", and cross-references
   `morph-state-type/src/main.rs` for the script-level enforcement.

Option 2 is a 10-line doc patch; option 1 is a small API change that
forces the hub to pipe the on-chain observation through. Option 1 is
cleaner and removes a class of footgun; option 2 is a no-cost
clarification.

### NODE-02 — `finalise_channel` does not require state_number closure

**Severity: MEDIUM.**
**Surface:** `crates/morph-core/src/node.rs:700-713`.

```rust
pub fn finalise_channel(&mut self, channel_id: &Bytes32) -> NodeResult<()> {
    let channel = self.channels.get_mut(channel_id)
        .ok_or(NodeError::ChannelNotFound)?;
    if channel.phase != Phase::Settling {
        return Err(NodeError::ChannelNotSettling);
    }
    channel.phase = Phase::Closed;
    ...
}
```

A channel can be transitioned `Active → Settling → Closed` after a single
`publish_state` call that bumps `state_number` to 2. There is no
requirement that the state being closed is the *latest* signed state, that
both parties have signed it, that the challenge window has elapsed, or
that the on-chain `StateCell` for the new state is committed.

The on-chain close (in `morph-state-type`) enforces the cooperative vs
unilateral close path; the host-side close here is a bookkeeping
transition only. But the method's name suggests it finalises the
*state*, not just the *bookkeeping*. A reader who uses `finalise_channel`
without first observing the on-chain close transaction will close the
host record while the channel is still live on-chain.

**Recommendation.** Rename to `record_channel_finalised` (per NODE-01
option 1), or document that the operator must verify the on-chain close
transaction before calling this.

### NODE-03 — `splice_channel` does not bind base_state_number

**Severity: MEDIUM.**
**Surface:** `crates/morph-core/src/node.rs:715-740`.

A splice on the on-chain side requires `SpliceHeader.base_state_number`
to match the current `StateHeader.state_number` (the splice is a
re-anchoring at a specific state number). The host-side
`splice_channel` does not check this. It only checks
`new_funding_epoch > channel.funding_epoch` and
`new_funding_context_id != channel.funding_context_id`.

This means: a buggy operator that calls `splice_channel` with the right
new epoch but at the wrong state number will push the host state to a
posture the on-chain scripts would reject. The on-chain scripts catch
it; the host state is wrong. Same shape as NODE-01.

**Recommendation.** Either accept the `SpliceHeader` and verify
`header.base_state_number == channel.state_number`, or rename and
document.

### NODE-04 — `open_factory` does not derive `factory_id` from participants

**Severity: MEDIUM.**
**Surface:** `crates/morph-core/src/node.rs:746-765`.

`open_factory` accepts any non-zero `factory_id`, only checking
`!participant_node_ids.is_empty()`, no zero members, and that the local
node is a member. Two factories with identical participants but different
`factory_id`s are accepted (lines 746-765, plus `test_factory_*` in
`node_invoice.rs:150-231`).

The on-chain factory id is `H(participants || …)` (see
`morph-factory-type`). If the host-side `factory_id` does not match the
on-chain id, the operator will push a state record that no on-chain
script can resolve.

**Recommendation.** Reject the caller-supplied `factory_id` and derive
it from the sorted `participant_node_ids` plus a version tag. This is a
4-line change in `open_factory`.

### NODE-05 — `peer.alias` is unbounded `String`

**Severity: LOW.**
**Surface:** `crates/morph-core/src/node.rs:612-625`
(`connect_peer` accepts `MorphPeer { node_id, alias: String }`).

`alias` has no length cap and no character-set validation. A peer
connecting with `alias = "a".repeat(1_000_000)` would cause a 1 MB
allocation in `BTreeMap`. Persisted to `/api/state-file` as JSON, this
becomes a 1 MB JSON document, which is then read back into memory on
restart (`from_persisted` at `hub.rs:748-751`).

The invoice's `description` field has the 280-byte cap
(`MAX_INVOICE_DESCRIPTION_LEN`, `node.rs:13`). Apply the same shape to
`alias` (cap bytes, reject control characters).

### NODE-06 — `MorphNodeState` has no internal lock

**Severity: LOW.**
**Surface:** `crates/morph-core/src/node.rs:537-771`.

`MorphNodeState` uses `&mut self` exclusively. `hub.rs` wraps the
state in `Arc<Mutex<HubStore>>` (`mutate` at `hub.rs:1289-1303`) and
uses a `clone → mutate → persist → swap` pattern to avoid panics on
contention, so concurrent calls are serialised at the hub layer. The
test at `hub.rs:2246` (`rejected_mutation_does_not_commit_partial_peer_state`)
verifies that a failed mutation is rolled back. This is correct, but
the contract is not visible from `node.rs`. A future caller that
constructs a `MorphNodeState` directly (not through the hub) and uses
it from multiple threads without external synchronisation would race
on the BTreeMaps.

**Recommendation.** Either add a `Send + Sync` doc comment, or accept
that `MorphNodeState` is a single-threaded type and document the hub's
responsibility to serialise access. Currently neither is stated.

### NODE-07 — `peer.alias` is also used to derive the persisted peer's
display identity

**Severity: LOW.**
**Surface:** `crates/morph-cli/src/hub.rs:1846-1854` and the hub's
`peer_view`.

The hub stores `peer_pubkeys: BTreeMap<NodeId, String>` separately from
`MorphNodeState.peers` so that the canonical sec1 pubkey is recovered
from the persisted state file. The `MorphPeer.alias` is free-form and
not authenticated against the pubkey. A peer record with a misleading
alias is therefore possible. For state-channel routing this is a UX
issue, not a security issue, but worth noting.

---

## 3. Invoice subsystem findings

### INV-01 — Domain string version convention is broken

**Severity: HIGH.**
**Surface:** `crates/morph-core/src/node.rs:9-10` and
`crates/morph-core/src/hash.rs:9-17`.

The protocol has 11 wire-format domain strings. The convention is
`CKB_MORPH_<NAME>`. 9 of the 11 follow this exactly. 2 diverge:

| Location | String | Form |
|----------|--------|------|
| `hash.rs:9`  | `STATE_DOMAIN` | `CKB_MORPH_CHANNEL_STATE` (no version) |
| `hash.rs:10` | `FUNDING_CONTEXT_DOMAIN` | `CKB_MORPH_FUNDING_CONTEXT` (no version) |
| `hash.rs:11` | `PARTICIPANTS_DOMAIN` | `CKB_MORPH_PARTICIPANTS` (no version) |
| `hash.rs:12` | `SPLICE_HEADER_DOMAIN` | `CKB_MORPH_SPLICE_HEADER` (no version) |
| `hash.rs:13` | `SPLICE_DELTA_DOMAIN` | `CKB_MORPH_SPLICE_DELTA` (no version) |
| `hash.rs:14` | `VAULT_DESCRIPTOR_DOMAIN` | `CKB_MORPH_VAULT_DESCRIPTOR` (no version) |
| `hash.rs:15` | `FACTORY_SPLICE_HEADER_DOMAIN` | `CKB_MORPH_FACTORY_SPLICE_HEADER` (no version) |
| `hash.rs:16` | `FACTORY_VAULT_DESCRIPTOR_DOMAIN` | `CKB_MORPH_FACTORY_VAULT_DESCRIPTOR` (no version) |
| `hash.rs:17` | `FACTORY_VAULT_DELTA_DOMAIN` | `CKB_MORPH_FACTORY_VAULT_DELTA` (no version) |
| `node.rs:9`  | `INVOICE_PAYLOAD_MAGIC` | `CKB_MORPH_INVOICE_V1` (**has `_V1`**) |
| `node.rs:10` | `INVOICE_ID_DOMAIN` | `CKB_MORPH_INVOICE_ID` (no version) |

Cross-references:

- The paper's signing digest (W2-01, anchor at `aa71651`) uses
  `CKB_MORPH_CHANNEL_STATE_V1` (with `_V1`). The implementation
  dropped the suffix. The swarm audit flagged this as paper↔code drift.
- The invoice *added back* a `_V1` suffix. The two domains disagree
  on whether versioning lives in the string.

**Risk.** A future version bump (e.g. a v2 invoice format) cannot
follow the same convention as the existing domains unless a decision is
made now. An external verifier that reads the constants
character-for-character will accept invoices for which the state
header is rejected (or vice versa). Today, since all verification is
on-chain, there is no interop gap; the risk is at the
"future audit / external verifier / off-chain signer" boundary.

**Recommendation.** Pick one convention. Options:

1. Strip `_V1` from `INVOICE_PAYLOAD_MAGIC`. Match the existing
   convention. State-side stays at `CKB_MORPH_CHANNEL_STATE`.
   This is the *minimum-churn* choice; W2-01 stays open as paper drift.
2. Add `_V1` to all 9 `hash.rs` domains. Match the paper. Higher
   cost (a hard-fork on the wire if any signed payload already uses
   the bare string), but it makes the wire format consistent with the
   paper's claim.

Option 1 is the recommended path; the W2-01 paper patch (drift paper
to bare string) is then the only remaining fix.

### INV-02 — Invoice has no payee signature

**Severity: HIGH.**
**Surface:** `crates/morph-core/src/node.rs:139-355`
(`MorphInvoice` + `NewMorphInvoice` + `encode/decode/validate`).

`MorphInvoice` carries `payee_node_id: Bytes32` (line 143) but the
`payload_bytes()` (line 301-307) does not include any signature over
the payload. A malicious actor can craft an invoice claiming to be from
any pubkey. The HTLC preimage is the only possession-based proof of
entitlement: only the payee (or whoever holds the preimage) can settle
the invoice.

In practice this is partially mitigated by `BLAKE2b(encoded_invoice)`
in `validate` (the `invoice_id` is the digest of the fields, line
254-256), so a tampered invoice will fail to re-derive. But the
*origin* of the encoded invoice is unauthenticated.

Compare to Lightning BOLT-11, which has an optional `signature` field
that wallets warn about if missing. Morph's invoice has no signature at
all, no warning mechanism, and no way to bind `payee_node_id` to the
pubkey that signs the eventual settlement state.

**Recommendation.** Add a `payee_signature: Option<[u8; 64]>` field
that signs the canonical payload, with `payee_node_id` recoverable from
the signature. The wallet/hub should warn or reject invoices without a
valid signature from the claimed `payee_node_id`. This is a 30-line
addition to `encode`/`decode`/`validate` and a small UI change.

### INV-03 — `description` length check happens after allocation

**Severity: MEDIUM (DoS).**
**Surface:** `crates/morph-core/src/node.rs:323-354` (`from_payload_bytes`).

```rust
let description_len = cursor.read_u16()? as usize;
let description = cursor.read_string(description_len)?;
...
// validate() rejects if description.len() > 280
```

`read_string` calls `String::from_utf8(bytes.to_vec())`, allocating up
to `description_len` bytes. The check against
`MAX_INVOICE_DESCRIPTION_LEN = 280` only runs in `validate()` after
the allocation. An attacker can submit a 65 KB invoice (`description_len
= 0xFFFF` with enough trailing data); the decoder will allocate 65 KB,
run validation, and reject. The rejection is fast, but the allocation
is the DoS surface.

**Recommendation.** Validate `description_len <= MAX_INVOICE_DESCRIPTION_LEN`
*before* the read, inside `from_payload_bytes` (or inside `decode` after
the cursor read but before the string allocation).

### INV-04 — `insert_decoded_received` does not check `payee_node_id` is not local

**Severity: MEDIUM.**
**Surface:** `crates/morph-core/src/node.rs:412-433` (the unstaged
`insert_decoded_received`).

The new `receive_decoded_invoice` flow (added in the unstaged changes,
exposed via `hub.rs:974-987` at `/api/invoices/decode`) decodes an
arbitrary `encoded_invoice` and stores it as `Received`. It does not
check whether `invoice.payee_node_id == self.node_id` — a node can
"receive" an invoice it created itself, which transitions it directly
to `Received` without ever having been `Open`. The downstream
`/api/invoices/{id}/settle` flow (hub line 1152-1166) then becomes
the canonical route for the payee to settle their own invoice using
their own preimage, which is a footgun but not a security issue (the
value still flows correctly through the channel).

The simpler `receive_invoice` (line 625-630) has the same shape: it
takes a `Bytes32` invoice id and trusts the caller. The new flow is
strictly worse because it bypasses the `Open → Received` step.

**Recommendation.** Reject in `insert_decoded_received` if
`invoice.payee_node_id == self.node_id` (or document the intended use).

### INV-05 — `payment_preimage` is persisted to disk in plaintext

**Severity: HIGH.**
**Surface:** `crates/morph-cli/src/hub.rs:689` (`persisted()`),
`hub.rs:695-704` (`persist()`), `hub.rs:877-879`
(`/api/state-file` GET endpoint), `hub.rs:1505-1537`
(`write_private_file_atomic` / `create_private_new_file`),
`hub.rs:2220-2245` (test `hub_state_file_is_owner_only_after_sensitive_invoice_persist`).

Once a `settle_invoice` call is made, `StoredMorphInvoice.payment_preimage`
(line 184, `node.rs`) is set. The `persisted()` function at hub line
689 includes the full `StoredMorphInvoice` in `PersistedHubState.invoices`.
The `persist()` function (line 695) serialises that via
`serde_json::to_vec_pretty` and writes it to disk via
`write_private_file_atomic`. The test at hub line 2214-2245 explicitly
verifies the resulting file is mode `0o600` (owner-only) on Unix.

The defence-in-depth is "the file is owner-only". This is sound for
single-user, but:

- On a multi-user host, root can still read it.
- Anyone with the bearer token can hit `/api/state-file` (hub line
  877-879) and receive the full JSON, which contains every preimage.
- The preimage is a 32-byte secret. Once leaked, anyone holding it
  can settle the same invoice again on a different node (or replay
  the proof of payment). The preimage is the *value* in the HTLC.

**Recommendation.** Two layered fixes:

1. Custom `Serialize` / `Deserialize` for `StoredMorphInvoice` that
   skips `payment_preimage` on persist, and accepts it only as an
   input field on `/api/invoices/{id}/settle`. This breaks the
   on-disk leak.
2. Add a "settled invoice preimage" log separate from the
   `MorphInvoiceBook` and never expose it via `/api/state`. The
   hub already has an event log (`push_event`); use a sidecar file
   keyed by `invoice_id` instead of embedding in the state.

The defence-in-depth "file is mode 0o600" should stay; it is correct
but it is not the only line of defence.

### INV-06 — Cross-network invoices are accepted on decode

**Severity: MEDIUM.**
**Surface:** `crates/morph-core/src/node.rs:240-259` (`decode`),
`node.rs:412-433` (`insert_decoded_received`).

`MorphInvoice::decode` (line 240) parses the embedded `network` field
but never compares it to the local node's network. `create_invoice`
(line 626-637) overrides the request's network with `self.network`,
but the inbound `insert_decoded` (line 432-449 in the
`MorphInvoiceBook` impl) and the new `insert_decoded_received` both
store the invoice as-is.

A Devnet node can therefore store an invoice claiming to be
`MorphNetwork::Mainnet`. The hub's `/api/state` view will report it
as a Mainnet invoice. If a downstream consumer trusts the network
field of the stored invoice, it could route value across networks.

**Recommendation.** In `decode` and `insert_decoded_received`, reject
if `invoice.network != expected_network` (where `expected_network` is
injected from the node at call time, or read from a
`MorphNodeState` context).

### INV-07 — `payment_hash = [0u8; 32]` is a degenerate preimage

**Severity: LOW.**
**Surface:** `crates/morph-core/src/node.rs:207-212`.

`MorphInvoice::new` accepts a `payment_preimage: Option<Bytes32>`. If
the caller passes `Some([0u8; 32])`, the derived `payment_hash` is
`BLAKE2b([0u8; 32])` which is some non-zero value, so the `ZeroIdentifier`
check (line 212) passes. The preimage is then stored in plaintext
(see INV-05). Any party that learns `BLAKE2b([0u8; 32])` cannot
recover the preimage (BLAKE2b is a one-way function), so this is not
a security issue *per se*, but it is a degenerate state that should
be rejected by convention.

**Recommendation.** Reject `payment_preimage == [0u8; 32]` in `new()`
and reject the symmetric `payment_hash == [0u8; 32]` (already done
by `validate_bytes32_nonzero` at line 212).

### INV-08 — `now_unix` is trusted at every API boundary

**Severity: MEDIUM.**
**Surface:** `crates/morph-cli/src/hub.rs:2173-2178` (`now_unix`),
every call to `node.settle_invoice`, `node.receive_invoice`,
`node.receive_decoded_invoice`, `node.cancel`.

`now_unix()` reads `SystemTime::now()`. It is a trusted system clock.
The hub has no NTP sanity check. An operator whose system clock is
skewed could see "expired" invoices that are not actually expired (or
vice versa), and a state-channel challenge window could appear to
elapse or not based on the clock.

This is not a code-level fix; it is an operational requirement. But
the code does not document it. The `test node_rejects_self_peer`
test passes a hard-coded `now_unix: 1_100` etc., which is correct
for tests but masks the operational assumption.

**Recommendation.** Document the clock-trust assumption at the top of
`hub.rs` and `node.rs`. Optionally, accept an `--allow-clock-skew`
or `--trusted-clock-source` flag for the hub to assert its clock has
been synchronised.

### INV-09 — Invoice `amount` is unbounded `u128`

**Severity: LOW.**
**Surface:** `crates/morph-core/src/node.rs:146, 198-200`.

`amount: Amount` where `Amount = u128`. The only check is `amount != 0`
(line 198). An invoice with `amount = u128::MAX` is accepted. The
on-chain state transition will reject the corresponding settlement
because the channel's asset balance cannot fund it, but the host-side
invoice is created and broadcast.

For an HTLC invoice, an over-amount invoice is mostly a UX issue. For
a real production node it is a footgun.

**Recommendation.** Cap at the channel's `local + remote` balance at
creation time. Optional, since the on-chain script catches it.

### INV-10 — `description` is byte-counted, not char-counted

**Severity: LOW.**
**Surface:** `crates/morph-core/src/node.rs:13, 274-276`.

`MAX_INVOICE_DESCRIPTION_LEN = 280` is a byte cap, not a Unicode
codepoint or grapheme cap. A description of 280 emoji (each 4 bytes
in UTF-8) would be 1120 bytes and rejected. A description of 70 CJK
characters would be 210 bytes and accepted; 80 CJK would be 240
bytes and accepted. Inconsistent: the displayed "characters" vary by
factor 4× across Unicode blocks.

**Recommendation.** Either keep the byte cap and document it
explicitly ("280 bytes; up to 280 ASCII, up to 70 emoji, etc."),
or switch to a grapheme cap (`unicode-segmentation`) and document
the dependency.

### INV-11 — `morph1` prefix is hex, not bech32

**Severity: LOW (interop).**
**Surface:** `crates/morph-core/src/node.rs:11, 230-238`.

`encode()` produces `morph1` + hex(payload) + hex(checksum). Hex is
not the standard for human-readable, error-corrected identifiers.
Lightning BOLT-11 uses bech32. A wallet that copies an invoice and
loses 1 character will detect a bech32 error; hex has no such
recovery. The 8-byte checksum is BLAKE2b truncated, not a bech32
polymod, so it can detect accidental corruption but not suggest
corrections.

**Recommendation.** Migrate to bech32m with a 6-character HRP
(`morph1q...`). Adds 80 lines of encoding logic; trades hex for
typed error correction. Optional, document as future work.

### INV-12 — `payment_preimage` is a 32-byte raw secret

**Severity: LOW.**
**Surface:** `crates/morph-core/src/node.rs:185, 207-212, 287-292`.

The preimage is a 32-byte value with no provenance: any 32 bytes will
do, including `[0u8; 32]`. BLAKE2b-preimage-of-payment-hash is the
uniqueness guarantee. For high-value HTLCs, the preimage should be
high-entropy. The current API does not require this; a payee could
intentionally choose a low-entropy preimage (e.g. a counter) and rely
on BLAKE2b preimage resistance to keep it secret.

In practice BLAKE2b is a strong PRF, so this is not exploitable. But
the API should warn or recommend `OsRng.gen::<[u8; 32]>()`.

**Recommendation.** Add a `generate_preimage()` helper in `node.rs`
that reads from `OsRng` and returns the preimage; have the hub's
`/api/invoices` endpoint default to it when no preimage is supplied.

---

## 4. Cross-cutting findings

### X-01 — Domain string version inconsistency
Already covered as INV-01. The two domains that disagree are
`STATE_DOMAIN` and `INVOICE_PAYLOAD_MAGIC`. See INV-01 for the
recommendation.

### X-02 — `from_persisted` re-validates invoices

**Severity: INFO (positive).**
**Surface:** `crates/morph-cli/src/hub.rs:821-823`.

```rust
for invoice in persisted.invoices {
    node.invoices.insert_stored(invoice)?;
}
```

`insert_stored` calls `stored.invoice.validate()` (line 363 in
`node.rs`) and re-derives the `invoice_id` from the fields. A
tampered state file is caught at startup. This is the right shape;
it means the on-disk file is integrity-protected at parse time, not
just at the JSON parse layer.

Note: the validation does *not* catch a tampered `payment_preimage`,
because the preimage is not part of the invoice_id derivation. The
preimage is a sidecar value; tampering with it produces a different
preimage that the on-chain settlement would reject. Acceptable.

### X-03 — `completed_flows` is restored from disk without validation

**Severity: LOW.**
**Surface:** `crates/morph-cli/src/hub.rs:824`.

```rust
node.completed_flows = persisted.completed_flows.into_iter().collect();
```

The `completed_flows` set is restored from the persisted file without
checking it against `required_business_flows()`. A state file that
claims `completed_flows` is full will pass `missing_business_flows() == ∅`
even if no real flows have happened. This is fine for an operator-driven
hub (the operator is the source of truth), but it is worth noting that
the "all flows complete" check is not a security property — it is a
UX hint.

---

## 5. Test surface

### TEST-01 — Coverage in `node_invoice.rs` is structurally good, semantically thin

**Surface:** `crates/morph-core/tests/node_invoice.rs:1-279` (8 tests).

The 8 tests cover:

- `invoice_round_trips_and_rejects_tampering` — encode/decode + checksum
- `invoice_settlement_requires_matching_preimage_and_live_invoice` —
  settle flow with preimage, expiry rejection
- `node_channel_lifecycle_publishes_and_finalises_current_context` —
  publish/finalise with funding_context check
- `node_rejects_self_peer_and_self_channel` — self-peer guard
- `splice_advances_funding_context_without_allowing_stale_publication` —
  splice + post-splice state publish
- `factory_requires_local_participant_and_child_counterparty_membership`
- `factory_materialises_child_channel_once`
- `node_records_all_business_flows_when_sequence_completes`

Missing negative tests (recommended additions):

- INV-02: invoice with no `payee_signature` is still accepted
- INV-03: invoice with `description_len = 0xFFFF` allocates 65 KB before
  validation rejects
- INV-04: `receive_decoded_invoice` on a self-created invoice (the
  unstaged change has no test)
- INV-06: invoice on `Mainnet` is accepted by a `Devnet` node
- INV-07: `payment_preimage = [0u8; 32]` is accepted
- NODE-04: two factories with the same participants and different
  `factory_id` are both accepted
- NODE-01 (light): `publish_state` accepts a `state_number` that does
  not match any signed `StateHeader`

The swarm audit's W5-03 finding (no property-based testing) applies
here. The invoice parser and the host state machine are good
candidates for `proptest`:

- `proptest!` for `MorphInvoice::encode → decode` round-trip with
  random valid payloads
- `proptest!` for `MorphNodeState` transitions (e.g. `publish_state`
  on a sequence of random `state_number` values, asserting that
  invariants hold)
- `proptest!` for the factory non-interference invariant across
  random participant sets

### TEST-02 — `hub.rs` has unit tests for the persistence layer

**Surface:** `crates/morph-cli/src/hub.rs:2180-2245+` (unit tests
inside the file).

The hub test module covers:

- `request_parser_rejects_oversized_request_lines` — line 2194
- `hub_state_file_is_owner_only_after_sensitive_invoice_persist` —
  line 2214 (verifies the `0o600` mode after a preimage-bearing
  invoice is persisted)
- `rejected_mutation_does_not_commit_partial_peer_state` — line 2246

The preimage-persistence test (line 2214) is the test that names the
concern behind INV-05. It documents the current design (file mode
defence) but does not address the leak itself.

Missing: tests for `/api/state-file` access control (it is gated by
auth; should be tested). Missing: tests for the new
`receive_decoded_invoice` flow (the unstaged `insert_decoded_received`
has no test).

---

## 6. Findings summary

| ID | Severity | Surface | Theme |
|----|----------|---------|-------|
| NODE-01 | HIGH | `node.rs:637-770` | Transitions lack on-chain witness |
| NODE-02 | MEDIUM | `node.rs:700-713` | `finalise_channel` no state-number closure |
| NODE-03 | MEDIUM | `node.rs:715-740` | `splice_channel` no `base_state_number` check |
| NODE-04 | MEDIUM | `node.rs:746-765` | `factory_id` not derived from participants |
| NODE-05 | LOW | `node.rs:612-625` | `peer.alias` unbounded |
| NODE-06 | LOW | `node.rs:537-771` | No `Send + Sync` contract documented |
| NODE-07 | LOW | `hub.rs:1846-1854` | `alias` not authenticated against pubkey |
| INV-01 | HIGH | `node.rs:9-10` ↔ `hash.rs:9-17` | Domain string version convention broken |
| INV-02 | HIGH | `node.rs:139-355` | No payee signature on invoice |
| INV-03 | MEDIUM (DoS) | `node.rs:323-354` | `description_len` checked after allocation |
| INV-04 | MEDIUM | `node.rs:412-433` (unstaged) | `receive_decoded_invoice` no self check |
| INV-05 | HIGH | `hub.rs:689, 877-879` | `payment_preimage` persisted in plaintext |
| INV-06 | MEDIUM | `node.rs:240-259, 412-433` | Cross-network invoice accepted on decode |
| INV-07 | LOW | `node.rs:207-212` | Zero preimage accepted |
| INV-08 | MEDIUM | `hub.rs:2173-2178` | Clock-trust assumption not documented |
| INV-09 | LOW | `node.rs:146` | `amount` unbounded `u128` |
| INV-10 | LOW | `node.rs:13` | Description cap is bytes, not chars |
| INV-11 | LOW (interop) | `node.rs:11` | `morph1` prefix is hex, not bech32 |
| INV-12 | LOW | `node.rs:185` | Preimage has no entropy check |
| X-02 | INFO | `hub.rs:821-823` | `from_persisted` re-validates invoices (positive) |
| X-03 | LOW | `hub.rs:824` | `completed_flows` restored without validation |
| TEST-01 | LOW | `tests/node_invoice.rs` | Missing negative tests for INV-02..07, NODE-01, NODE-04 |
| TEST-02 | LOW | `hub.rs:2180+` | Missing tests for `/api/state-file` auth + new `receive_decoded_invoice` |

Counts: 23 findings, 4 HIGH, 9 MEDIUM, 9 LOW, 1 INFO.

---

## 7. Recommendations (ordered by P0 / P1 / P2)

### P0 (within 24h, security-relevant)

- **REC-01 — INV-05 strip `payment_preimage` from persist.** Custom
  `Serialize` / `Deserialize` for `StoredMorphInvoice` that omits the
  preimage on write and accepts it only as an input on the
  `/api/invoices/{id}/settle` endpoint. Owner: code-maintainer.
  Effort: 1 day, 50 lines + 1 test.
- **REC-02 — INV-01 fix domain string convention.** Strip `_V1`
  from `INVOICE_PAYLOAD_MAGIC` to match the 9 other domains. Apply
  the W2-01 paper patch (drift paper to bare string) so paper and
  code agree. Owner: code-maintainer + paper-author. Effort: 2
  hours.
- **REC-03 — INV-02 add payee signature to invoice.** Add an
  optional `payee_signature: Option<[u8; 64]>` field; the hub
  warns or rejects when the field is absent and `payee_node_id`
  is not the local node. Owner: code-maintainer. Effort: 1 day.

### P1 (within 1 week)

- **REC-04 — NODE-01 either rename transitions or add a host-side
  trust-boundary doc comment.** Owner: code-maintainer.
  Effort: 30 minutes (doc option) or 3 days (API option).
- **REC-05 — NODE-04 derive `factory_id` from participants.** 4-line
  change in `open_factory`. Owner: code-maintainer. Effort: 1 hour.
- **REC-06 — INV-03 validate `description_len` before allocation.**
  2-line change in `from_payload_bytes`. Owner: code-maintainer.
  Effort: 10 minutes.
- **REC-07 — INV-06 cross-network invoice rejection.** Reject in
  `decode` and `insert_decoded_received`. Owner: code-maintainer.
  Effort: 1 hour.
- **REC-08 — INV-04 reject self-receive in `insert_decoded_received`.**
  Owner: code-maintainer. Effort: 10 minutes.
- **REC-09 — NODE-02 / NODE-03 rename or document `finalise_channel`
  and `splice_channel`.** Owner: code-maintainer. Effort: 1 hour.

### P2 (within 1 month, hardening)

- **REC-10 — INV-08 document clock-trust assumption.** Doc patch at
  `node.rs:1` and `hub.rs:1`. Owner: code-maintainer.
- **REC-11 — INV-10 / INV-11 / INV-12 invoice ergonomics** (char
  cap, bech32, preimage entropy). Owner: code-maintainer.
- **REC-12 — TEST-01 add 7 negative tests** (see TEST-01 list).
  Owner: code-maintainer. Effort: 1 day.
- **REC-13 — TEST-02 add tests for `/api/state-file` auth** and
  the new `receive_decoded_invoice` flow. Owner: code-maintainer.
- **REC-14 — W5-03 follow-on: proptest for invoice parser and host
  state machine.** Owner: code-maintainer. Effort: 2-3 days.
- **REC-15 — NODE-05 cap `peer.alias` length** (mirror
  `MAX_INVOICE_DESCRIPTION_LEN`). Owner: code-maintainer. Effort:
  30 minutes.

---

## 8. Cross-references to the swarm audit

The following swarm-audit findings are *adjacent* to this audit but
not covered by it. They remain as-is in the swarm-audit ledger:

- W1-01 to W1-12 — on-chain script findings, not host-side
- W2-01 to W2-16 — paper↔code drift; INV-01 is the host-side
  counterpart of W2-01
- W2-02 (Phase enum) — paper has 5, code has 4 (`Phase` in
  `types.rs:16-21`); confirmed by reading `types.rs:16-21`. The
  swarm audit notes the code side is also drift; not flagged here
  because it is a paper↔code issue not a host-side issue
- W3-01 to W3-11 — docs; some touch this layer but only
  superficially
- W4-01 to W4-12 — ops/scripts; `node.rs` and `hub.rs` are
  intentionally out of scope for the swarm W4 track
- W5-01 to W5-26 — tests; W5-03 (no property-based testing)
  is restated as TEST-01 here

The two audits are complementary, not overlapping. The swarm audit
is the source of truth for on-chain + paper + ops; this audit is
the source of truth for the host-side state machine and the
invoice layer.

---

## 9. Limitations

- The audit covers the host-side layer only. On-chain consensus is
  in the swarm audit. The two share assumptions (e.g. the
  on-chain `SpliceHeader.base_state_number` invariant that
  NODE-03 references) but this audit does not re-verify those.
- The audit was performed on the working tree at `39f0846` plus the
  unstaged `insert_decoded_received` addition. Findings that
  reference this method (`INV-04`, `TEST-02`) are anchored to
  the unstaged state and may move if the addition changes before
  commit.
- No fuzz testing was performed. The recommended `proptest` work
  in REC-14 would catch additional edge cases (e.g. round-trip
  with adversarial preimages, large balance overflow).
- The `hub.rs` HTTP API is large (3061 lines). The audit covered
  the invoice + channel + factory action routing, the persistence
  path, the auth check, and the `/api/state-file` endpoint. It did
  not cover the watchtower webhook delivery, the SSE event
  streaming, the static asset serving, the CORS handling, or the
  body-parser edge cases. Those are out of scope here.
- The `ui/morph-hub/` frontend (Vite + TypeScript, ~2000 lines of
  `App.tsx`) was not audited. The frontend is purely a consumer
  of the hub's API; if the API has a footgun, the frontend
  inherits it.
