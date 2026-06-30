# Host Node and Invoice Remediation Status

Date: 2026-06-28

This note is the live follow-up for `docs/host-node-invoice-audit.md`. The
audit file remains historical evidence; this file records the current state.

## Fixed in code

| Finding | Status | Evidence |
| --- | --- | --- |
| INV-01 | Fixed | `INVOICE_PAYLOAD_MAGIC` now uses `CKB_MORPH_INVOICE`, matching the unversioned implementation-domain convention without touching consensus signing domains. |
| INV-02 | Fixed | `MorphInvoice` carries a secp256k1 payee public key and payee signature; decode validates the signature and that the pubkey hashes to `payee_node_id`. |
| INV-03 | Fixed | `from_payload_bytes` checks `description_len` before allocating the string. |
| INV-04 | Fixed | `receive_decoded_invoice` rejects invoices whose payee is the local node. |
| INV-05 | Fixed | persisted Hub JSON redacts `payment_preimage`; the Hub state-file/export tests assert it is absent. |
| INV-06 | Fixed | decoded invoices are rejected when their network differs from the local node network. |
| INV-07 / INV-12 | Fixed | all-zero payment preimages are rejected at invoice creation and settlement. |
| INV-09 | Fixed for CKB invoices | CKB invoices are capped at `u64::MAX` shannons in `morph-core`, and Morph Hub applies the same client-side cap. xUDT invoice amounts remain `u128` because xUDT quantities are protocol-level `u128` values. |
| INV-11 | Fixed | new invoices encode as bech32m with HRP `morph`; decode still accepts the legacy `morph1` hex+checksum form for saved invoices. |
| NODE-05 | Fixed | peer aliases are trimmed, required, and capped at 80 bytes in `morph-core`; Morph Hub inputs mirror the cap. |
| TEST-01 | Fixed for the concrete audit cases | `crates/morph-core/tests/node_invoice.rs` plus core unit tests cover signature tampering, self/wrong-network invoice receive, zero preimage, bech32m/legacy invoice decoding, CKB amount bounds, peer alias bounds, stale publication after splice, and factory child materialisation constraints. |

## Refuted or documented

| Finding | Status | Evidence |
| --- | --- | --- |
| NODE-01 | Documented boundary | Host node methods are local mirror transitions, not on-chain witness verifiers. The scripts remain the source of spend truth. |
| NODE-02 / NODE-03 | Documented boundary | Host finalise/splice records local state and funding-context progress; on-chain validity remains script-checked. |
| NODE-04 | Refuted for current scripts | Factory ids are derived from funding input/output identity in `morph-factory-type`, not from participant sets; multiple factories may legitimately share participants. |
| NODE-06 | Operational boundary | `MorphNodeState` remains a plain state object; Hub owns synchronisation with `Arc<Mutex<HubStore>>`. |
| NODE-07 | Partially fixed | Hub now stores pubkeys and derives node ids from pubkeys on restore and API input. Peer aliases remain display names, not identity material. |

## Documented interoperability items

| Finding | Status | Rationale |
| --- | --- | --- |
| INV-08 | Documented | Invoice expiry uses the caller-supplied host clock. This is acceptable for local Hub UX; chain-enforced timeout semantics need an on-chain design. |
| INV-10 | Documented | description cap is byte-based to match payload encoding. |
