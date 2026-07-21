# Morph Model Re-audit — 2026-07-21

## Decision

Morph should keep its sovereign protocol core:

- Morph Factory owns shared pools, virtual subchannels, local/reduced exits,
  splice, and RGB++ liquidity reuse.
- Morph bilateral channels own the participant-signed state that CKB can force.
- Fiber is a replaceable routing/MPP/invoice/transport provider.
- Agent/x402/credential/fair-exchange services are application sidecars.
- The intended bridge is `Factory right -> materialised bilateral channel ->
  provider-neutral graph edge`.

Building a second proprietary multihop network now would duplicate Fiber's
strongest surface and dilute work on Morph's differentiated CKB/RGB++ state
machine. Deleting Factory to fit today's Fiber RPC would surrender Morph's
strongest surface. The correct integration is a minimal Fiber hook/adapter plus
a provider-neutral Morph edge contract.

Fiber issue #1255 is therefore treated as an Agent application requirements
document, not as authority to replace Morph Factory or its settlement model.

## Scope reviewed

The review followed signed objects from host construction through wire
encoding, package validation, CKB script parsing, transaction construction, and
CKB-VM/devnet evidence. It covered:

- bilateral State/Vault/Sponsor creation, publication, splice, and settlement;
- Factory creation, full and reduced rights updates, local/reduced exits, and
  full/reduced CKB+xUDT splices;
- Factory-to-bilateral materialisation and Fiber edge evidence;
- Agent x402, credential, outgoing-wallet, and fair-exchange boundaries;
- RGB++ asset identity and the current proof/watcher boundary;
- release, watchtower, and external integration readiness.

## Findings

| Severity | Finding | Status |
| --- | --- | --- |
| Critical for Factory integrity | `FactoryStateHeader` did not commit the concrete shared-pool Cell. Creation and ordinary state signatures could not prove the FactoryVault lock/capacity/type/data represented by canonical Factory state. | Fixed in this change. |
| High | `FactorySpliceHeader` signed reserve descriptors and deltas but not the concrete old/new FactoryVault materialisations. | Fixed in this change. |
| High | Ordinary Factory state/reduced-rights/Merkle updates did not have an explicit host-and-script rule preventing reserve-root drift because no reserve root existed. | Fixed in this change. |
| Critical for mainnet provenance | Vault materialisation roots commit Cell content, not the exact CKB OutPoint. A byte-identical, separately funded clone can satisfy a content-only match and create a substitution/orphaning path. This affects bilateral and Factory profiles. | Open; v2 activation/provenance binding required. |
| High | Approved contract deployment identities are checked by operator manifests/allowlists, not pinned by a versioned on-chain deployment profile. | Open; required before external edge admission. |
| High | The implemented Factory signature profile is fixed two-participant/2-of-2 with bounded proof shapes. It is a useful Factory prototype, not yet a general multiparty Factory. | Open; add an explicit versioned multiparty profile rather than silently widening v1. |
| High | Existing Fiber evidence proves real three-node routing and exact hops, but the advertised Fiber edge is not yet backed by live Morph materialisation/failure callbacks inside Fiber's channel state machine. | Open; implement the minimal external-edge hook/adapter. |
| High | RGB++ support has canonical xUDT type-script identity and real CKB transactions, but not a production SPV/leap/reorg proof pipeline. | Open; implement proof verification, confirmation policy, reorg rollback, and watcher evidence. |
| Medium | Agent payments have encrypted state, scoped credentials, policy caps, strict Fiber terminal-status checks, real routing, x402, and fair exchange. Operational ingress, HA/restart, revocation distribution, and abuse/load evidence remain incomplete. | Open. |
| Release blocker | Independent protocol/script review, reproducible release artefacts, value limits, and multi-operator operations remain open. | Open. |

## Changes made

### Signed FactoryVault materialisation

`FactoryStateHeader` grew from 238 to 270 bytes and now appends:

```text
vault_materialisation_root =
  H("CKB_MORPH_VAULT_CELL", lock_hash, capacity, type_hash_or_none, data)
```

Creation requires exactly one FactoryVault output whose lock args bind the
Factory id and Factory type hash and whose materialisation matches the signed
root. Missing, wrong, and ambiguous pools are rejected.

Ordinary full-signature, reduced-rights, and sparse-Merkle updates must preserve
the root. Only the four reserve-changing authorisation kinds may change it:
local exit, reduced exit, full splice, and reduced splice.

### Signed splice bridge

`FactorySpliceHeader` grew from 309 to 373 bytes and now signs the old and new
FactoryVault materialisation roots. Full and reduced splice verification binds
those fields to the old/new Factory headers.

The Factory type scans the transaction for the exact old/new materialisations.
The Factory vault lock independently hashes its own group input and unique
output and compares them with the canonical old/new Factory headers before it
checks reserve conservation. A bug in either script is therefore less likely
to silently remove the boundary.

### Host, package, schema, and devnet parity

- Factory create/splice/exit transaction builders compute roots from the actual
  packed CKB `CellOutput` and data before signing.
- Package JSON carries both splice roots; normal package validation forbids
  materialisation drift.
- Core signing bytes, script parsing, fixed-size envelope dispatch, draft
  schema annotations, hash-parity fixtures, and CKB-VM fixtures use the same
  new layouts.
- New negative tests cover missing/wrong/ambiguous FactoryVault creation and a
  fully signed ordinary update attempting root drift.

## Why the current fix is necessary but not sufficient

The materialisation root closes an authorization gap: participants and scripts
now agree on the exact Cell content. It does not create UTXO provenance. CKB
allows anyone to fund another output with the same lock/capacity/type/data, so
two Cells can have the same content commitment.

The preferred v2 design is a two-stage activation profile:

1. The funding transaction creates the State/Factory cell and Vault with a
   signed content root and an unbound locator.
2. After commitment, participants sign an activation update containing the
   exact Vault OutPoint.
3. The activation transaction includes that Vault as a read-only cell
   dependency so the State/Factory type can verify locator, lock, capacity,
   type, and data without spending it.
4. Every later publication, splice, exit, and settlement preserves or
   explicitly rotates the locator and requires the exact committed input
   OutPoint.

This preserves xUDT/RGB++ type scripts, avoids pretending a lock-only logical id
is globally unique, and does not require Fiber to become Morph's source of
truth. The v1 content-root profile should remain devnet-only after v2 is added;
v1 and v2 must be distinguished by an explicit layout/protocol version.

## RGB++ and Fiber integration plan

1. **Provenance-safe Morph v2** — add exact Vault OutPoint activation and
   rotation for bilateral and Factory profiles, migration fixtures, negative
   clone/substitution tests, and devnet crash/replay evidence.
2. **Morph edge lifecycle** — define a provider-neutral edge id that binds
   Factory right proof, materialised bilateral funding context, live Vault
   locator, asset type script, capacity, expiry, and force-close callback.
3. **Minimal Fiber hook** — add only the capabilities missing from current RPC:
   admit/update/disable an externally enforced edge, query route use by edge
   id, and deliver HTLC settle/fail callbacks. Fiber never owns Morph Factory
   rights or unilateral CKB recovery.
4. **Real routed capacity** — run node1 -> Morph-backed provider edge -> node2
   -> node3 payments, MPP, timeout, partial failure, restart, and forced edge
   withdrawal tests. Evidence must bind Fiber payment ids/hops to Morph edge ids
   and on-chain funding locators.
5. **RGB++ verifier/watcher** — verify asset type-script identity plus Bitcoin
   commitment/SPV proof, CKB binding/leap transaction, confirmation depth, and
   reorg rollback. Quarantine the edge on proof or watcher uncertainty.
6. **Agent layer** — keep x402 exact payment, scoped/delegable credentials,
   policy-capped outgoing wallet, encrypted fair exchange, replay protection,
   and idempotent receipts in `morph-agent`; add HTTP/gRPC ingress and
   revocation/HA/load evidence without moving this authority into Factory.
7. **Release gates** — reproducible ELFs and manifests, clean CI and full
   cross-stack devnet, independent review, multi-operator watchtower rehearsal,
   incident/rollback runbooks, and conservative value caps.

## Verification for this change

- Host workspace tests and fixed-layout/hash parity tests pass.
- Fixture generation/validation passes for bilateral, Factory, splice, reduced
  proof, local exit, and watcher packages.
- 93 CKB-VM tests pass, including all Factory CKB/xUDT positive paths and the
  new materialisation negative paths.

This evidence makes the Factory model materially stronger. It is not a mainnet
or production-readiness claim; the open provenance finding is deliberately a
hard blocker.
