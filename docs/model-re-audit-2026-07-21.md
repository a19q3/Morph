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
| Critical for mainnet provenance | Vault materialisation roots committed Cell content, not the exact CKB OutPoint. A byte-identical, separately funded clone could satisfy a content-only match and create a substitution/orphaning path in bilateral and Factory profiles. | Fixed with exact OutPoint activation/rotation; independent review remains required. |
| High | Approved contract deployment identities are checked by operator manifests/allowlists, not pinned by a versioned on-chain deployment profile. | Open; required before external edge admission. |
| High | The implemented Factory signature profile is fixed two-participant/2-of-2 with bounded proof shapes. It is a useful Factory prototype, not yet a general multiparty Factory. | Open; add an explicit versioned multiparty profile rather than silently widening v1. |
| High | Existing Fiber evidence proves real three-node routing and exact hops, but the advertised Fiber edge is not yet backed by live Morph materialisation/failure callbacks inside Fiber's channel state machine. | Open; implement the minimal external-edge hook/adapter. |
| High | RGB++ support has canonical xUDT type-script identity and real CKB transactions, but not a production SPV/leap/reorg proof pipeline. | Open; implement proof verification, confirmation policy, reorg rollback, and watcher evidence. |
| Medium | Agent payments have encrypted state, scoped credentials, policy caps, strict Fiber terminal-status checks, real routing, x402, and fair exchange. Operational ingress, HA/restart, revocation distribution, and abuse/load evidence remain incomplete. | Open. |
| Release blocker | Independent protocol/script review, reproducible release artefacts, value limits, and multi-operator operations remain open. | Open. |

## Changes made

### Signed FactoryVault materialisation

`FactoryStateHeader` first grew from 238 to 270 bytes for the content root, and
is now 302 bytes after appending the exact Vault OutPoint commitment:

```text
vault_materialisation_root =
  H("CKB_MORPH_VAULT_CELL", lock_hash, capacity, type_hash_or_none, data)

vault_outpoint_commitment =
  H("CKB_MORPH_VAULT_OUTPOINT_V1", tx_hash, u32_le(index))
```

Creation requires exactly one FactoryVault output whose lock args bind the
Factory id and Factory type hash and whose materialisation matches the signed
root. It deliberately emits an unbound zero locator. A second transaction
activates the Factory by preserving every other field and proving the exact
Vault as the first raw/direct CellDep. Missing, wrong, ambiguous, cloned, lock-
drifted, and noncanonical-dependency pools are rejected.

Ordinary full-signature, reduced-rights, and sparse-Merkle updates must preserve
the root and locator. Only the four reserve-changing authorisation kinds may
change the root: local exit, reduced exit, full splice, and reduced splice.
Their successor locator must be unbound and reactivated after commitment.

### Signed splice bridge

`FactorySpliceHeader` grew from 309 to 437 bytes and now signs the old and new
FactoryVault materialisation roots and OutPoint commitments. Full and reduced
splice verification binds those fields to the old/new Factory headers. The
bilateral `StateHeader` and `SpliceHeader` are now 346 and 453 bytes.

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
  fully signed ordinary update attempting root drift, byte-identical clone
  activation, activation lock drift, and noncanonical Vault dependency order.

## Exact OutPoint activation and remaining limits

The materialisation root closes the content authorization gap, while the
implemented two-stage activation adds UTXO provenance:

1. The funding transaction creates the State/Factory cell and Vault with a
   signed content root and an unbound locator.
2. After commitment, an activation update changes only the locator to the exact
   Vault OutPoint. Because the funding signature already commits every other
   field and content root, the script can enforce this deterministic update
   without a second discretionary state transition.
3. The activation transaction includes that Vault as its first direct read-only
   CellDep so the State/Factory type can verify locator, lock, capacity, type,
   and data without spending it or confusing it with a DepGroup member.
4. Every later publication, splice, exit, and settlement preserves or
   explicitly rotates the locator and requires the exact committed input
   OutPoint.

This preserves xUDT/RGB++ type scripts, avoids pretending a lock-only logical id
is globally unique, and does not require Fiber to become Morph's source of
truth. The remaining release work is independent review, deployment/version
pinning, and an explicit migration policy for the new wire layout.

## RGB++ and Fiber integration plan

1. **Provenance-safe Morph baseline (implemented)** — exact Vault OutPoint
   activation and rotation now cover bilateral and Factory profiles with
   clone/substitution negatives and full devnet lifecycle evidence; formalize
   migration/version policy and obtain independent review.
2. **Morph edge lifecycle** — define a provider-neutral edge id that binds
   Factory right proof, materialised bilateral funding context, live Vault
   locator, asset type script, capacity, expiry, and force-close callback.
3. **Minimal Fiber hook** — add only the capabilities missing from current RPC:
   admit/update/disable an externally enforced edge, query route use by edge
   id, and deliver HTLC settle/fail callbacks. Fiber never owns Morph Factory
   rights or unilateral CKB recovery. Exercise this control plane in shadow mode
   before carrying value.
4. **RGB++ verifier/watcher** — verify asset type-script identity plus Bitcoin
   commitment/SPV proof, CKB binding/leap transaction, confirmation depth, and
   reorg rollback. Quarantine the edge on proof or watcher uncertainty.
5. **Conditional force-close** — commit the pending-transfer root in Morph
   signed state and make preimage/timeout outcomes enforceable on CKB. A Fiber
   callback is evidence, not the only recovery path.
6. **Real routed capacity** — only after steps 3-5, run node1 -> Morph-backed
   provider edge -> node2 -> node3 payments, MPP, timeout, partial failure,
   restart, and forced edge withdrawal tests. Evidence must bind Fiber payment
   ids/hops to Morph edge ids and on-chain funding locators.
7. **Agent layer** — keep x402 exact payment, scoped/delegable credentials,
   policy-capped outgoing wallet, encrypted fair exchange, replay protection,
   and idempotent receipts in `morph-agent`; add HTTP/gRPC ingress and
   revocation/HA/load evidence without moving this authority into Factory.
8. **Release gates** — reproducible ELFs and manifests, clean CI and full
   cross-stack devnet, independent review, multi-operator watchtower rehearsal,
   incident/rollback runbooks, and conservative value caps.

## Additional implementation defects fixed during this audit

| Boundary | Defect | Remediation |
| --- | --- | --- |
| Sponsor policy | Host parsing read the owner field at the wrong offset, so a valid policy could be attributed to the wrong identity. | Corrected the offset and locked it with a regression test. |
| xUDT channel creation | The devnet builder did not attach the participant proof required by the xUDT creation path. | Added the proof to the real transaction builder and exercised it in stateful devnet. |
| Stateful evidence freshness | Operator-owned report/config files made a fresh run look stale. | Limited freshness comparison to generated protocol artifacts while retaining committed-input checks. |
| Agent/Fiber evidence | Early evidence could demonstrate a terminal provider result without proving a real routed Fiber payment or its exact hops. | Routed both x402 and fair-exchange payments through Fiber node1 -> node2 -> node3 and bound payment ids plus hop pubkeys into the Agent evidence. |
| Factory Vault authority | Factory state and splice signatures did not bind the concrete reserve Cell. | Added content roots to Factory state/splice, independent Factory type/vault checks, and CKB/xUDT negative paths. |
| Vault provenance | Content roots allowed substitution by a separately funded byte-identical Vault. | Added deterministic two-stage OutPoint activation/rotation for bilateral and Factory Vaults and exact-input enforcement on exit/splice/finalise. |
| Activation dependency selection | A raw CellDep index was incorrectly reused as a flattened resolved-dependency index when a secp DepGroup was present. | Made the Vault the first canonical direct CellDep, verified its raw dep type/outpoint, and read resolved CellDep zero; a prefixed dependency now fails. |
| Activation economics | The first activation builder paid one shannon, below real CKB relay/fee acceptance. | Set the activation fee to 10,000 shannons and exercised every reserve-changing devnet flow. |
| Watchtower scan origin | Watch scans began at the funding block even though the enforceable State outpoint is created by activation. | Persist and scan from the activated State block. |
| Evidence budgets | New activation transactions and locator fields invalidated aggregate-cycle and reduced-exit byte baselines. | Recalibrated only the measured suite total and affected reduced-exit byte gate; per-transaction cycle, proof, and witness caps remain enforced. |

## Verification for this change

- `make ci AUDIT='cargo audit --no-fetch'` passes formatting, clippy,
  supply-chain policy, host/property/hash-parity tests, fixtures, Agent SDK,
  Hub UI, RISC-V builds, and CKB-VM tests.
- Fixture generation/validation passes for bilateral, Factory, splice, reduced
  proof, local exit, and watcher packages.
- 100 CKB-VM tests pass, including all Factory CKB/xUDT positive paths and the
  new materialisation negative paths.
- Full Fiber/Morph acceptance run `20260721T142604Z` passes: 323 transaction
  records, 322 committed transactions, 9 expected stateful failures, 24
  Factory local exits, 32 Factory splices, 5 reduced exits, 9 watchtower
  alerts, real node1 -> node2 -> node3 x402/fair-exchange payments, the full
  Fiber recovery/UDT/watchtower matrix, and four funding-transaction tamper
  cases.

This evidence makes the Factory model materially stronger. It is not a mainnet
or production-readiness claim; external-edge, RGB++ proof/reorg, migration,
deployment-pinning, and independent-review gates remain deliberately open.
