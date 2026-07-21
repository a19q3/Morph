# Morph, Fiber, and RGB++ Responsibility Audit

## Decision

Morph is the sovereign CKB/RGB++ state and liquidity layer. Fiber is an
optional, replaceable network provider. Agent functionality is a sidecar.

Neither repository currently provides a complete RGB++ isomorphic leap or the
Agent/Fiber workflow proposed in Fiber issue #1255. Morph is structurally the
better place to add those capabilities because its State/Vault/Factory scripts
already own CKB-enforceable multi-asset value and rights. Fiber is the better
place to reuse routing, MPP, invoices, gossip, and peer communication.

## Capability Boundary

| Capability | Owner | Reason |
| --- | --- | --- |
| Shared reserve and virtual child rights | Morph Factory | Value and non-interference are CKB-enforceable. |
| Bilateral signed state and settlement | Morph ChannelBackend | Morph can force-enforce the state on CKB. |
| CKB/xUDT and future RGB++ asset policy | Morph | Asset provenance must not depend on an external router. |
| Route finding, MPP, gossip, invoice transport | Fiber provider | Mature network machinery; replaceable dependency. |
| x402 HTTP challenge/receipt flow | Morph Agent sidecar | Application protocol, independent of settlement engine. |
| Biscuit/macaroons/credentials | Morph Agent sidecar | Least-authority application capability. |
| Hold/fair-exchange orchestration | Morph Agent sidecar + ChannelBackend | Sidecar coordinates; Morph state remains enforceable. |
| Graph-edge lifecycle | Morph bridge contract | Activation derives from Morph evidence; provider mirrors it. |

## What Morph Has That Fiber Does Not

- native shared Factory reserve and typed rights;
- local/reduced exit that materialises a bilateral child;
- separate State and Vault authority;
- CKB/xUDT settlement descriptors;
- splice and liquidity reuse;
- bounded sponsor policy;
- script-side non-interference and FactoryVault conservation.

## What Fiber Has That Morph Should Reuse

- peer networking and gossip;
- graph and route computation;
- MPP/payment orchestration;
- invoice transport and hold-invoice primitives;
- restart/re-establishment and network operational experience.

## What Neither Has Yet

- RGB++ isomorphic BTC UTXO/CKB Cell binding;
- BTC SPV/confirmation proof verification boundary;
- leap-in/leap-out state machine and rollback;
- canonical Agent payment receipt shared across off-chain and on-chain paths;
- x402 challenge negotiation bound to a Morph asset/payment intent;
- capability credential verification and replay protection;
- a verified Morph-edge adapter accepted by Fiber routing;
- full reorg/restart reconciliation across Morph, Agent, and Fiber.

## Sovereign Bridge Rule

The bridge is not `Morph record -> Fiber RPC call`. It is a lifecycle with
evidence:

1. select a Factory right or bilateral funding source;
2. reserve it with an expiry/idempotency key;
3. construct and verify the child materialisation package;
4. observe the committed State/Vault cells;
5. derive an immutable edge descriptor from trusted code hashes, channel id,
   funding context, asset, capacity, and participant keys;
6. activate the provider edge;
7. reconcile provider state against Morph on restart;
8. disable or replace the edge on splice, dispute, close, reorg, or proof
   invalidation.

Fiber never becomes the source of truth for steps 1-5 or 7-8.

## Minimal Fiber Hook

Current Fiber public RPC is sufficient for coexistence and external funding,
but not for declaring an external, CKB-enforceable state backend as a routable
edge. The minimal upstream/downstream hook should be provider-neutral:

- register an externally enforced channel descriptor;
- report directional capacity and asset identity;
- callback/stream for payment prepare, commit, cancel, and failure;
- disable/replace an edge atomically by funding-context version;
- persist an opaque Morph commitment and terminal settlement receipt;
- never require Fiber to parse Factory proofs or Morph witnesses.

If upstream Fiber does not accept this hook, Morph should maintain an isolated
adapter patch/fork. Morph core and contracts must not import Fiber types.

## Issue #1255 Interpretation

The useful requirements are application capabilities, not a reason to replace
the Morph protocol model:

- x402 facilitator and HTTP 402 negotiation;
- payment-bound credentials;
- fair exchange through conditional/held payment;
- canonical terminal settlement events and optional CKB anchors;
- multi-asset Agent SDK ergonomics.

Morph should implement equivalent capability against its own provider-neutral
ChannelBackend. Fiber can be one transport/routing provider for that backend.

## RGB++ Direction

Do not label ordinary xUDT support as RGB++ isomorphic binding. The correct
incremental path is:

1. trusted deployment/code-hash profile;
2. `RgbppAssetId` and BTC outpoint ownership commitment;
3. proof-provider interface for BTC headers/SPV/confirmations;
4. leap-in/leap-out state machine with timeout and reorg rollback;
5. Factory rights for RGB++ liquidity reuse;
6. Agent payment intents and receipts that name the RGB++ asset and proof;
7. Fiber edge descriptors derived only from verified materialised channels.

Batch Cell may optimize settlement aggregation after this model is proven. It
is not a Factory and cannot replace shared rights, local exits, or splice.
