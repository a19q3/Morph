# Fiber Integration Plan

This note studies whether Morph Channel can connect cleanly to Fiber Network and
records the recommended integration shape.

## Evidence Base

- Morph repository: `v2`, after the factory devnet strict-acceptance work.
- Fiber repository: `/Users/arthur/RustroverProjects/fiber`, branch `develop`,
  commit `3bbf5ea0`; `origin/develop` points at the same commit when checked.
- Fiber is still explicitly work in progress in its public documentation and its
  local protocol documents mark some surfaces as changeable.

## Decision

Morph can connect well to Fiber, but only as a layered integration.

Do not try to replace Fiber's channel scripts or commitment transaction flow in
place. Fiber currently assumes its own channel establishment, funding lock,
commitment lock, commitment numbers, TLC lifecycle, revocation data, channel
gossip, and watchtower payloads. Morph uses a different on-chain authority
model: State Cell, Vault Cell, Sponsor Cell, factory state, factory vault, and
package publication.

The best plan is:

1. keep Fiber as the invoice, routing, payment-session, peer-to-peer, and node
   layer;
2. expose Morph initially as a direct-settlement backend and liquidity/factory
   service outside Fiber's public graph;
3. add an explicit channel-backend boundary in Fiber before making Morph-backed
   channels first-class routable channels;
4. expose Morph factory children to Fiber only after they materialise into
   bilateral channels with ordinary Fiber graph semantics.

## Why They Fit

The fit is real:

- both systems are CKB-native;
- both move CKB and UDT-like assets;
- both care about off-chain state with on-chain settlement fallback;
- both need watchtower support;
- Fiber already has external funding support and event emission around channel
  settlement;
- Fiber's higher layers are useful to Morph: invoices, peers, payment sessions,
  TLC forwarding, routing, and node operation.

The mismatch is also real:

- Fiber's external funding API freezes the transaction shape and allows witness
  filling only; it is a wallet-signing seam, not a settlement-backend seam.
- Fiber's watchtower stores commitment, revocation, settlement, TLC, and
  preimage data. Morph needs watch packages over State/Vault/Sponsor and factory
  evidence, not ordinary Fiber commitment transactions.
- Fiber's public channels are graph edges with fee and TLC policy. Morph factory
  rights are shared reserve rights and should not be advertised as graph edges
  until there is an explicit factory-liquidity protocol.
- Fiber's fee model uses funding and commitment fee rates. Morph deliberately
  separates fee authority through Sponsor Cell policy, where sponsor capacity is
  not channel value.
- Fiber's current TLC flow is hash-based in local docs, while some public text
  describes PTLC as a direction. Morph should model the generic conditional
  transfer first, then bind HTLC/PTLC encodings separately.

## Target Architecture

```text
Fiber RPC / App / Wallet
        |
Fiber Invoice + PaymentSession + Routing + P2P
        |
ChannelBackend boundary
        |
        +-- NativeFiberBackend
        |     - existing funding lock
        |     - existing commitment lock
        |     - existing watchtower payloads
        |
        +-- MorphBackend
              - State Cell progression
              - Vault Cell settlement
              - Sponsor Cell publication fees
              - Morph watch packages
              - MorphFactoryLiquidityManager
```

The boundary must be above settlement scripts and below Fiber's payment/session
logic. Fiber should ask the backend to open, update, close, settle, and produce
watch data; it should not assume that every backend is implemented by Fiber's
current funding and commitment transactions.

## Required Interfaces

### `ChannelBackend`

Minimum responsibilities:

- negotiate an open request and return a backend-specific channel handle;
- expose local/remote balances by canonical asset id;
- add/remove a conditional transfer;
- commit a new state and return the data needed by the peer;
- produce an on-chain publication package for cooperative and unilateral paths;
- produce watchtower packages;
- report channel graph eligibility.

Native Fiber channels would implement this with the existing commitment flow.
Morph channels would implement it with `StateHeader`, settlement descriptors,
vault checks, sponsor policy, and package publication.

### `CanonicalAssetId`

Fiber's `funding_udt_type_script` and invoice asset fields need a canonical
mapping to Morph asset identity. The mapping must commit to the whole script, not
only a display symbol or type hash. Amounts must stay `u128`; no decimal or
floating conversion is acceptable.

### `ConditionalTransfer`

Fiber's TLC/HTLC state should be represented as a backend-neutral conditional
transfer:

- id;
- direction;
- amount;
- asset id;
- condition kind: hash/preimage now, point/adaptor later;
- expiry;
- routing metadata commitment;
- settlement outcome.

Morph should commit this object inside its settlement descriptor. The backend
must reject any state where aggregate balances plus pending conditional
transfers violate asset conservation.

### `WatchPackage`

Fiber's existing event stream is a good transport surface, but Morph needs a new
payload type:

- latest Morph state package;
- State Cell identity and funding anchor;
- vault-set commitment;
- sponsor policy and fee budget;
- pending conditional transfers;
- factory evidence where applicable;
- publication priority and expiry policy.

The watchtower must not reinterpret Morph packages as Fiber commitment
transactions.

### `FactoryLiquidityManager`

Factory integration should be a separate service:

- tracks factory reserve rights;
- creates local exits or child materialisation packages;
- exposes only materialised bilateral channels to Fiber routing;
- keeps factory-internal reduced-rights and sparse-Merkle updates off the public
  Fiber graph until the protocol has explicit support.

## Phased Plan

### Phase 0: Adapter, No Public Graph

Build a small adapter that maps Fiber invoice/payment intent to Morph direct
channel operations between known peers. Do not advertise Morph factory rights as
Fiber public channels. The goal is to prove asset identity, amount preservation,
and state publication without touching Fiber routing semantics.

Acceptance:

- Fiber invoice amount and asset map exactly into Morph state packages.
- Morph rejects wrong asset script, wrong amount, stale state, and sponsor/value
  contamination.
- Watch packages can publish the latest Morph state on devnet.

### Phase 1: External Funding Interop

Use Fiber's external funding API only for what it currently supports: letting an
external wallet sign Fiber's frozen funding transaction. This can share wallet
and cell-selection code with Morph, but it cannot insert Morph's State/Vault/
Sponsor layout into Fiber's current channel.

Acceptance:

- prove that the signed transaction is structurally unchanged except witnesses;
- prove that Morph funding cells are not accidentally consumed as Fiber channel
  value unless explicitly selected.

### Phase 2: Channel Backend Boundary

Introduce or prototype a backend boundary in Fiber. This is the first point
where Morph can become a clean settlement backend rather than an external tool.

Acceptance:

- existing Fiber tests pass with `NativeFiberBackend`;
- a mock backend can open, update, fail, and close without Fiber assuming a
  commitment transaction shape;
- event and watchtower code distinguishes native Fiber and Morph payloads.

### Phase 3: Morph Bilateral Backend

Implement a Morph-backed bilateral channel under the backend boundary. Keep
Fiber's payment session and TLC logic above it.

Acceptance:

- direct Fiber payment over a Morph-backed bilateral channel;
- cooperative close;
- unilateral latest-state publication;
- stale-state rejection;
- xUDT amount/type mismatch rejection;
- sponsor budget cannot be used as participant value.

### Phase 4: Factory Materialisation

Connect Morph factory liquidity to Fiber by materialising bilateral child
channels. The materialised child channel can become a Fiber edge only after its
open state and settlement rules satisfy the backend's graph-eligibility check.

Acceptance:

- factory local exit creates a child bilateral channel usable by the backend;
- reduced-rights and sparse-Merkle paths do not mutate unrelated participant
  balances;
- factory reserve release and splice paths preserve xUDT and CKB value;
- Fiber never routes through a factory-internal right that is not a materialised
  bilateral edge.

### Phase 5: Protocol Advertisement

Only after the previous phases work, add feature negotiation and possibly
invoice/gossip feature bits for Morph-backed channels.

Acceptance:

- peers can discover Morph-backend support explicitly;
- routing policy can distinguish native Fiber and Morph-backed edges;
- unsupported peers fail closed rather than misinterpreting state.

## Test Matrix

Required tests before calling the integration healthy:

- asset identity mapping for CKB, UDT/xUDT, unknown UDT, and mismatched scripts;
- amount conservation across balances, pending conditional transfers, fees, and
  sponsor cells;
- stale Morph state publication;
- stale Fiber commitment data fed to Morph backend, expected rejection;
- Morph state package fed to native Fiber backend, expected rejection;
- wrong funding anchor after splice;
- one-sided CKB and xUDT flows;
- factory local exit and reduced exit;
- factory splice and reduced splice;
- watchtower publishes latest state after node restart;
- delayed block observation and reorg-like replay on devnet;
- route-level payment success over native Fiber, Morph bilateral, and mixed
  native/Morph paths once graph support exists.

## Risks

| Risk | Severity | Mitigation |
| --- | --- | --- |
| Treating Fiber external funding as a backend seam | High | Restrict Phase 1 to wallet signing; add backend boundary before script substitution. |
| Advertising factory rights as public channels too early | High | Only materialised bilateral channels may be graph edges. |
| Watchtower payload confusion | High | Use distinct payload variants and reject cross-backend interpretation. |
| Asset script mismatch | High | Canonical whole-script asset ids and negative tests. |
| Fee/value contamination | High | Preserve Morph's sponsor/value split at the backend boundary. |
| Fiber protocol drift | Medium | Keep backend interface narrow and versioned. |
| Morph mainnet readiness gap | Medium | Keep deployment on devnet/testnet until independent reviews and long-running watch evidence exist. |

## Conclusion

The connection is architecturally sound if Fiber remains the network/payment
layer and Morph becomes a settlement/factory backend through an explicit
boundary. A direct graft of Morph scripts into Fiber's current channel actor is
the wrong plan: it would mix two state machines and weaken both audit stories.

The practical next step is a Phase 0 adapter plus a small Fiber-side backend
boundary prototype. That gives quick evidence without committing the system to a
premature protocol merger.

The current same-devnet coexistence gate is documented in
[`fiber-morph-devnet-acceptance.md`](fiber-morph-devnet-acceptance.md). It runs
Morph's strict stateful channel/factory matrix against Fiber's local CKB devnet
and then runs Fiber channel/external-funding acceptance on that same devnet.
