# Morph Hub vs ThunderHub Audit

Date: 2026-06-23

Scope:

- Reference implementation: `../thunderhub`
- Morph implementation under review:
  - `ui/morph-hub`
  - `crates/morph-cli/src/hub.rs`
  - `crates/morph-cli/src/main.rs`
  - `README.md`

This audit is deliberately practical. ThunderHub is a mature Lightning node
manager; Morph Hub should not copy its whole product surface. The useful target
is a native Morph operator console with the same operational seriousness:
clear provenance, safe mutation boundaries, real-time state, searchable data,
and complete Morph-specific flows.

## Current Position

Morph Hub is now a real local operator console:

- It serves a built Vite UI from `morph-cli hub serve`.
- The Rust API exposes state, state-file export/import, peer connection,
  invoice create/decode/receive/settle, channel open/splice/publish/finalise,
  factory open/advance/materialise-child, and optional CKB RPC health.
- Hub mutations use a candidate store and only persist after successful
  validation, so failed mutations do not partially leak state.
- The UI has concrete action panels for invoices, channels, peers, factories,
  and raw state file handling.

The important weakness is that the current product still behaves like a local
state operator, while a production operator will expect every displayed fact to
say whether it is locally recorded, chain-observed, or chain-confirmed.
ThunderHub is valuable mainly because it treats that distinction as product
structure, not as copy hidden in a README.

## ThunderHub Patterns Worth Borrowing

### 1. Product Shell And Navigation

ThunderHub has route-level structure:

- public routes: login, SSO, setup, node setup;
- node-scoped authenticated routes: home, dashboard, channels, peers,
  transactions, forwards, chain, tools, swap, settings, assets, trading;
- a persistent header, left navigation, right sidebar, footer, toasts, and an
  error boundary.

Morph Hub currently keeps almost the entire UI in one `App.tsx` file. The shell
looks more native than before, but it is not yet a maintainable product shell.

Borrow:

- split app shell, monitor pages, action panels, tables, and form controls into
  separate modules;
- add route-like state for deep links, even if full React Router is deferred;
- add an error boundary around the app;
- keep the right-side action drawer, because it fits Morph better than
  ThunderHub's broad page tree.

Do not borrow:

- ThunderHub's many LN-specific pages unless Morph has the matching domain
  object. Amboss, Boltz, Magma, Taproot Assets, LNURL, forwards, and macaroon
  bakery are not Morph primitives.

### 2. Typed API Contract

ThunderHub uses GraphQL operations and generated React hooks. This gives
compile-time pressure between frontend queries and backend resolvers.

Morph Hub currently has hand-written TypeScript types in `domain.ts` and
hand-written Rust serde structs in `hub.rs`. They are close, but they can drift.

Borrow the contract discipline, not necessarily GraphQL:

- generate JSON Schema from Rust serde types with `schemars`, or generate
  TypeScript types from Rust with `ts-rs`;
- expose an API version in `/api/health`;
- add focused contract tests that compare the generated schema with the UI
  assumptions.

Do not borrow:

- Apollo/GraphQL just because ThunderHub uses it. Morph's current API is small
  and command-shaped; typed REST is simpler and more native here.

### 3. Real-Time Events

ThunderHub has an SSE endpoint, an SSE client context, and a listener that turns
node events into event-log entries and query refetches.

Morph Hub currently refreshes manually after mutations and has an event list
stored in the local state file. It has no live event stream.

Borrow:

- add `/api/events` as server-sent events;
- emit events after successful mutations and CKB RPC health changes;
- add a client event context that updates the visible event log and triggers
  light refreshes;
- keep the state-file event history bounded.

This is more important than animation polish. Operators need to know when the
node changed without hammering refresh.

### 4. Tables And Data Inspection

ThunderHub uses a shared table abstraction with:

- global filtering;
- sorting;
- column visibility;
- compact row styling;
- local persistence for hidden columns;
- specialised cells for notes, links, balances, status, and actions.

Morph Hub currently uses simple static tables/lists. They work for smoke data,
but they will not scale once there are many invoices, channels, factory
children, or watchtower alerts.

Borrow:

- a small Morph-native table component;
- search/filter across channel id, counterparty, invoice description, status,
  factory id, event type;
- column sorting for amount, state number, update number, expiry, and time;
- per-table empty states and row action menus.

Do not borrow:

- every ThunderHub table feature. Pagination, virtualisation, and column
  persistence can come after search/sort.

### 5. Action UX

ThunderHub usually wraps mutations with:

- disabled submit states;
- loading indicators;
- toast feedback;
- refetches;
- modal confirmation for destructive actions;
- inline validation and helper text.

Morph Hub has disabled states and error/status text, but forms are still dense,
manual, and easy to misuse. The state-file restore action is especially sharp:
it can replace the local persisted state with pasted JSON.

Borrow:

- inline field errors rather than one global error string;
- confirmation for state restore and any future destructive action;
- copy buttons for ids and invoices;
- pre-filled selects wherever current state can safely provide the value;
- success/failure toasts or a persistent action log.

Do not borrow:

- generic modal-heavy flows. Morph's operator console should prefer inline
  panels and slide-over detail panes.

### 6. Setup And Configuration

ThunderHub has setup/login/node setup and runtime client config. Morph Hub has a
CLI command with flags and README instructions, but no UI setup screen.

Borrow lightly:

- first-run screen when state is empty;
- explicit display of local pubkey, derived node id, network, state path, and
  RPC health;
- configuration view for API URL, CKB RPC URL, and read/write mode;
- clear "local state only" vs "chain-connected" mode labelling.

Do not borrow:

- full multi-user account management until Morph Hub is intended to be exposed
  beyond loopback.

### 7. Security Boundary

ThunderHub uses Helmet, auth guards, JWT/cookies, throttling, node-slug
scoping, account setup, and optional 2FA. Morph Hub is intentionally local, but
its current HTTP server allows permissive CORS and exposes `PUT /api/state-file`.

Borrow the security mindset, not the full account system:

- bind to loopback by default and warn when binding non-loopback;
- add an optional bearer token for non-loopback or remote use;
- remove `Access-Control-Allow-Origin: *` when auth is enabled;
- put state restore behind an explicit `--allow-state-restore` flag;
- keep request-size limits and atomic writes; those are already good.

This is a P0 production-readiness item because a local operator console can
still become dangerous when reverse-proxied or run on a shared host.

## Morph-Specific Gaps

### P0: Provenance Must Be First-Class

The UI must never let local JSON look like devnet truth.

Required change:

- add record-level provenance: `local`, `decoded`, `submitted`, `chain_seen`,
  `confirmed`, `failed`;
- show chain height / tx hash / out point when a record is chain-backed;
- display a clear banner when running without `--ckb-rpc-url`;
- separate "Hub state file" from "CKB devnet evidence" in the UI;
- reject or visually quarantine imported state whose network/pubkey does not
  match the running process.

ThunderHub's lesson is not that every datum needs a badge; it is that operators
must understand whether they are looking at wallet/node reality or local UI
state.

### P0: Read/Write Safety

Current state:

- `PUT /api/state-file` is disabled unless the process starts with
  `--allow-state-restore`.
- CORS is closed by default and only enabled for an explicit `--cors-origin`.
- Non-loopback listeners require `--auth-token` or `MORPH_HUB_AUTH_TOKEN`.
- The UI shows whether auth and state restore are active.

Required change:

- keep the new defaults covered by tests;
- add operator documentation for remote deployment behind a reverse proxy;
- consider request-rate limiting if Morph Hub is ever exposed beyond a trusted
  network.

### P0: Business Flow Coverage Tests

Current evidence:

- Rust workspace tests pass.
- Hub has one focused API test around rejected factory child mutation.
- `ui/morph-hub` has no frontend unit or e2e tests.

Required change:

- add a small API flow test that covers peer -> invoice -> receive -> settle;
- add channel flow test: open -> splice -> publish -> finalise;
- add factory flow test: open -> advance -> materialise child;
- add one rendered Playwright smoke test against a real `hub serve` process,
  exercising at least one mutation from the UI.

This is not "more gates". It is direct proof that the operator console can run
the flows it advertises.

### P1: Modular Frontend

Current risk:

- `ui/morph-hub/src/App.tsx` is over 1,000 lines.
- domain formatting, layout, forms, tables, action orchestration, and page
  state live together.

Required change:

- split into `components/shell`, `components/table`, `panels/*`,
  `actions/*`, `state/*`;
- keep `domain.ts` as the canonical UI type/formatting layer;
- add an app-level error boundary in `main.tsx`.

### P1: Searchable Operational Tables

Current limitation:

- channels, peers, factories, invoices, and events are readable but not
  searchable or sortable.

Required change:

- add a native table component with search and sort;
- keep dense operational styling;
- preserve keyboard focus and responsive overflow behaviour.

### P1: Live Updates

Current limitation:

- refresh is manual except after local mutations.

Required change:

- add SSE or short polling;
- update event log and health state automatically;
- avoid refetch storms by debouncing refreshes.

### P1: Watchtower And Devnet Evidence Surface

The README says Morph Hub covers watchtower state, but the UI does not expose a
watchtower-specific view. It only shows generic events and channels.

Required change:

- show watch policy status, last scanned block, last alert, selected state,
  publication tx hash, and next scan block;
- link watchtower alerts to affected channel rows;
- show whether an alert came from local scan output, devnet RPC observation, or
  state file import.

### P2: Morph-Specific Flow Completeness

Current UI flow coverage is narrower than the CLI/protocol:

- no channel close/cooperative-close profile view;
- no explicit pending/funding page;
- no factory exit / reduced-rights / reduced-splice / xUDT proof evidence;
- no devnet package publication controls;
- no transaction history or CKB out-point inspector;
- no channel/factory notes like ThunderHub channel notes;
- no QR display for invoices.

Required change:

- add details drawers before adding more top-level pages;
- favour Morph proof/evidence views over generic LN pages;
- integrate CLI/devnet package outputs only when they are real command results,
  not sample state.

## What Not To Copy

Do not copy these ThunderHub surfaces unless Morph later grows the matching
domain:

- Amboss, Magma, Boltz, swap/trading pages;
- LN forwards and payment-route analytics;
- macaroon bakery;
- Taproot Assets flows;
- multi-account DB setup as a default requirement;
- external price/fee widgets.

These would make Morph Hub feel larger, not more native.

## Recommended Architecture

Keep the Rust server. Do not introduce a Nest/GraphQL server only to mimic
ThunderHub.

Recommended shape:

```text
crates/morph-cli/src/hub.rs
  HTTP server, persistence, auth boundary, SSE, state projections

crates/morph-cli/src/hub_contract.rs
  serde DTOs + generated schema/exported UI contract

ui/morph-hub/src/
  api/
    client.ts
    contract.ts
  components/
    shell/
    table/
    forms/
    status/
  panels/
    overview/
    channels/
    invoices/
    peers/
    factories/
    watchtower/
    events/
  actions/
    channel-actions.tsx
    invoice-actions.tsx
    factory-actions.tsx
  state/
    event-stream.ts
    use-hub-state.ts
```

## Priority Roadmap

P0 should be done before calling Morph Hub production-ready:

1. Provenance labels and chain-connected mode separation.
2. State restore opt-in plus safer CORS/auth behaviour.
3. API tests for invoice/channel/factory flows.
4. One rendered UI smoke test against a real Hub process.

P1 makes it operator-grade:

1. Modularise the React code.
2. Add table search/sort and row details.
3. Add SSE or debounced polling.
4. Add watchtower-specific panel.

P2 makes it Morph-native rather than just useful:

1. Add proof/evidence views for factory and reduced proof flows.
2. Add CKB tx/out-point inspector.
3. Add notes and annotations for channels/factories.
4. Add invoice QR and richer receive/pay workflows if Morph invoices become
   user-facing rather than test/operator artefacts.

## Bottom Line

Morph Hub should borrow ThunderHub's product discipline, not its feature list.
The most important missing piece is provenance: every row must tell the operator
whether it is local state, decoded data, submitted devnet action, chain-seen
state, or confirmed chain evidence. After that, the next highest-value borrow is
ThunderHub's real-time event loop and operational table system.

Until those are present, Morph Hub is a useful local console, but not yet a
production-grade Morph operator console.
