# Morph Hub Frontend UI/UX Remediation Status

Date: 2026-06-28

This note is the live follow-up for `docs/hub-frontend-uiux-audit.md` and the
frontend portions of `docs/morph-hub-thunderhub-audit.md`. The audit files
remain historical evidence; this file records current closure state.

## Fixed in code

| Finding | Status | Evidence |
| --- | --- | --- |
| H3 | Fixed | reusable validated input/textarea controls now show inline errors after blur for peer pubkeys, custom participant pubkeys, hex ids/hashes, invoice amount, and integer capacity/state/update fields. |
| H1 | Fixed | the action drawer has a persisted collapse toggle, defaults collapsed on narrow desktop widths, expands when an action tab is selected, and exposes collapsed action tabs as a floating bottom-right control rail. |
| H2 | Fixed | `ChannelActions` and `FactoryActions` now use local action tabs, so open/splice/update/finalise and open/advance/materialise are no longer one long scrolling form. |
| H4 | Fixed | finalise actions use a confirmation dialog from both the row action and the drawer action path; state restore also uses a confirmation dialog. |
| H5 | Fixed | the global record search meta now shows a per-section breakdown for channels, invoices, peers, factories, watchtower alerts, and events. |
| H6 | Fixed | side panels use preview limits with explicit "show all / show fewer" controls instead of silently hiding records. |
| H7 / H8 | Fixed | actions emit dismissible toast notifications for submitted/accepted/rejected outcomes, and the topbar includes a live last-refreshed indicator alongside the live mode. |
| H9 | Fixed | channel, invoice, peer, factory, watchtower, and event empty states now explain the missing data and offer a relevant CTA when the empty state is not caused by search filtering. |
| H10 | Fixed | reusable copy buttons now sit next to high-frequency channel ids, pubkeys, funding context ids, encoded invoices, payment hashes, factory ids, event subjects, and watchtower tx/channel ids. |
| H11 | Fixed | Events and Watchtower panels have compact severity and time-window filters, with filter-specific empty messages. |
| H12 | Fixed | high-level provenance is surfaced in the top status/provenance banner and acceptance panel. |
| M4 | Fixed | the sidebar and `Cmd/Ctrl+K` open a command palette for search, refresh, action drawers, watchtower, and events; `/` focuses global search outside text fields. |
| P1 modular frontend | Fixed | `App.tsx` is now the shell/orchestrator, with action drawer forms in `src/actions.tsx`, record tables/panels in `src/records.tsx`, and search/sort/status helpers in `src/state.ts`. |
| P1 watchtower panel | Fixed | the Watchtower panel now includes scan position, latest alert, selected/observed state, publication tx, out-point, funding anchors, and funding context inspectors. |
| P2 evidence inspectors | Fixed | invoice rows now expose lifecycle/payee/channel/payment-hash evidence, factory rows expose the local factory proof surface, and Watchtower rows expose CKB out-point/tx evidence. |
| ThunderHub P0 read/write safety | Fixed | Hub auth, CORS, restore opt-in, restore narrowing, SSE fallback under auth, and state restore tests are implemented. |
| ThunderHub P0 business-flow API tests | Fixed | Hub API tests cover invoice, channel, factory, and complete required-flow paths. |
| ThunderHub P1 live updates | Fixed for current auth mode | the UI uses SSE only for explicit unauthenticated loopback mode and authenticated polling when bearer auth is active. |
