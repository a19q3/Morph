# Morph Hub Frontend UI/UX Audit

Date: 2026-06-27

Scope:

- `ui/morph-hub/src/App.tsx` (2210 lines, the whole operator console)
- `ui/morph-hub/src/styles.css` (1929 lines, the whole design system)
- `ui/morph-hub/src/api.ts`, `ui/morph-hub/src/domain.ts`
- `ui/morph-hub/index.html`, `vite.config.ts`, `package.json`

This audit focuses on operator ergonomics and humanization. It complements
`docs/morph-hub-thunderhub-audit.md` (which covers architecture and feature
parity). The two should be read together.

## Current Position

Morph Hub is a credible devnet operator console. The shell is well-built:

- Three-column layout (sidebar / workspace / action drawer) holds up at
  desktop widths and collapses sensibly below 1120px.
- The design system is consistent: tokens for surfaces, status tones,
  radii, spacing, shadows; primitives like `.status-pill`, `.panel`,
  `.form-grid`, `.drawer-section`, `.empty` are reused across every page.
- Domain vocabulary is honest: `Runbook`, `Vault value`, `Sponsor budget`,
  `Provenance`, `Flow coverage`, `Acceptance panel`. A real channel operator
  reads the screen without translation.
- Provenance and chain-status badges are first-class citizens on every row,
  not a footnote. That is the right product call for a state-channel
  console.
- Live updates work (SSE first, polling fallback, mode pill surfaces the
  state), and `latestEventIdRef` correctly suppresses redundant status
  flashes.
- Inline validation messages, generate-id helper buttons, and the
  "I understand this replaces the local Hub state file" checkbox are
  genuinely good operator hygiene.

The console is functionally complete for a local devnet operator. The
remaining work is not "build more features" — it is "make the existing
surface easier and friendlier to use under stress." The rest of this
document is organized as High-impact, Medium-impact, Low-impact
findings, with concrete fixes.

---

## High-impact findings

### H1. The 352px right drawer crowds the workspace and never collapses

`--drawer-w: 352px` is hard-coded into the app shell. On a 1366×768
laptop the workspace ends up with ~720px usable width after the 232px
sidebar; the channel table is 820px min-width and overflows horizontally
inside `.table-panel`. The operator must scroll sideways to reach the
Publish / Splice / Finalise row actions — the most destructive
controls in the product.

Fix:

- Add a collapse toggle to `.drawer-head`. Default state: collapsed on
  widths below 1280px, expanded above.
- When collapsed, surface the action tabs as a floating button bar at
  the bottom-right corner (similar to Intercom). Clicking a tab expands
  the drawer with that panel active.
- Persist the collapsed state in `sessionStorage` like the API token.

```css
:root { --drawer-w: 352px; --drawer-w-collapsed: 56px; }
.app-shell.drawer-collapsed { grid-template-columns: var(--sidebar-w) minmax(0, 1fr) var(--drawer-w-collapsed); }
```

### H2. Sub-forms inside Channel Actions / Factory Actions are one tall scroll

`ChannelActions` stacks Open (8 inputs + Asset select), Splice (3 inputs
+ select), Publish state (3 inputs + select), Finalise (1 select) into
one scrolling form. `FactoryActions` is worse: Open (3 inputs +
textarea + asset), Advance (1 select + 1 input), Materialise child
(10 inputs + asset). Total ~25–30 inputs visible only by scrolling past
earlier sub-forms. The operator who wants to "splice channel C now"
must scroll past Open / Publish / Finalise first.

Fix:

- Convert each sub-form into a tab strip inside the drawer (`Open` /
  `Splice` / `Publish` / `Finalise`). Default tab: the action the panel
  was opened for (the `panel` field in `flowItems` already encodes this).
- Or: accordion groups with the relevant one expanded by default based
  on the context that opened the drawer.
- The reusable helper here is `ChannelSelect` + `FactorySelect`, which
  are already filter-aware (`activeChannels`, `publishableChannels`,
  `settlingChannels`). Putting each behind a tab makes the filter logic
  obvious per action.

### H3. No inline validation for hex / pubkey fields

Every form field validates at submit time only. The operator types a
33-byte pubkey, mistypes one character, clicks Connect peer, and gets
the error at the top of the workspace — far away from the field they
were typing in. Worse: hex inputs look identical to text inputs, so the
operator has no visual cue they are entering the wrong format.

Fix:

- Wrap `assertPubkey`, `assertHex32`, `assertPositiveInteger` with a
  pre-validation hook (`onBlur` and on-change after first blur) that
  calls the same assertion and surfaces a per-field error message
  under the input in red.
- Visual cue: `input.invalid` gets `border-color: var(--bad)` plus
  helper text `<small class="field-error">{message}</small>` below it.
- For pubkey: validate prefix `02|03` and length 66 chars. For hex32:
  validate `0x` + 64 hex chars. Visual feedback while typing reduces
  submit-rejection loops significantly.

### H4. Destructive actions are single-click

`Finalise channel` is irreversible. `Restore state file` already has the
checkbox gate (good — keep that). But `Publish`, `Splice`, `Finalise`
on row actions, plus the four action-drawer sub-form submits, are all
single-click. On a touchpad misclick is easy.

Fix:

- Confirmation modal for `Finalise` and `Restore state file` only.
  Other actions can keep single-click but get an undo toast (see H7).
- Modal should show: "Finalise channel `{shortHex(channel_id)}`? This
  closes the settling channel. Active counterparty: `{alias}`. Cannot
  be undone." with Cancel and Confirm buttons.
- Use a small modal primitive, no third-party dep needed.

### H5. The "X/Y records" counter doesn't show the per-section breakdown

Search filters across all six record types silently. The operator sees
`5/142 records` and does not know whether the 5 are channels, invoices,
or events. They have to scroll to each panel to figure out what was
filtered.

Fix:

- Replace the meta line with a per-section breakdown:
  `3 channels · 1 invoice · 0 peers · 1 factory · 0 alerts · 0 events`
- When one section matches but is empty in the visible top-N (because
  InvoicePanel slices to 5), the operator currently misses matches.
  Either drop the slice or make it visible — see H6.

### H6. Inconsistent list truncation: ChannelTable shows all, InvoicePanel caps at 5

```ts
// InvoicePanel line 1102
orderedInvoices.slice(0, 5).map(...)

// PeerPanel line 1129
peers.slice(0, 5).map(...)
// FactoryPanel line 1153
factories.map(...) // no cap, but fact list is usually small
```

Channel table renders every row, but invoice / peer panels silently cap
at 5. Operator with 7 invoices sees 5 plus an empty list gap. They have
no signal that 2 more exist.

Fix:

- Drop the slice. If a panel is overflowing, add `max-height: 320px`
  with internal scroll, plus a footer count badge "showing 5 of 7".
- Or: keep the slice but add an explicit "Show all 7 invoices →" link
  that opens the panel in a modal or expands inline. The silent cap is
  the bug.

### H7. No toast / notification system

The only success feedback is a one-line status text in the topbar that
is overwritten by the next action. An operator who clicks Publish, then
clicks Refresh, then looks at the topbar sees "State refreshed from
Morph Hub API" and has no idea whether Publish actually succeeded.

Fix:

- Add a small toast system (no dep — a context provider with a stack
  of `Toast { id, tone, title, body, ttlMs }` and a fixed
  bottom-right container).
- On action submit: show toast `{ tone: 'info', title: 'Publish state
  submitted' }`. On resolve: replace with `{ tone: 'ok', title:
  'Publish accepted', body: 'State #14' }` or `{ tone: 'bad', title:
  'Publish rejected', body: error }`.
- TTL 5s for ok/info, 8s for bad. Dismissible. Stack max 3 visible.
- This is also the right place for the "Finalise accepted" undo path
  if the modal confirm is replaced by an undo toast in the future.

### H8. Status text in topbar becomes stale

After initial load, the topbar `<p>{status}</p>` reads `"State refreshed
from Morph Hub API"` forever — until the next user-triggered action.
Live updates do update it, but only when an event arrives. A quiet
period leaves the operator unsure whether the console is still live.

Fix:

- Replace the static status text with a live indicator:
  `Last refreshed {seconds}s ago · {liveMode}`. Update every 1s via a
  small interval that ticks off a "last refresh timestamp" stored on
  the state. When SSE delivers a new event, reset to `0s`.
- Keep the one-line status for explicit action outcomes ("Publish
  accepted", "Connect peer rejected") in the toast system (H7).

### H9. Empty states are single-line grey text with no guidance

```tsx
{invoices.length === 0 && <div className="empty">No invoices in the hub state file</div>}
```

Six panels share this pattern. An operator landing on a freshly started
Hub sees six identical empty messages and no idea which panel to click
first to seed data.

Fix:

- For each panel, when empty, render an empty state with:
  1. A one-line reason.
  2. A primary CTA that opens the relevant action drawer tab.

```tsx
<div className="empty rich">
  <ReceiptText size={24} />
  <strong>No invoices yet</strong>
  <small>Create one to start accepting payments on {shortHex(state.pubkey) || 'this node'}.</small>
  <button onClick={() => selectAction('invoice')}>Create invoice →</button>
</div>
```

- Use the `ProvenanceBanner` empty-state voice consistently.
- Only the search-active empty ("No invoices match this filter") should
  stay terse — that one has a clear cause.

### H10. Copy-to-clipboard buttons are missing for hex fields

The operator's day is copying channel IDs, pubkeys, payment hashes,
encoded invoices into curl commands and chat messages. Currently:

- `copyLatestInvoice` exists, but only the latest.
- No copy for individual channel IDs, pubkeys, hashes, or event subjects.

Fix:

- Add a tiny `<CopyButton value={...} />` primitive that shows a
  clipboard icon next to any hex field. Click → `copyTextToClipboard`
  (already implemented) → swap icon to checkmark for 1.5s.
- Wire it into: channel row ID, channel counterparty pubkey, channel
  funding context, invoice payment hash, peer pubkey, factory ID,
  event subject ID, watchtower publication tx hash.
- For mobile, this also lets the operator long-press the input and get
  the same behaviour, but a button is more discoverable.

### H11. Date / severity filters are missing on Events and Watchtower

Watchtower alerts have a `severity` field. Events have `severity` and
timestamps. Both panels show the most recent 10 with no filter. An
operator with 200 events gets the same list whether they care about
"critical in last hour" or "all events in last 24h."

Fix:

- Add a compact filter row above `.event-log`:
  `[Severity: all | info | warning | critical]   [Range: last 1h | 24h | 7d | all]`
- Filters are per-panel local state, no need to plumb through the App.
- On `.empty` rows, show the filter that caused the empty ("No critical
  events in last 24h" instead of "No API events recorded").

---

## Medium-impact findings

### M1. Runbook is shown twice

The sidebar shows `coverage-top` with `Runbook X/Y` plus a progress
meter. The workspace `FlowPanel` then shows the same Runbook at full
fidelity. Pick one as primary; the other becomes a pointer.

Recommendation:

- Keep the `FlowPanel` in the workspace as the operator's view of the
  runbook — it has the per-flow detail, the action links, and the
  complete/remaining badge.
- Reduce the sidebar meter to a one-line summary: `Runbook 5/11` next
  to a tiny dot indicator. Drop the per-flow text on the sidebar; the
  sidebar is for navigation, not detail.

### M2. Network badge is too quiet

`network-badge.devnet` dot is 7px and the same color family as the
border. The "devnet" / "testnet" / "mainnet" indicator is the single
most important context for an operator and it should not be lost in
the status pill row.

Fix:

- Move the network badge into the topbar `<h1>` directly (it already is,
  but make it a chip with stronger contrast: filled background
  `--accent-soft` for devnet, `--warn-bg` for testnet, `--ok-bg` for
  mainnet).
- Add a tooltip on the network badge: "devnet — Hub API is on the local
  development chain. Do not use this node for real value."

### M3. Acceptance Panel is always visible

Six cards, always shown. The panel is most useful when something is
wrong. When everything is green, it competes for attention with the
metrics grid.

Fix:

- When `blockers === 0 && warnings === 0`, collapse the panel to a
  single row: `Devnet Acceptance · ready · 6/6 green ▼`. Click to
  expand.
- When `blockers > 0`, expand by default and pin to top of the
  workspace (above metrics grid), with a red left border to mark it
  as the active blocker surface.

### M4. No keyboard shortcuts / command palette

Power users hit `Cmd+K` expecting a palette. There is none. The search
box is keyboard-focusable but typeahead across panels is not exposed.

Fix:

- Add a `Cmd/Ctrl+K` palette that opens a modal with:
  - `> Open channel` / `> Create invoice` / `> Finalise channel` —
    routes to the action drawer with the right tab preselected.
  - `Channels` / `Invoices` / `Peers` / `Factories` / `Watchtower` /
    `Events` — scrolls to that section.
  - The current `/api/state` search input becomes one of the palette
    modes (`/` to filter records inline).
- Even a minimal `Cmd+K` → `actions` selector is a clear upgrade.

### M5. Tabular numerics and status overlap in metric cards

`.metric-value` uses `font-variant-numeric: tabular-nums` (good).
But metric labels are 12px and values are 22px without enough
breathing room — the labels feel cramped against the big numbers. The
hover lift (`translateY(-1px)`) is subtle but the card padding is
uneven because the icon and label compete for the same row.

Fix:

- Stack icon above label vertically (`.metric-icon` as a 36px avatar
  on top, label as caption below), then big value below. This is the
  Stripe / Linear / Vercel pattern.
- Or: keep horizontal but give the icon a fixed 32px box with a tinted
  background and the label as a subtitle, so the visual hierarchy is
  Icon > Label > Value.

### M6. ProvenanceBanner is always shown and competes with errors

When the API is reachable and state is local-only, the banner says
`State-file records are local only · N records are persisted locally
and are not CKB devnet confirmation`. That's the most important
product message in the console — but it sits above the metrics grid
where it gets pushed out of view as soon as the operator scrolls into
the runbook.

Fix:

- Pin a compact provenance chip to the topbar (next to network badge)
  that says `Local only · N records` or `Watchtower · N alerts`. The
  full banner stays in the workspace but only when expanded.
- Click the chip → expand the banner inline with the full message.

### M7. Field labels are inconsistent (`Channel id` vs `Channel ID`)

Across forms: `Channel id`, `Factory id`, `Counterparty pubkey`,
`Asset`, `Reserve`. Capitalization is sentence case but never enforced;
the operator's eye doesn't pick a pattern. Trivial, but inconsistent
labels are an accessibility signal — screen readers may read
`Channel id` as `Channel id` (two words) but `ChannelID` differently.

Fix: pick a style and apply it. Sentence case (`Channel id`,
`Counterparty pubkey`) is fine for the operator persona — matches
their mental model of "the field where I put the channel id."

### M8. Tooltips are missing on row actions

`<button title="Publish state N+1 for 0x1234...">` is set, which is
browser-default tooltip. It works on hover but is invisible on touch
and unfriendly for keyboard users. The button is the destructive
control on the channel row — the operator needs to see what it does
before clicking.

Fix:

- Use a custom tooltip primitive that appears on focus and on a 600ms
  hover delay. Body: `Publish state #N+1 for {shortHex(channel_id)}.
  This moves the latest state into settlement. Counterparty:
  {peer.alias}.`
- For the empty-action row, give the channel a small info icon that
  opens a popover explaining why no action is available (`Closed
  channels cannot be re-published.`).

### M9. Status messages read like robot logs

```ts
setStatus(`${label} submitted`);
setStatus(`${label} accepted by Morph Hub API`);
setStatus(`${label} rejected`);
```

`Connect peer accepted by Morph Hub API` is technically accurate but
reads like a JSON dump. Humanization means a calmer voice:

- `Submitted: Connect peer`
- `Connected to peer {alias}`
- `Connect peer rejected: {error}`

These small rewordings add up. The console starts feeling like it
talks to the operator, not to the API.

### M10. `.event-meta` line wraps badly on narrow rows

```tsx
<div className="event-meta">
  <span className="mono">{shortHex(alert.channel_id)}</span>
  <span className="mono">selected #{alert.selected_state_number}</span>
  ...
</div>
```

Six mono spans on one wrap-flex row. On a 320px workspace the meta
wraps to three lines and the event main content becomes illegible.

Fix:

- Split into two rows: primary meta (channel ID + selected state) on
  line 1, secondary meta (observed state, scan height, tx hash) on
  line 2 with smaller font and lower contrast.
- Or: put secondary meta behind a `Show details` toggle per row to
  keep the dense log scannable.

---

## Low-impact findings (cosmetic)

### L1. The visual style is functional but flat

Mostly `#ffffff` surfaces, hairline `#e4e8ec` borders, one accent
green. No gradients beyond the brand mark and runbook meter. The
console reads as "internal admin tool" rather than "product." For a
devnet operator console this is appropriate, but as the product moves
toward shared multi-operator use, a stronger visual identity would
help (subtle radial gradients in empty backgrounds, micro-shadow on
focus rings, motion on status changes).

### L2. Typography is Inter everywhere

Inter is the right choice for the data-dense operator persona. But
display headings (`Morph Node`) and section headers could use a
slightly different weight or letter-spacing to create real hierarchy.
Currently every label fights for the same 11–13px range.

Fix: Inter is enough — just be more disciplined about weight
contrast (700 vs 500) and case (uppercase vs sentence) to give the
existing fonts room to breathe.

### L3. No skeleton loaders

On first load, the workspace shows `Loading Morph Hub API` and then
snaps to populated state. A 200ms skeleton (animated bars in the
metric tiles and table rows) would smooth the perceived load.

### L4. Focus ring is custom but not `:focus-visible`

```css
input:focus, textarea:focus, select:focus {
  outline: none;
  border-color: var(--accent);
  box-shadow: 0 0 0 3px var(--accent-soft);
}
```

The `outline: none` drops the browser default ring for everyone,
including keyboard users who tab into the field. Switch to
`:focus-visible` so mouse clicks don't show the ring but keyboard
navigation always does.

### L5. No dark mode

The token system is clean enough that a `prefers-color-scheme: dark`
variant would be cheap to add. Operators running the console in a
terminal-adjacent context often prefer dark. Optional, low priority.

### L6. `.text-3` (#8893a0) at 11px 700 is borderline for WCAG AA

Used widely for labels, captions, and section eyebrows. Contrast
ratio against white is roughly 3.6:1 — below AA's 4.5:1 for small text.
Bumping to `--text-3: #6b7682` brings it to ~4.8:1 without losing the
muted feel.

---

## What to do first

If only one week of work is available, the order is:

1. **H1** — Collapsible right drawer. Highest leverage on the
   workspace real estate.
2. **H2** — Tabs in `ChannelActions` and `FactoryActions`. The 30-input
   scrolling panel is the single worst operator ergonomics problem.
3. **H3** — Inline field validation. Stops the submit-rejection cycle.
4. **H7 + H8** — Toast system + live "X seconds ago" indicator. These
   compose: every action gets clear feedback, every refresh is visible.
5. **H9** — Empty-state CTAs. New operators get a guided first step.

After those land, the medium-impact tier (filters, copy buttons,
command palette, acceptance collapse) builds on the now-cleaner
foundation.

---

## What's already great (don't redo)

- The provenance / chain-status story is the right product call.
  Every row carries it; keep investing there.
- The three-column layout collapses sensibly below 1120px.
- The design tokens (`.surface`, `.accent`, `.ok-bg`, etc.) are
  consistent and reusable. New components should adopt the same
  primitives.
- Live updates (SSE + polling fallback) work, with proper
  `latestEventIdRef` deduplication.
- The candidate-store API on the backend (Hub mutations only persist
  after successful validation) means the UI can be optimistic without
  fearing partial state leaks. Keep that contract.
- The "Runbook" framing — flows as a sequence with provenance — is
  a clearer mental model than "tasks" or "tutorial steps."
- The acceptance panel's six-card structure (Live API / Network scope
  / Runbook flows / Watchtower feed / Record provenance / Release
  artefact) is the right scope for a devnet acceptance surface. Just
  collapse it when green (M3).

---

# Part Two — Flow Coverage And Step Count

This second pass answers two questions the first audit left open:

1. Does the UI expose every backend flow an operator can run?
2. For each exposed flow, how many actions does the operator have to
   take to complete it?

The first question matters because an incomplete surface silently
limits what the operator can do — they fall back to the CLI for
anything the console doesn't surface, which makes the console
ornamental. The second matters because every extra click is friction
in a state-channel workflow where most operations are
out-of-band-of-each-other and the operator's context-switch cost is
high.

## Backend API surface

Every flow goes through the Hub server in
`crates/morph-cli/src/hub.rs:route_api`. The complete surface:

| Method | Path                              | UI flow        | Row action | Drawer form |
|--------|-----------------------------------|----------------|------------|-------------|
| GET    | `/api/health`                     | (status only)  | —          | —           |
| GET    | `/api/state`                      | (status only)  | —          | —           |
| GET    | `/api/events`                     | (SSE stream)   | —          | —           |
| GET    | `/api/state-file`                 | state export   | —          | `State file` tab |
| PUT    | `/api/state-file`                 | state restore  | —          | `State file` tab |
| POST   | `/api/peers`                      | peer           | —          | `Peers` tab |
| POST   | `/api/invoices`                   | invoice-created | —         | `Invoices` tab → Create |
| POST   | `/api/invoices/decode`            | invoice-received | —        | `Invoices` tab → Decode |
| POST   | `/api/invoices/{id}/receive`      | (status transition) | —     | `Invoices` tab → Receive |
| POST   | `/api/invoices/{id}/settle`       | invoice-settled | —        | `Invoices` tab → Settle |
| POST   | `/api/channels`                   | channel-opened | —          | `Channels` tab → Open |
| POST   | `/api/channels/{id}/splice`       | channel-spliced | row button (active) | `Channels` tab → Splice |
| POST   | `/api/channels/{id}/publish`      | state-published | row button (active/settling) | `Channels` tab → Publish |
| POST   | `/api/channels/{id}/finalise`     | channel-finalised | row button (settling) | `Channels` tab → Finalise |
| POST   | `/api/factories`                  | factory-opened | —          | `Factories` tab → Open |
| POST   | `/api/factories/{id}/advance`     | factory-advanced | **no row action** | `Factories` tab → Advance |
| POST   | `/api/factories/{id}/materialise-child` | factory-child | **no row action** | `Factories` tab → Materialise |

**Coverage verdict:** All 11 runbook flows are reachable. The two gaps
to flag are:

- **`factory-advanced` and `factory-child` have no row action.** The
  operator must open the `Factories` drawer tab, scroll past Open,
  select the factory, click "Use selected", then submit. 4 clicks
  vs the 1-click path that Publish / Splice / Finalise already offer.
  Symmetry argues for adding row buttons:
  - Factory row → `Advance` (advance update number to +1).
  - Factory row → `Materialise child` (opens the materialise form
    with this factory preselected).
- **`receive` (status transition)** is exposed in the drawer but is
  semantically a separate operation from decode. See `F1` below.

## Step count per flow

Counted by tracing the operator's exact path through the UI. The
"current" column counts every click and every required text input
the operator has to make. The "target" column is what a
minimal-friction version should look like, with the proposed
optimisations applied. Auxiliary / confirmation clicks (toasts,
modals) are excluded — destructive actions still need a confirm step.

| Flow                  | Surface | Current steps | Target | Reducer |
|-----------------------|---------|---------------|--------|---------|
| Connect peer          | drawer  | 4             | 2      | `F2`    |
| Create invoice        | drawer  | 5–7           | 3      | `F3`    |
| Decode invoice        | drawer  | 3             | 3      | —       |
| Mark invoice received | drawer  | 3             | 2      | `F1`    |
| Settle invoice        | drawer  | 4             | 3      | `F1`    |
| Open channel          | drawer  | 9             | 4      | `F4`    |
| Splice channel        | row     | 1             | 1      | ✓       |
| Publish state         | row     | 1             | 1      | ✓       |
| Finalise channel      | row     | 1 (+ confirm modal) | 2  | `F5`    |
| Open factory          | drawer  | 6 + N pubkeys | 3      | `F6`    |
| Advance factory       | drawer  | 4             | 1      | `F2`    |
| Materialise child     | drawer  | 12            | 4      | `F4`, `F6` |

Detail on each reducer:

### F1 — Collapse "Mark received" into "Settle" path

The Decode → Receive → Settle path for an incoming invoice is the
operator's most common multi-step flow. Currently:

1. Decode (3 clicks, marks `invoice-received` flow)
2. Mark received (3 clicks, status `open` → `received`)
3. Settle (4 clicks, status `received` → `paid`, marks `invoice-settled` flow)

That's 10 actions and two drawer section switches. Worse, the
"receive" step is semantically awkward — the operator who decoded an
invoice has it. The mark-received transition is bookkeeping, not a
business event the operator thinks about.

Proposed path:

1. **Decode** (paste + 1 click) — UI auto-transitions the invoice
   to `received` on decode, since decoding IS the operator
   acknowledging receipt. Remove the explicit Mark received form.
2. **Settle** — when preimage is pasted, settle directly. 2 clicks
   past paste.

Total: 3 actions to decode, 2 to settle. Net 5 vs current 10.

**Backend implication:** `POST /api/invoices/decode` already calls
`completed_flows.insert(InvoiceReceived)` (hub.rs:985). Rename the
flow to `invoice-decoded` for naming consistency, or keep
`invoice-received` and rename the sub-form from "Decode" to
"Receive from text". One of those two naming changes should ship —
the current "Decode (runbook: Receive)" mismatch is operator
confusion waiting to happen.

### F2 — Promote single-step flows to row actions

Three flows force a 4-click drawer round trip when they could be a
1-click row action:

- **Connect peer**: peers have a `node_id` and `alias` but no quick
  "add" affordance on the Peers panel header. Add a `+` button in
  the panel header that opens a minimal modal (pubkey + alias, no
  drawer round trip).
- **Advance factory**: factories have an `update_number`. Add a row
  button `Advance to #{update_number + 1}`. One click.
- **Materialise child**: factory row → `Materialise child` button
  opens the form with the factory preselected. Saves 1 of the
  current 12 steps.

### F3 — Sensible defaults on Create invoice

The Create invoice form has 7 fields; only 3 are truly required per
the API:

- Required: `amount`, `description`, `payment_preimage | payment_hash`
- Optional: `expiry_secs`, `channel_id`, `asset`

Current behaviour: every field starts empty. The operator types
each one.

Proposed:

- `expiry_secs` default to `3600` (one hour) with a one-click
  dropdown `[1h | 6h | 24h | 7d | custom]`.
- `channel_id` already has a "Use active channel" button. Make it
  the default — pre-select on form open.
- `asset` default to CKB. Operator only changes for xUDT.
- `payment_preimage` already has a "Generate" button. Make it the
  default — auto-generate on form open.
- `description` is the only field that has no obvious default;
  keep it required.

Result: 3 inputs (amount, description, expiry override) + 1 submit.

### F4 — Channel open / materialise child share a form

Open channel and materialise child are 80% the same form. The
differences:

- Open: takes `channel_id`, no `child_channel_id`
- Materialise child: takes `child_channel_id`, no `channel_id`,
  adds a factory picker

Refactor `channelBody(input)` (App.tsx:1892) into a single
`<ChannelOpenForm mode="open|materialise" factoryId? ... />` with
the only difference being the id-field label. The factory picker
sits at the top of the form for materialise mode, and disables when
no factories exist.

This brings Materialise from 12 steps to ~5, since the operator
only fills channel-specific fields (local/remote/sponsor).

### F5 — Confirmation modal for destructive row actions

`Finalise` is the only channel row action that cannot be undone.
Currently it is single-click. Add the same confirmation modal that
`Restore state file` already has:

```
Finalise channel 0x1234...5678?
This closes the settling channel.
Counterparty: bob
Cannot be undone.

[ Cancel ]   [ Finalise ]
```

The modal adds 1 click on the happy path (Cancel closes it; Confirm
submits) but prevents the catastrophic mis-click on the sad path.
Splice and Publish keep single-click because they are recoverable.

### F6 — Multi-pick from connected peers

`Open factory` requires the operator to type every participant
pubkey as text. There is no connection between this form and the
peers panel that just sits two tabs to the left.

Refactor: replace the `textarea` for participant pubkeys with a
multi-select chip picker:

```
Participants (3 of 4):
[ ✓ alice 02ab...] [ ✓ bob 039c...] [ ✓ carol 02de...]
[ + add pubkey (custom) ]
[ ✓ local node (auto-added) ]
```

The operator clicks chips instead of typing hex. Adds the local
pubkey by default (matches the current "Add local" button but
auto-applies on form open).

For `Materialise child`, replace the free-text `counterparty_pubkey`
input with a `<select>` populated from connected peers. Drop the
alias field entirely — alias comes from the peer record.

## End-to-end happy path

The shortest realistic end-to-end scenario for a new operator
getting a settled payment through:

| Step                     | Current clicks | Target clicks |
|--------------------------|----------------|---------------|
| Open Hub in browser      | 0 (browser)    | 0             |
| Connect peer             | 4              | 2             |
| Open channel             | 9              | 4             |
| Create invoice           | 5–7            | 3             |
| (counterparty pays off-band) | —          | —             |
| Decode invoice           | 3              | 3             |
| Settle invoice           | 4              | 3             |
| **Total**                | **25–27**      | **15**        |

The 10+ click savings come almost entirely from row-action promotion
(`F2`) and sensible defaults (`F3`, `F4`, `F6`). The audit's High-impact
items (H2, H3) help; the step-count reducers here are mostly
information architecture, not styling.

## What's still missing (not blockers, just gaps)

These do not block devnet acceptance but a multi-operator
production console would want them:

- **Bulk select**: multiple invoices → bulk mark received; multiple
  channels → bulk finalise. Currently the operator does these
  one at a time. Useful when a watchtower catches up on many stale
  invoices at once.
- **Scheduled actions**: "splice at block height N" — current UI
  only supports immediate actions. API surface would need a
  `scheduled_at` parameter; UI would need a small scheduler view.
- **Multi-node switching**: if one operator runs two Hubs
  (Alice + Bob roles for testing), there is no node picker. Today
  the operator must run two browser tabs. Acceptable for devnet;
  worth flagging.
- **State diff view**: when the operator restores a state file,
  they should see what is changing before confirming. Currently
  the textarea is the only thing they see — no diff against the
  current state.
- **Export audit trail**: "give me a CSV of all events in the last
  24h" — for incident review. Not in scope today.