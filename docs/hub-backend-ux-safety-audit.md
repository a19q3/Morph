# Morph Hub 后端 — UX 与交互安全审计

Date: 2026-06-30
Status: Historical audit snapshot. The production-hardening pass in
`docs/hub-backend-ux-safety-remediation.md` supersedes the open status of H1,
H2, H3, H5, H6, M1, M2, M3, M4, M5, M6, M7, L2, L3, L4, and L5 as of
2026-06-30.
Scope: `crates/morph-cli/src/hub.rs` (3463 lines), `crates/morph-cli/src/main.rs`
(HubCommand + resolve_hub_auth_token), `crates/morph-core/src/node.rs` and
`validation.rs` (the host-side state machine the Hub calls), and
`crates/morph-cli/src/watch_alert.rs` (the only outbound side-effect path
triggered by Hub state).

Not in scope (already covered): the CKB on-chain scripts (covered by
`docs/swarm-audit-W1-code-security.md`) and the UI shell (covered by
`docs/hub-frontend-uiux-audit.md`).

This audit reads the Hub as a *single-tenant operator console* — one node
operator, one devnet, one state file. The audit asks two questions:

1. **UX**: when an operator drives the Hub through the UI/CLI, does the
   backend fail in a way the operator can recognise, recover from, and
   learn from? Or does it fail with raw internal text, swallowed state, or
   silent corruption?
2. **Interaction safety**: if a request reaches the Hub over loopback, a
   LAN, or an exposed TCP port, what is the worst the request can do to
   the operator's node state, private keys, or live channels/invoices?

Findings are split High / Medium / Low, with concrete code references and
fix sketches. The High findings are the ones that should land before
anyone runs the Hub against anything but loopback without an auth token.

---

## High-impact findings

### H1. Auth is all-or-nothing per process; loopback binds silently disable it

**Surface**: `crates/morph-cli/src/hub.rs:482-499`, `main.rs:3512-3550`

**Claim**: `serve()` requires an auth token only when the listen address is
not loopback. Any client that can reach the loopback port — another
process owned by the same user, a co-located shell, a forwarded
ssh-L socket, or a Docker `--network=host` peer — can issue any mutating
request (open channel, settle invoice, splice, advance factory, replace
state file) without a token. There is no per-action auth, no role
separation, and no warning at startup that the token gate is off.

**Evidence**:

```rust
// hub.rs:482
ensure!(
    listen_is_loopback(&options.listen) || auth_token.is_some(),
    "serving Morph Hub on a non-loopback address requires ..."
);
```

The startup banner is honest (`morph_hub_auth=loopback`) but the UI
welcome text and the README framing in
`README.md:191-208` (the "loopback-first" paragraph) is the only
defence. A operator who binds to `0.0.0.0` "to reach the dashboard from
a phone" without reading the banner turns the entire Hub into an
unauthenticated write surface.

**Interaction impact**: any reachable client can drain channels, mint
invoices in the operator's name, settle inbound invoices, advance
factory state, or replace the entire state file if
`--allow-state-restore` is also on.

**Suggested fix**:

- Default `listen` to `127.0.0.1:4617` (already is) and add a startup
  warning when bound to a non-loopback host *even when* a token is set:
  "warning: serving on `<addr>`; the bearer token is the only access
  gate. Do not share it."
- Add a per-action policy struct (`AuthScope { Read, Write, Restore,
  Sign }`) and let `--auth-token` carry a list of scopes. Read endpoints
  (GET `/api/state`, `/api/events`) remain open; write endpoints require
  a Write-scope token; `/api/state-file` PUT requires Restore-scope;
  `/api/invoices` POST requires Sign-scope. Even on loopback, missing
  scopes return 403.
- Add a startup probe that calls its own GET endpoints and refuses to
  start if a non-loopback bind is reachable from outside the expected
  interface (best-effort: enumerate local interfaces and warn if a
  public one answers).

**References**: `swarm-audit-W1` (note: W1 audits scripts, not the Hub
transport), README:191-208.

### H2. No rate limiting; Hub will accept any volume of mutating requests

**Surface**: `crates/morph-cli/src/hub.rs:486-548` (the accept loop and
`handle_connection`)

**Claim**: The accept loop is `for stream in listener.incoming() {
thread::spawn(...) }`. Every accepted TCP connection spawns a new
thread, with no connection cap, no request rate limit, no per-IP rate
limit, and no per-token rate limit. A misbehaving UI tab, a script with
a bug, or an attacker on the LAN can issue thousands of
`/api/channels` POSTs per second. Each call goes through:

- `mutate` → store clone (the full `BTreeMap<Bytes32, …>` of
  channels/invoices/factories is deep-cloned every request),
- the closure (channel / invoice / factory mutation),
- `view()` (rebuild every PeerView/ChannelView/InvoiceView/FactoryView),
- `persist()` (write a pretty-printed JSON to disk via temp+rename,
  `fsync` the parent dir).

With a few hundred channels the deep clone alone is several MB of
allocations. Persist writes a full state file (currently
`serde_json::to_vec_pretty` — no streaming) on every mutation.

**Interaction impact**: a runaway UI tab can pin a CPU core, fill the
disk with the same state file, and starve every other operator action.
For the *Hub* user this is a DoS, not a fund-loss bug — but the
operator will not be able to recover until the process is killed and
the write storm stops.

**Suggested fix**:

- Cap concurrent in-flight mutations with a `Semaphore` (e.g.
  `tokio::sync::Semaphore::new(4)` or a hand-rolled `Arc<AtomicUsize>`
  + condvar). Mutating endpoints acquire one permit; reads run
  lock-free against the snapshot.
- Replace the full-state persist with a delta-write journal: append
  one JSONL line per mutation to `node-state.journal`, periodically
  compact to `node-state.json`. This makes persist O(1) per request
  instead of O(state size).
- Add a per-source rate limit (token bucket per peer IP, default
  60 mutations / minute, configurable via `--rate-limit`).
- Cap the live SSE connection count (currently unbounded — see M4).
- Replace the per-request `thread::spawn` with a small thread pool
  (e.g. `rayon` or `tokio` runtime) so a flood of sockets cannot
  exhaust the file descriptor table.

**References**: hub.rs:486 (TcpListener::bind), hub.rs:539-547 (the
spawn loop), `generalized-audit.md` for prior observations on accept
loops in devnet tooling.

### H3. PUT /api/state-file is a complete-replace primitive; no diff, no
preview, no audit trail beyond one Critical event

**Surface**: `hub.rs:957-980` (route), `hub.rs:597-660` (`HubStore::replace`)

**Claim**: `replace` parses the uploaded JSON, validates the
pubkey/network invariants, refuses operational records, and overwrites
the live store in one step. There is no dry-run, no diff against the
current state, no operator confirmation step (the UI is the only
gatekeeper — see hub-frontend-uiux-audit.md H4), and the only
post-restore evidence is a single `Critical` event with the backup
path. If the upload is well-formed but semantically wrong (e.g. wrong
network in a value field, an invoice whose signature was signed by a
different `invoice_private_key` than the live one), the operator sees
"state restored" and a 200 OK response.

The validation is shallow: it only checks pubkey/network identity and
the empty-operational-records constraint. It does *not* re-verify
invoice signatures against the live signing key, does not check
channel `state_number` ordering, does not check factory
`update_number` ordering, and does not check that the watchtower
alert file references any of the restored channels.

**Interaction impact**: a successful PUT that does not match the live
signing key will produce invoices that fail external signature
verification on the next read, with no backend error. The operator
sees "Invoice created" in the UI but the `encoded_invoice` is invalid.
This is silent data corruption, not a hard fail.

**Suggested fix**:

- After parsing, re-run every invoice's `validate()` against the live
  signing key (`payee_pubkey_sec1` must derive from the running
  `invoice_signing_key`). Return 422 with a per-invoice list of
  failures.
- For channels and factories, re-verify `state_number` /
  `update_number` ordering, and assert that every channel's
  `funding_context_id` is referenced by at least one peer invoice or
  watchtower alert.
- Add a `?dry_run=true` query parameter to PUT that runs every
  validation and returns the diff (added/removed/changed records)
  without persisting. The UI can use this to show a confirmation
  panel ("3 channels will be removed, 2 invoices will be replaced").
- Promote the `Critical` event to also include the diff summary
  (added/removed counts, key fields of changed records) so the audit
  trail is recoverable from `events`.

**References**: hub.rs:597 (`replace`), hub-frontend-uiux-audit.md:H4
(destructive single-click), SECURITY-FIXES.md (the prior audit-cycle
findings all live at the CKB-script layer; the Hub-side restore
primitive is new ground).

### H4. Persist is synchronous on the request thread; the operator
sees 200 OK only after the file is fully written and fsynced

**Surface**: `hub.rs:1381-1395` (`mutate`), `hub.rs:776-785`
(`persist`), `hub.rs:1713-1730` (`write_private_file_atomic`)

**Claim**: The `mutate` flow is `lock → clone → closure → view →
persist → assign`. `persist` writes a pretty JSON to a temp file,
`fsync`s it, `rename`s into place, and `fsync`s the parent directory.
On a slow disk (or a devnet box that is also running a CKB node under
load), this can take hundreds of milliseconds. The operator's UI is
blocked for the full duration because the request thread is the one
doing the IO. There is no `Content-Length: 0` 202 Accepted fast path
for "queued for persist".

The flow is also fragile: if `persist` fails after the in-memory
mutation succeeded, the route returns 500 but the live store has
already been swapped. The `*store = candidate` assignment is the
*last* line of `mutate`, so a persist failure correctly rolls back —
*but* `push_event` and `view()` calls between the closure and
`persist` may have already appended events that are then dropped.
Re-read `mutate` carefully: it clones `store` into `candidate`,
runs the closure on `candidate`, builds a `view` from `candidate`,
persists `candidate`, then assigns. So events written into
`candidate.state.events` are persisted atomically with the mutation
that produced them. That is correct, but the operator never sees
partial state.

**Interaction impact**: a slow disk makes the UI feel frozen. A
persist failure returns 500 with no rollback signal in the events
log (the event that *would have* been written is gone). The operator
cannot tell whether the mutation succeeded.

**Suggested fix**:

- Move `persist` to a background writer task: the request clones,
  runs the closure, builds the view, sends the new state to a
  `mpsc::channel` to the writer, swaps the in-memory store, returns
  200 OK. The writer task does temp+rename+fsync off the request
  thread. A failure in the writer logs a `Critical` event
  ("state_persist_failed: {err}") that the operator sees in the
  console.
- Add a `?wait_for_persist=true` query parameter for tests and for
  the rare "I want to know the file is on disk before I close the
  tab" case.
- Surface the persist status in the `HubView.security` block (e.g.
  `persist_pending: true` when the writer queue is non-empty) so the
  UI can show a small "saving…" indicator instead of leaving the
  operator guessing.

**References**: hub.rs:1381 (`mutate`), hub.rs:776 (`persist`).

### H5. Error responses leak internal state through `anyhow`'s context
chain

**Surface**: `hub.rs:933-938` (`route` and `route_result`),
`hub.rs:552-595` (`HubStore::load_or_create`), `main.rs:2808-2816`
(token resolution)

**Claim**: Every error in `route_result` is rendered as
`json!({ "error": err.to_string() })`. `anyhow::Error::to_string()`
includes the *full* context chain: file paths, system error
descriptions, and any `with_context` messages. A few examples that
are reachable from a normal request:

- `"failed to write .node-state.json.12345.tmp: No space left on
  device (os error 28)"` — leaks the absolute temp path (which embeds
  the state file's parent dir) and the underlying OS error.
- `"hub state lock is poisoned"` — leaks the existence of an internal
  mutex and the fact that a previous request panicked.
- `"failed to read hub state
  /home/operator/.morph/node-state.json: invalid JSON"` — leaks the
  full home directory and that the file path the operator chose is
  wrong.
- `"failed to read auth token file /etc/morph-hub/token: permission
  denied (os error 13)"` — leaks the existence and content of a
  system file the operator was trying to keep secret.
- `auth_token_stdin` is *not* echoed back, but a malformed token
  produces a "must not be empty" error that confirms stdin was
  readable.

The auth token is the only field that is consistently *not* echoed
back (it is `hide_env_values = true` in clap), but everything else
is fair game.

**Interaction impact**: the operator gets enough information to
self-diagnose, which is good for UX but also gives an attacker on
the LAN (or a co-tenant) a full filesystem layout, internal state
shape, and which subsystems are wired in. Combined with H1, an
attacker on the same loopback can map the operator's environment
through 50-100 error responses.

**Suggested fix**:

- Define a `HubError` enum with `UserFacing(String)` and
  `Internal(anyhow::Error)` variants. The route layer renders
  `UserFacing` directly and renders `Internal` as
  `{"error": "internal error; check hub logs", "trace_id": "..."}`.
  The trace_id maps to a server-side log line that contains the full
  context.
- For known validation errors (bad hex, missing field, wrong
  network), keep the message user-facing — these are correct as is.
- For the file-system and lock-poisoned errors specifically, replace
  with `"failed to read hub state file; check that it is valid JSON
  and readable"` and a server-side log.
- For the auth-token-file path, do not include the path in the user
  response; log it server-side.

**References**: hub.rs:933 (`route`), hub.rs:557 (`fs::read_to_string`
context), main.rs:3530 (auth token file read context).

### H6. State-file corruption is a hard fail with no recovery guidance

**Surface**: `hub.rs:552-568` (`load_or_create`)

**Claim**: On startup, `HubStore::load_or_create` reads
`state_path` and parses it as `PersistedHubState`. If the file is
missing, fine — create a new state. If the file exists but is not
valid JSON, the Hub refuses to start. If the JSON parses but the
`version` field is wrong, the Hub refuses to start. The error
message is the raw `serde_json` message, which is informative for
the developer but not for the operator who edited the file by hand
or had a partial write survive a crash.

The `write_private_file_atomic` function uses temp+rename, so a
crash mid-write should not produce a partial file. But if the file
*was* hand-edited (e.g. by an operator trying to fix a typo), the
error chain is opaque: the operator does not know whether the
problem is the JSON shape, a missing field, a wrong `version`, or a
referential integrity failure (peer missing for a channel, etc.).

**Interaction impact**: a single character corruption in
`node-state.json` makes the entire Hub refuse to start, and the
operator has no guidance on how to recover short of restoring from
`.bak.<nanos>.<pid>` (which the API creates, but the operator may
not know to look for).

**Suggested fix**:

- On load failure, do not just refuse to start. Run a recovery
  ladder: (1) try to parse the file as `PersistedHubState`; (2) if
  that fails, look for `node-state.json.bak.*` in the same
  directory and offer to use the most recent; (3) if no backup
  exists, log a `Critical` event ("hub state file corrupt; backed
  up to {path} and starting fresh"), back up the corrupt file with
  `.corrupt.{nanos}.{pid}` suffix, and start with an empty state.
  This requires an opt-out flag (`--no-auto-recover`) so the
  operator can choose strict mode.
- Add a `morph hub repair --state-path ...` subcommand that runs
  the recovery ladder in offline mode and prints what it would do.
- The error message should distinguish "version mismatch" (do not
  auto-recover — likely a downgrade), "JSON parse error" (auto-
  recover candidate), and "ref-integrity failure" (partial —
  print which records failed).

**References**: hub.rs:552-595, SECURITY-FIXES.md (no prior finding
on Hub-side state recovery — the existing closeouts are all CKB-
script and watchtower policy).

---

## Medium-impact findings

### M1. HTTP parsing accepts `Content-Length: 0` and `Content-Length: N`
without a `Transfer-Encoding` check, but does not handle multiple
`Content-Length` headers

**Surface**: `hub.rs:1881-1910` (`read_request_from_reader`)

**Claim**: The parser reads `content-length` from the headers and
reads exactly that many bytes. It does not check for multiple
`Content-Length` headers (HTTP spec violation: must reject with 400)
and does not check `Transfer-Encoding: chunked` (which is silently
ignored — the request is treated as having no body). The request
line check accepts any `HTTP/x.y` version but does not reject
malformed version strings. The path parser uses
`uri.split('?').next()` which discards the query string; that is
correct for the current routing (no API uses query params yet), but
makes future auth-via-query-string impossible.

**Interaction impact**: request smuggling is not a real concern on
loopback, but if the Hub is ever fronted by a reverse proxy, the
mismatch between what the Hub reads and what a downstream proxy
reads could let an attacker append a body that the proxy strips
but the Hub reads (or vice versa). A multi-`Content-Length` header
is the classic way to do this.

**Suggested fix**:

- Reject requests with more than one `Content-Length` header.
- Reject requests with `Transfer-Encoding` other than `identity` (or
  implement `chunked` properly — the body reader already supports
  `read_exact`, so chunked is cheap to add).
- Validate the HTTP version is `HTTP/1.1` or `HTTP/1.0`.

**References**: hub.rs:1881-1910, RFC 9112 §6.1, §6.3.

### M2. `static_path` blocks `..` components but does not block
symlinks, null bytes, or non-UTF-8 paths

**Surface**: `hub.rs:2047-2058` (`static_path`)

**Claim**: `static_path` splits on `/` and rejects any component
that equals `..`. It does not:
- canonicalise the path and re-check that the resolved path is
  inside `ui_dir`. A symlink in `ui_dir` pointing outside
  (e.g. `ui_dir/leak -> /etc/passwd`) would be served.
- reject null bytes in the path. Rust's `Path` constructor does not
  reject NUL on Unix; downstream `fs::read` will fail with
  `InvalidInput`, but the request log will show the NUL-prefixed
  path.
- reject percent-encoded `..` (e.g. `/%2e%2e/etc/passwd`). The
  `split('/')` step sees a single component `%2e%2e`, which is not
  equal to `..`, so it passes. The `fs::read` step will fail to find
  the file, so this is not exploitable today, but a future endpoint
  that percent-decodes would be vulnerable.

**Interaction impact**: a misconfigured `ui_dir` (e.g. one that
shares a directory with secrets) can be exploited via a symlink.
The percent-encoding case is latent.

**Suggested fix**:

- After joining with `ui_dir`, call
  `path.canonicalize().unwrap_or(path.clone())` and assert the
  result starts with `ui_dir.canonicalize().unwrap_or(ui_dir.clone())`.
- Reject any path component that contains NUL (`.contains('\0')`).
- Reject any path component that percent-decodes to `..` (parse
  percent-encoded bytes; if any component decodes to `..`, reject).

**References**: hub.rs:2047-2058 (current implementation),
generalized-audit.md (similar `..` checks in other CKB tooling).

### M3. SSE event stream does not limit concurrent subscribers, and
each subscriber polls the store every second

**Surface**: `hub.rs:1172-1205` (`stream_events`),
`hub.rs:1215-1229` (`events_after`)

**Claim**: `stream_events` runs in a loop that takes the store lock
every 1 second (`EVENT_STREAM_POLL_INTERVAL`). Each subscriber
holds a thread for the full duration of the SSE connection. There
is no max-subscribers cap, no idle-timeout, and no Last-Event-ID
deduplication across subscribers (the operator's reconnect from a
phone hitting a flaky network can replay the same 128 events every
time). The store is taken under `store.lock()` to read `events`,
which serialises against the mutation lock.

**Interaction impact**: with 50 SSE clients and a 1-second poll, the
store lock is taken 50 times per second just to read events. On
loopback this is fine; on LAN with a slow CPU, it will visibly
delay mutations during a live event storm.

**Suggested fix**:

- Replace the 1-second poll with a `Condvar`/`Notify` pattern: the
  mutation path calls `state.notify_all()` after pushing an event,
  and each SSE subscriber `wait`s on it. This makes the lock acquire
  one-shot per event instead of per subscriber per second.
- Cap concurrent SSE subscribers (e.g. 16) and return 503 to
  additional clients.
- Add an idle timeout (e.g. 5 minutes) and a hard max-connection
  duration (e.g. 1 hour) so a runaway tab cannot keep a thread
  alive indefinitely.

**References**: hub.rs:1172-1205.

### M4. Invoice creation does not bound `expiry_secs`; the upper limit
is `u64::MAX` seconds (~5.85e11 years), but the *lower* limit is
just `> 0`

**Surface**: `hub.rs:1012-1020` (`POST /api/invoices`),
`crates/morph-core/src/node.rs:243-256` (`new_unsigned`)

**Claim**: `expiry_secs` is required to be `> 0`, and
`created_at_unix + expiry_secs` is required not to overflow. That
is the only check. An operator can create an invoice that expires
one second from now, or one that "expires" in the year
4027942307459565. The latter is a typo waiting to happen (an
operator typing `86400 * 365` when they meant `86400 * 30` will
type `31536000`; an operator typing `31536000 * 100` instead of
`* 10` will get an invoice that is alive for a century). There is
no warning at the API or UI layer for unusually long expiries.

**Interaction impact**: a UI mis-click on the expiry field can
create an invoice that is "valid" for centuries, which then sits in
the local state file and clutters the operator's `invoices` view
forever. Combined with H1, anyone on the LAN can DoS the operator
by minting thousands of these.

**Suggested fix**:

- Cap `expiry_secs` at a sane upper bound (e.g. 7 days = 604800
  seconds; configurable via `--max-invoice-expiry-secs`). Anything
  beyond that returns 422.
- In the UI, default the expiry field to 1 hour, and add a tooltip
  that says "long-lived invoices are not supported; max 7 days".
- In the API response, surface a warning if the expiry is more
  than 24 hours.

**References**: hub.rs:1012-1020, `generalized-audit.md` (the
existing devnet `*_secs` arguments all have implicit caps via
`relative-block` since values).

### M5. Channel `local` / `remote` / `pending` amounts are accepted
without a minimum granularity check

**Surface**: `hub.rs:1774-1785` (`parse_amount`),
`hub.rs:1077-1106` (`POST /api/channels`)

**Claim**: `parse_amount` accepts any positive u128 for
`local` / `remote` / `pending` / `reserve`. There is no check
that the value is aligned to the asset's granularity (CKB's
minimum unit is 1 shannon = 1; xUDT amounts have their own
decimals). The Hub is *operator UI* and not the chain, so it is
not a fund-loss bug per se — but a typo (`1000000` instead of
`100000` shannons) will be persisted and then show up in the UI
as "100,000" without a unit suffix, silently.

**Interaction impact**: an operator setting up a 0.001 CKB
channel with `local = 100000` shannons will see "0.001 CKB" in
some UIs and "100000" in others, depending on the asset view's
unit handling. There is no on-screen unit conversion. The devnet
xUDT smoke uses 8-decimal UDT amounts, but the Hub does not
enforce that xUDT amounts align to the UDT's decimals.

**Suggested fix**:

- In `AssetView`, surface the asset's `decimals` (for known
  xUDT types) or default to 8 (CKBytes shannons). Render all
  amounts in the API as a `(value, decimals)` pair, not as a
  stringified number.
- Reject amounts whose decimal expansion is not aligned to the
  asset's decimals (e.g. for a 2-decimal UDT, `1.234` is
  rejected; `1.23` is accepted).
- Add a `--amount-units ckb | shannon` flag to the API so the
  operator can choose the display unit.

**References**: hub.rs:1774, `docs/audit-matrix.md` (existing
observations on amount stringification).

### M6. `static_path` joins with `ui_dir` and serves `index.html` as a
fallback, but does not set `Cache-Control` headers on static assets

**Surface**: `hub.rs:1540-1572` (`route_static`)

**Claim**: The static asset path returns a `200 OK` with the file
body and the right `Content-Type`, but with no `Cache-Control`,
`ETag`, or `Last-Modified` header. The UI's `npm run build`
produces hashed asset names (e.g. `assets/index-abc123.js`), so
operators get a fresh download on every refresh. The `index.html`
fallback is served with no `Cache-Control: no-cache`, so a browser
that has cached an old `index.html` will keep loading it even
after a new build is deployed.

**Interaction impact**: UX-only, but a real one — operators
rebuilding the UI have to do a hard refresh to see the new build.

**Suggested fix**:

- For hashed assets (`/assets/*` or matching a fingerprint
  pattern), set `Cache-Control: public, max-age=31536000,
  immutable`.
- For `index.html`, set `Cache-Control: no-cache, must-revalidate`
  and add an `ETag` based on the file's mtime + size.

**References**: hub.rs:1540-1572.

### M7. Watchtower alert file re-read on every request; no incremental
state, no mtime cache

**Surface**: `hub.rs:1517-1538` (`watchtower_view`),
`crates/morph-cli/src/watch_alert.rs` (the `load_watchtower_alerts`
helper)

**Claim**: Every `/api/state` GET and every SSE event re-reads the
watchtower alert JSONL file from disk and re-parses every line.
The file is also re-read inside `mutate` to build the
`HubView.watchtower` block. For a file with thousands of alerts
(typical for a long-running watchtower), this is several MB of
parsing per request. There is no mtime cache: the file is
re-parsed even if nothing changed.

**Interaction impact**: a busy watchtower combined with a polling
UI (when SSE is unavailable) makes every state refresh noticeably
slow. Combined with H2, the read rate multiplied by mutations
creates a CPU hotspot.

**Suggested fix**:

- Cache the parsed `WatchtowerView` keyed by `(path, mtime,
  size)`. On `view()`, return the cached value if the file has
  not changed. The cache lives in the `HubServer` and is updated
  by a background poll (e.g. every 5 seconds).
- Stream-tail the JSONL: keep the file's current read offset in
  memory, only parse new lines since the last read. Combined with
  the mtime cache, this makes the per-request cost `O(new lines
  since last request)` instead of `O(total file size)`.

**References**: hub.rs:1517, `crates/morph-cli/src/watch_alert.rs`
(the full file is re-parsed in `load_watchtower_alerts`).

### M8. The Hub is single-tenant by design but the API surface
implies multi-tenant (no concept of "current operator")

**Surface**: `hub.rs` (all of `route_api`)

**Claim**: There is no concept of an "operator identity" beyond
the running `pubkey` baked into `--pubkey`. Every channel,
invoice, factory, and event is implicitly attributed to that one
operator. If two operators share the Hub (e.g. a team running
one devnet box, or an operator who rotates their pubkey), the
state file mixes records from both. There is no API to list "my"
channels vs "someone else's", no API to filter events by
operator, and no API to delete a record owned by a non-current
operator (the operator can only stop running the Hub and edit
the file by hand).

**Interaction impact**: this is a design-level UX bug. The Hub
advertises itself as a single-operator console but its data
model is shared. A second operator who joins the same Hub will
see the first operator's channels, invoices, and watchtower
alerts.

**Suggested fix**:

- Document the single-operator model in the README and in the
  HubView's `security` block. Add a `single_operator: true`
  field.
- For the devnet use case, add a `--node-name` flag (free-form
  string) and surface it in the topbar so operators running
  multiple Hubs can tell them apart. Not a real fix, but a UX
  hint that prevents the "wait, why is this channel here?"
  moment.

**References**: hub.rs:67-72 (`HubRuntimeState`),
hub-frontend-uiux-audit.md:M2 (network badge — same family of
"ambiguous context" findings).

---

## Low-impact findings

### L1. `constant_time_eq` is hand-rolled; consider
`subtle::ConstantTimeEq` for future-proofing

**Surface**: `hub.rs:1634-1643`

**Claim**: The implementation is correct for the
`left.len() == right.len()` common case (which is what `HubServer`
always sees — both are hex-encoded random bytes of the same
length). The `xor` of lengths is included in the diff, so unequal
lengths are also constant-time relative to the content. There is
no early return on length mismatch, which is the classic
constant-time mistake. The implementation is fine.

**Interaction impact**: none today. Future risk: if someone
refactors `auth_failure_response` to compare the raw bytes of
the `Authorization` header against the token (which would include
the `Bearer ` prefix), the lengths would differ and the function
would still be constant-time but slower. Move to `subtle` only if
the comparison ever involves a variable-length secret.

**Suggested fix**: leave as is, add a `#[allow(dead_code)]`-free
unit test that asserts the runtime on equal-length and
unequal-length inputs is identical (so a future refactor does not
introduce an early return).

**References**: hub.rs:1634.

### L2. `HubStore::load_or_create` writes the state file on every
load, even if nothing changed

**Surface**: `hub.rs:552-595`

**Claim**: After loading or creating the state, the function
calls `store.persist()` unconditionally. This is necessary to
write the initial empty state, but for an existing file that
parses correctly, it triggers a re-serialise + temp + rename +
fsync on every Hub start. On a large state file (tens of MB
after months of devnet use), this adds a noticeable startup
delay.

**Interaction impact**: UX-only, but the operator may interpret
"Hub takes 5 seconds to start" as broken.

**Suggested fix**: skip the persist when `path.exists()` is true
and the parsed state matches the in-memory representation
byte-for-byte. If you are paranoid, only skip when the `version`
field is the same and the `events.len()` is the same.

**References**: hub.rs:593 (`store.persist()?`).

### L3. `--auth-token` echo via clap is suppressed, but the value
appears in `ps aux` / `/proc/<pid>/cmdline`

**Surface**: `main.rs:455-457`

**Claim**: `hide_env_values = true` hides the token from clap's
help output, but the value is still passed as a CLI argument and
therefore visible in `ps aux` and in `/proc/<pid>/cmdline`. The
README correctly steers operators toward `--auth-token-file`,
`--auth-token-stdin`, and `--rotate-auth-token-on-restart`, but
does not warn about the `ps` leak for the direct flag.

**Interaction impact**: the value is in the process command line
for the entire Hub uptime. Co-tenant processes on the same host
can read it. Loopback-only deployment reduces but does not
eliminate the risk (any other process owned by the same user
can read `/proc/<pid>/cmdline`).

**Suggested fix**: add a one-line warning to the help text for
`--auth-token`: "the token is visible in process listings;
prefer `--auth-token-file` or `--auth-token-stdin`". Optionally,
in the Hub's startup banner, print a one-time warning when
`--auth-token` (not file/stdin/rotate) is used on a non-loopback
bind.

**References**: main.rs:455-457, README:191-208.

### L4. `error` field is the only diagnostic in every API response;
no `request_id` / `trace_id` for log correlation

**Surface**: `hub.rs:933-938` (the error response builder)

**Claim**: Every error response is
`{"error": "some message"}`. There is no correlation id, so
the operator cannot match an error in the UI to a log line. The
Hub's `eprintln!` calls in `stream_events` use the message
verbatim, but the message may be ambiguous if multiple
connections are erroring at once.

**Interaction impact**: low. The Hub is local, single-tenant,
and the operator's mental model is "I am the only one calling
this." A request id would be nice-to-have for future multi-
operator Hubs.

**Suggested fix**: generate a per-request UUID v4, set it as
`x-morph-hub-request-id` on every response, include it in the
`error` JSON, and print it in every `eprintln!` log line.

**References**: hub.rs:933-938.

### L5. The Hub's `CORS` allow-list is a single origin, but the
default of "no cross-origin" is correct only when the UI is
proxied through the same origin

**Surface**: `hub.rs:433-446` (`normalise_cors_origin`)

**Claim**: The `cors_origin` check rejects `*` and requires
`http://` or `https://`. It does not check that the origin
matches the listen address's host. An operator who sets
`--listen 0.0.0.0:4617 --cors-origin http://localhost:5173` will
allow a malicious site hosted at `localhost:5173` (or any
`http://localhost:...` page the operator happens to be
visiting) to issue cross-origin requests to the Hub with
credentials. The credentials are not auto-attached (no cookie
auth), so the practical impact is limited to the bearer token
path — but the operator may have the token in localStorage
(per the UI design), and a malicious site can read localStorage
if it shares the origin.

**Interaction impact**: low. The CORS rule is the right shape
(only the configured origin can read responses), but operators
should be told to keep `--cors-origin` and `--listen` aligned.

**Suggested fix**: when `cors_origin` is set, require that its
host component matches the listen host (allowing for
`localhost` ↔ `127.0.0.1` equivalence). Print a startup
warning if the mismatch is non-trivial.

**References**: hub.rs:433-446, hub.rs:1961-2000 (the
`write_response` CORS write).

### L6. The devnet-only `auto_fund_sponsor` and `fund_sponsor` paths
are reachable through the same Hub command surface

**Surface**: `main.rs:521-580` (the `devnet` subcommand)

**Claim**: This is not a Hub API issue — it is a CLI surface
issue. The devnet `auto_fund_sponsor` and `fund_sponsor`
subcommands are gated behind `--features devnet` in
`Cargo.toml`, but a user who enables the feature gets the
same CLI as the production one. There is no confirmation step
that says "this will deploy a real CKB transaction that costs
real capacity to a real sponsor cell." A misclick or a
script bug can broadcast a real on-chain action.

**Interaction impact**: devnet-only, so low. But the devnet
feature is part of the same `morph` binary, and the
`morph-hub` UI does not gate devnet commands. Operators who
run `morph devnet` from the same shell as `morph hub serve`
should be aware that the binary can do real chain actions.

**Suggested fix**: in the `morph devnet` subcommand help text,
add a banner: "devnet only — broadcasts to a local devnet
CKB node. Do not run against testnet or mainnet." The
subcommand already requires `MORPH_DEVNET_PRIVATE_KEY` env var
which is a soft signal, but a hard check on the RPC URL
(`http://127.0.0.1:*` and not `https://...`) would be
stronger.

**References**: main.rs:479-588, `docs/audit-matrix.md` (prior
observations on the devnet/testnet surface separation).

---

## Cross-cutting observations

**The Hub is a single-tenant, loopback-first service, and the
security model is correct for that scope.** Loopback binds
disable auth by design; non-loopback binds require a token;
the token is constant-time-compared; the state file is
private-mode and atomic-write; the watchtower webhook rejects
non-loopback HTTP and requires HMAC for the secret path. The
*CKB on-chain* trust model is covered by `W1` and the prior
security closeouts; the *Hub transport* trust model is
covered above.

**The biggest remaining gap is not crypto, it is operator
recovery.** H3, H6, M7, and L2 are all variations on the same
theme: the Hub is hard to recover from in edge cases (state
corruption, large state files, full state replacement). The
operator who is staring at a 500 OK followed by a broken UI
does not have a recovery runbook today.

**The Hub is also fragile under load.** H2, H4, M3, M7 all
stem from "every request walks the full state." The
mitigations are not glamorous (rate limit, semaphores,
background writer, mtime cache) but they are the difference
between a console that an operator can leave running for a
week and one that needs babysitting.

**UX-wise, the Hub is at parity with the UI audit's findings
on the action side (H4 in the UI audit, H3 here) and
slightly ahead on the diagnostic side (H5 vs M4 in the UI
audit).** The Hub's error messages are too verbose for
untrusted callers but exactly right for the operator. The
right fix is the `HubError { UserFacing, Internal }` enum in
H5, which keeps the operator experience while removing the
information leak.

---

## Recommended fix order

If only one sprint is available, the order is:

1. **H1** (loopback auth scope) and **H5** (error message
   scoping) — these are the only findings that can be
   exploited by an attacker on the same host. Both are
   small. H1 requires a config struct change; H5 is a
   `HubError` enum.
2. **H2** (rate limit + persist journal) and **H4**
   (background writer) — these are the UX-critical
   reliability fixes. Without them, the Hub cannot be left
   running unattended.
3. **H3** (state-restore preview) and **H6** (corruption
   recovery) — these are the recovery-runbook items. They
   are the difference between an operator who trusts the
   console and one who keeps a hand on the kill switch.
4. Everything else can be batched into the next audit cycle.

**Files touched by the recommended fixes**:

- `crates/morph-cli/src/hub.rs` (auth scope, rate limit,
  background writer, error enum, corruption recovery,
  restore preview, SSE cap, content-length hardening,
  static path canonicalisation, cache headers, watchtower
  mtime cache, request id)
- `crates/morph-cli/src/main.rs` (token warning, devnet
  RPC check)
- `crates/morph-core/src/node.rs` (re-run invoice
  `validate()` on restore)
- `ui/morph-hub/src/*` (consume the new `security` /
  `persist_pending` / `restore_preview` fields)
