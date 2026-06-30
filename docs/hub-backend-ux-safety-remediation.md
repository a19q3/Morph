# Morph Hub Backend Production-Hardening Remediation

Date: 2026-06-30
Scope: `crates/morph-cli/src/hub.rs`, `crates/morph-cli/src/main.rs`,
`ui/morph-hub/src/api.ts`, `ui/morph-hub/src/actions.tsx`, and
`ui/morph-hub/src/domain.ts`.

This document supersedes the open-status sections in
`docs/hub-backend-ux-safety-audit.md` for the current single-operator devnet
Hub. It does not claim CKB mainnet protocol readiness; it records the backend
and UI hardening needed to run Morph Hub as a production-quality local operator
console.

## Operator Contract

Morph Hub is now token-first. Startup requires an auth token unless the operator
explicitly passes `--allow-unauthenticated-loopback` on a loopback listener.
Tokens may be scoped with `read,write,restore,sign:<secret>`.

The important scopes are:

| Scope | Endpoints |
| --- | --- |
| `read` | `GET /api/state`, `GET /api/events`, read-only health/status routes |
| `write` | peer, channel, factory, decode/receive/settle mutations |
| `restore` | `GET /api/state-file`, `POST /api/state-file/preview`, `PUT /api/state-file` |
| `sign` | `POST /api/invoices` |

Raw state replacement is no longer a one-step primitive. The UI first calls
`POST /api/state-file/preview`; the server returns an exact confirmation hash
for the current canonical state and the candidate canonical state. The final
`PUT /api/state-file` must send `{ "state": ..., "confirmation_hash": ... }`.

## Finding Status

| Finding | Status | Remediation |
| --- | --- | --- |
| H1 auth all-or-nothing | Fixed | Auth is required by default, loopback unauthenticated mode is explicit, tokens support `read/write/restore/sign` scopes, and insufficient scopes return 403. |
| H2 unbounded request pressure | Fixed for current deployment | Concurrent TCP connections, mutating requests, SSE streams, and mutating request rate are capped. The full-state JSON persist remains synchronous by design for crash durability. |
| H3 state-file replace primitive | Fixed | Restore now has server-side preview, confirmation hash, empty-bootstrap gating, backup before commit, critical event, and UI confirmation tied to the server hash. |
| H4 synchronous persist UX | Bounded | The synchronous temp+rename+fsync path is retained so a 200 response means durable state. Connection and mutation caps prevent runaway write storms. |
| H5 error handling | Partially fixed | API errors now use structured JSON with `code` and `request_id`. Operator-facing validation details remain in the response for this single-tenant console. |
| H6 corrupt state recovery | Fixed | Startup parse failures now include the newest adjacent `.bak.*` candidate when present. Automatic rollback is intentionally not performed. |
| M3 static asset path handling | Fixed | Existing static targets are canonicalised and must remain under the UI root, including the SPA fallback. |
| M4 SSE fan-out | Fixed | Concurrent event streams are capped. Authenticated browser sessions continue to use polling because `EventSource` cannot send bearer headers. |
| M5 invoice expiry bound | Fixed | Backend rejects invoice expiries above seven days; the UI validates against the server-reported limit. |
| M7 watchtower alert re-read cost | Fixed | Alert-file reads are cached by path, modified time, and file length. |
| L2 startup rewrite | Fixed | Existing valid state files are no longer rewritten on every Hub start. |
| L5 CORS origin shape | Fixed | `--cors-origin` must be a concrete HTTP(S) origin without path, query, fragment, wildcard, or user info. |

## Verification

The hardening pass added regression coverage for:

- duplicate `Content-Length` rejection;
- static symlink escape rejection;
- auth required without the explicit loopback escape hatch;
- scoped-token denial for write and restore routes;
- global mutation rate limiting;
- concurrent mutation limiting;
- invoice expiry ceiling;
- state-restore confirmation-hash mismatch;
- existing restore backup and corruption-safety behaviours.

Verification commands run on 2026-06-30:

```sh
cargo fmt --all
cargo test --workspace --features devnet
npm run build
```

All three passed.
