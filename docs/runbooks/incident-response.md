# Incident Response and Emergency Stop

## Severity

| Severity | Examples | Initial response |
| --- | --- | --- |
| Critical | Key compromise, unexpected accepted invalid transition, contract hash mismatch, `chain_reorg_detected` with publication uncertainty. | Freeze new risk immediately; page release owner and incident commander. |
| High | Repeated watchtower failure, stale package with live settling state, sponsor-policy violation, unexplained balance delta. | Stop mutations; keep safe monitoring online; investigate within the pilot window. |
| Medium | Single transient RPC/webhook failure, delayed health update without chain risk. | Record, retry, and escalate if repeated. |

## Immediate Containment

1. Stop opening factories/channels and stop updates, splices, exits, and Hub
   write operations. Do not stop a healthy watchtower merely to simplify the
   incident.
2. If the watchtower key or process is compromised, create its configured stop
   file, wait for a clean stop if safe, revoke its funding source, and start a
   clean independent instance from verified packages.
3. Rotate Hub and webhook secrets by restart. Do not rotate participant keys by
   editing an existing Factory; use the migration procedure.
4. Snapshot read-only copies of configs, packages, cursors, health, alerts,
   release bundle, RPC tip/hash, transaction reports, and application logs.
5. Record UTC timestamps, operator identity, commands, tx hashes, block hashes,
   affected channel/factory IDs, and the last known-good manifest.

Never delete a cell, package, cursor, or log during containment. Never deploy a
new script hash as an emergency shortcut.

## Reorg Procedure

On `chain_reorg_detected`:

1. Stop new Factory mutations but keep the canonical rescan running.
2. Confirm the alert's expected and canonical hashes independently through a
   second RPC endpoint when available.
3. Confirm the cursor reset block equals the configured channel `from_block`.
4. Wait until the cursor passes the prior height with the policy detection
   depth and a new canonical hash.
5. Recheck all publications and finalisations referenced by the orphaned range.
   A transaction without canonical commitment is pending, not successful.
6. Ensure the latest package still matches the live funding context. Recreate a
   stale post-splice package; never publish it against another context.
7. Resume only after the incident commander records canonical tx/block hashes
   and the independent watchtower agrees.

If the scan floor is newer than the fork or channel creation, treat recovery as
failed: widen `from_block`, preserve the old cursor as evidence, and rescan.

## Compromised Key

- Fee-payer/watchtower key: stop its process, stop funding it, move remaining
  devnet capacity with a separately verified key if possible, and rotate.
- One participant key: freeze the Factory, have all participants settle or
  materialise through already signed valid packages, then recreate under new
  membership. Do not claim unilateral in-place signer rotation.
- All participant keys, or enough operator infrastructure to impersonate every
  member: stop the pilot and preserve evidence; no software procedure can
  restore the lost trust boundary.
- Hub token: restart with a fresh scoped token and review mutation events.

## Recovery and Restart Approval

Root cause and affected scope must be documented. Re-run `make
release-readiness`, package validation, targeted negative tests, and the
stateful acceptance suite when contracts or protocol handling are implicated.
The release owner and independent watchtower operator must both approve the
restart. Any cap increase or contract hash change requires a new release
candidate, not an incident waiver.
