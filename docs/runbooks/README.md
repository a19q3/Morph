# Pre-production Operator Runbooks

These runbooks govern the controlled-devnet
`factory-dynamic-n` pilot. They are executable procedures, not a
mainnet operations claim.

Read and rehearse all of the following before activation:

- [`operations.md`](operations.md): release verification, keys, package
  retention, watchtower startup, health, and routine shutdown;
- [`incident-response.md`](incident-response.md): alert triage, emergency stop,
  reorg recovery, evidence preservation, and restart approval;
- [`upgrade-and-migration.md`](upgrade-and-migration.md): pre-release resets,
  contract upgrades, and rollback;
- [`rehearsal-2026-08-14.md`](rehearsal-2026-08-14.md): the repository-side dry
  run evidence for this candidate.

## Roles

| Role | Responsibility | Must not do |
| --- | --- | --- |
| Release owner | Approves commit, manifest, envelope, and activation window. | Raise caps without new evidence. |
| Factory operator | Creates packages and submits approved devnet transactions. | Use participant keys as fee-payer or Hub tokens. |
| Watchtower operator | Runs an independent RPC/config/key set and responds to alerts. | Share the Factory operator's host or mutable package store. |
| Incident commander | Freezes new risk, preserves evidence, coordinates recovery. | Delete state or redeploy before evidence capture. |

One person may rehearse multiple roles locally, but an activated pilot requires
an independently operated watchtower as declared by the policy envelope.

## Activation Gate

Activation is allowed only when all items are true:

1. `make ci` passes on the exact candidate commit.
2. `make release-readiness` matches all seven ELF hashes.
3. The deployment report contains those same CKB data hashes.
4. The envelope is unexpired and every intended value is below its cap.
5. The Factory has 2–16 participants and every member verifies its N-of-N initial package.
6. The independent watchtower health file is healthy and its cursor scan floor
   predates the Factory/channel creation block.
7. Stop, incident, and migration procedures have been rehearsed.

If any item is false, the decision is no-go.
