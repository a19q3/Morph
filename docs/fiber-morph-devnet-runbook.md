# Fiber/Morph Devnet Runbook

This runbook is for operators who need clear evidence that Morph and Fiber can
share a local CKB devnet while covering the committed business-flow and security
model matrix.

The canonical release gate is:

```sh
make fiber-morph-devnet-acceptance-full
```

Use this runbook when preparing a release candidate, reviewing a protocol
change, or checking whether a local devnet run contains enough business-flow
evidence to trust.

## Quick Decision Table

| Need | Command | Expected result |
| --- | --- | --- |
| Check local dependencies only | `make fiber-morph-devnet-preflight` | Creates a run directory with `status=preflight-passed`. |
| Prove Morph and Fiber coexist on one CKB devnet | `make fiber-morph-devnet-acceptance` | Runs Morph stateful scenarios and Fiber external funding on the same Fiber CKB node. |
| Prove the full Morph plus Fiber matrix | `make fiber-morph-devnet-acceptance-full` | Runs coexistence, strict Fiber Bruno suites, funding-tx verification, and the combined audit. |
| Recheck existing evidence | `make fiber-morph-devnet-audit FIBER_MORPH_ACCEPTANCE_RUN=target/fiber-morph-devnet-acceptance/<run-id>` | Rebuilds `business-flow-audit.json` from an existing run. |
| Debug only the Fiber strict matrix | `FIBER_MORPH_ACCEPTANCE_MODE=fiber scripts/fiber-morph-devnet-acceptance.sh` | Runs Fiber suites without the Morph stateful matrix. |

Production acceptance expects a clean Morph worktree. Commit or stash local code
changes before the `coexistence`, `fiber`, or `full` gates.

## Before You Run

Expected checkout layout:

```text
parent/
  Morph/ or morph-channel/
  fiber/
  ckb/
  ckb-cli/
```

The acceptance script can clone missing upstream repositories, but release
evidence is easier to audit when all four checkouts already exist and are on the
intended branches.

Required tools:

- Rust and Cargo
- `jq`
- `curl`
- `nc`
- Node.js and `npm`
- CKB and ckb-cli build prerequisites

Run:

```sh
make fiber-morph-devnet-preflight
```

If this fails, fix the dependency or checkout problem before running the full
gate. Preflight does not start devnet nodes.

## Canonical Full Run

Run from the Morph repository:

```sh
make fiber-morph-devnet-acceptance-full
```

The full gate performs these phases:

1. Records Morph, Fiber, CKB, and ckb-cli repository state.
2. Starts Fiber's three-node local devnet stack.
3. Builds Morph RISC-V CKB scripts.
4. Runs Morph's strict stateful scenario matrix against Fiber's CKB RPC.
5. Runs Fiber external funding on the same CKB devnet.
6. Runs the Fiber external-funding restart regression.
7. Starts fresh Fiber devnets for the strict Fiber Bruno suite set.
8. Runs the four Fiber funding-transaction verification cases.
9. Writes the acceptance matrix, summary, and business-flow audit.

A successful run ends with:

```text
full Fiber/Morph acceptance passed
```

The run directory is:

```text
target/fiber-morph-devnet-acceptance/<run-id>/
```

## Business Flows Covered

The full gate covers both user-visible channel operations and adversarial
conditions. The audit is intentionally strict: a JSON pass is not enough unless
the expected files and log markers are present.

### Cross-Repository Flow

| Flow | What it proves | Main evidence |
| --- | --- | --- |
| Same CKB devnet coexistence | Morph deploys and exercises scripts on the CKB node started by Fiber, then Fiber runs channel acceptance on that same node. | `acceptance-matrix.json`, `morph-stateful/scenarios/summary-check.json`, `fiber-bruno-e2e_external-funding-open.json` |

### Morph Business Flows

| Flow | User story | Security point |
| --- | --- | --- |
| Bilateral direct publish and finalise | Two participants publish the latest signed channel state and settle the vault. | State authority and final settlement are bound to the current StateCell. |
| Bilateral supersede, watchtower, and finalise | A stale publication is superseded and a watchtower publishes the newer state before finalisation. | Stale state cannot win when fresher evidence exists. |
| Sponsor fee pressure | Sponsor funding, fee ceilings, and invalid sponsor ranges are exercised. | Sponsor policy boundaries reject fee leakage and state-range abuse. |
| Splice lifecycle matrix | CKB and xUDT splice-in and splice-out update funding anchors and vault sets. | Funding-anchor and descriptor changes require signed evidence. |
| Factory lifecycle matrix | Factory open, update, reduced rights, sparse Merkle update, local child exit, and reduced exit all execute. | Factory rights and child value cannot be changed without the required proof. |
| Factory splice then exit | Conservative and reduced CKB/xUDT factory splice paths can be followed by child materialisation and finalisation. | Factory value deltas are bound across reserve, balance, and vault cells. |
| Watchtower operations | Auto-sponsor, direct sponsor, config-loop, health-file, cursor, service stop, and stale-splice watching are recorded. | Watchtower publication is cursor-aware and funding-context-aware, with funding-anchor fallback for older packages. |
| Extreme state value cases | Asymmetric capacities and one-sided xUDT paths remain valid. | Edge-value cases do not bypass typed-asset or budget checks. |
| Negative attack matrix | Known attack-shaped transactions fail with exact expected errors, then later valid transitions still commit. | Rejection paths are precise and recovery continues afterwards. |

The Morph stateful assertion also enforces minimum evidence floors, including
committed transactions, factory splices, factory local exits, watchtower alerts,
referenced artefacts, and exact expected failures.

### Fiber Business Flows

| Flow | User story | Security point |
| --- | --- | --- |
| External funding open | A channel is opened through Fiber's external funding path. | Externally built funding transactions are accepted only when they match the channel intent. |
| External funding restart | The external funding flow survives node restart before signed funding submission. | Funding state is durable across process restart. |
| Open, use, close a channel | Peers open a channel, exchange payments, and cooperatively close it. | Cooperative settlement produces the expected terminal state. |
| Three-node transfer | A routed payment moves through an intermediate node. | Multi-hop transfer and channel shutdown evidence are present. |
| Router pay | Routing, duplicate payment controls, self-pay rejection, and graph updates are exercised. | The routing graph and payment identifiers cannot be abused for duplicate settlement. |
| Re-establish | Peers disconnect and reconnect, then re-establish channel state. | Recovery preserves agreed state after network interruption. |
| Shutdown force | A force-close path is triggered after peer disconnect. | Uncooperative close remains available. |
| Hold invoice cancel failure | A cancelled hold invoice returns the expected decoded failure. | TLC failure semantics are observable and precise. |
| Periodic expiry cleanup | Periodic checks remove expired TLCs. | Expired conditional payments cannot remain unresolved; force-close itself is covered by the shutdown and watchtower suites. |
| UDT channel flow | Fiber opens and settles typed-asset channel activity. | Typed assets stay bound to the expected channel type. |
| UDT router pay | Routed UDT payment succeeds through Fiber. | Typed-asset routing preserves the asset identity. |
| Watchtower force-close after open | Watchtower handles force close after channel open. | Watchtower settlement is active even with minimal payment history. |
| Watchtower force-close with pending TLCs | Watchtower handles force close with pending conditional transfers. | Pending transfer settlement is enforced during force close. |
| Watchtower force-close after multiple payments | Watchtower handles force close after repeated payments. | Repeated state updates do not break watchtower recovery. |
| Watchtower remote force-close with stopped watchtower | Remote force-close is exercised when the watchtower has been stopped. | Recovery behaviour is checked around watchtower availability boundaries. |
| Funding tx verification: remove change | A tampered funding transaction with removed change is rejected. | Funding transaction output shape is checked. |
| Funding tx verification: modify change | A tampered funding transaction with modified change is rejected. | Change output mutation is detected. |
| Funding tx verification: fund from peer | A funding transaction using peer funds is rejected. | Funding ownership assumptions are enforced. |
| Funding tx verification: missing inputs | A funding transaction with missing inputs is rejected. | Required funding inputs cannot be omitted. |

## Security Model Checklist

The combined audit writes security families into `business-flow-audit.json`.
Treat these as the high-level security checklist for a full run.

Morph families:

- `state_authority_authenticity`
- `canonical_relative_maturity`
- `state_retirement_non_orphaning`
- `signed_descriptor_evolution`
- `non_interference_not_authorisation`
- `factory_value_delta_binding`
- `typed_asset_binding`
- `sponsor_policy_boundary`
- `watchtower_authority_and_cursor`
- `negative_recovery_continuity`
- `budget_regression`

Fiber families:

- `fiber_external_funding_persistence`
- `fiber_funding_tx_shape_validation`
- `fiber_cooperative_close_settlement`
- `fiber_force_close_watchtower_settlement`
- `fiber_tlc_error_and_failure_semantics`
- `fiber_routing_graph_and_duplicate_payment_controls`
- `fiber_reconnect_reestablish_recovery`
- `fiber_typed_asset_channel_binding`
- `fiber_periodic_expiry_recovery`

For release evidence, every listed family must be present in
`business-flow-audit.json`, and the top-level run summary must say
`"status": "passed"`.

## Reading The Artefacts

Start with these files:

```text
target/fiber-morph-devnet-acceptance/<run-id>/manifest.txt
target/fiber-morph-devnet-acceptance/<run-id>/repo-state.json
target/fiber-morph-devnet-acceptance/<run-id>/acceptance-matrix.json
target/fiber-morph-devnet-acceptance/<run-id>/summary.json
target/fiber-morph-devnet-acceptance/<run-id>/business-flow-audit.json
```

Then inspect subsystem evidence:

```text
target/fiber-morph-devnet-acceptance/<run-id>/morph-stateful/scenarios/summary.json
target/fiber-morph-devnet-acceptance/<run-id>/morph-stateful/scenarios/summary-check.json
target/fiber-morph-devnet-acceptance/<run-id>/logs/morph-stateful-on-fiber-ckb.log
target/fiber-morph-devnet-acceptance/<run-id>/fiber-bruno-*.json
target/fiber-morph-devnet-acceptance/<run-id>/logs/fiber-bruno-*.log
```

Useful checks:

```sh
jq '.status, .mode' target/fiber-morph-devnet-acceptance/<run-id>/summary.json
jq '.business_flows | length' target/fiber-morph-devnet-acceptance/<run-id>/business-flow-audit.json
jq '.security_families | length' target/fiber-morph-devnet-acceptance/<run-id>/business-flow-audit.json
jq '.minimum_evidence' target/fiber-morph-devnet-acceptance/<run-id>/business-flow-audit.json
```

For a full run, expect:

- 29 business flows
- 20 security families
- 19 required Fiber business flows
- 9 required Fiber security families
- 4 Fiber funding-transaction verification cases

## Failure Handling

Use the failing command's run directory. Do not delete it before audit.

1. Read `manifest.txt`. If it lacks `status=passed`, the run failed before the
   final audit.
2. Read `logs/morph-stateful-on-fiber-ckb.log` for Morph scenario failures.
3. Read the relevant `fiber-bruno-*.json`, then open the log path stored in its
   `.log` field.
4. Rerun `make fiber-morph-devnet-audit FIBER_MORPH_ACCEPTANCE_RUN=<run-dir>`
   after fixing missing evidence or stale artefacts.
5. If the audit reports a missing log marker, the suite may have passed without
   proving the expected behaviour. Fix the test or the audit marker before
   accepting the run.

Common causes:

| Symptom | Likely cause | Action |
| --- | --- | --- |
| Clean-worktree error | Local source files changed before a production gate. | Commit, stash, or run only preflight. |
| Missing CKB or ckb-cli binary | Sibling checkout is absent or not built. | Run preflight, then build the reported dependency. |
| Morph freshness failure | Artefacts were generated from a different Morph commit. | Rerun the gate from a clean current commit. |
| Missing Fiber result file | A strict Fiber suite or funding case was skipped. | Use the default `FIBER_BRUNO_SUITES` and `FIBER_FUNDING_TX_VERIFICATION_CASES`. |
| Missing Fiber log marker | The Bruno suite did not produce the required behavioural evidence. | Inspect the suite log and update the test or marker deliberately. |

## Narrow Debug Runs

Use narrow runs only for diagnosis. They are not release acceptance.

```sh
FIBER_BRUNO_SUITES="e2e/router-pay" \
FIBER_MORPH_ACCEPTANCE_MODE=fiber \
scripts/fiber-morph-devnet-acceptance.sh
```

```sh
FIBER_FUNDING_TX_VERIFICATION_CASES="missing_inputs" \
FIBER_MORPH_ACCEPTANCE_MODE=fiber \
scripts/fiber-morph-devnet-acceptance.sh
```

```sh
BUILD_MORPH_CONTRACTS=0 make fiber-morph-devnet-acceptance
```

When the debug run passes, rerun the canonical full gate before declaring the
candidate accepted.

## Release Evidence Statement

A release candidate has acceptable local devnet evidence only when all of the
following are true:

- `make fiber-morph-devnet-acceptance-full` exits successfully.
- `manifest.txt` contains `status=passed`.
- `summary.json` contains `"status": "passed"` and `"mode": "full"`.
- `business-flow-audit.json` contains the expected 29 business flows and 20
  security families.
- Morph `summary-check.json` passes all stateful, budget, factory, xUDT,
  watchtower, and negative-path floors.
- Every strict Fiber suite and funding-transaction verification case has both a
  passing JSON result and the required log evidence.

This is a local devnet acceptance gate. It proves the committed same-devnet
business-flow and security matrix, not mainnet readiness or cross-repository
protocol merger by itself.
