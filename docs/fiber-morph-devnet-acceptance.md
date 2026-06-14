# Fiber/Morph Devnet Acceptance

This document defines the cross-repository devnet acceptance gate for running
Fiber and Morph against the same local CKB devnet.

For an operator-facing walkthrough of the commands, covered business flows,
evidence files, and failure handling, use
[`fiber-morph-devnet-runbook.md`](fiber-morph-devnet-runbook.md).

## Purpose

The gate proves coexistence before protocol merger:

- Fiber starts its normal three-node devnet stack.
- Morph runs the strict stateful channel and factory matrix against Fiber's CKB
  RPC endpoint.
- Fiber then runs channel and external-funding acceptance on the same running
  devnet.

This is deliberately stricter than a static compatibility document. It binds
Fiber's channel/external-funding evidence to Morph's bilateral, sponsor, splice,
factory, factory-splice, xUDT, watchtower, and negative-path stateful evidence.

## Commands

Preflight only:

```sh
make fiber-morph-devnet-preflight
```

Same-devnet coexistence gate:

```sh
make fiber-morph-devnet-acceptance
```

Full gate, including additional Fiber Bruno suites:

```sh
make fiber-morph-devnet-acceptance-full
```

Audit the latest completed run without rerunning devnet:

```sh
make fiber-morph-devnet-audit
```

Audit a specific run directory:

```sh
make fiber-morph-devnet-audit FIBER_MORPH_ACCEPTANCE_RUN=target/fiber-morph-devnet-acceptance/<run-id>
```

The script is also directly callable:

```sh
scripts/fiber-morph-devnet-acceptance.sh preflight
scripts/fiber-morph-devnet-acceptance.sh coexistence
scripts/fiber-morph-devnet-acceptance.sh full
scripts/fiber-morph-devnet-audit.sh target/fiber-morph-devnet-acceptance/<run-id>
```

## Dependency Resolution

The script expects sibling checkouts under the parent of this repository:

- `../fiber`
- `../ckb`
- `../ckb-cli`

If one is missing, the script clones the upstream Nervos checkout. It then
resolves or builds:

- `ckb`
- `ckb-cli`

Those binaries are exposed through a temporary `target/.../tool-bin` directory
so Fiber's existing dev scripts can keep calling `ckb` and `ckb-cli` from
`PATH`.

## Modes

### `preflight`

Checks tools, sibling repositories, CKB binaries, and records repo state. It
does not start devnet nodes.

### `coexistence`

The production coexistence gate:

1. requires a clean Morph worktree;
2. starts Fiber's three-node devnet with `e2e/external-funding-open`;
3. builds Morph RISC-V contracts;
4. runs `scripts/devnet-stateful-scenarios.sh` with
   `MORPH_CKB_RPC=http://127.0.0.1:8114`, so Morph uses Fiber's CKB devnet;
5. runs Fiber's `e2e/external-funding-open` Bruno suite;
6. runs Fiber's external-funding restart regression unless disabled.

### `fiber`

Runs the strict Fiber suite set without Morph's stateful matrix. This is useful
when debugging Fiber-only business-flow coverage before paying the cost of the
full cross-repository run.

### `full`

Runs `coexistence`, then starts fresh Fiber devnets for the strict Fiber suite
set listed in `FIBER_BRUNO_SUITES`.

Default strict Fiber suites:

```text
e2e/open-use-close-a-channel
e2e/3-nodes-transfer
e2e/router-pay
e2e/reestablish
e2e/shutdown-force
e2e/hold-invoice-cancel-failure
e2e/period-check/force-close-expiry
e2e/udt
e2e/udt-router-pay
e2e/watchtower/force-close-after-open-channel
e2e/watchtower/force-close-with-pending-tlcs
e2e/watchtower/force-close-after-multiple-payments
e2e/watchtower/force-close-remote-with-pending-tlcs-and-stop-watchtower
```

The strict Fiber gate also runs every funding-transaction verification case:

```text
remove_change
modify_change
fund_from_peer
missing_inputs
```

## Evidence

Each run writes under:

```text
target/fiber-morph-devnet-acceptance/<run-id>/
```

Key files:

- `manifest.txt`: run parameters and final status;
- `repo-state.json`: Morph, Fiber, CKB, and ckb-cli checkout state;
- `acceptance-matrix.json`: required evidence families;
- `business-flow-audit.json`: machine-checked Morph/Fiber business-flow and
  security-family coverage;
- `summary.json`: top-level pass summary;
- `logs/`: Fiber stack logs, Morph stateful logs, Bruno logs, and build logs;
- `morph-stateful/scenarios/`: Morph stateful scenario and smoke artifacts.

## Business-Flow And Security Audit

Every `coexistence`, `fiber`, and `full` run now executes
`scripts/fiber-morph-devnet-audit.sh` after writing the top-level summary. The
audit fails the run unless the completed artefacts prove the expected flow set.

For Morph, the required business scenarios are:

- `bilateral_direct_publish_finalise`
- `bilateral_supersede_watchtower_finalise`
- `sponsor_fee_pressure`
- `splice_lifecycle_matrix`
- `factory_lifecycle_matrix`
- `factory_splice_then_exit`
- `watchtower_operations`
- `extreme_state_value_cases`
- `negative_attack_matrix`

The same audit also requires all 11 Morph security families from
`docs/devnet-audit-profile.example.json` to pass, including the P0 authority,
maturity, non-interference, factory value-delta, and typed-asset binding
families.

For Fiber, `coexistence` requires:

- `e2e/external-funding-open`
- `e2e/external-funding-open/restart`

The `full` gate additionally requires:

- `e2e/open-use-close-a-channel`
- `e2e/3-nodes-transfer`
- `e2e/router-pay`
- `e2e/reestablish`
- `e2e/shutdown-force`
- `e2e/hold-invoice-cancel-failure`
- `e2e/period-check/force-close-expiry`
- `e2e/udt`
- `e2e/udt-router-pay`
- `e2e/watchtower/force-close-after-open-channel`
- `e2e/watchtower/force-close-with-pending-tlcs`
- `e2e/watchtower/force-close-after-multiple-payments`
- `e2e/watchtower/force-close-remote-with-pending-tlcs-and-stop-watchtower`
- `e2e/funding-tx-verification/remove_change`
- `e2e/funding-tx-verification/modify_change`
- `e2e/funding-tx-verification/fund_from_peer`
- `e2e/funding-tx-verification/missing_inputs`

For Fiber, the audit does not merely trust each suite's JSON status. It also
checks the Bruno or restart log for named request evidence, including external
funding submission after restart, duplicate-payment rejection, reconnect
re-establishment, forced shutdown, cancelled hold-invoice failure decoding,
periodic expired-TLC cleanup, xUDT routing, watchtower settlement, and all four
funding-transaction verification cases. The period-check expiry suite also
requires stack-log evidence that both expired TLCs were removed with
`RemoveTlcFail` and both sides reached zero active TLCs; the dedicated
shutdown/watchtower suites provide the force-close evidence.

The coexistence gate treats Fiber's `e2e/external-funding-open` balance and
early-readiness checks as stale in this devnet profile when the upstream Bruno
collection fails only after the essential external-funding requests have
succeeded. In that case the harness still requires explicit `200 OK` evidence
for open, sign, submit, cooperative shutdown, closed-state capture, and shutdown
transaction inspection before it writes a passed evidence JSON. This exception
does not accept a failure of the external-funding flow itself.

The generated `business-flow-audit.json` records these named flows, their
evidence files, the Morph and Fiber security families, and the minimum evidence
floors for committed transactions, factory exits, factory splices, watchtower
alerts, expected failures, referenced artefacts, Fiber business flows, and
funding-transaction verification cases.

## Production Strictness

The coexistence and full gates are intentionally strict:

- Morph stateful acceptance requires committed transaction evidence;
- factory lifecycle, factory splice, extreme one-sided paths, and exact factory
  negative failures remain required;
- cycle, byte, and proof-profile budgets remain active;
- the underlying Morph stateful assertion enforces fresh artifacts against the
  current Morph commit;
- Fiber external funding must pass on the same CKB devnet where Morph deployed
  and exercised its scripts.

The clean-worktree requirement is intentional. The underlying Morph
`devnet-stateful-assert` gate checks artifact freshness against the current
commit, so a production pass must be reproducible from a committed tree.

## Useful Environment Variables

```sh
FIBER_DIR=../fiber
CKB_SOURCE_DIR=../ckb
CKB_CLI_SOURCE_DIR=../ckb-cli
CKB_BIN=/absolute/path/to/ckb
CKB_CLI_BIN=/absolute/path/to/ckb-cli
FIBER_MORPH_ACCEPTANCE_MODE=coexistence
FIBER_TEST_ENV=debug
FIBER_BRUNO_SUITES="e2e/open-use-close-a-channel e2e/udt"
FIBER_FUNDING_TX_VERIFICATION_CASES="remove_change missing_inputs"
RUN_FIBER_RESTART_REGRESSION=0
BUILD_MORPH_CONTRACTS=0
```

`FIBER_BRUNO_SUITES` and `FIBER_FUNDING_TX_VERIFICATION_CASES` are useful for
local debugging. Production `fiber` and `full` audit runs expect the strict
default suite and case set above.

## Current Boundary

This gate proves same-devnet coexistence and strict scenario compatibility. It
does not claim that Morph factory rights are already Fiber public graph edges.
That remains a later protocol/backend integration step described in
`docs/fiber-integration-plan.md`.
