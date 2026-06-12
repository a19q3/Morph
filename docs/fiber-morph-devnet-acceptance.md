# Fiber/Morph Devnet Acceptance

This document defines the cross-repository devnet acceptance gate for running
Fiber and Morph against the same local CKB devnet.

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

Runs the extended Fiber suite set without Morph's stateful matrix.

### `full`

Runs `coexistence`, then starts fresh Fiber devnets for the extended Fiber
suites listed in `FIBER_BRUNO_SUITES`.

Default extended suites:

```text
e2e/open-use-close-a-channel
e2e/3-nodes-transfer
e2e/udt
e2e/udt-router-pay
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

Every `coexistence` and `full` run now executes
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
- `e2e/udt`
- `e2e/udt-router-pay`

The generated `business-flow-audit.json` records these named flows, their
evidence files, the security families, and the minimum Morph evidence floors
for committed transactions, factory exits, factory splices, watchtower alerts,
expected failures, and referenced artefacts.

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
RUN_FIBER_RESTART_REGRESSION=0
BUILD_MORPH_CONTRACTS=0
```

## Current Boundary

This gate proves same-devnet coexistence and strict scenario compatibility. It
does not claim that Morph factory rights are already Fiber public graph edges.
That remains a later protocol/backend integration step described in
`docs/fiber-integration-plan.md`.
