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

The script is also directly callable:

```sh
scripts/fiber-morph-devnet-acceptance.sh preflight
scripts/fiber-morph-devnet-acceptance.sh coexistence
scripts/fiber-morph-devnet-acceptance.sh full
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
- `summary.json`: top-level pass summary;
- `logs/`: Fiber stack logs, Morph stateful logs, Bruno logs, and build logs;
- `morph-stateful/scenarios/`: Morph stateful scenario and smoke artifacts.

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
