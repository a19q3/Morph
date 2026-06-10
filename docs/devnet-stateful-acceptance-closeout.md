# Devnet Stateful Production Scenario Acceptance

Status: historical devnet stateful acceptance evidence passed locally, including
the generalized audit profile and supply-chain gate. Contract boundary fixes
after this recorded run require a fresh clean `make devnet-stateful-e2e` artifact
before this closeout can be used as current release evidence again.

This is not a mainnet-ready or production real-assets-ready claim. The suite is
the devnet acceptance layer for production-shaped stateful lifecycles and
extreme cases. Mainnet fee-market evidence, reorg assumptions, external xUDT
compatibility, operational deployment practice, and value-limit policy remain
mainnet readiness gates.

## Scope

The stateful suite runs on a fresh real CKB devnet node and layers scenario
assertions over the existing on-chain smoke matrix. It records:

- long bilateral channel lifecycles, stale-state supersession, direct
  publication, and finalisation;
- sponsor fee boundaries, sponsor top-up/rotation, and finite script-level
  expiry rejection;
- CKB and xUDT splice-in/out paths, including asymmetric and one-sided
  settlement;
- factory all-participant updates, reduced-rights updates, sparse-Merkle
  updates, reduced exits, typed reduced exits, local child exits, and factory
  splices;
- watchtower auto-sponsor, direct sponsor, config-loop, service stop,
  health-file, cursor, and stale-splice-package behavior;
- negative attack-shaped cases with exact expected Morph script errors.

## Source Baseline

- Final committed baseline: `3814453`
- Artifact run-time commit: `17e1964`
- Working tree at run time: dirty because this stateful suite was under
  implementation before the final commit.
- The artifact records the implementation-in-progress state that produced the
  evidence. `17e1964` is therefore the run-time artifact commit, not the final
  committed baseline for this closeout.
- Stateful evidence artifact:
  `target/devnet-stateful-e2e/20260520T135931Z`
- Stateful scenario artifact:
  `target/devnet-stateful-e2e/20260520T135931Z/scenarios`
- Underlying smoke artifact:
  `target/devnet-stateful-e2e/20260520T135931Z/scenarios/smoke`
- Fresh standard devnet e2e artifact:
  `target/devnet-e2e/20260520T140603Z`

## Command Evidence

Required stateful evidence:

```sh
make devnet-stateful-e2e # passed
cargo run -p morph-cli -- devnet-stateful-report \
  --dir target/devnet-stateful-e2e/latest/scenarios \
  --audit-profile docs/devnet-audit-profile.example.json --json # passed
cargo run -p morph-cli -- devnet-stateful-assert \
  --dir target/devnet-stateful-e2e/latest/scenarios \
  --audit-profile docs/devnet-audit-profile.example.json \
  --budget-profile docs/devnet-stateful-budget.example.json # passed
```

Standard devnet and local gates:

```sh
cargo check --workspace --all-targets # passed
cargo test --workspace # passed
cargo clippy --workspace --all-targets -- -D warnings # passed
cargo fmt --all -- --check # passed
make fixture-checks # passed
make contract-tests # passed
git diff --check # passed
make devnet-e2e # passed
cargo run -p morph-cli -- devnet-smoke-report \
  --dir target/devnet-e2e/latest/smoke --json # passed
cargo run -p morph-cli -- devnet-smoke-assert \
  --dir target/devnet-e2e/latest/smoke \
  --budget-profile docs/devnet-smoke-budget.example.json --json # passed
```

Supply-chain status:

```sh
make supply-chain # passed
```

## Evidence Summary

- Stateful scenarios: 9 required, 9 present.
- Generalized audit families: 11 required, 11 passed.
- Unknown audit coverage tags: 0.
- Referenced artifacts: 81.
- Required committed checks: 44.
- Expected negative failures: 9.
- Underlying smoke transactions: 193 total, 192 committed, 1 expected
  competing-spend pending transaction.
- Expected script failures: 6.
- Watchtower alerts: 9.
- Factory reduced exits: 5.
- Factory splices: 32.
- Budget profile totals: 1,023,333,792 estimated cycles and 522,184 serialized
  bytes.

## Deployed Script Hashes

From `target/devnet-stateful-e2e/20260520T135931Z/scenarios/smoke/deploy-contracts.json`:

| Script | Data hash |
| --- | --- |
| `morph-state-lock` | `0x6aaa961106d9b7db144ba01146601fb4b854de96c1a8b3e42eba5070c51f0c88` |
| `morph-state-type` | `0x788db14916add38c9399eb41e5569d43a42c490f9f786ed4b7abf01d641e859a` |
| `morph-factory-type` | `0x8d5ee43a2db29e3a422dddf709653a26dec15f1669f428479e8a07fffe02eed4` |
| `morph-factory-vault-lock` | `0x4209317d0621db6d275641c4cf277c66c3051d3ff66ec553f8e5dc653f155caf` |
| `morph-vault-lock` | `0x62f8d3ef95bea4e6966a9c22e9c39942038fd376d61cb94a28cd1d32c5c8a3ee` |
| `morph-sponsor-lock` | `0x055db6d6085131fb6656cbccbe95afdb9c681adbee6174d0028799a084d44346` |
| `morph-devnet-xudt` | `0xeb56d956acdf44f0b70869154764d730208b3e273a24f2a4054c5277bd9157da` |

## Artifact Contract

`target/devnet-stateful-e2e/<run>/scenarios/` contains:

- `manifest.txt` with git, RPC, CKB, script, timing, and status metadata;
- one `morph.devnet_stateful_scenario` JSON file per required scenario;
- `smoke/`, the underlying real devnet smoke artifact tree;
- `summary.md`, `summary.json`, `summary-check.json`, and
  `summary-budget-check.json`.

The `` suffix on `morph.devnet_stateful_scenario` is only the scenario
artifact schema version. It is not a protocol or witness-version label. Current
factory authorisation is read through the bounded `WitnessEnvelope`
kind/body/digest envelope, and this historical closeout needs fresh rerun
evidence before it can serve as current release evidence again.

The assertion command fails unless every required scenario is present, every
referenced artifact exists, every required positive transaction is committed,
and every expected negative path records its exact Morph error.

## Remaining Mainnet Blockers

- Mainnet-like challenge-window latency and reorg evidence.
- Fee stress under publication, supersession, splice, factory update, and
  finalisation pressure.
- Multi-operator watchtower evidence outside a single local devnet.
- xUDT compatibility matrix beyond the devnet issuer.
- External diff review.
- Operational runbooks and value-limit policy.
