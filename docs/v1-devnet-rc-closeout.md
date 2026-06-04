# Devnet V1 RC Closeout

Status: historical Devnet V1 release-candidate evidence; superseded for current
readiness tracking by the V2 non-fixed factory witness work.

This is not a mainnet-ready or production real-assets-ready claim. Mainnet-like
challenge-window evidence, fee stress, supply-chain revalidation in release CI,
external diff review, operational runbooks, multi-operator watchtower evidence,
and value-limit policy remain release gates before raising asset limits.

## Supersession Note

The evidence below remains useful as a frozen V1 devnet release-candidate record
for commit `4ca867c`. It must not be read as the current implementation design
or as current release evidence.

The current post-V1 line is commit `a2059ba` on
`arthur/v2-final-nonfixed-witness`. That line removes the factory contracts'
fixed-width raw witness dispatch as the public authorisation boundary and
replaces it with a bounded `WitnessEnvelopeV2` header:

- witness kind selects the factory authorisation path;
- body length is bounded per kind instead of inferred from one global raw
  witness size;
- the body digest commits the envelope to the decoded authorisation payload;
- V1-style body names, such as reduced exit and splice, remain as historical
  body schemas rather than as the top-level dispatch contract.

Therefore the V1 limitations and script hashes below are deliberately retained
as historical evidence, but design decisions for the next mature version should
be taken from the V2 implementation and current roadmap documents.

## Source Baseline

- Implementation/evidence commit: `4ca867c`
- Previous safety-kernel baseline: `5fb7494`
- Evidence artifact: `target/devnet-e2e/20260520T100401Z`
- Smoke artifact: `target/devnet-e2e/20260520T100401Z/smoke`
- Manifest: `git_commit=4ca867c`, `git_dirty=false`, `status=passed`

## Command Evidence

- `make test`: passed.
- `make lint`: passed.
- `make fmt-check`: passed.
- `make fixture-checks`: passed.
- `make contract-tests`: passed.
- `git diff --check`: passed.
- `CARGO_HTTP_TIMEOUT=60 make supply-chain`: passed.
- `make devnet-e2e`: passed.
- `cargo run -p morph-cli -- devnet-smoke-report --dir target/devnet-e2e/latest/smoke --json`: passed.
- `cargo run -p morph-cli -- devnet-smoke-assert --dir target/devnet-e2e/latest/smoke --budget-profile docs/devnet-smoke-budget.example.json`: passed.
- `cargo run -p morph-cli -- devnet-smoke-compare --baseline target/devnet-e2e/m6-business-matrix-final-20260513T100822Z/smoke --candidate target/devnet-e2e/latest/smoke --fail-on-status-change`: passed; transaction-set changes are expected because xUDT reduced-exit smoke names were restored.

## Devnet Evidence Summary

- Smoke JSON files: 155.
- Transactions recorded: 193 total, 192 committed, 1 pending competing-spend transaction.
- Expected script failures: 6.
- Deployed scripts: 7, with local binary hashes verified by smoke assertions.
- Watchtower alerts: 9 total, including 3 publication alerts.
- Factory proof profiles: 25.
- Factory reduced exits: 5 total:
  - 2 CKB reduced exits.
  - 3 xUDT reduced exits: partial typed FactoryVault change, full release with CKB-only change, and one-sided child settlement.
- xUDT reduced-exit negative smoke rejects child token amount mismatch while FactoryVault change preserves total token supply.

## Deployed Script Hashes

From `target/devnet-e2e/20260520T100401Z/smoke/deploy-contracts.json`:

| Script | Data hash |
| --- | --- |
| `morph-state-lock` | `0x6aaa961106d9b7db144ba01146601fb4b854de96c1a8b3e42eba5070c51f0c88` |
| `morph-state-type` | `0x85fd432c8579f5a9ecf621b3f3387fa97058feea893be38fceb885f1c11ea743` |
| `morph-factory-type` | `0x502a17936689d72fcebf5aac07254f3fcb88bd67611a7585b004207c8e7c0adb` |
| `morph-factory-vault-lock` | `0x056b52e87c3de05c4e6848bea8d9460be27a3dc3a9abd3ff56939890121aa107` |
| `morph-vault-lock` | `0x014106adcd8b521ff7a092b6811bdf2a3b1be8c1c03e009a740962486ca91a11` |
| `morph-sponsor-lock` | `0x03be40d311b8fc6b592f51a6141f733e4998cd82250a10505976f3fd2c83e1f5` |
| `morph-devnet-xudt` | `0xeb56d956acdf44f0b70869154764d730208b3e273a24f2a4054c5277bd9157da` |

## Boundary Changes Closed

### xUDT Reduced-Exit Devnet Restoration

- Issue: xUDT reduced-exit was contract/CKB-VM active but devnet smoke coverage
  was not active.
- Attack model: typed `ReserveClaim` release could regress in CLI/devnet wiring
  without a full devnet artifact catching child amount, type hash, or typed
  FactoryVault change mismatches.
- Fix: restored typed reduced-exit devnet builder, active partial/full/one-sided
  smokes, negative child-token mismatch smoke, report assertions, and budget
  proof profiles.
- Negative test: `factory-reduced-xudt-negative-exit-smoke` expects
  `SettlementOutputMismatch`.
- Remaining limitation: no generic descriptor runtime, no multi-right reduced
  proof, and no variable-depth proof in V1. The later V2 witness envelope
  addresses fixed-width top-level factory dispatch, not these historical V1
  proof-model limitations by itself.

### Relative Since Devnet Maturity

- Issue: finalise smokes could rely on transaction-commit mining instead of
  explicitly waiting out the relative block challenge window.
- Attack model: strict relative-since validation can reject otherwise valid
  finalise transactions as immature, hiding the script boundary actually under
  test.
- Fix: finalise helpers mine the relative maturity window before sending
  finalise transactions. xUDT negative finalise smoke matures before testing the
  descriptor mismatch.
- Negative test: `finalise-since-negative-smoke` still rejects under-specified
  input since with `StateSinceNotMature`.
- Remaining limitation: mainnet challenge-window sizing still requires
  mainnet-like latency and reorg evidence.

### Devnet Splice-Out Capacity Defaults

- Issue: the default plain CKB splice-out smoke used an initial Vault capacity
  that could not satisfy both the withdrawal output occupied capacity and the
  post-splice Vault occupied capacity.
- Attack model: readiness smoke could fail for parameter-budget reasons unrelated
  to protocol safety.
- Fix: the default plain `splice-out-smoke` capacity budget now leaves both
  outputs above occupied capacity.
- Negative test: splice negative smoke remains active for malformed and
  mismatched splice packages.
- Remaining limitation: production value limits need separate fee-market and
  occupied-capacity policy.

## Remaining Mainnet Blockers

- Mainnet-like challenge-window evidence and conservative default policy.
- Fee stress across publication, supersession, splice, factory update, and
  finalisation flows.
- Supply-chain gate in release CI with a known-good advisory DB path.
- External diff review of `4ca867c`.
- Multi-operator watchtower recovery and alerting evidence.
- xUDT compatibility matrix beyond the devnet issuer.
- Operational runbook for key custody, health checks, restart, and incident
  response.
- Explicit value-limit policy before any real-assets deployment.
