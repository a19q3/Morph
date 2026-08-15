# Completion audit: production publication reliability

Date: 2026-08-15
Release: `v1.10.0`
Morph base: `790bf1c18a55b1186669a3833c5fcf7dd17177c1`
CKB comparison: `82c0bb640f406c9f7d5395157073005c7e583c89`
Fiber comparison: `de9071a3601ea6a3b8853d53b9f2f67184cab9a7`

## Objective coverage

| Requested outcome | Delivered evidence | Result |
| --- | --- | --- |
| Detailed solution in Markdown | `hardening.md`, `diagram.md`, `implementation-plan.md`, and the implementation contract | Complete |
| Compare with parent CKB/Fiber source | `parent-comparison.md`, pinned to exact sibling-repository commits and source locations | Complete |
| Implement the design | Bounded fee/RBF controller, deadline and confirmation-depth state machine, locked durable reconciliation, least-privilege watcher, production dataset controls, and devnet harness | Complete for the repository's devnet scope |
| Do not modify CI/CD | No path under `.github/` is changed; the shared contract build command now produces the same remapped ELF locally and in CI | Complete |
| Verify on devnet | Fresh release run `v1.10.0-release-final-r2` passed | Complete |
| Production-grade boundary | Local controls fail closed; the local harness is explicitly not proof of independent production infrastructure or sample provenance | External production evidence remains required |

## Fresh devnet evidence

Canonical report:
`target/devnet-publication-reliability/v1.10.0-release-final-r2/evidence/report.json`

The report binds the Git revision, complete tracked/untracked working-tree
content, CLI binary, harness, seven-contract ELF set, and exact dataset bytes by
SHA-256. The run proves:

- CKB advertised a non-trivial fee floor and a larger RBF floor;
- below-floor and over-cap attempts failed without consuming the SponsorCell;
- participant keys were absent from watcher processes, and operator A/B signing
  keys were asserted distinct before use;
- the key-scrubbing wrapper used for every watcher launch was exercised through
  a child environment probe, which verified that all four private-key variables
  were absent at that launch boundary;
- each watcher received only its own operator key while builds received no key;
- the operators used distinct identities, SponsorCells, stores, cursors,
  profiles, and attempt logs;
- B's first attempt recorded `rbf_fee_too_low` and CKB's numeric replacement
  floor, then attempt 2 replaced A;
- node `Rejected`/`Unknown` states were non-terminal and reconciled against the
  canonical chain;
- both the original winning publication and the alternate-branch republication
  were recorded as `confirmed` only after the configured canonical depth;
- their StateHeader output data and participant witness were byte-identical to
  the retained signed package;
- pool eviction forced a floor rescan and duplicate rebroadcast converged;
- IntegrationTest `truncate` invalidated the cursor and retained evidence was
  republished on a different canonical block;
- measured, non-zero timing components summed within end-to-end time;
- the deployed 40-block window preserved reorg/failover/safety reserves after
  deducting the stale StateCell's already-consumed confirmations;
- the dataset digest matched exact bytes, while the one-sample devnet dataset
  failed the production gate for public-network and sample-count requirements.

This remains a co-located test: both operator processes share one host, one
loopback RPC, and the harness does not instantiate independent health/alert
sinks. Those properties are production deployment gates, not local evidence.

## Parent comparison conclusions

- Morph uses CKB's actual RBF enablement rule and replacement-fee calculation,
  including the pending transaction's `min_replace_fee` and structured `-1111`
  rejection for an unknown competing transaction.
- Fiber's reviewed schema declares `TxInitRBF` and `TxAckRBF`, but its channel
  actor explicitly treats both as unsupported.
- Fiber's reviewed watchtower builders still construct a fixed rate of 1000,
  and its built-in plus optional standalone forwarding does not establish two
  independently administered Morph operators.
- Fiber therefore remains an integration peer, not the security boundary for
  Morph publication liveness.

## Deliberately open production gates

Real-assets production remains blocked until there are at least 1000 fresh,
distinct public-network samples overall and for each required fault family,
signed/externally verifiable collection provenance, repeated public-network
fee/reorg exercises, two independently administered operator receipts, external
review, sponsor-budget sizing from the measured attempt ladder, and a dated
value-limit decision. A caller-supplied dataset SHA-256 binds exact bytes but
does not prove who collected them or where.

## Verification record

- `cargo test -p morph-cli --features devnet`: 217 passed.
- `scripts/devnet-publication-reliability.sh`: passed as
  `v1.10.0-release-final-r2`, including canonical-depth, immutable-evidence,
  environment-isolation, deadline-reserve, and trusted-provenance assertions.
- Repeated fresh-target contract builds produced the same path-remapped ELF set;
  all seven artifacts matched the reviewed manifest.
- `make ci AUDIT='cargo audit --no-fetch'`: passed, including formatting,
  clippy with warnings denied, source hygiene, RustSec/deny checks, all workspace
  tests, fixture checks, SDK/UI checks, 125 CKB-VM contract tests, contract
  manifest verification, and release-readiness checks.
- `git diff --check`: passed.
