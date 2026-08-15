# Morph v1.10.0 publication reliability hardening

Status: implemented and locally devnet-verified; production evidence gates remain open
Decision: no signed-state, witness-envelope, or contract wire-format change

## Executive decision

Morph v1.10.0 must treat fee selection, challenge-window sizing, reorg recovery,
watchtower independence, and mempool contention as release gates. Fiber does not
currently close these gaps for Morph, and Morph must not inherit Fiber's fixed
fee or single-endpoint assumptions.

The recommended design preserves Morph's strongest architectural property:
participants sign state evidence, while operators rebuild the carrier
transaction. The implementation therefore belongs in the host publication and
watchtower control plane. Contract policy remains the final fee/budget boundary.

The v1.10.0 readiness claim is intentionally split:

- **Protocol/devnet v1.10.0:** allowed after deterministic and repeated devnet gates
  pass, under the existing no-real-assets envelope.
- **Production real-assets profile:** remains blocked until sufficient public
  network measurements, two genuinely independent operator rehearsals, external
  review, and a dated value-limit decision exist.

## What Jan's review changes

Jan correctly identified that a newer-state-wins protocol moves risk from
slashing mistakes into liveness engineering: sponsor exhaustion, griefing,
watchtower reliability, fee volatility, and challenge-window sizing become core
security concerns rather than optional operations work.

The RBF wording also needs precision. CKB supports transaction-pool RBF when
`min_rbf_rate > min_fee_rate`. A replacement Morph carrier transaction shares
the contested StateCell input with the pending carrier and may use a different
SponsorCell. The participant-signed State Header does not change. This is not a
Lightning-style family of pre-signed fee-bump transactions, but it is still CKB
RBF and must satisfy CKB's replacement rules, including the node-reported
minimum replacement fee.

The stable integration identity remains `channel_id`; funding context is
identified by the signed anchor/vault commitment and exposed to tooling through
`funding_context_id` and the current signed `funding_epoch`. No change to those
fields is required for this reliability work.

## Comparison with parent CKB and Fiber

See [`parent-comparison.md`](parent-comparison.md) for the commit-pinned,
line-by-line source mapping.

| Concern | Parent CKB | Fiber at reviewed baseline | Morph before this work | Morph v1.10.0 requirement |
| --- | --- | --- | --- | --- |
| Fee pressure | `estimate_fee_rate`, confirmed mean/median, tx-pool floor | 1000 shannons/KB defaults; watch paths also construct calculators at 1000 | fixed absolute fee | node-informed bounded rate and durable evidence |
| RBF | enabled when `min_rbf_rate > min_fee_rate`; pending tx exposes `min_replace_fee` | messages exist in schema, handlers warn unsupported | conflict rejection only | actual replacement, min-replace-fee aware |
| Reorg | IntegrationTest `truncate`; canonical block APIs | confirmation tracer, no durable cursor rollback found | durable cursor hash reset/rescan exists | induced truncate/alternate-chain rehearsal |
| Delay | block and tx status APIs | bounded protocol delay but no measured end-to-end window | configured poll/depth/timeouts | measured latency budget and release gate |
| Watchtowers | neutral base-layer support | built-in plus one optional standalone URL; best-effort event forwarding | one process may serve channels; local evidence | two operator identities and failure domains |

Fiber can remain an integration peer, but it is not the security boundary for
these properties. In particular, its `TxInitRBF` / `TxAckRBF` wire types do not
mean the channel actor implements RBF, and one optional standalone endpoint is
not evidence of two durable independent operators.

## Security invariants

1. **Evidence immutability.** Fee attempts never alter signed State Header or
   participant witness bytes.
2. **Latest-state safety.** A controller publishes only a package newer than the
   canonical StateCell. A state already equal/newer is idempotent success or
   obsolescence.
3. **Bounded fee authority.** The selected fee is bounded simultaneously by the
   node floor, operator profile, SponsorPolicy per-tx cap, remaining total budget,
   and occupied-capacity-safe change.
4. **Canonical reconciliation.** RPC submission errors and rejected/unknown
   transaction statuses are reconciled against the live canonical StateCell.
   A canonical-live stale StateCell retained in the cursor forces a floor rescan
   even without a chain reorganisation, so mempool eviction cannot strand an
   intent behind an already-advanced scan cursor.
5. **Least privilege.** Watchtower package publication needs no Alice/Bob private
   key. Participant signing remains offline/outside the operator runtime.
6. **Independent operation.** A production deployment uses distinct identifiers,
   sponsor budgets, cursors, stores, alerts, health files, RPC endpoints, hosts,
   and administrative principals. The deterministic local harness proves only
   the first four and process-level key separation on one host and one RPC.
7. **Observable attempts.** Every fee attempt has a stable intent id and a
   durable, secret-free record.
8. **Measured deadline.** A production challenge window must dominate measured
   end-to-end latency plus confirmation, reorg, failover, and safety budgets.

## PUB-01: bounded fee and RBF controller

### Initial fee selection

For a serialized carrier size `s` bytes, collect:

- node tx-pool `min_fee_rate`;
- node `estimate_fee_rate(..., fallback=true)`;
- confirmed-block mean/median as evidence and a fallback signal;
- the operator's configured minimum rate.

Apply the configured estimator multiplier in basis points and choose the maximum
of the resulting floors. Cap it at the operator maximum. Convert rate to fee
using integer ceiling:

```text
fee(rate, s) = ceil(rate * s / 1000)
```

Build once to learn the exact serialized size, recompute the fee, and rebuild.
Because the relevant witnesses have fixed length, a second pass must converge;
the implementation still verifies the final effective rate.

### Replacement

If an accepted transaction remains pending past the bump interval:

1. read its status with verbosity 2;
2. if committed, verify its block is canonical and wait for the configured
   canonical depth before reporting terminal success;
3. if pending, choose at least its `min_replace_fee`;
4. otherwise choose at least both the configured bump and
   `old_fee + fee(min_rbf_rate, replacement_size)`;
5. rebuild from the same signed evidence and live snapshot retained by the
   intent, then submit;
6. reconcile rejected/unknown outcomes against canonical state.

If a different operator's conflicting transaction is already pending, its hash
and aggregate conflict fee may be unknown. The controller treats CKB's first
`PoolRejectedRBF` response as an authoritative price discovery result. It first
requires the stable JSON-RPC code `-1111`, then parses the required fee from the
parent CKB implementation's response, records the rejection, and retries only
when the profile has another attempt and the required fee remains under every
cap. If the code is not `-1111` or the required amount cannot be decoded, it
fails closed instead of guessing a replacement price.

No attempt may cross any script or operator cap. Exhausting the cap is a critical
alert and a release-profile failure, not permission to borrow from channel value.
Profile validation requires the complete bump-delay ladder to fit strictly
inside the latency portion of the window. At runtime, confirmations already
consumed by the observed stale StateCell are deducted, as are the configured
reorg, failover, and safety reserves. Publication starts only when more than the
configured canonical-confirmation depth remains; every retry, sleep, and
confirmation wait shares that absolute deadline.

### Attempt record

Each JSONL record contains schema/version, operator id, intent id, channel/funding
context, target state number, attempt number, the complete fee observation,
fee/rate/size, tx hash, known predecessor tx hash, node replacement floor,
status, canonical tip, elapsed time, and a sanitized error classification.
Records are appended under an exclusive file lock after each observed submission
or status transition. Startup reconciliation re-queries every latest hash and
appends confirmed, shallow-committed, rejected, pending, proposed, or unknown
outcomes without rewriting history. A shallow commit is not counted as a
publication until the configured canonical depth is observed.
An HTTP timeout or duplicate response is not treated as rejection: the
controller first queries the locally known transaction hash and continues as an
accepted submission when it is pending, proposed, or committed. An outcome that
cannot be queried is recorded as `submission_unknown` for later reconciliation.
Each record is issued as one append and synced. A valid unterminated final
record is newline-normalised; an invalid torn final record is copied to a
timestamped, mode-0600 forensic sidecar before only those trailing bytes are
removed. Corruption in any completed line still fails closed. The recovery is
reported in the watch result rather than being silent.
The implementation fails closed at a 64 MiB log boundary; operators must rotate
and archive attempt logs rather than allow unbounded restart-time memory use.

## PUB-02: challenge-window measurement

Use end-to-end samples, not isolated RPC latency. Each sample begins when an
adversarial StateCell becomes observable at the operator's RPC and ends when the
newer state has the required canonical depth. Record these components:

```text
detection + package selection + build/verify + queue delay
+ rebroadcast/RBF + proposal/commit + canonical confirmations
+ reorg recovery + operator failover
```

The production recommendation is:

```text
Wmin = ceil(P99.9(end-to-end milliseconds) / conservative_block_ms)
     + reorg_budget_blocks
     + confirmation_blocks
     + failover_budget_blocks
     + safety_margin_blocks
```

Use nearest-rank P99.9. Require at least 1000 fresh samples overall and at least
1000 samples in each exact fault family `ordinary_load`, `fee_pressure`,
`rpc_delay`, `operator_failover`, and `induced_reorg`. A sample may carry more
than one label only when those faults were actually active together. Compute an
overall P99.9 and a P99.9 for each required family; use their maximum in `Wmin`
so a rare high-latency reorg or failover cannot be diluted by ordinary samples.
Devnet may exercise the calculator with fewer samples but the report must mark
it non-production. The production validator additionally requires a public CKB
network identity, an RBF-enabled profile, distinct serialized samples, non-zero
measured build and confirmation components, fault-labelled component evidence,
and an operator-supplied SHA-256 digest of the exact dataset bytes. It fails
closed for missing, stale, duplicated, synthetic-zero, or undersized datasets, a
profile-digest or genesis mismatch, missing fault-family coverage, and when the
profile window is not exactly represented by the canonical live StateCell's
deployed `finalise_since` or is below `Wmin`.

Deployment binding is not inferred from an arbitrary typed cell. The assessor
hashes the exact local RISC-V ELFs, resolves their live deployment, requires the
candidate to use that `morph-state-type`, verifies its type-bound
`morph-state-lock`, parses the StateHeader, and matches the header's funding
anchor to the first 32 Type-args bytes before reading canonical relative-block
`finalise_since`.

The measurement output must include network/genesis identity, CKB version,
profile digest, sample time range, sample count, percentiles, maxima, injected
fault labels, and the resulting minimum window.

The assessor compares network, genesis, and the exact RPC-reported CKB version
with the connected node. It bounds input size/count, validates hexadecimal
identities and sample timestamps/components, and computes freshness from every
sample end time as well as the dataset generation time. A recently rewritten
dataset therefore cannot disguise stale observations.

The digest and structural checks bind the decision to exact bytes; they do not
authenticate who collected them or prove independent infrastructure. Production
still requires externally verified operator receipts and measurement provenance.
Until a trusted receipt verifier is implemented, local `--production`
assessments deliberately report `production_provenance_verified: false` and
cannot pass, even when every structural and statistical check succeeds.

## PUB-03: induced reorg and delay

The deterministic devnet scenario is:

1. create and activate a channel; save the latest signed package;
2. observe a stale state and persist a hash-bound cursor;
3. delay the watcher's RPC view or watcher start by a bounded injected interval;
4. publish/confirm, record the committed block, then use IntegrationTest
   `truncate` on that block's parent so the publication itself is orphaned;
5. clear detached pool replay in the harness, rerun the watcher from retained
   evidence, and mine an alternate branch;
6. require a critical reorg alert, context clear, rescan from the configured
   floor, and canonical outcome reconciliation;
7. require the latest valid state to be rebuilt, commit again, and be reconciled
   in the attempt log when the canonical state is older; an already-landed
   canonical state is instead reported idempotently.

Production does not expose `truncate`; it reuses the same detector against real
canonical hashes. Fault-injection controls are devnet-only.

## PUB-04: two watchtower operators

Two processes on one host are useful for deterministic devnet tests but do not
constitute production independence. The production topology requires:

- different administrative principals and hosts/regions;
- different CKB RPC providers and network paths;
- separately funded SponsorCells with disjoint budgets;
- independent encrypted package stores and retention policies;
- independent cursor, attempt, alert, and health sinks;
- no shared participant private key material;
- periodic cross-checks that both operators hold the same latest package digest.

There is deliberately no on-chain leader election. Both may race safely because
the StateCell is single-spend and a state-number comparison makes duplicate work
idempotent. The operational goal is independent success, not mutual exclusion.

For explicit pre-funded SponsorCells, publication requires only the signed state
package and enough public information to construct the policy-mandated clean
change output. Automatic sponsor funding is a separate privileged role and may
use an operator funding key; it must not pull participant keys into the watcher.

## PUB-05: adversarial mempool matrix

The devnet gate configures non-trivial `min_fee_rate` and a larger
`min_rbf_rate`, then proves:

1. a carrier below the pool floor is rejected;
2. a valid carrier enters pending state without mining;
3. a same-input replacement below `min_replace_fee` is rejected;
4. a replacement at/above `min_replace_fee` is accepted;
5. the old transaction becomes `Rejected` with `RBFRejected` and the replacement
   commits;
6. a newer-state carrier from the second operator can safely win contention;
7. sponsor caps stop an unaffordable bump before broadcast;
8. restart/rebroadcast and duplicate requests converge on canonical state.

The report records the node pool policy, both operators' complete attempt arrays,
transaction hashes/fees/sizes, the learned replacement floor, expected
rejections, committed state number, measured component timings, operator
identities, the runtime deadline budget, immutable signed-evidence checks,
watcher-environment probe, dataset digest, and source/binary hashes.

The deterministic implementation is
`scripts/devnet-publication-reliability.sh`. A passing run is written under
`target/devnet-publication-reliability/<run>/evidence/report.json`; one such
local sample validates the control paths but deliberately reports
`production_measurement_sufficient: false`.

## Release gates

Protocol/devnet v1.10.0 requires all unit/invariant/contract tests, the existing
stateful matrix, and the new reliability smoke to pass with an archived report.
It must continue to say no real assets.

A production real-assets profile additionally requires:

- at least 1000 fresh measurement samples overall and per required fault family,
  with stratified P99.9 computation;
- repeated fee-pressure and reorg runs on a public test network;
- two independently administered operator receipts;
- sponsor budget sized from the measured worst-case attempt ladder;
- an external review of controller/config/runbook behavior;
- a dated value limit and incident/rollback decision.

No CI/CD work is part of this change. These gates are local commands and
operator evidence until a separate authorization adds automation.

## Residual risks

- RBF is local node policy and relay propagation can differ across peers.
- Fee estimators are historical/model-based and may underpredict sudden demand.
- Two operators can still share correlated infrastructure unknowingly.
- A challenge window cannot remove deep-reorg or prolonged-partition risk; it
  only makes the assumed risk budget explicit.
- Sponsor exhaustion remains a denial-of-service boundary even though channel
  value is protected.
- Devnet timing is not representative of public PoW block production.

These risks are addressed through explicit caps, production-independent
RPC/operator paths, canonical reconciliation, retained packages, measurement
freshness, and an honest release label rather than by weakening protocol
invariants. The local harness must not be cited as proof of host/RPC independence.
