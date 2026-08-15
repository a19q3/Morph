# Changelog

## v1.11.0 — 2026-08-15

### Publication verification follow-up

- Fail closed if rebuilding the initial publication carrier changes its final
  serialized size without converging to the fee selected from the observed fee
  market. The controller now verifies both the exact recomputed fee and the
  final effective fee rate before broadcast.
- Clarify that the deterministic private-key environment probe exercises the
  same key-scrubbing launch wrapper used by every harness watcher process; it
  does not introspect the watcher binary after launch.
- Align the host crates, Fiber adapter, TypeScript SDK, Morph Hub frontend, and
  their lockfiles at v1.11.0; the Hub displays its package version in the
  operator console.
- Preserve the controlled-devnet and production-measurement boundaries from
  v1.10.0. No CKB contract source or wire-format change is included.

## v1.10.0 — 2026-08-15

Publication Reliability Hardening for the controlled-devnet Morph Channel
prototype.

### Security and reliability

- Added a bounded fee and RBF publication controller that observes the live CKB
  fee market, learns structured node replacement floors, and fails closed at
  operator and SponsorPolicy caps.
- Added an absolute challenge deadline that deducts already-consumed
  confirmations and reserves canonical-confirmation, reorg, failover, and
  safety blocks.
- Made Pending, Proposed, Committed, Rejected, and Unknown explicit states;
  watcher completion now requires configured canonical depth.
- Added canonical reconciliation for restarts, mempool eviction, duplicate
  broadcast, replacement races, and induced reorganisation.
- Isolated deployer, participant, and independent operator keys into disjoint
  subprocess environments.
- Serialized attempt-log append and torn-tail recovery with a shared durable
  file lock.
- Bounded publication-critical RPC response bodies and diagnostic excerpts.
- Made production reliability assessment fail closed without trusted external
  measurement provenance.

### Operations and evidence

- Added path-aware multi-channel watchtower preflight and operator/profile/log
  binding.
- Added a deterministic devnet reliability harness covering live fee rejection,
  real RBF, two-operator failover, pool eviction, duplicate submission,
  SponsorPolicy rejection, canonical reorg recovery, and signed-package byte
  identity across branches.
- Added architecture, implementation, parent-source comparison, production
  gates, and completion-audit documentation under
  `docs/hardening/production-publication-reliability/`.

### Release boundary

The seven CKB contract sources and wire formats are unchanged by this
host/watchtower hardening release; their crate version remains `0.1.0`. Their
reviewed ELF Data Hashes are refreshed once because the release build now remaps
machine-specific source paths and rejects restored-target contamination. The
resulting hashes are stable across local and GitHub runners but require a fresh
devnet deployment.

v1.10.0 remains controlled-devnet research software. It is not approved for
mainnet or real assets. Trusted public-network measurements, independently
administered operator infrastructure, external review, and a dated value-limit
decision remain mandatory production gates.
