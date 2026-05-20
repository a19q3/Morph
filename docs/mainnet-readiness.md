# Mainnet Readiness

This repository remains devnet-first. The current implementation baseline is a
Devnet V1 release candidate, not a mainnet-ready or production-ready release. A
mainnet release candidate should not be cut until the items below have current
evidence from mainnet or a mainnet-like environment.

## P0 Release Blockers

### Challenge Window Evidence

- Measure mainnet confirmation latency for publication, supersession, splice,
  factory update, and finalisation transactions.
- Record the observed values used for:
  `detection_depth + poll_interval + build_time + confirmation_time + margin`.
- Publish a conservative default challenge policy and reject operator policies
  that fall below it.
- Include reorg handling assumptions and required confirmation depth in the
  release notes.

### Fee Market Safety

- Run fee stress tests where emergency publication fees rise during the
  challenge window.
- Verify sponsor rotation can rebuild a publication carrier with a fresh fee
  source without touching channel-owned value.
- Define operator alerts for low sponsor budget, repeated publication failure,
  and approaching challenge expiry.
- Keep per-transaction and proof-profile cycle/byte budgets in
  `docs/devnet-smoke-budget.example.json` aligned with measured mainnet fee
  assumptions.

### Watchtower Operations

- Exercise restart and cursor recovery after bilateral splice and factory splice
  transitions.
- Require funding-anchor-aware package selection, stale pre-splice package
  alerts, and persisted cursor metadata in smoke evidence.
- Document key custody, health-file monitoring, webhook delivery failure
  handling, and supervised restart expectations.
- Test at least two independent watchtower operators against the same channel
  package set before raising value limits.

## P1 Hardening

### xUDT Compatibility Matrix

- Test canonical xUDT plus representative mainnet xUDT variants with additional
  lock or type constraints.
- Include negative cases where total token supply is conserved but the Morph
  settlement descriptor, child vault amount, type hash, or participant-level
  allocation is wrong.
- Keep devnet-only issuer assumptions out of mainnet runbooks.

### Supply-Chain Gate

- `make supply-chain` must pass before release.
- `cargo audit` checks RustSec advisories against `Cargo.lock`.
- `cargo deny check` enforces allowed licenses, crate sources, and banned
  OpenSSL dependencies through `deny.toml`.
- Current `cargo audit` ignores are limited to transitive CKB dependency
  warnings for `paste` (`RUSTSEC-2024-0436`) and `rand 0.7`
  (`RUSTSEC-2026-0097`, the current rand advisory; `RUSTSEC-2020-0097` is an
  unrelated xcb advisory); remove them when upstream CKB crates update.
- New advisory ignores require a documented reason in the Makefile or
  `deny.toml`.

### Model Checking Slice

- Start with a small model for stale-state replacement, challenge expiry,
  splice funding epochs, and factory non-interference.
- Treat model checking as a supplement to the executable audit matrix, not a
  replacement for CKB-VM and devnet smoke evidence.

### Specification Sync

- Every protocol-level change must update the relevant spec surface before or
  alongside implementation:
  `schemas/morph.mol`, `docs/implementation.md`, `docs/roadmap.md`, and the
  executable audit matrix.
- If implementation intentionally leads the paper, the delta must be captured in
  a closeout document before external review.

## Deferred Beyond V1

- Generic descriptor runtime.
- Concurrent unconfirmed splice updates.
- Arbitrary splice-out payout locks without an explicit allowlist design.
- Multi-right or variable-depth reduced-signature proof bundles beyond the
  current fixed-width witnesses.
- Routing, gossip, path finding, and liquidity discovery.
