# Roadmap

## M0: Protocol Semantics

Status: implemented.

- State header signing domain.
- State transition monotonicity.
- Funding-anchor binding.
- Sponsor policy bounds.
- Vault finalisation conditions.
- Partition conservation across reserve, business CKB, xUDT, and sponsor cells.

## M1: Devnet Bilateral Channel

Status: implemented for the bilateral CKB-only path and the devnet CKB+xUDT
settlement path. The five script ELFs build, offline CKB-VM tests cover
state-lock delegation, state publication, stale-state rejection, invalid state
signatures, state-bound sponsor fees, descriptor-bound vault finalisation,
descriptor-output mismatch rejection, and devnet xUDT conservation. The CLI can
check/mine a local CKB devnet, deploy the Morph contract binaries, open a
channel, publish a signed settling state, top up sponsor capacity, publish a
newer signed state over the old settling state, finalise the vault, and run a
competing-spend smoke, a finalise-since negative smoke, a sponsor-budget
negative smoke, a CKB+xUDT settlement smoke, and a tampered-settlement xUDT
negative smoke through native JSON-RPC. Each transaction report includes
node-estimated cycles and serialized transaction size. SponsorCells can carry
explicit state-number and fee-budget bounds. Smoke runs also produce Markdown
and machine-readable benchmark summaries from the collected transaction
reports.

Required deliverables:

- Fixed-width V1 wire types, later replaced or generated from Molecule.
- Draft Molecule schema covering all active devnet V1 wire objects.
- `morph-state-lock` contract.
- `morph-state-type` contract.
- `morph-vault-lock` contract.
- `morph-sponsor-lock` contract.
- `morph-devnet-xudt` contract.
- Native devnet RPC check/mine/wait commands.
- Devnet contract deployment transaction.
- RPC transaction builder.
- Publish, supersede, and finalise devnet path.
- Per-transaction cycle and size reporting from the devnet node.
- Devnet smoke summary report for cycle, size, status, and expected script
  failure review.
- Configurable SponsorCell state-number and fee-budget policy.

Acceptance criteria:

- a canonical StateCell is created from the funding input and output index;
- a newer signed state can replace the active StateCell and enter settling;
- a newer signed state can replace an already settling StateCell;
- finalisation before the required relative `since` is rejected on devnet, then
  succeeds after explicit maturity blocks;
- sponsor capacity pays publication fees without touching vault value;
- finalisation consumes the settling StateCell and vault, then materialises the
  descriptor outputs;
- channel reserve cannot pay publication fees;
- sponsor policy cannot spend outside its budget;
- sponsor policy rejects publication outside its state-number range;
- a devnet SponsorCell with a too-low fee cap is rejected, then a fresh
  SponsorCell can publish the same state with a sufficient cap;
- xUDT type mismatch is rejected in host-side invariants;
- a devnet CKB+xUDT channel can open, publish, and finalise with exact token
  conservation;
- a devnet CKB+xUDT channel rejects a tampered recipient-level token
  distribution even when total token supply is unchanged.
- a competing publication against an already pending StateCell spend is
  rejected by the node's tx-pool-aware live-cell view, then the newer state can
  be rebuilt against the confirmed live StateCell.
- JSON devnet reports expose `estimated_cycles` and `tx_size_bytes` for every
  lifecycle transaction.
- completed smoke directories can be summarised into `summary.md` and
  `summary.json`.

## M2: Watchtower

Status: partially implemented for durable state package persistence, latest
package selection, publish-from-latest-package rebuilding, confirmation-depth
block polling, persisted scan cursors, and conservative auto-funded sponsor
rotation. Broader operator policy and alerting remain open.

- State package persistence.
- Detection-depth polling.
- Rebuild publication carrier with fresh sponsor inputs.
- Emergency fee budget policy.
- Persisted scan cursor.
- Conservative auto-funded SponsorCell rotation.

## M3: Conservative Factory Mode

- Factory state roots and access manifest.
- Full-participant signature mode.
- Local exit without reduced signing set.

## M4: Reduced-Signature Factory Mode

This remains blocked until a formal rights-dependency proof predicate exists.
