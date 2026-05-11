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

Status: implemented for the bilateral CKB-only path. The four script ELFs
build, offline CKB-VM tests cover state-lock delegation, state publication,
stale-state rejection, invalid state signatures, state-bound sponsor fees,
descriptor-bound vault finalisation, and descriptor-output mismatch rejection.
The CLI can check/mine a local CKB devnet, deploy the Morph contract binaries,
open a channel, publish a signed settling state, top up sponsor capacity,
publish a newer signed state over the old settling state, and finalise the
vault through native JSON-RPC. Each transaction report includes node-estimated
cycles and serialized transaction size.

Required deliverables:

- Fixed-width V1 wire types, later replaced or generated from Molecule.
- `morph-state-lock` contract.
- `morph-state-type` contract.
- `morph-vault-lock` contract.
- `morph-sponsor-lock` contract.
- Native devnet RPC check/mine/wait commands.
- Devnet contract deployment transaction.
- RPC transaction builder.
- Publish, supersede, and finalise devnet path.
- Per-transaction cycle and size reporting from the devnet node.

Acceptance criteria:

- a canonical StateCell is created from the funding input and output index;
- a newer signed state can replace the active StateCell and enter settling;
- a newer signed state can replace an already settling StateCell;
- sponsor capacity pays publication fees without touching vault value;
- finalisation consumes the settling StateCell and vault, then materialises the
  descriptor outputs;
- channel reserve cannot pay publication fees;
- sponsor policy cannot spend outside its budget;
- xUDT type mismatch is rejected in host-side invariants.
- JSON devnet reports expose `estimated_cycles` and `tx_size_bytes` for every
  lifecycle transaction.

## M2: Watchtower

Status: partially implemented for durable state package persistence and latest
package selection. Detection polling and fee-policy automation remain open.

- State package persistence.
- Detection-depth polling.
- Rebuild publication carrier with fresh sponsor inputs.
- Emergency fee budget policy.

## M3: Conservative Factory Mode

- Factory state roots and access manifest.
- Full-participant signature mode.
- Local exit without reduced signing set.

## M4: Reduced-Signature Factory Mode

This remains blocked until a formal rights-dependency proof predicate exists.
