# Upgrade, Migration, and Rollback

CKB cells commit script hashes, so a contract upgrade is a new deployment and
state migration, not an in-place binary replacement.

## Prepare an Upgrade

1. Freeze new Factory creation and concurrent splices.
2. Build from a clean candidate with Rust 1.92.0 and `Cargo.lock`.
3. Run `make ci`, `make devnet-stateful-e2e`, and independent review for every
   wire-format or contract change.
4. Generate a fresh candidate profile and manifest from the current source.
5. Compare domain strings, versions, fixed lengths, witness-kind tables,
   descriptor versions, and old/new script hashes.
6. Rehearse every migration and rollback using no-value devnet cells.

Any change to the supported signer-count bounds, proof depth, right count,
witness layout, envelope format, or `*_LEN` rule is a new protocol profile. The
dynamic-N manifest covers only 2–16 signers and must not be relabelled as
supporting a wider or threshold-based profile.

## Pre-release Reset Policy

Morph has no released Factory wire and supports no historical Factory cells,
packages, witnesses, JSON aliases, or in-place migrations. A contract or wire
change invalidates prior no-value development state. Stop the devnet, discard
that state, deploy the current manifest, and create new Factory IDs and watch
cursors. Do not add alternate parsers to preserve an unpublished shape.

## Rollback

Before any value enters a candidate deployment, rollback means abandoning its
no-value cells and returning to the last reviewed source revision. There is no
in-place downgrade path.

Never point an existing cell at an older code hash, reuse splice packages after
a funding-context change, or edit a candidate manifest to match an unreviewed
binary.

## Post-upgrade Verification

Verify deployed hashes, open/update/reduced update/exit/splice paths, negative
attacks, watch cursor canonicality, reorg rescan, package restoration, and
emergency stop. The watchtower must scan the recreated channels from creation
through the current canonical tip.
