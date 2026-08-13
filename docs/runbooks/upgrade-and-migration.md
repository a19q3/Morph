# Upgrade, Migration, and Rollback

CKB cells commit script hashes, so a contract upgrade is a new deployment and
state migration, not an in-place binary replacement.

## Prepare an Upgrade

1. Freeze new Factory creation and concurrent splices.
2. Build from a clean candidate with Rust 1.92.0 and `Cargo.lock`.
3. Run `make ci`, `make devnet-stateful-e2e`, and independent review for every
   wire-format or contract change.
4. Generate a new release profile and manifest; never overwrite the prior
   release evidence.
5. Compare domain strings, versions, fixed lengths, witness-kind tables,
   descriptor versions, and old/new script hashes.
6. Rehearse every migration and rollback using no-value devnet cells.

Any change to the supported signer-count bounds, proof depth, right count,
witness layout, envelope format, or `*_LEN` rule is a new protocol profile. The
v1.0 dynamic-N manifest covers only 2–16 signers and must not be relabelled as
supporting a wider or threshold-based profile.

## Legacy Factory Policy

Owner-locked legacy FactoryState cells and children lacking exact FactoryType
provenance cannot be upgraded in place. The approved procedure is:

1. stop new updates and save the latest mutually valid packages;
2. materialise/settle children and exit the old Factory using its own scripts;
3. wait for canonical finality under the watchtower policy;
4. deploy and verify the new manifest hashes;
5. create a new Factory ID, FactoryStateCell, FactoryVaultCell, packages, and
   watch cursor from the new creation block;
6. archive the old mapping and mark it closed in operator inventory.

Do not copy an old header under a new lock or mutate its participant commitment.
Lock continuity and provenance checks are expected to reject that shortcut.

## Rollback

Before any value enters a new deployment, rollback means abandoning its cells
and returning to the still-live prior deployment. After activation, rollback
means quiescing, settling with the new deployment's valid rules, and recreating
under the prior reviewed profile only if compatibility and operator policy
allow it.

Never point an existing cell at an older code hash, reuse old splice packages
after a funding-context change, or edit a release manifest to match an
unreviewed binary. Preserve both release bundles and an explicit old-ID to
new-ID migration ledger.

## Post-upgrade Verification

Verify deployed hashes, open/update/reduced update/exit/splice paths, negative
attacks, watch cursor canonicality, reorg rescan, package restoration, and
emergency stop. Keep the old watchtower active until the new operator has
scanned from creation through the current canonical tip.
