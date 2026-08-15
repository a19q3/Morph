# M5 Closeout

M5 closes the conservative bilateral splice scope.

## Supersession Note

This is a historical closeout for the conservative bilateral splice milestone.
It remains useful as evidence for the splice policy and devnet coverage, but it
is not the current factory witness-boundary document. Current factory
authorisation uses `WitnessEnvelope`; the M5 references below concern
bilateral splice package/body scope and `StateHeader` funding-epoch semantics.

The accepted conservative design is:

- quiescent splice packages with an explicit base state number;
- explicit funding-epoch semantics, with `StateHeader` as the active channel
  wire target;
- bounded CKB and CKB+xUDT asset delta descriptors;
- participant-owned splice-out withdrawals whose canonical participant lock
  hash is included in the signed header; arbitrary payout locks remain deferred
  beyond this conservative scope.

## Done

- `morph-core` validates signed CKB and xUDT splice-in/splice-out transitions,
  including base-state matching, epoch advancement, vault descriptor
  commitments, asset-delta conservation, withdrawal amounts, and remaining
  settlement coverage.
- `morph-script-common` exposes bounded parsers for the splice header,
  splice witness, old/new vault descriptors, asset deltas, bundled splice
  witness, and `StateHeader`.
- The signed splice header commits the exact participant withdrawal lock, and
  the vault lock requires an exact CKB/xUDT withdrawal output for every
  nonzero splice-out delta.
- `verify_splice_state_transition_bundle` covers the explicit-epoch target by
  binding old/new funding epochs to old/new vault-set commitments.
- `morph-state-type` and `morph-vault-lock` accept the conservative
  old/new-anchor splice bridge and reject wrong-channel or malformed vault
  transitions in CKB-VM coverage.
- `morph-cli` can print, validate, save, and apply reusable splice packages for
  CKB splice-in/out and xUDT splice-in/out.
- Devnet smoke covers CKB splice-in/out and xUDT splice-in/out through
  post-splice sponsor funding, descriptor-updated publication, and finalisation.
- Negative smoke rejects stale funding epochs, wrong channel ids, wrong vault
  type applications, insufficient remaining value, tampered xUDT deltas, and
  signed-fee leakage.
- Watchtower package selection is funding-anchor aware and emits splice-specific
  alerts for detected splices, stale packages, and splice-aware publication.
- Package and apply JSON artifacts expose the conservative participant-owned
  withdrawal rule through `withdrawal_payout_policy`, the participant pubkey,
  and the signed live withdrawal lock hash.
- Default smoke assertion now requires splice apply artifacts for all four
  splice smokes and verifies splice-out payout evidence stays
  `participant_signature_pubkey` with a concrete participant pubkey, lock hash,
  and withdrawal out point.

## Deferred

- Concurrent unconfirmed splice updates while ordinary off-chain updates keep
  advancing.
- Generic descriptor runtimes and arbitrary payout graphs.
- Pre-authorised third-party payout-lock allowlists, which remain separate
  policy work.
- Factory splice-in/out, which begins in M6.

## Closure Verification

Run the local checks before treating M5 as closed:

```sh
cargo fmt --all --check
cargo test -p morph-script-common
cargo test -p morph-core
cargo test -p morph-cli
cargo clippy -p morph-script-common --all-targets -- -D warnings
cargo clippy -p morph-core --all-targets -- -D warnings
cargo clippy -p morph-cli --all-targets -- -D warnings
bash -n scripts/devnet-smoke.sh
git diff --check
```

The live acceptance run remains:

```sh
scripts/devnet-smoke.sh
make smoke-report
make smoke-assert
```

That live path requires a local CKB devnet and built contract binaries.
