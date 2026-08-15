# Factory Pre-production Candidate

This directory defines the bounded release profile
`factory-dynamic-n`. It is a controlled-devnet candidate, not a
mainnet or real-assets release.

The profile deliberately freezes the executable Factory boundary:

- 2–16 Factory signing participants with sorted, commitment-bound membership;
- N-of-N conservative updates and exactly one touched-member authorisation on reduced paths;
- fixed-layout rights bodies and one-right, depth-256 sparse-Merkle proofs;
- resize witness version 2 with signed participant withdrawal locks and exact
  CKB/xUDT payout-output enforcement;
- exact bilateral and Factory Vault content plus OutPoint commitments;
- direct CKB flows plus the devnet-only `morph-devnet-xudt` test asset;
- no Hub-submitted chain mutations, RGB++, or Morph-backed Fiber routing.

`contracts.json` records the exact CKB data hash and size of every RISC-V ELF.
`envelope.json` is the machine-checked deployment policy. Both are checked by
CI and included with the built ELFs in the CI release bundle.

`watch-policy.json` is the enforced pilot policy. Copy
`watch-config.example.json` into operator-controlled storage, replace its
placeholder channel ID, set `from_block` to no later than channel creation, and
keep its relative policy/package/cursor paths together.

Verify a clean build:

```sh
make build-contracts
make release-readiness
make package-contract-release
```

`make build-contracts` always compiles in a fresh temporary target directory
and remaps the repository and Cargo-home prefixes to stable virtual paths. This
prevents machine-specific source paths or restored build caches from changing
the reviewed CKB Data Hashes.

Changing any contract hash requires a fresh protocol review, contract tests,
devnet acceptance run, and deliberate manifest update. Never update the
manifest merely to make CI green.

The current manifest includes the 2026-08-15 withdrawal-binding semantics and
was refreshed for the v1.10.0 deterministic path-remapped build. Any archive
produced before this manifest is stale and must not be used;
`make package-contract-release` always builds a fresh archive from the reviewed
files in this directory.
