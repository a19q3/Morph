# Factory v1.0 Pre-production Candidate

This directory defines the bounded release profile
`factory-v1.0-fixed-bilateral`. It is a controlled-devnet candidate, not a
mainnet or real-assets release.

The profile deliberately freezes the executable Factory boundary:

- exactly two Factory signing participants;
- 2-of-2 conservative updates and one-of-two authorised reduced paths;
- fixed-layout rights bodies and one-right, depth-256 sparse-Merkle proofs;
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

Changing any contract hash requires a fresh protocol review, contract tests,
devnet acceptance run, and deliberate manifest update. Never update the
manifest merely to make CI green.
