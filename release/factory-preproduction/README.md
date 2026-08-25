# Morph 3 Conditional-Batch Candidate

This directory defines the bounded `morph-v3-conditional-batch` release
profile. It is a controlled-devnet candidate, not a mainnet or real-assets
release.

The profile freezes these executable boundaries:

- bilateral and dynamic 2–16 participant Factory state/Vault rules;
- Factory N-of-N and reduced paths through witness-envelope kinds 1–8;
- bilateral descriptor version 3 for zero to eight CKB conditional transfers;
- SHA-256 or CKB-personalised Blake2b payment hashes, exact 32-byte preimages,
  and canonical absolute-block refunds;
- Vault args v2 pinning the only allowed `morph-batch-lock` code hash/hash type;
- whole-Vault materialisation into one Batch Cell, followed by exactly two
  plain participant outputs with no value loss;
- durable, channel/funding/state-bound force-resolution packages in Morph Hub;
- direct CKB flows plus the devnet-only `morph-devnet-xudt` test asset;
- no conditional xUDT, Hub-submitted chain mutations, mainnet deployment, or
  real-asset use.

`contracts.json` records the exact CKB data hash and size of all eight RISC-V
ELFs. `envelope.json` is the machine-checked deployment policy. Both are
checked by CI and included with the ELFs in the deterministic release archive.

Verify a clean build:

```sh
make build-contracts
make release-readiness
make package-contract-release
```

`make build-contracts` compiles in a fresh target directory and remaps source
paths so machine-specific paths and restored caches cannot change reviewed CKB
Data Hashes. A contract-hash change requires protocol review, contract tests,
devnet acceptance, and a deliberate manifest update; never update the manifest
only to make CI green.
