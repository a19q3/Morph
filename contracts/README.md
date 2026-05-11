# CKB Contracts

This directory contains the CKB script boundary for the devnet prototype.

The repository implements host-side protocol semantics in `morph-core` and the
fixed-width V1 validation subset in no-std CKB scripts:

- `morph-state-type`: owns State Cell progression, state-number monotonicity,
  and bilateral participant signature verification.
- `morph-state-lock`: ensures a State Cell can only be spent when it carries
  the expected state type script, leaving transition rules to the type script.
- `morph-vault-lock`: owns vault settlement, current-state authorisation, and
  descriptor-bound settlement output checks.
- `morph-sponsor-lock`: owns bounded sponsor budget spending and requires a
  matching settling StateHeader output.

Build the current scripts with:

```sh
make build-contracts
```

The output ELFs are under
`target/riscv64imac-unknown-none-elf/release/`.
