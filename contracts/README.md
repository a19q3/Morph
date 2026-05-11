# CKB Contracts

This directory contains the CKB script boundary for the devnet prototype.

The repository implements host-side protocol semantics in `morph-core` and the
fixed-width V1 validation subset in no-std CKB scripts:

- `morph-state-type`: owns State Cell progression and state-number monotonicity.
- `morph-vault-lock`: owns vault settlement and current-state authorisation.
- `morph-sponsor-lock`: owns bounded sponsor budget spending.

Do not deploy an always-success placeholder as Morph Channel. A devnet release
must include negative transaction tests for the audit matrix.

Build the current scripts with:

```sh
make build-contracts
```

The output ELFs are under
`target/riscv64imac-unknown-none-elf/release/`.
