# CKB Contracts

This directory records the planned script boundary for devnet contracts.

The repository currently implements the protocol semantics in `morph-core`.
The first contract milestone is to port the fixed-width V1 validation subset
into no-std CKB scripts:

- `morph-state-type`: owns State Cell progression and state-number monotonicity.
- `morph-vault-lock`: owns vault settlement and current-state authorisation.
- `morph-sponsor-lock`: owns bounded sponsor budget spending.

Do not deploy an always-success placeholder as Morph Channel. A devnet release
must include negative transaction tests for the audit matrix.

