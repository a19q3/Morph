# Base-Model Security Audit

Date: 2026-07-23

## Verdict

The bilateral and factory base models are internally coherent and suitable for
continued research and devnet use after the remediations in this review. No
known critical or high-severity defect remains open in the audited first-party
model.

This is not a mainnet-readiness claim. Real-assets deployment still requires an
independent review, parser and state-machine fuzzing, deployment-specific
economic analysis, and retirement of the upstream dependency exceptions listed
below.

## Scope And Authority

The review covered:

- the protocol types, commitments, transition validators, backend boundary, and
  invariant tests in `morph-core`;
- fixed-layout parsing and shared verification logic in
  `morph-script-common`;
- bilateral State, Factory, Vault, Sponsor, and development xUDT scripts;
- CLI state construction, splice packages, fixtures, and devnet paths;
- arithmetic, serialization, signatures, asset conservation, sponsor budgets,
  reduced exits, factory rights, unsafe-code boundaries, and the Rust supply
  chain.

CKB scripts are the consensus authority. Host validators are defensive preflight
checks and package-construction guards; their evidence summaries do not replace
script execution. UI behavior, a live public deployment, third-party consensus
code, and a fresh independent cryptographic review were outside this audit.

## Closed Findings

Severity is the impact before remediation.

| ID | Severity | Finding | Resolution |
| --- | --- | --- | --- |
| BM-01 | High | `StateHeader.asset_registry_commitment` could remain a placeholder while host validation trusted an out-of-band registry. | Added one canonical, strictly sorted commitment algorithm shared by host and scripts. State transitions, splice, vault, backend construction, devnet headers, packages, and fixtures now reject unbound registries. |
| BM-02 | High | Host signature validation admitted thresholds and key encodings that consensus scripts did not support. | Host and chain now share the exact 2-of-2 profile, two compressed 33-byte keys, fixed schemes, and reduced-factory profile. Unknown profiles fail closed. |
| BM-03 | High | Host splice validation did not enforce the consensus carrier-capacity delta. | Splice validation and package construction now require the exact activation-fee delta and stable occupied capacity. A regression test covers leakage. |
| BM-04 | High | Classified xUDT cells could hide carrier CKB or inconsistent class metadata, and xUDT carrier CKB was absent from business-CKB conservation. | Classification is shape-validated, xUDT business CKB is derived from capacity minus occupied capacity, and all business CKB now participates in conservation. Tamper and leakage regressions were added. |
| BM-05 | Medium | Protocol, layout, mode, and descriptor version fields were parsed but not consistently enforced. | Added explicit supported-profile validation to all relevant state, factory, vault, sponsor, and signature/splice paths. Vault descriptors must match the committed asset profile. |
| BM-06 | Medium | Host asset lists could be accepted in orders or sizes that fixed-layout scripts could not represent canonically. | Splice and factory sequences are bounded, non-empty where required, strictly sorted, and duplicate-free before crossing the wire boundary. |
| BM-07 | Medium | The lockfile contained yanked `bitcoin_hashes` and `bitcoin-io` releases. | Updated to non-yanked compatible releases and made the audit target deny warnings, with only documented advisory exceptions. |
| BM-08 | Defense in depth | First-party crates relied on convention rather than a compile-time unsafe-code boundary. | Every first-party library, binary, and contract root now declares `#![forbid(unsafe_code)]`. |

## Security Properties Rechecked

- Commitments use domain separation, exact fixed-width fields, canonical asset
  ordering, and shared host/script algorithms.
- Arithmetic at value boundaries is checked; CKB and xUDT conservation include
  carrier value, sponsor deltas, fees, withdrawals, and change.
- State publication remains monotonic and bound to the exact previous outpoint.
- Bilateral authorization is exactly 2-of-2 for the supported wire profile.
- Factory updates preserve sparse-Merkle roots and constrain reduced rights and
  exits to their committed scope.
- Vault settlement is bound to authentic State identity, descriptor profile,
  settlement amounts, and transition mode.
- Sponsor spending is constrained by budget, allowed scripts, fee accounting,
  and clean change.
- Host-only evidence fields are treated as boundary inputs, while scripts remain
  authoritative for consensus acceptance.

## Verification Record

The following repository gates pass on the audited tree:

```text
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --all-targets
make contract-tests
make fixture-checks
make supply-chain
```

The workspace run completed with 376 passing tests and 110 contract-VM tests
ignored by design. `make contract-tests` rebuilt the RISC-V contracts and
executed all 110 of those VM tests successfully.

Additional targeted checks cover commitment parity, rejected unknown profiles,
descriptor mismatch, chain-incompatible signature profiles, carrier-capacity
leakage, xUDT CKB leakage, classification tampering, and non-canonical asset
orders.

All first-party roots forbid unsafe Rust. `cargo geiger` reported no unsafe use
in `morph-core` or `morph-script-common`; some third-party crates could not be
fully scanned by that tool. A nightly Miri attempt reached the external
`blake2b-rs` C FFI boundary and stopped because that foreign function is not
supported by Miri, so Miri is not counted as passing evidence.

## Accepted Upstream Dependency Exceptions

`make supply-chain` fails on any unlisted advisory. These five temporary
exceptions are pinned in the `Makefile` with removal conditions:

| Advisory | Path / exposure | Current disposition |
| --- | --- | --- |
| [RUSTSEC-2024-0436](https://rustsec.org/advisories/RUSTSEC-2024-0436.html) | `paste`, inherited through the CKB ecosystem | Unmaintained rather than a demonstrated exploit here; remove when the supported CKB line removes it. |
| [RUSTSEC-2026-0097](https://rustsec.org/advisories/RUSTSEC-2026-0097.html) | `rand 0.7`, inherited through CKB | The reported custom-logger re-entrancy trigger is absent from first-party code; remove on the next compatible CKB dependency line. |
| [RUSTSEC-2026-0186](https://rustsec.org/advisories/RUSTSEC-2026-0186.html) | `memmap2`, test-only through `ckb-testtool` and `cacache` | The affected advise/flush API is not used by first-party code; remove when the test stack upgrades. |
| [RUSTSEC-2026-0173](https://rustsec.org/advisories/RUSTSEC-2026-0173.html) | `proc-macro-error2`, compile-time through `biscuit-auth` | No runtime protocol exposure; remove when upstream replaces the macro dependency. |
| [RUSTSEC-2026-0253](https://rustsec.org/advisories/RUSTSEC-2026-0253.html) | `lru 0.7`, test-only through `ckb-testtool` and `ckb-verification` | The affected CKB cache key is `Byte32`, whose drop cannot panic, so the advisory's panic-unwind trigger is absent. `ckb-verification 1.2` requires Rust 1.95; remove this waiver when the pinned CKB/Rust line can upgrade. |

The exceptions are risk acceptances, not declarations that the dependencies are
safe. A mainnet release must either remove them or document a separately
approved, deployment-specific decision.

## Compatibility Note

The registry commitment and supported-profile checks intentionally reject older
devnet State headers and splice packages that used placeholder commitments or
unsupported layout metadata. Regenerate fixtures and packages and reopen
ephemeral devnet state; do not attempt to reinterpret the old bytes.

## Remaining Release Blockers

Before a production or real-assets claim:

1. obtain an independent audit of the final scripts, transactions, and
   deployment parameters;
2. fuzz fixed-layout parsers and state-machine transition sequences, including
   cross-implementation differential tests;
3. run adversarial economic and liveness testing for sponsor exhaustion,
   challenge timing, reduced exits, and concurrent factory updates;
4. remove or separately approve every dependency exception and reproduce the
   build from pinned artifacts;
5. repeat the full verification matrix against the exact deployed code hashes.

Subject to those explicit limits, the current base model is safe, reasonable,
and structurally disciplined for its stated devnet and research maturity.
