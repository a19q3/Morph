# W6 Remediation Status

Date: 2026-06-28

This note is the live follow-up for `docs/swarm-audit-W6-current-status.md`,
`docs/swarm-audit-W6-rigor.md`, `docs/swarm-audit-W6-safety.md`, and
`docs/swarm-audit-W6-reasonable.md`. The original reports remain historical
evidence; this file records the current closure state.

## Closed or implemented

| Recommendation | Status | Evidence |
| --- | --- | --- |
| REC-W6-01 | Fixed | Hub state restore is disabled by default, restricted to empty bootstrap state when enabled, rejects operational/settling replacement, preserves a backup, and emits a critical `state_restored` event. |
| REC-W6-02 | Fixed | `SpliceTransition` has `next_state`; host validation checks successor vault/payload/context fields and rejects `SpliceNextStateMismatch`. |
| REC-W6-03 | Fixed | devnet sponsor defaults use the audited bounded state-number window and reports flag over-wide sponsor policies. |
| REC-W6-04 | Fixed | CLI private-key env args use `hide_env_values`; devnet smoke unsets inherited `MORPH_DEVNET_PRIVATE_KEY` for child cargo runs. |
| REC-W6-05 | Fixed | `morph-factory-vault-lock` parses owned Factory State data and no longer uses `Box::leak`. |
| REC-W6-08 | Fixed for current auth mode | Morph Hub disables SSE when bearer auth is configured and falls back to authenticated polling. |
| REC-W6-09 | Fixed | Hub bearer comparison uses a constant-time comparison helper. |
| REC-W6-10 | Fixed | state restore intersects restored `completed_flows` with live state and refuses operational replacement. |
| REC-W6-11 | Fixed | Hub supports `--auth-token-file`, `--auth-token-stdin`, and `--rotate-auth-token-on-restart`. |
| REC-W6-12 | Fixed | state/factory anchor derivation scans later inputs and rejects duplicate derived anchors/ids. |
| REC-W6-13 | Fixed | splice witness scans in state/vault scripts are capped with `MAX_WITNESS_INPUTS_PER_TX`. |
| REC-W6-19 | Fixed | `docs/implementation.md` documents the one-shot factory local-exit lifecycle and `state_number=0` child State requirement. |
| REC-W6-20 | Fixed by documentation | `docs/implementation.md` documents host-only `Phase::Funding` and `Phase::Closed` versus the script-level `Active`/`Settling` wire phases. |
| REC-W6-21 | Fixed | `ChannelOperation::is_publication_or_supersede` is the only helper; the old `is_publication_or_challenge` alias was removed. |
| REC-W6-22 | Fixed | Hub persisted-state restore derives node ids from pubkeys and rejects zero `Bytes32` inputs. |
| REC-W6-23 | Fixed | Morph Hub labels and restore copy now make the local/off-chain tracking boundary explicit. |
| W5-15 carry-over | Fixed | `witness_envelope_accepts_every_known_kind_and_rejects_bad_body_lengths` directly tests every envelope kind at the parser layer. |
| W6-RIGOR-06 | Fixed | host and script tests reject reduced factory exits that try to release non-`ReserveClaim` rights. |
| W6-RIGOR-12 | Fixed | `WitnessEnvelope::parse` rejects unknown kinds before dispatching to the guarded body-length table; the parser regression test covers the unknown-kind path. |
| W6-RIGOR-13 | Fixed | script-common now has a single `WITNESS_ENVELOPE_KIND_SPECS` table for known envelope kinds and valid body lengths; parser tests iterate that table. |

## Refuted or closed by design evidence

| Finding | Status | Rationale |
| --- | --- | --- |
| REC-W6-06 / W6-RIGOR-02 | Refuted for current CKB grouping | `morph-vault-lock` cannot use `Source::GroupInput` to find the State Cell because its script group contains vault cells. It scans transaction inputs, requires exact State header anchor plus type/lock-script binding, and rejects duplicates. |
| REC-W6-07 / W6-RIGOR-04 | Fixed | host and script-common `same_context_except_progress` preserve settlement descriptor commitment and descriptor version; splice also uses the stricter `state_context_matches_splice_next` bridge. |
| REC-W6-14 / REC-W6-15 / W6-RIGOR-03 | Closed by call order | factory-vault-lock verifies the reduced-exit witness against on-chain old/new Factory State headers before applying vault reserve arithmetic; `verify_reduced_factory_exit_update` binds the old/new rights roots to those headers and `validate_reduced_exit_non_interference` requires exactly the touched `RESERVE_CLAIM` decrement. |
| W6-RIGOR-09 | Closed by committed evidence | factory local-exit and reduced-exit evidence commit the exact child State header, including `participants_commitment`; `docs/implementation.md` documents that this is an indirect signed binding and that later child states are governed by child-channel signatures. |
| W6-RIGOR-11 | Fixed by documentation | `docs/implementation.md` documents host-only `Phase::Funding` and `Phase::Closed` versus the script-level `Active`/`Settling` wire phases. |
| W6-RIGOR-14 | Closed by boundary evidence | the sponsor script admits only a settling State output with the configured State type hash and a matching input State of that type; host validation additionally restricts sponsor spends to `Publish` or `Supersede`. |

## Resolved residual and v2-design items

| Recommendation | Status | Rationale |
| --- | --- | --- |
| REC-W6-16 | Fixed | the bilateral field is now named `vault_materialisation_root` / `new_vault_materialisation_root` in core, script-common, schema, CLI splice packages, and tests; host JSON accepts old `payload_commitment` aliases for saved packages. |
| REC-W6-17 | Fixed by deletion | the `SponsorPolicy::expiry` sentinel field was removed from core, script-common, schema, sponsor-lock, CLI policy construction, reports, and tests; finite windows remain operator/watchtower policy. |
| REC-W6-18 | Fixed | the unused `ChannelOperation::CooperativeClose` variant and vault-validation arm were removed; cooperative close is documented as not part of the current profile. |
| REC-W6-24 | Fixed | the live `devnet` command tree is hidden from default `morph-cli` builds, requires `--features devnet`, and also requires an explicit `--devnet-only` confirmation flag; scripts and docs were updated. |
| REC-W6-25 | Fixed for remediation scope | `morph-script-common` now has table-driven reduced-splice boundary-field rejection tests across factory id, update, state root, access root, participant commitments, non-interference digest, vault delta commitment, and vault factory id. The compact ~100 byte proof redesign remains a future v2 proof-system design, not a patch-level remediation. |
