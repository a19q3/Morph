# Compatibility and Removal Gates

Morph emits only the current wire and JSON names. The compatibility paths below
are read-only migration aids; they are not alternative protocol formats and
must not be extended with new fields or emitters.

| Compatibility path | Current behaviour | Removal gate |
| --- | --- | --- |
| Legacy `morph1` hex invoice body | `MorphInvoice::decode` accepts it; `encode` emits only Bech32m. | Remove after every supported fixture/operator store has been migrated and a release note has announced one full compatibility window. Keep the negative/current-format and legacy-read tests until removal. |
| `payload_commitment` / `new_payload_commitment` JSON names | Serde accepts the old names for state and splice packages; serializers emit `vault_materialisation_root` names. | Remove only with a fixture migration that rewrites all retained packages and proves `make fixture-checks` plus historical package validation. This does not change the fixed-layout on-chain format. |
| Historical sponsor `expiry` report field | Smoke report readers expose it as optional `legacy_expiry`; current 136-byte SponsorPolicy neither emits nor enforces it. | Remove after retained baseline artifacts no longer contain `expiry`, or migrate those artifacts to a versioned report schema first. |
| Watch cursor without `scanned_to_block_hash` | JSON decoding remains backward compatible, but the watchtower treats the cursor as unverifiable, emits `chain_reorg_detected`, clears observation context, and rescans from configured `from_block`. New cursors always record a canonical block hash after scanning. | Remove the optional decode only after every retained cursor has been rewritten by a successful canonical rescan and one compatibility window has been announced. |

Any removal is a compatibility change and must include release notes, migrated
fixtures/artifacts, and negative coverage proving that obsolete input is
rejected deliberately rather than misparsed.
