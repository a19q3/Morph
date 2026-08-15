# Morph Channel Explained — 2026-08-15 Update Draft

This is an edit companion for the public Nervos Talk explainer, not a second
protocol specification. It records statements in the June 2026 post that should
be replaced now that the executable devnet profile and the 2026-08-15 audit
remediation exist.

## Status Note For The Top Of The Post

> Implementation update, 2026-08-15: the repository now implements the bounded
> bilateral and Factory devnet profiles described below, including exact Vault
> OutPoint binding, a derived funding-context identifier, envelope-dispatched
> Factory proofs, and signed splice-out withdrawal destinations. The current
> code remains research/devnet software and is not approved for production or
> real assets. See the 2026-08-15 swarm audit, `SECURITY-FIXES.md`, and
> `docs/mainnet-readiness.md` for the evidence boundary.

## Replace “Vaults Sit Untouched For The Entire Channel Lifetime”

Vault Cells remain unchanged during ordinary off-chain updates and ordinary
State Cell publication/supersession. They are consumed only at explicit value
boundaries: finalisation, channel resize/re-anchor, Factory exit, or child
materialisation. A logical channel can therefore keep the same `channel_id`
while moving to a newly committed Vault and funding context.

## Replace The Simplified `StateHeader`

The current signed header is:

```text
struct StateHeader {
  protocol_version
  chain_id
  signature_scheme_id
  channel_id
  funding_epoch
  funding_anchor
  vault_set_commitment
  state_number
  mode
  phase
  participants_commitment
  asset_registry_commitment
  settlement_descriptor_commitment
  descriptor_version
  vault_materialisation_root
  challenge_policy_commitment
  state_layout_version
  vault_outpoint_commitment
}
```

`funding_anchor` is the signed Type-ID-style context identity in the current
devnet profile; it is not the live Vault locator. `vault_materialisation_root`
binds the exact Vault content, and `vault_outpoint_commitment` binds the exact
live CKB OutPoint after activation.

Tooling derives:

```text
funding_context_id = H(
  "CKB_MORPH_FUNDING_CONTEXT",
  chain_id,
  channel_id,
  funding_anchor,
  vault_set_commitment,
  vault_outpoint_commitment
)
```

`channel_id` is the stable logical integration key. `funding_context_id`
identifies the exact live funding object. The signed `funding_epoch` is a
monotonic generation label for packages, logs, recovery, SDKs, and indexers; it
is useful but is not the minimal anti-replay primitive by itself.

## Replace The Fee-Bumping Paragraph

CKB supports replacement of conflicting pending transactions. Morph's
distinction is not that it avoids RBF. Participants sign the State Header, not
the sponsor inputs or fee rate, so a participant or watchtower can rebuild or
replace the publication transaction with different sponsor inputs and a higher
fee without obtaining new channel-state signatures. Only one conflicting spend
of the live State Cell can commit.

## Rename The User-Facing Operation

Use **resize / re-anchor** in user-facing text and retain **`SPLICE`** when
referring to current wire fields, witness kinds, packages, CLI commands, or code.
The operation preserves `channel_id` while advancing `funding_context_id` and
`funding_epoch`; it is not modelled as closing one logical channel and opening a
different one.

The current resize header signs the old/new funding anchors, epochs, Vault-set
commitments, Vault content roots, exact Vault OutPoint commitments, asset delta,
participants, challenge policy, and base state. Resize-out additionally signs
`withdrawal_lock_hash`. The Vault scripts require an exact CKB/xUDT withdrawal
output with that lock and amount, preventing a transaction assembler from
redirecting the payout.

## Replace The Factory-State Description

The implemented Factory does not use a generic `StateHeader` plus separate
balances/sub-channel/membership/reserve roots. It uses one fixed 302-byte
`FactoryStateHeader` containing:

```text
protocol_version, chain_id, signature_scheme_id, factory_id,
update_number, state_root, participants_commitment,
access_manifest_root, non_interference_digest,
challenge_policy_commitment, state_layout_version,
vault_materialisation_root, vault_outpoint_commitment
```

Factory authorisation is dispatched through a committed `WitnessEnvelope`.
The current profile supports 2–16 participants, N-of-N conservative creation,
updates, local exits and full resize, plus bounded reduced-rights,
sparse-Merkle, reduced-exit, and reduced-resize bodies. Unknown shapes fail
closed; general multi-right and variable-depth reduced proofs remain deferred.

## Add The Factory-Liquidity Answer

A **rights delta** changes who may claim what inside the Factory while the
FactoryVault assets remain unchanged. Cooperative rights deltas can stay off
chain as signed Factory state. A **vault delta** changes assets at the Factory
boundary and must be enforced on chain. Adding/removing Factory funds,
materialising a child channel, and local/reduced exits therefore require CKB
transactions. A Merkle proof demonstrates locality, not economic authority;
unsupported reduced transitions fall back to full participant signatures.

## Refresh “What Is Still Unsolved”

| June 2026 question | 2026-08-15 status |
| --- | --- |
| Witness/proof byte and cycle cost | Measured in local devnet smoke/stateful budget profiles for the admitted shapes; public-network economics remain open. |
| Sponsor policy failures | Script-level fee/range/change boundaries and negative tests implemented; real fee-market exhaustion policy remains open. |
| Splice freshness | Funding-context-aware packages, exact Vault provenance, stale-package negatives, and post-resize watchtower selection implemented. |
| Factory acceptance | Positive/negative CKB-VM and devnet matrices implemented for the bounded 2–16 participant/fixed-proof profile. |
| Mechanised non-interference | Implemented for admitted fixed proof families; a general rights-dependency language and general multi-right proofs remain open. |
| Challenge reliability | Relative-`since` parsing and canonical reorg recovery implemented; mainnet-like delay, fee pressure, induced reorg, and multi-operator evidence remain open. |
| State Cell contention | Consensus single-spend behavior is relied upon; adversarial mempool/RBF/propagation measurements remain open. |

The penalty decision is unchanged: stale publication is a failed claim, not a
slashable offence. That keeps accidental stale-state publication from causing
an additional protocol penalty, but it makes watchtower liveness, sponsor
availability, challenge-window sizing, and reorg assumptions explicit
deployment responsibilities.
