#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

RPC_URL="${MORPH_CKB_RPC:-http://127.0.0.1:18114}"
OUT_DIR="${OUT_DIR:-target/devnet-stateful-scenarios/$(date -u +%Y%m%dT%H%M%SZ)}"
LATEST_LINK="${LATEST_LINK:-target/devnet-stateful-scenarios/latest}"
SMOKE_DIR="$OUT_DIR/smoke"
SMOKE_LATEST_LINK="$OUT_DIR/smoke-latest"
MINE_BLOCKS="${MINE_BLOCKS:-4}"
REUSE_SMOKE_DIR="${MORPH_DEVNET_STATEFUL_REUSE_SMOKE_DIR:-}"

mkdir -p "$OUT_DIR"

if ! command -v jq >/dev/null 2>&1; then
  printf 'missing: jq is required by scripts/devnet-stateful-scenarios.sh\n' >&2
  exit 1
fi

GIT_COMMIT="$(git rev-parse --short HEAD 2>/dev/null || printf 'unknown')"
if [ -n "$(git status --porcelain --untracked-files=no 2>/dev/null)" ]; then
  GIT_DIRTY="true"
else
  GIT_DIRTY="false"
fi

log() {
  printf '[devnet-stateful] %s\n' "$*"
}

write_scenario() {
  local scenario_id="$1"
  local category="$2"
  local description="$3"
  local references_json="$4"
  local required_json="$5"
  local failures_json="$6"
  local coverage_json="$7"
  jq -n \
    --arg schema "morph.devnet_stateful_scenario" \
    --arg scenario_id "$scenario_id" \
    --arg category "$category" \
    --arg description "$description" \
    --argjson references "$references_json" \
    --argjson required_committed_checks "$required_json" \
    --argjson expected_failures "$failures_json" \
    --argjson coverage "$coverage_json" \
    '{
      schema: $schema,
      scenario_id: $scenario_id,
      category: $category,
      description: $description,
      references: $references,
      required_committed_checks: $required_committed_checks,
      expected_failures: $expected_failures,
      coverage: $coverage,
      final_state_pointer: {},
      asset_deltas: {}
    }' >"$OUT_DIR/$scenario_id.json"
}

cat >"$OUT_DIR/manifest.txt" <<EOF
schema=morph.devnet_stateful_scenarios
rpc_url=$RPC_URL
started_at_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)
mine_blocks=$MINE_BLOCKS
git_commit=$GIT_COMMIT
git_dirty=$GIT_DIRTY
EOF

if [ -n "$REUSE_SMOKE_DIR" ]; then
  log "reusing smoke artifact $REUSE_SMOKE_DIR"
  rm -rf "$SMOKE_DIR"
  mkdir -p "$SMOKE_DIR"
  cp -R "$REUSE_SMOKE_DIR"/. "$SMOKE_DIR"/
  cat >>"$OUT_DIR/manifest.txt" <<EOF
smoke_source=$REUSE_SMOKE_DIR
EOF
else
  log "running underlying real devnet smoke -> $SMOKE_DIR"
  MORPH_CKB_RPC="$RPC_URL" \
  OUT_DIR="$SMOKE_DIR" \
  LATEST_LINK="$SMOKE_LATEST_LINK" \
  MINE_BLOCKS="$MINE_BLOCKS" \
    scripts/devnet-smoke.sh
fi

write_scenario \
  bilateral_supersede_watchtower_finalise \
  bilateral \
  "State packages advance beyond a stale publication; watchtower publishes the newer state and finalises the current state." \
  '["smoke/supersede-smoke.json","smoke/finalise-since-negative-smoke.json","smoke/competing-spend-smoke.json","smoke/watch-auto-sponsor/watch.json","smoke/watch-auto-sponsor/finalise.json"]' \
  '["supersede-smoke","watch-auto-sponsor/finalise"]' \
  '[{"check":"finalise-since-negative-smoke","morph_error":"StateSinceNotMature","error_code":16}]' \
  '["state_authority_authenticity","canonical_relative_maturity","watchtower_authority_and_cursor","negative_recovery_continuity"]'

write_scenario \
  bilateral_direct_publish_finalise \
  bilateral \
  "Direct package publication and finalisation without supersession, including explicit sponsor funding." \
  '["smoke/manual-channel/open.json","smoke/manual-channel/package.json","smoke/manual-channel/publish-latest.json","smoke/manual-channel/finalise.json","smoke/manual-sponsor/fund.json","smoke/manual-sponsor/publish.json","smoke/manual-sponsor/finalise.json"]' \
  '["manual-channel/open","manual-channel/publish-latest","manual-channel/finalise","manual-sponsor/fund","manual-sponsor/publish","manual-sponsor/finalise"]' \
  '[]' \
  '["state_authority_authenticity","state_retirement_non_orphaning","signed_descriptor_evolution"]'

write_scenario \
  sponsor_fee_pressure \
  sponsor \
  "Sponsor policy rejects out-of-range and over-budget publication while sponsor top-up and rotation preserve channel value." \
  '["smoke/sponsor-policy-negative-smoke.json","smoke/sponsor-budget-negative-smoke.json","smoke/manual-sponsor/fund.json","smoke/manual-sponsor/publish.json","smoke/manual-sponsor/finalise.json"]' \
  '["manual-sponsor/fund","manual-sponsor/publish","manual-sponsor/finalise"]' \
  '[{"check":"sponsor-policy-negative-smoke","morph_error":"SponsorStateOutOfRange","error_code":29},{"check":"sponsor-budget-negative-smoke","morph_error":"SponsorFeeTooHigh","error_code":17}]' \
  '["sponsor_policy_boundary","negative_recovery_continuity"]'

write_scenario \
  splice_lifecycle_matrix \
  splice \
  "CKB and xUDT splice-in/out paths update funding epochs, descriptor commitments, and final settlement assets." \
  '["smoke/splice-in-smoke.json","smoke/splice-out-smoke.json","smoke/splice-in-asymmetric-smoke.json","smoke/splice-out-asymmetric-smoke.json","smoke/xudt-splice-in-smoke.json","smoke/xudt-splice-out-smoke.json","smoke/xudt-splice-in-one-sided-smoke.json","smoke/xudt-splice-out-one-sided-smoke.json","smoke/splice-negative-smoke.json","smoke/watch-splice-stale/watch.json"]' \
  '["splice-in-smoke","splice-out-smoke","xudt-splice-in-smoke","xudt-splice-out-smoke","watch-splice-stale/apply"]' \
  '[]' \
  '["signed_descriptor_evolution","typed_asset_binding","watchtower_authority_and_cursor"]'

write_scenario \
  factory_lifecycle_matrix \
  factory \
  "Factory state advances through all-participant update, reduced rights, sparse Merkle decrease, local child exit, and typed reduced exits." \
  '["smoke/factory/update.json","smoke/factory/exit-channel.json","smoke/factory/child-publish.json","smoke/factory/child-finalise.json","smoke/factory-reduced-rights-smoke.json","smoke/factory-reduced-rights-tight-smoke.json","smoke/factory-merkle-update-smoke.json","smoke/factory-merkle-update-tight-smoke.json","smoke/factory-reduced-exit-smoke.json","smoke/factory-reduced-exit-asymmetric-smoke.json","smoke/factory-reduced-xudt-exit-smoke.json","smoke/factory-reduced-xudt-exit-full-smoke.json","smoke/factory-reduced-xudt-exit-one-sided-smoke.json","smoke/factory-xudt/smoke.json","smoke/factory-xudt-one-sided/smoke.json"]' \
  '["factory/update","factory/exit-channel","factory/child-publish","factory/child-finalise","factory-reduced-rights-smoke","factory-merkle-update-smoke","factory-reduced-exit-smoke","factory-reduced-xudt-exit-smoke","factory-xudt/smoke"]' \
  '[]' \
  '["state_retirement_non_orphaning","non_interference_not_authorisation","factory_value_delta_binding","typed_asset_binding","negative_recovery_continuity"]'

write_scenario \
  factory_splice_then_exit \
  factory \
  "Factory CKB/xUDT conservative and reduced splice paths can be followed by child materialisation and finalisation." \
  '["smoke/factory-splice-in-smoke.json","smoke/factory-splice-out-smoke.json","smoke/factory-splice-in-asymmetric-smoke.json","smoke/factory-splice-out-asymmetric-smoke.json","smoke/factory-reduced-splice-in-smoke.json","smoke/factory-reduced-splice-out-smoke.json","smoke/factory-reduced-xudt-splice-in-smoke.json","smoke/factory-reduced-xudt-splice-out-smoke.json","smoke/factory-xudt-splice-in-smoke.json","smoke/factory-xudt-splice-out-smoke.json","smoke/factory/child-finalise.json"]' \
  '["factory-splice-in-smoke","factory-splice-out-smoke","factory-reduced-splice-in-smoke","factory-reduced-splice-out-smoke","factory-reduced-xudt-splice-in-smoke","factory-reduced-xudt-splice-out-smoke","factory-xudt-splice-in-smoke","factory-xudt-splice-out-smoke","factory/child-finalise"]' \
  '[]' \
  '["signed_descriptor_evolution","factory_value_delta_binding","typed_asset_binding","budget_regression"]'

write_scenario \
  watchtower_operations \
  watchtower \
  "Watchtower auto-sponsor, direct sponsor, config loop, service stop, health-file, cursor, and stale splice package behavior are recorded." \
  '["smoke/watch-auto-sponsor/watch.json","smoke/watch-auto-sponsor/service.json","smoke/watch-auto-sponsor/service-health.json","smoke/watch-auto-sponsor/watch-alerts.jsonl","smoke/watch-direct-sponsor/watch.json","smoke/watch-direct-sponsor/watch-alerts.jsonl","smoke/watch-config-loop/loop.json","smoke/watch-config-loop/watch-alerts.jsonl","smoke/watch-splice-stale/watch.json","smoke/watch-splice-stale/cursor.json"]' \
  '["watch-auto-sponsor/finalise","watch-direct-sponsor/watch","watch-config-loop/finalise"]' \
  '[]' \
  '["state_authority_authenticity","watchtower_authority_and_cursor"]'

write_scenario \
  extreme_state_value_cases \
  extremes \
  "Asymmetric capacities, one-sided xUDT allocations, tight reduced-right updates, and multi-epoch splice/finalise paths remain valid." \
  '["smoke/xudt-one-sided-smoke.json","smoke/splice-in-asymmetric-smoke.json","smoke/splice-out-asymmetric-smoke.json","smoke/xudt-splice-in-one-sided-smoke.json","smoke/xudt-splice-out-one-sided-smoke.json","smoke/factory-reduced-rights-tight-smoke.json","smoke/factory-merkle-update-tight-smoke.json","smoke/factory-xudt-one-sided/smoke.json","smoke/factory-reduced-xudt-exit-one-sided-smoke.json","smoke/factory-reduced-xudt-splice-in-one-sided-smoke.json","smoke/factory-reduced-xudt-splice-out-one-sided-smoke.json"]' \
  '["xudt-one-sided-smoke","splice-in-asymmetric-smoke","splice-out-asymmetric-smoke","factory-reduced-rights-tight-smoke","factory-merkle-update-tight-smoke","factory-xudt-one-sided/smoke","factory-reduced-xudt-exit-one-sided-smoke"]' \
  '[]' \
  '["typed_asset_binding","budget_regression"]'

write_scenario \
  negative_attack_matrix \
  negative \
  "Known attack-shaped negative paths reject exact script or semantic errors while later scenarios continue to commit." \
  '["smoke/finalise-since-negative-smoke.json","smoke/sponsor-policy-negative-smoke.json","smoke/sponsor-budget-negative-smoke.json","smoke/xudt-negative-smoke.json","smoke/factory-xudt-negative/smoke.json","smoke/factory-reduced-xudt-negative-exit-smoke.json","smoke/splice-negative-smoke.json"]' \
  '[]' \
  '[{"check":"finalise-since-negative-smoke","morph_error":"StateSinceNotMature","error_code":16},{"check":"sponsor-policy-negative-smoke","morph_error":"SponsorStateOutOfRange","error_code":29},{"check":"sponsor-budget-negative-smoke","morph_error":"SponsorFeeTooHigh","error_code":17},{"check":"xudt-negative-smoke","morph_error":"SettlementOutputMismatch","error_code":28},{"check":"factory-xudt-negative/smoke","morph_error":"SettlementOutputMismatch","error_code":28},{"check":"factory-reduced-xudt-negative-exit-smoke","morph_error":"SettlementOutputMismatch","error_code":28}]' \
  '["canonical_relative_maturity","factory_value_delta_binding","typed_asset_binding","sponsor_policy_boundary","negative_recovery_continuity"]'

cat >>"$OUT_DIR/manifest.txt" <<EOF
finished_at_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)
status=passed
EOF

log "summary -> $OUT_DIR/summary.md"
cargo run -q -p morph-cli -- devnet-stateful-report --dir "$OUT_DIR" >"$OUT_DIR/summary.md"
log "summary-json -> $OUT_DIR/summary.json"
cargo run -q -p morph-cli -- devnet-stateful-report --dir "$OUT_DIR" --json >"$OUT_DIR/summary.json"
log "summary-check -> $OUT_DIR/summary-check.json"
cargo run -q -p morph-cli -- devnet-stateful-assert --dir "$OUT_DIR" --budget-profile docs/devnet-stateful-budget.example.json --json >"$OUT_DIR/summary-check.json"

if [ ! -e "$LATEST_LINK" ] || [ -L "$LATEST_LINK" ]; then
  OUT_DIR_ABS="$(cd "$OUT_DIR" && pwd)"
  mkdir -p "$(dirname "$LATEST_LINK")"
  rm -f "$LATEST_LINK"
  ln -s "$OUT_DIR_ABS" "$LATEST_LINK"
  log "latest -> $LATEST_LINK"
else
  log "latest link skipped because $LATEST_LINK exists and is not a symlink"
fi

log "passed; artifacts are in $OUT_DIR"
