#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEFAULT_BASE_DIR="$ROOT_DIR/target/fiber-morph-devnet-acceptance"

log() {
  printf '[fiber-morph-audit] %s\n' "$*"
}

fail() {
  printf '[fiber-morph-audit] error: %s\n' "$*" >&2
  exit 1
}

require_tool() {
  local name="$1"
  command -v "$name" >/dev/null 2>&1 || fail "missing required tool: $name"
}

resolve_run_dir() {
  local requested="${1:-}"
  if [ -z "$requested" ]; then
    [ -d "$DEFAULT_BASE_DIR" ] || fail "no acceptance run directory found under $DEFAULT_BASE_DIR"
    requested="$(find "$DEFAULT_BASE_DIR" -mindepth 1 -maxdepth 1 -type d | sort | tail -1)"
    [ -n "$requested" ] || fail "no acceptance run directory found under $DEFAULT_BASE_DIR"
  fi

  case "$requested" in
    /*) printf '%s\n' "$requested" ;;
    *) printf '%s\n' "$ROOT_DIR/$requested" ;;
  esac
}

require_file() {
  local path="$1"
  [ -s "$path" ] || fail "missing or empty file: $path"
}

jq_check() {
  local path="$1"
  local expression="$2"
  local description="$3"
  jq -e "$expression" "$path" >/dev/null || fail "$description ($path)"
}

require_manifest_status() {
  local path="$1"
  grep -qx 'status=passed' "$path" || fail "manifest does not contain status=passed: $path"
}

require_morph_scenario() {
  local path="$1"
  local scenario_id="$2"
  jq -e --arg scenario_id "$scenario_id" \
    '.scenarios[] | select(.scenario_id == $scenario_id)' "$path" >/dev/null ||
    fail "missing required Morph scenario: $scenario_id"
}

require_audit_family() {
  local path="$1"
  local family_id="$2"
  jq -e --arg family_id "$family_id" \
    '.audit_families[] | select(.id == $family_id and .passed == true)' "$path" >/dev/null ||
    fail "missing or failing Morph audit family: $family_id"
}

require_fiber_result() {
  local run_dir="$1"
  local file_name="$2"
  local suite="$3"
  local path="$run_dir/$file_name"
  require_file "$path"
  jq -e --arg suite "$suite" \
    '.suite == $suite and .status == "passed" and (.log | type == "string" and length > 0)' \
    "$path" >/dev/null || fail "Fiber suite did not pass with expected suite id: $suite"

  local log_path
  log_path="$(jq -r '.log' "$path")"
  case "$log_path" in
    /*) ;;
    *) log_path="$run_dir/$log_path" ;;
  esac
  require_file "$log_path"
}

verify_morph_stateful() {
  local run_dir="$1"
  local summary_check="$run_dir/morph-stateful/scenarios/summary-check.json"
  local summary="$run_dir/morph-stateful/scenarios/summary.json"

  require_file "$summary_check"
  require_file "$summary"

  jq_check "$summary_check" '.scenario_count >= 9' 'Morph stateful scenario count is below the strict matrix'
  jq_check "$summary_check" '.required_scenarios >= 9' 'Morph required scenario count is incomplete'
  jq_check "$summary_check" '.audit_families >= 11' 'Morph audit family count is incomplete'
  jq_check "$summary_check" '.audit_families_passed == .audit_families' 'not all Morph audit families passed'
  jq_check "$summary_check" '(.unknown_coverage_tags | length) == 0' 'Morph summary has unknown coverage tags'
  jq_check "$summary_check" '.referenced_artifacts >= 87' 'Morph referenced artifact evidence is below the strict floor'
  jq_check "$summary_check" '.required_committed_checks >= 62' 'Morph committed check evidence is below the strict floor'
  jq_check "$summary_check" '.expected_failures >= 9' 'Morph negative-path evidence is below the strict floor'
  jq_check "$summary_check" '.smoke.transaction_count >= 190' 'Morph committed transaction matrix is below the strict floor'
  jq_check "$summary_check" '.smoke.committed_count >= 190' 'Morph committed transaction count is below the strict floor'
  jq_check "$summary_check" '.smoke.deployed_script_hashes_verified == true' 'Morph deployed script hashes were not verified'
  jq_check "$summary_check" '.smoke.watchtower_alerts >= 9' 'Morph watchtower alert evidence is incomplete'
  jq_check "$summary_check" '.smoke.factory_reduced_rights_updates >= 4' 'Morph reduced-rights update evidence is incomplete'
  jq_check "$summary_check" '.smoke.factory_merkle_updates >= 4' 'Morph sparse Merkle update evidence is incomplete'
  jq_check "$summary_check" '.smoke.factory_reduced_exits >= 5' 'Morph reduced-exit evidence is incomplete'
  jq_check "$summary_check" '.smoke.factory_local_exits >= 24' 'Morph local-exit evidence is incomplete'
  jq_check "$summary_check" '.smoke.factory_splices >= 32' 'Morph factory splice evidence is incomplete'
  jq_check "$summary_check" '.smoke.splice_payouts >= 9' 'Morph splice payout evidence is incomplete'
  jq_check "$summary" '(.scenarios | length) >= 9' 'Morph scenario summary is incomplete'
  jq_check "$summary" '(.audit_families | length) >= 11' 'Morph audit family summary is incomplete'

  local scenario
  for scenario in \
    bilateral_direct_publish_finalise \
    bilateral_supersede_watchtower_finalise \
    sponsor_fee_pressure \
    splice_lifecycle_matrix \
    factory_lifecycle_matrix \
    factory_splice_then_exit \
    watchtower_operations \
    extreme_state_value_cases \
    negative_attack_matrix
  do
    require_morph_scenario "$summary" "$scenario"
  done

  local family
  for family in \
    state_authority_authenticity \
    canonical_relative_maturity \
    state_retirement_non_orphaning \
    signed_descriptor_evolution \
    non_interference_not_authorisation \
    factory_value_delta_binding \
    typed_asset_binding \
    sponsor_policy_boundary \
    watchtower_authority_and_cursor \
    negative_recovery_continuity \
    budget_regression
  do
    require_audit_family "$summary" "$family"
  done
}

write_report() {
  local run_dir="$1"
  local mode="$2"
  local include_morph="$3"
  local include_coexistence_fiber="$4"
  local include_extended_fiber="$5"
  local report="$run_dir/business-flow-audit.json"
  local audited_at_utc
  audited_at_utc="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

  jq -n \
    --arg run_dir "$run_dir" \
    --arg mode "$mode" \
    --arg audited_at_utc "$audited_at_utc" \
    --arg manifest "$run_dir/manifest.txt" \
    --arg repo_state "$run_dir/repo-state.json" \
    --arg summary "$run_dir/summary.json" \
    --arg matrix "$run_dir/acceptance-matrix.json" \
    --arg morph_summary_check "$run_dir/morph-stateful/scenarios/summary-check.json" \
    --arg morph_summary "$run_dir/morph-stateful/scenarios/summary.json" \
    --arg fiber_external "$run_dir/fiber-bruno-e2e_external-funding-open.json" \
    --arg fiber_restart "$run_dir/fiber-external-funding-restart.json" \
    --arg fiber_open_close "$run_dir/fiber-bruno-e2e_open-use-close-a-channel.json" \
    --arg fiber_three_nodes "$run_dir/fiber-bruno-e2e_3-nodes-transfer.json" \
    --arg fiber_udt "$run_dir/fiber-bruno-e2e_udt.json" \
    --arg fiber_udt_router "$run_dir/fiber-bruno-e2e_udt-router-pay.json" \
    --argjson include_morph "$include_morph" \
    --argjson include_coexistence_fiber "$include_coexistence_fiber" \
    --argjson include_extended_fiber "$include_extended_fiber" \
    '{
      schema: "morph.fiber_morph_business_flow_audit",
      status: "passed",
      mode: $mode,
      audited_at_utc: $audited_at_utc,
      run_dir: $run_dir,
      evidence: {
        manifest: $manifest,
        repo_state: $repo_state,
        summary: $summary,
        acceptance_matrix: $matrix,
        morph_stateful_summary_check: (if $include_morph == 1 then $morph_summary_check else null end),
        morph_stateful_summary: (if $include_morph == 1 then $morph_summary else null end)
      },
      business_flows:
        (
          (if $include_morph == 1 and $include_coexistence_fiber == 1 then [
            {
              id: "same_ckb_devnet_coexistence",
              system: "cross_repo",
              description: "Morph stateful acceptance and Fiber external funding execute against the same local CKB devnet.",
              evidence: [$matrix, $morph_summary_check, $fiber_external]
            }
          ] else [] end)
          + (if $include_morph == 1 then [
            {id: "morph_bilateral_direct_publish_finalise", system: "morph", scenario_id: "bilateral_direct_publish_finalise", evidence: [$morph_summary]},
            {id: "morph_bilateral_supersede_watchtower_finalise", system: "morph", scenario_id: "bilateral_supersede_watchtower_finalise", evidence: [$morph_summary]},
            {id: "morph_sponsor_fee_pressure", system: "morph", scenario_id: "sponsor_fee_pressure", evidence: [$morph_summary]},
            {id: "morph_splice_lifecycle_matrix", system: "morph", scenario_id: "splice_lifecycle_matrix", evidence: [$morph_summary]},
            {id: "morph_factory_lifecycle_matrix", system: "morph", scenario_id: "factory_lifecycle_matrix", evidence: [$morph_summary]},
            {id: "morph_factory_splice_then_exit", system: "morph", scenario_id: "factory_splice_then_exit", evidence: [$morph_summary]},
            {id: "morph_watchtower_operations", system: "morph", scenario_id: "watchtower_operations", evidence: [$morph_summary]},
            {id: "morph_extreme_state_value_cases", system: "morph", scenario_id: "extreme_state_value_cases", evidence: [$morph_summary]},
            {id: "morph_negative_attack_matrix", system: "morph", scenario_id: "negative_attack_matrix", evidence: [$morph_summary]}
          ] else [] end)
          + (if $include_coexistence_fiber == 1 then [
            {id: "fiber_external_funding_open", system: "fiber", suite: "e2e/external-funding-open", evidence: [$fiber_external]},
            {id: "fiber_external_funding_restart", system: "fiber", suite: "e2e/external-funding-open/restart", evidence: [$fiber_restart]}
          ] else [] end)
          + (if $include_extended_fiber == 1 then [
            {id: "fiber_open_use_close_channel", system: "fiber", suite: "e2e/open-use-close-a-channel", evidence: [$fiber_open_close]},
            {id: "fiber_three_node_transfer", system: "fiber", suite: "e2e/3-nodes-transfer", evidence: [$fiber_three_nodes]},
            {id: "fiber_udt_channel_flow", system: "fiber", suite: "e2e/udt", evidence: [$fiber_udt]},
            {id: "fiber_udt_router_pay", system: "fiber", suite: "e2e/udt-router-pay", evidence: [$fiber_udt_router]}
          ] else [] end)
        ),
      security_families:
        (if $include_morph == 1 then [
          {id: "state_authority_authenticity", severity: "P0", evidence: [$morph_summary]},
          {id: "canonical_relative_maturity", severity: "P0", evidence: [$morph_summary]},
          {id: "state_retirement_non_orphaning", severity: "P0", evidence: [$morph_summary]},
          {id: "signed_descriptor_evolution", severity: "P0", evidence: [$morph_summary]},
          {id: "non_interference_not_authorisation", severity: "P0", evidence: [$morph_summary]},
          {id: "factory_value_delta_binding", severity: "P0", evidence: [$morph_summary]},
          {id: "typed_asset_binding", severity: "P0", evidence: [$morph_summary]},
          {id: "sponsor_policy_boundary", severity: "P1", evidence: [$morph_summary]},
          {id: "watchtower_authority_and_cursor", severity: "P2", evidence: [$morph_summary]},
          {id: "negative_recovery_continuity", severity: "P1", evidence: [$morph_summary]},
          {id: "budget_regression", severity: "P2", evidence: [$morph_summary]}
        ] else [] end),
      minimum_evidence:
        (if $include_morph == 1 then {
          morph_scenarios: 9,
          morph_security_families: 11,
          morph_referenced_artifacts: 87,
          morph_committed_checks: 62,
          morph_expected_failures: 9,
          morph_committed_transactions: 190,
          morph_factory_splices: 32,
          morph_factory_local_exits: 24,
          morph_watchtower_alerts: 9
        } else {} end)
    }' >"$report"

  log "business-flow audit -> $report"
}

main() {
  require_tool jq
  require_tool grep
  require_tool find
  require_tool sort
  require_tool tail

  local run_dir
  run_dir="$(resolve_run_dir "${1:-}")"
  [ -d "$run_dir" ] || fail "acceptance run directory does not exist: $run_dir"

  local manifest="$run_dir/manifest.txt"
  local repo_state="$run_dir/repo-state.json"
  local matrix="$run_dir/acceptance-matrix.json"
  local summary="$run_dir/summary.json"

  require_file "$manifest"
  require_file "$repo_state"
  require_file "$matrix"
  require_file "$summary"

  require_manifest_status "$manifest"
  jq_check "$summary" '.schema == "morph.fiber_morph_devnet_acceptance_summary" and .status == "passed"' 'top-level acceptance summary did not pass'
  jq_check "$matrix" '.schema == "morph.fiber_morph_devnet_acceptance_matrix"' 'acceptance matrix schema mismatch'
  jq_check "$repo_state" '.schema == "morph.fiber_morph_repo_state"' 'repo-state schema mismatch'
  jq_check "$repo_state" '.morph.status == ""' 'Morph worktree was not clean when the run recorded repo state'
  jq_check "$repo_state" '.fiber.status == ""' 'Fiber tracked worktree was not clean when the run recorded repo state'

  local mode
  mode="$(jq -r '.mode // empty' "$matrix")"

  local include_morph=0
  local include_coexistence_fiber=0
  local include_extended_fiber=0
  case "$mode" in
    coexistence)
      include_morph=1
      include_coexistence_fiber=1
      ;;
    full)
      include_morph=1
      include_coexistence_fiber=1
      include_extended_fiber=1
      ;;
    fiber)
      include_extended_fiber=1
      ;;
    *)
      fail "unsupported acceptance audit mode: ${mode:-<empty>}"
      ;;
  esac

  if [ "$include_morph" = "1" ]; then
    verify_morph_stateful "$run_dir"
  fi

  if [ "$include_coexistence_fiber" = "1" ]; then
    require_fiber_result "$run_dir" "fiber-bruno-e2e_external-funding-open.json" "e2e/external-funding-open"
    require_fiber_result "$run_dir" "fiber-external-funding-restart.json" "e2e/external-funding-open/restart"
  fi

  if [ "$include_extended_fiber" = "1" ]; then
    require_fiber_result "$run_dir" "fiber-bruno-e2e_open-use-close-a-channel.json" "e2e/open-use-close-a-channel"
    require_fiber_result "$run_dir" "fiber-bruno-e2e_3-nodes-transfer.json" "e2e/3-nodes-transfer"
    require_fiber_result "$run_dir" "fiber-bruno-e2e_udt.json" "e2e/udt"
    require_fiber_result "$run_dir" "fiber-bruno-e2e_udt-router-pay.json" "e2e/udt-router-pay"
  fi

  write_report "$run_dir" "$mode" "$include_morph" "$include_coexistence_fiber" "$include_extended_fiber"
  log "audit passed for $mode run: $run_dir"
}

main "$@"
