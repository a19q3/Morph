#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

RPC_URL="${MORPH_CKB_RPC:-http://127.0.0.1:18114}"
OUT_DIR="${OUT_DIR:-target/devnet-smoke/$(date -u +%Y%m%dT%H%M%SZ)}"
LATEST_LINK="${LATEST_LINK:-target/devnet-smoke/latest}"
MINE_BLOCKS="${MINE_BLOCKS:-4}"

mkdir -p "$OUT_DIR"

if ! command -v jq >/dev/null 2>&1; then
  printf 'missing: jq is required by scripts/devnet-smoke.sh\n' >&2
  exit 1
fi

GIT_COMMIT="$(git rev-parse --short HEAD 2>/dev/null || printf 'unknown')"
if [ -n "$(git status --porcelain --untracked-files=no 2>/dev/null)" ]; then
  GIT_DIRTY="true"
else
  GIT_DIRTY="false"
fi

log() {
  printf '[devnet-smoke] %s\n' "$*"
}

run_log() {
  local name="$1"
  shift
  local path="$OUT_DIR/$name.log"
  log "$name -> $path"
  "$@" >"$path" 2>&1
}

run_json() {
  local name="$1"
  shift
  local path="$OUT_DIR/$name.json"
  log "$name -> $path"
  cargo run -q -p morph-cli -- "$@" --json >"$path"
}

cat >"$OUT_DIR/manifest.txt" <<EOF
rpc_url=$RPC_URL
started_at_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)
mine_blocks=$MINE_BLOCKS
git_commit=$GIT_COMMIT
git_dirty=$GIT_DIRTY
EOF

run_log check-devnet-env scripts/check-devnet-env.sh
run_log validate-fixture cargo run -q -p morph-cli -- validate-fixture
run_log cargo-test cargo test --workspace
run_log contract-tests make contract-tests

run_json devnet-check devnet --rpc-url "$RPC_URL" check
run_json devnet-mine devnet --rpc-url "$RPC_URL" mine --blocks "$MINE_BLOCKS"
run_json deploy-contracts devnet --rpc-url "$RPC_URL" deploy-contracts
run_json supersede-smoke devnet --rpc-url "$RPC_URL" supersede-smoke
run_json finalise-since-negative-smoke devnet --rpc-url "$RPC_URL" finalise-since-negative-smoke
run_json sponsor-policy-negative-smoke devnet --rpc-url "$RPC_URL" sponsor-policy-negative-smoke
run_json sponsor-budget-negative-smoke devnet --rpc-url "$RPC_URL" sponsor-budget-negative-smoke
run_json competing-spend-smoke devnet --rpc-url "$RPC_URL" competing-spend-smoke
run_json xudt-smoke devnet --rpc-url "$RPC_URL" xudt-smoke
run_json xudt-negative-smoke devnet --rpc-url "$RPC_URL" xudt-negative-smoke

FACTORY_DIR="$OUT_DIR/factory"
mkdir -p "$FACTORY_DIR"
log "factory-open -> $FACTORY_DIR/open.json"
cargo run -q -p morph-cli -- devnet --rpc-url "$RPC_URL" open-factory --json >"$FACTORY_DIR/open.json"
FACTORY_OUT_POINT="$(jq -r '.cells[] | select(.role == "factory") | .out_point.tx_hash + ":" + (.out_point.index | tostring)' "$FACTORY_DIR/open.json")"
FACTORY_VAULT_OUT_POINT="$(jq -r '.cells[] | select(.role == "factory-vault") | .out_point.tx_hash + ":" + (.out_point.index | tostring)' "$FACTORY_DIR/open.json")"
FACTORY_ID="$(jq -r '.factory_id' "$FACTORY_DIR/open.json")"

log "factory-save-package -> $FACTORY_DIR/package.json"
cargo run -q -p morph-cli -- devnet --rpc-url "$RPC_URL" save-factory-state-package \
  --factory-out-point "$FACTORY_OUT_POINT" \
  --store-dir "$FACTORY_DIR/packages" \
  --json >"$FACTORY_DIR/package.json"
FACTORY_PACKAGE_PATH="$(jq -r '.path' "$FACTORY_DIR/package.json")"

log "factory-latest-package -> $FACTORY_DIR/latest-package.json"
cargo run -q -p morph-cli -- devnet --rpc-url "$RPC_URL" latest-factory-state-package \
  --factory-id "$FACTORY_ID" \
  --store-dir "$FACTORY_DIR/packages" \
  --json >"$FACTORY_DIR/latest-package.json"

log "factory-update -> $FACTORY_DIR/update.json"
cargo run -q -p morph-cli -- devnet --rpc-url "$RPC_URL" update-factory \
  --factory-out-point "$FACTORY_OUT_POINT" \
  --factory-state-package "$FACTORY_PACKAGE_PATH" \
  --json >"$FACTORY_DIR/update.json"
FACTORY_OUT_POINT_AFTER_UPDATE="$(jq -r '.factory_out_point.tx_hash + ":" + (.factory_out_point.index | tostring)' "$FACTORY_DIR/update.json")"

log "factory-exit-channel -> $FACTORY_DIR/exit-channel.json"
cargo run -q -p morph-cli -- devnet --rpc-url "$RPC_URL" factory-exit-channel \
  --factory-out-point "$FACTORY_OUT_POINT_AFTER_UPDATE" \
  --factory-vault-out-point "$FACTORY_VAULT_OUT_POINT" \
  --json >"$FACTORY_DIR/exit-channel.json"
log "factory-local-exit-package -> $FACTORY_DIR/local-exit-package.json"
jq '.local_exit_package' "$FACTORY_DIR/exit-channel.json" >"$FACTORY_DIR/local-exit-package.json"
log "factory-local-exit-package-check -> $FACTORY_DIR/local-exit-package-check.json"
cargo run -q -p morph-cli -- validate-factory-local-exit-package \
  "$FACTORY_DIR/local-exit-package.json" \
  --json >"$FACTORY_DIR/local-exit-package-check.json"
FACTORY_CHILD_STATE_OUT_POINT="$(jq -r '.state_out_point.tx_hash + ":" + (.state_out_point.index | tostring)' "$FACTORY_DIR/exit-channel.json")"
FACTORY_CHILD_VAULT_OUT_POINT="$(jq -r '.vault_out_point.tx_hash + ":" + (.vault_out_point.index | tostring)' "$FACTORY_DIR/exit-channel.json")"
FACTORY_CHILD_SPONSOR_OUT_POINT="$(jq -r '.sponsor_out_point.tx_hash + ":" + (.sponsor_out_point.index | tostring)' "$FACTORY_DIR/exit-channel.json")"

log "factory-child-publish -> $FACTORY_DIR/child-publish.json"
cargo run -q -p morph-cli -- devnet --rpc-url "$RPC_URL" publish-state \
  --state-out-point "$FACTORY_CHILD_STATE_OUT_POINT" \
  --sponsor-out-point "$FACTORY_CHILD_SPONSOR_OUT_POINT" \
  --json >"$FACTORY_DIR/child-publish.json"
FACTORY_CHILD_PUBLISHED_STATE_OUT_POINT="$(jq -r '.state_out_point.tx_hash + ":" + (.state_out_point.index | tostring)' "$FACTORY_DIR/child-publish.json")"

log "factory-child-finalise -> $FACTORY_DIR/child-finalise.json"
cargo run -q -p morph-cli -- devnet --rpc-url "$RPC_URL" finalise-channel \
  --state-out-point "$FACTORY_CHILD_PUBLISHED_STATE_OUT_POINT" \
  --vault-out-point "$FACTORY_CHILD_VAULT_OUT_POINT" \
  --json >"$FACTORY_DIR/child-finalise.json"

FACTORY_XUDT_DIR="$OUT_DIR/factory-xudt"
mkdir -p "$FACTORY_XUDT_DIR"
log "factory-xudt-smoke -> $FACTORY_XUDT_DIR/smoke.json"
cargo run -q -p morph-cli -- devnet --rpc-url "$RPC_URL" factory-xudt-smoke \
  --store-dir "$FACTORY_XUDT_DIR/packages" \
  --json >"$FACTORY_XUDT_DIR/smoke.json"
log "factory-xudt-local-exit-package -> $FACTORY_XUDT_DIR/local-exit-package.json"
jq '.exit.local_exit_package' "$FACTORY_XUDT_DIR/smoke.json" >"$FACTORY_XUDT_DIR/local-exit-package.json"
log "factory-xudt-local-exit-package-check -> $FACTORY_XUDT_DIR/local-exit-package-check.json"
cargo run -q -p morph-cli -- validate-factory-local-exit-package \
  "$FACTORY_XUDT_DIR/local-exit-package.json" \
  --json >"$FACTORY_XUDT_DIR/local-exit-package-check.json"

FACTORY_XUDT_NEGATIVE_DIR="$OUT_DIR/factory-xudt-negative"
mkdir -p "$FACTORY_XUDT_NEGATIVE_DIR"
log "factory-xudt-negative-smoke -> $FACTORY_XUDT_NEGATIVE_DIR/smoke.json"
cargo run -q -p morph-cli -- devnet --rpc-url "$RPC_URL" factory-xudt-negative-smoke \
  --store-dir "$FACTORY_XUDT_NEGATIVE_DIR/packages" \
  --json >"$FACTORY_XUDT_NEGATIVE_DIR/smoke.json"
log "factory-xudt-negative-local-exit-package -> $FACTORY_XUDT_NEGATIVE_DIR/local-exit-package.json"
jq '.exit.local_exit_package' "$FACTORY_XUDT_NEGATIVE_DIR/smoke.json" >"$FACTORY_XUDT_NEGATIVE_DIR/local-exit-package.json"
log "factory-xudt-negative-local-exit-package-check -> $FACTORY_XUDT_NEGATIVE_DIR/local-exit-package-check.json"
cargo run -q -p morph-cli -- validate-factory-local-exit-package \
  "$FACTORY_XUDT_NEGATIVE_DIR/local-exit-package.json" \
  --json >"$FACTORY_XUDT_NEGATIVE_DIR/local-exit-package-check.json"

WATCH_DIR="$OUT_DIR/watch-auto-sponsor"
mkdir -p "$WATCH_DIR"
WATCH_DIR_ABS="$(cd "$WATCH_DIR" && pwd)"
log "watch-auto-sponsor-open -> $WATCH_DIR/open.json"
cargo run -q -p morph-cli -- devnet --rpc-url "$RPC_URL" open-channel --json >"$WATCH_DIR/open.json"
STATE_OUT_POINT="$(jq -r '.cells[] | select(.role == "state") | .out_point.tx_hash + ":" + (.out_point.index | tostring)' "$WATCH_DIR/open.json")"
VAULT_OUT_POINT="$(jq -r '.cells[] | select(.role == "vault") | .out_point.tx_hash + ":" + (.out_point.index | tostring)' "$WATCH_DIR/open.json")"
CHANNEL_ID="$(jq -r '.channel_id' "$WATCH_DIR/open.json")"
OPEN_BLOCK="$(jq -r '.block_number' "$WATCH_DIR/open.json")"

log "watch-auto-sponsor-package -> $WATCH_DIR/package.json"
cargo run -q -p morph-cli -- devnet --rpc-url "$RPC_URL" save-state-package \
  --state-out-point "$STATE_OUT_POINT" \
  --state-number 2 \
  --store-dir "$WATCH_DIR/packages" \
  --json >"$WATCH_DIR/package.json"

log "watch-auto-sponsor-policy -> $WATCH_DIR/watch-policy.json"
cargo run -q -p morph-cli -- print-watch-policy-fixture >"$WATCH_DIR/watch-policy.json"

log "watch-auto-sponsor-config -> $WATCH_DIR/watch-config.json"
jq -n \
  --arg channel_id "$CHANNEL_ID" \
  --argjson from_block "$OPEN_BLOCK" \
  --arg store_dir "$WATCH_DIR_ABS/packages" \
  --arg watch_policy "$WATCH_DIR_ABS/watch-policy.json" \
  --arg alert_file "$WATCH_DIR_ABS/watch-alerts.jsonl" \
  '{
    schema: "morph.watchtower_config.v1",
    defaults: {
      store_dir: $store_dir,
      watch_policy: $watch_policy,
      alert_file: $alert_file,
      detection_depth: 3,
      timeout_secs: 30,
      poll_ms: 250,
      fee: 100000000,
      mine_blocks: 4,
      auto_fund_sponsor: true,
      auto_sponsor_capacity: 50000000000
    },
    channels: [{
      channel_id: $channel_id,
      from_block: $from_block
    }]
  }' >"$WATCH_DIR/watch-config.json"

log "watch-auto-sponsor-config-check -> $WATCH_DIR/watch-config-check.json"
cargo run -q -p morph-cli -- validate-watch-config \
  "$WATCH_DIR/watch-config.json" \
  --json >"$WATCH_DIR/watch-config-check.json"

log "watch-auto-sponsor-depth -> $WATCH_DIR/depth.json"
cargo run -q -p morph-cli -- devnet --rpc-url "$RPC_URL" mine \
  --blocks 3 \
  --json >"$WATCH_DIR/depth.json"

log "watch-auto-sponsor-publish -> $WATCH_DIR/watch.json"
cargo run -q -p morph-cli -- devnet --rpc-url "$RPC_URL" watch-config-once \
  --config "$WATCH_DIR/watch-config.json" \
  --json >"$WATCH_DIR/watch.json"

PUBLISHED_STATE_OUT_POINT="$(jq -r '.channels[0].report.publication.state_out_point.tx_hash + ":" + (.channels[0].report.publication.state_out_point.index | tostring)' "$WATCH_DIR/watch.json")"
log "watch-auto-sponsor-finalise -> $WATCH_DIR/finalise.json"
cargo run -q -p morph-cli -- devnet --rpc-url "$RPC_URL" finalise-channel \
  --state-out-point "$PUBLISHED_STATE_OUT_POINT" \
  --vault-out-point "$VAULT_OUT_POINT" \
  --json >"$WATCH_DIR/finalise.json"

cat >>"$OUT_DIR/manifest.txt" <<EOF
finished_at_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)
status=passed
EOF

log "summary -> $OUT_DIR/summary.md"
cargo run -q -p morph-cli -- devnet-smoke-report --dir "$OUT_DIR" >"$OUT_DIR/summary.md"
log "summary-json -> $OUT_DIR/summary.json"
cargo run -q -p morph-cli -- devnet-smoke-report --dir "$OUT_DIR" --json >"$OUT_DIR/summary.json"
log "summary-check -> $OUT_DIR/summary-check.json"
cargo run -q -p morph-cli -- devnet-smoke-assert --dir "$OUT_DIR" --json >"$OUT_DIR/summary-check.json"

if [ ! -e "$LATEST_LINK" ] || [ -L "$LATEST_LINK" ]; then
  OUT_DIR_ABS="$(cd "$OUT_DIR" && pwd)"
  mkdir -p "$(dirname "$LATEST_LINK")"
  rm -f "$LATEST_LINK"
  ln -s "$OUT_DIR_ABS" "$LATEST_LINK"
  log "latest -> $LATEST_LINK"
else
  log "latest link skipped because $LATEST_LINK exists and is not a symlink"
fi

log "passed; artefacts are in $OUT_DIR"
