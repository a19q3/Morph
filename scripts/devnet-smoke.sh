#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

RPC_URL="${MORPH_CKB_RPC:-http://127.0.0.1:18114}"
OUT_DIR="${OUT_DIR:-target/devnet-smoke/$(date -u +%Y%m%dT%H%M%SZ)}"
MINE_BLOCKS="${MINE_BLOCKS:-1}"

mkdir -p "$OUT_DIR"

if ! command -v jq >/dev/null 2>&1; then
  printf 'missing: jq is required by scripts/devnet-smoke.sh\n' >&2
  exit 1
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

WATCH_DIR="$OUT_DIR/watch-auto-sponsor"
mkdir -p "$WATCH_DIR"
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

log "watch-auto-sponsor-publish -> $WATCH_DIR/watch.json"
cargo run -q -p morph-cli -- devnet --rpc-url "$RPC_URL" watch-latest-package \
  --channel-id "$CHANNEL_ID" \
  --from-block "$OPEN_BLOCK" \
  --store-dir "$WATCH_DIR/packages" \
  --detection-depth 3 \
  --auto-fund-sponsor \
  --watch-policy "$WATCH_DIR/watch-policy.json" \
  --alert-file "$WATCH_DIR/watch-alerts.jsonl" \
  --timeout-secs 30 \
  --poll-ms 250 \
  --json >"$WATCH_DIR/watch.json"

PUBLISHED_STATE_OUT_POINT="$(jq -r '.publication.state_out_point.tx_hash + ":" + (.publication.state_out_point.index | tostring)' "$WATCH_DIR/watch.json")"
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

log "passed; artefacts are in $OUT_DIR"
