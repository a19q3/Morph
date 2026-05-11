#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

RPC_URL="${MORPH_CKB_RPC:-http://127.0.0.1:18114}"
OUT_DIR="${OUT_DIR:-target/devnet-smoke/$(date -u +%Y%m%dT%H%M%SZ)}"
MINE_BLOCKS="${MINE_BLOCKS:-1}"

mkdir -p "$OUT_DIR"

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
run_json sponsor-policy-negative-smoke devnet --rpc-url "$RPC_URL" sponsor-policy-negative-smoke

cat >>"$OUT_DIR/manifest.txt" <<EOF
finished_at_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)
status=passed
EOF

log "passed; artefacts are in $OUT_DIR"
