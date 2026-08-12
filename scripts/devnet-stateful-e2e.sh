#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

CKB_SOURCE_DIR="${CKB_SOURCE_DIR:-$ROOT_DIR/../ckb}"
CKB_BUILD_PROFILE="${CKB_BUILD_PROFILE:-debug}"
CKB_BIN="${CKB_BIN:-}"
RPC_PORT="${RPC_PORT:-18114}"
P2P_PORT="${P2P_PORT:-18115}"
RPC_URL="http://127.0.0.1:$RPC_PORT"
RUN_ID="${RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
E2E_DIR="${E2E_DIR:-target/devnet-stateful-e2e/$RUN_ID}"
CKB_DIR="${CKB_DIR:-$E2E_DIR/node}"
OUT_DIR="${OUT_DIR:-$E2E_DIR/scenarios}"
LOG_DIR="$E2E_DIR/logs"
LATEST_LINK="${LATEST_LINK:-target/devnet-stateful-e2e/latest}"
MINE_BLOCKS="${MINE_BLOCKS:-4}"
BUDGET_PROFILE="${BUDGET_PROFILE:-docs/devnet-stateful-budget.example.json}"
BUILD_CONTRACTS="${BUILD_CONTRACTS:-1}"
KEEP_NODE="${KEEP_NODE:-0}"
FIBER_DIR="${FIBER_DIR:-$ROOT_DIR/../fiber}"
MORPH_E2E_DEPLOYER_KEY_FILE="${MORPH_E2E_DEPLOYER_KEY_FILE:-$FIBER_DIR/tests/nodes/deployer/ckb/plain_key}"
MORPH_E2E_ALICE_KEY_FILE="${MORPH_E2E_ALICE_KEY_FILE:-$FIBER_DIR/tests/nodes/1/ckb/plain_key}"
MORPH_E2E_BOB_KEY_FILE="${MORPH_E2E_BOB_KEY_FILE:-$FIBER_DIR/tests/nodes/2/ckb/plain_key}"
CKB_NODE_PID=""

log() {
  printf '[devnet-stateful-e2e] %s\n' "$*"
}

fail() {
  printf '[devnet-stateful-e2e] error: %s\n' "$*" >&2
  exit 1
}

require_tool() {
  local name="$1"
  if ! command -v "$name" >/dev/null 2>&1; then
    fail "missing required tool: $name"
  fi
}

load_devnet_fixture_key() {
  local variable="$1"
  local path="$2"
  local label="$3"
  local current="${!variable:-}"
  if [ -n "$current" ]; then
    [[ "$current" =~ ^(0x)?[0-9a-fA-F]{64}$ ]] ||
      fail "$variable must contain exactly one 32-byte secp256k1 key"
    return
  fi
  [ -f "$path" ] ||
    fail "missing $label devnet fixture key: set $variable or provide $path"
  local loaded
  loaded="$(tr -d '\r\n' <"$path")"
  [[ "$loaded" =~ ^(0x)?[0-9a-fA-F]{64}$ ]] ||
    fail "$label devnet fixture key file must contain exactly one 32-byte secp256k1 key: $path"
  printf -v "$variable" '%s' "$loaded"
  export "$variable"
}

resolve_ckb_bin() {
  if [ -n "$CKB_BIN" ]; then
    [ -x "$CKB_BIN" ] || fail "CKB_BIN is not executable: $CKB_BIN"
    return
  fi

  for candidate in \
    "$CKB_SOURCE_DIR/target/release/ckb" \
    "$CKB_SOURCE_DIR/target/debug/ckb"
  do
    if [ -x "$candidate" ]; then
      CKB_BIN="$candidate"
      return
    fi
  done

  if [ ! -f "$CKB_SOURCE_DIR/Cargo.toml" ]; then
    fail "cannot find CKB binary and CKB_SOURCE_DIR is not a Cargo workspace: $CKB_SOURCE_DIR"
  fi

  log "building CKB from $CKB_SOURCE_DIR with profile=$CKB_BUILD_PROFILE"
  if [ "$CKB_BUILD_PROFILE" = "release" ]; then
    cargo build --manifest-path "$CKB_SOURCE_DIR/Cargo.toml" --release -p ckb
    CKB_BIN="$CKB_SOURCE_DIR/target/release/ckb"
  else
    cargo build --manifest-path "$CKB_SOURCE_DIR/Cargo.toml" -p ckb
    CKB_BIN="$CKB_SOURCE_DIR/target/debug/ckb"
  fi
  [ -x "$CKB_BIN" ] || fail "CKB build did not produce executable: $CKB_BIN"
}

port_is_free() {
  local port="$1"
  if command -v lsof >/dev/null 2>&1; then
    ! lsof -nP -iTCP:"$port" -sTCP:LISTEN >/dev/null 2>&1
  else
    ! nc -z 127.0.0.1 "$port" >/dev/null 2>&1
  fi
}

wait_for_rpc() {
  local deadline=$((SECONDS + 90))
  local body='{"id":1,"jsonrpc":"2.0","method":"get_tip_header","params":[]}'
  while [ "$SECONDS" -lt "$deadline" ]; do
    if curl -fsS \
      -H 'content-type: application/json' \
      -d "$body" \
      "$RPC_URL" |
      jq -e '.result != null' >/dev/null 2>&1
    then
      return
    fi
    if ! kill -0 "$CKB_NODE_PID" >/dev/null 2>&1; then
      fail "CKB node exited before RPC became ready; see $LOG_DIR/ckb-node.log"
    fi
    sleep 1
  done
  fail "timed out waiting for CKB RPC at $RPC_URL; see $LOG_DIR/ckb-node.log"
}

stop_node() {
  if [ -n "$CKB_NODE_PID" ] && kill -0 "$CKB_NODE_PID" >/dev/null 2>&1; then
    if [ "$KEEP_NODE" = "1" ]; then
      log "leaving CKB node running: pid=$CKB_NODE_PID rpc=$RPC_URL ckb_dir=$CKB_DIR"
      return
    fi
    log "stopping CKB node pid=$CKB_NODE_PID"
    kill "$CKB_NODE_PID" >/dev/null 2>&1 || true
    wait "$CKB_NODE_PID" >/dev/null 2>&1 || true
  fi
}

trap stop_node EXIT

require_tool jq
require_tool curl
load_devnet_fixture_key MORPH_DEVNET_PRIVATE_KEY "$MORPH_E2E_DEPLOYER_KEY_FILE" deployer
load_devnet_fixture_key MORPH_ALICE_PRIVATE_KEY "$MORPH_E2E_ALICE_KEY_FILE" Alice
load_devnet_fixture_key MORPH_BOB_PRIVATE_KEY "$MORPH_E2E_BOB_KEY_FILE" Bob
resolve_ckb_bin

if [ -e "$CKB_DIR" ]; then
  fail "CKB_DIR already exists: $CKB_DIR. Use a new RUN_ID/E2E_DIR or remove it explicitly."
fi
if ! port_is_free "$RPC_PORT"; then
  fail "RPC_PORT is already in use: $RPC_PORT"
fi
if ! port_is_free "$P2P_PORT"; then
  fail "P2P_PORT is already in use: $P2P_PORT"
fi

mkdir -p "$LOG_DIR" "$OUT_DIR"

cat >"$E2E_DIR/manifest.txt" <<EOF
schema=morph.real_devnet_stateful_e2e
started_at_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)
run_id=$RUN_ID
root_dir=$ROOT_DIR
ckb_source_dir=$CKB_SOURCE_DIR
ckb_bin=$CKB_BIN
ckb_version=$("$CKB_BIN" --version 2>/dev/null || printf 'unknown')
ckb_dir=$CKB_DIR
rpc_url=$RPC_URL
rpc_port=$RPC_PORT
p2p_port=$P2P_PORT
out_dir=$OUT_DIR
mine_blocks=$MINE_BLOCKS
budget_profile=$BUDGET_PROFILE
build_contracts=$BUILD_CONTRACTS
morph_e2e_deployer_key_file=$MORPH_E2E_DEPLOYER_KEY_FILE
morph_e2e_alice_key_file=$MORPH_E2E_ALICE_KEY_FILE
morph_e2e_bob_key_file=$MORPH_E2E_BOB_KEY_FILE
EOF

if [ "$BUILD_CONTRACTS" = "1" ]; then
  log "building RISC-V contract binaries"
  make build-contracts >"$LOG_DIR/build-contracts.log" 2>&1
else
  log "contract build skipped by BUILD_CONTRACTS=0"
fi

log "starting real CKB devnet node"
CKB_BIN="$CKB_BIN" \
CKB_DIR="$CKB_DIR" \
RPC_PORT="$RPC_PORT" \
P2P_PORT="$P2P_PORT" \
  scripts/devnet-node.sh >"$LOG_DIR/ckb-node.log" 2>&1 &
CKB_NODE_PID="$!"
printf 'ckb_node_pid=%s\n' "$CKB_NODE_PID" >>"$E2E_DIR/manifest.txt"

wait_for_rpc
log "CKB RPC ready at $RPC_URL"

log "running stateful production scenario suite"
MORPH_CKB_RPC="$RPC_URL" \
CKB_BIN="$CKB_BIN" \
OUT_DIR="$OUT_DIR" \
LATEST_LINK="$E2E_DIR/scenarios-latest" \
MINE_BLOCKS="$MINE_BLOCKS" \
MORPH_DEVNET_SMOKE_SKIP_LOCAL_CHECKS=1 \
  scripts/devnet-stateful-scenarios.sh 2>&1 | tee "$LOG_DIR/devnet-stateful-scenarios.log"

log "running budget-backed stateful assertion"
cargo run -q -p morph-cli -- devnet-stateful-assert \
  --dir "$OUT_DIR" \
  --audit-profile docs/devnet-audit-profile.example.json \
  --budget-profile "$BUDGET_PROFILE" \
  --json >"$OUT_DIR/summary-budget-check.json"

cat >>"$E2E_DIR/manifest.txt" <<EOF
finished_at_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)
status=passed
EOF

if [ ! -e "$LATEST_LINK" ] || [ -L "$LATEST_LINK" ]; then
  E2E_DIR_ABS="$(cd "$E2E_DIR" && pwd)"
  mkdir -p "$(dirname "$LATEST_LINK")"
  rm -f "$LATEST_LINK"
  ln -s "$E2E_DIR_ABS" "$LATEST_LINK"
  log "latest -> $LATEST_LINK"
else
  log "latest link skipped because $LATEST_LINK exists and is not a symlink"
fi

log "passed; artifacts are in $E2E_DIR"
