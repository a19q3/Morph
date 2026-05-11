#!/usr/bin/env bash
set -euo pipefail

DEFAULT_LOCAL_CKB="/Users/arthur/RustroverProjects/ckb/target/debug/ckb"
CKB_BIN="${CKB_BIN:-$DEFAULT_LOCAL_CKB}"
CKB_DIR="${CKB_DIR:-target/devnet/node}"
RPC_PORT="${RPC_PORT:-18114}"
P2P_PORT="${P2P_PORT:-18115}"
DEFAULT_SECP_TYPE_HASH="0x9bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8"
BLOCK_ASSEMBLER_CODE_HASH="${BLOCK_ASSEMBLER_CODE_HASH:-$DEFAULT_SECP_TYPE_HASH}"
BLOCK_ASSEMBLER_ARG="${BLOCK_ASSEMBLER_ARG:-0xc8328aabcd9b9e8e64fbc566c4385c3bdeb219d7}"

if [ ! -x "$CKB_BIN" ]; then
  printf "missing executable CKB_BIN: %s\n" "$CKB_BIN" >&2
  exit 1
fi

ensure_integration_test_rpc() {
  local config="$CKB_DIR/ckb.toml"
  if grep -Eq '^modules = .*"IntegrationTest"' "$config"; then
    return
  fi

  perl -0pi -e 's/^modules = \[[^\n]*\]/modules = ["Net", "Pool", "Miner", "Chain", "Stats", "Subscription", "Experiment", "Debug", "Terminal", "IntegrationTest"]/m' "$config"
  if ! grep -Eq '^modules = .*"IntegrationTest"' "$config"; then
    printf "failed to enable IntegrationTest RPC in %s\n" "$config" >&2
    exit 1
  fi
}

ensure_block_assembler() {
  local config="$CKB_DIR/ckb.toml"
  if grep -Eq '^\[block_assembler\]' "$config"; then
    return
  fi

  cat >> "$config" <<EOF

[block_assembler]
code_hash = "$BLOCK_ASSEMBLER_CODE_HASH"
args = "$BLOCK_ASSEMBLER_ARG"
hash_type = "type"
message = "0x"
EOF
}

if [ ! -f "$CKB_DIR/ckb.toml" ]; then
  mkdir -p "$CKB_DIR"
  "$CKB_BIN" init \
    -C "$CKB_DIR" \
    --chain dev \
    --force \
    --rpc-port "$RPC_PORT" \
    --p2p-port "$P2P_PORT" \
    --ba-code-hash "$BLOCK_ASSEMBLER_CODE_HASH" \
    --ba-arg "$BLOCK_ASSEMBLER_ARG" \
    --ba-hash-type type \
    --log-to stdout
fi

ensure_integration_test_rpc
ensure_block_assembler

exec "$CKB_BIN" -C "$CKB_DIR" run
