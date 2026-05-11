#!/usr/bin/env bash
set -euo pipefail

DEFAULT_LOCAL_CKB="/Users/arthur/RustroverProjects/ckb/target/debug/ckb"
CKB_BIN="${CKB_BIN:-$DEFAULT_LOCAL_CKB}"
CKB_DIR="${CKB_DIR:-target/devnet/node}"
RPC_PORT="${RPC_PORT:-18114}"
P2P_PORT="${P2P_PORT:-18115}"

if [ ! -x "$CKB_BIN" ]; then
  printf "missing executable CKB_BIN: %s\n" "$CKB_BIN" >&2
  exit 1
fi

if [ ! -f "$CKB_DIR/ckb.toml" ]; then
  mkdir -p "$CKB_DIR"
  "$CKB_BIN" init \
    -C "$CKB_DIR" \
    --chain dev \
    --force \
    --rpc-port "$RPC_PORT" \
    --p2p-port "$P2P_PORT" \
    --log-to stdout
fi

exec "$CKB_BIN" -C "$CKB_DIR" run
