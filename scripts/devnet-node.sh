#!/usr/bin/env bash
set -euo pipefail

CKB_BIN="${CKB_BIN:-}"
CKB_DIR="${CKB_DIR:-target/devnet/node}"
RPC_PORT="${RPC_PORT:-18114}"
P2P_PORT="${P2P_PORT:-18115}"
DEFAULT_SECP_TYPE_HASH="0x9bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8"
BLOCK_ASSEMBLER_CODE_HASH="${BLOCK_ASSEMBLER_CODE_HASH:-$DEFAULT_SECP_TYPE_HASH}"
BLOCK_ASSEMBLER_ARG="${BLOCK_ASSEMBLER_ARG:-0xc8328aabcd9b9e8e64fbc566c4385c3bdeb219d7}"
MORPH_CKB_MIN_FEE_RATE="${MORPH_CKB_MIN_FEE_RATE:-}"
MORPH_CKB_MIN_RBF_RATE="${MORPH_CKB_MIN_RBF_RATE:-}"

if [ -z "$CKB_BIN" ]; then
  if command -v ckb >/dev/null 2>&1; then
    CKB_BIN="$(command -v ckb)"
  else
    printf "missing ckb binary: set CKB_BIN=/path/to/ckb or place ckb on PATH\n" >&2
    exit 1
  fi
fi

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

ensure_tx_pool_policy() {
  local config="$CKB_DIR/ckb.toml"
  if [ -n "$MORPH_CKB_MIN_FEE_RATE" ]; then
    [[ "$MORPH_CKB_MIN_FEE_RATE" =~ ^[0-9]+$ ]] || {
      printf "MORPH_CKB_MIN_FEE_RATE must be an unsigned integer\n" >&2
      exit 1
    }
    perl -0pi -e "s/^min_fee_rate = [0-9_]+.*$/min_fee_rate = $MORPH_CKB_MIN_FEE_RATE # Morph devnet fee-pressure override/m" "$config"
    grep -Eq "^min_fee_rate = $MORPH_CKB_MIN_FEE_RATE([[:space:]]|$)" "$config" || {
      printf "failed to set tx_pool.min_fee_rate in %s\n" "$config" >&2
      exit 1
    }
  fi
  if [ -n "$MORPH_CKB_MIN_RBF_RATE" ]; then
    [[ "$MORPH_CKB_MIN_RBF_RATE" =~ ^[0-9]+$ ]] || {
      printf "MORPH_CKB_MIN_RBF_RATE must be an unsigned integer\n" >&2
      exit 1
    }
    perl -0pi -e "s/^min_rbf_rate = [0-9_]+.*$/min_rbf_rate = $MORPH_CKB_MIN_RBF_RATE # Morph devnet RBF override/m" "$config"
    grep -Eq "^min_rbf_rate = $MORPH_CKB_MIN_RBF_RATE([[:space:]]|$)" "$config" || {
      printf "failed to set tx_pool.min_rbf_rate in %s\n" "$config" >&2
      exit 1
    }
  fi
  if [ -n "$MORPH_CKB_MIN_FEE_RATE" ] && [ -n "$MORPH_CKB_MIN_RBF_RATE" ] &&
    [ "$MORPH_CKB_MIN_RBF_RATE" -le "$MORPH_CKB_MIN_FEE_RATE" ]; then
    printf "RBF requires MORPH_CKB_MIN_RBF_RATE > MORPH_CKB_MIN_FEE_RATE\n" >&2
    exit 1
  fi
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
ensure_tx_pool_policy

exec "$CKB_BIN" -C "$CKB_DIR" run
