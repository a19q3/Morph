#!/usr/bin/env bash
set -euo pipefail

missing=0

check() {
  local name="$1"
  if command -v "$name" >/dev/null 2>&1; then
    printf "ok: %s -> %s\n" "$name" "$(command -v "$name")"
  else
    printf "missing: %s\n" "$name"
    missing=1
  fi
}

check_bin() {
  local label="$1"
  local value="$2"
  if [ -n "$value" ] && [ -x "$value" ]; then
    printf "ok: %s -> %s\n" "$label" "$value"
  elif command -v "$label" >/dev/null 2>&1; then
    printf "ok: %s -> %s\n" "$label" "$(command -v "$label")"
  else
    printf "missing: %s\n" "$label"
    missing=1
  fi
}

check cargo
check rustup
check jq

CKB_BIN="${CKB_BIN:-}"
check_bin ckb "$CKB_BIN"

if command -v ckb-cli >/dev/null 2>&1; then
  printf "ok: ckb-cli -> %s\n" "$(command -v ckb-cli)"
else
  printf "optional missing: ckb-cli\n"
fi

if rustup target list --installed | grep -q '^riscv64imac-unknown-none-elf$'; then
  printf "ok: riscv64imac-unknown-none-elf target installed\n"
else
  printf "missing: riscv64imac-unknown-none-elf target\n"
  missing=1
fi

if [ "$missing" -ne 0 ]; then
  cat <<'EOF'

The local semantic tests can run without CKB binaries:

  cargo test --workspace
  cargo run -p morph-cli -- validate-fixture

Full devnet broadcast requires a CKB node binary. ckb-cli is useful for manual
inspection but is not required by the Morph RPC tooling path.
EOF
  exit 1
fi
