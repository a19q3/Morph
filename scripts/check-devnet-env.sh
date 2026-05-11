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

check cargo
check rustup
check ckb
check ckb-cli

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

Full devnet broadcast requires ckb and ckb-cli on PATH.
EOF
  exit 1
fi

