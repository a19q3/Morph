#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(cd -- "$SCRIPT_DIR/.." && pwd)
CONTRACT_DIR="$REPO_ROOT/target/riscv64imac-unknown-none-elf/release"
OUTPUT_PARENT="$REPO_ROOT/target"

mkdir -p "$OUTPUT_PARENT"
STAGING_DIR=$(mktemp -d "$OUTPUT_PARENT/contract-release.XXXXXXXX")
ARTIFACT_DIR="$STAGING_DIR/factory-v1.0-fixed-bilateral"
mkdir -p "$ARTIFACT_DIR/contracts"

scripts=(
  morph-state-lock
  morph-state-type
  morph-factory-type
  morph-factory-vault-lock
  morph-vault-lock
  morph-sponsor-lock
  morph-devnet-xudt
)

for script_name in "${scripts[@]}"; do
  install -m 0755 "$CONTRACT_DIR/$script_name" "$ARTIFACT_DIR/contracts/$script_name"
done
install -m 0644 \
  "$REPO_ROOT/release/factory-v1.0-preproduction/contracts.json" \
  "$ARTIFACT_DIR/contracts.json"
install -m 0644 \
  "$REPO_ROOT/release/factory-v1.0-preproduction/envelope.json" \
  "$ARTIFACT_DIR/envelope.json"
install -m 0644 \
  "$REPO_ROOT/release/factory-v1.0-preproduction/README.md" \
  "$ARTIFACT_DIR/README.md"
install -m 0644 \
  "$REPO_ROOT/release/factory-v1.0-preproduction/watch-policy.json" \
  "$ARTIFACT_DIR/watch-policy.json"
install -m 0644 \
  "$REPO_ROOT/release/factory-v1.0-preproduction/watch-config.example.json" \
  "$ARTIFACT_DIR/watch-config.example.json"

(
  cd "$ARTIFACT_DIR"
  sha256sum contracts/* contracts.json envelope.json README.md \
    watch-policy.json watch-config.example.json > SHA256SUMS
)

STAGED_ARCHIVE="$STAGING_DIR/factory-v1.0-fixed-bilateral.tar.gz"
tar --sort=name --mtime=@0 --owner=0 --group=0 --numeric-owner \
  -C "$STAGING_DIR" -cf - factory-v1.0-fixed-bilateral \
  | gzip -n > "$STAGED_ARCHIVE"
ARCHIVE_PATH="$OUTPUT_PARENT/factory-v1.0-fixed-bilateral.tar.gz"
install -m 0644 "$STAGED_ARCHIVE" "$ARCHIVE_PATH"

echo "contract release directory: $ARTIFACT_DIR"
echo "contract release archive: $ARCHIVE_PATH"
