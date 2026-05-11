.PHONY: test fmt smoke build-contracts

test:
	cargo test --workspace

fmt:
	cargo fmt --all

smoke:
	cargo test --workspace
	cargo run -p morph-cli -- validate-fixture

build-contracts:
	cargo build --release --target riscv64imac-unknown-none-elf -p morph-state-type -p morph-vault-lock -p morph-sponsor-lock
