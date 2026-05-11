.PHONY: test fmt smoke build-contracts contract-tests

test:
	cargo test --workspace

fmt:
	cargo fmt --all

smoke:
	cargo test --workspace
	cargo run -p morph-cli -- validate-fixture

build-contracts:
	cargo build --release --target riscv64imac-unknown-none-elf -p morph-state-lock -p morph-state-type -p morph-vault-lock -p morph-sponsor-lock

contract-tests: build-contracts
	cargo test -p morph-core --test contract_scripts -- --ignored --test-threads=1
