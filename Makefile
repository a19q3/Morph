.PHONY: test fmt smoke build-contracts contract-tests devnet-smoke smoke-report smoke-assert

test:
	cargo test --workspace

fmt:
	cargo fmt --all

smoke:
	cargo test --workspace
	cargo run -p morph-cli -- validate-fixture

build-contracts:
	cargo build --release --target riscv64imac-unknown-none-elf -p morph-state-lock -p morph-state-type -p morph-factory-type -p morph-factory-vault-lock -p morph-vault-lock -p morph-sponsor-lock -p morph-devnet-xudt

contract-tests: build-contracts
	cargo test -p morph-core --test contract_scripts -- --ignored --test-threads=1

devnet-smoke:
	scripts/devnet-smoke.sh

smoke-report:
	cargo run -p morph-cli -- devnet-smoke-report

smoke-assert:
	cargo run -p morph-cli -- devnet-smoke-assert
