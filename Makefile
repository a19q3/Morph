.PHONY: ci test lint fmt fmt-check smoke fixture-checks build-contracts contract-tests devnet-smoke smoke-report smoke-assert

ci: fmt-check lint test fixture-checks contract-tests

test:
	cargo test --workspace

lint:
	cargo clippy --workspace --all-targets -- -D warnings

fmt:
	cargo fmt --all

fmt-check:
	cargo fmt --all -- --check

smoke:
	cargo test --workspace
	cargo run -p morph-cli -- validate-fixture

fixture-checks:
	mkdir -p target/fixture-checks
	cargo run -q -p morph-cli -- validate-fixture
	cargo run -q -p morph-cli -- print-factory-fixture > target/fixture-checks/factory-update.json
	cargo run -q -p morph-cli -- validate-factory-package target/fixture-checks/factory-update.json --json > target/fixture-checks/factory-update-summary.json
	cargo run -q -p morph-cli -- print-factory-state-fixture > target/fixture-checks/factory-state.json
	cargo run -q -p morph-cli -- validate-factory-state-package target/fixture-checks/factory-state.json --json > target/fixture-checks/factory-state-summary.json
	cargo run -q -p morph-cli -- print-reduced-factory-state-fixture > target/fixture-checks/factory-state-reduced.json
	cargo run -q -p morph-cli -- validate-factory-state-package target/fixture-checks/factory-state-reduced.json --json > target/fixture-checks/factory-state-reduced-summary.json
	cargo run -q -p morph-cli -- print-factory-local-exit-fixture > target/fixture-checks/factory-local-exit.json
	cargo run -q -p morph-cli -- validate-factory-local-exit-package target/fixture-checks/factory-local-exit.json --json > target/fixture-checks/factory-local-exit-summary.json
	cargo run -q -p morph-cli -- print-watch-policy-fixture > target/fixture-checks/watch-policy.json
	cargo run -q -p morph-cli -- validate-watch-policy target/fixture-checks/watch-policy.json --json > target/fixture-checks/watch-policy-summary.json
	cargo run -q -p morph-cli -- print-watch-config-fixture > target/fixture-checks/watch-config.json
	cargo run -q -p morph-cli -- validate-watch-config target/fixture-checks/watch-config.json --json > target/fixture-checks/watch-config-summary.json

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
