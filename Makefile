CARGO ?= cargo
CONTRACT_CARGO ?= $(CARGO)

.PHONY: ci test lint fmt fmt-check smoke fixture-checks build-contracts contract-tests devnet-smoke smoke-report smoke-assert

ci: fmt-check lint test fixture-checks contract-tests

test:
	$(CARGO) test --workspace

lint:
	$(CARGO) clippy --workspace --all-targets -- -D warnings

fmt:
	$(CARGO) fmt --all

fmt-check:
	$(CARGO) fmt --all -- --check

smoke:
	$(CARGO) test --workspace
	$(CARGO) run -p morph-cli -- validate-fixture

fixture-checks:
	mkdir -p target/fixture-checks
	$(CARGO) run -q -p morph-cli -- validate-fixture
	$(CARGO) run -q -p morph-cli -- print-factory-fixture > target/fixture-checks/factory-update.json
	$(CARGO) run -q -p morph-cli -- validate-factory-package target/fixture-checks/factory-update.json --json > target/fixture-checks/factory-update-summary.json
	$(CARGO) run -q -p morph-cli -- print-factory-state-fixture > target/fixture-checks/factory-state.json
	$(CARGO) run -q -p morph-cli -- validate-factory-state-package target/fixture-checks/factory-state.json --json > target/fixture-checks/factory-state-summary.json
	$(CARGO) run -q -p morph-cli -- print-reduced-factory-state-fixture > target/fixture-checks/factory-state-reduced.json
	$(CARGO) run -q -p morph-cli -- validate-factory-state-package target/fixture-checks/factory-state-reduced.json --json > target/fixture-checks/factory-state-reduced-summary.json
	$(CARGO) run -q -p morph-cli -- print-factory-reduced-rights-fixture > target/fixture-checks/factory-reduced-rights.json
	$(CARGO) run -q -p morph-cli -- validate-factory-reduced-rights-package target/fixture-checks/factory-reduced-rights.json --json > target/fixture-checks/factory-reduced-rights-summary.json
	$(CARGO) run -q -p morph-cli -- print-factory-local-exit-fixture > target/fixture-checks/factory-local-exit.json
	$(CARGO) run -q -p morph-cli -- validate-factory-local-exit-package target/fixture-checks/factory-local-exit.json --json > target/fixture-checks/factory-local-exit-summary.json
	$(CARGO) run -q -p morph-cli -- print-watch-policy-fixture > target/fixture-checks/watch-policy.json
	$(CARGO) run -q -p morph-cli -- validate-watch-policy target/fixture-checks/watch-policy.json --json > target/fixture-checks/watch-policy-summary.json
	$(CARGO) run -q -p morph-cli -- print-watch-config-fixture > target/fixture-checks/watch-config.json
	$(CARGO) run -q -p morph-cli -- validate-watch-config target/fixture-checks/watch-config.json --json > target/fixture-checks/watch-config-summary.json

build-contracts:
	$(CONTRACT_CARGO) build --release --target riscv64imac-unknown-none-elf -p morph-state-lock -p morph-state-type -p morph-factory-type -p morph-factory-vault-lock -p morph-vault-lock -p morph-sponsor-lock -p morph-devnet-xudt

contract-tests: build-contracts
	$(CARGO) test -p morph-core --test contract_scripts -- --ignored --test-threads=1

devnet-smoke:
	scripts/devnet-smoke.sh

smoke-report:
	$(CARGO) run -p morph-cli -- devnet-smoke-report

smoke-assert:
	$(CARGO) run -p morph-cli -- devnet-smoke-assert
