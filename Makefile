CARGO ?= cargo
CONTRACT_CARGO ?= $(CARGO)
AUDIT ?= cargo audit
DENY ?= cargo deny
# Current CKB dependencies pull transitive informational advisories for
# paste (unmaintained) and rand 0.7 (unsound). Keep vulnerability failures
# enabled while avoiding noisy warning trees until upstream CKB crates move.
# Track the rand waiver with `cargo tree -i rand@0.7.3`; remove
# RUSTSEC-2026-0097 when ckb-vm/ckb-resource no longer pull rand 0.7.
# RUSTSEC-2026-0097 is the current rand advisory; RUSTSEC-2020-0097 is for xcb.
AUDIT_IGNORE ?= --ignore RUSTSEC-2024-0436 --ignore RUSTSEC-2026-0097

.PHONY: ci full-test test lint fmt fmt-check audit deny supply-chain smoke fixture-checks sdk-check hub-ui-check build-contracts contract-tests devnet-smoke devnet-e2e devnet-stateful-e2e fiber-morph-devnet-preflight fiber-morph-devnet-acceptance fiber-morph-devnet-acceptance-full fiber-morph-devnet-audit smoke-report smoke-assert smoke-assert-budget devnet-stateful-report devnet-stateful-assert

ci: fmt-check lint supply-chain test fixture-checks sdk-check hub-ui-check contract-tests

full-test: test fixture-checks contract-tests

test:
	$(CARGO) test --workspace

lint:
	$(CARGO) clippy --workspace --all-targets -- -D warnings

fmt:
	$(CARGO) fmt --all

fmt-check:
	$(CARGO) fmt --all -- --check

audit:
	$(AUDIT) $(AUDIT_IGNORE)

deny:
	$(DENY) check

supply-chain: audit deny

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
	$(CARGO) run -q -p morph-cli -- print-factory-reduced-exit-fixture > target/fixture-checks/factory-reduced-exit.json
	$(CARGO) run -q -p morph-cli -- validate-factory-reduced-exit-package target/fixture-checks/factory-reduced-exit.json --json > target/fixture-checks/factory-reduced-exit-summary.json
	$(CARGO) run -q -p morph-cli -- print-factory-merkle-update-fixture > target/fixture-checks/factory-merkle-update.json
	$(CARGO) run -q -p morph-cli -- validate-factory-merkle-update-package target/fixture-checks/factory-merkle-update.json --json > target/fixture-checks/factory-merkle-update-summary.json
	$(CARGO) run -q -p morph-cli -- print-factory-local-exit-fixture > target/fixture-checks/factory-local-exit.json
	$(CARGO) run -q -p morph-cli -- validate-factory-local-exit-package target/fixture-checks/factory-local-exit.json --json > target/fixture-checks/factory-local-exit-summary.json
	$(CARGO) run -q -p morph-cli -- print-factory-splice-fixture --kind splice-in > target/fixture-checks/factory-splice-in.json
	$(CARGO) run -q -p morph-cli -- validate-factory-splice-package target/fixture-checks/factory-splice-in.json --json > target/fixture-checks/factory-splice-in-summary.json
	$(CARGO) run -q -p morph-cli -- print-factory-splice-fixture --kind xudt-splice-out > target/fixture-checks/factory-xudt-splice-out.json
	$(CARGO) run -q -p morph-cli -- validate-factory-splice-package target/fixture-checks/factory-xudt-splice-out.json --json > target/fixture-checks/factory-xudt-splice-out-summary.json
	$(CARGO) run -q -p morph-cli -- print-factory-reduced-splice-fixture --kind splice-in > target/fixture-checks/factory-reduced-splice-in.json
	$(CARGO) run -q -p morph-cli -- validate-factory-reduced-splice-package target/fixture-checks/factory-reduced-splice-in.json --json > target/fixture-checks/factory-reduced-splice-in-summary.json
	$(CARGO) run -q -p morph-cli -- print-factory-reduced-splice-fixture --kind xudt-splice-out > target/fixture-checks/factory-reduced-xudt-splice-out.json
	$(CARGO) run -q -p morph-cli -- validate-factory-reduced-splice-package target/fixture-checks/factory-reduced-xudt-splice-out.json --json > target/fixture-checks/factory-reduced-xudt-splice-out-summary.json
	$(CARGO) run -q -p morph-cli -- print-watch-policy-fixture > target/fixture-checks/watch-policy.json
	$(CARGO) run -q -p morph-cli -- validate-watch-policy target/fixture-checks/watch-policy.json --json > target/fixture-checks/watch-policy-summary.json
	$(CARGO) run -q -p morph-cli -- print-watch-config-fixture > target/fixture-checks/watch-config.json
	$(CARGO) run -q -p morph-cli -- validate-watch-config target/fixture-checks/watch-config.json --json > target/fixture-checks/watch-config-summary.json

sdk-check:
	cd sdk/typescript && npm ci && npm audit --registry=https://registry.npmjs.org --audit-level=high && npm run check && npm test

hub-ui-check:
	cd ui/morph-hub && npm ci && npm audit --registry=https://registry.npmjs.org --audit-level=high && npm run build

build-contracts:
	$(CONTRACT_CARGO) build --release --target riscv64imac-unknown-none-elf -p morph-state-lock -p morph-state-type -p morph-factory-type -p morph-factory-vault-lock -p morph-vault-lock -p morph-sponsor-lock -p morph-devnet-xudt

contract-tests: build-contracts
	$(CARGO) test -p morph-core --test contract_scripts -- --ignored --test-threads=1

devnet-smoke:
	scripts/devnet-smoke.sh

devnet-e2e:
	scripts/devnet-e2e.sh

devnet-stateful-e2e:
	scripts/devnet-stateful-e2e.sh

fiber-morph-devnet-preflight:
	FIBER_MORPH_ACCEPTANCE_MODE=preflight scripts/fiber-morph-devnet-acceptance.sh

fiber-morph-devnet-acceptance:
	FIBER_MORPH_ACCEPTANCE_MODE=coexistence scripts/fiber-morph-devnet-acceptance.sh

fiber-morph-devnet-acceptance-full:
	FIBER_MORPH_ACCEPTANCE_MODE=full scripts/fiber-morph-devnet-acceptance.sh

fiber-morph-devnet-audit:
	@if [ -n "$(FIBER_MORPH_ACCEPTANCE_RUN)" ]; then \
		scripts/fiber-morph-devnet-audit.sh "$(FIBER_MORPH_ACCEPTANCE_RUN)"; \
	else \
		scripts/fiber-morph-devnet-audit.sh; \
	fi

smoke-report:
	$(CARGO) run -p morph-cli -- devnet-smoke-report

smoke-assert:
	$(CARGO) run -p morph-cli -- devnet-smoke-assert

smoke-assert-budget:
	$(CARGO) run -p morph-cli -- devnet-smoke-assert --budget-profile docs/devnet-smoke-budget.example.json

devnet-stateful-report:
	$(CARGO) run -p morph-cli -- devnet-stateful-report --audit-profile docs/devnet-audit-profile.example.json

devnet-stateful-assert:
	$(CARGO) run -p morph-cli -- devnet-stateful-assert --audit-profile docs/devnet-audit-profile.example.json --budget-profile docs/devnet-stateful-budget.example.json
