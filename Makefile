.PHONY: test fmt smoke

test:
	cargo test --workspace

fmt:
	cargo fmt --all

smoke:
	cargo test --workspace
	cargo run -p morph-cli -- validate-fixture

