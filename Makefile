.PHONY: fmt check test

fmt:
	cargo fmt --all

check:
	cargo check --workspace

test:
	cargo test --workspace
