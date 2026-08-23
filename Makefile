SHELL := /usr/bin/env bash

.PHONY: all fmt fmt-check check test clippy build doc metadata diff-check verify audit deny security generate-keys

all: verify

fmt:
	cargo fmt --all

fmt-check:
	cargo fmt --all -- --check

check:
	cargo check --all-targets --all-features

test:
	cargo test --all-targets --all-features


clippy:
	cargo clippy --all-targets --all-features -- -D warnings

build:
	cargo build --all-targets

doc:
	cargo doc --no-deps --all-features

metadata:
	cargo metadata --locked --no-deps

diff-check:
	git diff --check

# The default unprivileged quality gate. The namespace integration test is
# intentionally separate because it creates network namespaces and changes
# routes, TUN devices, forwarding, and nftables state.
verify: fmt-check check test clippy build diff-check

audit:
	@command -v cargo-audit >/dev/null || { echo "cargo-audit is required: cargo install cargo-audit" >&2; exit 1; }
	cargo audit

deny:
	@command -v cargo-deny >/dev/null || { echo "cargo-deny is required: cargo install cargo-deny" >&2; exit 1; }
	cargo deny check

security: audit deny

generate-keys:
	cargo run --bin generate_noise_keys
