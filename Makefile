.PHONY: all build release test lint fmt check clean doc install help

# Default target
all: check

# Build targets
build:
	cargo build

release:
	cargo build --release

# Testing
test:
	cargo test

test-verbose:
	cargo test -- --nocapture

# Linting and formatting
lint:
	cargo clippy --all-targets -- --deny warnings

fmt:
	cargo fmt --all

fmt-check:
	cargo fmt --all -- --check

# Combined check (what CI runs)
check: fmt-check lint test doc-check

# Documentation
doc:
	cargo doc --no-deps --all-features --open

doc-check:
	RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --all-features

# Clean build artifacts
clean:
	cargo clean

# Install locally
install:
	cargo install --path squeeze-cli

# Development helpers
watch:
	watchexec --clear --restart 'cargo test'

watch-check:
	watchexec --clear --restart 'make check'

# Run the binary
run:
	@echo "Usage: echo 'text' | make run ARGS='--url'"
	@echo "Example: echo 'https://example.com' | cargo run -- $(ARGS)"

# MSRV check (Minimum Supported Rust Version)
msrv:
	cargo +1.85 build
	cargo +1.85 test

# Update dependencies
update:
	cargo update

# Show outdated dependencies
outdated:
	cargo outdated

# Security audit
audit:
	cargo audit

# Help
help:
	@echo "Available targets:"
	@echo "  all          - Run full check (default)"
	@echo "  build        - Build debug binary"
	@echo "  release      - Build release binary"
	@echo "  test         - Run all tests"
	@echo "  test-verbose - Run tests with output"
	@echo "  lint         - Run clippy linter"
	@echo "  fmt          - Format code"
	@echo "  fmt-check    - Check code formatting"
	@echo "  check        - Run fmt-check, lint, test, doc-check"
	@echo "  doc          - Generate and open documentation"
	@echo "  doc-check    - Check documentation builds without warnings"
	@echo "  clean        - Remove build artifacts"
	@echo "  install      - Install binary locally"
	@echo "  watch        - Watch for changes and run tests"
	@echo "  watch-check  - Watch for changes and run full check"
	@echo "  msrv         - Test with minimum supported Rust version (1.85)"
	@echo "  update       - Update dependencies"
	@echo "  outdated     - Show outdated dependencies"
	@echo "  audit        - Run security audit"
	@echo "  help         - Show this help"
