.PHONY: all
all: build lint test

.PHONY: build
build:
	cargo build --release

.PHONY: lint
lint:
	cargo clippy

.PHONY: test
test:
	cargo test

.PHONY: dev
dev:
	watchexec --restart --clear 'cargo build && cargo test'
