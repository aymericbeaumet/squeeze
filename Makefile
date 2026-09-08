.PHONY: all help build release test test-verbose bench lint fmt fmt-check check doc doc-check clean install watch watch-check run msrv update outdated audit

all: check

help:
	mise tasks

build release test test-verbose bench lint fmt fmt-check check doc doc-check clean install watch watch-check msrv update outdated audit:
	mise run $@

run:
	mise run run -- $(ARGS)
