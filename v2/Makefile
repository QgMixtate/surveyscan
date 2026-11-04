GO ?= go
CONTRACT_PYTHON ?= python3
REVISION := $(shell git rev-parse HEAD)
MODULE := github.com/QgMixtate/surveyscan/v2

.PHONY: build test vet contracts integration dev-up dev-down fmt-check verify
build:
	mkdir -p .dist/contracts
	$(GO) version
	CGO_ENABLED=0 $(GO) build -mod=readonly -trimpath -p 2 -ldflags '-X $(MODULE)/internal/platform/buildinfo.Revision=$(REVISION)' -o .dist/surveyscan-server ./cmd/surveyscan-server
	CGO_ENABLED=0 $(GO) build -mod=readonly -trimpath -p 2 -o .dist/surveyscan-collector ./cmd/surveyscan-collector
	CGO_ENABLED=0 $(GO) build -mod=readonly -trimpath -p 2 -o .dist/surveyscan-agent ./cmd/surveyscan-agent
	CGO_ENABLED=0 $(GO) build -mod=readonly -trimpath -p 2 -o .dist/surveyscanctl ./cmd/surveyscanctl
	cp contracts/*.json .dist/contracts/
	chmod 755 .dist .dist/contracts .dist/surveyscan-* .dist/surveyscanctl
	chmod 644 .dist/contracts/*.json
test:
	$(GO) test -mod=readonly -count=1 -p 2 ./...
vet:
	$(GO) vet -mod=readonly ./...
fmt-check:
	test -z "$$($$($(GO) env GOROOT)/bin/gofmt -l cmd internal contracts)"
contracts:
	mkdir -p .local
	$(CONTRACT_PYTHON) ../docs/plans/surveyscan-v2/contracts/C03/checks/validate_contracts.py .local/contracts-validation.json
integration:
	GO=$(GO) python3 scripts/dev.py integration
dev-up: build
	python3 scripts/dev.py up
dev-down:
	python3 scripts/dev.py down
verify: fmt-check vet test contracts
