GO ?= go
CONTRACT_PYTHON ?= python3
REVISION := $(shell git rev-parse HEAD)
VERSION ?= 0.0.0-c13
DIRTY := $(shell test -z "$$(git status --porcelain --untracked-files=normal)" && echo false || echo true)
MODULE := github.com/QgMixtate/surveyscan/v2
BUILD_FLAGS = -X $(MODULE)/internal/platform/buildinfo.Version=$(VERSION) -X $(MODULE)/internal/platform/buildinfo.Revision=$(REVISION) -X $(MODULE)/internal/platform/buildinfo.Dirty=$(DIRTY)

.PHONY: build test vet contracts integration dev-up dev-down fmt-check verify
build:
	mkdir -p .dist/contracts
	$(GO) version
	CGO_ENABLED=0 $(GO) build -mod=readonly -trimpath -p 2 -ldflags '$(BUILD_FLAGS)' -o .dist/surveyscan-server ./cmd/surveyscan-server
	CGO_ENABLED=0 $(GO) build -mod=readonly -trimpath -p 2 -ldflags '$(BUILD_FLAGS)' -o .dist/surveyscan-collector ./cmd/surveyscan-collector
	CGO_ENABLED=0 $(GO) build -mod=readonly -trimpath -p 2 -ldflags '$(BUILD_FLAGS)' -o .dist/surveyscan-agent ./cmd/surveyscan-agent
	CGO_ENABLED=0 $(GO) build -mod=readonly -trimpath -p 2 -ldflags '$(BUILD_FLAGS)' -o .dist/surveyscanctl ./cmd/surveyscanctl
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
