APP_NAME := ongoingai
CMD_PATH := ./cmd/ongoingai
BIN_DIR := ./bin
BIN_PATH := $(BIN_DIR)/$(APP_NAME)
DIST_DIR := ./dist
PLATFORMS := linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64

VERSION ?= dev
COMMIT ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
DATE ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS := -X github.com/ongoingai/gateway/internal/version.Version=$(VERSION) -X github.com/ongoingai/gateway/internal/version.Commit=$(COMMIT) -X github.com/ongoingai/gateway/internal/version.Date=$(DATE)

.PHONY: build build-cross test run fmt tidy clean version-next

build:
	@mkdir -p $(BIN_DIR)
	go build -ldflags "$(LDFLAGS)" -o $(BIN_PATH) $(CMD_PATH)

build-cross:
	@mkdir -p $(DIST_DIR)
	@set -eu; \
	for platform in $(PLATFORMS); do \
		os=$${platform%/*}; \
		arch=$${platform#*/}; \
		ext=""; \
		if [ "$$os" = "windows" ]; then ext=".exe"; fi; \
		out="$(DIST_DIR)/$(APP_NAME)_$${os}_$${arch}$${ext}"; \
		echo "building $$os/$$arch -> $$out"; \
		GOOS=$$os GOARCH=$$arch CGO_ENABLED=0 go build -ldflags "$(LDFLAGS)" -o "$$out" $(CMD_PATH); \
	done

test:
	go test ./...

run:
	go run $(CMD_PATH) serve --config ongoingai.yaml

fmt:
	gofmt -w $$(find . -name '*.go' -not -path './vendor/*')

tidy:
	go mod tidy

clean:
	rm -rf $(BIN_DIR) $(DIST_DIR)

version-next:
	scripts/release/next_tag.sh
