# Set the shell to bash
SHELL := /bin/bash

# Default target
all: build

# Build the project
build:
	go build -o bin/uds-security-hub main.go
	go build -o bin/table-init ./cmd/table-init/main.go
	go build -o bin/store ./cmd/store/main.go

# Lint the code
lint:
	 golangci-lint run ./...

# Clean the build
clean:
	rm -rf bin/

# Run the docker compose
docker-up: docker-down
	docker compose -f docker-compose.yml up -d
	sleep 5

table-init: docker-up
	@go run ./cmd/table-init/main.go || { echo "Failed to initialize tables"; exit 1; }

docker-down:
	docker compose -f docker-compose.yml down || true

test:
	go test ./... -v -coverprofile=coverage.out

test-integration: table-init
	@if [ -z "$${GITHUB_TOKEN}" ] || [ -z "$${GHCR_CREDS}" ] || [ -z "$${REGISTRY1_CREDS}" ]; then \
		echo "Error: GITHUB_TOKEN, GHCR_CREDS, or REGISTRY1_CREDS is not set"; \
		exit 1; \
	fi
	go test -tags=integration -timeout 160s ./... -v -coverprofile=coverage.out

.PHONY: all build test lint run clean e2e table-init
