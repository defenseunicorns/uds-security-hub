# Set the shell to bash
SHELL := /bin/bash

# Default target
all: build

# Get the current Git commit SHA and the latest Git tag
GIT_COMMIT := $(shell git rev-parse HEAD)
GIT_TAG := $(shell git describe --tags --abbrev=0)

# Build the project
build:
	go build -ldflags "-X 'github.com/defenseunicorns/uds-security-hub/cmd.CommitSHA=$(GIT_COMMIT)' -X 'github.com/defenseunicorns/uds-security-hub/cmd.Version=$(GIT_TAG)'" -o bin/uds-security-hub main.go
	go build -ldflags "-X 'github.com/defenseunicorns/uds-security-hub/cmd.CommitSHA=$(GIT_COMMIT)' -X 'github.com/defenseunicorns/uds-security-hub/cmd.Version=$(GIT_TAG)'" -o bin/table-init ./cmd/table-init/main.go
	go build -ldflags "-X 'github.com/defenseunicorns/uds-security-hub/cmd.CommitSHA=$(GIT_COMMIT)' -X 'github.com/defenseunicorns/uds-security-hub/cmd.Version=$(GIT_TAG)'" -o bin/store ./cmd/store/main.go
	go build -ldflags "-X 'github.com/defenseunicorns/uds-security-hub/cmd.CommitSHA=$(GIT_COMMIT)' -X 'github.com/defenseunicorns/uds-security-hub/cmd.Version=$(GIT_TAG)'" -o bin/scan ./cmd/scan.go

# Lint the code
lint:
	golangci-lint run ./...

# Clean the build
clean:
	rm -rf bin/

test: test-unit test-integration

test-unit:
	go test -timeout 160s ./... -v -coverprofile=coverage.out

test-integration:
	@if [ -z "$${GITHUB_TOKEN}" ] || [ -z "$${GHCR_CREDS}" ]; then \
		echo "Error: GITHUB_TOKEN or GHCR_CREDS is not set"; \
		exit 1; \
	fi
	integration=true go test -timeout 160s ./... -v -coverprofile=coverage.out

verify-version:
	@for binary in uds-security-hub store; do \
		VERSION_OUTPUT=$$(./bin/$$binary --version); \
		echo "Version output for $$binary: $$VERSION_OUTPUT"; \
		if [[ $$VERSION_OUTPUT != *\"version\"* || $$VERSION_OUTPUT != *\"commit\"* ]]; then \
			echo "Version information not embedded correctly in $$binary"; \
			exit 1; \
		fi; \
	done

.PHONY: all build test lint run clean e2e table-init verify-version
