# Set V to 1 for verbose output from the Makefile
Q=$(if $V,,@)
SRC=$(shell find . -type f -name '*.go')

all: lint test

.PHONY: all

#########################################
# Bootstrapping
#########################################

bootstrap:
	$Q curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $$(go env GOPATH)/bin latest
	$Q go install golang.org/x/vuln/cmd/govulncheck@latest
	$Q go install gotest.tools/gotestsum@latest

.PHONY: bootstrap

#########################################
# Test
#########################################

test:
	$Q gotestsum -- -race -coverprofile coverage.out ./...

.PHONY: test race

#########################################
# Linting
#########################################

fmt:
	$Q goimports -l -w $(SRC)

lint: SHELL:=/bin/bash
lint:
	$Q LOG_LEVEL=error golangci-lint run --config <(curl -s https://raw.githubusercontent.com/smallstep/workflows/master/.golangci.yml) --timeout=30m
	$Q govulncheck ./...

.PHONY: lint fmt
