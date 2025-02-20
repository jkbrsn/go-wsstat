PACKAGES = $(shell go list ./...)

test-all: vet lint test

test:
	go test -v -parallel=8 ${PACKAGES}

test-race:
	go test -v -parallel=8 -race ${PACKAGES}

vet:
	go vet ${PACKAGES}

lint:
	@go install golang.org/x/lint/golint@latest
	go list ./... | grep -v vendor | xargs -n1 golint

cover:
	go test -coverprofile=cover.out
	go tool cover -html cover.out -o coverage.html
	@which xdg-open &> /dev/null && xdg-open coverage.html || open coverage.html || echo "No way to open coverage.html automatically found."
	@sleep 1
	@rm -f cover.out coverage.html

explain:
	@echo "Usage: make [target]"
	@echo ""
	@echo "Targets:"
	@echo "  test           - Test the package code."
	@echo "  test-all       - Test, lint and vet the package code."
	@echo "  test-race      - Test race conditions."
	@echo "  cover          - Run the go test coverage tool."
	@echo "  lint           - Run golint on the package code."
	@echo "  vet            - Run go vet."
	@echo "  explain        - Display this help message."

.PHONY: test-all test test-race vet lint cover

.DEFAULT_GOAL := explain
