.PHONY: help up down logs run dev-run dev-certs build test lint vet tidy migrate migrate-down fmt kill

COMPOSE := docker compose -f ops/docker/docker-compose.yml
DB_URL  ?= postgres://deadman:deadman@localhost:5432/deadman?sslmode=disable
GOOSE_DIR := control/db/migrations

help:
	@awk 'BEGIN {FS = ":.*##"} /^[a-zA-Z_-]+:.*##/ {printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

up: ## Start local Postgres + MinIO
	$(COMPOSE) up -d

down: ## Stop and remove local stack
	$(COMPOSE) down

logs: ## Tail docker logs
	$(COMPOSE) logs -f

GOOSE_VERSION := v3.27.0

migrate: ## Apply pending DB migrations
	cd control && go run github.com/pressly/goose/v3/cmd/goose@$(GOOSE_VERSION) -dir db/migrations postgres "$(DB_URL)" up

migrate-down: ## Roll back one migration
	cd control && go run github.com/pressly/goose/v3/cmd/goose@$(GOOSE_VERSION) -dir db/migrations postgres "$(DB_URL)" down

run: ## Run the control-plane server (HTTP on :8080, no TLS)
	cd control && DEADMAN_DATABASE_URL="$(DB_URL)" go run ./cmd/server

dev-run: dev-certs kill ## Run the server with TLS + passkey-ready RP config (HTTPS on :8443)
	@bash -c '. ops/dev.env && cd control && go run ./cmd/server'

dev-certs: ops/dev-certs/deadman.local.pem ## Generate local TLS certs via mkcert (no-op if present)

ops/dev-certs/deadman.local.pem:
	@mkdir -p ops/dev-certs
	@if ! command -v mkcert >/dev/null 2>&1; then \
	  echo "mkcert not installed — see README for install steps"; exit 1; fi
	@if ! grep -q '^127\.0\.0\.1 deadman\.local' /etc/hosts; then \
	  echo "Add '127.0.0.1 deadman.local' to /etc/hosts (needs sudo)"; exit 1; fi
	cd ops/dev-certs && mkcert deadman.local
	@echo "Certs generated. If your browser still distrusts them, run 'mkcert -install' and restart the browser."

kill: ## Kill any process holding :8080 or :8443
	@lsof -ti:8080 2>/dev/null | xargs -r kill 2>/dev/null; true
	@lsof -ti:8443 2>/dev/null | xargs -r kill 2>/dev/null; true

build: ## Build the control-plane binary
	cd control && CGO_ENABLED=0 go build -o bin/deadman-control ./cmd/server

test: ## Run Go tests
	cd control && go test ./... -race -count=1

lint: ## Run golangci-lint
	cd control && go run github.com/golangci/golangci-lint/cmd/golangci-lint@v1.61.0 run ./...

vet: ## Run go vet
	cd control && go vet ./...

tidy: ## go mod tidy
	cd control && go mod tidy

fmt: ## Format Go code
	cd control && gofmt -s -w .
