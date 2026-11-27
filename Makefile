.PHONY: all web server generate test vet vuln dev-server dev-web clean

DIST := server/internal/web/dist
BIN  := server/bin/kumokeep
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)

all: web server

## web: build the SvelteKit app and copy it into the Go embed directory
web:
	cd web && npm ci && npm run build
	find $(DIST) -mindepth 1 ! -name .placeholder -delete
	cp -r web/build/. $(DIST)/

## server: build the kumokeep binary (embeds whatever is in $(DIST))
server:
	cd server && CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=$(VERSION)" -o bin/kumokeep ./cmd/kumokeep

## generate: regenerate sqlc code from internal/db/{migrations,queries}
generate:
	cd server && go run github.com/sqlc-dev/sqlc/cmd/sqlc@v1.30.0 generate

test:
	cd server && go test -race ./...
	cd web && npm run check

vet:
	cd server && go vet ./...

vuln:
	cd server && go run golang.org/x/vuln/cmd/govulncheck@latest ./...

## dev-server: run the API on :8080 with a local ./data dir
dev-server:
	cd server && KUMOKEEP_DEV=true KUMOKEEP_DATA_DIR=../data go run ./cmd/kumokeep serve

## dev-web: run the Vite dev server (proxies /api to dev-server)
dev-web:
	cd web && npm run dev

clean:
	rm -rf server/bin web/build
	find $(DIST) -mindepth 1 ! -name .placeholder -delete
