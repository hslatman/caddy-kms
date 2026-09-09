.PHONY: test test-race test-tpm lint build

# Default test run: no cgo, no hardware.
test:
	CGO_ENABLED=0 go test ./...

test-race:
	go test -race ./...

# Opt-in: needs cgo and go-tpm-tools. On Debian/Ubuntu, install libssl-dev.
test-tpm:
	CGO_ENABLED=1 go test -tags tpmsimulator ./...

lint:
	gofmt -l .
	go vet ./...

# Build a Caddy binary with this module, to check the plugin actually loads.
build:
	xcaddy build --with github.com/hslatman/caddy-kms=.
