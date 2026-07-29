.PHONY: test guard-smoke guard-e2e

test:
	go test ./...

guard-smoke:
	go run ./cmd/kontext guard smoke-test

guard-e2e:
	./scripts/guard-e2e-local.sh
