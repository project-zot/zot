export GO111MODULE=on

.PHONY: all
all: doc binary debug test check

.PHONY: binary
binary: doc
	go build -v -o bin/zot -tags=jsoniter ./cmd/zot

.PHONY: debug
debug: doc
	go build -v -gcflags '-N -l' -o bin/zot-debug -tags=jsoniter ./cmd/zot

.PHONY: test
test:
	go test -v -race -cover -coverprofile=coverage.txt -covermode=atomic ./...

./bin/golangci-lint:
	curl -sfL https://install.goreleaser.com/github.com/golangci/golangci-lint.sh | sh -s v1.17.1

.PHONY: check
check: ./bin/golangci-lint
	./bin/golangci-lint run --enable-all ./cmd/... ./pkg/...

.PHONY: doc
doc:
	swag -v || go get -u github.com/swaggo/swag/cmd/swag
	swag init -g pkg/api/routes.go

.PHONY: clean
clean:
	rm -f bin/zot*

.PHONY: run
run: binary test
	./bin/zot serve examples/config-test.json
