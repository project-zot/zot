export GO111MODULE=on
TOP_LEVEL=$(shell git rev-parse --show-toplevel)
CONTAINER_RUNTIME := $(shell command -v podman 2> /dev/null || echo docker)
PATH := bin:$(PATH)

.PHONY: all
all: doc binary debug test check

.PHONY: binary
binary: doc
	go build -v -o bin/zot -tags=jsoniter ./cmd/zot

.PHONY: debug
debug: doc
	go build -v -gcflags all='-N -l' -o bin/zot-debug -tags=jsoniter ./cmd/zot

.PHONY: test
test:
	$(shell cd test/data; ./gen_certs.sh; cd ${TOP_LEVEL})
	go test -v -race -cover -coverprofile=coverage.txt -covermode=atomic ./...

.PHONY: check
check:
	golangci-lint --version || curl -sfL https://install.goreleaser.com/github.com/golangci/golangci-lint.sh | sh -s v1.17.1
	golangci-lint run --enable-all ./cmd/... ./pkg/...

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

.PHONY: binary-container
binary-container:
	${CONTAINER_RUNTIME} build ${BUILD_ARGS} -f Dockerfile -t zot:latest .
	${CONTAINER_RUNTIME} run --rm --security-opt label=disable -v $$(pwd):/go/src/github.com/anuvu/zot \
		zot:latest make

.PHONY: binary-stacker
binary-stacker:
	stacker build --substitute PWD=$$PWD --no-cache
