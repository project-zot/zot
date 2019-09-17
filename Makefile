export GO111MODULE=on
TOP_LEVEL=$(shell git rev-parse --show-toplevel)
COMMIT_HASH=$(shell git describe --always --tags --long)
COMMIT=$(if $(shell git status --porcelain --untracked-files=no),$(COMMIT_HASH)-dirty,$(COMMIT_HASH))
CONTAINER_RUNTIME := $(shell command -v podman 2> /dev/null || echo docker)
PATH := bin:$(PATH)

.PHONY: all
all: doc binary debug test check

.PHONY: binary
binary: doc
	go build -v -ldflags "-X  github.com/anuvu/zot/pkg/api.Commit=${COMMIT}" -o bin/zot -tags=jsoniter ./cmd/zot

.PHONY: debug
debug: doc
	go build -v -gcflags all='-N -l' -ldflags "-X  github.com/anuvu/zot/pkg/api.Commit=${COMMIT}" -o bin/zot-debug -tags=jsoniter ./cmd/zot

.PHONY: test
test:
	$(shell cd test/data; ./gen_certs.sh; cd ${TOP_LEVEL})
	go test -v -race -cover -coverprofile=coverage.txt -covermode=atomic ./...

.PHONY: check
check:
	golangci-lint --version || curl -sfL https://install.goreleaser.com/github.com/golangci/golangci-lint.sh | sh -s v1.17.1
	golangci-lint run --enable-all ./cmd/... ./pkg/...

docs/docs.go: 
	swag -v || go install github.com/swaggo/swag/cmd/swag
	swag init -g pkg/api/routes.go

.PHONY: doc
doc: docs/docs.go

.PHONY: clean
clean:
	rm -f bin/zot* docs/*

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
