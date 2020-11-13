export GO111MODULE=on
TOP_LEVEL=$(shell git rev-parse --show-toplevel)
COMMIT_HASH=$(shell git describe --always --tags --long)
COMMIT=$(if $(shell git status --porcelain --untracked-files=no),$(COMMIT_HASH)-dirty,$(COMMIT_HASH))
CONTAINER_RUNTIME := $(shell command -v podman 2> /dev/null || echo docker)
PATH := bin:$(PATH)
TMPDIR := $(shell mktemp -d)
STACKER := $(shell which stacker)

.PHONY: all
all: doc binary binary-minimal debug test check

.PHONY: binary-minimal
binary-minimal: doc
	go build -tags minimal -v  -ldflags "-X  github.com/anuvu/zot/pkg/api.Commit=${COMMIT}" -o bin/zot-minimal ./cmd/zot

.PHONY: binary
binary: doc
	go build -tags extended -v -ldflags "-X  github.com/anuvu/zot/pkg/api.Commit=${COMMIT}" -o bin/zot ./cmd/zot

.PHONY: debug
debug: doc
	go build -tags extended -v -gcflags all='-N -l' -ldflags "-X  github.com/anuvu/zot/pkg/api.Commit=${COMMIT}" -o bin/zot-debug ./cmd/zot

.PHONY: test
test:
	$(shell mkdir -p test/data;  cd test/data; ../scripts/gen_certs.sh; cd ${TOP_LEVEL}; sudo skopeo --insecure-policy copy -q docker://centos:latest oci:${TOP_LEVEL}/test/data/zot-test:0.0.1;sudo skopeo --insecure-policy copy -q docker://centos:8 oci:${TOP_LEVEL}/test/data/zot-cve-test:0.0.1)
	sudo -E env "PATH=$$PATH" go test -tags extended -v -race -cover -coverpkg ./... -coverprofile=coverage.txt -covermode=atomic ./...

.PHONY: covhtml
covhtml:
	go tool cover -html=coverage.txt -o coverage.html

.PHONY: check
check: .bazel/golangcilint.yaml
	golangci-lint --version || curl -sfL https://install.goreleaser.com/github.com/golangci/golangci-lint.sh | sh -s v1.26.0
	golangci-lint --config .bazel/golangcilint.yaml run --enable-all --build-tags extended ./cmd/... ./pkg/...

docs/docs.go: 
	swag -v || go install github.com/swaggo/swag/cmd/swag
	swag init -g pkg/api/routes.go

.PHONY: doc
doc: docs/docs.go

.PHONY: clean
clean:
	rm -f bin/zot*

.PHONY: run
run: binary test
	./bin/zot serve examples/config-test.json

.PHONY: binary-container
binary-container:
	${CONTAINER_RUNTIME} build ${BUILD_ARGS} -f Dockerfile -t zot-build:latest .

.PHONY: run-container
run-container:
	${CONTAINER_RUNTIME} run --rm --security-opt label=disable -v $$(pwd):/go/src/github.com/anuvu/zot \
		zot-build:latest 

.PHONY: binary-stacker
binary-stacker:
	sudo ${STACKER} build --substitute PWD=$$PWD

.PHONY: image
image:
	${CONTAINER_RUNTIME} build ${BUILD_ARGS} -f Dockerfile -t zot:latest .
