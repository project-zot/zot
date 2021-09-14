export GO111MODULE=on
TOP_LEVEL=$(shell git rev-parse --show-toplevel)
COMMIT_HASH=$(shell git describe --always --tags --long)
GO_VERSION=$(shell go version | awk '{print $$3}')
COMMIT=$(if $(shell git status --porcelain --untracked-files=no),$(COMMIT_HASH)-dirty,$(COMMIT_HASH))
CONTAINER_RUNTIME := $(shell command -v podman 2> /dev/null || echo docker)
PATH := bin:$(PATH)
TMPDIR := $(shell mktemp -d)
STACKER := $(shell which stacker)

.PHONY: all
all: doc binary binary-minimal debug test test-clean check

.PHONY: binary-minimal
binary-minimal: doc
	go build -tags minimal -v  -ldflags "-X  github.com/anuvu/zot/pkg/api.Commit=${COMMIT} -X github.com/anuvu/zot/pkg/api.BinaryType=minimal -X github.com/anuvu/zot/pkg/api.GoVersion=${GO_VERSION}" -o bin/zot-minimal ./cmd/zot

.PHONY: binary
binary: doc
	go build -tags extended -v -ldflags "-X  github.com/anuvu/zot/pkg/api.Commit=${COMMIT} -X github.com/anuvu/zot/pkg/api.BinaryType=extended -X github.com/anuvu/zot/pkg/api.GoVersion=${GO_VERSION}" -o bin/zot ./cmd/zot

.PHONY: debug
debug: doc
	go build -tags extended -v -gcflags all='-N -l' -ldflags "-X  github.com/anuvu/zot/pkg/api.Commit=${COMMIT} -X github.com/anuvu/zot/pkg/api.BinaryType=extended -X github.com/anuvu/zot/pkg/api.GoVersion=${GO_VERSION}" -o bin/zot-debug ./cmd/zot

.PHONY: test
test:
	$(shell mkdir -p test/data;  cd test/data; ../scripts/gen_certs.sh; cd ${TOP_LEVEL}; sudo skopeo --insecure-policy copy -q docker://public.ecr.aws/t0x7q1g8/centos:7 oci:${TOP_LEVEL}/test/data/zot-test:0.0.1;sudo skopeo --insecure-policy copy -q docker://public.ecr.aws/t0x7q1g8/centos:8 oci:${TOP_LEVEL}/test/data/zot-cve-test:0.0.1)
	$(shell sudo mkdir -p /etc/containers/certs.d/127.0.0.1:8089/; sudo cp test/data/client.* /etc/containers/certs.d/127.0.0.1:8089/; sudo cp test/data/ca.* /etc/containers/certs.d/127.0.0.1:8089/;)
	$(shell sudo chmod a=rwx /etc/containers/certs.d/127.0.0.1:8089/*.key)
	go test -tags extended -v -race -cover -coverpkg ./... -coverprofile=coverage.txt -covermode=atomic ./...

.PHONY: test-clean
test-clean:
	$(shell sudo rm -rf /etc/containers/certs.d/127.0.0.1:8089/)

.PHONY: covhtml
covhtml:
	go tool cover -html=coverage.txt -o coverage.html

.PHONY: check
check: ./golangcilint.yaml
	golangci-lint --version || curl -sfL https://install.goreleaser.com/github.com/golangci/golangci-lint.sh | sh -s v1.26.0
	golangci-lint --config ./golangcilint.yaml run --enable-all --build-tags extended ./cmd/... ./pkg/...

docs/docs.go: 
	swag -v || go install github.com/swaggo/swag/cmd/swag
	swag init -g pkg/api/routes.go

.PHONY: doc
doc: docs/docs.go

.PHONY: update-licenses
update-licenses:
	go get github.com/google/go-licenses
	$(shell echo "Module | License URL | License" > THIRD-PARTY-LICENSES.md; echo "---|---|---" >> THIRD-PARTY-LICENSES.md; for i in $$(cat go.sum  | awk '{print $$1}'); do l=$$(go-licenses csv $$i 2>/dev/null); if [ $$? -ne 0 ]; then continue; fi; echo $$l | tr \, \| | tr ' ' '\n'; done | sort -u >> THIRD-PARTY-LICENSES.md)

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
