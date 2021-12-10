export GO111MODULE=on
TOP_LEVEL=$(shell git rev-parse --show-toplevel)
COMMIT_HASH=$(shell git describe --always --tags --long)
GO_VERSION=$(shell go version | awk '{print $$3}')
COMMIT ?= $(if $(shell git status --porcelain --untracked-files=no),$(COMMIT_HASH)-dirty,$(COMMIT_HASH))
CONTAINER_RUNTIME := $(shell command -v podman 2> /dev/null || echo docker)
TMPDIR := $(shell mktemp -d)
TOOLSDIR := hack/tools
PATH := bin:$(TOOLSDIR)/bin:$(PATH)
STACKER := $(shell which stacker)
GOLINTER := $(TOOLSDIR)/bin/golangci-lint
NOTATION := $(TOOLSDIR)/bin/notation
OS ?= linux
ARCH ?= amd64

.PHONY: all
all: swagger binary binary-minimal binary-debug binary-arch binary-arch-minimal cli cli-arch bench bench-arch exporter-minimal verify-config test test-clean check

.PHONY: binary-minimal
binary-minimal: swagger
	env CGO_ENABLED=0 GOOS=$(OS) GOARCH=$(ARCH) go build -o bin/zot-minimal -tags minimal,containers_image_openpgp -v -trimpath -ldflags "-X zotregistry.io/zot/pkg/api/config.Commit=${COMMIT} -X zotregistry.io/zot/pkg/api/config.BinaryType=minimal -X zotregistry.io/zot/pkg/api/config.GoVersion=${GO_VERSION} -s -w" ./cmd/zot

.PHONY: binary
binary: swagger
	env CGO_ENABLED=0 GOOS=$(OS) GOARCH=$(ARCH) go build -o bin/zot -tags extended,containers_image_openpgp -v -trimpath -ldflags "-X zotregistry.io/zot/pkg/api/config.Commit=${COMMIT} -X zotregistry.io/zot/pkg/api/config.BinaryType=extended -X zotregistry.io/zot/pkg/api/config.GoVersion=${GO_VERSION} -s -w" ./cmd/zot

.PHONY: binary-debug
binary-debug: swagger
	env CGO_ENABLED=0 GOOS=$(OS) GOARCH=$(ARCH) go build -o bin/zot-debug -tags extended,containers_image_openpgp -v -gcflags all='-N -l' -ldflags "-X zotregistry.io/zot/pkg/api/config.Commit=${COMMIT} -X zotregistry.io/zot/pkg/api/config.BinaryType=extended -X zotregistry.io/zot/pkg/api/config.GoVersion=${GO_VERSION}" ./cmd/zot

.PHONY: binary-arch-minimal
binary-arch-minimal: swagger
	env CGO_ENABLED=0 GOOS=$(OS) GOARCH=$(ARCH) go build -o bin/zot-$(ARCH)-minimal -tags minimal,containers_image_openpgp -v -trimpath -ldflags "-X zotregistry.io/zot/pkg/api/config.Commit=${COMMIT} -X zotregistry.io/zot/pkg/api/config.BinaryType=minimal -X zotregistry.io/zot/pkg/api/config.GoVersion=${GO_VERSION} -s -w" ./cmd/zot

.PHONY: binary-arch
binary-arch: swagger
	env CGO_ENABLED=0 GOOS=$(OS) GOARCH=$(ARCH) go build -o bin/zot-$(ARCH) -tags extended,containers_image_openpgp -v -trimpath -ldflags "-X zotregistry.io/zot/pkg/api/config.Commit=${COMMIT} -X zotregistry.io/zot/pkg/api/config.BinaryType=extended -X zotregistry.io/zot/pkg/api/config.GoVersion=${GO_VERSION} -s -w" ./cmd/zot

.PHONY: cli
cli:
	env CGO_ENABLED=0 GOOS=$(OS) GOARCH=$(ARCH) go build -o bin/zli -tags extended,containers_image_openpgp -v -trimpath -ldflags "-X zotregistry.io/zot/pkg/api/config.Commit=${COMMIT} -X zotregistry.io/zot/pkg/api/config.BinaryType=extended -X zotregistry.io/zot/pkg/api/config.GoVersion=${GO_VERSION} -s -w" ./cmd/zli

.PHONY: cli-arch
cli-arch: 
	env CGO_ENABLED=0 GOOS=$(OS) GOARCH=$(ARCH) go build -o bin/zli-$(ARCH) -tags extended,containers_image_openpgp -v -trimpath -ldflags "-X zotregistry.io/zot/pkg/api/config.Commit=${COMMIT} -X zotregistry.io/zot/pkg/api/config.BinaryType=extended -X zotregistry.io/zot/pkg/api/config.GoVersion=${GO_VERSION} -s -w" ./cmd/zli

.PHONY: bench
bench:
	env CGO_ENABLED=0 GOOS=$(OS) GOARCH=$(ARCH) go build -o bin/zb -tags extended,containers_image_openpgp -v -trimpath -ldflags "-X zotregistry.io/zot/pkg/api/config.Commit=${COMMIT} -X zotregistry.io/zot/pkg/api/config.BinaryType=extended -X zotregistry.io/zot/pkg/api/config.GoVersion=${GO_VERSION} -s -w" ./cmd/zb

.PHONY: bench-arch
bench-arch: 
	env CGO_ENABLED=0 GOOS=$(OS) GOARCH=$(ARCH) go build -o bin/zb-$(ARCH) -tags extended,containers_image_openpgp -v -trimpath -ldflags "-X zotregistry.io/zot/pkg/api/config.Commit=${COMMIT} -X zotregistry.io/zot/pkg/api/config.BinaryType=extended -X zotregistry.io/zot/pkg/api/config.GoVersion=${GO_VERSION} -s -w" ./cmd/zb

.PHONY: exporter-minimal
exporter-minimal: swagger
	env CGO_ENABLED=0 GOOS=$(OS) GOARCH=$(ARCH) go build -o bin/zot-exporter -tags minimal,containers_image_openpgp -v -trimpath ./cmd/exporter

.PHONY: test
test: check-skopeo $(NOTATION)
	$(shell mkdir -p test/data;  cd test/data; ../scripts/gen_certs.sh; cd ${TOP_LEVEL}; sudo skopeo --insecure-policy copy -q docker://public.ecr.aws/t0x7q1g8/centos:7 oci:${TOP_LEVEL}/test/data/zot-test:0.0.1;sudo skopeo --insecure-policy copy -q docker://public.ecr.aws/t0x7q1g8/centos:8 oci:${TOP_LEVEL}/test/data/zot-cve-test:0.0.1)
	$(shell sudo mkdir -p /etc/containers/certs.d/127.0.0.1:8089/; sudo cp test/data/client.* test/data/ca.* /etc/containers/certs.d/127.0.0.1:8089/;)
	$(shell sudo chmod a=rwx /etc/containers/certs.d/127.0.0.1:8089/*.key)
	go test -tags extended,containers_image_openpgp -v -trimpath -race -timeout 15m -cover -coverpkg ./... -coverprofile=coverage-extended.txt -covermode=atomic ./...
	go test -tags minimal,containers_image_openpgp -v -trimpath -race -cover -coverpkg ./... -coverprofile=coverage-minimal.txt -covermode=atomic ./...

.PHONY: test-clean
test-clean:
	$(shell sudo rm -rf /etc/containers/certs.d/127.0.0.1:8089/)

.PHONY: check-skopeo
check-skopeo:
	skopeo -v || (echo "You need skopeo to be installed in order to run tests"; exit 1)

$(NOTATION):
	mkdir -p $(TOOLSDIR)/bin
	curl -Lo notation.tar.gz https://github.com/notaryproject/notation/releases/download/v0.7.1-alpha.1/notation_0.7.1-alpha.1_linux_amd64.tar.gz
	tar xvzf notation.tar.gz -C $(TOOLSDIR)/bin  notation
	rm notation.tar.gz

.PHONY: covhtml
covhtml:
	tail -n +2 coverage-minimal.txt > tmp.txt && mv tmp.txt coverage-minimal.txt
	cat coverage-extended.txt coverage-minimal.txt > coverage.txt
	go tool cover -html=coverage.txt -o coverage.html

$(GOLINTER):
	mkdir -p $(TOOLSDIR)/bin
	curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $(TOOLSDIR)/bin v1.43.0
	$(GOLINTER) version

.PHONY: check
check: ./golangcilint.yaml $(GOLINTER)
	$(GOLINTER) --config ./golangcilint.yaml run --enable-all --out-format=colored-line-number --build-tags minimal,containers_image_openpgp ./...
	$(GOLINTER) --config ./golangcilint.yaml run --enable-all --out-format=colored-line-number --build-tags extended,containers_image_openpgp ./...

swagger/docs.go: 
	swag -v || go install github.com/swaggo/swag/cmd/swag
	swag init -o swagger -g pkg/api/routes.go

.PHONY: swagger
swagger: swagger/docs.go

.PHONY: update-licenses
update-licenses:
	go get github.com/google/go-licenses
	$(shell echo "Module | License URL | License" > THIRD-PARTY-LICENSES.md; echo "---|---|---" >> THIRD-PARTY-LICENSES.md; for i in $$(cat go.sum  | awk '{print $$1}'); do l=$$(go-licenses csv $$i 2>/dev/null); if [ $$? -ne 0 ]; then continue; fi; echo $$l | tr \, \| | tr ' ' '\n'; done | sort -u >> THIRD-PARTY-LICENSES.md)

.PHONY: clean
clean:
	rm -f bin/z*
	rm -rf hack

.PHONY: run
run: binary test
	./bin/zot serve examples/config-test.json

.PHONY: verify-config
verify-config: binary
	$(foreach file, $(wildcard examples/config-*), ./bin/zot verify $(file) || exit 1;)

.PHONY: binary-container
binary-container:
	${CONTAINER_RUNTIME} build ${BUILD_ARGS} -f Dockerfile -t zot-build:latest .

.PHONY: run-container
run-container:
	${CONTAINER_RUNTIME} run --rm --security-opt label=disable -v $$(pwd):/go/src/github.com/project-zot/zot \
		zot-build:latest 

.PHONY: binary-stacker
binary-stacker:
	sudo ${STACKER} build --substitute PWD=$$PWD

.PHONY: image
image:
	${CONTAINER_RUNTIME} build ${BUILD_ARGS} -f Dockerfile -t zot:latest .
