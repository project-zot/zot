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
BENCH_OUTPUT ?= stdout

.PHONY: all
all: modcheck swagger binary binary-minimal binary-debug cli bench exporter-minimal verify-config test covhtml test-clean check

.PHONY: modcheck
modcheck:
	go mod tidy

.PHONY: binary-debug
binary-debug: modcheck swagger
	env CGO_ENABLED=0 GOOS=$(OS) GOARCH=$(ARCH) go build -o bin/zot-$(OS)-$(ARCH)-debug -tags extended,containers_image_openpgp -v -gcflags all='-N -l' -ldflags "-X zotregistry.io/zot/pkg/api/config.Commit=${COMMIT} -X zotregistry.io/zot/pkg/api/config.BinaryType=extended -X zotregistry.io/zot/pkg/api/config.GoVersion=${GO_VERSION}" ./cmd/zot

.PHONY: binary-minimal
binary-minimal: modcheck swagger
	env CGO_ENABLED=0 GOOS=$(OS) GOARCH=$(ARCH) go build -o bin/zot-$(OS)-$(ARCH)-minimal -tags minimal,containers_image_openpgp -v -trimpath -ldflags "-X zotregistry.io/zot/pkg/api/config.Commit=${COMMIT} -X zotregistry.io/zot/pkg/api/config.BinaryType=minimal -X zotregistry.io/zot/pkg/api/config.GoVersion=${GO_VERSION} -s -w" ./cmd/zot

.PHONY: binary
binary: modcheck swagger
	env CGO_ENABLED=0 GOOS=$(OS) GOARCH=$(ARCH) go build -o bin/zot-$(OS)-$(ARCH) -tags extended,containers_image_openpgp -v -trimpath -ldflags "-X zotregistry.io/zot/pkg/api/config.Commit=${COMMIT} -X zotregistry.io/zot/pkg/api/config.BinaryType=extended -X zotregistry.io/zot/pkg/api/config.GoVersion=${GO_VERSION} -s -w" ./cmd/zot

.PHONY: cli
cli: modcheck
	env CGO_ENABLED=0 GOOS=$(OS) GOARCH=$(ARCH) go build -o bin/zli-$(OS)-$(ARCH) -tags extended,containers_image_openpgp -v -trimpath -ldflags "-X zotregistry.io/zot/pkg/api/config.Commit=${COMMIT} -X zotregistry.io/zot/pkg/api/config.BinaryType=extended -X zotregistry.io/zot/pkg/api/config.GoVersion=${GO_VERSION} -s -w" ./cmd/zli

.PHONY: bench
bench: modcheck
	env CGO_ENABLED=0 GOOS=$(OS) GOARCH=$(ARCH) go build -o bin/zb-$(OS)-$(ARCH) -tags extended,containers_image_openpgp -v -trimpath -ldflags "-X zotregistry.io/zot/pkg/api/config.Commit=${COMMIT} -X zotregistry.io/zot/pkg/api/config.BinaryType=extended -X zotregistry.io/zot/pkg/api/config.GoVersion=${GO_VERSION} -s -w" ./cmd/zb

.PHONY: exporter-minimal
exporter-minimal: modcheck
	env CGO_ENABLED=0 GOOS=$(OS) GOARCH=$(ARCH) go build -o bin/zxp-$(OS)-$(ARCH) -tags minimal,containers_image_openpgp -v -trimpath ./cmd/zxp

.PHONY: test
test: check-skopeo $(NOTATION)
	$(shell mkdir -p test/data;  cd test/data; ../scripts/gen_certs.sh; cd ${TOP_LEVEL}; skopeo --insecure-policy copy -q docker://public.ecr.aws/t0x7q1g8/centos:7 oci:${TOP_LEVEL}/test/data/zot-test:0.0.1;skopeo --insecure-policy copy -q docker://public.ecr.aws/t0x7q1g8/centos:8 oci:${TOP_LEVEL}/test/data/zot-cve-test:0.0.1)
	$(shell sudo mkdir -p /etc/containers/certs.d/127.0.0.1:8089/; sudo cp test/data/client.* test/data/ca.* /etc/containers/certs.d/127.0.0.1:8089/;)
	$(shell sudo chmod a=rwx /etc/containers/certs.d/127.0.0.1:8089/*.key)
	go test -tags extended,containers_image_openpgp -v -trimpath -race -timeout 15m -cover -coverpkg ./... -coverprofile=coverage-extended.txt -covermode=atomic ./...
	go test -tags minimal,containers_image_openpgp -v -trimpath -race -cover -coverpkg ./... -coverprofile=coverage-minimal.txt -covermode=atomic ./...
	# development-mode unit tests possibly using failure injection
	go test -tags dev,extended,containers_image_openpgp -v -trimpath -race -timeout 15m -cover -coverpkg ./... -coverprofile=coverage-dev-extended.txt -covermode=atomic ./pkg/test/... ./pkg/storage/... ./pkg/extensions/sync/... -run ^TestInject
	go test -tags dev,minimal,containers_image_openpgp -v -trimpath -race -cover -coverpkg ./... -coverprofile=coverage-dev-minimal.txt -covermode=atomic ./pkg/test/... ./pkg/storage/... ./pkg/extensions/sync/... -run ^TestInject

.PHONY: run-bench
run-bench: binary bench
	bin/zot-$(OS)-$(ARCH) serve examples/config-minimal.json &
	sleep 5
	bin/zb-$(OS)-$(ARCH) -c 10 -n 100 -o $(BENCH_OUTPUT) http://localhost:8080
	killall -r zot-*

.PHONY: push-pull
push-pull: binary check-skopeo
	bin/zot-$(OS)-$(ARCH) serve examples/config-minimal.json &
	sleep 5
	# skopeo push/pull
	skopeo --debug copy --format=oci --dest-tls-verify=false docker://ghcr.io/project-zot/golang:1.17 docker://localhost:8080/golang:1.17
	skopeo --debug copy --src-tls-verify=false docker://localhost:8080/golang:1.17 oci:golang:1.17
	# oras artifacts
	echo "{\"name\":\"foo\",\"value\":\"bar\"}" > config.json
	echo "hello world" > artifact.txt
	oras push localhost:8080/hello-artifact:v2 \
	    --manifest-config config.json:application/vnd.acme.rocket.config.v1+json \
		      artifact.txt:text/plain -d -v
	rm -f artifact.txt # first delete the file
	oras pull localhost:8080/hello-artifact:v2 -d -v -a
	grep -q "hello world" artifact.txt  # should print "hello world"
	if [ $? -ne 0 ]; then \
		killall -r zot-*; \
		exit 1; \
	fi
	killall -r zot-*

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
	go install github.com/wadey/gocovmerge@latest
	gocovmerge coverage-minimal.txt coverage-extended.txt coverage-dev-minimal.txt coverage-dev-extended.txt > coverage.txt
	go tool cover -html=coverage.txt -o coverage.html

$(GOLINTER):
	mkdir -p $(TOOLSDIR)/bin
	curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $(TOOLSDIR)/bin v1.43.0
	$(GOLINTER) version

.PHONY: check
check: ./golangcilint.yaml $(GOLINTER)
	$(GOLINTER) --config ./golangcilint.yaml run --enable-all --out-format=colored-line-number --build-tags minimal,containers_image_openpgp ./...
	$(GOLINTER) --config ./golangcilint.yaml run --enable-all --out-format=colored-line-number --build-tags extended,containers_image_openpgp ./...
	$(GOLINTER) --config ./golangcilint.yaml run --enable-all --out-format=colored-line-number --build-tags dev,minimal,containers_image_openpgp ./...
	$(GOLINTER) --config ./golangcilint.yaml run --enable-all --out-format=colored-line-number --build-tags dev,extended,containers_image_openpgp ./...

swagger/docs.go: 
	swag -v || go install github.com/swaggo/swag/cmd/swag
	swag init -o swagger -g pkg/api/routes.go

.PHONY: swagger
swagger: swagger/docs.go

.PHONY: update-licenses
update-licenses:
	@echo "Detecting and updating licenses ... please be patient!"
	go install github.com/google/go-licenses@latest
	$(shell echo "Module | License URL | License" > THIRD-PARTY-LICENSES.md; echo "---|---|---" >> THIRD-PARTY-LICENSES.md; for i in $$(go list -m all  | awk '{print $$1}'); do l=$$(go-licenses csv $$i 2>/dev/null); if [ $$? -ne 0 ]; then continue; fi; echo $$l | tr \, \| | tr ' ' '\n'; done | sort -u >> THIRD-PARTY-LICENSES.md)

.PHONY: check-licenses
check-licenses:
	go install github.com/google/go-licenses@latest
	@for tag in "extended,containers_image_openpgp" "minimal,containers_image_openpgp"; do \
		echo Evaluating tag: $$tag;\
		for mod in $$(go list -m -f '{{if not (or .Indirect .Main)}}{{.Path}}{{end}}' all); do \
			while [ x$$mod != x ]; do \
				echo -n "Checking $$mod ... "; \
				result=$$(GOFLAGS="-tags=$${tag}" go-licenses check $$mod 2>&1); \
				if [ $$? -eq 0 ]; then \
					echo OK; \
					break; \
				fi; \
				echo "$${result}" | grep -q "Forbidden"; \
				if [ $$? -eq 0 ]; then \
					echo FAIL; \
					exit 1; \
				fi; \
				echo "$${result}" | egrep -q "missing go.sum entry|no required module provides package|build constraints exclude all|updates to go.mod needed"; \
				if [ $$? -eq 0 ]; then \
					echo UNKNOWN; \
					break; \
				fi; \
			done; \
		 done; \
	 done

.PHONY: clean
clean:
	rm -f bin/z*
	rm -rf hack

.PHONY: run
run: binary test
	./bin/zot-$(OS)-$(ARCH) serve examples/config-test.json

.PHONY: verify-config
verify-config: binary
	$(foreach file, $(wildcard examples/config-*), ./bin/zot-$(OS)-$(ARCH) verify $(file) || exit 1;)

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
