export GO111MODULE=on
export GOEXPERIMENT=jsonv2
SHELL := /bin/bash
TOP_LEVEL=$(shell git rev-parse --show-toplevel)
COMMIT_HASH=$(shell git describe --always --tags --long)
RELEASE_TAG=$(shell git describe --tags --abbrev=0)
GO_VERSION=$(shell go version | awk '{print $$3}')
COMMIT ?= $(if $(shell git status --porcelain --untracked-files=no),$(COMMIT_HASH)-dirty,$(COMMIT_HASH))
CONTAINER_RUNTIME := $(shell command -v podman 2> /dev/null || echo docker)
TMPDIR := $(shell mktemp -d)
TOOLSDIR := $(shell pwd)/hack/tools
PATH := bin:$(TOOLSDIR)/bin:$(PATH)
STACKER := $(shell which stacker)
GOLINTER := $(TOOLSDIR)/bin/golangci-lint
GOLINTER_VERSION := v2.6.2
NOTATION := $(TOOLSDIR)/bin/notation
NOTATION_VERSION := 1.3.2
COSIGN := $(TOOLSDIR)/bin/cosign
COSIGN_VERSION := 2.2.0
HELM := $(TOOLSDIR)/bin/helm
ORAS := $(TOOLSDIR)/bin/oras
ORAS_VERSION := 1.2.1
HELM_VERSION := v3.9.1
REGCLIENT := $(TOOLSDIR)/bin/regctl
REGCLIENT_VERSION := v0.10.0
CRICTL := $(TOOLSDIR)/bin/crictl
CRICTL_VERSION := v1.26.1
ACTION_VALIDATOR := $(TOOLSDIR)/bin/action-validator
ACTION_VALIDATOR_VERSION := v0.5.3
ZUI_BUILD_PATH := ""
ZUI_VERSION := commit-111cb8e
ZUI_REPO_OWNER := project-zot
ZUI_REPO_NAME := zui
SWAGGER_VERSION := v1.16.2
STACKER := $(TOOLSDIR)/bin/stacker
STACKER_VERSION := v1.1.0-rc3
KIND := $(TOOLSDIR)/bin/kind
KIND_VERSION := v0.31.0
BATS := $(TOOLSDIR)/bin/bats
TESTDATA := $(TOP_LEVEL)/test/data
OS ?= $(shell go env GOOS)
ARCH ?= $(shell go env GOARCH)
GREP_BIN_PATH ?= $(shell which grep)
BLACKBOX_DOCKER_ENV = BUILDX_NO_DEFAULT_ATTESTATIONS=1 DOCKER_DEFAULT_PLATFORM=linux/amd64

MODULE_PATH := $(shell go list -m)
CONFIG_PACKAGE := $(MODULE_PATH)/pkg/api/config
CONFIG_RELEASE_TAG := $(CONFIG_PACKAGE).ReleaseTag
CONFIG_COMMIT := $(CONFIG_PACKAGE).Commit
CONFIG_BINARY_TYPE := $(CONFIG_PACKAGE).BinaryType
CONFIG_GO_VERSION := $(CONFIG_PACKAGE).GoVersion

PROTOC := $(TOOLSDIR)/bin/protoc
PROTOC_VERSION := 24.4
GO_PROTOC_VERSION := 1.31.0
HOST_OS := $(shell go env GOOS)
HOST_ARCH := $(shell go env GOARCH)
ifeq ($(HOST_OS),linux)
	PROTOC_OS := linux
else ifeq ($(HOST_OS),darwin)
	PROTOC_OS := osx
endif
ifeq ($(HOST_ARCH),amd64)
	PROTOC_ARCH := x86_64
else ifeq ($(HOST_ARCH),arm64)
	PROTOC_ARCH := aarch_64
endif

BENCH_OUTPUT ?= stdout
ALL_EXTENSIONS = debug,imagetrust,lint,metrics,mgmt,profile,scrub,search,sync,ui,userprefs,events
EXTENSIONS ?= sync,search,scrub,metrics,lint,ui,mgmt,profile,userprefs,imagetrust,events
UI_DEPENDENCIES := search,mgmt,userprefs
# freebsd is not supported for pie builds if CGO is disabled
# see supported platforms at https://cs.opensource.google/go/go/+/master:src/internal/platform/supported.go;l=222-231;drc=d7fcb5cf80953f1d63246f1ae9defa60c5ce2d76
BUILDMODE_FLAGS := -buildmode=pie
BASE_IMAGE=gcr.io/distroless/base-nossl-debian13:latest-$(ARCH)
ifeq ($(OS),freebsd)
	BUILDMODE_FLAGS=
	BASE_IMAGE=freebsd/freebsd-static:14.3
endif
BIN_EXT :=
ifeq ($(OS),windows)
	BIN_EXT=.exe
endif
comma:= ,
space := $(null) #
hyphen:= -

merge-ui-extensions=$(subst $(1),$(2),$(if $(findstring ui,$(3)),$(3)$(1)$(4),$(3)))
merged-extensions = $(call merge-ui-extensions,$(comma),$(space),$(EXTENSIONS),$(UI_DEPENDENCIES))
filter-valid = $(foreach ext, $(merged-extensions), $(if $(findstring $(ext),$(ALL_EXTENSIONS)),$(ext),$(error unknown extension: $(ext))))
add-extensions = $(subst $(1),$(2),$(sort $(filter-valid)))
BUILD_LABELS = $(call add-extensions,$(space),$(comma))
extended-name = -$(subst $(comma),$(hyphen),$(BUILD_LABELS))
GO_CMD_TAGS := $(if $(BUILD_LABELS),-tags $(BUILD_LABELS),)


BATS_TEST_FILE_PATH ?= replace_me
ifeq ($(BATS_VERBOSITY),2)
	BATS_FLAGS = --trace --verbose-run --show-output-of-passing-tests --print-output-on-failure
else ifeq ($(BATS_VERBOSITY),1)
	BATS_FLAGS = --trace --verbose-run --print-output-on-failure
else
	BATS_FLAGS = --print-output-on-failure
endif

.PHONY: all
all: swaggercheck binary binary-minimal binary-debug cli bench exporter-minimal verify-config check check-gh-actions test covhtml

.PHONY: modtidy
modtidy:
	go mod tidy

.PHONY: modcheck
modcheck: modtidy
	$(eval UNCOMMITED_FILES = $(shell git status --porcelain | grep -c 'go.mod\|go.sum'))
	@if [ $(UNCOMMITED_FILES) != 0 ]; then \
		echo "Updated go.mod and/or go.sum have uncommitted changes, commit the changes accordingly ";\
		git status;\
		exit 1;\
	fi

.PHONY: swaggercheck
swaggercheck: swagger
	$(eval UNCOMMITED_FILES = $(shell git status --porcelain | grep -c swagger))
	@if [ $(UNCOMMITED_FILES) != 0 ]; then \
		echo "Updated swagger files uncommitted, make sure all swagger files are committed:";\
		git status;\
		exit 1;\
	fi

.PHONY: build-metadata
build-metadata: $(if $(findstring ui,$(BUILD_LABELS)), ui)
	echo "Imports: \n"
	env GOEXPERIMENT=jsonv2 go list $(GO_CMD_TAGS) -f '{{ join .Imports "\n" }}' ./... | sort -u
	echo "\n Files: \n"
	env GOEXPERIMENT=jsonv2 go list $(GO_CMD_TAGS) -f '{{ join .GoFiles "\n" }}' ./... | sort -u

.PHONY: gen-protobuf
gen-protobuf: $(PROTOC)
	$(PROTOC) --experimental_allow_proto3_optional \
		--proto_path=$(TOP_LEVEL)/pkg/meta/proto \
		--go_out=$(TOP_LEVEL)/pkg/meta/proto \
		--go_opt='Moci/oci.proto=./gen' \
		--go_opt='Mmeta/meta.proto=./gen' \
		--go_opt='Moci/config.proto=./gen' \
		--go_opt='Moci/manifest.proto=./gen' \
		--go_opt='Moci/index.proto=./gen' \
		--go_opt='Moci/descriptor.proto=./gen' \
		--go_opt='Moci/versioned.proto=./gen' \
		$(TOP_LEVEL)/pkg/meta/proto/meta/meta.proto
	$(PROTOC) --experimental_allow_proto3_optional \
		--proto_path=$(TOP_LEVEL)/pkg/meta/proto \
		--go_out=$(TOP_LEVEL)/pkg/meta/proto \
		--go_opt='Moci/versioned.proto=./gen' \
		$(TOP_LEVEL)/pkg/meta/proto/oci/versioned.proto
	$(PROTOC) --experimental_allow_proto3_optional \
		--proto_path=$(TOP_LEVEL)/pkg/meta/proto \
		--go_out=$(TOP_LEVEL)/pkg/meta/proto \
		--go_opt='Moci/descriptor.proto=./gen' \
		$(TOP_LEVEL)/pkg/meta/proto/oci/descriptor.proto
	$(PROTOC) --experimental_allow_proto3_optional \
		--proto_path=$(TOP_LEVEL)/pkg/meta/proto \
		--go_out=$(TOP_LEVEL)/pkg/meta/proto \
		--go_opt='Moci/descriptor.proto=./gen' \
		--go_opt='Moci/versioned.proto=./gen' \
		--go_opt='Moci/index.proto=./gen' \
		$(TOP_LEVEL)/pkg/meta/proto/oci/index.proto
	$(PROTOC) --experimental_allow_proto3_optional \
		--proto_path=$(TOP_LEVEL)/pkg/meta/proto \
		--go_out=$(TOP_LEVEL)/pkg/meta/proto \
		--go_opt='Moci/oci.proto=./gen' \
		--go_opt='Moci/descriptor.proto=./gen' \
		--go_opt='Moci/config.proto=./gen' \
		$(TOP_LEVEL)/pkg/meta/proto/oci/config.proto
	$(PROTOC) --experimental_allow_proto3_optional \
		--proto_path=$(TOP_LEVEL)/pkg/meta/proto \
		--go_out=$(TOP_LEVEL)/pkg/meta/proto \
		--go_opt='Moci/versioned.proto=./gen' \
		--go_opt='Moci/descriptor.proto=./gen' \
		--go_opt='Moci/manifest.proto=./gen' \
		$(TOP_LEVEL)/pkg/meta/proto/oci/manifest.proto

.PHONY: binary-minimal
binary-minimal: EXTENSIONS=
binary-minimal: build-metadata
	env CGO_ENABLED=0 GOEXPERIMENT=jsonv2 GOOS=$(OS) GOARCH=$(ARCH) go build -o bin/zot-$(OS)-$(ARCH)-minimal$(BIN_EXT) $(BUILDMODE_FLAGS) -v -trimpath -ldflags "-X $(CONFIG_RELEASE_TAG)=${RELEASE_TAG} -X $(CONFIG_COMMIT)=${COMMIT} -X $(CONFIG_BINARY_TYPE)=minimal -X $(CONFIG_GO_VERSION)=${GO_VERSION} -s -w" ./cmd/zot

.PHONY: binary
binary: $(if $(findstring ui,$(BUILD_LABELS)), ui)
binary: build-metadata
	env CGO_ENABLED=0 GOEXPERIMENT=jsonv2 GOOS=$(OS) GOARCH=$(ARCH) go build -o bin/zot-$(OS)-$(ARCH)$(BIN_EXT) $(BUILDMODE_FLAGS) $(GO_CMD_TAGS) -v -trimpath -ldflags "-X $(CONFIG_RELEASE_TAG)=${RELEASE_TAG} -X $(CONFIG_COMMIT)=${COMMIT} -X $(CONFIG_BINARY_TYPE)=$(extended-name) -X $(CONFIG_GO_VERSION)=${GO_VERSION} -s -w" ./cmd/zot

.PHONY: binary-debug
binary-debug: $(if $(findstring ui,$(BUILD_LABELS)), ui)
binary-debug: swaggercheck build-metadata
	env CGO_ENABLED=0 GOEXPERIMENT=jsonv2 GOOS=$(OS) GOARCH=$(ARCH) go build -o bin/zot-$(OS)-$(ARCH)-debug$(BIN_EXT) $(BUILDMODE_FLAGS) -tags $(BUILD_LABELS),debug -v -gcflags all='-N -l' -ldflags "-X $(CONFIG_RELEASE_TAG)=${RELEASE_TAG} -X $(CONFIG_COMMIT)=${COMMIT} -X $(CONFIG_BINARY_TYPE)=$(extended-name) -X $(CONFIG_GO_VERSION)=${GO_VERSION}" ./cmd/zot

.PHONY: cli
cli: build-metadata
	env CGO_ENABLED=0 GOEXPERIMENT=jsonv2 GOOS=$(OS) GOARCH=$(ARCH) go build -o bin/zli-$(OS)-$(ARCH)$(BIN_EXT) $(BUILDMODE_FLAGS) -tags $(BUILD_LABELS),search -v -trimpath -ldflags "-X $(CONFIG_COMMIT)=${COMMIT} -X $(CONFIG_BINARY_TYPE)=$(extended-name) -X $(CONFIG_GO_VERSION)=${GO_VERSION} -s -w" ./cmd/zli

.PHONY: bench
bench: build-metadata
	env CGO_ENABLED=0 GOEXPERIMENT=jsonv2 GOOS=$(OS) GOARCH=$(ARCH) go build -o bin/zb-$(OS)-$(ARCH)$(BIN_EXT) $(BUILDMODE_FLAGS) $(GO_CMD_TAGS) -v -trimpath -ldflags "-X $(CONFIG_COMMIT)=${COMMIT} -X $(CONFIG_BINARY_TYPE)=$(extended-name) -X $(CONFIG_GO_VERSION)=${GO_VERSION} -s -w" ./cmd/zb

.PHONY: exporter-minimal
exporter-minimal: EXTENSIONS=
exporter-minimal: build-metadata
	env CGO_ENABLED=0 GOEXPERIMENT=jsonv2 GOOS=$(OS) GOARCH=$(ARCH) go build -o bin/zxp-$(OS)-$(ARCH)$(BIN_EXT) $(BUILDMODE_FLAGS) -v -trimpath ./cmd/zxp

.PHONY: test-prereq
test-prereq: check-skopeo $(TESTDATA) $(ORAS)

.PHONY: test-extended
test-extended: $(if $(findstring ui,$(BUILD_LABELS)), ui)
test-extended: testdata-images
	env GOEXPERIMENT=jsonv2 go test -failfast $(GO_CMD_TAGS) -trimpath -race -timeout 20m -cover -coverpkg ./... -coverprofile=coverage-extended.txt -covermode=atomic ./...
	rm -rf /tmp/getter*; rm -rf /tmp/trivy*

.PHONY: test-minimal
test-minimal: testdata-images
	env GOEXPERIMENT=jsonv2 go test -failfast -trimpath -race -cover -coverpkg ./... -coverprofile=coverage-minimal.txt -covermode=atomic ./...
	rm -rf /tmp/getter*; rm -rf /tmp/trivy*

.PHONY: test-devmode
test-devmode: $(if $(findstring ui,$(BUILD_LABELS)), ui)
test-devmode:
	env GOEXPERIMENT=jsonv2 go test -failfast -tags dev,$(BUILD_LABELS) -trimpath -race -timeout 15m -cover -coverpkg ./... -coverprofile=coverage-dev-extended.txt -covermode=atomic ./pkg/test/... ./pkg/api/... ./pkg/storage/... ./pkg/extensions/sync/... -run ^TestInject
	rm -rf /tmp/getter*; rm -rf /tmp/trivy*
	env GOEXPERIMENT=jsonv2 go test -failfast -tags dev -trimpath -race -cover -coverpkg ./... -coverprofile=coverage-dev-minimal.txt -covermode=atomic ./pkg/test/... ./pkg/storage/... ./pkg/extensions/sync/... -run ^TestInject
	rm -rf /tmp/getter*; rm -rf /tmp/trivy*
	env GOEXPERIMENT=jsonv2 go test -failfast -tags stress,$(BUILD_LABELS) -trimpath -race -timeout 15m ./pkg/cli/server/stress_test.go

.PHONY: test
test: $(if $(findstring ui,$(BUILD_LABELS)), ui)
test: test-extended test-minimal test-devmode

.PHONY: privileged-test
privileged-test: $(if $(findstring ui,$(BUILD_LABELS)), ui)
privileged-test:
	env GOEXPERIMENT=jsonv2 go test -failfast -tags needprivileges,$(BUILD_LABELS) -trimpath -race -timeout 15m -cover -coverpkg ./... -coverprofile=coverage-needprivileges-local.txt -covermode=atomic ./pkg/storage/local/... ./pkg/cli/client/... -run ^TestElevatedPrivileges
	env GOEXPERIMENT=jsonv2 go test -failfast -tags needprivileges,$(BUILD_LABELS) -trimpath -race -timeout 15m -cover -coverpkg ./... -coverprofile=coverage-needprivileges-gcs.txt -covermode=atomic ./pkg/storage/gcs/...

.PHONY: testdata-certs
testdata-certs:
	mkdir -p ${TESTDATA}; \
	cd ${TESTDATA}; ../scripts/gen_certs.sh; \
	mkdir -p noidentity; cd ${TESTDATA}/noidentity; ../../scripts/gen_nameless_certs.sh; \
	chmod -R a=rwx ${TESTDATA}

.PHONY: testdata-images
testdata-images: check-skopeo
	mkdir -p ${TESTDATA}; \
	cd ${TOP_LEVEL}; \
	skopeo --insecure-policy copy -q docker://public.ecr.aws/t0x7q1g8/centos:7 oci:${TESTDATA}/zot-test:0.0.1; \
	skopeo --insecure-policy copy -q docker://public.ecr.aws/t0x7q1g8/centos:8 oci:${TESTDATA}/zot-cve-test:0.0.1; \
	skopeo --insecure-policy copy -q docker://ghcr.io/project-zot/test-images/java:0.0.1 oci:${TESTDATA}/zot-cve-java-test:0.0.1; \
	skopeo --insecure-policy copy -q docker://ghcr.io/project-zot/test-images/alpine:3.17.3 oci:${TESTDATA}/alpine:3.17.3; \
	skopeo --insecure-policy copy -q docker://ghcr.io/project-zot/test-images/spring-web:5.3.31 oci:${TESTDATA}/spring-web:5.3.31; \
	chmod -R a=rwx ${TESTDATA}

$(TESTDATA): testdata-certs testdata-images
	ls -R -l ${TESTDATA}

.PHONY: run-bench
run-bench: binary bench
	bin/zot-$(OS)-$(ARCH) serve examples/config-bench.json & echo $$! > zot.PID
	curl --connect-timeout 3 --max-time 5 --retry 60 --retry-delay 1 --retry-max-time 180 --retry-connrefused http://localhost:8080/v2/
	bin/zb-$(OS)-$(ARCH) -c 10 -n 100 -o $(BENCH_OUTPUT) http://localhost:8080
	@if [ -e zot.PID ]; then \
		kill -TERM $$(cat zot.PID) || true; \
	fi; \
	rm zot.PID

.PHONY: check-skopeo
check-skopeo:
	skopeo -v || (echo "You need skopeo to be installed in order to run tests"; exit 1)

.PHONY: check-awslocal
check-awslocal:
	awslocal --version || (echo "You need awslocal to be installed in order to run tests"; exit 1)

$(NOTATION):
	mkdir -p $(TOOLSDIR)/bin
	curl -Lo notation.tar.gz https://github.com/notaryproject/notation/releases/download/v$(NOTATION_VERSION)/notation_$(NOTATION_VERSION)_$(OS)_$(ARCH).tar.gz
	tar xvzf notation.tar.gz -C $(TOOLSDIR)/bin  notation
	rm notation.tar.gz

$(ORAS):
	mkdir -p $(TOOLSDIR)/bin
	curl -Lo oras.tar.gz https://github.com/oras-project/oras/releases/download/v$(ORAS_VERSION)/oras_$(ORAS_VERSION)_$(OS)_$(ARCH).tar.gz
	tar xvzf oras.tar.gz -C $(TOOLSDIR)/bin  oras
	rm oras.tar.gz

$(HELM):
	mkdir -p $(TOOLSDIR)/bin
	curl -Lo helm.tar.gz https://get.helm.sh/helm-$(HELM_VERSION)-$(OS)-$(ARCH).tar.gz
	tar xvzf helm.tar.gz --strip-components=1 -C $(TOOLSDIR)/bin $(OS)-$(ARCH)/helm
	rm helm.tar.gz

$(REGCLIENT):
	mkdir -p $(TOOLSDIR)/bin
	curl -Lo regctl https://github.com/regclient/regclient/releases/download/$(REGCLIENT_VERSION)/regctl-$(OS)-$(ARCH)
	mv regctl $(TOOLSDIR)/bin/regctl
	chmod +x $(TOOLSDIR)/bin/regctl

$(CRICTL):
	mkdir -p $(TOOLSDIR)/bin
	curl -Lo crictl.tar.gz https://github.com/kubernetes-sigs/cri-tools/releases/download/$(CRICTL_VERSION)/crictl-$(CRICTL_VERSION)-$(OS)-$(ARCH).tar.gz
	tar xvzf crictl.tar.gz && rm crictl.tar.gz
	mv crictl $(TOOLSDIR)/bin/crictl
	chmod +x $(TOOLSDIR)/bin/crictl

$(PROTOC):
	mkdir -p $(TOOLSDIR)/bin
	curl -Lo protoc.zip https://github.com/protocolbuffers/protobuf/releases/download/v$(PROTOC_VERSION)/protoc-$(PROTOC_VERSION)-$(PROTOC_OS)-$(PROTOC_ARCH).zip
	unzip -o -d $(TOOLSDIR) protoc.zip bin/protoc
	rm protoc.zip
	chmod +x $(PROTOC)
	go install google.golang.org/protobuf/cmd/protoc-gen-go@v$(GO_PROTOC_VERSION)

$(ACTION_VALIDATOR):
	mkdir -p $(TOOLSDIR)/bin
	curl -Lo action-validator https://github.com/mpalmer/action-validator/releases/download/$(ACTION_VALIDATOR_VERSION)/action-validator_$(OS)_$(ARCH)
	mv action-validator $(TOOLSDIR)/bin/action-validator
	chmod +x $(TOOLSDIR)/bin/action-validator

.PHONY: check-gh-actions
check-gh-actions: check-compatibility $(ACTION_VALIDATOR)
	for i in $$(ls  .github/workflows/*); do $(ACTION_VALIDATOR) $$i; done

.PHONY: covhtml
covhtml:
	go install github.com/wadey/gocovmerge@latest
	gocovmerge coverage*.txt > coverage.txt
	go tool cover -html=coverage.txt -o coverage.html

$(GOLINTER): $(TOOLSDIR)/.golangci-lint-$(GOLINTER_VERSION)

$(TOOLSDIR)/.golangci-lint-$(GOLINTER_VERSION):
	mkdir -p $(TOOLSDIR)/bin
	rm -f $(TOOLSDIR)/.golangci-lint-*
	curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $(TOOLSDIR)/bin $(GOLINTER_VERSION)
	$(GOLINTER) version
	touch $@

.PHONY: check-logs
check-logs:
	@./scripts/check_logs.sh

.PHONY: check
check: $(if $(findstring ui,$(BUILD_LABELS)), ui)
check: ./.golangci.yaml $(GOLINTER)
	mkdir -p pkg/extensions/build; touch pkg/extensions/build/.empty
	$(GOLINTER) run --output.text.colors --build-tags ./...
	$(GOLINTER) run --output.text.colors --build-tags $(BUILD_LABELS)  ./...
	$(GOLINTER) run --output.text.colors --build-tags debug  ./pkg/debug/swagger/ ./pkg/debug/gqlplayground
	$(GOLINTER) run --output.text.colors --build-tags dev ./pkg/test/inject/
	$(GOLINTER) run --output.text.colors --build-tags stress ./pkg/cli/server/
	$(GOLINTER) run --output.text.colors --build-tags needprivileges,$(BUILD_LABELS) ./pkg/cli/client/ ./pkg/storage/local/ ./pkg/storage/gcs/ ./pkg/api/config/
	rm pkg/extensions/build/.empty

.PHONY: swagger
swagger:
	swag -v || go install github.com/swaggo/swag/cmd/swag@$(SWAGGER_VERSION)
	swag init --parseDependency -o swagger -g pkg/api/routes.go -q

.PHONY: update-licenses
# note: for predictable output of below sort command we use locale LC_ALL=C
update-licenses: check-linux
	@echo "Detecting and updating licenses ... please be patient!"
	go install github.com/google/go-licenses@latest
	./scripts/update_licenses.sh
	$(eval UNCOMMITED_FILES = $(shell git status --porcelain | grep -c THIRD-PARTY-LICENSES.md))
	@if [ $(UNCOMMITED_FILES) != 0 ]; then \
		echo "THIRD-PARTY-LICENSES.md file needs to be updated";\
		git status;\
		exit 1;\
	fi

.PHONY: check-licenses
check-licenses:
# note: "printf" works for darwin instead of "echo -n"
	go install github.com/google/go-licenses@latest
	@for tag_set in "$(BUILD_LABELS)" ""; do \
		echo Evaluating tag set: $$tag_set; \
		for mod in $$(go list -m -f '{{if not (or .Indirect .Main)}}{{.Path}}{{end}}' all); do \
			while [ x$$mod != x ]; do \
				printf "Checking $$mod ... "; \
				if [ -n "$$tag_set" ]; then \
					result=$$(GOFLAGS="-tags=$${tag_set}" go-licenses check $$mod 2>&1); \
				else \
					result=$$(go-licenses check $$mod 2>&1); \
				fi; \
				if [ $$? -eq 0 ]; then \
					echo OK; \
					break; \
				fi; \
				echo "$${result}" | grep -q "Forbidden"; \
				if [ $$? -eq 0 ]; then \
					echo FAIL; \
					exit 1; \
				fi; \
				echo "$${result}" | egrep -q "missing go.sum entry|no required module provides package|build constraints exclude all|updates to go.mod needed|non-Go code"; \
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
	rm -rf test/data/zot-test
	rm -rf test/data/zot-cve-test
	rm -rf test/data/zot-cve-java-test
	rm -rf pkg/extensions/build

.PHONY: run
run: binary
	./bin/zot-$(OS)-$(ARCH) serve examples/config-test.json

.PHONY: verify-config
verify-config: _verify-config verify-config-warnings verify-config-commited

.PHONY: _verify-config
_verify-config: binary
	rm -f output.txt
	$(foreach file, $(filter-out $(wildcard examples/config-*-credentials.json), $(wildcard examples/config-*)), ./bin/zot-$(OS)-$(ARCH) verify $(file) 2>&1 | tee -a output.txt || exit 1;)

.PHONY: verify-config-warnings
verify-config-warnings: _verify-config
	$(eval WARNINGS = $(shell cat output.txt | grep -c '"warn"'))
	$(eval ERRORS = $(shell cat output.txt | grep -c '"error"'))
	@if [ $(WARNINGS) != 0 ] || [ $(ERRORS) != 0 ]; then \
		echo "verify-config-warnings: warnings or errors found while verifying configs"; \
		rm output.txt; \
		exit 1; \
	fi
	rm -f output.txt

.PHONY: verify-config-commited
verify-config-commited: _verify-config
	$(eval UNCOMMITED_FILES = $(shell git status --porcelain | grep -c examples/config-))
	@if [ $(UNCOMMITED_FILES) != 0 ]; then \
		echo "Uncommited config files, make sure all config files are commited. Verify might have changed a config file.";\
		exit 1;\
	fi; \

.PHONY: gqlgen
gqlgen:
	cd pkg/extensions/search;\
	go run github.com/99designs/gqlgen version;\
	go run github.com/99designs/gqlgen generate

.PHONY: verify-gql-committed
verify-gql-committed:
	$(eval UNCOMMITED_FILES = $(shell git status --porcelain | grep -c extensions/search))
	@if [ $(UNCOMMITED_FILES) != 0 ]; then \
		echo "Updated gql files uncommitted, make sure all gql files are committed:";\
		git status;\
		exit 1;\
	fi; \

.PHONY: binary-container
binary-container:
	${CONTAINER_RUNTIME} build ${BUILD_ARGS} \
		--build-arg BASE_IMAGE=$(BASE_IMAGE) \
		-f build/Dockerfile -t zot-build:latest .

.PHONY: run-container
run-container:
	${CONTAINER_RUNTIME} run --rm --security-opt label=disable -v $$(pwd):/go/src/github.com/project-zot/zot \
		zot-build:latest

.PHONY: binary-minimal-container
binary-minimal-container:
	${CONTAINER_RUNTIME} build ${BUILD_ARGS} \
		--build-arg BASE_IMAGE=$(BASE_IMAGE) \
		-f build/Dockerfile-minimal -t zot-minimal:latest .

.PHONY: run-minimal-container
run-minimal-container:
	${CONTAINER_RUNTIME} run --rm --security-opt label=disable -v $$(pwd):/go/src/github.com/project-zot/zot \
		zot-minimal:latest

.PHONY: binary-exporter-container
binary-exporter-container:
	${CONTAINER_RUNTIME} build ${BUILD_ARGS} \
		--build-arg BASE_IMAGE=$(BASE_IMAGE) \
		-f build/Dockerfile-zxp -t zxp:latest .

.PHONY: run-exporter-container
run-exporter-container:
	${CONTAINER_RUNTIME} run --rm --security-opt label=disable zxp:latest

.PHONY: oci-image
oci-image: $(STACKER)
	${STACKER} --debug build \
		-f build/stacker.yaml \
		--substitute COMMIT=$(COMMIT) \
		--substitute ARCH=$(ARCH) \
		--substitute OS=$(OS) \
		--substitute RELEASE_TAG=$(RELEASE_TAG) \
		--substitute REPO_NAME=zot-$(OS)-$(ARCH) \
		--substitute BASE_IMAGE=$(BASE_IMAGE)

.PHONY: docker-image
docker-image:
	${CONTAINER_RUNTIME} buildx build --platform $(OS)/$(ARCH) \
		--build-arg BASE_IMAGE=$(BASE_IMAGE) \
		-f build/Dockerfile .

$(BATS):
	rm -rf bats-core; \
	git clone https://github.com/bats-core/bats-core.git; \
	cd bats-core; ./install.sh $(TOOLSDIR); cd ..; \
	rm -rf bats-core

.PHONY: check-blackbox-prerequisites
check-blackbox-prerequisites: check-linux check-skopeo $(BATS) $(REGCLIENT) $(ORAS) $(HELM) $(CRICTL) $(NOTATION) $(COSIGN) $(STACKER) $(KIND)
	which skopeo && skopeo --version; \
	which stacker && stacker --version; \
	which regctl && regctl version; \
	which oras && oras version; \
	which helm && helm version; \
	which crictl && crictl version; \
	which notation && notation version; \
	which cosign && cosign version; \
	which kind && kind version;

.PHONY: run-blackbox-tests
run-blackbox-tests: $(BATS_TEST_FILE_PATH) check-blackbox-prerequisites binary binary-minimal cli bench
	echo running bats test "$(BATS_TEST_FILE_PATH)"; \
	$(BLACKBOX_DOCKER_ENV) $(BATS) $(BATS_FLAGS) $(BATS_TEST_FILE_PATH)

.PHONY: run-cloud-scale-out-tests
run-cloud-scale-out-tests: check-blackbox-prerequisites check-awslocal binary bench test-prereq
	echo running scale out bats test; \
	$(BATS) $(BATS_FLAGS) test/scale-out/cloud_scale_out_no_auth.bats; \
	$(BATS) $(BATS_FLAGS) test/scale-out/cloud_scale_out_basic_auth_tls.bats

.PHONY: run-cloud-scale-out-redis-tests
run-cloud-scale-out-redis-tests: check-blackbox-prerequisites check-awslocal binary bench test-prereq
	echo running redis scale out bats test; \
	$(BATS) $(BATS_FLAGS) test/scale-out/cloud_scale_out_redis.bats

.PHONY: run-cloud-scale-out-high-scale-tests
run-cloud-scale-out-high-scale-tests: check-blackbox-prerequisites check-awslocal binary bench test-prereq
	echo running cloud scale out bats high scale test; \
	$(BATS) $(BATS_FLAGS) test/scale-out/cloud_scale_out_basic_auth_tls_scale.bats

.PHONY: run-cloud-scale-out-redis-high-scale-tests
run-cloud-scale-out-redis-high-scale-tests: check-blackbox-prerequisites check-awslocal binary bench test-prereq
	echo running redis scale out high scale bats test; \
	$(BATS) $(BATS_FLAGS) test/scale-out/cloud_scale_out_redis_scale.bats

.PHONY: run-blackbox-ci
run-blackbox-ci: check-blackbox-prerequisites binary binary-minimal cli
	echo running CI bats tests concurrently; \
	$(BLACKBOX_DOCKER_ENV) BATS_FLAGS="$(BATS_FLAGS)" test/blackbox/ci.sh

.PHONY: run-blackbox-cloud-ci
run-blackbox-cloud-ci: check-blackbox-prerequisites check-awslocal binary $(BATS)
	echo running cloud CI bats tests; \
	$(BATS) $(BATS_FLAGS) test/blackbox/cloud_only.bats
	$(BATS) $(BATS_FLAGS) test/blackbox/sync_cloud.bats
	$(BATS) $(BATS_FLAGS) test/blackbox/redis_s3.bats

.PHONY: run-blackbox-dedupe-nightly
run-blackbox-dedupe-nightly: check-blackbox-prerequisites check-awslocal binary binary-minimal
	echo running nightly dedupe tests; \
	$(BATS) $(BATS_FLAGS) test/blackbox/restore_s3_blobs.bats && \
	$(BATS) $(BATS_FLAGS) test/blackbox/pushpull_running_dedupe.bats

.PHONY: run-blackbox-sync-nightly
run-blackbox-sync-nightly: check-blackbox-prerequisites binary binary-minimal bench
	echo running nightly sync tests; \
	$(BATS) $(BATS_FLAGS) test/blackbox/sync_harness.bats

.PHONY: fuzz-all
fuzz-all: fuzztime=${1}
fuzz-all:
	rm -rf test-data; \
	rm -rf pkg/storage/testdata; \
	git clone https://github.com/project-zot/test-data.git; \
	mv test-data/storage pkg/storage/testdata; \
	rm -rf test-data; \
	bash test/scripts/fuzzAll.sh ${fuzztime}; \
	rm -rf pkg/storage/testdata; \

$(STACKER): check-linux
	mkdir -p $(TOOLSDIR)/bin; \
	curl -fsSL https://github.com/project-stacker/stacker/releases/download/$(STACKER_VERSION)/stacker -o $@; \
	chmod +x $@

$(COSIGN):
	mkdir -p $(TOOLSDIR)/bin
	curl -fsSL https://github.com/sigstore/cosign/releases/download/v$(COSIGN_VERSION)/cosign-$(OS)-$(ARCH) -o $@; \
	chmod +x $@

$(KIND): check-linux
	mkdir -p $(TOOLSDIR)/bin; \
	curl -fsSL curl -Lo ./kind https://kind.sigs.k8s.io/dl/$(KIND_VERSION)/kind-$(OS)-$(ARCH) -o $@; \
	chmod +x $@

# set ZUI_VERSION to empty string in order to clone zui locally and build default branch
.PHONY: ui
ui:
	echo $(BUILD_LABELS);\
	if [ -n $(ZUI_BUILD_PATH) ]; then\
		rm -rf ./pkg/extensions/build;\
		cp -R $(ZUI_BUILD_PATH) ./pkg/extensions/;\
		exit 0;\
	fi;\
	if [ -z $(ZUI_VERSION) ]; then\
		pwd=$$(pwd);\
		tdir=$$(mktemp -d);\
		cd $$tdir;\
		git clone https://github.com/$(ZUI_REPO_OWNER)/$(ZUI_REPO_NAME).git zui;\
		cd zui;\
		npm install;\
		npm run build;\
		cd $$pwd;\
		rm -rf ./pkg/extensions/build;\
		cp -R $$tdir/zui/build ./pkg/extensions/;\
	else\
		curl --fail --head https://github.com/$(ZUI_REPO_OWNER)/$(ZUI_REPO_NAME)/releases/download/$(ZUI_VERSION)/zui.tgz;\
		if [ $$? -ne 0 ]; then\
			pwd=$$(pwd);\
			tdir=$$(mktemp -d);\
			cd $$tdir;\
			git clone --depth=1 --branch $(ZUI_VERSION) https://github.com/$(ZUI_REPO_OWNER)/$(ZUI_REPO_NAME).git zui;\
			cd zui;\
			git checkout $(ZUI_VERSION);\
			npm install;\
			npm run build;\
			cd $$pwd;\
			rm -rf ./pkg/extensions/build;\
			cp -R $$tdir/zui/build ./pkg/extensions/;\
		else\
			curl -fsSL https://github.com/$(ZUI_REPO_OWNER)/$(ZUI_REPO_NAME)/releases/download/$(ZUI_VERSION)/zui.tgz -o zui.tgz;\
			tar xvzf zui.tgz -C ./pkg/extensions/;\
			rm zui.tgz;\
		fi;\
	fi;\

.PHONY: check-linux
check-linux:
ifneq ($(shell go env GOOS),linux)
	$(error makefile target can be run only on linux)
endif

.PHONY: check-compatibility
check-compatibility:
ifeq ($(OS),freebsd)
	$(error makefile target can't be run on freebsd)
endif
ifneq ($(OS),$(shell go env GOOS))
	$(error target can't be run on $(shell go env GOOS) as binary is compiled for $(OS))
endif
ifneq ($(ARCH),$(shell go env GOARCH))
	$(error target can't be run on $(shell go env GOARCH) (binary is for $(ARCH)))
endif
