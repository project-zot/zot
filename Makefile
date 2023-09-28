export GO111MODULE=on
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
GOLINTER_VERSION := v1.52.2
NOTATION := $(TOOLSDIR)/bin/notation
NOTATION_VERSION := 1.0.0-rc.4
COSIGN := $(TOOLSDIR)/bin/cosign
COSIGN_VERSION := 2.2.0
HELM := $(TOOLSDIR)/bin/helm
ORAS := $(TOOLSDIR)/bin/oras
ORAS_VERSION := 1.0.0-rc.1
REGCLIENT := $(TOOLSDIR)/bin/regctl
REGCLIENT_VERSION := v0.4.5
CRICTL := $(TOOLSDIR)/bin/crictl
CRICTL_VERSION := v1.26.1
ACTION_VALIDATOR := $(TOOLSDIR)/bin/action-validator
ACTION_VALIDATOR_VERSION := v0.5.3
ZUI_VERSION := commit-b787273
SWAGGER_VERSION := v1.8.12
STACKER := $(TOOLSDIR)/bin/stacker
BATS := $(TOOLSDIR)/bin/bats
TESTDATA := $(TOP_LEVEL)/test/data
OS ?= $(shell go env GOOS)
ARCH ?= $(shell go env GOARCH)

BENCH_OUTPUT ?= stdout
ALL_EXTENSIONS = debug,imagetrust,lint,metrics,mgmt,profile,scrub,search,sync,ui,userprefs
EXTENSIONS ?= sync,search,scrub,metrics,lint,ui,mgmt,profile,userprefs,imagetrust
UI_DEPENDENCIES := search,mgmt,userprefs
# freebsd/arm64 not supported for pie builds
BUILDMODE_FLAGS := -buildmode=pie
ifeq ($(OS),freebsd)
	ifeq ($(ARCH),arm64)
		BUILDMODE_FLAGS=
	endif
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

BATS_TEST_FILE_PATH ?= replace_me
ifeq ($(BATS_VERBOSITY),2)
	BATS_FLAGS = --trace --verbose-run --show-output-of-passing-tests --print-output-on-failure
else ifeq ($(BATS_VERBOSITY),1)
	BATS_FLAGS = --trace --verbose-run --print-output-on-failure
else
	BATS_FLAGS = --print-output-on-failure
endif

.PHONY: all
all: modcheck swaggercheck binary binary-minimal binary-debug cli bench exporter-minimal verify-config check check-gh-actions test covhtml

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
	# do not allow empty $(BUILD_TAGS) (at least add containers_image_openpgp that doesn't affect package import & files listing)
	$(eval BUILD_TAGS=$(if $(BUILD_LABELS),$(BUILD_LABELS),containers_image_openpgp))
	echo "Imports: \n"
	go list -tags $(BUILD_TAGS) -f '{{ join .Imports "\n" }}' ./... | sort -u
	echo "\n Files: \n"
	go list -tags $(BUILD_TAGS) -f '{{ join .GoFiles "\n" }}' ./... | sort -u

.PHONY: binary-minimal
binary-minimal: EXTENSIONS=
binary-minimal: modcheck build-metadata
	env CGO_ENABLED=0 GOOS=$(OS) GOARCH=$(ARCH) go build -o bin/zot-$(OS)-$(ARCH)-minimal $(BUILDMODE_FLAGS) -tags containers_image_openpgp -v -trimpath -ldflags "-X zotregistry.io/zot/pkg/api/config.ReleaseTag=${RELEASE_TAG} -X zotregistry.io/zot/pkg/api/config.Commit=${COMMIT} -X zotregistry.io/zot/pkg/api/config.BinaryType=minimal -X zotregistry.io/zot/pkg/api/config.GoVersion=${GO_VERSION} -s -w" ./cmd/zot

.PHONY: binary
binary: $(if $(findstring ui,$(BUILD_LABELS)), ui)
binary: modcheck build-metadata
	env CGO_ENABLED=0 GOOS=$(OS) GOARCH=$(ARCH) go build -o bin/zot-$(OS)-$(ARCH) $(BUILDMODE_FLAGS) -tags $(BUILD_LABELS),containers_image_openpgp -v -trimpath -ldflags "-X zotregistry.io/zot/pkg/api/config.ReleaseTag=${RELEASE_TAG} -X zotregistry.io/zot/pkg/api/config.Commit=${COMMIT} -X zotregistry.io/zot/pkg/api/config.BinaryType=$(extended-name) -X zotregistry.io/zot/pkg/api/config.GoVersion=${GO_VERSION} -s -w" ./cmd/zot

.PHONY: binary-debug
binary-debug: $(if $(findstring ui,$(BUILD_LABELS)), ui)
binary-debug: modcheck swaggercheck build-metadata
	env CGO_ENABLED=0 GOOS=$(OS) GOARCH=$(ARCH) go build -o bin/zot-$(OS)-$(ARCH)-debug $(BUILDMODE_FLAGS) -tags $(BUILD_LABELS),debug,containers_image_openpgp -v -gcflags all='-N -l' -ldflags "-X zotregistry.io/zot/pkg/api/config.ReleaseTag=${RELEASE_TAG} -X zotregistry.io/zot/pkg/api/config.Commit=${COMMIT} -X zotregistry.io/zot/pkg/api/config.BinaryType=$(extended-name) -X zotregistry.io/zot/pkg/api/config.GoVersion=${GO_VERSION}" ./cmd/zot

.PHONY: cli
cli: modcheck build-metadata
	env CGO_ENABLED=0 GOOS=$(OS) GOARCH=$(ARCH) go build -o bin/zli-$(OS)-$(ARCH) $(BUILDMODE_FLAGS) -tags $(BUILD_LABELS),search,containers_image_openpgp -v -trimpath -ldflags "-X zotregistry.io/zot/pkg/api/config.Commit=${COMMIT} -X zotregistry.io/zot/pkg/api/config.BinaryType=$(extended-name) -X zotregistry.io/zot/pkg/api/config.GoVersion=${GO_VERSION} -s -w" ./cmd/zli

.PHONY: bench
bench: modcheck build-metadata
	env CGO_ENABLED=0 GOOS=$(OS) GOARCH=$(ARCH) go build -o bin/zb-$(OS)-$(ARCH) $(BUILDMODE_FLAGS) -tags $(BUILD_LABELS),containers_image_openpgp -v -trimpath -ldflags "-X zotregistry.io/zot/pkg/api/config.Commit=${COMMIT} -X zotregistry.io/zot/pkg/api/config.BinaryType=$(extended-name) -X zotregistry.io/zot/pkg/api/config.GoVersion=${GO_VERSION} -s -w" ./cmd/zb

.PHONY: exporter-minimal
exporter-minimal: EXTENSIONS=
exporter-minimal: modcheck build-metadata
	env CGO_ENABLED=0 GOOS=$(OS) GOARCH=$(ARCH) go build -o bin/zxp-$(OS)-$(ARCH) $(BUILDMODE_FLAGS) -tags containers_image_openpgp -v -trimpath ./cmd/zxp

.PHONY: test-prereq
test-prereq: check-skopeo $(TESTDATA) $(ORAS)

.PHONY: test-extended
test-extended: $(if $(findstring ui,$(BUILD_LABELS)), ui)
test-extended: test-prereq
	go test -failfast -tags $(BUILD_LABELS),containers_image_openpgp -trimpath -race -timeout 15m -cover -coverpkg ./... -coverprofile=coverage-extended.txt -covermode=atomic ./...
	rm -rf /tmp/getter*; rm -rf /tmp/trivy*

.PHONY: test-minimal
test-minimal: test-prereq
	go test -failfast -tags containers_image_openpgp -trimpath -race -cover -coverpkg ./... -coverprofile=coverage-minimal.txt -covermode=atomic ./...
	rm -rf /tmp/getter*; rm -rf /tmp/trivy*

.PHONY: test-devmode
test-devmode: $(if $(findstring ui,$(BUILD_LABELS)), ui)
test-devmode: test-prereq
	go test -failfast -tags dev,$(BUILD_LABELS),containers_image_openpgp -trimpath -race -timeout 15m -cover -coverpkg ./... -coverprofile=coverage-dev-extended.txt -covermode=atomic ./pkg/test/... ./pkg/api/... ./pkg/storage/... ./pkg/extensions/sync/... -run ^TestInject
	rm -rf /tmp/getter*; rm -rf /tmp/trivy*
	go test -failfast -tags dev,containers_image_openpgp -trimpath -race -cover -coverpkg ./... -coverprofile=coverage-dev-minimal.txt -covermode=atomic ./pkg/test/... ./pkg/storage/... ./pkg/extensions/sync/... -run ^TestInject
	rm -rf /tmp/getter*; rm -rf /tmp/trivy*
	go test -failfast -tags stress,$(BUILD_LABELS),containers_image_openpgp -trimpath -race -timeout 15m ./pkg/cli/server/stress_test.go

.PHONY: test
test: $(if $(findstring ui,$(BUILD_LABELS)), ui)
test: test-extended test-minimal test-devmode

.PHONY: privileged-test
privileged-test: $(if $(findstring ui,$(BUILD_LABELS)), ui)
privileged-test: check-skopeo $(TESTDATA)
	go test -failfast -tags needprivileges,$(BUILD_LABELS),containers_image_openpgp -trimpath -race -timeout 15m -cover -coverpkg ./... -coverprofile=coverage-dev-needprivileges.txt -covermode=atomic ./pkg/storage/local/... ./pkg/cli/client/... -run ^TestElevatedPrivileges

$(TESTDATA): check-skopeo
	mkdir -p ${TESTDATA}; \
	cd ${TESTDATA}; ../scripts/gen_certs.sh; \
	mkdir -p noidentity; cd ${TESTDATA}/noidentity; ../../scripts/gen_nameless_certs.sh; \
	cd ${TOP_LEVEL}; \
	skopeo --insecure-policy copy -q docker://public.ecr.aws/t0x7q1g8/centos:7 oci:${TESTDATA}/zot-test:0.0.1; \
	skopeo --insecure-policy copy -q docker://public.ecr.aws/t0x7q1g8/centos:8 oci:${TESTDATA}/zot-cve-test:0.0.1; \
	skopeo --insecure-policy copy -q docker://ghcr.io/project-zot/test-images/java:0.0.1 oci:${TESTDATA}/zot-cve-java-test:0.0.1; \
	skopeo --insecure-policy copy -q docker://ghcr.io/project-zot/test-images/alpine:3.17.3 oci:${TESTDATA}/alpine:3.17.3; \
	chmod -R a=rwx ${TESTDATA}
	ls -R -l ${TESTDATA}

.PHONY: run-bench
run-bench: binary bench
	bin/zot-$(OS)-$(ARCH) serve examples/config-bench.json & echo $$! > zot.PID
	sleep 5
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
	curl -Lo notation.tar.gz https://github.com/notaryproject/notation/releases/download/v$(NOTATION_VERSION)/notation_$(NOTATION_VERSION)_linux_amd64.tar.gz
	tar xvzf notation.tar.gz -C $(TOOLSDIR)/bin  notation
	rm notation.tar.gz

$(ORAS):
	mkdir -p $(TOOLSDIR)/bin
	curl -Lo oras.tar.gz https://github.com/oras-project/oras/releases/download/v$(ORAS_VERSION)/oras_$(ORAS_VERSION)_linux_amd64.tar.gz
	tar xvzf oras.tar.gz -C $(TOOLSDIR)/bin  oras
	rm oras.tar.gz

$(HELM):
	mkdir -p $(TOOLSDIR)/bin
	curl -Lo helm.tar.gz https://get.helm.sh/helm-v3.9.1-linux-amd64.tar.gz
	tar xvzf helm.tar.gz -C $(TOOLSDIR)/bin linux-amd64/helm  --strip-components=1
	rm helm.tar.gz

$(REGCLIENT):
	mkdir -p $(TOOLSDIR)/bin
	curl -Lo regctl https://github.com/regclient/regclient/releases/download/$(REGCLIENT_VERSION)/regctl-linux-amd64
	mv regctl $(TOOLSDIR)/bin/regctl
	chmod +x $(TOOLSDIR)/bin/regctl

$(CRICTL):
	mkdir -p $(TOOLSDIR)/bin
	curl -Lo crictl.tar.gz https://github.com/kubernetes-sigs/cri-tools/releases/download/$(CRICTL_VERSION)/crictl-$(CRICTL_VERSION)-linux-amd64.tar.gz
	tar xvzf crictl.tar.gz && rm crictl.tar.gz
	mv crictl $(TOOLSDIR)/bin/crictl
	chmod +x $(TOOLSDIR)/bin/crictl


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

$(GOLINTER):
	mkdir -p $(TOOLSDIR)/bin
	curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $(TOOLSDIR)/bin $(GOLINTER_VERSION)
	$(GOLINTER) version

.PHONY: check
check: $(if $(findstring ui,$(BUILD_LABELS)), ui)
check: ./golangcilint.yaml $(GOLINTER)
	mkdir -p pkg/extensions/build; touch pkg/extensions/build/.empty
	$(GOLINTER) --config ./golangcilint.yaml run --enable-all --out-format=colored-line-number --build-tags containers_image_openpgp ./...
	$(GOLINTER) --config ./golangcilint.yaml run --enable-all --out-format=colored-line-number --build-tags $(BUILD_LABELS),containers_image_openpgp  ./...
	$(GOLINTER) --config ./golangcilint.yaml run --enable-all --out-format=colored-line-number --build-tags debug  ./pkg/debug/swagger/ ./pkg/debug/gqlplayground
	$(GOLINTER) --config ./golangcilint.yaml run --enable-all --out-format=colored-line-number --build-tags dev ./pkg/test/inject/
	$(GOLINTER) --config ./golangcilint.yaml run --enable-all --out-format=colored-line-number --build-tags stress ./pkg/cli/server/
	rm pkg/extensions/build/.empty

.PHONY: swagger
swagger:
	swag -v || go install github.com/swaggo/swag/cmd/swag@$(SWAGGER_VERSION)
	swag init --parseDependency -o swagger -g pkg/api/routes.go -q

.PHONY: update-licenses
update-licenses:
	@echo "Detecting and updating licenses ... please be patient!"
	go install github.com/google/go-licenses@latest
	$(shell echo "Module | License URL | License" > THIRD-PARTY-LICENSES.md; echo "---|---|---" >> THIRD-PARTY-LICENSES.md; for i in $$(go list -m all  | awk '{print $$1}'); do l=$$(go-licenses csv $$i 2>/dev/null); if [ $$? -ne 0 ]; then continue; fi; echo $$l | tr \, \| | tr ' ' '\n'; done | sort -u >> THIRD-PARTY-LICENSES.md)

.PHONY: check-licenses
check-licenses:
# note: "printf" works for darwin instead of "echo -n"
	go install github.com/google/go-licenses@latest
	@for tag in "$(BUILD_LABELS),containers_image_openpgp" "containers_image_openpgp"; do \
		echo Evaluating tag: $$tag;\
		for mod in $$(go list -m -f '{{if not (or .Indirect .Main)}}{{.Path}}{{end}}' all); do \
			while [ x$$mod != x ]; do \
				printf "Checking $$mod ... "; \
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
run: binary test
	./bin/zot-$(OS)-$(ARCH) serve examples/config-test.json

.PHONY: verify-config
verify-config: _verify-config verify-config-warnings verify-config-commited

.PHONY: _verify-config
_verify-config: binary
	rm -f output.txt
	$(foreach file, $(wildcard examples/config-*), ./bin/zot-$(OS)-$(ARCH) verify $(file) 2>&1 | tee -a output.txt || exit 1;)

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
	${CONTAINER_RUNTIME} build ${BUILD_ARGS} -f build/Dockerfile -t zot-build:latest .

.PHONY: run-container
run-container:
	${CONTAINER_RUNTIME} run --rm --security-opt label=disable -v $$(pwd):/go/src/github.com/project-zot/zot \
		zot-build:latest

.PHONY: binary-stacker
binary-stacker: $(STACKER)
	${STACKER} --debug build \
		-f build/stacker.yaml \
		--substitute COMMIT=$(COMMIT) \
		--substitute ARCH=$(ARCH) \
		--substitute OS=$(OS) \
		--substitute RELEASE_TAG=$(RELEASE_TAG) \
		--substitute REPO_NAME=zot-$(OS)-$(ARCH)

.PHONY: image
image:
	${CONTAINER_RUNTIME} build ${BUILD_ARGS} -f build/Dockerfile -t zot:latest .

$(BATS):
	rm -rf bats-core; \
	git clone https://github.com/bats-core/bats-core.git; \
	cd bats-core; ./install.sh $(TOOLSDIR); cd ..; \
	rm -rf bats-core

.PHONY: check-blackbox-prerequisites
check-blackbox-prerequisites: check-linux check-skopeo $(BATS) $(REGCLIENT) $(ORAS) $(HELM) $(CRICTL) $(NOTATION) $(COSIGN) $(STACKER)
	which skopeo && skopeo --version; \
	which stacker && stacker --version; \
	which regctl && regctl version; \
	which oras && oras version; \
	which helm && helm version; \
	which crictl && crictl version; \
	which notation && notation version; \
	which cosign && cosign version;

.PHONY: run-blackbox-tests
run-blackbox-tests: $(BATS_TEST_FILE_PATH) check-blackbox-prerequisites binary binary-minimal cli bench
	echo running bats test "$(BATS_TEST_FILE_PATH)"; \
	$(BATS) $(BATS_FLAGS) $(BATS_TEST_FILE_PATH)

.PHONY: run-blackbox-ci
run-blackbox-ci: check-blackbox-prerequisites binary binary-minimal cli
	# ideally we would run a single bats command but too much disk space would be used at once
	echo running CI bats tests; \
	$(BATS) $(BATS_FLAGS) test/blackbox/pushpull.bats && \
	$(BATS) $(BATS_FLAGS) test/blackbox/pushpull_authn.bats && \
	$(BATS) $(BATS_FLAGS) test/blackbox/delete_images.bats && \
	$(BATS) $(BATS_FLAGS) test/blackbox/referrers.bats && \
	$(BATS) $(BATS_FLAGS) test/blackbox/metadata.bats && \
	$(BATS) $(BATS_FLAGS) test/blackbox/anonymous_policy.bats && \
	$(BATS) $(BATS_FLAGS) test/blackbox/annotations.bats && \
	$(BATS) $(BATS_FLAGS) test/blackbox/detect_manifest_collision.bats && \
	$(BATS) $(BATS_FLAGS) test/blackbox/cve.bats && \
	$(BATS) $(BATS_FLAGS) test/blackbox/sync.bats && \
	$(BATS) $(BATS_FLAGS) test/blackbox/sync_docker.bats && \
	$(BATS) $(BATS_FLAGS) test/blackbox/sync_replica_cluster.bats && \
	$(BATS) $(BATS_FLAGS) test/blackbox/scrub.bats && \
	$(BATS) $(BATS_FLAGS) test/blackbox/garbage_collect.bats && \
	$(BATS) $(BATS_FLAGS) test/blackbox/metrics.bats

.PHONY: run-blackbox-cloud-ci
run-blackbox-cloud-ci: check-blackbox-prerequisites check-awslocal binary $(BATS)
	echo running cloud CI bats tests; \
	$(BATS) $(BATS_FLAGS) test/blackbox/cloud_only.bats

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

$(STACKER):
	mkdir -p $(TOOLSDIR)/bin; \
	curl -fsSL https://github.com/project-stacker/stacker/releases/latest/download/stacker -o $@; \
	chmod +x $@

$(COSIGN):
	mkdir -p $(TOOLSDIR)/bin
	curl -fsSL https://github.com/sigstore/cosign/releases/download/v$(COSIGN_VERSION)/cosign-linux-amd64 -o $@; \
	chmod +x $@

# set ZUI_VERSION to empty string in order to clone zui locally and build default branch
.PHONY: ui
ui:
	echo $(BUILD_LABELS);\
	if [ -z $(ZUI_VERSION) ]; then\
		pwd=$$(pwd);\
		tdir=$$(mktemp -d);\
		cd $$tdir;\
		git clone https://github.com/project-zot/zui.git;\
		cd zui;\
		npm install;\
		npm run build;\
		cd $$pwd;\
		rm -rf ./pkg/extensions/build;\
		cp -R $$tdir/zui/build ./pkg/extensions/;\
	else\
		curl --fail --head https://github.com/project-zot/zui/releases/download/$(ZUI_VERSION)/zui.tgz;\
		if [ $$? -ne 0 ]; then\
			pwd=$$(pwd);\
			tdir=$$(mktemp -d);\
			cd $$tdir;\
  			git clone --depth=1 --branch $(ZUI_VERSION)  https://github.com/project-zot/zui.git;\
			cd zui;\
			git checkout $(ZUI_VERSION);\
			npm install;\
			npm run build;\
			cd $$pwd;\
			rm -rf ./pkg/extensions/build;\
			cp -R $$tdir/zui/build ./pkg/extensions/;\
		else\
 			curl -fsSL https://github.com/project-zot/zui/releases/download/$(ZUI_VERSION)/zui.tgz -o zui.tgz;\
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
