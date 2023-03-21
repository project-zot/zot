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
GOLINTER_VERSION := v1.49.0
NOTATION := $(TOOLSDIR)/bin/notation
NOTATION_VERSION := 1.0.0-rc.2
COSIGN := $(TOOLSDIR)/bin/cosign
HELM := $(TOOLSDIR)/bin/helm
ORAS := $(TOOLSDIR)/bin/oras
ORAS_VERSION := 1.0.0-rc.1
REGCLIENT := $(TOOLSDIR)/bin/regctl
REGCLIENT_VERSION := v0.4.5
ACTION_VALIDATOR := $(TOOLSDIR)/bin/action-validator
ACTION_VALIDATOR_VERSION := v0.2.1
ZUI_VERSION := commit-ddf1d92
STACKER := $(TOOLSDIR)/bin/stacker
BATS := $(TOOLSDIR)/bin/bats
TESTDATA := $(TOP_LEVEL)/test/data
OS ?= linux
ARCH ?= amd64
BENCH_OUTPUT ?= stdout
EXTENSIONS ?= sync,search,scrub,metrics,lint,ui,mgmt
comma:= ,
hyphen:= -
extended-name:=

.PHONY: all
all: modcheck swagger binary binary-minimal binary-debug cli bench exporter-minimal verify-config test covhtml check check-gh-actions

.PHONY: modcheck
modcheck:
	go mod tidy

.PHONY: create-name
create-name:
ifdef EXTENSIONS
	$(eval extended-name=-$(subst $(comma),$(hyphen),$(EXTENSIONS)))
endif

.PHONY: build-metadata
build-metadata: $(if $(findstring ui,$(EXTENSIONS)), ui)
	echo "Imports: \n"
	go list -tags $(EXTENSIONS) -f '{{ join .Imports "\n" }}' ./... | sort -u
	echo "\n Files: \n"
	go list -tags $(EXTENSIONS) -f '{{ join .GoFiles "\n" }}' ./... | sort -u

.PHONY: binary-minimal
binary-minimal: EXTENSIONS=minimal # tag doesn't exist, but we need it to overwrite default value and indicate that we have no extension in build-metadata
binary-minimal: modcheck build-metadata
	env CGO_ENABLED=0 GOOS=$(OS) GOARCH=$(ARCH) go build -o bin/zot-$(OS)-$(ARCH)-minimal -buildmode=pie -tags containers_image_openpgp -v -trimpath -ldflags "-X zotregistry.io/zot/pkg/api/config.ReleaseTag=${RELEASE_TAG} -X zotregistry.io/zot/pkg/api/config.Commit=${COMMIT} -X zotregistry.io/zot/pkg/api/config.BinaryType=minimal -X zotregistry.io/zot/pkg/api/config.GoVersion=${GO_VERSION} -s -w" ./cmd/zot

.PHONY: binary
binary: $(if $(findstring ui,$(EXTENSIONS)), ui)
binary: modcheck create-name build-metadata
	env CGO_ENABLED=0 GOOS=$(OS) GOARCH=$(ARCH) go build -o bin/zot-$(OS)-$(ARCH) -buildmode=pie -tags $(EXTENSIONS),containers_image_openpgp -v -trimpath -ldflags "-X zotregistry.io/zot/pkg/api/config.ReleaseTag=${RELEASE_TAG} -X zotregistry.io/zot/pkg/api/config.Commit=${COMMIT} -X zotregistry.io/zot/pkg/api/config.BinaryType=$(extended-name) -X zotregistry.io/zot/pkg/api/config.GoVersion=${GO_VERSION} -s -w" ./cmd/zot

.PHONY: binary-debug
binary-debug: $(if $(findstring ui,$(EXTENSIONS)), ui)
binary-debug: modcheck swagger create-name build-metadata
	env CGO_ENABLED=0 GOOS=$(OS) GOARCH=$(ARCH) go build -o bin/zot-$(OS)-$(ARCH)-debug -buildmode=pie -tags $(EXTENSIONS),debug,containers_image_openpgp -v -gcflags all='-N -l' -ldflags "-X zotregistry.io/zot/pkg/api/config.ReleaseTag=${RELEASE_TAG} -X zotregistry.io/zot/pkg/api/config.Commit=${COMMIT} -X zotregistry.io/zot/pkg/api/config.BinaryType=$(extended-name) -X zotregistry.io/zot/pkg/api/config.GoVersion=${GO_VERSION}" ./cmd/zot

.PHONY: cli
cli: modcheck create-name build-metadata
	env CGO_ENABLED=0 GOOS=$(OS) GOARCH=$(ARCH) go build -o bin/zli-$(OS)-$(ARCH) -buildmode=pie -tags $(EXTENSIONS),search,containers_image_openpgp -v -trimpath -ldflags "-X zotregistry.io/zot/pkg/api/config.Commit=${COMMIT} -X zotregistry.io/zot/pkg/api/config.BinaryType=$(extended-name) -X zotregistry.io/zot/pkg/api/config.GoVersion=${GO_VERSION} -s -w" ./cmd/zli

.PHONY: bench
bench: modcheck create-name build-metadata
	env CGO_ENABLED=0 GOOS=$(OS) GOARCH=$(ARCH) go build -o bin/zb-$(OS)-$(ARCH) -buildmode=pie -tags $(EXTENSIONS),containers_image_openpgp -v -trimpath -ldflags "-X zotregistry.io/zot/pkg/api/config.Commit=${COMMIT} -X zotregistry.io/zot/pkg/api/config.BinaryType=$(extended-name) -X zotregistry.io/zot/pkg/api/config.GoVersion=${GO_VERSION} -s -w" ./cmd/zb

.PHONY: exporter-minimal
exporter-minimal: EXTENSIONS=minimal # tag doesn't exist, but we need it to overwrite default value and indicate that we have no extension in build-metadata
exporter-minimal: modcheck build-metadata
	env CGO_ENABLED=0 GOOS=$(OS) GOARCH=$(ARCH) go build -o bin/zxp-$(OS)-$(ARCH) -buildmode=pie -tags containers_image_openpgp -v -trimpath ./cmd/zxp

.PHONY: test
test: $(if $(findstring ui,$(EXTENSIONS)), ui)
test: check-skopeo $(TESTDATA) $(ORAS)
	go test -failfast -tags $(EXTENSIONS),containers_image_openpgp -v -trimpath -race -timeout 15m -cover -coverpkg ./... -coverprofile=coverage-extended.txt -covermode=atomic ./...
	go test -failfast -tags containers_image_openpgp -v -trimpath -race -cover -coverpkg ./... -coverprofile=coverage-minimal.txt -covermode=atomic ./...
	# development-mode unit tests possibly using failure injection
	go test -failfast -tags dev,$(EXTENSIONS),containers_image_openpgp -v -trimpath -race -timeout 15m -cover -coverpkg ./... -coverprofile=coverage-dev-extended.txt -covermode=atomic ./pkg/test/... ./pkg/api/... ./pkg/storage/... ./pkg/extensions/sync/... -run ^TestInject
	go test -failfast -tags dev,containers_image_openpgp -v -trimpath -race -cover -coverpkg ./... -coverprofile=coverage-dev-minimal.txt -covermode=atomic ./pkg/test/... ./pkg/storage/... ./pkg/extensions/sync/... -run ^TestInject
	go test -failfast -tags stress,$(EXTENSIONS),containers_image_openpgp -v -trimpath -race -timeout 15m ./pkg/cli/stress_test.go

.PHONY: privileged-test
privileged-test: $(if $(findstring ui,$(EXTENSIONS)), ui)
privileged-test: check-skopeo $(TESTDATA)
	go test -failfast -tags needprivileges,$(EXTENSIONS),containers_image_openpgp -v -trimpath -race -timeout 15m -cover -coverpkg ./... -coverprofile=coverage-dev-needprivileges.txt -covermode=atomic ./pkg/storage/... ./pkg/cli/... -run ^TestElevatedPrivileges

$(TESTDATA): check-skopeo
	$(shell mkdir -p ${TESTDATA}; cd ${TESTDATA}; mkdir -p noidentity; ../scripts/gen_certs.sh; cd ${TESTDATA}/noidentity; ../../scripts/gen_nameless_certs.sh; cd ${TOP_LEVEL}; skopeo --insecure-policy copy -q docker://public.ecr.aws/t0x7q1g8/centos:7 oci:${TESTDATA}/zot-test:0.0.1;skopeo --insecure-policy copy -q docker://public.ecr.aws/t0x7q1g8/centos:8 oci:${TESTDATA}/zot-cve-test:0.0.1)
	$(shell chmod -R a=rwx ${TESTDATA})

.PHONY: run-bench
run-bench: binary bench
	bin/zot-$(OS)-$(ARCH) serve examples/config-bench.json &
	sleep 5
	bin/zb-$(OS)-$(ARCH) -c 10 -n 100 -o $(BENCH_OUTPUT) http://localhost:8080
	killall -r zot-*

.PHONY: check-skopeo
check-skopeo:
	skopeo -v || (echo "You need skopeo to be installed in order to run tests"; exit 1)

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
	cp regctl $(TOOLSDIR)/bin/regctl
	chmod +x $(TOOLSDIR)/bin/regctl

$(ACTION_VALIDATOR):
	mkdir -p $(TOOLSDIR)/bin
	curl -Lo action-validator https://github.com/mpalmer/action-validator/releases/download/$(ACTION_VALIDATOR_VERSION)/action-validator_linux_amd64
	cp action-validator $(TOOLSDIR)/bin/action-validator
	chmod +x $(TOOLSDIR)/bin/action-validator

.PHONY: check-gh-actions
check-gh-actions: $(ACTION_VALIDATOR)
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
check: $(if $(findstring ui,$(EXTENSIONS)), ui)
check: ./golangcilint.yaml $(GOLINTER)
	mkdir -p pkg/extensions/build; touch pkg/extensions/build/.empty
	$(GOLINTER) --config ./golangcilint.yaml run --enable-all --out-format=colored-line-number --build-tags containers_image_openpgp ./...
	$(GOLINTER) --config ./golangcilint.yaml run --enable-all --out-format=colored-line-number --build-tags $(EXTENSIONS),containers_image_openpgp ./...
	$(GOLINTER) --config ./golangcilint.yaml run --enable-all --out-format=colored-line-number --build-tags $(EXTENSIONS),containers_image_openpgp,debug ./...
	$(GOLINTER) --config ./golangcilint.yaml run --enable-all --out-format=colored-line-number --build-tags dev,containers_image_openpgp ./...
	$(GOLINTER) --config ./golangcilint.yaml run --enable-all --out-format=colored-line-number --build-tags dev,$(EXTENSIONS),containers_image_openpgp ./...
	$(GOLINTER) --config ./golangcilint.yaml run --enable-all --out-format=colored-line-number --build-tags stress,$(EXTENSIONS),containers_image_openpgp ./...
	rm pkg/extensions/build/.empty

swagger/docs.go: 
	swag -v || go install github.com/swaggo/swag/cmd/swag@1.6.3
	swag init -o swagger -g pkg/api/routes.go

.PHONY: swagger
swagger: swagger/docs.go pkg/api/routes.go

.PHONY: update-licenses
update-licenses:
	@echo "Detecting and updating licenses ... please be patient!"
	go install github.com/google/go-licenses@latest
	$(shell echo "Module | License URL | License" > THIRD-PARTY-LICENSES.md; echo "---|---|---" >> THIRD-PARTY-LICENSES.md; for i in $$(go list -m all  | awk '{print $$1}'); do l=$$(go-licenses csv $$i 2>/dev/null); if [ $$? -ne 0 ]; then continue; fi; echo $$l | tr \, \| | tr ' ' '\n'; done | sort -u >> THIRD-PARTY-LICENSES.md)

.PHONY: check-licenses
check-licenses:
	go install github.com/google/go-licenses@latest
	@for tag in "$(EXTENSIONS),containers_image_openpgp" "$(EXTENSIONS),containers_image_openpgp"; do \
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
binary-stacker:
	${STACKER} --debug build \
		-f build/stacker.yaml \
		--substitute PWD=$$PWD \
		--substitute COMMIT=$$COMMIT \
		--substitute ARCH=$$ARCH \
		--substitute OS=$$OS

.PHONY: image
image:
	${CONTAINER_RUNTIME} build ${BUILD_ARGS} -f build/Dockerfile -t zot:latest .

$(BATS):
	rm -rf bats-core; \
	git clone https://github.com/bats-core/bats-core.git; \
	cd bats-core; ./install.sh $(TOOLSDIR); cd ..; \
	rm -rf bats-core

.PHONY: test-push-pull
test-push-pull: binary check-skopeo $(BATS) $(REGCLIENT) $(ORAS) $(HELM)
	$(BATS) --trace --print-output-on-failure test/blackbox/pushpull.bats

.PHONY: test-push-pull-verbose
test-push-pull-verbose: binary check-skopeo $(BATS)
	$(BATS) --trace --verbose-run --print-output-on-failure --show-output-of-passing-tests test/blackbox/pushpull.bats

.PHONY: test-bats-referrers
test-bats-referrers: EXTENSIONS=search
test-bats-referrers: binary check-skopeo $(BATS) $(ORAS)
	$(BATS) --trace --print-output-on-failure test/blackbox/referrers.bats

.PHONY: test-cloud-only
test-cloud-only: binary check-skopeo $(BATS)
	$(BATS) --trace --print-output-on-failure test/blackbox/cloud-only.bats

.PHONY: test-cloud-only-verbose
test-cloud-only-verbose: binary check-skopeo $(BATS)
	$(BATS) --trace --verbose-run --print-output-on-failure --show-output-of-passing-tests test/blackbox/cloud-only.bats

.PHONY: test-bats-sync
test-bats-sync: EXTENSIONS=sync
test-bats-sync: binary binary-minimal check-skopeo $(BATS) $(NOTATION) $(COSIGN)
	$(BATS) --trace --print-output-on-failure test/blackbox/sync.bats
	$(BATS) --trace --print-output-on-failure test/blackbox/sync_docker.bats
	
.PHONY: test-bats-sync-verbose
test-bats-sync-verbose: EXTENSIONS=sync
test-bats-sync-verbose: binary binary-minimal check-skopeo $(BATS) $(NOTATION) $(COSIGN)
	$(BATS) --trace -t -x -p --verbose-run --print-output-on-failure --show-output-of-passing-tests test/blackbox/sync.bats
	$(BATS) --trace -t -x -p --verbose-run --print-output-on-failure --show-output-of-passing-tests test/blackbox/sync_docker.bats

.PHONY: test-bats-cve
test-bats-cve: EXTENSIONS=search
test-bats-cve: binary cli check-skopeo $(BATS)
	$(BATS) --trace --print-output-on-failure test/blackbox/cve.bats

.PHONY: test-bats-cve-verbose
test-bats-cve-verbose: EXTENSIONS=search
test-bats-cve-verbose: binary cli check-skopeo $(BATS)
	$(BATS) --trace -t -x -p --verbose-run --print-output-on-failure --show-output-of-passing-tests test/blackbox/cve.bats

.PHONY: test-bats-scrub
test-bats-scrub: EXTENSIONS=scrub
test-bats-scrub: binary check-skopeo $(BATS)
	$(BATS) --trace --print-output-on-failure test/blackbox/scrub.bats

.PHONY: test-bats-scrub-verbose
test-bats-scrub-verbose: EXTENSIONS=scrub
test-bats-scrub-verbose: binary check-skopeo $(BATS)
	$(BATS) --trace -p --verbose-run --print-output-on-failure --show-output-of-passing-tests test/blackbox/scrub.bats

.PHONY: test-bats-metrics
test-bats-metrics: EXTENSIONS=metrics
test-bats-metrics: binary check-skopeo $(BATS)
	$(BATS) --trace --print-output-on-failure test/blackbox/metrics.bats

.PHONY: test-bats-metrics-verbose
test-bats-metrics-verbose: EXTENSIONS=metrics
test-bats-metrics-verbose: binary check-skopeo $(BATS)
	$(BATS) --trace -p --verbose-run --print-output-on-failure --show-output-of-passing-tests test/blackbox/metrics.bats

.PHONY: test-anonymous-push-pull
test-anonymous-push-pull: binary check-skopeo $(BATS)
	$(BATS) --trace --print-output-on-failure test/blackbox/anonymous_policy.bats

.PHONY: test-annotations
test-annotations: binary check-skopeo $(BATS) $(STACKER) $(NOTATION) $(COSIGN)
	$(BATS) --trace --print-output-on-failure test/blackbox/annotations.bats

.PHONY: test-detect-manifest-collision
test-detect-manifest-collision: binary check-skopeo $(BATS)
	$(BATS) --trace --print-output-on-failure test/blackbox/detect_manifest_collision.bats

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
	curl -fsSL https://github.com/sigstore/cosign/releases/download/v1.13.0/cosign-linux-amd64 -o $@; \
	chmod +x $@

# set ZUI_VERSION to empty string in order to clone zui locally and build default branch
.PHONY: ui
ui:
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
		curl -fsSL https://github.com/project-zot/zui/releases/download/$(ZUI_VERSION)/zui.tgz -o zui.tgz;\
		tar xvzf zui.tgz -C ./pkg/extensions/;\
		rm zui.tgz;\
	fi;\

