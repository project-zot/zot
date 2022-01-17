CONTAINER_RUNTIME := docker

.PHONY: binary-container
binary-container:
	${CONTAINER_RUNTIME} build -f Dockerfile -t zot-build:latest ../../.

.PHONY: run-container
run-container:
	${CONTAINER_RUNTIME} run --rm --security-opt label=disable -v $$(pwd)/../..:/go/src/github.com/project-zot/zot \
		zot-build:latest

.PHONY: binary-minimal-container
binary-minimal-container:
	${CONTAINER_RUNTIME} build -f Dockerfile-minimal -t zot-minimal:latest ../../.

.PHONY: run-minimal-container
run-minimal-container:
	${CONTAINER_RUNTIME} run --rm --security-opt label=disable -v $$(pwd)/../..:/go/src/github.com/project-zot/zot \
		zot-minimal:latest

.PHONY: binary-exporter-container
binary-exporter-container:
	${CONTAINER_RUNTIME} build -f Dockerfile-zxp -t zxp:latest ../../.

.PHONY: run-exporter-container
run-exporter-container:
	${CONTAINER_RUNTIME} run --rm --security-opt label=disable zxp:latest
