# ---
# Global ARGs for FROM statements
# This needs to be declared in the global scope otherwise the build will fail in Docker & Podman.
# Docker:
#   WARNING: UndefinedArgInFrom - https://docs.docker.com/go/dockerfile/rule/undefined-arg-in-from/
#   FROM argument 'BASE_IMAGE' is not declared
# Podman: Error: determining starting point for build: no FROM statement found
# ---
ARG BASE_IMAGE=gcr.io/distroless/static-debian13:nonroot

# ---
# Stage 1: Build binary, create default config file and data directory
# ---
FROM --platform=$BUILDPLATFORM ghcr.io/project-zot/golang:1.27 AS builder

ARG TARGETOS
ARG TARGETARCH
ARG COMMIT

RUN mkdir -p /go/src/github.com/project-zot/zot
WORKDIR /go/src/github.com/project-zot/zot
COPY . .
RUN make COMMIT=$COMMIT OS=$TARGETOS ARCH=$TARGETARCH clean binary
RUN echo '{\n\
    "storage": {\n\
        "rootDirectory": "/var/lib/registry"\n\
    },\n\
    "http": {\n\
        "address": "0.0.0.0",\n\
        "port": "5000",\n\
        "compat": ["docker2s2"]\n\
    },\n\
    "log": {\n\
        "level": "debug"\n\
    }\n\
}\n' > config.json && cat config.json
RUN mkdir -p /var/lib/registry && chown 65532:65532 /var/lib/registry

# ---
# Stage 2: Final image with the binary, default config, and a data directory
# ---
FROM $BASE_IMAGE AS final
ARG TARGETOS
ARG TARGETARCH
COPY --from=builder --chown=65532:65532 /var/lib/registry /var/lib/registry
COPY --from=builder /go/src/github.com/project-zot/zot/bin/zot-$TARGETOS-$TARGETARCH /usr/bin/zot
COPY --from=builder /go/src/github.com/project-zot/zot/config.json /etc/zot/config.json
USER 65532:65532
ENTRYPOINT ["/usr/bin/zot"]
EXPOSE 5000
CMD ["serve", "/etc/zot/config.json"]
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["/usr/bin/zot", "healthcheck", "--insecure-skip-verify", "/etc/zot/config.json"]
