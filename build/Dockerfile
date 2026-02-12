# ---
# Global ARGs for FROM statements
# This needs to be declared in the global scope otherwise the build will fail in Docker & Podman.
# Docker:
#   WARNING: UndefinedArgInFrom - https://docs.docker.com/go/dockerfile/rule/undefined-arg-in-from/
#   FROM argument 'BASE_IMAGE' is not declared
# Podman: Error: determining starting point for build: no FROM statement found
# ---
ARG BASE_IMAGE=gcr.io/distroless/base-nossl-debian13:latest

# ---
# Stage 1: Install certs, build binary, create default config file
# ---
FROM --platform=$BUILDPLATFORM ghcr.io/project-zot/golang:1.25 AS builder

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

# ---
# Stage 2: Final image with nothing but certs, binary, and default config file
# ---
FROM $BASE_IMAGE AS final
ARG TARGETOS
ARG TARGETARCH
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=builder /go/src/github.com/project-zot/zot/bin/zot-$TARGETOS-$TARGETARCH /usr/bin/zot
COPY --from=builder /go/src/github.com/project-zot/zot/config.json /etc/zot/config.json
ENTRYPOINT ["/usr/bin/zot"]
EXPOSE 5000
CMD ["serve", "/etc/zot/config.json"]
