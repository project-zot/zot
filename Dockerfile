# ---
# Stage 1: Install certs, build binary, create default config file
# ---
FROM ghcr.io/project-zot/golang:1.17 AS builder
ARG COMMIT
ARG OS
ARG ARCH
RUN mkdir -p /go/src/github.com/project-zot/zot
WORKDIR /go/src/github.com/project-zot/zot
COPY . .
RUN make COMMIT=$COMMIT OS=$OS ARCH=$ARCH clean binary
RUN echo '{\n\
    "storage": {\n\
        "rootDirectory": "/var/lib/registry"\n\
    },\n\
    "http": {\n\
        "address": "0.0.0.0",\n\
        "port": "5000"\n\
    },\n\
    "extensions": {\n\
        "search" : {\n\
          "enable": true\n\
        },\n\
        "ui": {\n\
            "path": "/var/lib/zui"\n\
        }\n\
    },\n\
    "log": {\n\
        "level": "debug"\n\
    }\n\
}\n' > config.json && cat config.json

# ---
# Stage 2: Build UI
# ---
FROM node:16 AS ui-builder
ARG OS
ARG ARCH
RUN mkdir -p /src/project-zot
RUN git clone https://github.com/project-zot/zui.git /src/project-zot/
WORKDIR /src/project-zot/zui
RUN npm install
RUN npm run build

# ---
# Stage 3: Final image with nothing but certs, binary, and default config file
# ---
FROM gcr.io/distroless/base AS final
ARG OS
ARG ARCH
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=builder /go/src/github.com/project-zot/zot/bin/zot-$OS-$ARCH /usr/bin/zot
COPY --from=builder /go/src/github.com/project-zot/zot/config.json /etc/zot/config.json
COPY --from=ui-builder /src/project-zot/build/. /var/lib/zui
# COPY ui assets to /var/lib/zot-ui
ENTRYPOINT ["/usr/bin/zot"]
EXPOSE 5000
VOLUME ["/var/lib/registry"]
CMD ["serve", "/etc/zot/config.json"]
