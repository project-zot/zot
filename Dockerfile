# ---
# Stage 1: Install certs, build binary, create default config file
# ---
FROM ghcr.io/project-zot/golang:1.17 AS builder
ARG COMMIT
RUN mkdir -p /go/src/github.com/project-zot/zot
WORKDIR /go/src/github.com/project-zot/zot
COPY . .
RUN make COMMIT=$COMMIT clean binary
RUN echo '{\n\
    "storage": {\n\
        "rootDirectory": "/var/lib/registry"\n\
    },\n\
    "http": {\n\
        "address": "0.0.0.0",\n\
        "port": "5000"\n\
    },\n\
    "log": {\n\
        "level": "debug"\n\
    }\n\
}\n' > config.json && cat config.json

# ---
# Stage 2: Final image with nothing but certs, binary, and default config file
# ---
FROM scratch AS final
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=builder /go/src/github.com/project-zot/zot/bin/zot /usr/bin/zot
COPY --from=builder /go/src/github.com/project-zot/zot/config.json /etc/zot/config.json
ENTRYPOINT ["/usr/bin/zot"]
EXPOSE 5000
VOLUME ["/var/lib/registry"]
CMD ["serve", "/etc/zot/config.json"]
