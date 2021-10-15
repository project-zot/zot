# ---
# Stage 1: Install certs, build binary, create default config file
# ---
FROM docker.io/golang:1.16 AS builder
RUN mkdir -p /go/src/github.com/anuvu/zot
WORKDIR /go/src/github.com/anuvu/zot
COPY . .
RUN CGO_ENABLED=0 make clean binary
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
    },\n\
    "extensions": {\n\
        "metrics": {\n\
            "enable": true,\n\
            "prometheus": {\n\
                "path": "/metrics"\n\
            }\n\
        }\n\
    }\n\
}\n' > config.json && cat config.json

# ---
# Stage 2: Final image with nothing but certs, binary, and default config file
# ---
FROM scratch AS final
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=builder /go/src/github.com/anuvu/zot/bin/zot /zot
COPY --from=builder /go/src/github.com/anuvu/zot/config.json /etc/zot/config.json
ENTRYPOINT ["/zot"]
EXPOSE 5000
VOLUME ["/var/lib/registry"]
CMD ["serve", "/etc/zot/config.json"]
