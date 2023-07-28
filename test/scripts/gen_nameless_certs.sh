#!/usr/bin/env bash

set -xe

openssl req \
    -newkey rsa:2048 \
    -nodes \
    -days 3650 \
    -x509 \
    -keyout ca.key \
    -out ca.crt \
    -subj "/CN="

openssl req \
    -newkey rsa:2048 \
    -nodes \
    -keyout server.key \
    -out server.csr \
    -subj "/OU=TestServer/CN="

openssl x509 \
    -req \
    -days 3650 \
    -sha256 \
    -in server.csr \
    -CA ca.crt \
    -CAkey ca.key \
    -CAcreateserial \
    -out server.cert \
    -extfile <(echo subjectAltName = IP:127.0.0.1)

openssl req \
    -newkey rsa:2048 \
    -nodes \
    -keyout client.key \
    -out client.csr \
    -subj "/OU=TestClient/CN="

openssl x509 \
    -req \
    -days 3650 \
    -sha256 \
    -in client.csr \
    -CA ca.crt \
    -CAkey ca.key \
    -CAcreateserial \
    -out client.cert
