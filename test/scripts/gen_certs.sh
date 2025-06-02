#!/usr/bin/env bash

set -xe

# RSA
openssl req \
    -newkey rsa:2048 \
    -nodes \
    -days 3650 \
    -x509 \
    -keyout ca.key \
    -out ca.crt \
    -subj "/CN=*"

openssl req \
    -newkey rsa:2048 \
    -nodes \
    -keyout server.key \
    -out server.csr \
    -subj "/OU=TestServer/CN=*"

openssl rsa \
    -in server.key \
    -pubout \
    -out server-public.key

openssl rsa \
    -in server.key \
    -RSAPublicKey_out \
    -out server-public-pkcs1.key

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
    -subj "/OU=TestClient/CN=*"

openssl x509 \
    -req \
    -days 3650 \
    -sha256 \
    -in client.csr \
    -CA ca.crt \
    -CAkey ca.key \
    -CAcreateserial \
    -out client.cert

# ECDSA
openssl ecparam \
    -name prime256v1 \
    -genkey \
    -noout \
    -out ca-ecdsa.key

openssl req \
    -new \
    -key ca-ecdsa.key \
    -nodes \
    -days 3650 \
    -x509 \
    -out ca-ecdsa.crt \
    -subj "/CN=*"

openssl ecparam \
    -name prime256v1 \
    -genkey \
    -noout \
    -out server-ecdsa.key

openssl req \
    -new \
    -key server-ecdsa.key \
    -nodes \
    -out server-ecdsa.csr \
    -subj "/OU=TestServer/CN=*"

openssl ec \
    -in server-ecdsa.key \
    -pubout \
    -out server-public-ecdsa.key

openssl x509 \
    -req \
    -days 3650 \
    -sha256 \
    -in server-ecdsa.csr \
    -CA ca-ecdsa.crt \
    -CAkey ca-ecdsa.key \
    -CAcreateserial \
    -out server-ecdsa.cert \
    -extfile <(echo subjectAltName = IP:127.0.0.1)

# ED25519
openssl genpkey \
    -algorithm ed25519 \
    -out ca-ed25519.key

openssl req \
    -new \
    -key ca-ed25519.key \
    -nodes \
    -days 3650 \
    -x509 \
    -out ca-ed25519.crt \
    -subj "/CN=*"

openssl genpkey \
    -algorithm ed25519 \
    -out server-ed25519.key

openssl req \
    -new \
    -key server-ed25519.key \
    -nodes \
    -out server-ed25519.csr \
    -subj "/OU=TestServer/CN=*"

openssl pkey \
    -in server-ed25519.key \
    -pubout \
    -out server-public-ed25519.key

openssl x509 \
    -req \
    -days 3650 \
    -in server-ed25519.csr \
    -CA ca-ed25519.crt \
    -CAkey ca-ed25519.key \
    -CAcreateserial \
    -out server-ed25519.cert \
    -extfile <(echo subjectAltName = IP:127.0.0.1)
