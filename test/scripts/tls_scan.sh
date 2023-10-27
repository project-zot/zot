#!/usr/bin/env bash

set -x

curl -kv --tls-max 1.0 https://localhost:8080/v2/
if [[ "$?" -eq 0 ]]; then echo "TLSv1.0 detected"; exit 1; fi

curl -kv --tls-max 1.1 https://localhost:8080/v2/
if [[ "$?" -eq 0 ]]; then echo "TLSv1.1 detected"; exit 1; fi

curl -kv --tls-max 1.2 https://localhost:8080/v2/
if [[ "$?" -ne 0 ]]; then echo "TLSv1.2 missing"; exit 1; fi

curl -kv --tls-max 1.3 https://localhost:8080/v2/
if [[ "$?" -ne 0 ]]; then echo "TLSv1.3 missing"; exit 1; fi

exit 0
