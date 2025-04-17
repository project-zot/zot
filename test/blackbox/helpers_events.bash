function nats_server_start() {
  local cname="$1" # container name
  local free_port="$2"
  docker run -d --name ${cname} -p ${free_port}:4222 nats:2.11.1 --user jane.joe --pass opensesame
}

function nats_server_stop() {
  local cname="$1"
  docker stop ${cname}
  docker rm -f ${cname}
}

function log_output() {
    local zot_log_file=${BATS_FILE_TMPDIR}/zot/zot-log.json
    cat ${zot_log_file} | jq ' .["message"] '
}

function wait_event_on_subject() {
    local subject="$1"
    local port="$2"
    local dir="$3"
    local count="${4:-1}"

    mkdir -p "${dir}"

    docker run -d --rm --network host --user "$(id -u):$(id -g)" -v "${dir}":/data natsio/nats-box:latest  \
        nats sub ${subject} --user jane.joe --password opensesame \
        --server nats://127.0.0.1:${port} --count=${count} --wait=5s --raw --dump=/data

    # give client a chance to startup
    sleep 2

    return $?
}

function http_server_start() {
    local cname="$1"
    local port="$2"
    local dir="$3"

    mkdir -p "${dir}"

    docker run -d --rm --name "${cname}" \
        -p "${port}:8080" \
        -v "${dir}":/data \
        python:3 sh -c '
            pip install flask > /dev/null && \
            echo "
import os
import json
from flask import Flask, request, Response

app = Flask(__name__)
counter = 0

USERNAME = \"jane.joe\"
PASSWORD = \"opensesame\"

def check_auth(auth):
    return auth and auth.username == USERNAME and auth.password == PASSWORD

def authenticate():
    return Response(
        \"Unauthorized\", 401,
        {\"WWW-Authenticate\": \"Basic realm=\\\"Login Required\\\"\"}
    )

@app.route(\"/reset\", methods=[\"GET\"])
def reset_counter():
    global counter
    counter = 0
    return \"\", 200

@app.route(\"/events\", methods=[\"POST\"])
def receive_event():
    auth = request.authorization
    if not check_auth(auth):
      return authenticate

    global counter
    counter += 1
    method = request.method
    headers = dict(request.headers)
    raw_data = request.data.decode(\"utf-8\", errors=\"replace\")
    try:
        body = json.loads(raw_data)
    except Exception:
        body = raw_data  # fallback to plain text

    event = {
        \"method\": method,
        \"headers\": headers,
        \"body\": body
    }

    filename = f\"/data/{counter}.json\"

    with open(filename, \"w\") as f:
        json.dump(event, f, indent=2)

    return \"\", 200

app.run(host=\"0.0.0.0\", port=8080)
            " > app.py && python app.py
'
}

function http_server_stop() {
    local cname="$1"
    docker rm -f "${cname}" >/dev/null 2>&1
}

function wait_for_http_server() {
    local port="$1"
    local timeout=10
    local elapsed=0

    while [ "$elapsed" -lt "$timeout" ]; do
        if curl --silent --fail --output /dev/null "http://127.0.0.1:${port}/reset"; then
            return 0
        fi
        sleep 1
        elapsed=$((elapsed + 1))
    done

    return 1
}