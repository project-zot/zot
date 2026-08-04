function nats_server_start() {
  local cname="$1" # container name
  local free_port="$2"
  docker run -d --name ${cname} -p ${free_port}:4222 ghcr.io/project-zot/ci-images/nats:2.11.1 --user jane.joe --pass opensesame
}

function nats_server_stop() {
  local cname="$1"
  docker stop ${cname}
  docker rm -f ${cname}
}

function wait_event_on_subject() {
    local subject="$1"
    local port="$2"
    local dir="$3"
    local count="${4:-1}"

    mkdir -p "${dir}"

    # --wait must cover slow concurrent-CI pushes (e.g. golang:1.20). A short
    # window lets the subscriber exit before ImageUpdated / RepositoryCreated.
    docker run -d --rm --network host --user "$(id -u):$(id -g)" -v "${dir}":/data ghcr.io/project-zot/ci-images/nats-box:0.19.7  \
        nats sub ${subject} --user jane.joe --password opensesame \
        --server nats://127.0.0.1:${port} --count=${count} --wait=60s --raw --dump=/data

    # give client a chance to startup
    sleep 2

    return $?
}

# Poll until nats sub --dump has written the expected number of event files.
# Call this after the action that should publish (push/delete), not before.
function wait_for_nats_event_files() {
    local dir="$1"
    local expected="${2:-1}"
    local timeout="${3:-60}"
    local start_ts=$SECONDS
    local count=0
    local elapsed=0
    local last_log=0

    echo "# waiting for ${expected} nats event file(s) in ${dir}..." >&3

    while [ $((SECONDS - start_ts)) -lt "$timeout" ]; do
        count=$(find "${dir}" -type f 2>/dev/null | wc -l)
        if [ "$count" -ge "$expected" ]; then
            elapsed=$((SECONDS - start_ts))
            echo "# found ${count} nats event file(s) after ${elapsed}s" >&3
            return 0
        fi
        sleep 0.5
        elapsed=$((SECONDS - start_ts))
        if [ $((elapsed - last_log)) -ge 5 ]; then
            echo "# still waiting for nats events in ${dir}... (${count}/${expected}, ${elapsed}s)" >&3
            last_log=$elapsed
        fi
    done

    count=$(find "${dir}" -type f 2>/dev/null | wc -l)
    echo "# timed out waiting for ${expected} nats event file(s) in ${dir} (got ${count})" >&3
    ls -la "${dir}" >&3 2>&1 || true
    return 1
}

function http_server_start() {
    local cname="$1"
    local port="$2"
    local dir="$3"

    mkdir -p "${dir}"

    echo "# starting HTTP server container '${cname}' on port ${port}..." >&3

    # Use stdlib only (no pip install) so readiness is not gated on PyPI.
    docker run -d --rm --name "${cname}" \
        -p "${port}:8080" \
        -v "${dir}":/data \
        ghcr.io/project-zot/ci-images/python:3.11 sh -c ' \
            echo "
import base64
import json
from http.server import BaseHTTPRequestHandler, HTTPServer

USERNAME = \"jane.joe\"
PASSWORD = \"opensesame\"
counter = 0

class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        return

    def _unauthorized(self):
        self.send_response(401)
        self.send_header(\"WWW-Authenticate\", \"Basic realm=\\\"Login Required\\\"\")
        self.end_headers()
        self.wfile.write(b\"Unauthorized\")

    def _authorized(self):
        auth = self.headers.get(\"Authorization\", \"\")
        if not auth.startswith(\"Basic \"):
            return False
        try:
            decoded = base64.b64decode(auth[6:]).decode(\"utf-8\")
        except Exception:
            return False
        user, _, password = decoded.partition(\":\")
        return user == USERNAME and password == PASSWORD

    def do_GET(self):
        global counter
        if self.path != \"/reset\":
            self.send_response(404)
            self.end_headers()
            return
        counter = 0
        self.send_response(200)
        self.end_headers()

    def do_POST(self):
        global counter
        if self.path != \"/events\":
            self.send_response(404)
            self.end_headers()
            return
        if not self._authorized():
            self._unauthorized()
            return
        try:
            length = int(self.headers.get(\"Content-Length\", \"0\"))
        except ValueError:
            self.send_response(400)
            self.end_headers()
            return
        raw_data = self.rfile.read(length).decode(\"utf-8\", errors=\"replace\")
        try:
            body = json.loads(raw_data)
        except Exception:
            body = raw_data
        counter += 1
        event = {
            \"method\": self.command,
            \"headers\": dict(self.headers),
            \"body\": body,
        }
        with open(f\"/data/{counter}.json\", \"w\") as f:
            json.dump(event, f, indent=2)
        self.send_response(200)
        self.end_headers()

# Single-threaded so counter + /data/{n}.json stay deterministic under concurrent POSTs.
HTTPServer((\"0.0.0.0\", 8080), Handler).serve_forever()
            " > app.py && python app.py
'

    # Give container a moment to start
    sleep 2

    # Check if container is running
    if docker ps --format "{{.Names}}" | grep -qx "${cname}"; then
        echo "# HTTP server container '${cname}' started successfully" >&3
    else
        echo "# WARNING: HTTP server container '${cname}' may not have started properly" >&3
        docker logs "${cname}" >&3 2>&1 || true
    fi
}

function http_server_stop() {
    local cname="$1"
    docker rm -f "${cname}" >/dev/null 2>&1
}

function wait_for_http_server() {
    local port="$1"
    local cname="${2:-}"
    local timeout=60
    local start_ts=$SECONDS
    local elapsed=0
    local last_log=0

    echo "# waiting for HTTP server on port ${port}..." >&3

    while [ $((SECONDS - start_ts)) -lt "$timeout" ]; do
        if curl --silent --fail --connect-timeout 3 --max-time 5 \
            --output /dev/null "http://127.0.0.1:${port}/reset"; then
            elapsed=$((SECONDS - start_ts))
            echo "# HTTP server ready on port ${port} after ${elapsed}s" >&3
            return 0
        fi
        sleep 1
        elapsed=$((SECONDS - start_ts))
        if [ $((elapsed - last_log)) -ge 5 ]; then
            echo "# still waiting for HTTP server on port ${port}... (${elapsed}s elapsed)" >&3
            last_log=$elapsed
        fi
    done

    elapsed=$((SECONDS - start_ts))
    echo "# HTTP server failed to start on port ${port} after ${elapsed}s" >&3
    if [ -n "${cname}" ]; then
        echo "# docker logs for '${cname}':" >&3
        docker logs "${cname}" >&3 2>&1 || true
        docker inspect "${cname}" --format '{{.State.Status}} {{.State.Error}}' >&3 2>&1 || true
    fi
    return 1
}
