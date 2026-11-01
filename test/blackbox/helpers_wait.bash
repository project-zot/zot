function wait_for_string() {
    local search_term="$1"
    local filepath="$2"
    local wait_time="${3:-2m}"

    wait_file "$filepath" 60 || { echo "server log file missing: '$filepath'"; return 1; }

    wait_str "$filepath" "$search_term" "$wait_time"
}

function wait_str() {
    local filepath="$1"
    local search_term="$2"
    local wait_time="${3:-2m}"

    (timeout $wait_time tail -F -n +1 "$filepath" &) | grep -q "$search_term" && return 0

    echo "timeout of $wait_time reached. unable to find '$search_term' in '$filepath'"

    return 1
}

# Waits for a fixed string to appear in a log at or after start_line, so a
# test only matches entries it caused, not ones from earlier tests that
# share the same zot log.
# Args: $1 = log file, $2 = start line, $3 = expected string, $4 = timeout seconds (default 30)
function wait_for_log_entry() {
    local log_file="$1"
    local start_line="$2"
    local expected="$3"
    local deadline=$((SECONDS + ${4:-30}))

    while [ "${SECONDS}" -lt "${deadline}" ]; do
        if tail -n +"${start_line}" "${log_file}" | grep -Fq "${expected}"; then
            return 0
        fi
        sleep 0.5
    done

    echo "did not find '${expected}' in ${log_file}" >&3
    tail -n 100 "${log_file}" >&3
    return 1
}

function wait_file() {
    local file="$1"; shift
    local wait_seconds="${1:-60}"; shift

    until test $((wait_seconds--)) -eq 0 -o -f "$file" ; do sleep 1; done
}

# Args: $1 = max attempts, $2 = delay seconds, $3+ = command
function retry_until_success() {
    local attempts=${1}
    local delay=${2}
    shift 2

    while [ "${attempts}" -gt 0 ]; do
        run "$@"
        if [ "${status}" -eq 0 ]; then
            return 0
        fi
        attempts=$((attempts - 1))
        if [ "${attempts}" -eq 0 ]; then
            return "${status}"
        fi
        sleep "${delay}"
    done
}
