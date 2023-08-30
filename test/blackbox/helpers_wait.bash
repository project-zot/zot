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

    (timeout $wait_time tail -F -n0 "$filepath" &) | grep -q "$search_term" && return 0

    echo "timeout of $wait_time reached. unable to find '$search_term' in '$filepath'"

    return 1
}

function wait_file() {
    local file="$1"; shift
    local wait_seconds="${1:-60}"; shift

    until test $((wait_seconds--)) -eq 0 -o -f "$file" ; do sleep 1; done
}
