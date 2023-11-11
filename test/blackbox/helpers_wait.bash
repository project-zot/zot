function wait_for_string() {
    local search_term="$1"
    local filepath="$2"
    local wait_time="${3:-2m}"

    wait_file "$filepath" 60 || { echo "server log file missing: '$filepath'"; return 1; }

    wait_str "$filepath" "$search_term" "$wait_time"
}

function wait_for_string_count() {
    local search_term="$1"
    local filepath="$2"
    local wait_time="${3:-60}"
    local count="$4"

    wait_file "$filepath" 60 || { echo "server log file missing: '$filepath'"; return 1; }

    timeout_func $wait_time wait_string_count "$search_term" $filepath $count
}

function wait_string_count() {
    local search_term="$1"
    local filepath="$2"
    local count="$3"
while ! [[ $(grep -c "$search_term" "$filepath") -ge $count ]]; do
  sleep 1
done
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

function timeout_func() {
	local cmd_pid sleep_pid retval
	(shift; "$@") &   # shift out sleep value and run rest as command in background job
	cmd_pid=$!
	(sleep "$1"; kill "$cmd_pid" 2>/dev/null) &
	sleep_pid=$!
	wait "$cmd_pid"
	retval=$?
	kill "$sleep_pid" 2>/dev/null
	return "$retval"
}
