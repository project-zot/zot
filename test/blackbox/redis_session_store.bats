# Note: Intended to be run as "make run-blackbox-tests" or "make run-blackbox-ci"
#       Makefile target installs & checks all necessary tooling
#       Extra tools that are not covered in Makefile target needs to be added in verify_prerequisites()

load helpers_zot
load helpers_redis
load ../port_helper

function verify_prerequisites() {
    if [ ! $(command -v curl) ]; then
        echo "you need to install curl as a prerequisite to running the tests" >&3
        return 1
    fi

    if [ ! $(command -v docker) ]; then
        echo "you need to install docker as a prerequisite to running the tests" >&3
        return 1
    fi

    if [ ! $(command -v valkey-cli) ]; then
        echo "you need to install valkey-cli as a prerequisite to running the tests" >&3
        return 1
    fi

    return 0
}

HTPASSWD_PATH=/tmp/zotpasswd
CURL_COOKIES_DIR=/tmp/zotcookies
REDIS_TEST_CONTAINER_NAME="redis_sessions_server_local"

function setup_file() {
    # Verify prerequisites are available
    if ! $(verify_prerequisites); then
        exit 1
    fi

    mkdir -p ${CURL_COOKIES_DIR}

    # Create htpasswd file for basic auth
    htpasswd -bBn test test123 > ${HTPASSWD_PATH}

    # Setup redis server
    redis_port=$(get_free_port_for_service "redis")
    redis_start ${REDIS_TEST_CONTAINER_NAME} ${redis_port}

    # Setup zot server
    local zot_root_dir=${BATS_FILE_TMPDIR}/zot
    local zot_redis_session_config_file=${BATS_FILE_TMPDIR}/zot_redis_session_config.json
    zot_port=$(get_free_port_for_service "zot")
    echo ${zot_port} > ${BATS_FILE_TMPDIR}/zot.port
    echo ${redis_port} > ${BATS_FILE_TMPDIR}/redis.port

    mkdir -p ${zot_root_dir}

    cat >${zot_redis_session_config_file} <<EOF
{
    "distSpecVersion": "1.1.1",
    "storage": {
        "rootDirectory": "${zot_root_dir}"
    },
    "http": {
        "address": "127.0.0.1",
        "port": "${zot_port}",
        "auth": {
            "htpasswd": {
                "path": "${HTPASSWD_PATH}"
            },
            "sessionDriver": {
                "name": "redis",
                "url": "redis://localhost:${redis_port}",
                "keyprefix": "zotsession"
            }
        }
    },
    "log": {
        "level": "debug",
        "output": "/tmp/blackbox.log"
    },
    "extensions": {
      "ui": {
        "enable": true
      },
      "search": {
        "enable": true
      }
    }
}
EOF

    zot_serve ${ZOT_PATH} ${zot_redis_session_config_file}
    wait_zot_reachable ${zot_port}
}

function get_zot_port() {
    cat ${BATS_FILE_TMPDIR}/zot.port
}

function get_redis_port() {
    cat ${BATS_FILE_TMPDIR}/redis.port
}

function get_session_count() {
    port=$(get_redis_port)
    valkey-cli -u "redis://localhost:${port}" --scan --pattern 'zotsession:*' | wc -l
}

function perform_login() {
    zot_port=$(get_zot_port)
    user_num=$1

    # The authorization header carries a base 64 encode of test:test123
    curl -s -o /dev/null -w '%{http_code}' --cookie-jar "${CURL_COOKIES_DIR}/zot-cookie-${user_num}" \
    "http://localhost:${zot_port}/v2/" \
    -H 'Accept: application/json, text/plain, */*' \
    -H 'Accept-Language: en-US,en;q=0.5' \
    -H 'Accept-Encoding: gzip, deflate, br, zstd' \
    -H 'Authorization: Basic dGVzdDp0ZXN0MTIz' \
    -H 'X-ZOT-API-CLIENT: zot-ui' \
    -H 'Connection: keep-alive' \
    -H "Referer: http://localhost:${zot_port}/login" \
    -H 'Sec-Fetch-Dest: empty' \
    -H 'Sec-Fetch-Mode: cors' \
    -H 'Sec-Fetch-Site: same-origin' \
    -H 'Priority: u=0' \
    -H 'Pragma: no-cache' \
    -H 'Cache-Control: no-cache'
}

function perform_logout() {
    zot_port=$(get_zot_port)
    user_num=$1

    curl -s -o /dev/null -w '%{http_code}' --cookie "${CURL_COOKIES_DIR}/zot-cookie-${user_num}" \
    -X POST \
    "http://localhost:${zot_port}/zot/auth/logout" \
    -H 'Accept: application/json, text/plain, */*' \
    -H 'Accept-Language: en-US,en;q=0.5' \
    -H 'Accept-Encoding: gzip, deflate, br, zstd' \
    -H "Origin: http://localhost:${zot_port}/login" \
    -H 'X-ZOT-API-CLIENT: zot-ui' \
    -H 'Connection: keep-alive' \
    -H "Referer: http://localhost:${zot_port}/home" \
    -H 'Sec-Fetch-Dest: empty' \
    -H 'Sec-Fetch-Mode: cors' \
    -H 'Sec-Fetch-Site: same-origin' \
    -H 'Priority: u=0' \
    -H 'Pragma: no-cache' \
    -H 'Cache-Control: no-cache' \
    -H 'Content-Length: 0'
}

function perform_authenticated_globalsearch() {
    zot_port=$(get_zot_port)
    user_num=$1

    url="http://localhost:${zot_port}"
    url+='/v2/_zot/ext/search?query={GlobalSearch(query:%22%22,%20requestedPage:%20{limit:3%20offset:0%20sortBy:%20DOWNLOADS}%20)%20{Page%20{TotalCount%20ItemCount}%20Repos%20{Name%20LastUpdated%20Size%20Platforms%20{%20Os%20Arch%20}%20IsStarred%20IsBookmarked%20NewestImage%20{%20Tag%20Vulnerabilities%20{MaxSeverity%20Count}%20Description%20IsSigned%20SignatureInfo%20{%20Tool%20IsTrusted%20Author%20}%20Licenses%20Vendor%20Labels%20}%20StarCount%20DownloadCount}}}'

    curl -g -s -o /dev/null -w '%{http_code}' --cookie "${CURL_COOKIES_DIR}/zot-cookie-${user_num}" \
     "${url}" \
    -H 'Accept: application/json' \
    -H 'Accept-Language: en-US,en;q=0.5' \
    -H 'Accept-Encoding: gzip, deflate, br, zstd' \
    -H 'X-ZOT-API-CLIENT: zot-ui' \
    -H 'Connection: keep-alive' \
    -H "Referer: http://localhost:${zot_port}/home" \
    -H 'Sec-Fetch-Dest: empty' \
    -H 'Sec-Fetch-Mode: cors' \
    -H 'Sec-Fetch-Site: same-origin' \
    -H 'Pragma: no-cache' \
    -H 'Cache-Control: no-cache'
}

@test "verify bulk user authentication cycle" {
    num_users=20

    # Note: queries are forked and run concurrently for load

    for i in $(seq 1 ${num_users}); do
        (
            # User tries to access the global search URL without login
            echo "user $i unauthenticated URL check"
            status=$(perform_authenticated_globalsearch $i)
            [ 401 -eq "${status}" ]

            # User login
            echo "user $i login"
            status=$(perform_login $i)
            [ 200 -eq "${status}" ]
        ) &
    done

    # wait for background processes to complete
    sleep 0.1
    echo "waiting for background process completion"
    wait $(jobs -p)

    for i in $(seq 1 ${num_users}); do
        # Retry authenticated global search URL
        (
            echo "user $i authenticated URL check"
            status=$(perform_authenticated_globalsearch $i)
            [ 200 -eq "${status}" ]
        ) &
    done

    # wait for background processes to complete
    sleep 0.1
    echo "waiting for background process completion"
    wait $(jobs -p)

    cookies_count=$(get_session_count)
    echo "total cookies ${cookies_count}"
    [ "${cookies_count}" -eq "${num_users}" ]

    for i in $(seq 1 ${num_users}); do
        # All users logout
        (
            status=$(perform_logout $i)
            [ 200 -eq "${status}" ]
        ) &
    done

    # wait for background processes to complete
    sleep 0.1
    echo "waiting for background process completion"
    wait $(jobs -p)

    for i in $(seq 1 ${num_users}); do
        # All users verify no access to URL
        (
            status=$(perform_authenticated_globalsearch $i)
            [ 401 -eq "${status}" ]
        ) &
    done

    # wait for background processes to complete
    sleep 0.1
    echo "waiting for background process completion"
    wait $(jobs -p)

    cookies_count=$(get_session_count)
    echo "total cookies ${cookies_count}"
    [ 0 -eq "${cookies_count}" ]
}

function teardown_file() {
    zot_stop_all
    redis_stop ${REDIS_TEST_CONTAINER_NAME}
    rm ${HTPASSWD_PATH}
    rm -r ${CURL_COOKIES_DIR}
}
