function dist_route_check () {
    local servername="http://127.0.0.1:${1}/v2/"
    status_code=$(curl --write-out '%{http_code}' ${2}  --silent --output /dev/null ${servername})

    [ "$status_code" -eq ${3} ]
}
