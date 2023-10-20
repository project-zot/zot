METRICS_USER=observability
METRICS_PASS=MySecreTPa55

function metrics_route_check () {
    local servername="http://127.0.0.1:${1}/metrics"
    status_code=$(curl --write-out '%{http_code}' ${2}  --silent --output /dev/null ${servername})

    [ "$status_code" -eq ${3} ]
}
