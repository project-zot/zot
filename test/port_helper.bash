ROOT_DIR=$(git rev-parse --show-toplevel)
PORTS_JSON_PATH="${ROOT_DIR}/test/ports.json"

# outputs an available port in the given range
# usage: get_free_port_in_range range_start range_end
function get_free_port_in_range(){
    range_start=$1
    range_end=$2

    range=$(( range_end - range_start + 1 ))

    while true
    do
        random_port=$(( range_start + (RANDOM % range) ))
        status="$(nc -z 127.0.0.1 $random_port < /dev/null &>/dev/null; echo $?)"
        if [ "${status}" != "0" ]; then
            free_port=${random_port};
            break;
        fi
    done

    echo ${free_port}
}

# gets a free port for a service in a BATS test run
# the output port is from an allocated range in ports.json
# usage: get_free_port_for_service service_name
function get_free_port_for_service() {
    svc_name="$1"

    dir_name=$(basename ${BATS_TEST_DIRNAME})
    file_name=$(basename ${BATS_TEST_FILENAME})
    test_file_name="${dir_name}/${file_name}"

    # lookup info in ports.json
    service_obj=$(jq ".\"${test_file_name}\".${svc_name}" ${PORTS_JSON_PATH})
    [ "0" -eq $? ] || exit 1

    range_start=$(echo "${service_obj}" | jq '.begin')
    [ "0" -eq $? ] || exit 1

    range_end=$(echo "${service_obj}" | jq '.end')
    [ "0" -eq $? ] || exit 1

    echo "# fetching free port for service ${svc_name} in ${test_file_name} range ${range_start} to ${range_end}" >&3

    free_port=$(get_free_port_in_range ${range_start} ${range_end})
    echo "# returning free port for service ${svc_name} in ${test_file_name} => ${free_port}" >&3

    echo ${free_port}
}
