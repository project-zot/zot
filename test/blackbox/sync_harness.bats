# Note: Intended to be run as "make run-blackbox-tests" or "make run-blackbox-sync-nightly"
#       Makefile target installs & checks all necessary tooling
#       Extra tools that are not covered in Makefile target needs to be added in verify_prerequisites()

load helpers_zot
load helpers_wait

function verify_prerequisites() {
    return 0
}

function setup_file() {
    # Verify prerequisites are available
    if ! $(verify_prerequisites); then
        exit 1
    fi

    # Setup zot server
    local zot_sync_per_root_dir=${BATS_FILE_TMPDIR}/zot-per

    local zot_sync_per_config_file=${BATS_FILE_TMPDIR}/zot_sync_per_config.json
    local zot_sync_ondemand_config_file=${BATS_FILE_TMPDIR}/zot_sync_ondemand_config.json

    local zot_minimal_root_dir=${BATS_FILE_TMPDIR}/zot-minimal
    local zot_minimal_config_file=${BATS_FILE_TMPDIR}/zot_minimal_config.json

    local oci_data_dir=${BATS_FILE_TMPDIR}/oci
    mkdir -p ${zot_sync_per_root_dir}
    mkdir -p ${zot_minimal_root_dir}
    mkdir -p ${oci_data_dir}

    local ZOT_LOG_FILE=${zot_sync_per_root_dir}/zot.log


    cat >${zot_sync_per_config_file} <<EOF
{
    "distSpecVersion": "1.1.0",
    "storage": {
        "rootDirectory": "${zot_sync_per_root_dir}"
    },
    "http": {
        "address": "0.0.0.0",
        "port": "8081"
    },
    "log": {
        "level": "debug",
        "output": "${ZOT_LOG_FILE}"
    },
    "extensions": {
        "sync": {
            "registries": [
                {
                    "urls": [
                        "http://localhost:8080"
                    ],
                    "onDemand": false,
                    "tlsVerify": false,
                    "PollInterval": "5m",
                    "content": [
                        {
                            "prefix": "**"
                        }
                    ]
                }
            ]
        }
    }
}
EOF

    cat >${zot_minimal_config_file} <<EOF
{
    "distSpecVersion": "1.1.0",
    "storage": {
        "rootDirectory": "${zot_minimal_root_dir}"
    },
    "http": {
        "address": "0.0.0.0",
        "port": "8080"
    },
    "log": {
        "level": "debug",
        "output": "${zot_minimal_root_dir}/zot.log"
    }
}
EOF
    zot_serve ${ZOT_MINIMAL_PATH} ${zot_minimal_config_file}
    wait_zot_reachable 8080
}

function teardown_file() {
    zot_stop_all
}

# sync zb images
@test "run zb benchmark and let zot sync all repos" {
    local zot_sync_per_root_dir=${BATS_FILE_TMPDIR}/zot-per
    local zot_sync_per_config_file=${BATS_FILE_TMPDIR}/zot_sync_per_config.json
    local zot_minimal_root_dir=${BATS_FILE_TMPDIR}/zot-minimal
    local ZOT_LOG_FILE=${zot_sync_per_root_dir}/zot.log

    zb_run "http://127.0.0.1:8080"

    # start zot sync server
    zot_serve ${ZOT_PATH} ${zot_sync_per_config_file}
    wait_zot_reachable 8081

    start=`date +%s`
    echo "waiting for sync to finish" >&3

    run wait_for_string "finished syncing all repos" ${ZOT_LOG_FILE} "5m"
    [ "$status" -eq 0 ]

    end=`date +%s`

    runtime=$((end-start))
    echo "sync finished in $runtime sec" >&3
    sleep 10 # wait a bit more because sync runs in background.

    # diff, but exclude log files, .sync subdirs and cache.db
    run diff -r -x "*.db" -x ".sync" -x "*.log" ${zot_sync_per_root_dir} ${zot_minimal_root_dir}
    [ "$status" -eq 0 ]
}
