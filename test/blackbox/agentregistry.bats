# Run with make run-kind-agentregistry; kept separate from concurrent blackbox CI.
load ../port_helper

@test "publish an MCP server to Zot, register it in AgentRegistry, and deploy it through KMCP" {
    command -v nc >/dev/null || { echo "netcat is required" >&3; return 1; }
    export ZOT_HOST_PORT
    export AR_HOST_PORT
    ZOT_HOST_PORT=$(get_free_port_for_service "zot")
    AR_HOST_PORT=$(get_free_port_for_service "agentregistry")

    run bash "${ROOT_DIR}/examples/kind/kind-agentregistry.sh"
    echo "${output}"
    [ "${status}" -eq 0 ]
}
