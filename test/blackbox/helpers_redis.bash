
function redis_start() {
  local cname="$1" # container name
  local free_port="$2"
  # pinned to the ghcr mirror (not bare "redis") so this doesn't depend on reaching Docker Hub,
  # matching every other blackbox helper container; see helpers_events.bash for what happens
  # when a helper container isn't self-contained like this.
  docker run -d --name ${cname} -p ${free_port}:6379 ghcr.io/project-zot/ci-images/redis:7.4.2
}

function redis_stop() {
  local cname="$1"
  docker stop ${cname}
  docker rm -f ${cname}
}
