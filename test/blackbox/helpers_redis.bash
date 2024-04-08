ROOT_DIR=$(git rev-parse --show-toplevel)
OS=$(go env GOOS)
ARCH=$(go env GOARCH)
ZOT_MINIMAL_PATH=${ROOT_DIR}/bin/zot-${OS}-${ARCH}-minimal
ZB_PATH=${ROOT_DIR}/bin/zb-${OS}-${ARCH}
TEST_DATA_DIR=${BATS_FILE_TMPDIR}/test/data

function redis_start() {
  docker run -d --name redis_server -p 6379:6379 redis
}

function redis_stop() {
  docker stop redis_server
  docker rm -f redis_server
}
