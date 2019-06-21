#!/usr/bin/env bash

# This command is used by bazel as the workspace_status_command
# to implement build stamping with git information.

set -o errexit
set -o nounset
set -o pipefail

GIT_COMMIT=$(git rev-parse --short HEAD)
GIT_TAG=$(git describe --abbrev=0 --tags 2>/dev/null || echo "0.0.0")

# Prefix with STABLE_ so that these values are saved to stable-status.txt
# instead of volatile-status.txt.
# Stamped rules will be retriggered by changes to stable-status.txt, but not by
# changes to volatile-status.txt.
cat <<EOF
STABLE_BUILD_GIT_COMMIT ${GIT_COMMIT-}
STABLE_BUILD_GIT_TAG ${GIT_TAG-}
EOF
