#!/bin/bash

# Pre-download Docker images used in blackbox tests.
# Optional first argument (or BLACKBOX_CI_SHARD) selects a shard-aware subset:
#   registry / upgrade — busybox-docker (docker_compat / pushpull / upgrade helpers)
#   host-deps — nats, nats-box, python, redis
#   sync — none of the helper images
#   all (default) — every image below

set -e

SHARD="${1:-${BLACKBOX_CI_SHARD:-all}}"

echo "Pre-downloading Docker images for blackbox tests (shard=${SHARD})..."

IMG_NATS="ghcr.io/project-zot/ci-images/nats:2.11.1"
IMG_NATS_BOX="ghcr.io/project-zot/ci-images/nats-box:0.19.7"
IMG_PYTHON="ghcr.io/project-zot/ci-images/python:3.11"
IMG_REDIS="ghcr.io/project-zot/ci-images/redis:7.4.2"
IMG_BUSYBOX_DOCKER="ghcr.io/project-zot/test-images/busybox-docker:1.37"

IMAGES=()
case "${SHARD}" in
  registry|upgrade)
    IMAGES=("${IMG_BUSYBOX_DOCKER}")
    ;;
  host-deps)
    IMAGES=("${IMG_NATS}" "${IMG_NATS_BOX}" "${IMG_PYTHON}" "${IMG_REDIS}")
    ;;
  sync)
    IMAGES=()
    ;;
  all)
    IMAGES=(
      "${IMG_NATS}"
      "${IMG_NATS_BOX}"
      "${IMG_PYTHON}"
      "${IMG_REDIS}"
      "${IMG_BUSYBOX_DOCKER}"
    )
    ;;
  *)
    echo "unknown shard '${SHARD}' for image preload; expected registry|host-deps|sync|upgrade|all" >&2
    exit 1
    ;;
esac

download_image() {
    local image="$1"
    echo "Checking for image: $image"

    if docker image inspect "$image" >/dev/null 2>&1; then
        echo "✓ Image $image already exists"
    else
        echo "Downloading image: $image"
        if docker pull "$image"; then
            echo "✓ Successfully downloaded $image"
        else
            echo "✗ Failed to download $image"
            return 1
        fi
    fi
}

if [ "${#IMAGES[@]}" -eq 0 ]; then
    echo "No helper Docker images required for shard '${SHARD}'."
    exit 0
fi

for image in "${IMAGES[@]}"; do
    download_image "$image"
done

echo "All Docker images are ready for testing!"
