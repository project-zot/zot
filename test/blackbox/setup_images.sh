#!/bin/bash

# Pre-download Docker images used in blackbox tests
# This script ensures all required images are available before tests start

set -e

echo "Pre-downloading Docker images for blackbox tests..."

# List of images used in the tests
IMAGES=(
    "ghcr.io/project-zot/ci-images/nats:2.11.1"
    "ghcr.io/project-zot/ci-images/nats-box:0.19.7"
    "ghcr.io/project-zot/ci-images/python:3.11"
    "ghcr.io/project-zot/ci-images/redis:7.4.2"
    "ghcr.io/project-zot/test-images/busybox-docker:1.37"
)

# Function to download an image if not already present
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

# Download all images
for image in "${IMAGES[@]}"; do
    download_image "$image"
done

echo "All Docker images are ready for testing!"
