#!/bin/bash

# Pre-download Docker images used in blackbox tests
# This script ensures all required images are available before tests start

set -e

echo "Pre-downloading Docker images for blackbox tests..."

# List of images used in the tests
IMAGES=(
    "nats:2.11.1"
    "natsio/nats-box:latest"
    "python:3"
    "redis:latest"
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
