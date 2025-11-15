#!/bin/bash
# Build script for zot conda package
set -euo pipefail

# This script is called by conda-build and should not be run directly
# Use: conda build build/conda/meta.yaml

echo "Building zot with conda-build..."
echo "Target platform: ${target_platform:-unknown}"
echo "Prefix: ${PREFIX:-unknown}"

# The actual build commands are in meta.yaml
# This script can be used for any custom pre/post build steps if needed

echo "Build script completed successfully"
