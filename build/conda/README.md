# Conda Build for zot

This directory contains Conda/Mamba build configurations for building zot and its related tools as Conda packages.

## Prerequisites

- [Conda](https://docs.conda.io/en/latest/miniconda.html) or [Mamba](https://mamba.readthedocs.io/) installed
- `conda-build` package: `conda install conda-build`
- Alternatively, use `boa` for faster builds: `conda install boa`

### Quick Setup

Create a conda environment with all build dependencies:

```bash
conda env create -f build/conda/environment.yaml
conda activate zot-build
```

## Building with conda-build

### Build zot (full version with all extensions)
```bash
# From project root
conda build build/conda/meta.yaml --output-folder conda-bld/

# Or use the Makefile target
make binary-conda
```

### Build zot-minimal (minimal version without extensions)
```bash
# From project root
conda build build/conda/meta-minimal.yaml --output-folder conda-bld/

# Or use the Makefile target
make binary-conda-minimal
```

## Building with boa (faster alternative)

Boa is a faster alternative to conda-build that uses mambabuild:

```bash
# Install boa
conda install -c conda-forge boa

# Build with boa
conda mambabuild build/conda/meta.yaml --output-folder conda-bld/
```

## Building from the Makefile

From the project root:
```bash
make binary-conda          # Build zot with conda
make binary-conda-minimal  # Build zot-minimal with conda
make binary-conda-boa      # Build zot with boa (faster)
```

The built packages will be available in `conda-bld/` directory.

## Quick Reference

| Command | Description |
|---------|-------------|
| `make check-conda` | Verify conda and conda-build are installed |
| `make binary-conda` | Build full zot package with all extensions |
| `make binary-conda-minimal` | Build minimal zot package without extensions |
| `make binary-conda-boa` | Build with boa/mambabuild (faster alternative) |
| `conda install -c ./conda-bld zot` | Install locally built package |
| `make clean` | Remove build artifacts including conda-bld/ |

## Installing the Built Package

After building, you can install the package locally:

```bash
# Install from local build
conda install -c ./conda-bld zot

# Or create a new environment with the package
conda create -n zot-env -c ./conda-bld zot
conda activate zot-env
zot --help
```

## Environment Variables

You can customize the build by setting environment variables:

- `RELEASE_TAG`: Set the release version tag (e.g., `v2.0.0`)
- `COMMIT`: Set the git commit hash
- `GO_VERSION`: Set the Go version used for building
- `BUILD_LABELS`: Comma-separated list of extension labels

Example:
```bash
RELEASE_TAG=v2.0.0 COMMIT=$(git rev-parse HEAD) conda build build/conda/meta.yaml
```

## Cross-Platform Building

To build for different platforms:

```bash
# Build for linux-64
conda build build/conda/meta.yaml --platform linux-64

# Build for linux-aarch64
conda build build/conda/meta.yaml --platform linux-aarch64

# Build for osx-64
conda build build/conda/meta.yaml --platform osx-64

# Build for osx-arm64 (Apple Silicon)
conda build build/conda/meta.yaml --platform osx-arm64
```

## Uploading to Conda Channel

To share your builds, you can upload to Anaconda.org:

```bash
# Install anaconda-client
conda install anaconda-client

# Login
anaconda login

# Upload the package
anaconda upload conda-bld/linux-64/zot-*.tar.bz2
```

## Multi-Package Build

The standard build includes three binaries:
- `zot` - Main registry server
- `zli` - CLI tool for interacting with zot
- `zb` - Benchmark tool

All three are included in a single conda package.

## Package Variants

- **zot** (`meta.yaml`) - Full build with all extensions enabled
- **zot-minimal** (`meta-minimal.yaml`) - Minimal build with no extensions

## Troubleshooting

### Build fails with "go: module cache not found"

Make sure you have internet access during the build as conda-build needs to download Go modules.

### CGO errors

All builds are configured with `CGO_ENABLED=0` for static binaries. If you need CGO support, modify the `meta.yaml` files.

### Platform-specific issues

Some platforms may require additional build dependencies. Check the conda-forge documentation for platform-specific requirements.

## Notes

- All binaries are built with CGO disabled for maximum portability
- Binaries are statically linked where possible
- Debug symbols are stripped for smaller package size
- The build uses Go modules for dependency management
