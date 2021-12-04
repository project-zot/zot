# zot [![build-test](https://github.com/project-zot/zot/actions/workflows/ci-cd.yml/badge.svg?branch=main)](https://github.com/project-zot/zot/actions/workflows/ci-cd.yml) [![codecov.io](http://codecov.io/github/project-zot/zot/coverage.svg?branch=main)](http://codecov.io/github/project-zot/zot?branch=main) [![Conformance Results](https://github.com/project-zot/zot/workflows/conformance/badge.svg)](https://github.com/project-zot/zot/actions?query=workflow%3Aconformance)

**zot** is a vendor-neutral OCI image registry server purely based on 
[OCI Distribution Specification](https://github.com/opencontainers/distribution-spec).

https://zotregistry.io

[```docker pull ghcr.io/project-zot/zot:latest```](https://github.com/project-zot/zot/pkgs/container/zot)

[```docker run -p 5000:5000 ghcr.io/project-zot/zot:latest```](https://github.com/project-zot/zot/pkgs/container/zot)

[**Why zot?**](COMPARISON.md)

# Features
* Conforms to [OCI distribution spec](https://github.com/opencontainers/distribution-spec) APIs
* Clear separation between core dist-spec and zot-specific extensions
  * ```make binary-minimal``` builds a dist-spec-only zot
  * ```make binary``` builds a zot with all extensions enabled 
* Uses [OCI image layout](https://github.com/opencontainers/image-spec/blob/master/image-layout.md) for image storage
  * Can serve any OCI image layout as a registry 
* Supports container image signatures - [cosign](https://github.com/sigstore/cosign) and [notation](https://github.com/notaryproject/notation)
* Supports [helm charts](https://helm.sh/docs/topics/registries/)
* Behavior controlled via [configuration](./examples/README.md)
* Supports image deletion by tag
* Currently suitable for on-prem deployments (e.g. colocated with Kubernetes)
* Compatible with ecosystem tools such as [skopeo](#skopeo) and [cri-o](#cri-o)
* [Vulnerability scanning of images](#Scanning-images-for-known-vulnerabilities)
* [Command-line client support](#cli)
* TLS support
* Authentication via:
  * TLS mutual authentication
  * HTTP *Basic* (local _htpasswd_ and LDAP)
  * HTTP *Bearer* token
* Supports Identity-Based Access Control
* Supports live modifications on the config file while zot is running (Authorization config only)
* Doesn't require _root_ privileges
* Storage optimizations:
  * Automatic garbage collection of orphaned blobs
  * Layer deduplication using hard links when content is identical
* Serve [multiple storage paths (and backends)](./examples/config-multiple.json) using a single zot server
* Pull and synchronize from other dist-spec conformant registries [sync](#sync)
* Swagger based documentation
* Single binary for _all_ the above features
* Released under Apache 2.0 License
* [Metrics](#metrics) with Prometheus
  * Using a node exporter in case of dist-spec-only zot
* ```go get -u github.com/project-zot/zot/cmd/zot```

# Presentations

* [OCI Weekly Discussion - Oct 2, 2019](https://hackmd.io/El8Dd2xrTlCaCG59ns5cwg#October-2-2019)

# Build and install binary (using host's toolchain)

```
go get -u github.com/project-zot/zot/cmd/zot
```

# Full CI/CD Build

* Build inside a container (preferred)

```
make binary-container
```

* Alternatively, build inside a container using [stacker](https://github.com/project-stacker/stacker) (preferred)

```
make binary-stacker
```

* Build using host's toolchain

```
make
```

Build artifacts are in bin/

# Serving

```
bin/zot serve _config-file_
```

Examples of config files are available in [examples/](examples/) dir.

# Container Image

The [Dockerfile](./Dockerfile) in this repo can be used to build a container image
that runs _zot_.

To build the image with ref `zot:latest`:

```
make image
```

Then run the image with your preferred container runtime:

```
# with podman
podman run --rm -it -p 5000:5000 -v $(pwd)/registry:/var/lib/registry zot:latest

# with docker
docker run --rm -it -p 5000:5000 -v $(pwd)/registry:/var/lib/registry zot:latest
```

This will run a registry at http://localhost:5000, storing content at `./registry` 
(bind mounted to `/var/lib/registry` in the container). By default, auth is disabled.

If you wish use custom configuration settings, you can override
the YAML config file located at `/etc/zot/config.yml`:

```
# Example: using a local file "custom-config.yml" that
# listens on port 8080 and uses /tmp/zot for storage root
podman run --rm -p 8080:8080 \
  -v $(pwd)/custom-config.yml:/etc/zot/config.yml \
  -v $(pwd)/registry:/tmp/zot \
  zot:latest
```

# CLI

The same zot binary can be used for interacting with any zot server instances.

## Adding a zot server URL

To add a zot server URL with an alias "remote-zot":

```console
$ zot config add remote-zot https://server-example:8080
```

List all configured URLs with their aliases:
```console
$ zot config -l
remote-zot https://server-example:8080
local      http://localhost:8080
```

## Listing images
You can list all images from a server by using its alias specified [in this step](#adding-a-zot-server-url):

```console
$ zot images remote-zot
IMAGE NAME                        TAG                       DIGEST    SIZE
postgres                          9.6.18-alpine             ef27f3e1  14.4MB
postgres                          9.5-alpine                264450a7  14.4MB
busybox                           latest                    414aeb86  707.8KB
```

Or filter the list by an image name:

```console
$ zot images remote-zot -n busybox
IMAGE NAME                        TAG                       DIGEST    SIZE
busybox                           latest                    414aeb86  707.8KB
```
## Scanning images for known vulnerabilities

You can fetch CVE (Common Vulnerabilities and Exposures) info for images hosted on zot

- Get all images affected by a CVE

```console
$ zot cve remote-zot -i CVE-2017-9935
IMAGE NAME                        TAG                       DIGEST    SIZE
c3/openjdk-dev                    commit-5be4d92            ac3762e2  335MB
```

- Get all CVEs for an image

```console
$ zot cve remote-zot -I c3/openjdk-dev:0.3.19
ID                SEVERITY  TITLE
CVE-2015-8540     LOW       libpng: underflow read in png_check_keyword()
CVE-2017-16826    LOW       binutils: Invalid memory access in the coff_s...
```

- Get detailed json output

```console
$ zot cve remote-zot -I c3/openjdk-dev:0.3.19 -o json
{
  "Tag": "0.3.19",
  "CVEList": [
    {
      "Id": "CVE-2019-17006",
      "Severity": "MEDIUM",
      "Title": "nss: Check length of inputs for cryptographic primitives",
      "Description": "A vulnerability was discovered in nss where input text length was not checked when using certain cryptographic primitives. This could lead to a heap-buffer overflow resulting in a crash and data leak. The highest threat is to confidentiality and integrity of data as well as system availability.",
      "PackageList": [
        {
          "Name": "nss",
          "InstalledVersion": "3.44.0-7.el7_7",
          "FixedVersion": "Not Specified"
        },
        {
          "Name": "nss-sysinit",
          "InstalledVersion": "3.44.0-7.el7_7",
          "FixedVersion": "Not Specified"
        },
        {
          "Name": "nss-tools",
          "InstalledVersion": "3.44.0-7.el7_7",
          "FixedVersion": "Not Specified"
        }
      ]
    },
```

- Get all images in a specific repo affected by a CVE

```console
$ zot cve remote-zot -I c3/openjdk-dev -i CVE-2017-9935
IMAGE NAME                        TAG                       DIGEST    SIZE
c3/openjdk-dev                    commit-2674e8a            71046748  338MB
c3/openjdk-dev                    commit-bd5cc94            0ab7fc76  
```

- Get all images of a specific repo where a CVE is fixed

```console
$ zot cve remote-zot -I c3/openjdk-dev -i CVE-2017-9935 --fixed
IMAGE NAME                        TAG                       DIGEST    SIZE
c3/openjdk-dev                    commit-2674e8a-squashfs   b545b8ba  321MB
c3/openjdk-dev                    commit-d5024ec-squashfs   cd45f8cf  321MB
```

# Sync
Periodically pull and synchronize images between zot registries.
The synchronization is achieved by copying all the images found at source to destination.
To use it see [sync-config](examples/config-sync.json)
Supports:
  - TLS verification
  - Prefix filtering (can contain multiple repos, eg repo1/repoX/repoZ)
  - Tags regex filtering
  - Tags semver compliance filtering (the 'v' prefix is optional)
  - BASIC auth
  - Trigger sync with a POST call to http://registry:port/sync


# Ecosystem


## skopeo

[skopeo](https://github.com/containers/skopeo) is a tool to work with remote
image repositories.

* Pull Images

```
skopeo copy docker://<zot-server:port>/repo:tag docker://<another-server:port>/repo:tag
```

* Push Images

```
skopeo copy --format=oci docker://<another-server:port>/repo:tag docker://<zot-server:port>/repo:tag
```

## cri-o

[cri-o](https://github.com/cri-o/cri-o) is a OCI-based Kubernetes container
runtime interface.

Works with "docker://" transport which is the default.

# Metrics

Can be used for both dist-spec-only zot & the zot with all extensions enabled

## Node Exporter
The dist-spec-only zot exposes internal metrics into a Prometheus format through a node exporter.
The configuration of node exporter contains connection details for the zot server it is intend to scrape metrics from. See a [configuration example](./examples/metrics/exporter/config-minimal.json). The metrics are automatically enabled in the zot server on first scrape from the Node Exporter (no extra configuration option is needed). Similarly, the metrics are automatically disabled when Node Exporter did not perform any scrapings in a while.

```
bin/zot-exporter config _config-file_
```

## Enable Metrics
In the zot with all extensions case see [configuration example](./examples/config-metrics.json) for enabling metrics

# Caveats

* go 1.15+
* The OCI distribution spec is still WIP, and we try to keep up

# Contributing

We encourage and support an active, healthy community of contributors.

* Details are in the [code of conduct](CODE_OF_CONDUCT.md)
* Details to get started on code development are in
[contributing](CONTRIBUTING.md) document.
