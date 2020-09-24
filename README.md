# zot [![Build Status](https://travis-ci.org/anuvu/zot.svg?branch=master)](https://travis-ci.org/anuvu/zot) [![codecov.io](http://codecov.io/github/anuvu/zot/coverage.svg?branch=master)](http://codecov.io/github/anuvu/zot?branch=master)

**zot** is a vendor-neutral OCI image repository server purely based on 
[OCI Distribution Specification](https://github.com/opencontainers/distribution-spec).

* Conforms to [OCI distribution spec](https://github.com/opencontainers/distribution-spec) APIs [![zot](https://github.com/bloodorangeio/oci-conformance/workflows/zot-1/badge.svg)](https://github.com/bloodorangeio/oci-conformance/actions?query=workflow%3Azot-1) [![zot w. auth](https://github.com/bloodorangeio/oci-distribution-conformance-results/workflows/zot-auth/badge.svg)](https://oci.bloodorange.io/results/report-zot-auth.html)
* Uses [OCI storage layout](https://github.com/opencontainers/image-spec/blob/master/image-layout.md) for storage layout
* Supports [helm charts](https://helm.sh/docs/topics/registries/)
* Currently suitable for on-prem deployments (e.g. colocated with Kubernetes)
* Compatible with ecosystem tools such as [skopeo](#skopeo) and [cri-o](#cri-o)
* [Vulnerability scanning of images](#Scanning-images-for-known-vulnerabilities)
* [Command-line client support](#cli)
* TLS support
* Authentication via:
  * TLS mutual authentication
  * HTTP *Basic* (local _htpasswd_ and LDAP)
  * HTTP *Bearer* token
* Doesn't require _root_ privileges
* Storage optimizations:
  * Automatic garbage collection of orphaned blobs
  * Layer deduplication using hard links when content is identical
* Swagger based documentation
* Single binary for _all_ the above features
* Released under Apache 2.0 License
* ```go get -u github.com/anuvu/zot/cmd/zot```


# Presentations

* [OCI Weekly Discussion - Oct 2, 2019](https://hackmd.io/El8Dd2xrTlCaCG59ns5cwg#October-2-2019)

# Build and install binary (using host's toolchain)

```
go get -u github.com/anuvu/zot/cmd/zot
```

# Full CI/CD Build

* Build inside a container (preferred)

```
make binary-container
```

* Alternatively, build inside a container using [stacker](https://github.com/anuvu/stacker) (preferred)

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

# Caveats

* go 1.12+
* The OCI distribution spec is still WIP, and we try to keep up
