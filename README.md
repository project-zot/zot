# zot [![Build Status](https://travis-ci.org/anuvu/zot.svg?branch=master)](https://travis-ci.org/anuvu/zot) [![codecov.io](http://codecov.io/github/anuvu/zot/coverage.svg?branch=master)](http://codecov.io/github/anuvu/zot?branch=master)

**zot** is a vendor-neutral OCI image repository server purely based on 
[OCI Distribution Specification](https://github.com/opencontainers/distribution-spec).

* Conforms to [OCI distribution spec](https://github.com/opencontainers/distribution-spec) APIs [![zot](https://github.com/bloodorangeio/oci-distribution-conformance-results/workflows/zot/badge.svg)](https://oci.bloodorange.io/results/report-zot.html) [![zot w. auth](https://github.com/bloodorangeio/oci-distribution-conformance-results/workflows/zot-auth/badge.svg)](https://oci.bloodorange.io/results/report-zot-auth.html)
* Uses [OCI storage layout](https://github.com/opencontainers/image-spec/blob/master/image-layout.md) for storage layout
* Currently suitable for on-prem deployments (e.g. colocated with Kubernetes)
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
* Search CVE Vulnerabilities based on CVEId, Package Vendor, Package Name and Package Name+Version
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
# Search Vulnerabilities 

* Start the server 

* Run the following command

``` 
curl -X POST -H "Content-Type: application/json" --data '{ "query": "{ CveIdSearch (text:\"CVE-1999-0002\") { name VulDesc VulDetails { PkgName PkgVendor PkgVersion } } }" }' http://localhost:8080/v2/query
```
```
curl -X POST -H "Content-Type: application/json" --data '{ "query": "{ PkgVendor (text:\"openbsd\") { name  } }" }' http://localhost:8080/v2/query 
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

# Ecosystem

Since we couldn't find clients or client libraries that are stictly compliant to
the dist spec, we had to patch containers/image (available as [anuvu/image](https://github.com/anuvu/image)) and
then link various binaries against the patched version.

## skopeo

[skopeo](https://github.com/containers/skopeo) is a tool to work with remote
image repositories.

We have a [patched version](https://github.com/anuvu/skopeo) available that
works with _zot_.

```
git clone https://github.com/anuvu/skopeo

cd skopeo

make GO111MODULE=on binary-local
```

## cri-o

[cri-o](https://github.com/cri-o/cri-o) is a OCI-based Kubernetes container
runtime interface.

We have a [patched version](https://github.com/anuvu/image) of containers/image
available that works with _zot_ which must be linked with cri-o.

```
git clone https://github.com/cri-o/cri-o

cd cri-o

echo 'replace github.com/containers/image => github.com/anuvu/image v1.5.2-0.20190827234748-f71edca6153a' >> go.mod

make bin/crio crio.conf GO111MODULE=on

```

# Caveats

* go 1.12+
* The OCI distribution spec is still WIP, and we try to keep up
