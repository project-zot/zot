# zot [![Build Status](https://travis-ci.org/anuvu/zot.svg?branch=master)](https://travis-ci.org/anuvu/zot) [![codecov.io](http://codecov.io/github/anuvu/zot/coverage.svg?branch=master)](http://codecov.io/github/anuvu/zot?branch=master)

**zot** is a single-purpose OCI image repository server based on the
[OCI distribution spec](https://github.com/opencontainers/distribution-spec).

* Conforms to [OCI distribution spec](https://github.com/opencontainers/distribution-spec) APIs
* Uses [OCI storage layout](https://github.com/opencontainers/image-spec/blob/master/image-layout.md) for storage layout
* TLS support
* *Basic* and TLS mutual authentication
* Swagger based documentation

# Building

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

# Running

bin/zot serve <config>

# Caveats

* go 1.12+
* The OCI distribution spec is still WIP, and we try to keep up
