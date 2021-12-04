# Why zot?

A comparison between various registries and their capabilities with respect to zot.

Please see [documentation](./examples/README.md) for various configuration options.

## [docker distribution](https://github.com/distribution/distribution)

| | docker distribution | zot |
|---|---|---|
| **Last stable release** | v2.7.1 (Jan 17, 2019) | v1.3.0 (Sep 1, 2021) |
| **License** | Apache 2.0 | Apache 2.0 |
| **On-premise deployment** | yes | yes |
| **Minimal build*** | no | yes |
| **Storage Layout** | project-specific layout [1] | ociv1 image layout [2] |
| **Authentication** | auxiliary [3] | built-in |
| **Authorization** | auxiliary [3] | built-in |
| **Garbage collection** | requires server shutdown | inline |
| **Storage deduplication** | none | inline |
| **Cloud storage support** | yes | yes |
| **Delete by tag** | unsupported [4],[5] | yes |
| **Vulnerability scanning** | none | built-in |
| **cli** | yes | yes |
| **ui** | auxiliary [3],[4] | yes [8] |
| **External contributions** | yes | yes |
| **CNCF project** | yes [9] | no |
| **dist-spec conformance** | pending 3.x release [10][11] | yes [12] |
| **Image Signatures** | auxiliary [13] | built-in [14][15] |

\* NOTE: "minimal build" criterion above means the ability to build a minimal
distribution-spec compliant registry in order to reduce library dependencies
and the possible attack surface.

# References

[1] https://github.com/distribution/distribution/tree/main/registry/storage

[2] https://github.com/opencontainers/image-spec

[3] https://github.com/cesanta/docker_auth

[4] https://github.com/distribution/distribution/issues/3234

[5] https://github.com/distribution/distribution/issues/2747

[6] https://github.com/Joxit/docker-registry-ui

[7] https://github.com/parabuzzle/craneoperator

[8] https://github.com/project-zot/zot-ui

[9] https://www.docker.com/blog/donating-docker-distribution-to-the-cncf/

[10] https://github.com/distribution/distribution/issues/3203

[11] https://github.com/opencontainers/oci-conformance/tree/main/distribution-spec#distributiondistribution

[12] https://github.com/opencontainers/oci-conformance/tree/main/distribution-spec#project-zotzot

[13] https://docs.docker.com/engine/security/trust/

[14] https://github.com/notaryproject/notation

[15] https://github.com/sigstore/cosign
