# `zb`

`zb` is a registry benchmarking tool which can run against any [distribution spec](https://github.com/opencontainers/distribution-spec) comformant registry.

-n : total number of requests
-c : number of concurrent clients performing (n/c) requests per client
-d : working dir to store test data
-A : BASIC authentication in `username:passwd` format

# References

[1] [https://github.com/opencontainers/distribution-spec/tree/main/conformance](https://github.com/opencontainers/distribution-spec/tree/main/conformance)
[2] [https://en.wikipedia.org/wiki/ApacheBench](https://en.wikipedia.org/wiki/ApacheBench)
