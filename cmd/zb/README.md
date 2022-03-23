# `zb`

## `zb` is a registry benchmarking tool which can run against any [distribution spec](https://github.com/opencontainers/distribution-spec) comformant registry.


```
Usage:
  zb [options] <url> [flags]

Flags:
  -A, --auth-creds string      Use colon-separated BASIC auth creds
  -c, --concurrency int        Number of multiple requests to make at a time (default 1)
  -h, --help                   help for zb
  -o, --output-format string   Output format of test results: stdout (default), json, ci-cd
  -r, --repo string            Use specified repo on remote registry for test data
  -n, --requests int           Number of requests to perform (default 1)
  -s, --src-cidr string        Use specified cidr to obtain ips to make requests from, src-ips and src-cidr are mutually exclusive
  -i, --src-ips string         Use colon-separated ips to make requests from, src-ips and src-cidr are mutually exclusive
  -v, --version                Show the version and exit
  -d, --working-dir string     Use specified directory to store test data
  ```
  
  ## Command example
  ```
  ./bin/zb-linux-amd64 -c 10 -n 100 --src-cidr 127.0.0.0/8 -A user:pass http://localhost:8080
  ```

# References

[1] [https://github.com/opencontainers/distribution-spec/tree/main/conformance](https://github.com/opencontainers/distribution-spec/tree/main/conformance)
[2] [https://en.wikipedia.org/wiki/ApacheBench](https://en.wikipedia.org/wiki/ApacheBench)
