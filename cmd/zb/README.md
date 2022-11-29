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

```
docker run -net=host -it ghcr.io/project-zot/zb-linux-amd64:latest -c 2 -n 10 -s 127.0.0.0/8 http://localhost:5000
```

## Command output

```console
$ zb -c 10 -n 1000 http://localhost:8080

Registry URL: http://localhost:8080

Concurrency Level: 2
Total requests:    100
Working dir:

============
Test name:            Get Catalog
Time taken for tests: 45.397205ms
Complete requests:    100
Failed requests:      0
Requests per second:  2202.7788

2xx responses: 100

min: 402.259µs
max: 3.295887ms
p50: 855.045µs
p75: 971.709µs
p90: 1.127389ms
p99: 3.295887ms

============
Test name:            Push Monolith 1MB
Time taken for tests: 952.336383ms
Complete requests:    100
Failed requests:      0
Requests per second:  105.00491

2xx responses: 100

min: 11.125673ms
max: 26.375356ms
p50: 18.917253ms
p75: 21.753441ms
p90: 24.02137ms
p99: 26.375356ms

...
```

# References

[1] [https://github.com/opencontainers/distribution-spec/tree/main/conformance](https://github.com/opencontainers/distribution-spec/tree/main/conformance)
[2] [https://en.wikipedia.org/wiki/ApacheBench](https://en.wikipedia.org/wiki/ApacheBench)
