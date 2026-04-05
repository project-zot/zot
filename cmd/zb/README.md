# `zb`

## `zb` is a registry benchmarking tool which can run against any [distribution spec](https://github.com/opencontainers/distribution-spec) comformant registry.


```
Usage:
  zb <url> [flags]

Flags:
  -A, --auth-creds string            Use colon-separated BASIC auth creds
  -c, --concurrency int              Number of multiple requests to make at a time (default 1)
  -h, --help                         help for zb
  -l, --list-tests                   Print a list of all available tests. When used together with test regex, lists the tests that match the regex.
  -o, --output-format string         Output format of test results: stdout (default), json, ci-cd
  -r, --repo string                  Use specified repo on remote registry for test data
  -n, --requests int                 Number of requests to perform (default 1)
      --skip-cleanup                 Skip clean up of pushed repos from remote registry after running benchmark (default false)
  -s, --src-cidr string              Use specified cidr to obtain ips to make requests from, src-ips and src-cidr are mutually exclusive
  -i, --src-ips string               Use colon-separated ips to make requests from, src-ips and src-cidr are mutually exclusive
  -t, --test-regex string            Optional regex for selectively running tests. If blank, all tests are run by default.
  -u, --upstream-server-url string   Sets the upstream server URL for sync tests. Must be provided for sync tests.
  -v, --version                      Show the version and exit
  -d, --working-dir string           Use specified directory to store test data
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
$ zb -c 2 -n 100 http://localhost:8080
Registry URL:      http://localhost:8080
Concurrency Level: 2
Total requests:    100
Working dir:       /home/user/test

Skipping test On-demand Sync 100MB
Skipping test On-demand Sync 1GB
Preparing test data ...
Starting tests ...
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

## List tests

```
$ zb -l http://localhost:9000
Get Catalog
Push Monolith 1MB
Push Monolith 10MB
Push Monolith 100MB
Push Chunk Streamed 1MB
Push Chunk Streamed 10MB
Push Chunk Streamed 100MB
Pull 1MB
Pull 10MB
Pull 100MB
Pull Mixed 20% 1MB, 70% 10MB, 10% 100MB
Push Monolith Mixed 20% 1MB, 70% 10MB, 10% 100MB
Push Chunk Mixed 33% 1MB, 33% 10MB, 33% 100MB
Pull 75% and Push 25% Mixed 1MB
Pull 75% and Push 25% Mixed 10MB
Pull 75% and Push 25% Mixed 100MB
On-demand Sync 100MB
On-demand Sync 1GB
```

## List tests with Regex

```
$ zb -l --test-regex "^(Push Monolith|Pull) 1MB$" http://localhost:9000
Push Monolith 1MB
Pull 1MB
```

## Selective test run example with only push

```
$ zb --src-cidr 127.0.0.0/8 --test-regex "^Push Monolith 1MB$" http://localhost:9000
Registry URL:      http://localhost:9000
Concurrency Level: 1
Total requests:    1
Working dir:       /home/user/test

Skipping test Get Catalog
Skipping test Push Monolith 10MB
Skipping test Push Monolith 100MB
Skipping test Push Chunk Streamed 1MB
Skipping test Push Chunk Streamed 10MB
Skipping test Push Chunk Streamed 100MB
Skipping test Pull 1MB
Skipping test Pull 10MB
Skipping test Pull 100MB
Skipping test Pull Mixed 20% 1MB, 70% 10MB, 10% 100MB
Skipping test Push Monolith Mixed 20% 1MB, 70% 10MB, 10% 100MB
Skipping test Push Chunk Mixed 33% 1MB, 33% 10MB, 33% 100MB
Skipping test Pull 75% and Push 25% Mixed 1MB
Skipping test Pull 75% and Push 25% Mixed 10MB
Skipping test Pull 75% and Push 25% Mixed 100MB
Skipping test On-demand Sync 100MB
Skipping test On-demand Sync 1GB
Preparing test data ...
Starting tests ...
============
Test name:            Push Monolith 1MB
Time taken for tests: 20.821408ms
Requests per second:  48.027493
Complete requests:    1
Failed requests:      0

2xx responses: 1

min: 18.527633ms
max: 18.527633ms
p50: 18.527633ms
p75: 18.527633ms
p90: 18.527633ms
p99: 18.527633ms
```

## Selective test run with a push and corresponding pull

```
$ zb --src-cidr 127.0.0.0/8 --test-regex "^(Push Monolith|Pull) 1MB$" http://localhost:9000
Registry URL:      http://localhost:9000
Concurrency Level: 1
Total requests:    1
Working dir:       /home/user/test

Skipping test Get Catalog
Skipping test Push Monolith 10MB
Skipping test Push Monolith 100MB
Skipping test Push Chunk Streamed 1MB
Skipping test Push Chunk Streamed 10MB
Skipping test Push Chunk Streamed 100MB
Skipping test Pull 10MB
Skipping test Pull 100MB
Skipping test Pull Mixed 20% 1MB, 70% 10MB, 10% 100MB
Skipping test Push Monolith Mixed 20% 1MB, 70% 10MB, 10% 100MB
Skipping test Push Chunk Mixed 33% 1MB, 33% 10MB, 33% 100MB
Skipping test Pull 75% and Push 25% Mixed 1MB
Skipping test Pull 75% and Push 25% Mixed 10MB
Skipping test Pull 75% and Push 25% Mixed 100MB
Skipping test On-demand Sync 100MB
Skipping test On-demand Sync 1GB
Preparing test data ...
Starting tests ...
============
Test name:            Push Monolith 1MB
Time taken for tests: 21.497313ms
Requests per second:  46.51744
Complete requests:    1
Failed requests:      0

2xx responses: 1

min: 18.826599ms
max: 18.826599ms
p50: 18.826599ms
p75: 18.826599ms
p90: 18.826599ms
p99: 18.826599ms

============
Test name:            Pull 1MB
Time taken for tests: 15.387887ms
Requests per second:  64.98618
Complete requests:    1
Failed requests:      0

2xx responses: 1

min: 2.343145ms
max: 2.343145ms
p50: 2.343145ms
p75: 2.343145ms
p90: 2.343145ms
p99: 2.343145ms

Manifest HEAD TTFB p50: 352.099µs
Manifest HEAD TTFB p75: 352.099µs
Manifest HEAD TTFB p90: 352.099µs
Manifest HEAD TTFB p99: 352.099µs

Manifest GET TTFB p50: 323.77µs
Manifest GET TTFB p75: 323.77µs
Manifest GET TTFB p90: 323.77µs
Manifest GET TTFB p99: 323.77µs

Config TTFB p50: 318.809µs
Config TTFB p75: 318.809µs
Config TTFB p90: 318.809µs
Config TTFB p99: 318.809µs

Layer TTFB p50: 219.679µs
Layer TTFB p75: 219.679µs
Layer TTFB p90: 219.679µs
Layer TTFB p99: 219.679µs
```

## Run on-demand sync tests

Sync tests require an upstream zot registry to be provided and the target zot instance must be configured with on-demand sync config that points to the upstream server.
If upstream registry is not provided, sync tests will be skipped.

```
$ zb --src-cidr 127.0.0.0/8 --test-regex "^On-demand Sync" --upstream-server-url http://localhost:9000  http://localhost:8080
Registry URL:          http://localhost:8080
Upstream Registry URL: http://localhost:9000
Concurrency Level:     1
Total requests:        1
Working dir:           /home/user/test

Skipping test Get Catalog
Skipping test Push Monolith 1MB
Skipping test Push Monolith 10MB
Skipping test Push Monolith 100MB
Skipping test Push Chunk Streamed 1MB
Skipping test Push Chunk Streamed 10MB
Skipping test Push Chunk Streamed 100MB
Skipping test Pull 1MB
Skipping test Pull 10MB
Skipping test Pull 100MB
Skipping test Pull Mixed 20% 1MB, 70% 10MB, 10% 100MB
Skipping test Push Monolith Mixed 20% 1MB, 70% 10MB, 10% 100MB
Skipping test Push Chunk Mixed 33% 1MB, 33% 10MB, 33% 100MB
Skipping test Pull 75% and Push 25% Mixed 1MB
Skipping test Pull 75% and Push 25% Mixed 10MB
Skipping test Pull 75% and Push 25% Mixed 100MB
Preparing test data ...
Starting tests ...
============
Test name:            On-demand Sync 100MB
Time taken for tests: 1.444024183s
Requests per second:  0.6925092
Complete requests:    1
Failed requests:      0

2xx responses: 1

min: 550.943262ms
max: 550.943262ms
p50: 550.943262ms
p75: 550.943262ms
p90: 550.943262ms
p99: 550.943262ms

Manifest HEAD TTFB p50: 546.921878ms
Manifest HEAD TTFB p75: 546.921878ms
Manifest HEAD TTFB p90: 546.921878ms
Manifest HEAD TTFB p99: 546.921878ms

Manifest GET TTFB p50: 1.988577ms
Manifest GET TTFB p75: 1.988577ms
Manifest GET TTFB p90: 1.988577ms
Manifest GET TTFB p99: 1.988577ms

Config TTFB p50: 387.699µs
Config TTFB p75: 387.699µs
Config TTFB p90: 387.699µs
Config TTFB p99: 387.699µs

Layer TTFB p50: 232.091µs
Layer TTFB p75: 232.091µs
Layer TTFB p90: 232.091µs
Layer TTFB p99: 232.091µs

============
Test name:            On-demand Sync 1GB
Time taken for tests: 16.783082396s
Requests per second:  0.05958381
Complete requests:    1
Failed requests:      0

2xx responses: 1

min: 5.175110487s
max: 5.175110487s
p50: 5.175110487s
p75: 5.175110487s
p90: 5.175110487s
p99: 5.175110487s

Manifest HEAD TTFB p50: 5.170570733s
Manifest HEAD TTFB p75: 5.170570733s
Manifest HEAD TTFB p90: 5.170570733s
Manifest HEAD TTFB p99: 5.170570733s

Manifest GET TTFB p50: 2.269987ms
Manifest GET TTFB p75: 2.269987ms
Manifest GET TTFB p90: 2.269987ms
Manifest GET TTFB p99: 2.269987ms

Config TTFB p50: 623.639µs
Config TTFB p75: 623.639µs
Config TTFB p90: 623.639µs
Config TTFB p99: 623.639µs

Layer TTFB p50: 439.369µs
Layer TTFB p75: 439.369µs
Layer TTFB p90: 439.369µs
Layer TTFB p99: 439.369µs
```

# References

[1] [https://github.com/opencontainers/distribution-spec/tree/main/conformance](https://github.com/opencontainers/distribution-spec/tree/main/conformance)
[2] [https://en.wikipedia.org/wiki/ApacheBench](https://en.wikipedia.org/wiki/ApacheBench)
