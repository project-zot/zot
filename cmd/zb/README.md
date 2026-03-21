# `zb`

## `zb` is a registry benchmarking tool which can run against any [distribution spec](https://github.com/opencontainers/distribution-spec) comformant registry.


```
Usage:
  zb <url> [flags]

Flags:
  -A, --auth-creds string      Use colon-separated BASIC auth creds
  -c, --concurrency int        Number of multiple requests to make at a time (default 1)
  -h, --help                   help for zb
  -l, --list-tests             Print a list of all available tests. When used together with test regex, lists the tests that match the regex.
  -o, --output-format string   Output format of test results: stdout (default), json, ci-cd
  -r, --repo string            Use specified repo on remote registry for test data
  -n, --requests int           Number of requests to perform (default 1)
      --skip-cleanup           Skip clean up of pushed repos from remote registry after running benchmark (default false)
  -s, --src-cidr string        Use specified cidr to obtain ips to make requests from, src-ips and src-cidr are mutually exclusive
  -i, --src-ips string         Use colon-separated ips to make requests from, src-ips and src-cidr are mutually exclusive
  -t, --test-regex string      Optional regex for selectively running tests. If blank, all tests are run by default.
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
Registry URL: http://localhost:9000

Concurrency Level: 1
Total requests:    1
Working dir:       /home/darkaether/projects/github/zot

Preparing test data ...
Starting tests ...
Skipping test Get Catalog
============
Test name:            Push Monolith 1MB
Time taken for tests: 18.700779ms
Requests per second:  53.47371
Complete requests:    1
Failed requests:      0

2xx responses: 1

min: 15.970773ms
max: 15.970773ms
p50: 15.970773ms
p75: 15.970773ms
p90: 15.970773ms
p99: 15.970773ms

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
```

## Selective test run with a push and corresponding pull

```
$ zb --src-cidr 127.0.0.0/8 --test-regex "^(Push Monolith|Pull) 1MB$" http://localhost:9000
Registry URL: http://localhost:9000

Concurrency Level: 1
Total requests:    1
Working dir:       /home/darkaether/projects/github/zot

Preparing test data ...
Starting tests ...
Skipping test Get Catalog
============
Test name:            Push Monolith 1MB
Time taken for tests: 19.136523ms
Requests per second:  52.256096
Complete requests:    1
Failed requests:      0

2xx responses: 1

min: 16.496555ms
max: 16.496555ms
p50: 16.496555ms
p75: 16.496555ms
p90: 16.496555ms
p99: 16.496555ms

Skipping test Push Monolith 10MB
Skipping test Push Monolith 100MB
Skipping test Push Chunk Streamed 1MB
Skipping test Push Chunk Streamed 10MB
Skipping test Push Chunk Streamed 100MB
============
Test name:            Pull 1MB
Time taken for tests: 17.836719ms
Requests per second:  56.06412
Complete requests:    1
Failed requests:      0

2xx responses: 1

min: 3.774833ms
max: 3.774833ms
p50: 3.774833ms
p75: 3.774833ms
p90: 3.774833ms
p99: 3.774833ms

Skipping test Pull 10MB
Skipping test Pull 100MB
Skipping test Pull Mixed 20% 1MB, 70% 10MB, 10% 100MB
Skipping test Push Monolith Mixed 20% 1MB, 70% 10MB, 10% 100MB
Skipping test Push Chunk Mixed 33% 1MB, 33% 10MB, 33% 100MB
Skipping test Pull 75% and Push 25% Mixed 1MB
Skipping test Pull 75% and Push 25% Mixed 10MB
Skipping test Pull 75% and Push 25% Mixed 100MB
```

# References

[1] [https://github.com/opencontainers/distribution-spec/tree/main/conformance](https://github.com/opencontainers/distribution-spec/tree/main/conformance)
[2] [https://en.wikipedia.org/wiki/ApacheBench](https://en.wikipedia.org/wiki/ApacheBench)
