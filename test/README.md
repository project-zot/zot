# BATS Port Allocations

The `ports.json` file in this directory tracks the port ranges provided for each BATS test that runs concurrently to avoid overlaps.
IANA registered ports range - 1024 to 49151

## Adding a new BATS Test file

For the range, use a gap of 10 ports (e.g. 9000 to 9009) and leave a gap of 10 ports between the new range and the last range.

Avoid ranges in the 4000, 8000, and 10000 series as these may overlap with other services such as localstack, fixed port zot, and clustered zot.

For a new BATS test file, add a new entry to `ports.json` as follows:

replace `TEST_DIR` with just the directory name of the directory containing your test file.
replace `FILENAME` with the name of the test file along with its extension e.g. `new_test.bats`

```json
"TEST_DIR/FILENAME": {
  "svc1": {
    "begin": 20020,
    "end": 20029
  },
  "svc2": {
    "begin": 20040,
    "end": 20049
  }
}
```

A test file may have multiple services defined by a unique key. You can use any key for the service identifier, however, ensure that the same key is used in the BATS test file as an argument to the `get_free_port_for_service` function.
