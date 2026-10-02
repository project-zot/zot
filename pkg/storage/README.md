`zot` currently supports two types of underlying filesystems:

1. **local** - a locally mounted filesystem

2. **remote** - a remote filesystem such as AWS S3

The cache database can be configured independently of storage. Right now, `zot` supports the following database implementations:

1. **BoltDB** - local storage. Set the "cloudCache" field in the config file to false. Example: examples/config-boltdb.json

## Driver error surfaces

Inventory of how local / S3 / GCS / Azure surface Stat, List, Walk, Get, and Delete failures (Missing vs Transient vs Permanent):

- Matrix: [errclass/driver-error-matrix.md](./errclass/driver-error-matrix.md)
- Sentinels: `zerr.ErrStorageMissing` / `ErrStorageTransient` / `ErrStoragePermanent` in `errors/`
- Wrappers: [`errclass`](./errclass/) (`MarkMissing` / `MarkTransient` / `MarkPermanent`)

### Tests

| Kind | Purpose | Where |
|------|---------|--------|
| Characterization | What distribution / OS / emulator returns | `{local,s3,gcs,azure}/upstream_driver_errors_test.go`; Azure also `azure_test.go` (Azurite) |
| Mapping | How zot `formatErr` maps those onto sentinels | `{s3,gcs,azure}/storage_error_mapping_test.go`; local `driver_internal_test.go` |
