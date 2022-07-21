`zot` currently supports two types of underlying filesystems:

1. **local** - a locally mounted filesystem

2. **remote** - a remote filesystem such as AWS S3

The cache database can be configured independently of storage. Right now, `zot` supports the following database implementations:

1. **BoltDB** - local storage. Set the "cloudCache" field in the config file to false. Example: examples/config-boltdb.json
