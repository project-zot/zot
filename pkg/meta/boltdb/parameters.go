package boltdb

import (
	"path"
	"time"

	bolt "go.etcd.io/bbolt"
)

type DBParameters struct {
	RootDir string
}

func GetBoltDriver(params DBParameters) (*bolt.DB, error) {
	const perms = 0o600

	boltDB, err := bolt.Open(path.Join(params.RootDir, "meta.db"), perms, &bolt.Options{Timeout: time.Second * 10})
	if err != nil {
		return nil, err
	}

	return boltDB, nil
}
