package storage

import (
	godigest "github.com/opencontainers/go-digest"
)

type Lint interface {
	Lint(repo string, manifestDigest godigest.Digest, imageStore ImageStore) (bool, error)
}
