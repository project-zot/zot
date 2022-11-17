package storage

import (
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
)

type Lint interface {
	Lint(repo string, manifestDescriptor ispec.Descriptor, imageStore ImageStore) (bool, error)
}
