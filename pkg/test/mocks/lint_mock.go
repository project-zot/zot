package mocks

import (
	ispec "github.com/opencontainers/image-spec/specs-go/v1"

	"zotregistry.io/zot/pkg/storage"
)

type MockedLint struct {
	LintFn func(repo string, manifestDescriptor ispec.Descriptor, imageStore storage.ImageStore) (bool, error)
}

func (lint MockedLint) Lint(repo string, manifestDescriptor ispec.Descriptor,
	imageStore storage.ImageStore,
) (bool, error) {
	if lint.LintFn != nil {
		return lint.LintFn(repo, manifestDescriptor, imageStore)
	}

	return false, nil
}
