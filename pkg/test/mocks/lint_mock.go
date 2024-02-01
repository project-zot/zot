package mocks

import (
	godigest "github.com/opencontainers/go-digest"

	storageTypes "zotregistry.dev/zot/pkg/storage/types"
)

type MockedLint struct {
	LintFn func(repo string, manifestDigest godigest.Digest, imageStore storageTypes.ImageStore) (bool, error)
}

func (lint MockedLint) Lint(repo string, manifestDigest godigest.Digest, imageStore storageTypes.ImageStore,
) (bool, error) {
	if lint.LintFn != nil {
		return lint.LintFn(repo, manifestDigest, imageStore)
	}

	return false, nil
}
