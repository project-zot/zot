package mocks

import (
	godigest "github.com/opencontainers/go-digest"
	"zotregistry.io/zot/pkg/storage"
)

type MockedLint struct {
	LintFn func(repo string, manifestDigest godigest.Digest, imageStore storage.ImageStore) (bool, error)
}

func (lint MockedLint) Lint(repo string, manifestDigest godigest.Digest, imageStore storage.ImageStore) (bool, error) {
	if lint.LintFn != nil {
		return lint.LintFn(repo, manifestDigest, imageStore)
	}

	return false, nil
}
