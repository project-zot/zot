package mocks

import (
	"context"

	"github.com/containers/image/v5/types"
	"github.com/opencontainers/go-digest"
)

type SyncRemote struct {
	// Get temporary ImageReference, is used by functions in containers/image package
	GetImageReferenceFn func(repo string, tag string) (types.ImageReference, error)

	// Get local oci layout context, is used by functions in containers/image package
	GetContextFn func() *types.SystemContext

	// Get a list of repos (catalog)
	GetRepositoriesFn func(ctx context.Context) ([]string, error)

	// Get a list of tags given a repo
	GetRepoTagsFn func(repo string) ([]string, error)

	GetDockerRemoteRepoFn func(repo string) string

	// Get manifest content, mediaType, digest given an ImageReference
	GetManifestContentFn func(imageReference types.ImageReference) ([]byte, string, digest.Digest, error)
}

func (remote SyncRemote) GetDockerRemoteRepo(repo string) string {
	if remote.GetDockerRemoteRepoFn != nil {
		return remote.GetDockerRemoteRepoFn(repo)
	}

	return ""
}

func (remote SyncRemote) GetImageReference(repo string, tag string) (types.ImageReference, error) {
	if remote.GetImageReferenceFn != nil {
		return remote.GetImageReferenceFn(repo, tag)
	}

	return nil, nil
}

func (remote SyncRemote) GetContext() *types.SystemContext {
	if remote.GetContextFn != nil {
		return remote.GetContextFn()
	}

	return nil
}

func (remote SyncRemote) GetRepositories(ctx context.Context) ([]string, error) {
	if remote.GetRepositoriesFn != nil {
		return remote.GetRepositoriesFn(ctx)
	}

	return []string{}, nil
}

func (remote SyncRemote) GetRepoTags(repo string) ([]string, error) {
	if remote.GetRepoTagsFn != nil {
		return remote.GetRepoTagsFn(repo)
	}

	return []string{}, nil
}

func (remote SyncRemote) GetManifestContent(imageReference types.ImageReference) (
	[]byte, string, digest.Digest, error,
) {
	if remote.GetManifestContentFn != nil {
		return remote.GetManifestContentFn(imageReference)
	}

	return nil, "", "", nil
}
