package mocks

import (
	"context"

	"github.com/opencontainers/go-digest"
	"github.com/regclient/regclient/types/ref"
)

type SyncRemoteMock struct {
	// Methods required by sync Remote interface.
	GetHostNameFn       func() string
	GetRepositoriesFn   func(ctx context.Context) ([]string, error)
	GetTagsFn           func(ctx context.Context, repo string) ([]string, error)
	GetOCIDigestFn      func(ctx context.Context, repo, tag string) (digest.Digest, digest.Digest, bool, error)
	GetDigestFn         func(ctx context.Context, repo, tag string) (digest.Digest, error)
	GetImageReferenceFn func(repo string, tag string) (ref.Ref, error)
}

// Methods required by sync Remote interface.

func (remote SyncRemoteMock) GetHostName() string {
	if remote.GetHostNameFn != nil {
		return remote.GetHostNameFn()
	}

	return "mock-host"
}

func (remote SyncRemoteMock) GetRepositories(ctx context.Context) ([]string, error) {
	if remote.GetRepositoriesFn != nil {
		return remote.GetRepositoriesFn(ctx)
	}

	return []string{}, nil
}

func (remote SyncRemoteMock) GetTags(ctx context.Context, repo string) ([]string, error) {
	if remote.GetTagsFn != nil {
		return remote.GetTagsFn(ctx, repo)
	}

	return []string{}, nil
}

func (remote SyncRemoteMock) GetOCIDigest(ctx context.Context, repo, tag string) (
	digest.Digest, digest.Digest, bool, error,
) {
	if remote.GetOCIDigestFn != nil {
		return remote.GetOCIDigestFn(ctx, repo, tag)
	}

	return digest.Digest("sha256:abc123"), digest.Digest("sha256:def456"), false, nil
}

func (remote SyncRemoteMock) GetDigest(ctx context.Context, repo, tag string) (digest.Digest, error) {
	if remote.GetDigestFn != nil {
		return remote.GetDigestFn(ctx, repo, tag)
	}

	return digest.Digest("sha256:abc123"), nil
}

func (remote SyncRemoteMock) GetImageReference(repo string, tag string) (ref.Ref, error) {
	if remote.GetImageReferenceFn != nil {
		return remote.GetImageReferenceFn(repo, tag)
	}

	return ref.New("mock-registry/" + repo + ":" + tag)
}

type SyncDestinationMock struct {
	// Methods required by sync Destination interface.
	GetImageReferenceFn func(repo string, tag string) (ref.Ref, error)
	CanSkipImageFn      func(repo string, tag string, digest digest.Digest) (bool, error)
	CommitAllFn         func(repo string, imageReference ref.Ref) error
	CleanupImageFn      func(imageReference ref.Ref, repo string) error
}

// Methods required by sync Destination interface.

func (dest SyncDestinationMock) GetImageReference(repo string, tag string) (ref.Ref, error) {
	if dest.GetImageReferenceFn != nil {
		return dest.GetImageReferenceFn(repo, tag)
	}

	return ref.New("mock-local/" + repo + ":" + tag)
}

func (dest SyncDestinationMock) CanSkipImage(repo string, tag string, digest digest.Digest) (bool, error) {
	if dest.CanSkipImageFn != nil {
		return dest.CanSkipImageFn(repo, tag, digest)
	}

	return false, nil
}

func (dest SyncDestinationMock) CommitAll(repo string, imageReference ref.Ref) error {
	if dest.CommitAllFn != nil {
		return dest.CommitAllFn(repo, imageReference)
	}

	return nil
}

func (dest SyncDestinationMock) CleanupImage(imageReference ref.Ref, repo string) error {
	if dest.CleanupImageFn != nil {
		return dest.CleanupImageFn(imageReference, repo)
	}

	return nil
}
