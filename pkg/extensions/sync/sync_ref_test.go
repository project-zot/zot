//go:build sync
// +build sync

package sync

import (
	"context"
	"fmt"
	"testing"

	godigest "github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/regclient/regclient"
	"github.com/regclient/regclient/types/manifest"
	"github.com/regclient/regclient/types/platform"
	"github.com/regclient/regclient/types/ref"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	syncconf "zotregistry.dev/zot/pkg/extensions/config/sync"
	"zotregistry.dev/zot/pkg/log"
)

// Mock implementations for testing
type mockRemote struct {
	mock.Mock
}

func (m *mockRemote) GetImageReference(repo string, tag string) (ref.Ref, error) {
	args := m.Called(repo, tag)
	return args.Get(0).(ref.Ref), args.Error(1)
}

func (m *mockRemote) GetHostName() string {
	args := m.Called()
	return args.String(0)
}

func (m *mockRemote) GetRepositories(ctx context.Context) ([]string, error) {
	args := m.Called(ctx)
	return args.Get(0).([]string), args.Error(1)
}

func (m *mockRemote) GetTags(ctx context.Context, repo string) ([]string, error) {
	args := m.Called(ctx, repo)
	return args.Get(0).([]string), args.Error(1)
}

func (m *mockRemote) GetOCIDigest(ctx context.Context, repo, tag string) (godigest.Digest, godigest.Digest, bool, error) {
	args := m.Called(ctx, repo, tag)
	return args.Get(0).(godigest.Digest), args.Get(1).(godigest.Digest), args.Bool(2), args.Error(3)
}

func (m *mockRemote) GetDigest(ctx context.Context, repo, tag string) (godigest.Digest, error) {
	args := m.Called(ctx, repo, tag)
	return args.Get(0).(godigest.Digest), args.Error(1)
}

type mockDestination struct {
	mock.Mock
}

func (m *mockDestination) GetImageReference(repo string, tag string) (ref.Ref, error) {
	args := m.Called(repo, tag)
	return args.Get(0).(ref.Ref), args.Error(1)
}

func (m *mockDestination) CanSkipImage(repo string, tag string, digest godigest.Digest) (bool, error) {
	args := m.Called(repo, tag, digest)
	return args.Bool(0), args.Error(1)
}

func (m *mockDestination) CommitAll(repo string, imageReference ref.Ref) error {
	args := m.Called(repo, imageReference)
	return args.Error(0)
}

func (m *mockDestination) CleanupImage(imageReference ref.Ref, repo string) error {
	args := m.Called(imageReference, repo)
	return args.Error(0)
}

// Mock RegClient for testing
type mockRegClient struct {
	mock.Mock
}

func (m *mockRegClient) ManifestGet(ctx context.Context, r ref.Ref) (manifest.Manifest, error) {
	args := m.Called(ctx, r)
	return args.Get(0).(manifest.Manifest), args.Error(1)
}

func (m *mockRegClient) ImageCopy(ctx context.Context, src, dst ref.Ref, opts ...regclient.ImageOpts) error {
	// Convert from variadic to an array that can be captured by the mock
	args := m.Called(ctx, src, dst, opts)
	return args.Error(0)
}

func (m *mockRegClient) Close(ctx context.Context, r ref.Ref) error {
	args := m.Called(ctx, r)
	return args.Error(0)
}

// Mock manifest types for testing
type mockManifest struct {
	mock.Mock
	descriptor ispec.Descriptor
}

func (m *mockManifest) GetDescriptor() ispec.Descriptor {
	args := m.Called()
	if len(args) > 0 {
		return args.Get(0).(ispec.Descriptor)
	}
	return m.descriptor
}

type mockIndexManifest struct {
	mockManifest
	manifests []ispec.Descriptor
}

func (m *mockIndexManifest) GetManifestList() ([]ispec.Descriptor, error) {
	args := m.Called()
	if len(args) > 0 {
		return args.Get(0).([]ispec.Descriptor), args.Error(1)
	}
	return m.manifests, nil
}

// Setup function to create a service with the desired configuration
func setupServiceWithConfig(platforms []string) (*BaseService, *mockRemote, *mockDestination, *mockRegClient) {
	logger := log.NewLogger("debug", "")

	// Create configuration
	config := syncconf.RegistryConfig{
		Platforms: platforms,
	}

	// Create mocks
	mockRemote := new(mockRemote)
	mockDestination := new(mockDestination)
	mockRegClient := new(mockRegClient)

	// Create service
	service := &BaseService{
		config:      config,
		remote:      mockRemote,
		destination: mockDestination,
		rc:          mockRegClient,
		log:         logger,
	}

	return service, mockRemote, mockDestination, mockRegClient
}

// Helper function to create a mock manifest with a specific platform
func createSingleArchManifest(os, arch string) manifest.Manifest {
	descriptor := ispec.Descriptor{
		Platform: &ispec.Platform{
			OS:           os,
			Architecture: arch,
		},
	}

	mockMan := &mockManifest{
		descriptor: descriptor,
	}

	mockMan.On("GetDescriptor").Return(descriptor)

	return mockMan
}

// Helper function to create a mock multi-arch manifest with specified platforms
func createMultiArchManifest(platforms []platform.Platform) manifest.Manifest {
	descriptors := make([]ispec.Descriptor, len(platforms))

	for i, plat := range platforms {
		descriptors[i] = ispec.Descriptor{
			Platform: &ispec.Platform{
				OS:           plat.OS,
				Architecture: plat.Architecture,
				Variant:      plat.Variant,
				OSVersion:    plat.OSVersion,
				OSFeatures:   plat.OSFeatures,
			},
		}
	}

	indexMan := &mockIndexManifest{
		manifests: descriptors,
	}

	indexMan.On("GetManifestList").Return(descriptors, nil)

	// Make sure it satisfies the Indexer interface
	manifest.Indexer(indexMan)

	return indexMan
}

func TestSyncRefWithNoConfiguredPlatforms(t *testing.T) {
	// Create service with no platforms configured
	service, mockRemote, mockDestination, mockRegClient := setupServiceWithConfig([]string{})

	// Test context
	ctx := context.Background()
	localRepo := "test-repo"
	remoteRef := ref.Ref{
		Scheme:     "docker",
		Registry:   "remote-registry.com",
		Repository: "repo",
		Tag:        "latest",
	}
	localRef := ref.Ref{
		Scheme:     "docker",
		Registry:   "localhost",
		Repository: "test-repo",
		Tag:        "latest",
	}
	digest := godigest.FromString("test")

	// Setup expectation for CanSkipImage
	mockDestination.On("CanSkipImage", localRepo, "latest", digest).Return(false, nil)

	// Setup single-arch manifest
	manifest := createSingleArchManifest("linux", "amd64")
	mockRegClient.On("ManifestGet", ctx, remoteRef).Return(manifest, nil)

	// Expect ImageCopy to be called since no platforms are configured (should copy everything)
	mockRegClient.On("ImageCopy", ctx, remoteRef, localRef, mock.Anything).Return(nil)

	// Run the test
	err := service.syncRef(ctx, localRepo, remoteRef, localRef, digest, false)

	// Verify expectations
	assert.NoError(t, err)
	mockRegClient.AssertNumberOfCalls(t, "ImageCopy", 1)
	mockDestination.AssertCalled(t, "CanSkipImage", localRepo, "latest", digest)
}

func TestSyncRefWithArchitectureOnly(t *testing.T) {
	// Create service with only amd64 architecture configured
	service, _, mockDestination, mockRegClient := setupServiceWithConfig([]string{"amd64"})

	// Test context
	ctx := context.Background()
	localRepo := "test-repo"
	remoteRef := ref.Ref{
		Scheme:     "docker",
		Registry:   "remote-registry.com",
		Repository: "repo",
		Tag:        "latest",
	}
	localRef := ref.Ref{
		Scheme:     "docker",
		Registry:   "localhost",
		Repository: "test-repo",
		Tag:        "latest",
	}
	digest := godigest.FromString("test")

	// Setup expectation for CanSkipImage
	mockDestination.On("CanSkipImage", localRepo, "latest", digest).Return(false, nil)

	t.Run("MatchingArchitecture", func(t *testing.T) {
		// Create a single-arch manifest with matching architecture
		manifest := createSingleArchManifest("linux", "amd64")
		mockRegClient.On("ManifestGet", ctx, remoteRef).Return(manifest, nil).Once()

		// Expect ImageCopy to be called since the architecture matches
		mockRegClient.On("ImageCopy", ctx, remoteRef, localRef, mock.Anything).Return(nil).Once()

		// Run the test
		err := service.syncRef(ctx, localRepo, remoteRef, localRef, digest, false)

		// Verify expectations
		assert.NoError(t, err)
		mockRegClient.AssertCalled(t, "ImageCopy", ctx, remoteRef, localRef, mock.Anything)
	})

	t.Run("NonMatchingArchitecture", func(t *testing.T) {
		// Create a single-arch manifest with non-matching architecture
		manifest := createSingleArchManifest("linux", "arm64")
		mockRegClient.On("ManifestGet", ctx, remoteRef).Return(manifest, nil).Once()

		// ImageCopy should not be called since the architecture doesn't match

		// Run the test
		err := service.syncRef(ctx, localRepo, remoteRef, localRef, digest, false)

		// Verify expectations
		assert.NoError(t, err)
		// Check that ImageCopy was NOT called again
		mockRegClient.AssertNumberOfCalls(t, "ImageCopy", 1) // Still 1 from the previous subtest
	})
}

func TestSyncRefWithFullPlatform(t *testing.T) {
	// Create service with full platform specification
	service, _, mockDestination, mockRegClient := setupServiceWithConfig([]string{"linux/amd64"})

	// Test context
	ctx := context.Background()
	localRepo := "test-repo"
	remoteRef := ref.Ref{
		Scheme:     "docker",
		Registry:   "remote-registry.com",
		Repository: "repo",
		Tag:        "latest",
	}
	localRef := ref.Ref{
		Scheme:     "docker",
		Registry:   "localhost",
		Repository: "test-repo",
		Tag:        "latest",
	}
	digest := godigest.FromString("test")

	// Setup expectation for CanSkipImage
	mockDestination.On("CanSkipImage", localRepo, "latest", digest).Return(false, nil)

	t.Run("MatchingPlatform", func(t *testing.T) {
		// Create a single-arch manifest with matching platform
		manifest := createSingleArchManifest("linux", "amd64")
		mockRegClient.On("ManifestGet", ctx, remoteRef).Return(manifest, nil).Once()

		// Expect ImageCopy to be called since the platform matches
		mockRegClient.On("ImageCopy", ctx, remoteRef, localRef, mock.Anything).Return(nil).Once()

		// Run the test
		err := service.syncRef(ctx, localRepo, remoteRef, localRef, digest, false)

		// Verify expectations
		assert.NoError(t, err)
		mockRegClient.AssertCalled(t, "ImageCopy", ctx, remoteRef, localRef, mock.Anything)
	})

	t.Run("MatchingArchDifferentOS", func(t *testing.T) {
		// Create a single-arch manifest with matching arch but different OS
		manifest := createSingleArchManifest("windows", "amd64")
		mockRegClient.On("ManifestGet", ctx, remoteRef).Return(manifest, nil).Once()

		// ImageCopy should not be called since the OS doesn't match

		// Run the test
		err := service.syncRef(ctx, localRepo, remoteRef, localRef, digest, false)

		// Verify expectations
		assert.NoError(t, err)
		// Check that ImageCopy was NOT called again
		mockRegClient.AssertNumberOfCalls(t, "ImageCopy", 1) // Still 1 from the previous subtest
	})

	t.Run("NonMatchingPlatform", func(t *testing.T) {
		// Create a single-arch manifest with non-matching platform
		manifest := createSingleArchManifest("linux", "arm64")
		mockRegClient.On("ManifestGet", ctx, remoteRef).Return(manifest, nil).Once()

		// ImageCopy should not be called since the platform doesn't match

		// Run the test
		err := service.syncRef(ctx, localRepo, remoteRef, localRef, digest, false)

		// Verify expectations
		assert.NoError(t, err)
		// Check that ImageCopy was NOT called again
		mockRegClient.AssertNumberOfCalls(t, "ImageCopy", 1) // Still 1 from the previous subtest
	})
}

func TestSyncRefWithMultiplePlatforms(t *testing.T) {
	// Create service with multiple platforms
	service, _, mockDestination, mockRegClient := setupServiceWithConfig([]string{"amd64", "linux/arm64"})

	// Test context
	ctx := context.Background()
	localRepo := "test-repo"
	remoteRef := ref.Ref{
		Scheme:     "docker",
		Registry:   "remote-registry.com",
		Repository: "repo",
		Tag:        "latest",
	}
	localRef := ref.Ref{
		Scheme:     "docker",
		Registry:   "localhost",
		Repository: "test-repo",
		Tag:        "latest",
	}
	digest := godigest.FromString("test")

	// Setup expectation for CanSkipImage
	mockDestination.On("CanSkipImage", localRepo, "latest", digest).Return(false, nil)

	t.Run("AnyOSWithAMD64", func(t *testing.T) {
		// Create a single-arch manifest with amd64 on Windows (should be included)
		manifest := createSingleArchManifest("windows", "amd64")
		mockRegClient.On("ManifestGet", ctx, remoteRef).Return(manifest, nil).Once()

		// Expect ImageCopy to be called since amd64 matches regardless of OS
		mockRegClient.On("ImageCopy", ctx, remoteRef, localRef, mock.Anything).Return(nil).Once()

		// Run the test
		err := service.syncRef(ctx, localRepo, remoteRef, localRef, digest, false)

		// Verify expectations
		assert.NoError(t, err)
		mockRegClient.AssertCalled(t, "ImageCopy", ctx, remoteRef, localRef, mock.Anything)
	})

	t.Run("LinuxARM64", func(t *testing.T) {
		// Create a single-arch manifest with Linux/arm64 (should be included)
		manifest := createSingleArchManifest("linux", "arm64")
		mockRegClient.On("ManifestGet", ctx, remoteRef).Return(manifest, nil).Once()

		// Expect ImageCopy to be called since linux/arm64 matches
		mockRegClient.On("ImageCopy", ctx, remoteRef, localRef, mock.Anything).Return(nil).Once()

		// Run the test
		err := service.syncRef(ctx, localRepo, remoteRef, localRef, digest, false)

		// Verify expectations
		assert.NoError(t, err)
		mockRegClient.AssertCalled(t, "ImageCopy", ctx, remoteRef, localRef, mock.Anything)
		mockRegClient.AssertNumberOfCalls(t, "ImageCopy", 2) // Now 2 calls total
	})

	t.Run("WindowsARM64", func(t *testing.T) {
		// Create a single-arch manifest with Windows/arm64 (should be excluded)
		manifest := createSingleArchManifest("windows", "arm64")
		mockRegClient.On("ManifestGet", ctx, remoteRef).Return(manifest, nil).Once()

		// ImageCopy should not be called since only linux/arm64 matches, not windows/arm64

		// Run the test
		err := service.syncRef(ctx, localRepo, remoteRef, localRef, digest, false)

		// Verify expectations
		assert.NoError(t, err)
		// Check that ImageCopy was NOT called again
		mockRegClient.AssertNumberOfCalls(t, "ImageCopy", 2) // Still 2 from previous subtests
	})
}

func TestSyncRefWithMultiArchImage(t *testing.T) {
	// Various platform configurations to test
	testCases := []struct {
		name            string
		configPlatforms []string
		platforms       []platform.Platform
		expectedCalls   int
	}{
		{
			name:            "NoFilteringConfigured",
			configPlatforms: []string{},
			platforms: []platform.Platform{
				{OS: "linux", Architecture: "amd64"},
				{OS: "linux", Architecture: "arm64"},
				{OS: "windows", Architecture: "amd64"},
			},
			expectedCalls: 1, // Should copy the whole manifest list
		},
		{
			name:            "SingleArchFilter",
			configPlatforms: []string{"amd64"},
			platforms: []platform.Platform{
				{OS: "linux", Architecture: "amd64"},
				{OS: "linux", Architecture: "arm64"},
				{OS: "windows", Architecture: "amd64"},
			},
			expectedCalls: 1, // Should still copy once and filtering happens in destination
		},
		{
			name:            "FullPlatformFilter",
			configPlatforms: []string{"linux/amd64"},
			platforms: []platform.Platform{
				{OS: "linux", Architecture: "amd64"},
				{OS: "linux", Architecture: "arm64"},
				{OS: "windows", Architecture: "amd64"},
			},
			expectedCalls: 1, // Should still copy once and filtering happens in destination
		},
		{
			name:            "MultiplePlatformFilter",
			configPlatforms: []string{"linux/amd64", "linux/arm64"},
			platforms: []platform.Platform{
				{OS: "linux", Architecture: "amd64"},
				{OS: "linux", Architecture: "arm64"},
				{OS: "windows", Architecture: "amd64"},
			},
			expectedCalls: 1, // Should still copy once and filtering happens in destination
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create service with the configured platforms
			service, _, mockDestination, mockRegClient := setupServiceWithConfig(tc.configPlatforms)

			// Test context
			ctx := context.Background()
			localRepo := "test-repo"
			remoteRef := ref.Ref{
				Scheme:     "docker",
				Registry:   "remote-registry.com",
				Repository: "repo",
				Tag:        "latest",
			}
			localRef := ref.Ref{
				Scheme:     "docker",
				Registry:   "localhost",
				Repository: "test-repo",
				Tag:        "latest",
			}
			digest := godigest.FromString("test")

			// Setup expectation for CanSkipImage
			mockDestination.On("CanSkipImage", localRepo, "latest", digest).Return(false, nil).Once()

			// Create a multi-arch manifest
			manifest := createMultiArchManifest(tc.platforms)
			mockRegClient.On("ManifestGet", ctx, remoteRef).Return(manifest, nil).Once()

			// Expect ImageCopy to be called
			mockRegClient.On("ImageCopy", ctx, remoteRef, localRef, mock.Anything).Return(nil).Once()

			// Run the test
			err := service.syncRef(ctx, localRepo, remoteRef, localRef, digest, false)

			// Verify expectations
			assert.NoError(t, err)
			mockRegClient.AssertNumberOfCalls(t, "ImageCopy", tc.expectedCalls)
		})
	}
}

func TestSyncRefWithImageAlreadySynced(t *testing.T) {
	// Create service with no platforms configured
	service, _, mockDestination, mockRegClient := setupServiceWithConfig([]string{})

	// Test context
	ctx := context.Background()
	localRepo := "test-repo"
	remoteRef := ref.Ref{
		Scheme:     "docker",
		Registry:   "remote-registry.com",
		Repository: "repo",
		Tag:        "latest",
	}
	localRef := ref.Ref{
		Scheme:     "docker",
		Registry:   "localhost",
		Repository: "test-repo",
		Tag:        "latest",
	}
	digest := godigest.FromString("test")

	// Setup expectation for CanSkipImage - return true to indicate image already synced
	mockDestination.On("CanSkipImage", localRepo, "latest", digest).Return(true, nil)

	// ManifestGet and ImageCopy should not be called

	// Run the test
	err := service.syncRef(ctx, localRepo, remoteRef, localRef, digest, false)

	// Verify expectations
	assert.NoError(t, err)
	mockRegClient.AssertNotCalled(t, "ManifestGet")
	mockRegClient.AssertNotCalled(t, "ImageCopy")
}

func TestSyncRefCanSkipImageError(t *testing.T) {
	// Create service with no platforms configured
	service, _, mockDestination, _ := setupServiceWithConfig([]string{})

	// Test context
	ctx := context.Background()
	localRepo := "test-repo"
	remoteRef := ref.Ref{
		Scheme:     "docker",
		Registry:   "remote-registry.com",
		Repository: "repo",
		Tag:        "latest",
	}
	localRef := ref.Ref{
		Scheme:     "docker",
		Registry:   "localhost",
		Repository: "test-repo",
		Tag:        "latest",
	}
	digest := godigest.FromString("test")

	// Setup expectation for CanSkipImage - return error
	testError := fmt.Errorf("test error")
	mockDestination.On("CanSkipImage", localRepo, "latest", digest).Return(false, testError)

	// Run the test
	err := service.syncRef(ctx, localRepo, remoteRef, localRef, digest, false)

	// Verify expectations
	assert.Equal(t, testError, err)
}
