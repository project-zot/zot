//go:build sync
// +build sync

package sync

import (
	"testing"

	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	syncconf "zotregistry.dev/zot/pkg/extensions/config/sync"
	"zotregistry.dev/zot/pkg/log"
)

func TestShouldIncludePlatform(t *testing.T) {
	logger := log.NewLogger("debug", "")

	// Test case 1: When no platforms are configured (should return true)
	t.Run("NoPlatformsConfigured", func(t *testing.T) {
		service := &BaseService{
			config: syncconf.RegistryConfig{
				Platforms: []string{},
			},
			log: logger,
		}

		platform := &ispec.Platform{
			Architecture: "amd64",
			OS:           "linux",
		}

		if !service.shouldIncludePlatform(platform) {
			t.Errorf("Expected shouldIncludePlatform to return true when no platforms configured, got false")
		}
	})

	// Test case 2: When the platform is nil (should return true)
	t.Run("NilPlatform", func(t *testing.T) {
		service := &BaseService{
			config: syncconf.RegistryConfig{
				Platforms: []string{"linux/amd64", "arm64"},
			},
			log: logger,
		}

		if !service.shouldIncludePlatform(nil) {
			t.Errorf("Expected shouldIncludePlatform to return true for nil platform, got false")
		}
	})

	// Test case 3: When the platform matches an OS/arch combination in the config
	t.Run("MatchesOSAndArch", func(t *testing.T) {
		service := &BaseService{
			config: syncconf.RegistryConfig{
				Platforms: []string{"linux/amd64", "linux/arm64"},
			},
			log: logger,
		}

		platform := &ispec.Platform{
			Architecture: "amd64",
			OS:           "linux",
		}

		if !service.shouldIncludePlatform(platform) {
			t.Errorf("Expected shouldIncludePlatform to return true for matching OS/arch, got false")
		}

		// Should not match when OS is different
		platform.OS = "windows"
		if service.shouldIncludePlatform(platform) {
			t.Errorf("Expected shouldIncludePlatform to return false for non-matching OS, got true")
		}
	})

	// Test case 4: When the platform matches just an architecture in the config
	t.Run("MatchesArchOnly", func(t *testing.T) {
		service := &BaseService{
			config: syncconf.RegistryConfig{
				Platforms: []string{"amd64", "linux/arm64"},
			},
			log: logger,
		}

		// Should match any OS with amd64 architecture
		platform := &ispec.Platform{
			Architecture: "amd64",
			OS:           "linux",
		}
		if !service.shouldIncludePlatform(platform) {
			t.Errorf("Expected shouldIncludePlatform to return true for matching arch-only, got false")
		}

		platform.OS = "windows"
		if !service.shouldIncludePlatform(platform) {
			t.Errorf("Expected shouldIncludePlatform to return true for matching arch-only with different OS, got false")
		}

		// Should match specific OS/arch combo
		platform = &ispec.Platform{
			Architecture: "arm64",
			OS:           "linux",
		}
		if !service.shouldIncludePlatform(platform) {
			t.Errorf("Expected shouldIncludePlatform to return true for matching OS/arch, got false")
		}

		// Should not match when OS is different from specified OS/arch
		platform.OS = "windows"
		if service.shouldIncludePlatform(platform) {
			t.Errorf("Expected shouldIncludePlatform to return false for non-matching OS, got true")
		}
	})

	// Test case 5: When the platform doesn't match any of the configured platforms
	t.Run("NoMatches", func(t *testing.T) {
		service := &BaseService{
			config: syncconf.RegistryConfig{
				Platforms: []string{"linux/amd64", "linux/arm64"},
			},
			log: logger,
		}

		platform := &ispec.Platform{
			Architecture: "ppc64le",
			OS:           "linux",
		}

		if service.shouldIncludePlatform(platform) {
			t.Errorf("Expected shouldIncludePlatform to return false for non-matching platform, got true")
		}
	})

	// Test case 6: Empty OS in platform specification
	t.Run("EmptyOSInConfig", func(t *testing.T) {
		service := &BaseService{
			config: syncconf.RegistryConfig{
				Platforms: []string{"/amd64"}, // This is an edge case with empty OS
			},
			log: logger,
		}

		platform := &ispec.Platform{
			Architecture: "amd64",
			OS:           "linux",
		}

		if !service.shouldIncludePlatform(platform) {
			t.Errorf("Expected shouldIncludePlatform to return true for matching arch with empty OS, got false")
		}
	})

	// Test case 7: Mixed format platforms (OS/arch and arch-only)
	t.Run("MixedFormatPlatforms", func(t *testing.T) {
		service := &BaseService{
			config: syncconf.RegistryConfig{
				Platforms: []string{"amd64", "linux/arm64"},
			},
			log: logger,
		}

		// Should match amd64 arch on any OS
		platform := &ispec.Platform{
			Architecture: "amd64",
			OS:           "windows",
		}
		if !service.shouldIncludePlatform(platform) {
			t.Errorf("Expected shouldIncludePlatform to return true for matching arch-only, got false")
		}

		// Should match linux/arm64 combo
		platform = &ispec.Platform{
			Architecture: "arm64",
			OS:           "linux",
		}
		if !service.shouldIncludePlatform(platform) {
			t.Errorf("Expected shouldIncludePlatform to return true for matching OS/arch, got false")
		}

		// Should not match non-linux arm64
		platform = &ispec.Platform{
			Architecture: "arm64",
			OS:           "windows",
		}
		if service.shouldIncludePlatform(platform) {
			t.Errorf("Expected shouldIncludePlatform to return false for non-matching OS with arm64, got true")
		}
	})
}

func TestShouldIncludeArchitecture(t *testing.T) {
	logger := log.NewLogger("debug", "")

	// Test case 1: When no platforms are configured (should return true)
	t.Run("NoPlatformsConfigured", func(t *testing.T) {
		service := &BaseService{
			config: syncconf.RegistryConfig{
				Platforms: []string{},
			},
			log: logger,
		}

		if !service.shouldIncludeArchitecture("amd64") {
			t.Errorf("Expected shouldIncludeArchitecture to return true when no platforms configured, got false")
		}
	})

	// Test case 2: When the architecture matches one in the config (platform format)
	t.Run("MatchingArchInPlatform", func(t *testing.T) {
		service := &BaseService{
			config: syncconf.RegistryConfig{
				Platforms: []string{"linux/amd64", "arm64"},
			},
			log: logger,
		}

		if !service.shouldIncludeArchitecture("amd64") {
			t.Errorf("Expected shouldIncludeArchitecture to return true for matching arch, got false")
		}
	})

	// Test case 3: When the architecture matches one in the config (arch-only format)
	t.Run("MatchingArchOnly", func(t *testing.T) {
		service := &BaseService{
			config: syncconf.RegistryConfig{
				Platforms: []string{"amd64", "linux/arm64"},
			},
			log: logger,
		}

		if !service.shouldIncludeArchitecture("amd64") {
			t.Errorf("Expected shouldIncludeArchitecture to return true for matching arch-only, got false")
		}

		if !service.shouldIncludeArchitecture("arm64") {
			t.Errorf("Expected shouldIncludeArchitecture to return true for matching arch in OS/arch, got false")
		}
	})

	// Test case 4: When the architecture doesn't match any in the config
	t.Run("NonMatchingArch", func(t *testing.T) {
		service := &BaseService{
			config: syncconf.RegistryConfig{
				Platforms: []string{"linux/amd64", "arm64"},
			},
			log: logger,
		}

		if service.shouldIncludeArchitecture("ppc64le") {
			t.Errorf("Expected shouldIncludeArchitecture to return false for non-matching arch, got true")
		}
	})

	// Test case 5: Verify that shouldIncludeArchitecture delegates to shouldIncludePlatform
	t.Run("DelegatesToShouldIncludePlatform", func(t *testing.T) {
		service := &BaseService{
			config: syncconf.RegistryConfig{
				Platforms: []string{"linux/amd64", "arm64"},
			},
			log: logger,
		}

		// Create platform equivalent of architecture
		arch := "amd64"
		platform := &ispec.Platform{
			Architecture: arch,
		}

		// Results from both functions should match
		includeArch := service.shouldIncludeArchitecture(arch)
		includePlatform := service.shouldIncludePlatform(platform)

		if includeArch != includePlatform {
			t.Errorf("Expected shouldIncludeArchitecture to delegate to shouldIncludePlatform, got different results")
		}
	})
}
