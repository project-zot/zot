//go:build sync

package sync

import (
	"testing"

	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/assert"
)

func TestParsePlatform(t *testing.T) {
	tests := []struct {
		name           string
		platformString string
		expected       Platform
	}{
		{
			name:           "OS/arch format",
			platformString: "linux/amd64",
			expected: Platform{
				OS:           "linux",
				Architecture: "amd64",
			},
		},
		{
			name:           "arch-only format",
			platformString: "arm64",
			expected: Platform{
				OS:           "",
				Architecture: "arm64",
			},
		},
		{
			name:           "empty string",
			platformString: "",
			expected: Platform{
				OS:           "",
				Architecture: "",
			},
		},
		{
			name:           "OS with slash but no arch",
			platformString: "linux/",
			expected: Platform{
				OS:           "linux",
				Architecture: "",
			},
		},
		{
			name:           "slash but no OS",
			platformString: "/amd64",
			expected: Platform{
				OS:           "",
				Architecture: "amd64",
			},
		},
		{
			name:           "multiple slashes",
			platformString: "linux/amd64/v8",
			expected: Platform{
				OS:           "",
				Architecture: "linux/amd64/v8",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := ParsePlatform(test.platformString)
			assert.Equal(t, test.expected, result)
		})
	}
}

func TestMatchesPlatform(t *testing.T) {
	tests := []struct {
		name          string
		platform      *ispec.Platform
		platformSpecs []string
		expected      bool
	}{
		{
			name:          "nil platform",
			platform:      nil,
			platformSpecs: []string{"linux/amd64", "linux/arm64"},
			expected:      true,
		},
		{
			name: "empty platform specs",
			platform: &ispec.Platform{
				OS:           "linux",
				Architecture: "amd64",
			},
			platformSpecs: []string{},
			expected:      true,
		},
		{
			name: "exact OS/arch match",
			platform: &ispec.Platform{
				OS:           "linux",
				Architecture: "amd64",
			},
			platformSpecs: []string{"linux/amd64"},
			expected:      true,
		},
		{
			name: "exact OS/arch non-match",
			platform: &ispec.Platform{
				OS:           "linux",
				Architecture: "amd64",
			},
			platformSpecs: []string{"linux/arm64"},
			expected:      false,
		},
		{
			name: "arch-only match",
			platform: &ispec.Platform{
				OS:           "linux",
				Architecture: "amd64",
			},
			platformSpecs: []string{"amd64"},
			expected:      true,
		},
		{
			name: "arch-only non-match",
			platform: &ispec.Platform{
				OS:           "linux",
				Architecture: "amd64",
			},
			platformSpecs: []string{"arm64"},
			expected:      false,
		},
		{
			name: "OS/arch and non-matching OS",
			platform: &ispec.Platform{
				OS:           "windows",
				Architecture: "amd64",
			},
			platformSpecs: []string{"linux/amd64"},
			expected:      false,
		},
		{
			name: "multiple specs with match",
			platform: &ispec.Platform{
				OS:           "linux",
				Architecture: "amd64",
			},
			platformSpecs: []string{"windows/amd64", "linux/arm64", "linux/amd64"},
			expected:      true,
		},
		{
			name: "multiple specs with no match",
			platform: &ispec.Platform{
				OS:           "darwin",
				Architecture: "arm64",
			},
			platformSpecs: []string{"windows/amd64", "linux/arm64", "linux/amd64"},
			expected:      false,
		},
		{
			name: "match with empty OS in spec",
			platform: &ispec.Platform{
				OS:           "linux",
				Architecture: "arm64",
			},
			platformSpecs: []string{"/arm64"},
			expected:      true,
		},
		{
			name: "match with empty architecture in spec",
			platform: &ispec.Platform{
				OS:           "linux",
				Architecture: "",
			},
			platformSpecs: []string{"linux/"},
			expected:      true,
		},
		{
			name: "match with both arch-only and OS/arch formats",
			platform: &ispec.Platform{
				OS:           "linux",
				Architecture: "amd64",
			},
			platformSpecs: []string{"arm64", "linux/amd64"},
			expected:      true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := MatchesPlatform(test.platform, test.platformSpecs)
			assert.Equal(t, test.expected, result)
		})
	}
}
