package regexp_test

import (
	"strings"
	"testing"

	zreg "zotregistry.dev/zot/v2/pkg/regexp"
)

func TestIsDistributionSpecTag(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name  string
		tag   string
		valid bool
	}{
		{"empty", "", false},
		{"latest", "latest", true},
		{"with dots", "v1.0.0", true},
		{"with hyphen", "meta-a", true},
		{"with underscore", "my_tag", true},
		{"max length", strings.Repeat("a", zreg.TagMaxLen), true},
		{"too long", strings.Repeat("a", zreg.TagMaxLen+1), false},
		{"slash", "bad/ref", false},
		{"leading dot", ".bad", false},
		{"colon", "bad:tag", false},
		{"space", "bad tag", false},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			got := zreg.IsDistributionSpecTag(testCase.tag)
			if got != testCase.valid {
				t.Fatalf("IsDistributionSpecTag(%q) = %v, want %v", testCase.tag, got, testCase.valid)
			}
		})
	}
}
