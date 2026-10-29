package retention

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRegexMatcherSkipsInvalidAndEmpty(t *testing.T) {
	matcher := NewRegexMatcher()

	require.True(t, matcher.MatchesListOfRegex("v1.0", nil))
	require.False(t, matcher.MatchesListOfRegex("v1.0", []string{"("}))
	require.True(t, matcher.MatchesListOfRegex("v1.0", []string{"(", "^v1\\."}))
	require.False(t, matcher.MatchesListOfRegex("latest", []string{"(", "^v1\\."}))
}
