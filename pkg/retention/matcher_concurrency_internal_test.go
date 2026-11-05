package retention

import (
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRegexMatcherConcurrentUse(t *testing.T) {
	matcher := NewRegexMatcher()
	regexes := []string{"^v[0-9]+$", "^release-.*", "^nightly-[0-9]{8}$", "^sha256-.*\\.sig$"}

	var wg sync.WaitGroup

	for worker := range 16 {
		wg.Add(1)

		go func() {
			defer wg.Done()

			for i := range 200 {
				name := "v1"
				if (worker+i)%2 == 0 {
					name = "release-" + string(rune('a'+i%26))
				}

				require.True(t, matcher.MatchesListOfRegex(name, regexes))
				require.False(t, matcher.MatchesListOfRegex("unmatched", regexes))
			}
		}()
	}

	wg.Wait()
}
