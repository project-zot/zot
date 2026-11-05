package retention

import (
	"regexp"
	"sync"
)

// RegexMatcher caches compiled regexes. It is shared by every GC scan of a store and scans
// run concurrently, so the cache is guarded.
type RegexMatcher struct {
	mu       sync.RWMutex
	compiled map[string]*regexp.Regexp
}

func NewRegexMatcher() *RegexMatcher {
	return &RegexMatcher{
		compiled: make(map[string]*regexp.Regexp, 0),
	}
}

// MatchesListOfRegex is used by retention, it return true if list of regexes is empty.
func (r *RegexMatcher) MatchesListOfRegex(name string, regexes []string) bool {
	if len(regexes) == 0 {
		// empty regexes matches everything in retention logic
		return true
	}

	for _, regex := range regexes {
		tagReg, ok := r.lookup(regex)
		if !ok {
			var err error
			// all are compilable because they are checked at startup
			if tagReg, err = regexp.Compile(regex); err != nil {
				continue
			}

			r.store(regex, tagReg)
		}

		if tagReg.MatchString(name) {
			return true
		}
	}

	return false
}

func (r *RegexMatcher) lookup(regex string) (*regexp.Regexp, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	tagReg, ok := r.compiled[regex]

	return tagReg, ok
}

func (r *RegexMatcher) store(regex string, tagReg *regexp.Regexp) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.compiled[regex] = tagReg
}
