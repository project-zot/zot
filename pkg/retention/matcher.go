package retention

import "regexp"

type RegexMatcher struct {
	compiled map[string]*regexp.Regexp
}

func NewRegexMatcher() *RegexMatcher {
	return &RegexMatcher{
		make(map[string]*regexp.Regexp, 0),
	}
}

// MatchesListOfRegex is used by retention, it return true if list of regexes is empty.
func (r *RegexMatcher) MatchesListOfRegex(name string, regexes []string) bool {
	if len(regexes) == 0 {
		// empty regexes matches everything in retention logic
		return true
	}

	for _, regex := range regexes {
		if tagReg, ok := r.compiled[regex]; ok {
			if tagReg.MatchString(name) {
				return true
			}
		} else {
			// all are compilable because they are checked at startup
			if tagReg, err := regexp.Compile(regex); err == nil {
				r.compiled[regex] = tagReg
				if tagReg.MatchString(name) {
					return true
				}
			}
		}
	}

	return false
}
