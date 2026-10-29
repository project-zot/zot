// Package protectedtags compiles and evaluates storage tag protection rules.
package protectedtags

import (
	"errors"
	"fmt"
	"regexp"
	"strings"

	zreg "zotregistry.dev/zot/v2/pkg/regexp"
)

// ErrInvalidRule identifies invalid protected tag configuration.
var ErrInvalidRule = errors.New("invalid protected tag rule")

// Config describes the tag rules configured for one image store.
//
// Exact and wildcard rules are matched against the complete tag. Regex rules
// are also matched against the complete tag, regardless of whether the caller
// supplied anchors.
type Config struct {
	Exact    []string `json:"exact,omitempty"    mapstructure:"exact,omitempty"`
	Wildcard []string `json:"wildcard,omitempty" mapstructure:"wildcard,omitempty"`
	Regex    []string `json:"regex,omitempty"    mapstructure:"regex,omitempty"`
}

// Matcher is the compiled form of Config. A zero Matcher is disabled.
type Matcher struct {
	exact    map[string]struct{}
	wildcard []*regexp.Regexp
	regex    []*regexp.Regexp
}

// Compile validates and compiles tag protection rules.
func Compile(config Config) (*Matcher, error) {
	matcher := &Matcher{}

	if len(config.Exact) > 0 {
		matcher.exact = make(map[string]struct{}, len(config.Exact))
	}

	for _, tag := range config.Exact {
		if !zreg.IsDistributionSpecTag(tag) {
			return nil, fmt.Errorf("%w: invalid protected tag %q", ErrInvalidRule, tag)
		}

		matcher.exact[tag] = struct{}{}
	}

	for _, pattern := range config.Wildcard {
		compiled, err := compileWildcard(pattern)
		if err != nil {
			return nil, fmt.Errorf("invalid protected tag wildcard %q: %w", pattern, err)
		}

		matcher.wildcard = append(matcher.wildcard, compiled)
	}

	for _, pattern := range config.Regex {
		if pattern == "" {
			return nil, fmt.Errorf("%w: invalid protected tag regex: pattern is empty", ErrInvalidRule)
		}

		compiled, err := regexp.Compile("^(?:" + pattern + ")$")
		if err != nil {
			return nil, fmt.Errorf("invalid protected tag regex %q: %w", pattern, err)
		}

		matcher.regex = append(matcher.regex, compiled)
	}

	return matcher, nil
}

// Enabled reports whether at least one protection rule is configured.
func (matcher *Matcher) Enabled() bool {
	return matcher != nil && (len(matcher.exact) > 0 || len(matcher.wildcard) > 0 || len(matcher.regex) > 0)
}

// Matches reports whether tag is covered by any protection rule.
func (matcher *Matcher) Matches(tag string) bool {
	if matcher == nil {
		return false
	}

	if _, ok := matcher.exact[tag]; ok {
		return true
	}

	for _, pattern := range matcher.wildcard {
		if pattern.MatchString(tag) {
			return true
		}
	}

	for _, pattern := range matcher.regex {
		if pattern.MatchString(tag) {
			return true
		}
	}

	return false
}

func compileWildcard(pattern string) (*regexp.Regexp, error) {
	if pattern == "" {
		return nil, fmt.Errorf("%w: pattern is empty", ErrInvalidRule)
	}

	var expression strings.Builder
	expression.WriteString("^(?:")

	for _, character := range pattern {
		switch character {
		case '*':
			expression.WriteString(".*")
		case '?':
			expression.WriteByte('.')
		case 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',
			'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
			'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M',
			'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
			'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '_', '.', '-':
			expression.WriteString(regexp.QuoteMeta(string(character)))
		default:
			return nil, fmt.Errorf("%w: contains unsupported character %q", ErrInvalidRule, character)
		}
	}

	expression.WriteString(")$")

	return regexp.Compile(expression.String())
}
