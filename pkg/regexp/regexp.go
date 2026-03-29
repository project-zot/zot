package regexp

import (
	"fmt"
	"regexp"
	"strings"
)

// TagMaxLen is the maximum length of a manifest tag in the OCI Distribution Specification
// (opencontainers/distribution-spec spec.md, "Pulling manifests").
const TagMaxLen = 128

//nolint:gochecknoglobals
var (
	// alphaNumericRegexp defines the alpha numeric atom, typically a
	// component of names. This only allows lower case characters and digits.
	alphaNumericRegexp = match(`[a-z0-9]+`)

	// separatorRegexp defines the separators allowed to be embedded in name
	// components. This allow one period, one or two underscore and multiple
	// dashes.
	separatorRegexp = match(`(?:[._]|__|[-]*)`)

	// nameComponentRegexp restricts registry path component names to start
	// with at least one letter or number, with following parts able to be
	// separated by one period, one or two underscore and multiple dashes.
	nameComponentRegexp = expression(
		alphaNumericRegexp,
		optional(repeated(separatorRegexp, alphaNumericRegexp)))

	// NameRegexp is the format for the name component of references. The
	// regexp has capturing groups for the domain and name part omitting
	// the separating forward slash from either.
	NameRegexp = expression(
		nameComponentRegexp,
		optional(repeated(literal(`/`), nameComponentRegexp)))

	// FullNameRegexp is the format which matches the full string of the
	// name component of reference.
	FullNameRegexp = expression(match("^"), NameRegexp, match("$"))

	// TagRegexp matches a manifest tag per the OCI Distribution Specification
	// (opencontainers/distribution-spec spec.md, "Pulling manifests"): a tag MUST be at most
	// TagMaxLen characters and MUST match
	// [a-zA-Z0-9_][a-zA-Z0-9._-]* with the suffix length bounded by TagMaxLen (anchored).
	TagRegexp = match(fmt.Sprintf(`^[a-zA-Z0-9_][a-zA-Z0-9._-]{0,%d}$`, TagMaxLen-1))
)

// IsDistributionSpecTag reports whether s is a valid distribution-spec tag (same grammar as the
// <reference> component in GET /v2/<name>/manifests/<reference> when <reference> is a tag).
func IsDistributionSpecTag(s string) bool {
	return TagRegexp.MatchString(s)
}

// match compiles the string to a regular expression.
//
//nolint:gochecknoglobals
var match = regexp.MustCompile

// literal compiles s into a literal regular expression, escaping any regexp
// reserved characters.
func literal(s string) *regexp.Regexp {
	regx := match(regexp.QuoteMeta(s))

	if _, complete := regx.LiteralPrefix(); !complete {
		panic("must be a literal")
	}

	return regx
}

// expression defines a full expression, where each regular expression must
// follow the previous.
func expression(res ...*regexp.Regexp) *regexp.Regexp {
	var s strings.Builder
	for _, re := range res {
		s.WriteString(re.String())
	}

	return match(s.String())
}

// optional wraps the expression in a non-capturing group and makes the
// production optional.
func optional(res ...*regexp.Regexp) *regexp.Regexp {
	return match(group(expression(res...)).String() + `?`)
}

// repeated wraps the regexp in a non-capturing group to get one or more
// matches.
func repeated(res ...*regexp.Regexp) *regexp.Regexp {
	return match(group(expression(res...)).String() + `+`)
}

// group wraps the regexp in a non-capturing group.
func group(res ...*regexp.Regexp) *regexp.Regexp {
	return match(`(?:` + expression(res...).String() + `)`)
}
