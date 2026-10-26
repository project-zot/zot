//go:build sync

package sync

import (
	"regexp"
	"strings"

	"github.com/Masterminds/semver"
	glob "github.com/bmatcuk/doublestar/v4"

	"zotregistry.dev/zot/v2/pkg/common"
	syncconf "zotregistry.dev/zot/v2/pkg/extensions/config/sync"
	"zotregistry.dev/zot/v2/pkg/log"
)

/* ContentManager uses registry content configuration to filter repos/tags
and also manages applying destination/stripPrefix rules
eg: "content": [
	{
		"prefix": "/repo1/repo",
		"destination": "/repo",
		"stripPrefix": true,
		"platforms": ["linux/amd64"],
		"tags": {
			"regex": "4.*",
			"semver": true
		}
	}
]
*/

type ContentManager struct {
	contents []syncconf.Content
	log      log.Logger
}

func NewContentManager(contents []syncconf.Content, log log.Logger) ContentManager {
	return ContentManager{contents: contents, log: log}
}

/*
MatchesContent returns whether a repo matches a registry
config content (is not filtered out by content config rules).
*/
func (cm ContentManager) MatchesContent(repo string) bool {
	content := cm.getContentByUpstreamRepo(repo)

	return content != nil
}

// EffectivePlatforms returns the periodic platforms allowlist for upstream repo.
// content[].platforms wins when set; otherwise registryDefault is used (empty = all).
func (cm ContentManager) EffectivePlatforms(repo string, registryDefault []string) []string {
	return effectivePeriodicPlatforms(cm.getContentByUpstreamRepo(repo), registryDefault)
}

// effectivePeriodicPlatforms returns content.platforms if set, otherwise registryDefault.
// An empty list means all platforms.
func effectivePeriodicPlatforms(content *syncconf.Content, registryDefault []string) []string {
	if content != nil && content.Platforms != nil {
		return *content.Platforms
	}

	return registryDefault
}

// FilterTags filters a repo tags based on content config rules (semver, regex).
func (cm ContentManager) FilterTags(repo string, tags []string) ([]string, error) {
	return cm.filterTags(cm.getContentByUpstreamRepo(repo), tags)
}

// FilterLocalTags is FilterTags for a local repo name, so the push loop applies the same tag
// rules the pull loop applies upstream.
func (cm ContentManager) FilterLocalTags(repo string, tags []string) ([]string, error) {
	return cm.filterTags(cm.GetContentByLocalRepo(repo), tags)
}

// MatchesLocalRepo reports whether a local repo may leave the store. No content rules at all
// means the whole store: an operator who configured no allowlist asked for a mirror.
func (cm ContentManager) MatchesLocalRepo(repo string) bool {
	if len(cm.contents) == 0 {
		return true
	}

	return cm.GetContentByLocalRepo(repo) != nil
}

// EffectiveLocalPlatforms is EffectivePlatforms for a local repo name.
func (cm ContentManager) EffectiveLocalPlatforms(repo string, registryDefault []string) []string {
	return effectivePeriodicPlatforms(cm.GetContentByLocalRepo(repo), registryDefault)
}

func (cm ContentManager) filterTags(content *syncconf.Content, tags []string) ([]string, error) {
	var err error
	// filter based on tags rules
	if content != nil && content.Tags != nil {
		if content.Tags.Regex != nil {
			tags, err = filterTagsByRegex(tags, *content.Tags.Regex, cm.log)
			if err != nil {
				return []string{}, err
			}
		}

		if content.Tags.ExcludeRegex != nil {
			tags, err = excludeTagsByRegex(tags, *content.Tags.ExcludeRegex, cm.log)
			if err != nil {
				return []string{}, err
			}
		}

		if content.Tags.Semver != nil && *content.Tags.Semver {
			tags = filterTagsBySemver(tags, cm.log)
		}
	}

	return tags, nil
}

/*
GetRepoDestination applies content destination config rule and returns the final repo namespace.
- used by periodically sync.
*/
func (cm ContentManager) GetRepoDestination(repo string) string {
	content := cm.getContentByUpstreamRepo(repo)
	if content == nil {
		return ""
	}

	return getRepoDestination(repo, *content)
}

/*
GetRepoSource is the inverse function of GetRepoDestination, needed in on demand to find out
the remote name of a repo given a local repo.
- used by on demand sync.
*/
func (cm ContentManager) GetRepoSource(repo string) string {
	content := cm.GetContentByLocalRepo(repo)
	if content == nil {
		return ""
	}

	return getRepoSource(repo, *content)
}

// utilies functions.
func (cm ContentManager) getContentByUpstreamRepo(repo string) *syncconf.Content {
	for i := range cm.contents {
		content := &cm.contents[i]

		var prefix string
		// handle prefixes starting with '/'
		if strings.HasPrefix(content.Prefix, "/") {
			prefix = content.Prefix[1:]
		} else {
			prefix = content.Prefix
		}

		matched, err := glob.Match(prefix, repo)
		if err != nil {
			cm.log.Error().Str("errorType", common.TypeOf(err)).
				Err(err).Str("pattern",
				prefix).Msg("failed to parse glob pattern, skipping it")

			continue
		}

		if matched {
			return content
		}
	}

	return nil
}

// GetContentByLocalRepo returns the content entry that governs a local repository, or nil when
// none matches. Entries are evaluated in config order and the first match wins: a repo can be
// matched by a broad rule and a narrow one, and only the broad one's tag and platform rules
// would apply. The pull direction has the same rule (see getContentByUpstreamRepo), so both
// directions read a content list the same way.
func (cm ContentManager) GetContentByLocalRepo(repo string) *syncconf.Content {
	matches := cm.LocalContentMatches(repo)
	if len(matches) == 0 {
		return nil
	}

	return matches[0]
}

// LocalContentMatches returns every content entry whose rules match a local repo, in config
// order. Only the first governs, which GetContentByLocalRepo enforces; the full list exists so
// the push loop can report an ambiguous config instead of silently applying one of two rules.
func (cm ContentManager) LocalContentMatches(repo string) []*syncconf.Content {
	repo = strings.Trim(repo, "/")

	var matches []*syncconf.Content

	for cID := range cm.contents {
		content := &cm.contents[cID]

		// make sure prefix ends in "/" to extract the meta characters
		prefix := strings.Trim(content.Prefix, "/") + "/"
		destination := strings.Trim(content.Destination, "/")

		var patternSlice []string

		if content.StripPrefix {
			_, metaCharacters := glob.SplitPattern(prefix)
			patternSlice = append(patternSlice, destination, metaCharacters)
		} else {
			patternSlice = append(patternSlice, destination, prefix)
		}

		pattern := strings.Trim(strings.Join(patternSlice, "/"), "/")

		matched, err := glob.Match(pattern, repo)
		if err != nil {
			continue
		}

		if matched {
			matches = append(matches, content)
		}
	}

	return matches
}

func getRepoSource(localRepo string, content syncconf.Content) string {
	localRepo = strings.Trim(localRepo, "/")
	destination := strings.Trim(content.Destination, "/")
	prefix := strings.Trim(content.Prefix, "/*")

	var localRepoSlice []string

	localRepo = strings.TrimPrefix(localRepo, destination)
	localRepo = strings.Trim(localRepo, "/")

	if content.StripPrefix {
		localRepoSlice = append([]string{prefix}, localRepo)
	} else {
		localRepoSlice = []string{localRepo}
	}

	repoSource := strings.Join(localRepoSlice, "/")
	if repoSource == "/" {
		return repoSource
	}

	return strings.Trim(repoSource, "/")
}

// getRepoDestination returns the local storage path of the synced repo based on the specified destination.
func getRepoDestination(remoteRepo string, content syncconf.Content) string {
	remoteRepo = strings.Trim(remoteRepo, "/")
	destination := strings.Trim(content.Destination, "/")
	prefix := strings.Trim(content.Prefix, "/*")

	var repoDestSlice []string

	if content.StripPrefix {
		remoteRepo = strings.TrimPrefix(remoteRepo, prefix)
		remoteRepo = strings.Trim(remoteRepo, "/")
		repoDestSlice = append(repoDestSlice, destination, remoteRepo)
	} else {
		repoDestSlice = append(repoDestSlice, destination, remoteRepo)
	}

	repoDestination := strings.Join(repoDestSlice, "/")

	if repoDestination == "/" {
		return "/"
	}

	return strings.Trim(repoDestination, "/")
}

// filterTagsByRegex filters images by tag regex given in the config.
func filterTagsByRegex(tags []string, regex string, log log.Logger) ([]string, error) {
	filteredTags := []string{}

	if len(tags) == 0 || regex == "" {
		return filteredTags, nil
	}

	log.Info().Str("regex", regex).Msg("filtering tags using regex")

	tagReg, err := regexp.Compile(regex)
	if err != nil {
		log.Error().Err(err).Str("regex", regex).Msg("failed to compile regex")

		return filteredTags, err
	}

	for _, tag := range tags {
		if tagReg.MatchString(tag) {
			filteredTags = append(filteredTags, tag)
		}
	}

	return filteredTags, nil
}

// excludeTagsByRegex filter-out images by tag regex given in the config.
func excludeTagsByRegex(tags []string, regex string, log log.Logger) ([]string, error) {
	if len(tags) == 0 || regex == "" {
		return tags, nil
	}

	filteredTags := make([]string, 0, len(tags))

	log.Info().Str("excludeRegex", regex).Msg("filtering out tags using regex")

	tagReg, err := regexp.Compile(regex)
	if err != nil {
		log.Error().Err(err).Str("excludeRegex", regex).Msg("failed to compile regex")

		return filteredTags, err
	}

	for _, tag := range tags {
		if !tagReg.MatchString(tag) {
			filteredTags = append(filteredTags, tag)
		}
	}

	return filteredTags, nil
}

// filterTagsBySemver filters tags by checking if they are semver compliant.
func filterTagsBySemver(tags []string, log log.Logger) []string {
	filteredTags := []string{}

	log.Info().Msg("start filtering using semver compliant rule")

	for _, tag := range tags {
		_, err := semver.NewVersion(tag)
		if err == nil {
			filteredTags = append(filteredTags, tag)
		}
	}

	return filteredTags
}
