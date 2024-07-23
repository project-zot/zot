//go:build sync
// +build sync

package sync

import (
	"regexp"
	"strings"

	"github.com/Masterminds/semver"
	glob "github.com/bmatcuk/doublestar/v4"

	"zotregistry.dev/zot/pkg/common"
	syncconf "zotregistry.dev/zot/pkg/extensions/config/sync"
	"zotregistry.dev/zot/pkg/log"
)

/* ContentManager uses registry content configuration to filter repos/tags
and also manages applying destination/stripPrefix rules
eg: "content": [
	{
		"prefix": "/repo1/repo",
		"destination": "/repo",
		"stripPrefix": true
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

// FilterTags filters a repo tags based on content config rules (semver, regex).
func (cm ContentManager) FilterTags(repo string, tags []string) ([]string, error) {
	content := cm.getContentByLocalRepo(repo)

	var err error
	// filter based on tags rules
	if content != nil && content.Tags != nil {
		if content.Tags.Regex != nil {
			tags, err = filterTagsByRegex(tags, *content.Tags.Regex, cm.log)
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
	content := cm.getContentByLocalRepo(repo)
	if content == nil {
		return ""
	}

	return getRepoSource(repo, *content)
}

// utilies functions.
func (cm ContentManager) getContentByUpstreamRepo(repo string) *syncconf.Content {
	for _, content := range cm.contents {
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
			return &content
		}
	}

	return nil
}

func (cm ContentManager) getContentByLocalRepo(repo string) *syncconf.Content {
	contentID := -1
	repo = strings.Trim(repo, "/")

	for cID, content := range cm.contents {
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
			contentID = cID

			break
		}
	}

	if contentID == -1 {
		return nil
	}

	return &cm.contents[contentID]
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
