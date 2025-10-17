//go:build sync
// +build sync

package sync_test //nolint: testpackage

import (
	"testing"

	. "github.com/smartystreets/goconvey/convey"

	syncconf "zotregistry.dev/zot/v2/pkg/extensions/config/sync"
	"zotregistry.dev/zot/v2/pkg/extensions/sync"
	"zotregistry.dev/zot/v2/pkg/log"
)

func TestContentManager(t *testing.T) {
	testCases := []struct {
		repo     string
		content  syncconf.Content
		expected string
	}{
		{
			repo:     "alpine/zot-fold/alpine",
			content:  syncconf.Content{Prefix: "zot-fold/alpine", Destination: "/alpine", StripPrefix: false},
			expected: "zot-fold/alpine",
		},
		{
			repo:     "zot-fold/alpine",
			content:  syncconf.Content{Prefix: "zot-fold/alpine", Destination: "/", StripPrefix: false},
			expected: "zot-fold/alpine",
		},
		{
			repo:     "alpine",
			content:  syncconf.Content{Prefix: "zot-fold/alpine", Destination: "/alpine", StripPrefix: true},
			expected: "zot-fold/alpine",
		},
		{
			repo:     "/",
			content:  syncconf.Content{Prefix: "zot-fold/alpine", Destination: "/", StripPrefix: true},
			expected: "zot-fold/alpine",
		},
		{
			repo:     "",
			content:  syncconf.Content{Prefix: "/", Destination: "/", StripPrefix: true},
			expected: "/",
		},
		{
			repo:     "alpine",
			content:  syncconf.Content{Prefix: "zot-fold/alpine", Destination: "/alpine", StripPrefix: true},
			expected: "zot-fold/alpine",
		},
		{
			repo:     "alpine",
			content:  syncconf.Content{Prefix: "zot-fold/*", Destination: "/", StripPrefix: true},
			expected: "zot-fold/alpine",
		},
		{
			repo:     "alpine",
			content:  syncconf.Content{Prefix: "zot-fold/**", Destination: "/", StripPrefix: true},
			expected: "zot-fold/alpine",
		},
		{
			repo:     "zot-fold/alpine",
			content:  syncconf.Content{Prefix: "zot-fold/**", Destination: "/", StripPrefix: false},
			expected: "zot-fold/alpine",
		},
	}

	Convey("Test GetRepoDestination()", t, func() {
		for _, test := range testCases {
			cm := sync.NewContentManager([]syncconf.Content{test.content}, log.NewTestLogger())
			actualResult := cm.GetRepoDestination(test.expected)
			So(actualResult, ShouldEqual, test.repo)
		}
	})

	// this is the inverse function of getRepoDestination()
	Convey("Test GetRepoSource()", t, func() {
		for _, test := range testCases {
			cm := sync.NewContentManager([]syncconf.Content{test.content}, log.NewTestLogger())
			actualResult := cm.GetRepoSource(test.repo)
			So(actualResult, ShouldEqual, test.expected)
		}
	})

	Convey("Test MatchesContent() error", t, func() {
		content := syncconf.Content{Prefix: "[repo%^&"}
		cm := sync.NewContentManager([]syncconf.Content{content}, log.NewTestLogger())
		So(cm.MatchesContent("repo"), ShouldEqual, false)
	})
}

func TestGetContentByLocalRepo(t *testing.T) {
	testCases := []struct {
		repo     string
		content  []syncconf.Content
		expected int
	}{
		{
			repo: "alpine/zot-fold/alpine",
			content: []syncconf.Content{
				{Prefix: "zot-fold/alpine/", Destination: "/alpine", StripPrefix: true},
				{Prefix: "zot-fold/alpine", Destination: "/alpine", StripPrefix: false},
			},
			expected: 1,
		},
		{
			repo: "alpine/zot-fold/alpine",
			content: []syncconf.Content{
				{Prefix: "zot-fold/*", Destination: "/alpine", StripPrefix: false},
				{Prefix: "zot-fold/alpine", Destination: "/alpine", StripPrefix: true},
			},
			expected: 0,
		},
		{
			repo: "myFold/zot-fold/internal/alpine",
			content: []syncconf.Content{
				{Prefix: "zot-fold/alpine", Destination: "/alpine", StripPrefix: true},
				{Prefix: "zot-fold/**", Destination: "/myFold", StripPrefix: false},
			},
			expected: 1,
		},
		{
			repo: "alpine",
			content: []syncconf.Content{
				{Prefix: "zot-fold/*", Destination: "/alpine", StripPrefix: true},
				{Prefix: "zot-fold/alpine", Destination: "/", StripPrefix: true},
			},
			expected: -1,
		},
		{
			repo: "alpine",
			content: []syncconf.Content{
				{Prefix: "zot-fold/*", Destination: "/alpine", StripPrefix: true},
				{Prefix: "zot-fold/*", Destination: "/", StripPrefix: true},
			},
			expected: 1,
		},
		{
			repo: "alpine/alpine",
			content: []syncconf.Content{
				{Prefix: "zot-fold/*", Destination: "/alpine", StripPrefix: true},
				{Prefix: "zot-fold/*", Destination: "/", StripPrefix: true},
			},
			expected: 0,
		},
	}

	Convey("Test getContentByLocalRepo()", t, func() {
		for _, test := range testCases {
			cm := sync.NewContentManager(test.content, log.NewTestLogger())
			actualResult := cm.GetContentByLocalRepo(test.repo)

			if test.expected == -1 {
				var tnil *syncconf.Content = nil

				So(actualResult, ShouldEqual, tnil)
			} else {
				So(actualResult, ShouldEqual, &test.content[test.expected])
			}
		}
	})

	Convey("Test getContentByLocalRepo() error", t, func() {
		content := syncconf.Content{Prefix: "[repo%^&"}
		cm := sync.NewContentManager([]syncconf.Content{content}, log.NewTestLogger())
		So(cm.GetContentByLocalRepo("repo"), ShouldBeNil)
	})
}

func TestFilterTags(t *testing.T) {
	allTagsRegex := ".*"
	badRegex := "[*"
	excludeArchRegex := ".*(x86_64|aarch64|amd64|arm64)$"
	semverFalse := false
	semverTrue := true
	testCases := []struct {
		tags         []string
		repo         string
		content      []syncconf.Content
		filteredTags []string
		err          bool
	}{
		{
			repo: "alpine",
			content: []syncconf.Content{
				{Prefix: "**", Tags: &syncconf.Tags{Regex: &allTagsRegex, Semver: &semverFalse}},
			},
			tags:         []string{"v1", "v2", "v3"},
			filteredTags: []string{"v1", "v2", "v3"},
			err:          false,
		},
		{
			repo: "alpine",
			content: []syncconf.Content{
				{Prefix: "**", Tags: &syncconf.Tags{}},
			},
			tags:         []string{"v1", "v2", "v3"},
			filteredTags: []string{"v1", "v2", "v3"},
			err:          false,
		},
		{
			repo: "alpine",
			content: []syncconf.Content{
				{Prefix: "**", Tags: &syncconf.Tags{Regex: &allTagsRegex, Semver: &semverTrue}},
			},
			tags:         []string{"1s0", "2v9", "v3.0.3"},
			filteredTags: []string{"v3.0.3"},
			err:          false,
		},
		{
			repo: "infra/busybox",
			content: []syncconf.Content{
				{Prefix: "infra/*", Tags: &syncconf.Tags{Semver: &semverTrue}},
			},
			tags:         []string{"latest", "v1.0.1"},
			filteredTags: []string{"v1.0.1"},
			err:          false,
		},
		{
			repo: "repo",
			content: []syncconf.Content{
				{Prefix: "repo*", Tags: &syncconf.Tags{Regex: &badRegex}},
			},
			tags:         []string{"latest", "v2.0.1"},
			filteredTags: []string{},
			err:          true,
		},

		{
			repo: "repo",
			content: []syncconf.Content{
				{Prefix: "repo", Tags: &syncconf.Tags{Regex: &allTagsRegex}},
			},
			tags:         []string{},
			filteredTags: []string{},
			err:          false,
		},
		{
			repo: "alpine",
			content: []syncconf.Content{
				{Prefix: "**", Tags: &syncconf.Tags{ExcludeRegex: &allTagsRegex}},
			},
			tags:         []string{"v1", "v2", "v3"},
			filteredTags: []string{},
			err:          false,
		},
		{
			repo: "alpine",
			content: []syncconf.Content{
				{Prefix: "**", Tags: &syncconf.Tags{ExcludeRegex: &excludeArchRegex}},
			},
			tags:         []string{"v1", "v2-x86_64", "v3-aarch64"},
			filteredTags: []string{"v1"},
			err:          false,
		},
		{
			repo: "repo",
			content: []syncconf.Content{
				{Prefix: "repo*", Tags: &syncconf.Tags{ExcludeRegex: &badRegex}},
			},
			tags:         []string{"latest", "v2.0.1"},
			filteredTags: []string{},
			err:          true,
		},
	}

	Convey("Test FilterTags()", t, func() {
		for _, test := range testCases {
			cm := sync.NewContentManager(test.content, log.NewTestLogger())
			actualResult, err := cm.FilterTags(test.repo, test.tags)
			So(actualResult, ShouldResemble, test.filteredTags)

			if test.err {
				So(err, ShouldNotBeNil)
			} else {
				So(err, ShouldBeNil)
			}
		}
	})
}
