package version

import "zotregistry.dev/zot/v2/pkg/buildinfo"

// CurrentWriterVersion returns this binary's identity used to stamp the
// metaDB after a successful storage parse. For released builds the value is
// the release tag; for local development builds (`make binary` without a
// release tag) it is "dev-<commit>". Builds without either ldflag (typically
// `go run` and `go test`) return "" which always forces a full parse.
func CurrentWriterVersion() string {
	return writerVersion(buildinfo.ReleaseTag, buildinfo.Commit)
}

// writerVersion is the core of CurrentWriterVersion, split out so the
// release-tag/commit resolution can be tested directly without mutating the
// process-global buildinfo values.
func writerVersion(releaseTag, commit string) string {
	if releaseTag != "" {
		return releaseTag
	}

	if commit != "" {
		return "dev-" + commit
	}

	return ""
}
