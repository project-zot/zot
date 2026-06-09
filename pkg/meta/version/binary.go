package version

import "zotregistry.dev/zot/v2/pkg/buildinfo"

// CurrentBinaryVersion returns this binary's identity used to stamp the
// metaDB after a successful storage parse. For released builds it combines the
// release tag and commit ("<tag>+<commit>"). For local development builds
// without a release tag it is "dev-<commit>". Builds without either ldflag
// (typically `go run` and `go test`) return "" which always forces a full parse.
func CurrentBinaryVersion() string {
	return binaryVersion(buildinfo.ReleaseTag, buildinfo.Commit)
}

// binaryVersion is the core of CurrentBinaryVersion, split out so the
// release-tag/commit resolution can be tested directly without mutating the
// process-global buildinfo values.
func binaryVersion(releaseTag, commit string) string {
	switch {
	case releaseTag != "" && commit != "":
		return releaseTag + "+" + commit
	case releaseTag != "":
		return releaseTag
	case commit != "":
		return "dev-" + commit
	default:
		return ""
	}
}
