package version

import "zotregistry.dev/zot/v2/pkg/buildinfo"

// CurrentWriterVersion returns this binary's identity used to stamp the
// metaDB after a successful storage parse. For released builds the value is
// the release tag; for local development builds (`make binary` without a
// release tag) it is "dev-<commit>". Builds without either ldflag (typically
// `go run` and `go test`) return "" which always forces a full parse.
func CurrentWriterVersion() string {
	if buildinfo.ReleaseTag != "" {
		return buildinfo.ReleaseTag
	}

	if buildinfo.Commit != "" {
		return "dev-" + buildinfo.Commit
	}

	return ""
}
