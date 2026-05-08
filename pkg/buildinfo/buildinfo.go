package buildinfo

// This package intentionally stays tiny and dependency-free because it is
// imported by CLI binaries that should not pull in server-only deps.

var (
	// Commit is the git commit hash, injected at build time via -ldflags.
	Commit string //nolint:gochecknoglobals

	// ReleaseTag is the git tag for the release, injected at build time via -ldflags.
	ReleaseTag string //nolint:gochecknoglobals

	// BinaryType is a short identifier like "server", "cli", etc, injected at build time.
	BinaryType string //nolint:gochecknoglobals

	// GoVersion is the Go toolchain version used to build the binary, injected at build time.
	GoVersion string //nolint:gochecknoglobals
)
