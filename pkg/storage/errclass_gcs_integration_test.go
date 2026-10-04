//go:build needprivileges && linux

package storage_test

import (
	"testing"

	"zotregistry.dev/zot/v2/pkg/test/gcsemulator"
	"zotregistry.dev/zot/v2/pkg/test/storageerrclass"
)

// The GCS driver needs the emulator harness (hosts redirect + HTTPS proxy on 443),
// which needs privileges, so GCS joins the error-class matrix only in this build.

func TestMain(m *testing.M) {
	gcsemulator.Main(m)
}

//nolint:gochecknoinits // registers the GCS backend only for needprivileges builds
func init() {
	errClassBackends = append(errClassBackends, storageerrclass.GCS())
}
