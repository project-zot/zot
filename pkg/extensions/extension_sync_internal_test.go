//go:build sync

package extensions

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	syncconf "zotregistry.dev/zot/v2/pkg/extensions/config/sync"
	"zotregistry.dev/zot/v2/pkg/log"
)

func TestGetLocalIPs(t *testing.T) {
	t.Parallel()

	ips, err := getLocalIPs()
	require.NoError(t, err)
	assert.Contains(t, ips, "127.0.0.1", "loopback must always be among the local IPs")
}

func TestRemoveSelfURLsLiteralSelfAddressMatch(t *testing.T) {
	t.Parallel()

	logger := log.NewTestLogger()

	registryConfig := &syncconf.RegistryConfig{
		URLs: []string{
			"http://127.0.0.1:8080/self",
			"https://definitely-invalid-host.invalid:443/other",
		},
	}

	err := removeSelfURLs("127.0.0.1", "8080", registryConfig, logger)
	require.NoError(t, err)
	assert.Equal(t, []string{"https://definitely-invalid-host.invalid:443/other"}, registryConfig.URLs)
}

func TestRemoveSelfURLsInvalidURLIsDropped(t *testing.T) {
	t.Parallel()

	logger := log.NewTestLogger()

	registryConfig := &syncconf.RegistryConfig{
		URLs: []string{
			"http://%zzzz",
			"https://definitely-invalid-host.invalid:443/other",
		},
	}

	err := removeSelfURLs("127.0.0.1", "8080", registryConfig, logger)
	require.NoError(t, err)
	assert.Equal(t, []string{"https://definitely-invalid-host.invalid:443/other"}, registryConfig.URLs)
}

func TestRemoveSelfURLsDNSLoopbackMatch(t *testing.T) {
	t.Parallel()

	logger := log.NewTestLogger()

	// "localhost" resolves to a loopback IP; removeSelfURLs treats any loopback
	// resolution on the configured HTTP port as self, regardless of hostname.
	registryConfig := &syncconf.RegistryConfig{
		URLs: []string{
			"http://localhost:8080/self",
			"https://definitely-invalid-host.invalid:443/other",
		},
	}

	err := removeSelfURLs("192.0.2.1", "8080", registryConfig, logger)
	require.NoError(t, err)
	assert.Equal(t, []string{"https://definitely-invalid-host.invalid:443/other"}, registryConfig.URLs)
}

func TestRemoveSelfURLsDNSLoopbackDifferentPortIsKept(t *testing.T) {
	t.Parallel()

	logger := log.NewTestLogger()

	// Loopback resolution alone is not enough - the port must also match httpPort.
	registryConfig := &syncconf.RegistryConfig{
		URLs: []string{"http://localhost:9999/notself"},
	}

	err := removeSelfURLs("192.0.2.1", "8080", registryConfig, logger)
	require.NoError(t, err)
	assert.Equal(t, []string{"http://localhost:9999/notself"}, registryConfig.URLs)
}

func TestRemoveSelfURLsUnresolvableHostnameIsKept(t *testing.T) {
	t.Parallel()

	logger := log.NewTestLogger()

	// "invalid" is a reserved TLD (RFC 2606) guaranteed to never resolve, so the
	// DNS lookup fails and the URL is kept rather than removed (fail open, since
	// it might resolve later after retries per the function's comment).
	registryConfig := &syncconf.RegistryConfig{
		URLs: []string{"https://definitely-invalid-host.invalid:443/other"},
	}

	err := removeSelfURLs("127.0.0.1", "8080", registryConfig, logger)
	require.NoError(t, err)
	assert.Equal(t, []string{"https://definitely-invalid-host.invalid:443/other"}, registryConfig.URLs)
}

func TestRemoveSelfURLsAllRemovedLeavesEmptySlice(t *testing.T) {
	t.Parallel()

	logger := log.NewTestLogger()

	registryConfig := &syncconf.RegistryConfig{
		URLs: []string{
			"http://127.0.0.1:8080/one",
			"http://127.0.0.1:8080/two",
		},
	}

	err := removeSelfURLs("127.0.0.1", "8080", registryConfig, logger)
	require.NoError(t, err)
	assert.Empty(t, registryConfig.URLs)
}
