//go:build search

package client

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	zerr "zotregistry.dev/zot/v2/errors"
	"zotregistry.dev/zot/v2/pkg/common"
	tlsutils "zotregistry.dev/zot/v2/pkg/test/tls"
)

func TestZliClientCertAuth(t *testing.T) {
	dir := t.TempDir()

	caCert, caKey, err := tlsutils.GenerateCACert()
	require.NoError(t, err)

	serverCert, serverKey, err := tlsutils.GenerateServerCert(caCert, caKey,
		&tlsutils.CertificateOptions{Hostname: "127.0.0.1"})
	require.NoError(t, err)

	caPath := filepath.Join(dir, "ca.crt")
	certPath := filepath.Join(dir, "client.crt")
	keyPath := filepath.Join(dir, "client.key")

	require.NoError(t, os.WriteFile(caPath, caCert, 0o600))
	require.NoError(t, tlsutils.GenerateClientCertToFile(caCert, caKey, certPath, keyPath,
		&tlsutils.CertificateOptions{CommonName: "bob"}))

	serverPair, err := tls.X509KeyPair(serverCert, serverKey)
	require.NoError(t, err)

	clientCAs := x509.NewCertPool()
	require.True(t, clientCAs.AppendCertsFromPEM(caCert))

	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{}`)
	}))
	srv.TLS = &tls.Config{
		Certificates: []tls.Certificate{serverPair},
		ClientCAs:    clientCAs,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		MinVersion:   tls.VersionTLS12,
	}
	srv.StartTLS()
	t.Cleanup(srv.Close)

	get := func(c *HTTPClient) error {
		var out map[string]any

		_, err := c.makeGETRequest(context.Background(), srv.URL, "", "", true, false, &out, io.Discard)

		return err
	}

	t.Run("fails without client certificate", func(t *testing.T) {
		c := NewHTTPClient()
		c.setCertOptions(commonCertOptions(caPath, "", ""))
		require.Error(t, get(c))
	})

	t.Run("succeeds with ca and client certificate", func(t *testing.T) {
		c := NewHTTPClient()
		c.setCertOptions(commonCertOptions(caPath, certPath, keyPath))
		require.NoError(t, get(c))
	})

	t.Run("config profile provides the options", func(t *testing.T) {
		home := t.TempDir()
		t.Setenv("HOME", home)
		t.Setenv("USERPROFILE", home)

		cfg := &ZliConfigFile{Configs: []ZliConfig{{
			Name: "mtls", URL: srv.URL, CACert: caPath, ClientCert: certPath, ClientKey: keyPath,
		}}}
		require.NoError(t, cfg.WriteFile(filepath.Join(home, ".zot")))

		cmd := &cobra.Command{}
		cmd.Flags().String(ConfigFlag, "mtls", "")
		cmd.Flags().String(URLFlag, "", "")

		opts, err := getCliCertOptions(cmd)
		require.NoError(t, err)
		assert.Equal(t, commonCertOptions(caPath, certPath, keyPath), opts)

		c := NewHTTPClient()
		c.setCertOptions(opts)
		require.NoError(t, get(c))
	})

	t.Run("client cert without key is rejected", func(t *testing.T) {
		home := t.TempDir()
		t.Setenv("HOME", home)
		t.Setenv("USERPROFILE", home)

		cfg := &ZliConfigFile{Configs: []ZliConfig{{Name: "bad", URL: srv.URL, ClientCert: certPath}}}
		require.NoError(t, cfg.WriteFile(filepath.Join(home, ".zot")))

		cmd := &cobra.Command{}
		cmd.Flags().String(ConfigFlag, "bad", "")
		cmd.Flags().String(URLFlag, "", "")

		_, err := getCliCertOptions(cmd)
		assert.ErrorIs(t, err, zerr.ErrCliBadConfig)
	})
}

func commonCertOptions(ca, cert, key string) common.HTTPClientCertOptions {
	return common.HTTPClientCertOptions{RootCaCertFile: ca, ClientCertFile: cert, ClientKeyFile: key}
}
