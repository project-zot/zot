package api_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"testing"
	"time"

	. "github.com/smartystreets/goconvey/convey"
	"gopkg.in/resty.v1"

	"zotregistry.dev/zot/v2/pkg/api"
	"zotregistry.dev/zot/v2/pkg/api/config"
	test "zotregistry.dev/zot/v2/pkg/test/common"
	"zotregistry.dev/zot/v2/pkg/test/mocks"
	tlsutils "zotregistry.dev/zot/v2/pkg/test/tls"
)

var ErrUnexpectedError = errors.New("error: unexpected error")

// setupTestCerts generates CA, server, and client certificates for testing.
// Returns paths to certificate files and PEM data for CA cert.
func setupTestCerts(t *testing.T) (
	string, string, string, string, string, []byte,
) {
	t.Helper()
	tempDir := t.TempDir()

	// Generate CA certificate (10 years validity, matching gen_certs.sh)
	caOpts := &tlsutils.CertificateOptions{
		CommonName: "*",
		NotAfter:   time.Now().AddDate(10, 0, 0),
	}
	caCertPEM, caKeyPEM, err := tlsutils.GenerateCACert(caOpts)
	if err != nil {
		t.Fatalf("Failed to generate CA cert: %v", err)
	}

	caCertPath := path.Join(tempDir, "ca.crt")
	caKeyPath := path.Join(tempDir, "ca.key")
	err = os.WriteFile(caCertPath, caCertPEM, 0o600)
	if err != nil {
		t.Fatalf("Failed to write CA cert: %v", err)
	}
	_ = os.WriteFile(caKeyPath, caKeyPEM, 0o600)

	// Generate server certificate
	serverCertPath := path.Join(tempDir, "server.cert")
	serverKeyPath := path.Join(tempDir, "server.key")
	serverOpts := &tlsutils.CertificateOptions{
		Hostname:           "127.0.0.1",
		CommonName:         "*",
		OrganizationalUnit: "TestServer",
		NotAfter:           time.Now().AddDate(10, 0, 0),
	}
	err = tlsutils.GenerateServerCertToFile(caCertPEM, caKeyPEM, serverCertPath, serverKeyPath, serverOpts)
	if err != nil {
		t.Fatalf("Failed to generate server cert: %v", err)
	}

	// Generate client certificate (10 years validity, matching gen_certs.sh)
	clientCertPath := path.Join(tempDir, "client.cert")
	clientKeyPath := path.Join(tempDir, "client.key")
	clientOpts := &tlsutils.CertificateOptions{
		CommonName:         "testclient",
		OrganizationalUnit: "TestClient",
		NotAfter:           time.Now().AddDate(10, 0, 0),
	}
	err = tlsutils.GenerateClientCertToFile(caCertPEM, caKeyPEM, clientCertPath, clientKeyPath, clientOpts)
	if err != nil {
		t.Fatalf("Failed to generate client cert: %v", err)
	}

	return caCertPath, serverCertPath, serverKeyPath, clientCertPath, clientKeyPath, caCertPEM
}

// mTLSTestCase defines a test case for mTLS identity extraction.
type mTLSTestCase struct {
	name              string
	clientCertOptions *tlsutils.CertificateOptions
	mtlsConfig        *config.MTLSConfig
	allowedUsers      []string // Users allowed in access control
	expectedIdentity  string   // Expected identity extracted from cert
	expectedStatus    int      // Expected HTTP status code
	description       string   // Test description
}

// getExpectedSubjectDN constructs the expected Subject DN string based on the certificate options.
// This matches the format used by tlsutils for client certificates.
func getExpectedSubjectDN(commonName string) string {
	subject := pkix.Name{
		Organization:  []string{"Test Client"},
		Country:       []string{"US"},
		Province:      []string{""},
		Locality:      []string{"San Francisco"},
		StreetAddress: []string{""},
		PostalCode:    []string{""},
	}
	if commonName != "" {
		subject.CommonName = commonName
	}

	return subject.String()
}

// runMTLSTest executes a single mTLS test case.
func runMTLSTest(t *testing.T, testCase mTLSTestCase) {
	t.Helper()

	tempDir := t.TempDir()

	// Generate CA certificate
	caCert, caKey, err := tlsutils.GenerateCACert()
	So(err, ShouldBeNil)
	caCertPath := path.Join(tempDir, "ca.crt")
	err = os.WriteFile(caCertPath, caCert, 0o600)
	So(err, ShouldBeNil)

	// Generate server certificate
	serverCertPath := path.Join(tempDir, "server.crt")
	serverKeyPath := path.Join(tempDir, "server.key")
	serverOpts := &tlsutils.CertificateOptions{
		Hostname: "localhost",
	}
	err = tlsutils.GenerateServerCertToFile(caCert, caKey, serverCertPath, serverKeyPath, serverOpts)
	So(err, ShouldBeNil)

	// Generate client certificate
	clientCertPath := path.Join(tempDir, "client.crt")
	clientKeyPath := path.Join(tempDir, "client.key")
	err = tlsutils.GenerateClientCertToFile(caCert, caKey, clientCertPath, clientKeyPath, testCase.clientCertOptions)
	So(err, ShouldBeNil)

	// Set up server
	conf := config.New()
	port := test.GetFreePort()
	baseURL := test.GetSecureBaseURL(port)

	conf.HTTP.Port = port
	conf.HTTP.TLS = &config.TLSConfig{
		Cert:   serverCertPath,
		Key:    serverKeyPath,
		CACert: caCertPath,
	}
	conf.HTTP.Auth = &config.AuthConfig{
		MTLS: testCase.mtlsConfig,
	}

	// Set up access control
	repoPolicies := make([]config.Policy, 0)
	if len(testCase.allowedUsers) > 0 {
		repoPolicies = append(repoPolicies, config.Policy{
			Users:   testCase.allowedUsers,
			Actions: []string{"read", "create"},
		})
	}

	conf.HTTP.AccessControl = &config.AccessControlConfig{
		Repositories: config.Repositories{
			"**": config.PolicyGroup{
				AnonymousPolicy: make([]string, 0),
				Policies:        make([]config.Policy, 0),
			},
			"test-repo": config.PolicyGroup{
				Policies: repoPolicies,
			},
		},
	}
	conf.Storage.RootDirectory = t.TempDir()

	ctlr := api.NewController(conf)
	cm := test.NewControllerManager(ctlr)

	cm.StartAndWait(port)
	defer cm.StopServer()

	// Set up client
	caCertPEM, err := os.ReadFile(caCertPath)
	So(err, ShouldBeNil)

	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCertPEM)

	clientCert, err := tls.LoadX509KeyPair(clientCertPath, clientKeyPath)
	So(err, ShouldBeNil)

	client := resty.New()
	client.SetTLSClientConfig(&tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{clientCert},
		RootCAs:      caCertPool,
	})

	// Make request
	resp, err := client.R().Get(baseURL + "/v2/test-repo/tags/list")
	So(err, ShouldBeNil)
	So(resp.StatusCode(), ShouldEqual, testCase.expectedStatus)
}

func TestExtractMTLSIdentity(t *testing.T) {
	testCases := []mTLSTestCase{
		// Positive tests - authentication should succeed
		{
			name: "CommonName",
			clientCertOptions: &tlsutils.CertificateOptions{
				CommonName: "testuser",
			},
			mtlsConfig: &config.MTLSConfig{
				IdentityAttibutes: []string{"CommonName"},
			},
			allowedUsers:     []string{"testuser"},
			expectedIdentity: "testuser",
			expectedStatus:   http.StatusNotFound, // 404 means auth passed
			description:      "Extract identity from CommonName",
		},
		{
			name: "Subject",
			clientCertOptions: &tlsutils.CertificateOptions{
				CommonName: "testuser",
			},
			mtlsConfig: &config.MTLSConfig{
				IdentityAttibutes: []string{"Subject"},
			},
			allowedUsers:     []string{getExpectedSubjectDN("testuser")},
			expectedIdentity: getExpectedSubjectDN("testuser"),
			expectedStatus:   http.StatusNotFound,
			description:      "Extract identity from Subject DN",
		},
		{
			name: "EmailSAN",
			clientCertOptions: &tlsutils.CertificateOptions{
				EmailAddresses: []string{"testuser@example.com"},
			},
			mtlsConfig: &config.MTLSConfig{
				IdentityAttibutes: []string{"Email"},
			},
			allowedUsers:     []string{"testuser@example.com"},
			expectedIdentity: "testuser@example.com",
			expectedStatus:   http.StatusNotFound,
			description:      "Extract identity from Email SAN",
		},
		{
			name: "DNSNameSAN",
			clientCertOptions: &tlsutils.CertificateOptions{
				DNSNames: []string{"client.example.com"},
			},
			mtlsConfig: &config.MTLSConfig{
				IdentityAttibutes: []string{"DNSName"},
			},
			allowedUsers:     []string{"client.example.com"},
			expectedIdentity: "client.example.com",
			expectedStatus:   http.StatusNotFound,
			description:      "Extract identity from DNSName SAN",
		},
		{
			name: "URISAN",
			clientCertOptions: &tlsutils.CertificateOptions{
				URIs: []string{"spiffe://example.org/workload/testuser"},
			},
			mtlsConfig: &config.MTLSConfig{
				IdentityAttibutes: []string{"URI"},
			},
			allowedUsers:     []string{"spiffe://example.org/workload/testuser"},
			expectedIdentity: "spiffe://example.org/workload/testuser",
			expectedStatus:   http.StatusNotFound,
			description:      "Extract identity from URI SAN",
		},
		{
			name: "URISANWithRegex",
			clientCertOptions: &tlsutils.CertificateOptions{
				URIs: []string{"spiffe://example.org/workload/testuser"},
			},
			mtlsConfig: &config.MTLSConfig{
				IdentityAttibutes: []string{"URI"},
				URISANPattern:     "spiffe://example.org/workload/(.*)",
			},
			allowedUsers:     []string{"testuser"},
			expectedIdentity: "testuser",
			expectedStatus:   http.StatusNotFound,
			description:      "Extract identity from URI SAN with regex pattern",
		},
		{
			name: "FallbackChain",
			clientCertOptions: &tlsutils.CertificateOptions{
				CommonName: "testuser",
			},
			mtlsConfig: &config.MTLSConfig{
				IdentityAttibutes: []string{"Email", "DNSName", "CommonName"},
			},
			allowedUsers:     []string{"testuser"},
			expectedIdentity: "testuser",
			expectedStatus:   http.StatusNotFound,
			description:      "Extract identity using fallback chain",
		},
		{
			name: "CaseInsensitive",
			clientCertOptions: &tlsutils.CertificateOptions{
				CommonName: "testuser",
			},
			mtlsConfig: &config.MTLSConfig{
				IdentityAttibutes: []string{"commonname"}, // lowercase
			},
			allowedUsers:     []string{"testuser"},
			expectedIdentity: "testuser",
			expectedStatus:   http.StatusNotFound,
			description:      "Extract identity with case-insensitive source name",
		},
		{
			name: "DNSANIndex1",
			clientCertOptions: &tlsutils.CertificateOptions{
				DNSNames: []string{"first.example.com", "second.example.com"},
			},
			mtlsConfig: &config.MTLSConfig{
				IdentityAttibutes: []string{"DNSName"},
				DNSANIndex:        1, // Use second DNS name
			},
			allowedUsers:     []string{"second.example.com"},
			expectedIdentity: "second.example.com",
			expectedStatus:   http.StatusNotFound,
			description:      "Extract identity from DNS SAN with index 1",
		},
		{
			name: "URISANIndex1",
			clientCertOptions: &tlsutils.CertificateOptions{
				URIs: []string{
					"spiffe://example.org/workload/first",
					"spiffe://example.org/workload/second",
				},
			},
			mtlsConfig: &config.MTLSConfig{
				IdentityAttibutes: []string{"URI"},
				URISANIndex:       1, // Use second URI
			},
			allowedUsers:     []string{"spiffe://example.org/workload/second"},
			expectedIdentity: "spiffe://example.org/workload/second",
			expectedStatus:   http.StatusNotFound,
			description:      "Extract identity from URI SAN with index 1",
		},
		{
			name: "EmailSANIndex1",
			clientCertOptions: &tlsutils.CertificateOptions{
				EmailAddresses: []string{"first@example.com", "second@example.com"},
			},
			mtlsConfig: &config.MTLSConfig{
				IdentityAttibutes: []string{"Email"},
				EmailSANIndex:     1, // Use second email
			},
			allowedUsers:     []string{"second@example.com"},
			expectedIdentity: "second@example.com",
			expectedStatus:   http.StatusNotFound,
			description:      "Extract identity from Email SAN with index 1",
		},
		// Negative tests - authentication should fail
		{
			name: "CommonNameNotAllowed",
			clientCertOptions: &tlsutils.CertificateOptions{
				CommonName: "testuser",
			},
			mtlsConfig: &config.MTLSConfig{
				IdentityAttibutes: []string{"CommonName"},
			},
			allowedUsers:     []string{"otheruser"}, // Different user
			expectedIdentity: "testuser",
			expectedStatus:   http.StatusForbidden, // 403 means auth passed but access denied
			description:      "Authentication succeeds but user not in allowed list",
		},
		{
			name: "EmailSANNotAllowed",
			clientCertOptions: &tlsutils.CertificateOptions{
				EmailAddresses: []string{"testuser@example.com"},
			},
			mtlsConfig: &config.MTLSConfig{
				IdentityAttibutes: []string{"Email"},
			},
			allowedUsers:     []string{"other@example.com"},
			expectedIdentity: "testuser@example.com",
			expectedStatus:   http.StatusForbidden,
			description:      "Email SAN extracted but user not in allowed list",
		},
		{
			name: "DNSNameSANNotAllowed",
			clientCertOptions: &tlsutils.CertificateOptions{
				DNSNames: []string{"client.example.com"},
			},
			mtlsConfig: &config.MTLSConfig{
				IdentityAttibutes: []string{"DNSName"},
			},
			allowedUsers:     []string{"other.example.com"},
			expectedIdentity: "client.example.com",
			expectedStatus:   http.StatusForbidden,
			description:      "DNSName SAN extracted but user not in allowed list",
		},
		{
			name: "URISANNotAllowed",
			clientCertOptions: &tlsutils.CertificateOptions{
				URIs: []string{"spiffe://example.org/workload/testuser"},
			},
			mtlsConfig: &config.MTLSConfig{
				IdentityAttibutes: []string{"URI"},
			},
			allowedUsers:     []string{"spiffe://example.org/workload/other"},
			expectedIdentity: "spiffe://example.org/workload/testuser",
			expectedStatus:   http.StatusForbidden,
			description:      "URI SAN extracted but user not in allowed list",
		},
		{
			name: "URISANRegexNotAllowed",
			clientCertOptions: &tlsutils.CertificateOptions{
				URIs: []string{"spiffe://example.org/workload/testuser"},
			},
			mtlsConfig: &config.MTLSConfig{
				IdentityAttibutes: []string{"URI"},
				URISANPattern:     "spiffe://example.org/workload/(.*)",
			},
			allowedUsers:     []string{"otheruser"},
			expectedIdentity: "testuser",
			expectedStatus:   http.StatusForbidden,
			description:      "URI SAN regex extracted but user not in allowed list",
		},
		{
			name:              "NoIdentitySource",
			clientCertOptions: &tlsutils.CertificateOptions{
				// No CN, no SANs
			},
			mtlsConfig: &config.MTLSConfig{
				IdentityAttibutes: []string{"CommonName"},
			},
			allowedUsers:     []string{},
			expectedIdentity: "",
			expectedStatus:   http.StatusUnauthorized, // 401 means auth failed
			description:      "No identity found in certificate",
		},
		{
			name:              "DefaultConfigWithoutCN",
			clientCertOptions: &tlsutils.CertificateOptions{
				// CommonName intentionally not set - no CN, no SANs
			},
			mtlsConfig:       nil,        // Default behavior (should default to CommonName)
			allowedUsers:     []string{}, // Not used - authentication fails before authorization is checked
			expectedIdentity: "",
			expectedStatus:   http.StatusUnauthorized, // 401 means auth failed - no CN to extract
			description: "Default config (CommonName) with certificate without CN - " +
				"authentication fails before authorization",
		},
		{
			name:              "FallbackChainAllFail",
			clientCertOptions: &tlsutils.CertificateOptions{
				// No CN, no SANs
			},
			mtlsConfig: &config.MTLSConfig{
				IdentityAttibutes: []string{"Email", "DNSName", "CommonName"},
			},
			allowedUsers:     []string{},
			expectedIdentity: "",
			expectedStatus:   http.StatusUnauthorized,
			description:      "Fallback chain fails when no identity attributes are available",
		},
		{
			name: "InvalidURISANIndex",
			clientCertOptions: &tlsutils.CertificateOptions{
				URIs: []string{"spiffe://example.org/workload/testuser"},
			},
			mtlsConfig: &config.MTLSConfig{
				IdentityAttibutes: []string{"URI"},
				URISANIndex:       5, // Out of range
			},
			allowedUsers:     []string{},
			expectedIdentity: "",
			expectedStatus:   http.StatusUnauthorized,
			description:      "URI SAN index out of range",
		},
		{
			name: "InvalidDNSANIndex",
			clientCertOptions: &tlsutils.CertificateOptions{
				DNSNames: []string{"client.example.com"},
			},
			mtlsConfig: &config.MTLSConfig{
				IdentityAttibutes: []string{"DNSName"},
				DNSANIndex:        5, // Out of range
			},
			allowedUsers:     []string{},
			expectedIdentity: "",
			expectedStatus:   http.StatusUnauthorized,
			description:      "DNS SAN index out of range",
		},
		{
			name: "InvalidEmailSANIndex",
			clientCertOptions: &tlsutils.CertificateOptions{
				EmailAddresses: []string{"testuser@example.com"},
			},
			mtlsConfig: &config.MTLSConfig{
				IdentityAttibutes: []string{"Email"},
				EmailSANIndex:     5, // Out of range
			},
			allowedUsers:     []string{},
			expectedIdentity: "",
			expectedStatus:   http.StatusUnauthorized,
			description:      "Email SAN index out of range",
		},
		{
			name: "URISANRegexNoMatch",
			clientCertOptions: &tlsutils.CertificateOptions{
				URIs: []string{"spiffe://example.org/workload/testuser"},
			},
			mtlsConfig: &config.MTLSConfig{
				IdentityAttibutes: []string{"URI"},
				URISANPattern:     "spiffe://other.org/workload/(.*)", // Won't match
			},
			allowedUsers:     []string{},
			expectedIdentity: "",
			expectedStatus:   http.StatusUnauthorized,
			description:      "URI SAN regex pattern doesn't match",
		},
		{
			name: "NoURISANFound",
			clientCertOptions: &tlsutils.CertificateOptions{
				CommonName: "testuser", // Has CN but no URIs
			},
			mtlsConfig: &config.MTLSConfig{
				IdentityAttibutes: []string{"URI"}, // Try to extract from URL but cert has no URIs
			},
			allowedUsers:     []string{},
			expectedIdentity: "",
			expectedStatus:   http.StatusUnauthorized,
			description:      "No URI SAN found in certificate when URL is requested",
		},
		{
			name: "InvalidURISANPattern",
			clientCertOptions: &tlsutils.CertificateOptions{
				URIs: []string{"spiffe://example.org/workload/testuser"},
			},
			mtlsConfig: &config.MTLSConfig{
				IdentityAttibutes: []string{"URI"},
				URISANPattern:     "[invalid(regex", // Invalid regex pattern
			},
			allowedUsers:     []string{},
			expectedIdentity: "",
			expectedStatus:   http.StatusUnauthorized,
			description:      "Invalid URI SAN regex pattern",
		},
		{
			name: "UnsupportedIdentitySource",
			clientCertOptions: &tlsutils.CertificateOptions{
				CommonName: "testuser",
			},
			mtlsConfig: &config.MTLSConfig{
				IdentityAttibutes: []string{"InvalidSource"}, // Unsupported source
			},
			allowedUsers:     []string{},
			expectedIdentity: "",
			expectedStatus:   http.StatusUnauthorized,
			description:      "Unsupported identity source",
		},
	}

	Convey("Test mTLS identity extraction", t, func() {
		for _, tc := range testCases {
			Convey(tc.description+" ("+tc.name+")", func() {
				runMTLSTest(t, tc)
			})
		}
	})
}

func TestMTLSAuthentication(t *testing.T) {
	// Create temporary directory for certificates
	tempDir := t.TempDir()

	// Generate CA certificate
	caCert, caKey, err := tlsutils.GenerateCACert()
	if err != nil {
		panic(err)
	}
	caCertPath := path.Join(tempDir, "ca.crt")
	err = os.WriteFile(caCertPath, caCert, 0o600)
	if err != nil {
		panic(err)
	}

	// Generate server certificate
	serverCertPath := path.Join(tempDir, "server.crt")
	serverKeyPath := path.Join(tempDir, "server.key")
	opts := &tlsutils.CertificateOptions{
		Hostname: "localhost",
	}
	err = tlsutils.GenerateServerCertToFile(caCert, caKey, serverCertPath, serverKeyPath, opts)
	if err != nil {
		panic(err)
	}

	// Generate valid client certificate for "testuser" user
	clientCertPath := path.Join(tempDir, "client.crt")
	clientKeyPath := path.Join(tempDir, "client.key")
	clientOpts := &tlsutils.CertificateOptions{
		CommonName: "testuser",
	}
	err = tlsutils.GenerateClientCertToFile(caCert, caKey, clientCertPath, clientKeyPath, clientOpts)
	if err != nil {
		panic(err)
	}

	// Generate self-signed client cert for "testuser" user
	selfSignedClientCertPath := path.Join(tempDir, "client-selfsigned.crt")
	selfSignedClientKeyPath := path.Join(tempDir, "client-selfsigned.key")
	selfSignedOpts := &tlsutils.CertificateOptions{
		CommonName: "testuser",
	}
	err = tlsutils.GenerateClientSelfSignedCertToFile(selfSignedClientCertPath, selfSignedClientKeyPath, selfSignedOpts)
	if err != nil {
		panic(err)
	}

	// Create htpasswd file with sample "httpuser"
	htpasswdPath := test.MakeHtpasswdFileFromString(t, test.GetBcryptCredString("httpuser", "httppass"))
	defer os.Remove(htpasswdPath)

	Convey("Test mTLS-only authentication", t, func() {
		// Set up server
		conf := config.New()
		port := test.GetFreePort()
		baseURL := test.GetSecureBaseURL(port)

		conf.HTTP.Port = port
		conf.HTTP.TLS = &config.TLSConfig{
			Cert:   serverCertPath,
			Key:    serverKeyPath,
			CACert: caCertPath,
		}
		conf.HTTP.AccessControl = &config.AccessControlConfig{
			Groups: config.Groups{
				"mtls-users": config.Group{
					Users: []string{"testuser"},
				},
			},
			Repositories: config.Repositories{
				"**": config.PolicyGroup{ // Default restrict all
					AnonymousPolicy: make([]string, 0),
					Policies:        make([]config.Policy, 0),
				},
				"test-repo": config.PolicyGroup{
					Policies: []config.Policy{
						{
							Users:   []string{"testuser"},
							Actions: []string{"read", "create"},
						},
					},
				},
			},
		}
		conf.Storage.RootDirectory = t.TempDir()

		ctlr := api.NewController(conf)
		cm := test.NewControllerManager(ctlr)

		cm.StartAndWait(port)
		defer cm.StopServer()

		// Test without client certificate - should fail
		caCertPEM, err := os.ReadFile(caCertPath)
		So(err, ShouldBeNil)

		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(caCertPEM)

		client := resty.New()
		client.SetTLSClientConfig(&tls.Config{RootCAs: caCertPool, MinVersion: tls.VersionTLS13})
		resp, err := client.R().Get(baseURL + "/v2/test-repo/tags/list")
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusUnauthorized)

		// Test with valid client certificate - should succeed
		clientCert, err := tls.LoadX509KeyPair(clientCertPath, clientKeyPath)
		So(err, ShouldBeNil)

		client = resty.New()
		client.SetTLSClientConfig(&tls.Config{
			MinVersion:   tls.VersionTLS13,
			Certificates: []tls.Certificate{clientCert},
			RootCAs:      caCertPool,
		})

		resp, err = client.R().Get(baseURL + "/v2/test-repo/tags/list")
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusNotFound) // 404 meaning we successfully passed auth

		// Test with self-signed client certificate - should fail
		selfSignedClientCert, err := tls.LoadX509KeyPair(selfSignedClientCertPath, selfSignedClientKeyPath)
		So(err, ShouldBeNil)

		client = resty.New()
		client.SetTLSClientConfig(&tls.Config{
			MinVersion:   tls.VersionTLS13,
			Certificates: []tls.Certificate{selfSignedClientCert},
			RootCAs:      caCertPool,
		})

		resp, err = client.R().Get(baseURL + "/v2/test-selfsigned-repo/tags/list")
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusUnauthorized)
	})

	Convey("Test mTLS with basic auth and user/group access policies", t, func() {
		// Set up server
		conf := config.New()
		port := test.GetFreePort()
		baseURL := test.GetSecureBaseURL(port)

		conf.HTTP.Port = port
		conf.HTTP.TLS = &config.TLSConfig{
			Cert:   serverCertPath,
			Key:    serverKeyPath,
			CACert: caCertPath,
		}
		conf.HTTP.Auth = &config.AuthConfig{
			HTPasswd: config.AuthHTPasswd{
				Path: htpasswdPath,
			},
		}
		conf.HTTP.AccessControl = &config.AccessControlConfig{
			Groups: config.Groups{
				"mtls-users": config.Group{
					Users: []string{"testuser"},
				},
			},
			Repositories: config.Repositories{
				"**": config.PolicyGroup{ // Default restrict all
					AnonymousPolicy: make([]string, 0),
					Policies:        make([]config.Policy, 0),
				},
				"group-repo": config.PolicyGroup{
					Policies: []config.Policy{
						{
							Groups:  []string{"mtls-users"},
							Actions: []string{"read", "create"},
						},
					},
				},
				"test-repo": config.PolicyGroup{
					Policies: []config.Policy{
						{
							Users:   []string{"testuser"},
							Actions: []string{"read", "create"},
						},
					},
				},
				"htpasswd-repo": config.PolicyGroup{
					Policies: []config.Policy{
						{
							Users:   []string{"httpuser"},
							Actions: []string{"read", "create"},
						},
					},
				},
			},
		}
		conf.Storage.RootDirectory = t.TempDir()

		ctlr := api.NewController(conf)
		cm := test.NewControllerManager(ctlr)

		cm.StartAndWait(port)
		defer cm.StopServer()

		// Load server CA certificate
		caCertPEM, err := os.ReadFile(caCertPath)
		So(err, ShouldBeNil)

		// Load self-signed client certificate
		selfSignedClientCert, err := tls.LoadX509KeyPair(selfSignedClientCertPath, selfSignedClientKeyPath)
		So(err, ShouldBeNil)

		// Load valid client certificate with CN "testuser"
		clientCert, err := tls.LoadX509KeyPair(clientCertPath, clientKeyPath)
		So(err, ShouldBeNil)

		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(caCertPEM)

		// Tests without client certificate
		client := resty.New()
		client.SetTLSClientConfig(&tls.Config{RootCAs: caCertPool, MinVersion: tls.VersionTLS13})
		resp, err := client.R().SetBasicAuth("httpuser", "httppass").Get(baseURL + "/v2/htpasswd-repo/tags/list")
		// Test without client CA but with htpasswd credentials - should pass because of valid htpasswd credentials
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusNotFound) // 404 meaning we successfully passed auth

		// Tests with self-signed (== non-acceptable by server) client certificate
		client = resty.New()
		client.SetTLSClientConfig(&tls.Config{
			MinVersion:   tls.VersionTLS13,
			Certificates: []tls.Certificate{selfSignedClientCert},
			RootCAs:      caCertPool,
		})

		// Test with self-signed client certificate - should still pass because of correct htpasswd auth
		resp, err = client.R().SetBasicAuth("httpuser", "httppass").Get(baseURL + "/v2/htpasswd-repo/tags/list")
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusNotFound) // 404 meaning we successfully passed auth

		// Tests with valid client certificate
		client = resty.New()
		client.SetTLSClientConfig(&tls.Config{
			MinVersion:   tls.VersionTLS13,
			Certificates: []tls.Certificate{clientCert},
			RootCAs:      caCertPool,
		})
		// Tests with valid client cert and creds - should fail with 403 due to no permissions for user from basic auth
		// This validates that identity from basic auth has higher priority over mTLS identity
		resp, err = client.R().SetBasicAuth("httpuser", "httppass").Get(baseURL + "/v2/test-repo/tags/list")
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusForbidden)

		// Test with correct auth credentials and different basic auth username from client certificate CN - should success
		// This validates that identity from basic auth has higher priority over mTLS identity
		resp, err = client.R().SetBasicAuth("httpuser", "httppass").Get(baseURL + "/v2/htpasswd-repo/tags/list")
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusNotFound) // 404 meaning we successfully passed auth

		// Should have access to test-repo for identity from client-cert
		resp, err = client.R().Get(baseURL + "/v2/test-repo/tags/list")
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusNotFound) // 404 meaning we successfully passed auth

		// Should not have access to other repos for identity from client-cert
		resp, err = client.R().Get(baseURL + "/v2/unauthorized-repo/tags/list")
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusForbidden)

		// Should have access to group-repo through group membership for identity from client-cert
		resp, err = client.R().Get(baseURL + "/v2/group-repo/tags/list")
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusNotFound) // 404 meaning we successfully passed auth
	})
}

func TestMTLSAuthenticationWithCertificateChain(t *testing.T) {
	// Create temporary directory for certificates
	tempDir := t.TempDir()

	Convey("Test mTLS with certificate chain - uses leaf certificate identity", t, func() {
		// Create certificate chain: Root CA -> Intermediate CA -> Client Certificate
		// Generate root CA
		rootCACert, rootCAKey, err := tlsutils.GenerateCACert()
		So(err, ShouldBeNil)
		rootCACertPath := path.Join(tempDir, "root-ca.crt")
		err = os.WriteFile(rootCACertPath, rootCACert, 0o600)
		So(err, ShouldBeNil)

		// Generate intermediate CA (signed by root CA)
		intermediateCAOpts := &tlsutils.CertificateOptions{
			CommonName: "Intermediate CA",
		}
		intermediateCACert, intermediateCAKeyPEM, err := tlsutils.GenerateIntermediateCACert(
			rootCACert, rootCAKey, intermediateCAOpts)
		So(err, ShouldBeNil)

		// Generate client certificate with CN signed by intermediate CA
		clientWithCNOpts := &tlsutils.CertificateOptions{
			CommonName: "clientuser",
		}
		clientCertWithCN, clientKeyWithCN, err := tlsutils.GenerateClientCert(
			intermediateCACert, intermediateCAKeyPEM, clientWithCNOpts)
		So(err, ShouldBeNil)

		// Generate client certificate without CN signed by intermediate CA
		clientWithoutCNOpts := &tlsutils.CertificateOptions{
			// No CommonName - empty to test that identity is not taken from intermediate CA
		}
		clientCertWithoutCN, clientKeyWithoutCNPEM, err := tlsutils.GenerateClientCert(
			intermediateCACert, intermediateCAKeyPEM, clientWithoutCNOpts)
		So(err, ShouldBeNil)

		// Generate server certificate signed by root CA for this test
		serverCertForChainPath := path.Join(tempDir, "server-chain.crt")
		serverKeyForChainPath := path.Join(tempDir, "server-chain.key")
		serverOpts := &tlsutils.CertificateOptions{
			Hostname: "localhost",
		}
		err = tlsutils.GenerateServerCertToFile(
			rootCACert, rootCAKey, serverCertForChainPath, serverKeyForChainPath, serverOpts)
		So(err, ShouldBeNil)

		// Set up server with root CA
		conf := config.New()
		port := test.GetFreePort()
		baseURL := test.GetSecureBaseURL(port)

		conf.HTTP.Port = port
		conf.HTTP.TLS = &config.TLSConfig{
			Cert:   serverCertForChainPath,
			Key:    serverKeyForChainPath,
			CACert: rootCACertPath, // Server trusts root CA
		}
		conf.HTTP.AccessControl = &config.AccessControlConfig{
			Repositories: config.Repositories{
				"**": config.PolicyGroup{
					AnonymousPolicy: make([]string, 0),
					Policies:        make([]config.Policy, 0),
				},
				"client-repo": config.PolicyGroup{
					Policies: []config.Policy{
						{
							Users:   []string{"clientuser"},
							Actions: []string{"read", "create"},
						},
					},
				},
			},
		}
		conf.Storage.RootDirectory = t.TempDir()

		ctlr := api.NewController(conf)
		cm := test.NewControllerManager(ctlr)

		cm.StartAndWait(port)
		defer cm.StopServer()

		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(rootCACert)

		// Test 1: Client cert with CN in chain - should use client cert CN, not intermediate CA CN
		clientCertWithCNPath := path.Join(tempDir, "client-with-cn.crt")
		clientKeyWithCNPath := path.Join(tempDir, "client-with-cn.key")
		err = os.WriteFile(clientCertWithCNPath, clientCertWithCN, 0o600)
		So(err, ShouldBeNil)
		err = os.WriteFile(clientKeyWithCNPath, clientKeyWithCN, 0o600)
		So(err, ShouldBeNil)

		// Create certificate chain file (client cert + intermediate CA)
		chainCertPath := path.Join(tempDir, "client-with-cn-chain.crt")
		err = tlsutils.WriteCertificateChainToFile(chainCertPath, clientCertWithCN, intermediateCACert)
		So(err, ShouldBeNil)

		// Load certificate chain
		clientCertChain, err := tls.LoadX509KeyPair(chainCertPath, clientKeyWithCNPath)
		So(err, ShouldBeNil)

		client := resty.New()
		client.SetTLSClientConfig(&tls.Config{
			MinVersion:   tls.VersionTLS13,
			Certificates: []tls.Certificate{clientCertChain},
			RootCAs:      caCertPool,
		})

		// Should succeed because client cert has CN "clientuser" which matches policy
		resp, err := client.R().Get(baseURL + "/v2/client-repo/tags/list")
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusNotFound) // 404 means auth passed

		// Test 2: Client cert without CN in chain - should fail, not use intermediate CA CN
		clientCertWithoutCNPath := path.Join(tempDir, "client-without-cn.crt")
		clientKeyWithoutCNPath := path.Join(tempDir, "client-without-cn.key")
		err = os.WriteFile(clientCertWithoutCNPath, clientCertWithoutCN, 0o600)
		So(err, ShouldBeNil)
		err = os.WriteFile(clientKeyWithoutCNPath, clientKeyWithoutCNPEM, 0o600)
		So(err, ShouldBeNil)

		// Create certificate chain file (client cert without CN + intermediate CA)
		chainCertWithoutCNPath := path.Join(tempDir, "client-without-cn-chain.crt")
		err = tlsutils.WriteCertificateChainToFile(chainCertWithoutCNPath, clientCertWithoutCN, intermediateCACert)
		So(err, ShouldBeNil)

		// Load certificate chain
		clientCertChainWithoutCN, err := tls.LoadX509KeyPair(chainCertWithoutCNPath, clientKeyWithoutCNPath)
		So(err, ShouldBeNil)

		client = resty.New()
		client.SetTLSClientConfig(&tls.Config{
			MinVersion:   tls.VersionTLS13,
			Certificates: []tls.Certificate{clientCertChainWithoutCN},
			RootCAs:      caCertPool,
		})

		// Should fail because client cert has no CN, even though intermediate CA has CN
		resp, err = client.R().Get(baseURL + "/v2/client-repo/tags/list")
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusUnauthorized)
	})
}

func TestMTLSAuthenticationWithExpiredCertificate(t *testing.T) {
	// Create temporary directory for certificates
	tempDir := t.TempDir()

	Convey("Test mTLS authentication with expired certificate", t, func() {
		// Generate CA certificate
		caCert, caKey, err := tlsutils.GenerateCACert()
		So(err, ShouldBeNil)
		caCertPath := path.Join(tempDir, "ca.crt")
		err = os.WriteFile(caCertPath, caCert, 0o600)
		So(err, ShouldBeNil)

		// Generate server certificate
		serverCertPath := path.Join(tempDir, "server.crt")
		serverKeyPath := path.Join(tempDir, "server.key")
		opts := &tlsutils.CertificateOptions{
			Hostname: "localhost",
		}
		err = tlsutils.GenerateServerCertToFile(caCert, caKey, serverCertPath, serverKeyPath, opts)
		So(err, ShouldBeNil)

		// Generate expired client certificate (NotAfter is in the past)
		expiredClientCertPath := path.Join(tempDir, "client-expired.crt")
		expiredClientKeyPath := path.Join(tempDir, "client-expired.key")
		expiredOpts := &tlsutils.CertificateOptions{
			CommonName: "testuser",
			NotBefore:  time.Now().Add(-365 * 24 * time.Hour), // 1 year ago
			NotAfter:   time.Now().Add(-24 * time.Hour),       // 1 day ago (expired)
		}
		err = tlsutils.GenerateClientCertToFile(caCert, caKey, expiredClientCertPath, expiredClientKeyPath, expiredOpts)
		So(err, ShouldBeNil)

		// Set up server
		conf := config.New()
		port := test.GetFreePort()
		baseURL := test.GetSecureBaseURL(port)

		conf.HTTP.Port = port
		conf.HTTP.TLS = &config.TLSConfig{
			Cert:   serverCertPath,
			Key:    serverKeyPath,
			CACert: caCertPath,
		}
		conf.HTTP.AccessControl = &config.AccessControlConfig{
			Repositories: config.Repositories{
				"**": config.PolicyGroup{
					AnonymousPolicy: make([]string, 0),
					Policies:        make([]config.Policy, 0),
				},
				"test-repo": config.PolicyGroup{
					Policies: []config.Policy{
						{
							Users:   []string{"testuser"},
							Actions: []string{"read", "create"},
						},
					},
				},
			},
		}
		conf.Storage.RootDirectory = t.TempDir()

		ctlr := api.NewController(conf)
		cm := test.NewControllerManager(ctlr)

		cm.StartAndWait(port)
		defer cm.StopServer()

		// Set up client with expired certificate
		caCertPEM, err := os.ReadFile(caCertPath)
		So(err, ShouldBeNil)

		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(caCertPEM)

		expiredClientCert, err := tls.LoadX509KeyPair(expiredClientCertPath, expiredClientKeyPath)
		So(err, ShouldBeNil)

		client := resty.New()
		client.SetTLSClientConfig(&tls.Config{
			MinVersion:   tls.VersionTLS13,
			Certificates: []tls.Certificate{expiredClientCert},
			RootCAs:      caCertPool,
		})

		// Expired certificate should be rejected at TLS handshake level
		// The TLS stack will reject it before it reaches the application layer
		_, err = client.R().Get(baseURL + "/v2/test-repo/tags/list")
		// Error is expected - TLS handshake fails with expired certificate
		So(err, ShouldNotBeNil)
		So(err.Error(), ShouldContainSubstring, "expired certificate")
	})
}

func TestMTLSAuthenticationWithUnknownCA(t *testing.T) {
	// Create temporary directory for certificates
	tempDir := t.TempDir()

	Convey("Test mTLS authentication with certificate signed by unknown CA", t, func() {
		// Generate server CA and certificate
		serverCACert, serverCAKey, err := tlsutils.GenerateCACert()
		So(err, ShouldBeNil)
		serverCACertPath := path.Join(tempDir, "server-ca.crt")
		err = os.WriteFile(serverCACertPath, serverCACert, 0o600)
		So(err, ShouldBeNil)

		serverCertPath := path.Join(tempDir, "server.crt")
		serverKeyPath := path.Join(tempDir, "server.key")
		opts := &tlsutils.CertificateOptions{
			Hostname: "localhost",
		}
		err = tlsutils.GenerateServerCertToFile(serverCACert, serverCAKey, serverCertPath, serverKeyPath, opts)
		So(err, ShouldBeNil)

		// Generate a different CA (unknown to the server) and client certificate
		unknownCACert, unknownCAKey, err := tlsutils.GenerateCACert()
		So(err, ShouldBeNil)

		unknownClientCertPath := path.Join(tempDir, "client-unknown-ca.crt")
		unknownClientKeyPath := path.Join(tempDir, "client-unknown-ca.key")
		clientOpts := &tlsutils.CertificateOptions{
			CommonName: "testuser",
		}
		err = tlsutils.GenerateClientCertToFile(unknownCACert, unknownCAKey, unknownClientCertPath,
			unknownClientKeyPath, clientOpts)
		So(err, ShouldBeNil)

		// Set up server with server CA (doesn't know about unknown CA)
		conf := config.New()
		port := test.GetFreePort()
		baseURL := test.GetSecureBaseURL(port)

		conf.HTTP.Port = port
		conf.HTTP.TLS = &config.TLSConfig{
			Cert:   serverCertPath,
			Key:    serverKeyPath,
			CACert: serverCACertPath, // Server only trusts serverCACert, not unknownCACert
		}
		conf.HTTP.AccessControl = &config.AccessControlConfig{
			Repositories: config.Repositories{
				"**": config.PolicyGroup{
					AnonymousPolicy: make([]string, 0),
					Policies:        make([]config.Policy, 0),
				},
				"test-repo": config.PolicyGroup{
					Policies: []config.Policy{
						{
							Users:   []string{"testuser"},
							Actions: []string{"read", "create"},
						},
					},
				},
			},
		}
		conf.Storage.RootDirectory = t.TempDir()

		ctlr := api.NewController(conf)
		cm := test.NewControllerManager(ctlr)

		cm.StartAndWait(port)
		defer cm.StopServer()

		// Set up client with certificate signed by unknown CA
		serverCACertPEM, err := os.ReadFile(serverCACertPath)
		So(err, ShouldBeNil)

		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(serverCACertPEM)

		unknownClientCert, err := tls.LoadX509KeyPair(unknownClientCertPath, unknownClientKeyPath)
		So(err, ShouldBeNil)

		client := resty.New()
		client.SetTLSClientConfig(&tls.Config{
			MinVersion:   tls.VersionTLS13,
			Certificates: []tls.Certificate{unknownClientCert},
			RootCAs:      caCertPool,
		})

		// Certificate signed by unknown CA should be rejected at TLS handshake level
		// The TLS stack will reject it before it reaches the application layer
		_, err = client.R().Get(baseURL + "/v2/test-repo/tags/list")
		// Error is expected - TLS handshake fails with unknown certificate authority
		So(err, ShouldNotBeNil)
		So(err.Error(), ShouldContainSubstring, "unknown certificate authority")
	})
}

func TestMTLSAuthenticationWithMetaDBError(t *testing.T) {
	// Create temporary directory for certificates
	tempDir := t.TempDir()

	Convey("Test mTLS authentication with MetaDB.SetUserGroups error", t, func() {
		// Generate CA certificate
		caCert, caKey, err := tlsutils.GenerateCACert()
		So(err, ShouldBeNil)
		caCertPath := path.Join(tempDir, "ca.crt")
		err = os.WriteFile(caCertPath, caCert, 0o600)
		So(err, ShouldBeNil)

		// Generate server certificate
		serverCertPath := path.Join(tempDir, "server.crt")
		serverKeyPath := path.Join(tempDir, "server.key")
		opts := &tlsutils.CertificateOptions{
			Hostname: "localhost",
		}
		err = tlsutils.GenerateServerCertToFile(caCert, caKey, serverCertPath, serverKeyPath, opts)
		So(err, ShouldBeNil)

		// Generate valid client certificate for "testuser" user
		clientCertPath := path.Join(tempDir, "client.crt")
		clientKeyPath := path.Join(tempDir, "client.key")
		clientOpts := &tlsutils.CertificateOptions{
			CommonName: "testuser",
		}
		err = tlsutils.GenerateClientCertToFile(caCert, caKey, clientCertPath, clientKeyPath, clientOpts)
		So(err, ShouldBeNil)

		// Set up server
		conf := config.New()
		port := test.GetFreePort()
		baseURL := test.GetSecureBaseURL(port)

		conf.HTTP.Port = port
		conf.HTTP.TLS = &config.TLSConfig{
			Cert:   serverCertPath,
			Key:    serverKeyPath,
			CACert: caCertPath,
		}
		conf.HTTP.AccessControl = &config.AccessControlConfig{
			Groups: config.Groups{
				"mtls-users": config.Group{
					Users: []string{"testuser"},
				},
			},
			Repositories: config.Repositories{
				"**": config.PolicyGroup{
					AnonymousPolicy: make([]string, 0),
					Policies:        make([]config.Policy, 0),
				},
				"test-repo": config.PolicyGroup{
					Policies: []config.Policy{
						{
							Users:   []string{"testuser"},
							Actions: []string{"read", "create"},
						},
					},
				},
			},
		}
		conf.Storage.RootDirectory = t.TempDir()

		ctlr := api.NewController(conf)
		cm := test.NewControllerManager(ctlr)

		cm.StartAndWait(port)
		defer cm.StopServer()

		// Set up client with valid certificate
		caCertPEM, err := os.ReadFile(caCertPath)
		So(err, ShouldBeNil)

		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(caCertPEM)

		clientCert, err := tls.LoadX509KeyPair(clientCertPath, clientKeyPath)
		So(err, ShouldBeNil)

		client := resty.New()
		client.SetTLSClientConfig(&tls.Config{
			MinVersion:   tls.VersionTLS13,
			Certificates: []tls.Certificate{clientCert},
			RootCAs:      caCertPool,
		})

		// Mock MetaDB to return error on SetUserGroups
		ctlr.MetaDB = mocks.MetaDBMock{
			SetUserGroupsFn: func(ctx context.Context, groups []string) error {
				return ErrUnexpectedError
			},
		}

		// Should return 500 Internal Server Error due to MetaDB error
		resp, err := client.R().Get(baseURL + "/v2/test-repo/tags/list")
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusInternalServerError)
	})
}

func TestMutualTLSAuthWithUserPermissions(t *testing.T) {
	Convey("Make a new controller", t, func() {
		caCertPath, serverCertPath, serverKeyPath, clientCertPath, clientKeyPath, caCertPEM := setupTestCerts(t)

		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(caCertPEM)

		port := test.GetFreePort()
		baseURL := test.GetBaseURL(port)
		secureBaseURL := test.GetSecureBaseURL(port)

		resty.SetTLSClientConfig(&tls.Config{RootCAs: caCertPool, MinVersion: tls.VersionTLS12})

		defer func() { resty.SetTLSClientConfig(nil) }()

		conf := config.New()
		conf.HTTP.Port = port

		conf.HTTP.TLS = &config.TLSConfig{
			Cert:   serverCertPath,
			Key:    serverKeyPath,
			CACert: caCertPath,
		}

		conf.HTTP.AccessControl = &config.AccessControlConfig{
			Repositories: config.Repositories{
				test.AuthorizationAllRepos: config.PolicyGroup{
					Policies: []config.Policy{
						{
							Users:   []string{"testclient"},
							Actions: []string{"read"},
						},
					},
				},
			},
		}

		ctlr := api.NewController(conf)
		ctlr.Config.Storage.RootDirectory = t.TempDir()

		cm := test.NewControllerManager(ctlr)
		cm.StartAndWait(port)

		defer cm.StopServer()

		resp, err := resty.R().Get(baseURL)
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusBadRequest)

		repoPolicy := conf.HTTP.AccessControl.Repositories[test.AuthorizationAllRepos]

		// setup TLS mutual auth
		cert, err := tls.LoadX509KeyPair(clientCertPath, clientKeyPath)
		So(err, ShouldBeNil)

		// Use separate resty client with certificates, because we cannot perform cleanup with resty.SetCertificates()
		client := resty.New().SetTLSClientConfig(&tls.Config{
			RootCAs:      caCertPool,
			MinVersion:   tls.VersionTLS12,
			Certificates: []tls.Certificate{cert},
		})

		// with client certs but without creds, should succeed
		resp, err = client.R().Get(secureBaseURL + "/v2/")
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)

		resp, err = client.R().Get(secureBaseURL + "/v2/_catalog")
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)

		// with creds, should get expected status code
		resp, _ = client.R().Get(secureBaseURL)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusNotFound)

		// reading a repo should not get 403
		resp, err = client.R().Get(secureBaseURL + "/v2/repo/tags/list")
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusNotFound)

		// without creds, writes should fail
		resp, err = client.R().Post(secureBaseURL + "/v2/repo/blobs/uploads/")
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusForbidden)

		// empty default authorization and give user the permission to create
		repoPolicy.Policies[0].Actions = append(repoPolicy.Policies[0].Actions, "create")
		conf.HTTP.AccessControl.Repositories[test.AuthorizationAllRepos] = repoPolicy
		resp, err = client.R().Post(secureBaseURL + "/v2/repo/blobs/uploads/")
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusAccepted)
	})
}

func TestTLSMutualAuth(t *testing.T) {
	Convey("Make a new controller", t, func() {
		caCertPath, serverCertPath, serverKeyPath, clientCertPath, clientKeyPath, caCertPEM := setupTestCerts(t)

		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(caCertPEM)

		port := test.GetFreePort()
		baseURL := test.GetBaseURL(port)
		secureBaseURL := test.GetSecureBaseURL(port)

		conf := config.New()
		conf.HTTP.Port = port
		conf.HTTP.TLS = &config.TLSConfig{
			Cert:   serverCertPath,
			Key:    serverKeyPath,
			CACert: caCertPath,
		}

		ctlr := api.NewController(conf)
		ctlr.Config.Storage.RootDirectory = t.TempDir()

		cm := test.NewControllerManager(ctlr)
		cm.StartAndWait(port)

		defer cm.StopServer()

		// access without any certificate settings
		client := resty.New()

		// accessing insecure HTTP site should fail
		resp, err := client.R().Get(baseURL)
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusBadRequest)

		// without client certs and creds, should get certificate verification error
		_, err = client.R().Get(secureBaseURL)
		So(err, ShouldNotBeNil)

		// without client certs should fail auth
		_, err = client.R().Get(secureBaseURL + "/v2/")
		So(err, ShouldNotBeNil)

		// Use resty client with certificates,
		client = resty.New().SetTLSClientConfig(&tls.Config{
			RootCAs:    caCertPool,
			MinVersion: tls.VersionTLS12,
		})

		// without client certs should fail auth
		resp, err = client.R().Get(secureBaseURL)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusNotFound)

		// without client certs should fail auth
		resp, _ = client.R().Get(secureBaseURL + "/v2/")
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusUnauthorized)

		username, seedUser := test.GenerateRandomString()
		password, seedPass := test.GenerateRandomString()
		ctlr.Log.Info().Int64("seedUser", seedUser).Int64("seedPass", seedPass).Msg("random seed for username & password")

		resp, err = client.R().SetBasicAuth(username, password).Get(secureBaseURL)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusNotFound)

		// with only creds, should get 401 because basic auth is disabled
		// (Authorization header should be rejected when the auth method is disabled, regardless of mTLS)
		resp, _ = client.R().SetBasicAuth(username, password).Get(secureBaseURL + "/v2/")
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusUnauthorized)

		// setup TLS mutual auth
		cert, err := tls.LoadX509KeyPair(clientCertPath, clientKeyPath)
		So(err, ShouldBeNil)

		client = resty.New().SetTLSClientConfig(&tls.Config{
			RootCAs:      caCertPool,
			MinVersion:   tls.VersionTLS12,
			Certificates: []tls.Certificate{cert},
		})

		// with client certs but without creds, should succeed
		resp, err = client.R().Get(secureBaseURL + "/v2/")
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)

		resp, _ = client.R().SetBasicAuth(username, password).Get(secureBaseURL)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusNotFound)

		// with client certs and creds, should get 401 because basic auth is disabled
		// (Authorization header should be rejected when the auth method is disabled, regardless of mTLS)
		resp, _ = client.R().SetBasicAuth(username, password).Get(secureBaseURL + "/v2/")
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusUnauthorized)
	})
}

func TestTLSMutualAuthAllowReadAccess(t *testing.T) {
	Convey("Make a new controller", t, func() {
		caCertPath, serverCertPath, serverKeyPath, clientCertPath, clientKeyPath, caCertPEM := setupTestCerts(t)

		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(caCertPEM)

		port := test.GetFreePort()
		baseURL := test.GetBaseURL(port)
		secureBaseURL := test.GetSecureBaseURL(port)

		// Use resty client with certificates,
		client := resty.New().SetTLSClientConfig(&tls.Config{
			RootCAs:    caCertPool,
			MinVersion: tls.VersionTLS12,
		})

		conf := config.New()
		conf.HTTP.Port = port
		conf.HTTP.TLS = &config.TLSConfig{
			Cert:   serverCertPath,
			Key:    serverKeyPath,
			CACert: caCertPath,
		}

		conf.HTTP.AccessControl = &config.AccessControlConfig{
			Repositories: config.Repositories{
				test.AuthorizationAllRepos: config.PolicyGroup{
					AnonymousPolicy: []string{"read"},
				},
			},
		}

		ctlr := api.NewController(conf)
		ctlr.Config.Storage.RootDirectory = t.TempDir()

		cm := test.NewControllerManager(ctlr)
		cm.StartAndWait(port)

		defer cm.StopServer()

		// accessing insecure HTTP site should fail
		resp, err := client.R().Get(baseURL)
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusBadRequest)

		// without client certs and creds, reads are allowed
		resp, err = client.R().Get(secureBaseURL + "/v2/")
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)

		username, seedUser := test.GenerateRandomString()
		password, seedPass := test.GenerateRandomString()

		ctlr.Log.Info().Int64("seedUser", seedUser).Int64("seedPass", seedPass).Msg("random seed for username & password")
		// with creds but without certs, reads are not allowed as server does not use basic auth
		// and basic auth headers are expected to contain valid credentials
		resp, err = client.R().SetBasicAuth(username, password).Get(secureBaseURL + "/v2/")
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusUnauthorized)

		// without creds, writes should fail
		resp, err = client.R().Post(secureBaseURL + "/v2/repo/blobs/uploads/")
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusUnauthorized)

		// setup TLS mutual auth
		cert, err := tls.LoadX509KeyPair(clientCertPath, clientKeyPath)
		So(err, ShouldBeNil)

		// Use separate resty client with certificates, because we cannot perform cleanup with resty.SetCertificates()
		client = resty.New().SetTLSClientConfig(&tls.Config{
			RootCAs:      caCertPool,
			MinVersion:   tls.VersionTLS12,
			Certificates: []tls.Certificate{cert},
		})

		// with client certs but without creds, should succeed
		resp, _ = client.R().Get(secureBaseURL)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusNotFound)

		// with client certs but without creds, should succeed
		resp, err = client.R().Get(secureBaseURL + "/v2/")
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)

		// with client certs and creds, reads are not allowed as server does not use basic auth
		// and basic auth headers are expected to contain valid credentials
		resp, _ = client.R().SetBasicAuth(username, password).Get(secureBaseURL)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusNotFound)

		// with client certs, reads are not allowed as server does not use basic auth
		resp, _ = client.R().SetBasicAuth(username, password).Get(secureBaseURL + "/v2/")
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusUnauthorized)
	})
}

func TestTLSMutualAndBasicAuth(t *testing.T) {
	Convey("Make a new controller", t, func() {
		caCertPath, serverCertPath, serverKeyPath, clientCertPath, clientKeyPath, caCertPEM := setupTestCerts(t)

		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(caCertPEM)

		username, seedUser := test.GenerateRandomString()
		password, seedPass := test.GenerateRandomString()

		htpasswdPath := test.MakeHtpasswdFileFromString(t, test.GetBcryptCredString(username, password))

		port := test.GetFreePort()
		baseURL := test.GetBaseURL(port)
		secureBaseURL := test.GetSecureBaseURL(port)

		resty.SetTLSClientConfig(&tls.Config{RootCAs: caCertPool, MinVersion: tls.VersionTLS12})

		defer func() { resty.SetTLSClientConfig(nil) }()

		conf := config.New()
		conf.HTTP.Port = port
		conf.HTTP.Auth = &config.AuthConfig{
			HTPasswd: config.AuthHTPasswd{
				Path: htpasswdPath,
			},
		}
		conf.HTTP.TLS = &config.TLSConfig{
			Cert:   serverCertPath,
			Key:    serverKeyPath,
			CACert: caCertPath,
		}

		ctlr := api.NewController(conf)
		ctlr.Config.Storage.RootDirectory = t.TempDir()
		ctlr.Log.Info().Int64("seedUser", seedUser).Int64("seedPass", seedPass).Msg("random seed for username & password")

		cm := test.NewControllerManager(ctlr)
		cm.StartAndWait(port)

		defer cm.StopServer()

		// accessing insecure HTTP site should fail
		resp, err := resty.R().Get(baseURL)
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusBadRequest)

		// without client certs and creds, should fail
		_, err = resty.R().Get(secureBaseURL)
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusBadRequest)

		// with creds but without certs, should succeed
		_, err = resty.R().SetBasicAuth(username, password).Get(secureBaseURL)
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusBadRequest)

		// setup TLS mutual auth
		cert, err := tls.LoadX509KeyPair(clientCertPath, clientKeyPath)
		So(err, ShouldBeNil)

		// Use separate resty client with certificates, because we cannot perform cleanup with resty.SetCertificates()
		client := resty.New().SetTLSClientConfig(&tls.Config{
			RootCAs:      caCertPool,
			MinVersion:   tls.VersionTLS12,
			Certificates: []tls.Certificate{cert},
		})

		// with client certs but without creds, succeed because mTLS is used for auth when no auth headers provided
		resp, err = client.R().Get(secureBaseURL + "/v2/")
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)

		// with client certs and creds, should get expected status code
		resp, _ = client.R().SetBasicAuth(username, password).Get(secureBaseURL)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusNotFound)

		resp, _ = client.R().SetBasicAuth(username, password).Get(secureBaseURL + "/v2/")
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)
	})
}

func TestTLSMutualAndBasicAuthAllowReadAccess(t *testing.T) {
	Convey("Make a new controller", t, func() {
		caCertPath, serverCertPath, serverKeyPath, clientCertPath, clientKeyPath, caCertPEM := setupTestCerts(t)

		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(caCertPEM)

		username, seedUser := test.GenerateRandomString()
		password, seedPass := test.GenerateRandomString()

		htpasswdPath := test.MakeHtpasswdFileFromString(t, test.GetBcryptCredString(username, password))

		port := test.GetFreePort()
		baseURL := test.GetBaseURL(port)
		secureBaseURL := test.GetSecureBaseURL(port)

		resty.SetTLSClientConfig(&tls.Config{RootCAs: caCertPool, MinVersion: tls.VersionTLS12})

		defer func() { resty.SetTLSClientConfig(nil) }()

		conf := config.New()
		conf.HTTP.Port = port
		conf.HTTP.Auth = &config.AuthConfig{
			HTPasswd: config.AuthHTPasswd{
				Path: htpasswdPath,
			},
		}
		conf.HTTP.TLS = &config.TLSConfig{
			Cert:   serverCertPath,
			Key:    serverKeyPath,
			CACert: caCertPath,
		}

		conf.HTTP.AccessControl = &config.AccessControlConfig{
			Repositories: config.Repositories{
				test.AuthorizationAllRepos: config.PolicyGroup{
					AnonymousPolicy: []string{"read"},
				},
			},
		}

		ctlr := api.NewController(conf)
		ctlr.Config.Storage.RootDirectory = t.TempDir()
		ctlr.Log.Info().Int64("seedUser", seedUser).Int64("seedPass", seedPass).Msg("random seed for username & password")

		cm := test.NewControllerManager(ctlr)
		cm.StartAndWait(port)

		defer cm.StopServer()

		// accessing insecure HTTP site should fail
		resp, err := resty.R().Get(baseURL)
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusBadRequest)

		// without client certs and creds, should fail
		_, err = resty.R().Get(secureBaseURL)
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusBadRequest)

		// with creds but without certs, should succeed
		_, err = resty.R().SetBasicAuth(username, password).Get(secureBaseURL)
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusBadRequest)

		// setup TLS mutual auth
		cert, err := tls.LoadX509KeyPair(clientCertPath, clientKeyPath)
		So(err, ShouldBeNil)

		// Use separate resty client with certificates, because we cannot perform cleanup with resty.SetCertificates()
		client := resty.New().SetTLSClientConfig(&tls.Config{
			RootCAs:      caCertPool,
			MinVersion:   tls.VersionTLS12,
			Certificates: []tls.Certificate{cert},
		})

		// with client certs but without creds, reads should succeed
		resp, err = client.R().Get(secureBaseURL + "/v2/")
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)

		// with only client certs, writes should fail with insufficient permissions
		resp, err = client.R().Post(secureBaseURL + "/v2/repo/blobs/uploads/")
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusForbidden)

		// with client certs and creds, should get expected status code
		resp, _ = client.R().SetBasicAuth(username, password).Get(secureBaseURL)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusNotFound)

		resp, _ = client.R().SetBasicAuth(username, password).Get(secureBaseURL + "/v2/")
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)
	})
}

func TestTSLFailedReadingOfCACert(t *testing.T) {
	Convey("no permissions", t, func() {
		caCertPath, serverCertPath, serverKeyPath, _, _, _ := setupTestCerts(t)
		port := test.GetFreePort()
		conf := config.New()
		conf.HTTP.Port = port
		conf.HTTP.TLS = &config.TLSConfig{
			Cert:   serverCertPath,
			Key:    serverKeyPath,
			CACert: caCertPath,
		}

		err := os.Chmod(caCertPath, 0o000)
		defer func() {
			err := os.Chmod(caCertPath, 0o644)
			So(err, ShouldBeNil)
		}()
		So(err, ShouldBeNil)

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		ctlr := api.NewController(conf)
		ctlr.Config.Storage.RootDirectory = t.TempDir()

		err = ctlr.Init()
		So(err, ShouldBeNil)

		errChan := make(chan error, 1)

		go func() {
			err = ctlr.Run()
			errChan <- err
		}()

		testTimeout := false

		select {
		case err := <-errChan:
			So(err, ShouldNotBeNil)
		case <-ctx.Done():
			testTimeout = true

			cancel()
		}

		So(testTimeout, ShouldBeFalse)
	})

	Convey("empty CACert", t, func() {
		badCACert := filepath.Join(t.TempDir(), "badCACert")
		err := os.WriteFile(badCACert, []byte(""), 0o600)
		So(err, ShouldBeNil)

		_, serverCertPath, serverKeyPath, _, _, _ := setupTestCerts(t)
		port := test.GetFreePort()
		conf := config.New()
		conf.HTTP.Port = port
		conf.HTTP.TLS = &config.TLSConfig{
			Cert:   serverCertPath,
			Key:    serverKeyPath,
			CACert: badCACert,
		}

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		ctlr := api.NewController(conf)
		ctlr.Config.Storage.RootDirectory = t.TempDir()

		err = ctlr.Init()
		So(err, ShouldBeNil)

		errChan := make(chan error, 1)

		go func() {
			err = ctlr.Run()
			errChan <- err
		}()

		testTimeout := false

		select {
		case err := <-errChan:
			So(err, ShouldNotBeNil)
		case <-ctx.Done():
			testTimeout = true

			cancel()
		}

		So(testTimeout, ShouldBeFalse)
	})
}
