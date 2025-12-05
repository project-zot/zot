package tls

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"os"
	"time"
)

var (
	ErrDecodeCAPEM                = errors.New("failed to decode CA certificate PEM")
	ErrInvalidCertificateType     = errors.New("invalid certificate type")
	ErrCertificateOptionsRequired = errors.New("CertificateOptions is required")
	ErrHostnameRequired           = errors.New("Hostname is required in CertificateOptions")
	ErrNoCertificatesProvided     = errors.New("at least one certificate is required")
)

const (
	certTypeCA     = "CA"
	certTypeServer = "Server"
	certTypeClient = "Client"
)

// CertificateOptions contains optional settings for certificate generation.
// If a field is nil or zero, default values will be used.
type CertificateOptions struct {
	// NotBefore is the certificate validity start time.
	// If zero, defaults to time.Now().
	NotBefore time.Time

	// NotAfter is the certificate validity end time.
	// If zero, defaults will be used based on certificate type.
	NotAfter time.Time

	// DNSNames contains the DNS names for the Subject Alternative Name extension.
	// If nil, default values may be used based on certificate type.
	DNSNames []string

	// IPAddresses contains the IP addresses for the Subject Alternative Name extension.
	// If nil, default values may be used based on certificate type.
	IPAddresses []net.IP

	// EmailAddresses contains the email addresses for the Subject Alternative Name extension.
	// If nil, no email addresses will be included.
	EmailAddresses []string

	// Hostname is the hostname or IP address for server certificates.
	// For server certificates, this is required and will be added to DNSNames or IPAddresses
	// based on whether it's a valid IP address or a DNS name.
	Hostname string

	// CommonName is the CommonName (CN) for client certificates.
	// For client certificates, this is optional - if not provided, the certificate will not have a CN.
	CommonName string
}

// generateCertificate is a helper function that generates a certificate and private key.
// If signerCert and signerKey are nil, the certificate will be self-signed.
func generateCertificate(
	certType string,
	opts *CertificateOptions,
	signerCert *x509.Certificate,
	signerKey *rsa.PrivateKey,
) ([]byte, []byte, error) {
	// Generate private key
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate private key: %w", err)
	}

	// Initialize certificate template
	template, err := initializeTemplate(certType)
	if err != nil {
		return nil, nil, err
	}

	// Apply options
	applyOptions(template, opts, certType)

	// Determine signer (self-signed if signerCert is nil)
	var issuerCert *x509.Certificate

	var issuerKey *rsa.PrivateKey
	if signerCert == nil {
		// Self-signed
		issuerCert = template
		issuerKey = privKey
	} else {
		// Signed by CA
		issuerCert = signerCert
		issuerKey = signerKey
	}

	// Create the certificate
	certDER, err := x509.CreateCertificate(rand.Reader, template, issuerCert, &privKey.PublicKey, issuerKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create certificate: %w", err)
	}

	// Encode certificate to PEM
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	// Encode private key to PEM
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privKey),
	})

	return certPEM, keyPEM, nil
}

// parseCA parses CA certificate and private key from PEM format.
func parseCA(caCertPEM, caKeyPEM []byte) (*x509.Certificate, *rsa.PrivateKey, error) {
	// Parse CA certificate
	caCertBlock, _ := pem.Decode(caCertPEM)
	if caCertBlock == nil {
		return nil, nil, ErrDecodeCAPEM
	}

	caCert, err := x509.ParseCertificate(caCertBlock.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse CA certificate: %w", err)
	}

	// Parse CA private key
	caKeyBlock, _ := pem.Decode(caKeyPEM)
	if caKeyBlock == nil {
		return nil, nil, ErrDecodeCAPEM
	}

	caPrivKey, err := x509.ParsePKCS1PrivateKey(caKeyBlock.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse CA private key: %w", err)
	}

	return caCert, caPrivKey, nil
}

// initializeTemplate creates and initializes a certificate template based on the certificate type.
// certType can be "CA", "Server", or "Client".
func initializeTemplate(certType string) (*x509.Certificate, error) {
	template := &x509.Certificate{}

	// Initialize certificate type-specific fields and defaults
	switch certType {
	case certTypeCA:
		template.IsCA = true
		template.ExtKeyUsage = []x509.ExtKeyUsage{}
		template.KeyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign
		template.BasicConstraintsValid = true
		template.Subject = pkix.Name{
			Organization:  []string{"Test CA"},
			Country:       []string{"US"},
			Province:      []string{""},
			Locality:      []string{"San Francisco"},
			StreetAddress: []string{""},
			PostalCode:    []string{""},
		}
		template.NotBefore = time.Now()
		template.NotAfter = time.Now().AddDate(10, 0, 0) // 10 years for CA
	case certTypeServer:
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		template.KeyUsage = x509.KeyUsageDigitalSignature
		template.Subject = pkix.Name{
			Organization:  []string{"Test Server"},
			Country:       []string{"US"},
			Province:      []string{""},
			Locality:      []string{"San Francisco"},
			StreetAddress: []string{""},
			PostalCode:    []string{""},
		}
		template.NotBefore = time.Now()
		template.NotAfter = time.Now().AddDate(1, 0, 0)           // 1 year for server
		template.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")} // Default IP for Server
	case certTypeClient:
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
		template.KeyUsage = x509.KeyUsageDigitalSignature
		template.Subject = pkix.Name{
			Organization:  []string{"Test Client"},
			Country:       []string{"US"},
			Province:      []string{""},
			Locality:      []string{"San Francisco"},
			StreetAddress: []string{""},
			PostalCode:    []string{""},
		}
		template.NotBefore = time.Now()
		template.NotAfter = time.Now().AddDate(1, 0, 0) // 1 year for client
	default:
		return nil, fmt.Errorf("%w: %s", ErrInvalidCertificateType, certType)
	}

	return template, nil
}

// applyOptions applies options to the certificate template, using defaults when options are not provided.
// certType can be "CA", "Server", or "Client".
func applyOptions(template *x509.Certificate, opts *CertificateOptions, certType string) {
	if opts == nil {
		opts = &CertificateOptions{}
	}

	// Apply NotBefore if provided in options
	if !opts.NotBefore.IsZero() {
		template.NotBefore = opts.NotBefore
	}

	// Apply NotAfter if provided in options
	if !opts.NotAfter.IsZero() {
		template.NotAfter = opts.NotAfter
	}

	// Apply SAN (Subject Alternative Name) - handle IPAddresses
	// Priority: 1) opts.IPAddresses, 2) hostname if IP, 3) keep default from initializeTemplate
	if opts.IPAddresses != nil {
		template.IPAddresses = opts.IPAddresses
	} else if certType == certTypeServer && opts.Hostname != "" {
		if ip := net.ParseIP(opts.Hostname); ip != nil {
			// Hostname is an IP address, use it
			template.IPAddresses = []net.IP{ip}
		}
		// If hostname is DNS name, keep default IP from initializeTemplate
	}

	// Apply SAN (Subject Alternative Name) - handle DNSNames
	// Priority: 1) opts.DNSNames, 2) hostname if DNS name
	if opts.DNSNames != nil {
		template.DNSNames = opts.DNSNames
	} else if certType == certTypeServer && opts.Hostname != "" {
		if ip := net.ParseIP(opts.Hostname); ip == nil {
			// Hostname is a DNS name, use it
			template.DNSNames = []string{opts.Hostname}
		}
	}

	// Apply email addresses
	if opts.EmailAddresses != nil {
		template.EmailAddresses = opts.EmailAddresses
	}

	// Apply CommonName - explicitly set to empty string if not provided to ensure it's empty
	if opts.CommonName != "" {
		template.Subject.CommonName = opts.CommonName
	} else {
		template.Subject.CommonName = ""
	}
}

// GenerateCACert generates a CA certificate and private key.
// opts is optional and can be used to customize certificate settings.
func GenerateCACert(opts ...*CertificateOptions) ([]byte, []byte, error) {
	var options *CertificateOptions
	if len(opts) > 0 && opts[0] != nil {
		options = opts[0]
	}

	// Self-signed certificate (signerCert and signerKey are nil)
	return generateCertificate(certTypeCA, options, nil, nil)
}

// GenerateIntermediateCACert generates an intermediate CA certificate signed by the provided parent CA.
// opts is optional and can be used to customize certificate settings, including CommonName.
func GenerateIntermediateCACert(
	parentCACertPEM,
	parentCAKeyPEM []byte,
	opts ...*CertificateOptions,
) ([]byte, []byte, error) {
	var options *CertificateOptions
	if len(opts) > 0 && opts[0] != nil {
		options = opts[0]
	} else {
		options = &CertificateOptions{}
	}

	// Parse parent CA certificate and key
	parentCACert, parentCAPrivKey, err := parseCA(parentCACertPEM, parentCAKeyPEM)
	if err != nil {
		return nil, nil, err
	}

	// Generate intermediate CA certificate signed by parent CA
	return generateCertificate(certTypeCA, options, parentCACert, parentCAPrivKey)
}

// writeCertAndKeyToFile writes certificate and key bytes to their respective files.
func writeCertAndKeyToFile(certPath, keyPath string, certBytes, keyBytes []byte) error {
	err := os.WriteFile(certPath, certBytes, 0o600)
	if err != nil {
		return err
	}

	return os.WriteFile(keyPath, keyBytes, 0o600)
}

// WriteCertificateChainToFile writes a certificate chain to a file.
// The certificates should be provided in order: leaf certificate first, followed by intermediate CAs.
// All certificates should be in PEM format.
func WriteCertificateChainToFile(certChainPath string, certs ...[]byte) error {
	if len(certs) == 0 {
		return ErrNoCertificatesProvided
	}

	// Calculate total size for pre-allocation
	totalSize := 0
	for _, cert := range certs {
		totalSize += len(cert)
	}

	// Concatenate all certificates
	chainPEM := make([]byte, 0, totalSize)
	for _, cert := range certs {
		chainPEM = append(chainPEM, cert...)
	}

	// Write to file
	err := os.WriteFile(certChainPath, chainPEM, 0o600)
	if err != nil {
		return err
	}

	return nil
}

// GenerateServerCert generates a server certificate signed by the provided CA.
// opts is required and must contain a Hostname field.
func GenerateServerCert(caCertPEM, caKeyPEM []byte, opts *CertificateOptions) ([]byte, []byte, error) {
	if opts == nil || opts.Hostname == "" {
		return nil, nil, ErrHostnameRequired
	}

	// Parse CA certificate and key
	caCert, caPrivKey, err := parseCA(caCertPEM, caKeyPEM)
	if err != nil {
		return nil, nil, err
	}

	// Generate certificate signed by CA
	return generateCertificate(certTypeServer, opts, caCert, caPrivKey)
}

// GenerateServerCertToFile generates a server certificate signed by the provided CA
// and writes generated key and cert to files.
// opts is required and must contain a Hostname field.
func GenerateServerCertToFile(
	caCertPEM, caKeyPEM []byte,
	certOutputPath, keyOutputPath string,
	opts *CertificateOptions,
) error {
	serverCertBytes, serverKeyBytes, err := GenerateServerCert(caCertPEM, caKeyPEM, opts)
	if err != nil {
		return err
	}

	return writeCertAndKeyToFile(certOutputPath, keyOutputPath, serverCertBytes, serverKeyBytes)
}

// GenerateClientCert generates a client certificate signed by the provided CA.
// opts is optional. CommonName is optional - if not provided, the certificate will not have a CN.
func GenerateClientCert(caCertPEM, caKeyPEM []byte, opts *CertificateOptions) ([]byte, []byte, error) {
	// Parse CA certificate and key
	caCert, caPrivKey, err := parseCA(caCertPEM, caKeyPEM)
	if err != nil {
		return nil, nil, err
	}

	// Generate certificate signed by CA
	return generateCertificate(certTypeClient, opts, caCert, caPrivKey)
}

// GenerateClientCertToFile generates a client certificate signed by the provided CA
// and writes generated key and cert to files.
// opts is optional. CommonName is optional - if not provided, the certificate will not have a CN.
func GenerateClientCertToFile(caCertPEM, caKeyPEM []byte, certPath, keyPath string, opts *CertificateOptions) error {
	clientCertBytes, clientKeyBytes, err := GenerateClientCert(caCertPEM, caKeyPEM, opts)
	if err != nil {
		return err
	}

	return writeCertAndKeyToFile(certPath, keyPath, clientCertBytes, clientKeyBytes)
}

// GenerateClientSelfSignedCert generates a client certificate not signed by any CA.
// opts is optional. CommonName is optional - if not provided, the certificate will not have a CN.
func GenerateClientSelfSignedCert(opts *CertificateOptions) ([]byte, []byte, error) {
	// Self-signed certificate (signerCert and signerKey are nil)
	return generateCertificate(certTypeClient, opts, nil, nil)
}

// GenerateClientSelfSignedCertToFile generates a client certificate not signed by any CA
// and writes generated key and cert to files.
// opts is optional. CommonName is optional - if not provided, the certificate will not have a CN.
func GenerateClientSelfSignedCertToFile(certOutputPath, keyOutputPath string, opts *CertificateOptions) error {
	clientCertBytes, clientKeyBytes, err := GenerateClientSelfSignedCert(opts)
	if err != nil {
		return err
	}

	return writeCertAndKeyToFile(certOutputPath, keyOutputPath, clientCertBytes, clientKeyBytes)
}
