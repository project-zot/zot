package tls

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
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
	ErrDecodeCAPEM               = errors.New("failed to decode CA certificate PEM")
	ErrInvalidCertificateType    = errors.New("invalid certificate type")
	ErrHostnameRequired          = errors.New("Hostname is required in CertificateOptions")
	ErrNoCertificatesProvided    = errors.New("at least one certificate is required")
	ErrInvalidKeyType            = errors.New("invalid key type")
	ErrUnsupportedPrivateKeyType = errors.New("unsupported private key type")
	ErrFailedParsePrivateKey     = errors.New("failed to parse private key: unsupported key format")
	ErrFailedDecodeCertPEM       = errors.New("failed to decode certificate PEM")
	ErrFailedDecodeKeyPEM        = errors.New("failed to decode private key PEM")
	ErrPrivateKeyNotRSA          = errors.New("private key is not RSA")
)

// KeyType represents the type of cryptographic key to use for certificate generation.
type KeyType string

const (
	KeyTypeRSA     KeyType = "RSA"
	KeyTypeECDSA   KeyType = "ECDSA"
	KeyTypeED25519 KeyType = "ED25519"
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

	// CommonName is the CommonName (CN) for certificates.
	// For client certificates, this is optional - if not provided, the certificate will not have a CN.
	CommonName string

	// OrganizationalUnit is the OrganizationalUnit (OU) for certificates.
	// If not provided, the certificate will not have an OU.
	OrganizationalUnit string

	// KeyType specifies the type of cryptographic key to use.
	// Valid values: "RSA" (default), "ECDSA", "ED25519".
	// If empty or "RSA", RSA keys will be generated.
	KeyType KeyType
}

// generateCertificate is a helper function that generates a certificate and private key.
// If signerCert and signerKey are nil, the certificate will be self-signed.
// signerKey can be *rsa.PrivateKey, *ecdsa.PrivateKey, or ed25519.PrivateKey.
func generateCertificate(
	certType string,
	opts *CertificateOptions,
	signerCert *x509.Certificate,
	signerKey any, // Can be *rsa.PrivateKey, *ecdsa.PrivateKey, or ed25519.PrivateKey
) ([]byte, []byte, error) {
	var (
		issuerCert *x509.Certificate
		issuerKey  any
		privKey    any
		publicKey  any
		err        error
	)

	// Determine key type
	keyType := KeyTypeRSA
	if opts != nil && opts.KeyType != "" {
		keyType = opts.KeyType
	}

	// Generate private key based on key type
	switch keyType {
	case KeyTypeRSA:
		rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to generate RSA private key: %w", err)
		}
		privKey = rsaKey
		publicKey = &rsaKey.PublicKey
	case KeyTypeECDSA:
		ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to generate ECDSA private key: %w", err)
		}
		privKey = ecKey
		publicKey = &ecKey.PublicKey
	case KeyTypeED25519:
		edPublicKey, edKey, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to generate ED25519 private key: %w", err)
		}
		privKey = edKey
		publicKey = edPublicKey
	default:
		return nil, nil, fmt.Errorf("%w: %s", ErrInvalidKeyType, keyType)
	}

	// Initialize certificate template
	template, err := initializeTemplate(certType)
	if err != nil {
		return nil, nil, err
	}

	// Apply options
	applyOptions(template, opts, certType)

	// Determine signer (self-signed if signerCert is nil)

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
	certDER, err := x509.CreateCertificate(rand.Reader, template, issuerCert, publicKey, issuerKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create certificate: %w", err)
	}

	// Encode certificate to PEM
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	// Encode private key to PEM based on key type
	var keyPEM []byte

	switch privKeyType := privKey.(type) {
	case *rsa.PrivateKey:
		keyPEM = pem.EncodeToMemory(&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(privKeyType),
		})
	case *ecdsa.PrivateKey:
		keyBytes, err := x509.MarshalECPrivateKey(privKeyType)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to marshal ECDSA private key: %w", err)
		}
		keyPEM = pem.EncodeToMemory(&pem.Block{
			Type:  "EC PRIVATE KEY",
			Bytes: keyBytes,
		})
	case ed25519.PrivateKey:
		keyBytes, err := x509.MarshalPKCS8PrivateKey(privKeyType)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to marshal ED25519 private key: %w", err)
		}
		keyPEM = pem.EncodeToMemory(&pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: keyBytes,
		})
	default:
		return nil, nil, fmt.Errorf("%w: %T", ErrUnsupportedPrivateKeyType, privKey)
	}

	return certPEM, keyPEM, nil
}

// parsePrivateKeyFromPEM parses a private key from PEM-encoded bytes.
// Tries PKCS8 first (handles RSA, ECDSA, and ED25519), then falls back to PKCS1 (RSA) and EC SEC1 (ECDSA).
func parsePrivateKeyFromPEM(keyBytes []byte) (any, error) {
	// Try PKCS8 first (handles RSA, ECDSA, and ED25519)
	if privKey, err := x509.ParsePKCS8PrivateKey(keyBytes); err == nil {
		return privKey, nil
	}

	// Fall back to PKCS1 (RSA only)
	if rsaKey, err := x509.ParsePKCS1PrivateKey(keyBytes); err == nil {
		return rsaKey, nil
	}

	// Fall back to EC SEC1 format
	if ecKey, err := x509.ParseECPrivateKey(keyBytes); err == nil {
		return ecKey, nil
	}

	return nil, ErrFailedParsePrivateKey
}

// ExtractPublicKeyFromCert extracts the public key from a certificate in PEM format.
// Returns the public key in PKIX format (suitable for ECDSA and ED25519).
func ExtractPublicKeyFromCert(certPEM []byte) ([]byte, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, ErrFailedDecodeCertPEM
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	publicKeyBytes, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal public key: %w", err)
	}

	return pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	}), nil
}

// ExtractRSAPublicKeyPKCS1 extracts the RSA public key from a private key in PEM format.
// Returns the public key in PKCS1 format (RSA-specific).
func ExtractRSAPublicKeyPKCS1(keyPEM []byte) ([]byte, error) {
	block, _ := pem.Decode(keyPEM)
	if block == nil {
		return nil, ErrFailedDecodeKeyPEM
	}

	privKey, err := parsePrivateKeyFromPEM(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse RSA private key: %w", err)
	}

	rsaKey, ok := privKey.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("%w, got %T", ErrPrivateKeyNotRSA, privKey)
	}

	publicKeyBytes := x509.MarshalPKCS1PublicKey(&rsaKey.PublicKey)

	return pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: publicKeyBytes,
	}), nil
}

// parseCA parses CA certificate and private key from PEM format.
// Returns the certificate and the private key (which can be *rsa.PrivateKey, *ecdsa.PrivateKey, or ed25519.PrivateKey).
func parseCA(caCertPEM, caKeyPEM []byte) (*x509.Certificate, any, error) {
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

	caPrivKey, err := parsePrivateKeyFromPEM(caKeyBlock.Bytes)
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
		// NotBefore and NotAfter are set via CertificateOptions in test logic
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
		// NotBefore and NotAfter are set via CertificateOptions in test logic
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
		// NotBefore and NotAfter are set via CertificateOptions in test logic
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

	// Apply NotBefore - default to time.Now() if not provided
	if !opts.NotBefore.IsZero() {
		template.NotBefore = opts.NotBefore
	} else {
		template.NotBefore = time.Now()
	}

	// Apply NotAfter - default to 1 year if not provided, matching gen_certs.sh
	if !opts.NotAfter.IsZero() {
		template.NotAfter = opts.NotAfter
	} else {
		template.NotAfter = time.Now().AddDate(1, 0, 0)
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

	// Apply CommonName - if provided, override the default; otherwise keep default from initializeTemplate
	if opts.CommonName != "" {
		template.Subject.CommonName = opts.CommonName
	} else if opts != nil && opts.CommonName == "" && certType == certTypeClient {
		// Special case: For client certs, if opts is provided and CommonName is explicitly set to empty,
		// use empty CN (for noidentity-style certs)
		template.Subject.CommonName = ""
	}

	// Apply OrganizationalUnit - if provided, set it
	if opts.OrganizationalUnit != "" {
		template.Subject.OrganizationalUnit = []string{opts.OrganizationalUnit}
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
