package common

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"regexp"
	"strings"
	"syscall"
	"time"
	"unicode/utf8"
)

const (
	httpTimeout        = 5 * time.Minute
	certsPath          = "/etc/containers/certs.d"
	homeCertsDir       = ".config/containers/certs.d"
	ClientCertFilename = "client.cert"
	ClientKeyFilename  = "client.key"
	CaCertFilename     = "ca.crt"

	CosignSignature   = "cosign"
	CosignSigKey      = "dev.cosignproject.cosign/signature"
	NotationSignature = "notation"
	// same value as github.com/notaryproject/notation-go/registry.ArtifactTypeNotation (assert by internal test).
	// reason used: to reduce zot minimal binary size (otherwise adds oras.land/oras-go/v2 deps).
	ArtifactTypeNotation = "application/vnd.cncf.notary.signature"
	ArtifactTypeCosign   = "application/vnd.dev.cosign.artifact.sig.v1+json"
	// CosignSignatureTagSuffix is the suffix used for cosign signature tags (e.g., "sha256-digest.sig")
	// Using constant to avoid pulling in cosign dependency
	CosignSignatureTagSuffix = "sig"
)

var cosignSignatureTagRule = regexp.MustCompile(`sha256\-.+\.sig`)

var cosignSBOMTagRule = regexp.MustCompile(`sha256\-.+\.sbom`)

func IsCosignSignature(tag string) bool {
	return cosignSignatureTagRule.MatchString(tag)
}

func IsCosignSBOM(tag string) bool {
	return cosignSBOMTagRule.MatchString(tag)
}

func IsCosignTag(tag string) bool {
	return IsCosignSignature(tag) || IsCosignSBOM(tag)
}

func Contains[T comparable](elems []T, v T) bool {
	for _, s := range elems {
		if v == s {
			return true
		}
	}

	return false
}

// first match of item in [].
func Index(slice []string, item string) int {
	for k, v := range slice {
		if item == v {
			return k
		}
	}

	return -1
}

// remove matches of item in [].
func RemoveFrom(inputSlice []string, item string) []string {
	var newSlice []string

	for _, v := range inputSlice {
		if item != v {
			newSlice = append(newSlice, v)
		}
	}

	return newSlice
}

func TypeOf(v interface{}) string {
	return fmt.Sprintf("%T", v)
}

func DirExists(d string) bool {
	if !utf8.ValidString(d) {
		return false
	}

	fileInfo, err := os.Stat(d)
	if err != nil {
		if e, ok := err.(*fs.PathError); ok && errors.Is(e.Err, syscall.ENAMETOOLONG) || //nolint: errorlint
			errors.Is(e.Err, syscall.EINVAL) {
			return false
		}
	}

	if err != nil && os.IsNotExist(err) {
		return false
	}

	if !fileInfo.IsDir() {
		return false
	}

	return true
}

// Used to filter a json fields by using an intermediate struct.
func MarshalThroughStruct(obj interface{}, throughStruct interface{}) ([]byte, error) {
	toJSON, err := json.Marshal(obj)
	if err != nil {
		return []byte{}, err
	}

	err = json.Unmarshal(toJSON, throughStruct)
	if err != nil {
		return []byte{}, err
	}

	toJSON, err = json.Marshal(throughStruct)
	if err != nil {
		return []byte{}, err
	}

	return toJSON, nil
}

func ContainsStringIgnoreCase(strSlice []string, str string) bool {
	for _, val := range strSlice {
		if strings.EqualFold(val, str) {
			return true
		}
	}

	return false
}

// this function will check if tag is a referrers tag
// (https://github.com/opencontainers/distribution-spec/blob/main/spec.md#referrers-tag-schema).
func IsReferrersTag(tag string) bool {
	referrersTagRule := regexp.MustCompile(`sha256\-[A-Za-z0-9]*$`)

	return referrersTagRule.MatchString(tag)
}

func IsContextDone(ctx context.Context) bool {
	select {
	case <-ctx.Done():
		return true
	default:
		return false
	}
}

// get a list of IP addresses configured on the host's
// interfaces.
func GetLocalIPs() ([]string, error) {
	var localIPs []string

	ifaces, err := net.Interfaces()
	if err != nil {
		return []string{}, err
	}

	for _, i := range ifaces {
		addrs, err := i.Addrs()
		if err != nil {
			return localIPs, err
		}

		for _, addr := range addrs {
			if localIP, ok := addr.(*net.IPNet); ok {
				localIPs = append(localIPs, localIP.IP.String())
			}
		}
	}

	return localIPs, nil
}

// get a list of listening sockets on the host (IP:port).
// IPv6 is returned as [host]:port.
func GetLocalSockets(port string) ([]string, error) {
	localIPs, err := GetLocalIPs()
	if err != nil {
		return []string{}, err
	}

	localSockets := make([]string, len(localIPs))

	for idx, ip := range localIPs {
		// JoinHostPort automatically wraps IPv6 addresses in []
		localSockets[idx] = net.JoinHostPort(ip, port)
	}

	return localSockets, nil
}

func GetIPFromHostName(host string) ([]string, error) {
	addrs, err := net.LookupIP(host)
	if err != nil {
		return []string{}, err
	}

	ips := make([]string, 0, len(addrs))

	for _, ip := range addrs {
		ips = append(ips, ip.String())
	}

	return ips, nil
}

// checks if 2 sockets are equal at the host port level.
func AreSocketsEqual(socketA string, socketB string) (bool, error) {
	hostA, portA, err := net.SplitHostPort(socketA)
	if err != nil {
		return false, err
	}

	hostB, portB, err := net.SplitHostPort(socketB)
	if err != nil {
		return false, err
	}

	hostAIP := net.ParseIP(hostA)
	if hostAIP == nil {
		// this could be a fully-qualified domain name (FQDN)
		// for FQDN, just a normal compare is enough
		return hostA == hostB, nil
	}

	hostBIP := net.ParseIP(hostB)
	if hostBIP == nil {
		// if the host part of socketA was parsed successfully, it was an IP
		// if the host part of socketA was an FQDN, then the comparison is
		// already done as the host of socketB is also assumed to be an FQDN.
		// since the parsing failed, assume that A and B are not equal.
		return false, nil
	}

	return (hostAIP.Equal(hostBIP) && (portA == portB)), nil
}
