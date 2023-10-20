package common

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
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
	clientCertFilename = "client.cert"
	clientKeyFilename  = "client.key"
	caCertFilename     = "ca.crt"

	CosignSignature   = "cosign"
	CosignSigKey      = "dev.cosignproject.cosign/signature"
	NotationSignature = "notation"
	// same value as github.com/notaryproject/notation-go/registry.ArtifactTypeNotation (assert by internal test).
	// reason used: to reduce zot minimal binary size (otherwise adds oras.land/oras-go/v2 deps).
	ArtifactTypeNotation = "application/vnd.cncf.notary.signature"
	ArtifactTypeCosign   = "application/vnd.dev.cosign.artifact.sig.v1+json"
)

var cosignTagRule = regexp.MustCompile(`sha256\-.+\.sig`)

func IsCosignTag(tag string) bool {
	return cosignTagRule.MatchString(tag)
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
