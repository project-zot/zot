package common

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
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
)

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
