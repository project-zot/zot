package sync

import (
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path"
	"strings"

	"github.com/anuvu/zot/errors"
	"github.com/anuvu/zot/pkg/log"
	"github.com/containers/image/v5/docker/reference"
	"github.com/containers/image/v5/types"
)

var certsDir = fmt.Sprintf("%s/zot-certs-dir/", os.TempDir()) //nolint: gochecknoglobals

func copyFile(sourceFilePath, destFilePath string) error {
	destFile, err := os.Create(destFilePath)
	if err != nil {
		return err
	}
	defer destFile.Close()

	// should never get error because server certs are already handled by zot, by the time
	// it gets here
	sourceFile, _ := os.Open(sourceFilePath)
	defer sourceFile.Close()

	if _, err := io.Copy(destFile, sourceFile); err != nil {
		return err
	}

	return nil
}

func copyLocalCerts(serverCert, serverKey, caCert string, log log.Logger) (string, error) {
	log.Debug().Msgf("Creating certs directory: %s", certsDir)

	err := os.Mkdir(certsDir, 0755)
	if err != nil && !os.IsExist(err) {
		return "", err
	}

	if serverCert != "" {
		log.Debug().Msgf("Copying server cert: %s", serverCert)

		err := copyFile(serverCert, path.Join(certsDir, "server.cert"))
		if err != nil {
			return "", err
		}
	}

	if serverKey != "" {
		log.Debug().Msgf("Copying server key: %s", serverKey)

		err := copyFile(serverKey, path.Join(certsDir, "server.key"))
		if err != nil {
			return "", err
		}
	}

	if caCert != "" {
		log.Debug().Msgf("Copying CA cert: %s", caCert)

		err := copyFile(caCert, path.Join(certsDir, "ca.crt"))
		if err != nil {
			return "", err
		}
	}

	return certsDir, nil
}

// getTagFromRef returns a tagged reference from an image reference.
func getTagFromRef(ref types.ImageReference, log log.Logger) reference.Tagged {
	tagged, isTagged := ref.DockerReference().(reference.Tagged)
	if !isTagged {
		log.Warn().Msgf("internal server error, reference %s does not have a tag, skipping", ref.DockerReference())
		return nil
	}

	return tagged
}

// parseRepositoryReference parses input into a reference.Named, and verifies that it names a repository, not an image.
func parseRepositoryReference(input string) (reference.Named, error) {
	ref, err := reference.ParseNormalizedNamed(input)
	if err != nil {
		return nil, err
	}

	if !reference.IsNameOnly(ref) {
		return nil, errors.ErrInvalidRepositoryName
	}

	return ref, nil
}

// filterRepos filters repos based on prefix given in the config.
func filterRepos(repos []string, content []Content) map[int][]string {
	// prefix: repo
	filtered := make(map[int][]string)

	for _, repo := range repos {
		matched := false
		// we use contentID to figure out tags filtering
		for contentID, c := range content {
			// handle prefixes starting with '/'
			var prefix string
			if strings.HasPrefix(c.Prefix, "/") {
				prefix = c.Prefix[1:]
			} else {
				prefix = c.Prefix
			}

			// split both prefix and repository and compare each part
			splittedPrefix := strings.Split(prefix, "/")
			// split at most n + 1
			splittedRepo := strings.SplitN(repo, "/", len(splittedPrefix)+1)

			// if prefix is longer than a repository, no match
			if len(splittedPrefix) > len(splittedRepo) {
				continue
			}

			// check if matched each part of prefix and repository
			for i := 0; i < len(splittedPrefix); i++ {
				if splittedRepo[i] == splittedPrefix[i] {
					matched = true
				} else {
					// if a part doesn't match, check next prefix
					matched = false
					break
				}
			}

			// if matched no need to check the next prefixes
			if matched {
				filtered[contentID] = append(filtered[contentID], repo)
				break
			}
		}
	}

	return filtered
}

// Get sync.FileCredentials from file.
func getFileCredentials(filepath string) (CredentialsFile, error) {
	f, err := ioutil.ReadFile(filepath)
	if err != nil {
		return nil, err
	}

	var creds CredentialsFile

	err = json.Unmarshal(f, &creds)
	if err != nil {
		return nil, err
	}

	return creds, nil
}
