package main

import (
	"fmt"
	"net/http"

	"gopkg.in/resty.v1"
	"zotregistry.io/zot/errors"
)

func deleteTestRepo(repos []string, url string, client *resty.Client) error {
	for _, repo := range repos {
		resp, err := client.R().Delete((fmt.Sprintf("%s/v2/%s/", url, repo)))
		if err != nil {
			return err
		}

		// request specific check
		statusCode := resp.StatusCode()
		if statusCode != http.StatusAccepted {
			return errors.ErrUnknownCode
		}
	}

	return nil
}
