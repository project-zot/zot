//go:build search
// +build search

package cli

import (
	"github.com/spf13/cobra"
)

func NewListReposCommand(searchService SearchService) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List all repositories",
		Long:  "List all repositories",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			searchConfig, err := GetSearchConfigFromFlags(cmd, searchService)
			if err != nil {
				return err
			}

			return SearchRepos(searchConfig)
		},
	}

	return cmd
}
