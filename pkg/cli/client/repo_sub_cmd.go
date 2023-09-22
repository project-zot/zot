//go:build search
// +build search

package client

import (
	"fmt"

	"github.com/spf13/cobra"
)

func NewListReposCommand(searchService SearchService) *cobra.Command {
	repoListSortFlag := RepoListSortFlag(SortByAlphabeticAsc)

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

	cmd.Flags().Var(&repoListSortFlag, SortByFlag,
		fmt.Sprintf("Options for sorting the output: [%s]", RepoListSortOptionsStr()))

	return cmd
}
