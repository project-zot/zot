//go:build search
// +build search

package client

import (
	"fmt"

	"github.com/spf13/cobra"

	"zotregistry.io/zot/pkg/cli/cmdflags"
)

func NewListReposCommand(searchService SearchService) *cobra.Command {
	repoListSortFlag := cmdflags.RepoListSortFlag(cmdflags.SortByAlphabeticAsc)

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

	cmd.Flags().Var(&repoListSortFlag, cmdflags.SortByFlag,
		fmt.Sprintf("Options for sorting the output: [%s]", cmdflags.RepoListSortOptionsStr()))

	return cmd
}
