//go:build search
// +build search

package client

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v2"

	zerr "zotregistry.dev/zot/errors"
	"zotregistry.dev/zot/pkg/api/constants"
)

const (
	StatusOnline  = "online"
	StatusOffline = "offline"
	StatusUnknown = "unknown"
)

func NewServerStatusCommand() *cobra.Command {
	serverInfoCmd := &cobra.Command{
		Use:   "status",
		Short: "Information about the server configuration and build information",
		Long:  `Information about the server configuration and build information`,
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			searchConfig, err := GetSearchConfigFromFlags(cmd, NewSearchService())
			if err != nil {
				return err
			}

			return GetServerStatus(searchConfig)
		},
	}

	serverInfoCmd.PersistentFlags().String(URLFlag, "",
		"Specify zot server URL if config-name is not mentioned")
	serverInfoCmd.PersistentFlags().StringP(ConfigFlag, "c", "",
		"Specify the registry configuration to use for connection")
	serverInfoCmd.PersistentFlags().StringP(UserFlag, "u", "",
		`User Credentials of zot server in "username:password" format`)
	serverInfoCmd.Flags().StringP(OutputFormatFlag, "f", "text", "Specify the output format [text|json|yaml]")

	return serverInfoCmd
}

func GetServerStatus(config SearchConfig) error {
	ctx := context.Background()
	username, password := getUsernameAndPassword(config.User)

	checkAPISupportEndpoint, err := combineServerAndEndpointURL(config.ServURL, constants.RoutePrefix+"/")
	if err != nil {
		return err
	}

	_, err = makeGETRequest(ctx, checkAPISupportEndpoint, username, password, config.VerifyTLS, config.Debug,
		nil, config.ResultWriter)
	if err != nil {
		serverInfo := ServerInfo{}

		switch {
		case errors.Is(err, zerr.ErrUnauthorizedAccess):
			serverInfo.Status = StatusUnknown
			serverInfo.ErrorMsg = fmt.Sprintf("unauthorised access, %s", getCredentialsSuggestion(username))
		case errors.Is(err, zerr.ErrBadHTTPStatusCode), errors.Is(err, zerr.ErrURLNotFound):
			serverInfo.Status = StatusOffline
			serverInfo.ErrorMsg = fmt.Sprintf("%s: request at %s failed", zerr.ErrAPINotSupported.Error(),
				checkAPISupportEndpoint)
		default:
			serverInfo.Status = StatusOffline
			serverInfo.ErrorMsg = err.Error()
		}

		return PrintServerInfo(serverInfo, config)
	}

	mgmtEndpoint, err := combineServerAndEndpointURL(config.ServURL, fmt.Sprintf("%s%s",
		constants.RoutePrefix, constants.ExtMgmt))
	if err != nil {
		return err
	}

	serverInfo := ServerInfo{}

	_, err = makeGETRequest(ctx, mgmtEndpoint, username, password, config.VerifyTLS, config.Debug,
		&serverInfo, config.ResultWriter)

	switch {
	case err == nil:
		serverInfo.Status = StatusOnline
	case errors.Is(err, zerr.ErrURLNotFound):
		serverInfo.Status = StatusOnline
		serverInfo.ErrorMsg = fmt.Sprintf("%s%s endpoint is not available", constants.RoutePrefix, constants.ExtMgmt)
	case errors.Is(err, zerr.ErrUnauthorizedAccess):
		serverInfo.Status = StatusOnline
		serverInfo.ErrorMsg = fmt.Sprintf("unauthorised access, %s", getCredentialsSuggestion(username))
	case errors.Is(err, zerr.ErrBadHTTPStatusCode):
		serverInfo.Status = StatusOnline
		serverInfo.ErrorMsg = fmt.Sprintf("%s: request at %s failed", zerr.ErrAPINotSupported.Error(),
			checkAPISupportEndpoint)
	default:
		serverInfo.Status = StatusOffline
		serverInfo.ErrorMsg = err.Error()
	}

	return PrintServerInfo(serverInfo, config)
}

func getCredentialsSuggestion(username string) string {
	if username == "" {
		return "endpoint requires valid user credentials (add the flag '--user [user]:[password]')"
	}

	return "given credentials are invalid"
}

func PrintServerInfo(serverInfo ServerInfo, config SearchConfig) error {
	outputResult, err := serverInfo.ToStringFormat(config.OutputFormat)
	if err != nil {
		return err
	}

	fmt.Fprintln(config.ResultWriter, outputResult)

	return nil
}

type ServerInfo struct {
	Status          string `json:"status,omitempty"          mapstructure:"status"`
	ErrorMsg        string `json:"error,omitempty"           mapstructure:"error"`
	DistSpecVersion string `json:"distSpecVersion,omitempty" mapstructure:"distSpecVersion"`
	Commit          string `json:"commit,omitempty"          mapstructure:"commit"`
	BinaryType      string `json:"binaryType,omitempty"      mapstructure:"binaryType"`
	ReleaseTag      string `json:"releaseTag,omitempty"      mapstructure:"releaseTag"`
}

func (si *ServerInfo) ToStringFormat(format string) (string, error) {
	switch format {
	case "text", "":
		return si.ToText()
	case "json":
		return si.ToJSON()
	case "yaml", "yml":
		return si.ToYAML()
	default:
		return "", zerr.ErrFormatNotSupported
	}
}

func (si *ServerInfo) ToText() (string, error) {
	flagsList := strings.Split(strings.Trim(si.BinaryType, "-"), "-")
	flags := strings.Join(flagsList, ", ")

	var output string

	if si.ErrorMsg != "" {
		serverStatus := fmt.Sprintf("Server Status: %s\n"+
			"Error: %s", si.Status, si.ErrorMsg)

		output = serverStatus
	} else {
		serverStatus := fmt.Sprintf("Server Status: %s", si.Status)
		serverInfo := fmt.Sprintf("Server Version: %s\n"+
			"Dist Spec Version: %s\n"+
			"Built with: %s",
			si.ReleaseTag, si.DistSpecVersion, flags,
		)

		output = serverStatus + "\n" + serverInfo
	}

	return output, nil
}

func (si *ServerInfo) ToJSON() (string, error) {
	blob, err := json.MarshalIndent(*si, "", "    ")

	return string(blob), err
}

func (si *ServerInfo) ToYAML() (string, error) {
	body, err := yaml.Marshal(*si)

	return string(body), err
}
