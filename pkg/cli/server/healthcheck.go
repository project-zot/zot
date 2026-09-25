package server

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/spf13/cobra"

	zerr "zotregistry.dev/zot/v2/errors"
	"zotregistry.dev/zot/v2/pkg/api/config"
)

const (
	defaultHealthcheckHost    = "127.0.0.1"
	defaultHealthcheckPort    = "8080"
	defaultHealthcheckTimeout = 2 * time.Second
	defaultHealthcheckPath    = "readyz"
)

func newHealthcheckCmd(conf *config.Config) *cobra.Command {
	var (
		endpoint   string
		urlFlag    string
		timeout    time.Duration
		skipVerify bool
	)

	healthcheckCmd := &cobra.Command{
		Use:     "healthcheck <config>",
		Aliases: []string{"ready"},
		Short:   "`healthcheck` probes a local zot health endpoint and exits 0 on success",
		Long: "`healthcheck` performs an HTTP GET against a local zot health endpoint " +
			"(/livez, /readyz, or /startupz) and exits 0 if the response status is 2xx.\n\n" +
			"Intended for container HEALTHCHECK / Podman --health-cmd. " +
			"Like `serve`, the config file is a positional argument. " +
			"Alternatively pass --url instead of a config file (the two are mutually exclusive). " +
			"Bind addresses 0.0.0.0 and :: are rewritten to loopback.",
		Args: func(cmd *cobra.Command, args []string) error {
			urlVal, err := cmd.Flags().GetString("url")
			if err != nil {
				return err
			}

			if urlVal != "" {
				return cobra.ExactArgs(0)(cmd, args)
			}

			return cobra.ExactArgs(1)(cmd, args)
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			cmd.SilenceUsage = true

			if err := validateHealthcheckEndpoint(endpoint); err != nil {
				return err
			}

			if len(args) > 0 {
				if err := LoadConfiguration(conf, args[0]); err != nil {
					return err
				}
			}

			targetURL, err := buildHealthcheckURL(conf, endpoint, urlFlag)
			if err != nil {
				return err
			}

			return runHealthcheck(cmd.Context(), targetURL, timeout, skipVerify)
		},
	}

	healthcheckCmd.Flags().StringVarP(&endpoint, "endpoint", "e", defaultHealthcheckPath,
		"health endpoint to probe: livez, readyz, or startupz")
	healthcheckCmd.Flags().StringVar(&urlFlag, "url", "",
		"full URL to probe (mutually exclusive with a config file argument)")
	healthcheckCmd.Flags().DurationVar(&timeout, "timeout", defaultHealthcheckTimeout,
		"HTTP request timeout")
	healthcheckCmd.Flags().BoolVar(&skipVerify, "insecure-skip-verify", false,
		"skip TLS certificate verification")

	return healthcheckCmd
}

func validateHealthcheckEndpoint(endpoint string) error {
	switch endpoint {
	case "livez", "readyz", "startupz":
		return nil
	default:
		return fmt.Errorf("%w: endpoint must be one of livez, readyz, startupz", zerr.ErrInvalidCLIParameter)
	}
}

func buildHealthcheckURL(conf *config.Config, endpoint, urlOverride string) (string, error) {
	if urlOverride != "" {
		parsed, err := url.Parse(urlOverride)
		if err != nil {
			return "", fmt.Errorf("%w: invalid --url: %w", zerr.ErrInvalidCLIParameter, err)
		}

		if parsed.Scheme == "" || parsed.Host == "" {
			return "", fmt.Errorf("%w: --url must include scheme and host", zerr.ErrInvalidCLIParameter)
		}

		if parsed.Path == "" || parsed.Path == "/" {
			parsed.Path = "/" + endpoint
		}

		return parsed.String(), nil
	}

	host := defaultHealthcheckHost
	port := defaultHealthcheckPort
	useTLS := false

	if conf != nil {
		if conf.HTTP.Address != "" {
			host = resolveHealthcheckHost(conf.HTTP.Address)
		}

		if conf.HTTP.Port != "" {
			port = conf.HTTP.Port
		}

		useTLS = conf.HTTP.TLS != nil && conf.HTTP.TLS.Cert != "" && conf.HTTP.TLS.Key != ""
	}

	scheme := "http"
	if useTLS {
		scheme = "https"
	}

	return (&url.URL{
		Scheme: scheme,
		Host:   net.JoinHostPort(host, port),
		Path:   "/" + endpoint,
	}).String(), nil
}

func resolveHealthcheckHost(address string) string {
	switch address {
	case "", "0.0.0.0":
		return defaultHealthcheckHost
	case "::", "[::]":
		return "::1"
	default:
		// Strip brackets so net.JoinHostPort does not produce [[::1]]:port.
		if len(address) >= 2 && address[0] == '[' && address[len(address)-1] == ']' {
			return address[1 : len(address)-1]
		}

		return address
	}
}

func runHealthcheck(ctx context.Context, targetURL string, timeout time.Duration, skipVerify bool) error {
	if timeout <= 0 {
		timeout = defaultHealthcheckTimeout
	}

	parsed, err := url.Parse(targetURL)
	if err != nil {
		return fmt.Errorf("%w: %w", zerr.ErrHealthcheckFailed, err)
	}

	// Do not follow redirects: success means the probed endpoint itself returned 2xx.
	client := &http.Client{
		Timeout: timeout,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	if strings.EqualFold(parsed.Scheme, "https") {
		transport, ok := http.DefaultTransport.(*http.Transport)
		if !ok {
			return zerr.ErrCouldNotCreateHTTPEventTransport
		}

		tlsTransport := transport.Clone()
		tlsTransport.TLSClientConfig = &tls.Config{
			InsecureSkipVerify: skipVerify, //nolint:gosec // optional skip-verify for local probes
			MinVersion:         tls.VersionTLS12,
		}
		client.Transport = tlsTransport
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
	if err != nil {
		return fmt.Errorf("%w: %w", zerr.ErrHealthcheckFailed, err)
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("%w: %w", zerr.ErrHealthcheckFailed, err)
	}

	defer resp.Body.Close()

	_, _ = io.Copy(io.Discard, resp.Body)

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return fmt.Errorf("%w: %s returned status %d", zerr.ErrHealthcheckFailed, parsed.Redacted(), resp.StatusCode)
	}

	return nil
}
