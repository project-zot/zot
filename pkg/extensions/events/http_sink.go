package events

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/url"

	cloudevents "github.com/cloudevents/sdk-go/v2"
	cehttp "github.com/cloudevents/sdk-go/v2/protocol/http"

	zerr "zotregistry.dev/zot/errors"
	eventsconf "zotregistry.dev/zot/pkg/extensions/config/events"
)

type HTTPSink struct {
	cloudevents.Client
	config eventsconf.SinkConfig
}

func NewHTTPSink(config eventsconf.SinkConfig) (*HTTPSink, error) {
	if config.Type != eventsconf.HTTP {
		return nil, zerr.ErrInvalidEventSinkType
	}

	if config.Address == "" {
		return nil, zerr.ErrEventSinkAddressEmpty
	}

	// Create the basic http client
	httpClient, err := getHTTPClientForConfig(config)
	if err != nil {
		return nil, err
	}

	opts := []cehttp.Option{
		cehttp.WithTarget(config.Address),
		cehttp.WithClient(*httpClient),
	}

	if config.Credentials != nil && config.Credentials.Username != "" {
		opts = append(opts, cehttp.WithHeader("Authorization",
			"Basic "+basicAuth(config.Credentials.Username, config.Credentials.Password)))
	}

	// Create CloudEvents HTTP protocol
	provider, err := cehttp.New(opts...)
	if err != nil {
		return nil, err
	}

	// Create CloudEvents client
	ceClient, err := cloudevents.NewClient(provider)
	if err != nil {
		return nil, err
	}

	return &HTTPSink{
		Client: ceClient,
		config: config,
	}, nil
}

// Emit sends the event to the sink.
func (s *HTTPSink) Emit(event *cloudevents.Event) cloudevents.Result {
	ctx, cancel := context.WithTimeout(context.Background(), s.config.Timeout)
	defer cancel()

	if err := event.Validate(); err != nil {
		return err
	}

	if s.config.Channel != "" {
		event.SetExtension("channel", s.config.Channel)
	}

	// Send the event
	return s.Send(ctx, *event)
}

// Close implements a method to clean up resources.
func (s *HTTPSink) Close() error {
	// For HTTP clients, typically no specific cleanup is needed
	// We could cancel any in-flight requests if we tracked them
	return nil
}

func getHTTPClientForConfig(config eventsconf.SinkConfig) (*http.Client, error) {
	transport, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		return nil, zerr.ErrCouldNotCreateHTTPEventTransport
	}
	transport = transport.Clone()

	if config.Proxy != nil && *config.Proxy != "" {
		proxyURL, err := url.Parse(*config.Proxy)
		if err != nil {
			return nil, err
		}
		transport.Proxy = http.ProxyURL(proxyURL)
	}

	if config.TLSConfig != nil && (config.TLSConfig.CACertFile != "" || config.TLSConfig.CertFile != "") {
		tlsConfig, err := getTLSConfig(config)
		if err != nil {
			return nil, err
		}
		transport.TLSClientConfig = tlsConfig
	}

	timeout := config.Timeout
	if timeout == 0 {
		timeout = DefaultHTTPTimeout
	}

	return &http.Client{
		Transport: transport,
		Timeout:   timeout,
	}, nil
}

// Helper function for basic auth encoding.
func basicAuth(username, password string) string {
	auth := username + ":" + password

	return base64.StdEncoding.EncodeToString([]byte(auth))
}
