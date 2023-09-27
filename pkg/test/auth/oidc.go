package auth

import (
	"crypto/rand"
	"crypto/rsa"
	"net"
	"net/http"
	"strings"

	"github.com/project-zot/mockoidc"
)

func MockOIDCRun() (*mockoidc.MockOIDC, error) {
	// Create a fresh RSA Private Key for token signing
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048) //nolint: gomnd

	// Create an unstarted MockOIDC server
	mockServer, _ := mockoidc.NewServer(rsaKey)

	// Create the net.Listener, kernel will chose a valid port
	listener, _ := net.Listen("tcp", "127.0.0.1:0")

	bearerMiddleware := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(response http.ResponseWriter, req *http.Request) {
			// stateVal := req.Form.Get("state")
			header := req.Header.Get("Authorization")
			parts := strings.SplitN(header, " ", 2) //nolint: gomnd
			if header != "" {
				if strings.ToLower(parts[0]) == "bearer" {
					req.Header.Set("Authorization", strings.Join([]string{"Bearer", parts[1]}, " "))
				}
			}

			next.ServeHTTP(response, req)
		})
	}

	err := mockServer.AddMiddleware(bearerMiddleware)
	if err != nil {
		return mockServer, err
	}
	// tlsConfig can be nil if you want HTTP
	return mockServer, mockServer.Start(listener, nil)
}
