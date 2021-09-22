// Package ldap provides a simple ldap client to authenticate,
// retrieve basic information and groups for a user.
package api

import (
	"sync"
	"time"

	"crypto/tls"
	"crypto/x509"
	"fmt"

	"github.com/anuvu/zot/errors"
	goldap "github.com/go-ldap/ldap/v3"

	"github.com/anuvu/zot/pkg/log"
	"github.com/go-ldap/ldap/v3"
)

type LDAPClient struct {
	InsecureSkipVerify bool
	UseSSL             bool
	SkipTLS            bool
	SubtreeSearch      bool
	Port               int
	Attributes         []string
	Base               string
	BindDN             string
	BindPassword       string
	GroupFilter        string // e.g. "(memberUid=%s)"
	Host               string
	ServerName         string
	UserFilter         string // e.g. "(uid=%s)"
	Conn               *ldap.Conn
	ClientCertificates []tls.Certificate // Adding client certificates
	ClientCAs          *x509.CertPool
	Log                log.Logger
	lock               sync.Mutex
}

// Connect connects to the ldap backend.
func (lc *LDAPClient) Connect() error {
	if lc.Conn == nil {
		var l *goldap.Conn

		var err error

		address := fmt.Sprintf("%s:%d", lc.Host, lc.Port)

		if !lc.UseSSL {
			l, err = goldap.Dial("tcp", address)
			if err != nil {
				lc.Log.Error().Err(err).Str("address", address).Msg("non-TLS connection failed")
				return err
			}

			// Reconnect with TLS
			if !lc.SkipTLS {
				config := &tls.Config{
					InsecureSkipVerify: lc.InsecureSkipVerify, // nolint: gosec // InsecureSkipVerify is not true by default
					RootCAs:            lc.ClientCAs,
				}
				if lc.ClientCertificates != nil && len(lc.ClientCertificates) > 0 {
					config.Certificates = lc.ClientCertificates
					config.BuildNameToCertificate() // nolint: staticcheck
				}

				err = l.StartTLS(config)

				if err != nil {
					lc.Log.Error().Err(err).Str("address", address).Msg("TLS connection failed")
					return err
				}
			}
		} else {
			config := &tls.Config{
				InsecureSkipVerify: lc.InsecureSkipVerify, // nolint: gosec // InsecureSkipVerify is not true by default
				ServerName:         lc.ServerName,
				RootCAs:            lc.ClientCAs,
			}
			if lc.ClientCertificates != nil && len(lc.ClientCertificates) > 0 {
				config.Certificates = lc.ClientCertificates
				config.BuildNameToCertificate() // nolint: staticcheck
			}
			l, err = goldap.DialTLS("tcp", address, config)
			if err != nil {
				lc.Log.Error().Err(err).Str("address", address).Msg("TLS connection failed")
				return err
			}
		}

		lc.Conn = l
	}

	return nil
}

// Close closes the ldap backend connection.
func (lc *LDAPClient) Close() {
	if lc.Conn != nil {
		lc.Conn.Close()
		lc.Conn = nil
	}
}

const maxRetries = 8

func sleepAndRetry(retries, maxRetries int) bool {
	if retries > maxRetries {
		return false
	}

	if retries < maxRetries {
		time.Sleep(time.Duration(retries) * time.Second) // gradually backoff
		return true
	}

	return false
}

// Authenticate authenticates the user against the ldap backend.
func (lc *LDAPClient) Authenticate(username, password string) (bool, map[string]string, error) {
	// serialize LDAP calls since some LDAP servers don't allow searches when binds are in flight
	lc.lock.Lock()
	defer lc.lock.Unlock()

	if password == "" {
		// RFC 4513 section 5.1.2
		return false, nil, errors.ErrLDAPEmptyPassphrase
	}

	connected := false
	for retries := 0; !connected && sleepAndRetry(retries, maxRetries); retries++ {
		err := lc.Connect()
		if err != nil {
			continue
		}

		// First bind with a read only user
		if lc.BindDN != "" && lc.BindPassword != "" {
			err := lc.Conn.Bind(lc.BindDN, lc.BindPassword)
			if err != nil {
				lc.Log.Error().Err(err).Str("bindDN", lc.BindDN).Msg("bind failed")
				// clean up the cached conn, so we can retry
				lc.Conn.Close()
				lc.Conn = nil

				continue
			}
		}

		connected = true
	}

	// exhausted all retries?
	if !connected {
		lc.Log.Error().Err(errors.ErrLDAPBadConn).Msg("exhausted all retries")
		return false, nil, errors.ErrLDAPBadConn
	}

	attributes := append(lc.Attributes, "dn")
	searchScope := goldap.ScopeSingleLevel

	if lc.SubtreeSearch {
		searchScope = goldap.ScopeWholeSubtree
	}
	// Search for the given username
	searchRequest := goldap.NewSearchRequest(
		lc.Base,
		searchScope, goldap.NeverDerefAliases, 0, 0, false,
		fmt.Sprintf(lc.UserFilter, username),
		attributes,
		nil,
	)

	sr, err := lc.Conn.Search(searchRequest)
	if err != nil {
		fmt.Printf("%v\n", err)
		lc.Log.Error().Err(err).Str("bindDN", lc.BindDN).Str("username", username).
			Str("baseDN", lc.Base).Msg("search failed")

		return false, nil, err
	}

	if len(sr.Entries) < 1 {
		err := errors.ErrBadUser
		lc.Log.Error().Err(err).Str("bindDN", lc.BindDN).Str("username", username).
			Str("baseDN", lc.Base).Msg("entries not found")

		return false, nil, err
	}

	if len(sr.Entries) > 1 {
		err := errors.ErrEntriesExceeded
		lc.Log.Error().Err(err).Str("bindDN", lc.BindDN).Str("username", username).
			Str("baseDN", lc.Base).Msg("too many entries")

		return false, nil, err
	}

	userDN := sr.Entries[0].DN
	user := map[string]string{}

	for _, attr := range lc.Attributes {
		user[attr] = sr.Entries[0].GetAttributeValue(attr)
	}

	// Bind as the user to verify their password
	err = lc.Conn.Bind(userDN, password)
	if err != nil {
		lc.Log.Error().Err(err).Str("bindDN", userDN).Msg("user bind failed")
		return false, user, err
	}

	return true, user, nil
}
