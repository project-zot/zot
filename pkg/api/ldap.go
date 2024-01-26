// Package ldap provides a simple ldap client to authenticate,
// retrieve basic information and groups for a user.
package api

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"sync"
	"time"

	"github.com/go-ldap/ldap/v3"

	"zotregistry.dev/zot/errors"
	"zotregistry.dev/zot/pkg/log"
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
	UserGroupAttribute string // e.g. "memberOf"
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
		var l *ldap.Conn

		var err error

		address := fmt.Sprintf("%s:%d", lc.Host, lc.Port)

		if !lc.UseSSL {
			l, err = ldap.Dial("tcp", address)
			if err != nil {
				lc.Log.Error().Err(err).Str("address", address).Msg("failed to establish a TCP connection")

				return err
			}

			// Reconnect with TLS
			if !lc.SkipTLS {
				config := &tls.Config{
					InsecureSkipVerify: lc.InsecureSkipVerify, //nolint: gosec // InsecureSkipVerify is not true by default
					RootCAs:            lc.ClientCAs,
				}

				if lc.ClientCertificates != nil && len(lc.ClientCertificates) > 0 {
					config.Certificates = lc.ClientCertificates
				}

				err = l.StartTLS(config)

				if err != nil {
					lc.Log.Error().Err(err).Str("address", address).Msg("failed to establish a TLS connection")

					return err
				}
			}
		} else {
			config := &tls.Config{
				InsecureSkipVerify: lc.InsecureSkipVerify, //nolint: gosec // InsecureSkipVerify is not true by default
				ServerName:         lc.ServerName,
				RootCAs:            lc.ClientCAs,
			}
			if lc.ClientCertificates != nil && len(lc.ClientCertificates) > 0 {
				config.Certificates = lc.ClientCertificates
				// config.BuildNameToCertificate()
			}
			l, err = ldap.DialTLS("tcp", address, config)
			if err != nil {
				lc.Log.Error().Err(err).Str("address", address).Msg("failed to establish a TLS connection")

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
func (lc *LDAPClient) Authenticate(username, password string) (bool, map[string]string, []string, error) {
	// serialize LDAP calls since some LDAP servers don't allow searches when binds are in flight
	lc.lock.Lock()
	defer lc.lock.Unlock()

	if password == "" {
		// RFC 4513 section 5.1.2
		return false, nil, nil, errors.ErrLDAPEmptyPassphrase
	}

	connected := false
	for retries := 0; !connected && sleepAndRetry(retries, maxRetries); retries++ {
		err := lc.Connect()
		if err != nil {
			continue
		}

		// First bind with a read only user
		if lc.BindPassword != "" {
			err := lc.Conn.Bind(lc.BindDN, lc.BindPassword)
			if err != nil {
				lc.Log.Error().Err(err).Str("bindDN", lc.BindDN).Msg("failed to bind")
				// clean up the cached conn, so we can retry
				lc.Conn.Close()
				lc.Conn = nil

				continue
			}
		} else {
			err := lc.Conn.UnauthenticatedBind(lc.BindDN)
			if err != nil {
				lc.Log.Error().Err(err).Str("bindDN", lc.BindDN).Msg("failed to bind")
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
		lc.Log.Error().Err(errors.ErrLDAPBadConn).Msg("failed to authenticate, exhausted all retries")

		return false, nil, nil, errors.ErrLDAPBadConn
	}

	attributes := lc.Attributes

	attributes = append(attributes, "dn")
	if lc.UserGroupAttribute != "" {
		attributes = append(attributes, lc.UserGroupAttribute)
	}

	searchScope := ldap.ScopeSingleLevel

	if lc.SubtreeSearch {
		searchScope = ldap.ScopeWholeSubtree
	}
	// Search for the given username
	searchRequest := ldap.NewSearchRequest(
		lc.Base,
		searchScope, ldap.NeverDerefAliases, 0, 0, false,
		fmt.Sprintf(lc.UserFilter, username),
		attributes,
		nil,
	)

	search, err := lc.Conn.Search(searchRequest)
	if err != nil {
		fmt.Printf("%v\n", err)
		lc.Log.Error().Err(err).Str("bindDN", lc.BindDN).Str("username", username).
			Str("baseDN", lc.Base).Msg("failed to perform a search request")

		return false, nil, nil, err
	}

	if len(search.Entries) < 1 {
		err := errors.ErrBadUser
		lc.Log.Error().Err(err).Str("bindDN", lc.BindDN).Str("username", username).
			Str("baseDN", lc.Base).Msg("failed to find entry")

		return false, nil, nil, err
	}

	if len(search.Entries) > 1 {
		err := errors.ErrEntriesExceeded
		lc.Log.Error().Err(err).Str("bindDN", lc.BindDN).Str("username", username).
			Str("baseDN", lc.Base).Msg("failed to retrieve due to an excessive amount of entries")

		return false, nil, nil, err
	}

	userDN := search.Entries[0].DN

	var userGroups []string

	if lc.UserGroupAttribute != "" && len(search.Entries[0].Attributes) > 0 {
		userAttributes := search.Entries[0].Attributes[0]
		userGroups = userAttributes.Values
	}
	user := map[string]string{}

	for _, attr := range lc.Attributes {
		user[attr] = search.Entries[0].GetAttributeValue(attr)
	}

	// Bind as the user to verify their password
	err = lc.Conn.Bind(userDN, password)
	if err != nil {
		lc.Log.Error().Err(err).Str("bindDN", userDN).Msg("failed to bind user")

		return false, user, userGroups, err
	}

	return true, user, userGroups, nil
}
