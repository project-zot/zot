package api

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"

	"github.com/anuvu/zot/errors"
	"github.com/jtblin/go-ldap-client"
	"github.com/rs/zerolog"
	goldap "gopkg.in/ldap.v2"
)

type LDAPClient struct {
	ldap.LDAPClient
	subtreeSearch bool
	clientCAs     *x509.CertPool
	log           zerolog.Logger
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
				lc.log.Error().Err(err).Str("address", address).Msg("non-TLS connection failed")
				return err
			}

			// Reconnect with TLS
			if !lc.SkipTLS {
				config := &tls.Config{
					InsecureSkipVerify: lc.InsecureSkipVerify, // nolint (gosec): InsecureSkipVerify is not true by default
					RootCAs:            lc.clientCAs,
				}
				if lc.ClientCertificates != nil && len(lc.ClientCertificates) > 0 {
					config.Certificates = lc.ClientCertificates
					config.BuildNameToCertificate()
				}
				err = l.StartTLS(config)
				if err != nil {
					lc.log.Error().Err(err).Str("address", address).Msg("TLS connection failed")
					return err
				}
			}
		} else {
			config := &tls.Config{
				InsecureSkipVerify: lc.InsecureSkipVerify, // nolint (gosec): InsecureSkipVerify is not true by default
				ServerName:         lc.ServerName,
				RootCAs:            lc.clientCAs,
			}
			if lc.ClientCertificates != nil && len(lc.ClientCertificates) > 0 {
				config.Certificates = lc.ClientCertificates
				config.BuildNameToCertificate()
			}
			l, err = goldap.DialTLS("tcp", address, config)
			if err != nil {
				lc.log.Error().Err(err).Str("address", address).Msg("TLS connection failed")
				return err
			}
		}

		lc.Conn = l
	}
	return nil
}

// Authenticate authenticates the user against the ldap backend.
func (lc *LDAPClient) Authenticate(username, password string) (bool, map[string]string, error) {
	err := lc.Connect()
	if err != nil {
		return false, nil, err
	}

	// First bind with a read only user
	if lc.BindDN != "" && lc.BindPassword != "" {
		err := lc.Conn.Bind(lc.BindDN, lc.BindPassword)
		if err != nil {
			lc.log.Error().Err(err).Str("bindDN", lc.BindDN).Msg("bind failed")
			return false, nil, err
		}
	}

	attributes := append(lc.Attributes, "dn")
	searchScope := goldap.ScopeSingleLevel
	if lc.subtreeSearch {
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
		lc.log.Error().Err(err).Str("bindDN", lc.BindDN).Str("username", username).
			Str("baseDN", lc.Base).Msg("search failed")
		return false, nil, err
	}

	if len(sr.Entries) < 1 {
		err := errors.ErrBadUser
		lc.log.Error().Err(err).Str("bindDN", lc.BindDN).Str("username", username).
			Str("baseDN", lc.Base).Msg("entries not found")
		return false, nil, err
	}

	if len(sr.Entries) > 1 {
		err := errors.ErrEntriesExceeded
		lc.log.Error().Err(err).Str("bindDN", lc.BindDN).Str("username", username).
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
		lc.log.Error().Err(err).Str("bindDN", userDN).Msg("user bind failed")
		return false, user, err
	}

	// Rebind as the read only user for any further queries
	if lc.BindDN != "" && lc.BindPassword != "" {
		err = lc.Conn.Bind(lc.BindDN, lc.BindPassword)
		if err != nil {
			return true, user, err
		}
	}

	return true, user, nil
}
