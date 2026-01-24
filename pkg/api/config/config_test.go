package config_test

import (
	"testing"
	"time"

	. "github.com/smartystreets/goconvey/convey"

	"zotregistry.dev/zot/v2/pkg/api/config"
	"zotregistry.dev/zot/v2/pkg/compat"
	extconf "zotregistry.dev/zot/v2/pkg/extensions/config"
	eventsconf "zotregistry.dev/zot/v2/pkg/extensions/config/events"
	syncconf "zotregistry.dev/zot/v2/pkg/extensions/config/sync"
)

func TestConfig(t *testing.T) {
	Convey("Test config utils", t, func() {
		firstStorageConfig := config.StorageConfig{
			GC: true, Dedupe: true,
			GCDelay: 1 * time.Minute, GCInterval: 1 * time.Hour,
		}
		secondStorageConfig := config.StorageConfig{
			GC: true, Dedupe: true,
			GCDelay: 1 * time.Minute, GCInterval: 1 * time.Hour,
		}

		So(firstStorageConfig.ParamsEqual(secondStorageConfig), ShouldBeTrue)

		firstStorageConfig.GC = false

		So(firstStorageConfig.ParamsEqual(secondStorageConfig), ShouldBeFalse)

		firstStorageConfig.GC = true
		firstStorageConfig.Dedupe = false

		So(firstStorageConfig.ParamsEqual(secondStorageConfig), ShouldBeFalse)

		firstStorageConfig.Dedupe = true
		firstStorageConfig.GCDelay = 2 * time.Minute

		So(firstStorageConfig.ParamsEqual(secondStorageConfig), ShouldBeFalse)

		firstStorageConfig.GCDelay = 1 * time.Minute
		firstStorageConfig.GCInterval = 2 * time.Hour

		So(firstStorageConfig.ParamsEqual(secondStorageConfig), ShouldBeFalse)

		firstStorageConfig.GCInterval = 1 * time.Hour

		So(firstStorageConfig.ParamsEqual(secondStorageConfig), ShouldBeTrue)

		isSame, err := config.SameFile("test-config", "test")
		So(err, ShouldNotBeNil)
		So(isSame, ShouldBeFalse)

		dir1 := t.TempDir()

		isSame, err = config.SameFile(dir1, "test")
		So(err, ShouldNotBeNil)
		So(isSame, ShouldBeFalse)

		dir2 := t.TempDir()

		isSame, err = config.SameFile(dir1, dir2)
		So(err, ShouldBeNil)
		So(isSame, ShouldBeFalse)

		isSame, err = config.SameFile(dir1, dir1)
		So(err, ShouldBeNil)
		So(isSame, ShouldBeTrue)
	})

	Convey("Test DeepCopy() & Sanitize()", t, func() {
		Convey("Test DeepCopy negative cases", func() {
			conf := config.New()
			So(conf, ShouldNotBeNil)

			// negative
			obj := make(chan int)
			err := config.DeepCopy(conf, obj)
			So(err, ShouldNotBeNil)
			err = config.DeepCopy(obj, conf)
			So(err, ShouldNotBeNil)
		})

		Convey("Test Sanitize() with LDAP bind password", func() {
			conf := config.New()
			So(conf, ShouldNotBeNil)

			// Set LDAP bind password
			authConfig := &config.AuthConfig{LDAP: (&config.LDAPConfig{}).SetBindPassword("secret-ldap-password")}
			conf.HTTP.Auth = authConfig

			So(func() { conf.Sanitize() }, ShouldNotPanic)

			sanitizedConf := conf.Sanitize()
			So(sanitizedConf.HTTP.Auth.LDAP.BindPassword(), ShouldEqual, "******")

			// Verify original config is not modified
			So(conf.HTTP.Auth.LDAP.BindPassword(), ShouldEqual, "secret-ldap-password")
		})

		Convey("Test Sanitize() with OpenID client secrets", func() {
			conf := config.New()
			So(conf, ShouldNotBeNil)

			// Set OpenID client secrets
			authConfig := &config.AuthConfig{
				OpenID: &config.OpenIDConfig{
					Providers: map[string]config.OpenIDProviderConfig{
						"google": {
							Name:         "Google",
							ClientID:     "google-client-id",
							ClientSecret: "google-client-secret",
							Issuer:       "https://accounts.google.com",
							Scopes:       []string{"openid", "email"},
						},
						"github": {
							Name:         "GitHub",
							ClientID:     "github-client-id",
							ClientSecret: "github-client-secret",
							AuthURL:      "github-auth-url",
							TokenURL:     "github-token-url",
							Scopes:       []string{"user:email"},
						},
					},
				},
			}
			conf.HTTP.Auth = authConfig

			So(func() { conf.Sanitize() }, ShouldNotPanic)

			sanitizedConf := conf.Sanitize()

			// Verify OpenID client secrets are sanitized
			So(sanitizedConf.HTTP.Auth.OpenID.Providers["google"].ClientSecret, ShouldEqual, "******")
			So(sanitizedConf.HTTP.Auth.OpenID.Providers["github"].ClientSecret, ShouldEqual, "******")

			// Verify other fields are preserved
			So(sanitizedConf.HTTP.Auth.OpenID.Providers["google"].ClientID, ShouldEqual, "google-client-id")
			So(sanitizedConf.HTTP.Auth.OpenID.Providers["google"].Name, ShouldEqual, "Google")
			So(sanitizedConf.HTTP.Auth.OpenID.Providers["google"].Issuer, ShouldEqual, "https://accounts.google.com")
			So(sanitizedConf.HTTP.Auth.OpenID.Providers["google"].Scopes, ShouldResemble, []string{"openid", "email"})

			// Verify original config is not modified
			So(conf.HTTP.Auth.OpenID.Providers["google"].ClientSecret, ShouldEqual, "google-client-secret")
			So(conf.HTTP.Auth.OpenID.Providers["github"].ClientSecret, ShouldEqual, "github-client-secret")
			So(conf.HTTP.Auth.OpenID.Providers["github"].AuthURL, ShouldEqual, "github-auth-url")
			So(conf.HTTP.Auth.OpenID.Providers["github"].TokenURL, ShouldEqual, "github-token-url")
		})

		Convey("Test Sanitize() with Event sink credentials", func() {
			conf := config.New()
			So(conf, ShouldNotBeNil)

			// Enable events extension and set sink credentials
			enabled := true
			conf.Extensions = &extconf.ExtensionConfig{
				Events: &eventsconf.Config{
					Enable: &enabled,
					Sinks: []eventsconf.SinkConfig{
						{
							Type:    eventsconf.HTTP,
							Address: "https://example.com/webhook",
							Credentials: &eventsconf.Credentials{
								Username: "webhook-user",
								Password: "webhook-password",
							},
						},
						{
							Type:    eventsconf.NATS,
							Address: "nats://localhost:4222",
							Credentials: &eventsconf.Credentials{
								Username: "nats-user",
								Password: "nats-token",
							},
						},
					},
				},
			}

			So(func() { conf.Sanitize() }, ShouldNotPanic)

			sanitizedConf := conf.Sanitize()

			// Verify event sink credentials passwords are sanitized
			So(sanitizedConf.Extensions.Events.Sinks[0].Credentials.Password, ShouldEqual, "******")
			So(sanitizedConf.Extensions.Events.Sinks[1].Credentials.Password, ShouldEqual, "******")

			// Verify other fields are preserved
			So(sanitizedConf.Extensions.Events.Sinks[0].Credentials.Username, ShouldEqual, "webhook-user")
			So(sanitizedConf.Extensions.Events.Sinks[1].Credentials.Username, ShouldEqual, "nats-user")
			So(sanitizedConf.Extensions.Events.Sinks[0].Type, ShouldEqual, eventsconf.HTTP)
			So(sanitizedConf.Extensions.Events.Sinks[1].Type, ShouldEqual, eventsconf.NATS)

			// Verify original config is not modified
			So(conf.Extensions.Events.Sinks[0].Credentials.Password, ShouldEqual, "webhook-password")
			So(conf.Extensions.Events.Sinks[1].Credentials.Password, ShouldEqual, "nats-token")
		})

		Convey("Test Sanitize() with Event sink credentials including nil credentials", func() {
			conf := config.New()
			So(conf, ShouldNotBeNil)

			// Enable events extension with mixed sink credentials (some nil, some not)
			enabled := true
			conf.Extensions = &extconf.ExtensionConfig{
				Events: &eventsconf.Config{
					Enable: &enabled,
					Sinks: []eventsconf.SinkConfig{
						{
							Type:    eventsconf.HTTP,
							Address: "https://example.com/webhook",
							Credentials: &eventsconf.Credentials{
								Username: "webhook-user",
								Password: "webhook-password",
							},
						},
						{
							Type:        eventsconf.NATS,
							Address:     "nats://localhost:4222",
							Credentials: nil, // This should trigger the continue statement
						},
						{
							Type:    eventsconf.HTTP,
							Address: "https://another.com/webhook",
							Credentials: &eventsconf.Credentials{
								Username: "another-user",
								Password: "another-password",
							},
						},
					},
				},
			}

			So(func() { conf.Sanitize() }, ShouldNotPanic)

			sanitizedConf := conf.Sanitize()

			// Verify that sinks with credentials have their passwords sanitized
			So(sanitizedConf.Extensions.Events.Sinks[0].Credentials.Password, ShouldEqual, "******")
			So(sanitizedConf.Extensions.Events.Sinks[2].Credentials.Password, ShouldEqual, "******")

			// Verify that sink with nil credentials is preserved as-is (no panic, no modification)
			So(sanitizedConf.Extensions.Events.Sinks[1].Credentials, ShouldBeNil)
			So(sanitizedConf.Extensions.Events.Sinks[1].Type, ShouldEqual, eventsconf.NATS)
			So(sanitizedConf.Extensions.Events.Sinks[1].Address, ShouldEqual, "nats://localhost:4222")

			// Verify other fields are preserved
			So(sanitizedConf.Extensions.Events.Sinks[0].Credentials.Username, ShouldEqual, "webhook-user")
			So(sanitizedConf.Extensions.Events.Sinks[2].Credentials.Username, ShouldEqual, "another-user")
			So(sanitizedConf.Extensions.Events.Sinks[0].Type, ShouldEqual, eventsconf.HTTP)
			So(sanitizedConf.Extensions.Events.Sinks[2].Type, ShouldEqual, eventsconf.HTTP)

			// Verify original config is not modified
			So(conf.Extensions.Events.Sinks[0].Credentials.Password, ShouldEqual, "webhook-password")
			So(conf.Extensions.Events.Sinks[2].Credentials.Password, ShouldEqual, "another-password")
			So(conf.Extensions.Events.Sinks[1].Credentials, ShouldBeNil)
		})

		Convey("Test Sanitize() with all sensitive data types", func() {
			conf := config.New()
			So(conf, ShouldNotBeNil)

			// Set all types of sensitive data
			authConfig := &config.AuthConfig{
				LDAP: (&config.LDAPConfig{}).SetBindPassword("ldap-secret"),
				OpenID: &config.OpenIDConfig{
					Providers: map[string]config.OpenIDProviderConfig{
						"azure": {
							Name:         "Azure AD",
							ClientID:     "azure-client-id",
							ClientSecret: "azure-client-secret",
							Issuer:       "https://login.microsoftonline.com/...",
						},
					},
				},
			}
			conf.HTTP.Auth = authConfig

			// Enable events extension
			enabled := true
			conf.Extensions = &extconf.ExtensionConfig{
				Events: &eventsconf.Config{
					Enable: &enabled,
					Sinks: []eventsconf.SinkConfig{
						{
							Type:    eventsconf.HTTP,
							Address: "https://smtp.example.com/webhook",
							Credentials: &eventsconf.Credentials{
								Username: "smtp-user",
								Password: "smtp-password",
							},
						},
					},
				},
			}

			So(func() { conf.Sanitize() }, ShouldNotPanic)

			sanitizedConf := conf.Sanitize()

			// Verify all sensitive data is sanitized
			So(sanitizedConf.HTTP.Auth.LDAP.BindPassword(), ShouldEqual, "******")
			So(sanitizedConf.HTTP.Auth.OpenID.Providers["azure"].ClientSecret, ShouldEqual, "******")
			So(sanitizedConf.Extensions.Events.Sinks[0].Credentials.Password, ShouldEqual, "******")

			// Verify non-sensitive data is preserved
			So(sanitizedConf.HTTP.Auth.OpenID.Providers["azure"].ClientID, ShouldEqual, "azure-client-id")
			So(sanitizedConf.HTTP.Auth.OpenID.Providers["azure"].Name, ShouldEqual, "Azure AD")
			So(sanitizedConf.Extensions.Events.Sinks[0].Credentials.Username, ShouldEqual, "smtp-user")
			So(sanitizedConf.Extensions.Events.Sinks[0].Type, ShouldEqual, eventsconf.HTTP)
		})

		Convey("Test Sanitize() with nil sensitive data", func() {
			conf := config.New()
			So(conf, ShouldNotBeNil)

			// Set config with nil sensitive data
			authConfig := &config.AuthConfig{
				LDAP:   nil, // No LDAP config
				OpenID: nil, // No OpenID config
			}
			conf.HTTP.Auth = authConfig

			// No events extension
			conf.Extensions = nil

			So(func() { conf.Sanitize() }, ShouldNotPanic)

			sanitizedConf := conf.Sanitize()

			// Verify nil configs are handled gracefully
			So(sanitizedConf.HTTP.Auth.LDAP, ShouldBeNil)
			So(sanitizedConf.HTTP.Auth.OpenID, ShouldBeNil)
			So(sanitizedConf.Extensions, ShouldBeNil)
		})

		Convey("Test Sanitize() with empty sensitive data", func() {
			conf := config.New()
			So(conf, ShouldNotBeNil)

			// Set config with empty sensitive data
			authConfig := &config.AuthConfig{
				LDAP: (&config.LDAPConfig{}).SetBindPassword(""), // Empty password
				OpenID: &config.OpenIDConfig{
					Providers: map[string]config.OpenIDProviderConfig{
						"empty": {
							Name:         "Empty Provider",
							ClientID:     "empty-client-id",
							ClientSecret: "", // Empty secret
						},
					},
				},
			}
			conf.HTTP.Auth = authConfig

			// Enable events extension with empty password
			enabled := true
			conf.Extensions = &extconf.ExtensionConfig{
				Events: &eventsconf.Config{
					Enable: &enabled,
					Sinks: []eventsconf.SinkConfig{
						{
							Type:    eventsconf.HTTP,
							Address: "https://example.com/webhook",
							Credentials: &eventsconf.Credentials{
								Username: "user",
								Password: "", // Empty password
							},
						},
					},
				},
			}

			So(func() { conf.Sanitize() }, ShouldNotPanic)

			sanitizedConf := conf.Sanitize()

			// Verify empty passwords behavior
			// LDAP empty password should remain empty
			So(sanitizedConf.HTTP.Auth.LDAP.BindPassword(), ShouldEqual, "")
			// OpenID empty secret is always sanitized
			So(sanitizedConf.HTTP.Auth.OpenID.Providers["empty"].ClientSecret, ShouldEqual, "******")
			// Event sink empty password is always sanitized
			So(sanitizedConf.Extensions.Events.Sinks[0].Credentials.Password, ShouldEqual, "******")
		})

		Convey("Test Sanitize() with nil config", func() {
			var conf *config.Config = nil

			So(func() { conf.Sanitize() }, ShouldNotPanic)

			sanitizedConf := conf.Sanitize()
			So(sanitizedConf, ShouldBeNil)
		})
	})

	Convey("Test IsRetentionEnabled()", t, func() {
		// Test nil config
		var nilConf *config.Config = nil

		So(nilConf.IsRetentionEnabled(), ShouldBeFalse)

		conf := config.New()
		So(conf.IsRetentionEnabled(), ShouldBeFalse)

		conf.Storage.Retention.Policies = []config.RetentionPolicy{
			{
				Repositories: []string{"repo"},
			},
		}

		So(conf.IsRetentionEnabled(), ShouldBeFalse)

		policies := []config.RetentionPolicy{
			{
				Repositories: []string{"repo"},
				KeepTags: []config.KeepTagsPolicy{
					{
						Patterns:                []string{"tag"},
						MostRecentlyPulledCount: 2,
					},
				},
			},
		}

		conf.Storage.Retention = config.ImageRetention{
			Policies: policies,
		}

		So(conf.IsRetentionEnabled(), ShouldBeTrue)

		subPaths := make(map[string]config.StorageConfig)

		subPaths["/a"] = config.StorageConfig{
			GC: true,
			Retention: config.ImageRetention{
				Policies: policies,
			},
		}

		conf.Storage.SubPaths = subPaths

		So(conf.IsRetentionEnabled(), ShouldBeTrue)

		// Test MostRecentlyPushedCount
		conf = config.New()
		conf.Storage.Retention.Policies = []config.RetentionPolicy{
			{
				Repositories: []string{"repo"},
				KeepTags: []config.KeepTagsPolicy{
					{
						Patterns:                []string{"tag"},
						MostRecentlyPushedCount: 3,
					},
				},
			},
		}
		So(conf.IsRetentionEnabled(), ShouldBeTrue)

		// Test PulledWithin
		conf = config.New()
		duration := time.Hour * 24
		conf.Storage.Retention.Policies = []config.RetentionPolicy{
			{
				Repositories: []string{"repo"},
				KeepTags: []config.KeepTagsPolicy{
					{
						Patterns:     []string{"tag"},
						PulledWithin: &duration,
					},
				},
			},
		}
		So(conf.IsRetentionEnabled(), ShouldBeTrue)

		// Test PushedWithin
		conf = config.New()
		conf.Storage.Retention.Policies = []config.RetentionPolicy{
			{
				Repositories: []string{"repo"},
				KeepTags: []config.KeepTagsPolicy{
					{
						Patterns:     []string{"tag"},
						PushedWithin: &duration,
					},
				},
			},
		}
		So(conf.IsRetentionEnabled(), ShouldBeTrue)

		// Test SubPaths with retention policies
		conf = config.New()
		conf.Storage.SubPaths = map[string]config.StorageConfig{
			"subpath1": {
				Retention: config.ImageRetention{
					Policies: []config.RetentionPolicy{
						{
							Repositories: []string{"repo1"},
							KeepTags: []config.KeepTagsPolicy{
								{
									Patterns:                []string{"latest"},
									MostRecentlyPulledCount: 5,
								},
							},
						},
					},
				},
			},
		}
		So(conf.IsRetentionEnabled(), ShouldBeTrue)

		// Test empty policies with no retention criteria
		conf = config.New()
		conf.Storage.Retention.Policies = []config.RetentionPolicy{
			{
				Repositories: []string{"repo"},
				KeepTags: []config.KeepTagsPolicy{
					{
						Patterns: []string{"tag"},
						// No retention criteria set
					},
				},
			},
		}
		So(conf.IsRetentionEnabled(), ShouldBeFalse)
	})

	Convey("Test IsEventRecorderEnabled()", t, func() {
		conf := config.New()
		extensionsConfig := conf.CopyExtensionsConfig()
		So(extensionsConfig.IsEventRecorderEnabled(), ShouldBeFalse)

		// Enable the event recorder
		enable := true
		conf.Extensions = &extconf.ExtensionConfig{}
		conf.Extensions.Events = &eventsconf.Config{
			Enable: &enable,
		}

		extensionsConfig = conf.CopyExtensionsConfig()
		So(extensionsConfig.IsEventRecorderEnabled(), ShouldBeTrue)

		// Disabled scenario
		disable := false
		conf.Extensions.Events.Enable = &disable
		extensionsConfig = conf.CopyExtensionsConfig()
		So(extensionsConfig.IsEventRecorderEnabled(), ShouldBeFalse)

		// nil pointers
		conf.Extensions.Events = nil
		extensionsConfig = conf.CopyExtensionsConfig()
		So(extensionsConfig.IsEventRecorderEnabled(), ShouldBeFalse)

		conf.Extensions = nil
		extensionsConfig = conf.CopyExtensionsConfig()
		So(extensionsConfig.IsEventRecorderEnabled(), ShouldBeFalse)
	})

	Convey("Test AccessControlConfig.ContainsOnlyAnonymousPolicy()", t, func() {
		Convey("When accessControlConfig is nil", func() {
			var accessControlConfig *config.AccessControlConfig = nil

			result := accessControlConfig.ContainsOnlyAnonymousPolicy()
			So(result, ShouldBeTrue)
		})

		Convey("When accessControlConfig has admin policies", func() {
			accessControlConfig := &config.AccessControlConfig{}
			accessControlConfig.AdminPolicy = config.Policy{
				Actions: []string{"read"},
				Users:   []string{"admin"},
			}

			result := accessControlConfig.ContainsOnlyAnonymousPolicy()
			So(result, ShouldBeFalse)
		})

		Convey("When accessControlConfig has only anonymous policies", func() {
			accessControlConfig := &config.AccessControlConfig{}
			accessControlConfig.Repositories = config.Repositories{
				"repo1": config.PolicyGroup{
					AnonymousPolicy: []string{"read"},
				},
			}

			result := accessControlConfig.ContainsOnlyAnonymousPolicy()
			So(result, ShouldBeTrue)
		})

		Convey("When accessControlConfig has default policies", func() {
			accessControlConfig := &config.AccessControlConfig{}
			accessControlConfig.Repositories = config.Repositories{
				"repo1": config.PolicyGroup{
					DefaultPolicy: []string{"read"},
				},
			}

			result := accessControlConfig.ContainsOnlyAnonymousPolicy()
			So(result, ShouldBeFalse)
		})

		Convey("When accessControlConfig has non-empty repository policies", func() {
			accessControlConfig := &config.AccessControlConfig{}
			accessControlConfig.Repositories = config.Repositories{
				"repo1": config.PolicyGroup{
					Policies: []config.Policy{
						{
							Actions: []string{"read"},
							Users:   []string{"user1"},
						},
					},
				},
			}

			result := accessControlConfig.ContainsOnlyAnonymousPolicy()
			So(result, ShouldBeFalse)
		})

		Convey("When accessControlConfig has empty admin policy and no repositories", func() {
			accessControlConfig := &config.AccessControlConfig{}
			accessControlConfig.AdminPolicy = config.Policy{
				Actions: []string{},
				Users:   []string{},
			}
			accessControlConfig.Repositories = config.Repositories{}

			result := accessControlConfig.ContainsOnlyAnonymousPolicy()
			So(result, ShouldBeFalse)
		})

		Convey("When accessControlConfig has empty policies in repository", func() {
			accessControlConfig := &config.AccessControlConfig{}
			accessControlConfig.Repositories = config.Repositories{
				"repo1": config.PolicyGroup{
					AnonymousPolicy: []string{"read"},
					Policies: []config.Policy{
						{
							Actions: []string{},
							Users:   []string{},
						},
					},
				},
			}

			result := accessControlConfig.ContainsOnlyAnonymousPolicy()
			So(result, ShouldBeTrue)
		})
	})

	Convey("Test AuthConfig methods", t, func() {
		Convey("Test IsLdapAuthEnabled()", func() {
			// Test with nil AuthConfig
			var authConfig *config.AuthConfig = nil

			So(authConfig.IsLdapAuthEnabled(), ShouldBeFalse)

			// Test with AuthConfig but nil LDAP
			authConfig = &config.AuthConfig{}
			So(authConfig.IsLdapAuthEnabled(), ShouldBeFalse)

			// Test with AuthConfig and LDAP configured
			authConfig = &config.AuthConfig{
				LDAP: &config.LDAPConfig{},
			}
			So(authConfig.IsLdapAuthEnabled(), ShouldBeTrue)
		})

		Convey("Test IsHtpasswdAuthEnabled()", func() {
			// Test with nil AuthConfig
			var authConfig *config.AuthConfig = nil

			So(authConfig.IsHtpasswdAuthEnabled(), ShouldBeFalse)

			// Test with AuthConfig but empty HTPasswd path
			authConfig = &config.AuthConfig{
				HTPasswd: config.AuthHTPasswd{Path: ""},
			}
			So(authConfig.IsHtpasswdAuthEnabled(), ShouldBeFalse)

			// Test with AuthConfig and HTPasswd configured
			authConfig = &config.AuthConfig{
				HTPasswd: config.AuthHTPasswd{Path: "/path/to/htpasswd"},
			}
			So(authConfig.IsHtpasswdAuthEnabled(), ShouldBeTrue)
		})

		Convey("Test IsBearerAuthEnabled()", func() {
			// Test with nil AuthConfig
			var authConfig *config.AuthConfig = nil

			So(authConfig.IsBearerAuthEnabled(), ShouldBeFalse)

			// Test with AuthConfig but nil Bearer
			authConfig = &config.AuthConfig{}
			So(authConfig.IsBearerAuthEnabled(), ShouldBeFalse)

			// Test with AuthConfig and Bearer configured with all required fields
			authConfig = &config.AuthConfig{
				Bearer: &config.BearerConfig{
					Cert:    "/path/to/cert.pem",
					Realm:   "test-realm",
					Service: "test-service",
				},
			}
			So(authConfig.IsBearerAuthEnabled(), ShouldBeTrue)
		})

		Convey("Test IsTraditionalBearerAuthEnabled()", func() {
			// Test with nil AuthConfig
			var authConfig *config.AuthConfig = nil
			So(authConfig.IsTraditionalBearerAuthEnabled(), ShouldBeFalse)

			// Test with AuthConfig but nil Bearer
			authConfig = &config.AuthConfig{}
			So(authConfig.IsTraditionalBearerAuthEnabled(), ShouldBeFalse)

			// Test with AuthConfig and Bearer configured with all required fields
			authConfig = &config.AuthConfig{
				Bearer: &config.BearerConfig{
					Cert:    "/path/to/cert.pem",
					Realm:   "test-realm",
					Service: "test-service",
				},
			}
			So(authConfig.IsTraditionalBearerAuthEnabled(), ShouldBeTrue)

			// Test with partial config (missing Cert)
			authConfig = &config.AuthConfig{
				Bearer: &config.BearerConfig{
					Realm:   "test-realm",
					Service: "test-service",
				},
			}
			So(authConfig.IsTraditionalBearerAuthEnabled(), ShouldBeFalse)
		})

		Convey("Test IsOIDCBearerAuthEnabled()", func() {
			// Test with nil AuthConfig
			var authConfig *config.AuthConfig = nil
			So(authConfig.IsOIDCBearerAuthEnabled(), ShouldBeFalse)

			// Test with AuthConfig but nil Bearer
			authConfig = &config.AuthConfig{}
			So(authConfig.IsOIDCBearerAuthEnabled(), ShouldBeFalse)

			// Test with AuthConfig and OIDC Bearer configured
			authConfig = &config.AuthConfig{
				Bearer: &config.BearerConfig{
					OIDC: []config.BearerOIDCConfig{{
						Issuer:    "https://issuer.example.com",
						Audiences: []string{"zot"},
					}},
				},
			}
			So(authConfig.IsOIDCBearerAuthEnabled(), ShouldBeTrue)

			// Test with invalid OIDC config (missing audiences)
			authConfig = &config.AuthConfig{
				Bearer: &config.BearerConfig{
					OIDC: []config.BearerOIDCConfig{{
						Issuer: "https://issuer.example.com",
					}},
				},
			}
			So(authConfig.IsOIDCBearerAuthEnabled(), ShouldBeFalse)
		})

		Convey("Test IsOpenIDAuthEnabled()", func() {
			// Test with nil AuthConfig
			var authConfig *config.AuthConfig = nil

			So(authConfig.IsOpenIDAuthEnabled(), ShouldBeFalse)

			// Test with AuthConfig but nil OpenID
			authConfig = &config.AuthConfig{}
			So(authConfig.IsOpenIDAuthEnabled(), ShouldBeFalse)

			// Test with AuthConfig and OpenID configured with providers
			authConfig = &config.AuthConfig{
				OpenID: &config.OpenIDConfig{
					Providers: map[string]config.OpenIDProviderConfig{
						"google": {
							ClientID: "client-id",
						},
					},
				},
			}
			So(authConfig.IsOpenIDAuthEnabled(), ShouldBeTrue)
		})

		Convey("Test IsAPIKeyEnabled()", func() {
			// Test with nil AuthConfig
			var authConfig *config.AuthConfig = nil

			So(authConfig.IsAPIKeyEnabled(), ShouldBeFalse)

			// Test with AuthConfig but APIKey disabled
			authConfig = &config.AuthConfig{
				APIKey: false,
			}
			So(authConfig.IsAPIKeyEnabled(), ShouldBeFalse)

			// Test with AuthConfig and APIKey enabled
			authConfig = &config.AuthConfig{
				APIKey: true,
			}
			So(authConfig.IsAPIKeyEnabled(), ShouldBeTrue)
		})

		Convey("Test IsBasicAuthnEnabled()", func() {
			// Test with nil AuthConfig
			var authConfig *config.AuthConfig = nil

			So(authConfig.IsBasicAuthnEnabled(), ShouldBeFalse)

			// Test with AuthConfig but no basic auth methods
			authConfig = &config.AuthConfig{}
			So(authConfig.IsBasicAuthnEnabled(), ShouldBeFalse)

			// Test with HTPasswd enabled
			authConfig = &config.AuthConfig{
				HTPasswd: config.AuthHTPasswd{Path: "/path/to/htpasswd"},
			}
			So(authConfig.IsBasicAuthnEnabled(), ShouldBeTrue)

			// Test with LDAP enabled
			authConfig = &config.AuthConfig{
				LDAP: &config.LDAPConfig{},
			}
			So(authConfig.IsBasicAuthnEnabled(), ShouldBeTrue)

			// Test with OpenID enabled (with ClientID)
			authConfig = &config.AuthConfig{
				OpenID: &config.OpenIDConfig{
					Providers: map[string]config.OpenIDProviderConfig{
						"google": {
							ClientID: "client-id",
							Scopes:   []string{"openid", "email"},
						},
					},
				},
			}
			So(authConfig.IsBasicAuthnEnabled(), ShouldBeTrue)

			// Test with OpenID enabled (with Issuer)
			authConfig = &config.AuthConfig{
				OpenID: &config.OpenIDConfig{
					Providers: map[string]config.OpenIDProviderConfig{
						"google": {
							ClientID: "",
							Issuer:   "https://accounts.google.com",
							Scopes:   []string{},
						},
					},
				},
			}
			So(authConfig.IsBasicAuthnEnabled(), ShouldBeTrue)

			// Test with OpenID enabled (with Scopes only)
			authConfig = &config.AuthConfig{
				OpenID: &config.OpenIDConfig{
					Providers: map[string]config.OpenIDProviderConfig{
						"google": {
							ClientID: "",
							Issuer:   "",
							Scopes:   []string{"openid", "email"},
						},
					},
				},
			}
			So(authConfig.IsBasicAuthnEnabled(), ShouldBeTrue)

			// Test with OAuth2 provider (github)
			authConfig = &config.AuthConfig{
				OpenID: &config.OpenIDConfig{
					Providers: map[string]config.OpenIDProviderConfig{
						"github": {
							ClientID: "github-client-id",
							Scopes:   []string{"user:email"},
						},
					},
				},
			}
			So(authConfig.IsBasicAuthnEnabled(), ShouldBeTrue)

			// Test with OpenID but no valid providers (empty config)
			// Note: AuthConfig.IsOpenIDAuthEnabled() only checks if provider is supported,
			// not if the configuration is valid, so this returns true
			authConfig = &config.AuthConfig{
				OpenID: &config.OpenIDConfig{
					Providers: map[string]config.OpenIDProviderConfig{
						"google": {
							ClientID: "",
							Issuer:   "",
							Scopes:   []string{},
						},
					},
				},
			}
			So(authConfig.IsBasicAuthnEnabled(), ShouldBeTrue)

			// Test with OpenID but unsupported provider
			authConfig = &config.AuthConfig{
				OpenID: &config.OpenIDConfig{
					Providers: map[string]config.OpenIDProviderConfig{
						"unsupported": {
							ClientID: "client-id",
							Scopes:   []string{"scope"},
						},
					},
				},
			}
			So(authConfig.IsBasicAuthnEnabled(), ShouldBeFalse)

			// Test with APIKey enabled
			authConfig = &config.AuthConfig{
				APIKey: true,
			}
			So(authConfig.IsBasicAuthnEnabled(), ShouldBeTrue)
		})

		Convey("Test GetFailDelay()", func() {
			// Test with nil AuthConfig
			var authConfig *config.AuthConfig = nil

			So(authConfig.GetFailDelay(), ShouldEqual, 0)

			// Test with AuthConfig and custom FailDelay
			authConfig = &config.AuthConfig{
				FailDelay: 5,
			}
			So(authConfig.GetFailDelay(), ShouldEqual, 5)
		})

		Convey("Test GetMTLSConfig()", func() {
			// Test with nil AuthConfig
			var authConfig *config.AuthConfig = nil

			So(authConfig.GetMTLSConfig(), ShouldBeNil)

			// Test with AuthConfig but nil MTLS
			authConfig = &config.AuthConfig{}
			So(authConfig.GetMTLSConfig(), ShouldBeNil)

			// Test with AuthConfig and MTLS configured
			authConfig = &config.AuthConfig{
				MTLS: &config.MTLSConfig{
					IdentityAttibutes: []string{"CommonName", "URI"},
					URISANPattern:     "spiffe://example.org/workload/(.*)",
				},
			}
			mtlsConfig := authConfig.GetMTLSConfig()
			So(mtlsConfig, ShouldNotBeNil)
			So(len(mtlsConfig.IdentityAttibutes), ShouldEqual, 2)
			So(mtlsConfig.IdentityAttibutes[0], ShouldEqual, "CommonName")
			So(mtlsConfig.IdentityAttibutes[1], ShouldEqual, "URI")
			So(mtlsConfig.URISANPattern, ShouldEqual, "spiffe://example.org/workload/(.*)")
		})
	})

	Convey("Test LDAPConfig methods", t, func() {
		Convey("Test BindDN()", func() {
			ldapConfig := &config.LDAPConfig{}
			So(ldapConfig.BindDN(), ShouldEqual, "")

			ldapConfig.SetBindDN("cn=admin,dc=example,dc=com")
			So(ldapConfig.BindDN(), ShouldEqual, "cn=admin,dc=example,dc=com")
		})

		Convey("Test BindPassword()", func() {
			ldapConfig := &config.LDAPConfig{}
			So(ldapConfig.BindPassword(), ShouldEqual, "")

			ldapConfig.SetBindPassword("secretpassword")
			So(ldapConfig.BindPassword(), ShouldEqual, "secretpassword")
		})
	})

	Convey("Test AccessControlConfig methods", t, func() {
		Convey("Test IsAuthzEnabled()", func() {
			// Test with nil AccessControlConfig
			var accessControlConfig *config.AccessControlConfig = nil

			So(accessControlConfig.IsAuthzEnabled(), ShouldBeFalse)

			// Test with AccessControlConfig
			accessControlConfig = &config.AccessControlConfig{}
			So(accessControlConfig.IsAuthzEnabled(), ShouldBeTrue)
		})

		Convey("Test AnonymousPolicyExists()", func() {
			// Test with nil AccessControlConfig
			var accessControlConfig *config.AccessControlConfig = nil

			So(accessControlConfig.AnonymousPolicyExists(), ShouldBeFalse)

			// Test with AccessControlConfig but no repositories
			accessControlConfig = &config.AccessControlConfig{}
			So(accessControlConfig.AnonymousPolicyExists(), ShouldBeFalse)

			// Test with AccessControlConfig and repository with anonymous policy
			accessControlConfig = &config.AccessControlConfig{}
			accessControlConfig.Repositories = config.Repositories{
				"repo1": config.PolicyGroup{
					AnonymousPolicy: []string{"read"},
				},
			}
			So(accessControlConfig.AnonymousPolicyExists(), ShouldBeTrue)

			// Test with AccessControlConfig and repository without anonymous policy
			accessControlConfig = &config.AccessControlConfig{}
			accessControlConfig.Repositories = config.Repositories{
				"repo1": config.PolicyGroup{
					DefaultPolicy: []string{"read"},
				},
			}
			So(accessControlConfig.AnonymousPolicyExists(), ShouldBeFalse)
		})

		Convey("Test GetRepositories()", func() {
			repositories := config.Repositories{
				"repo1": config.PolicyGroup{
					AnonymousPolicy: []string{"read"},
				},
			}
			accessControlConfig := &config.AccessControlConfig{}
			accessControlConfig.Repositories = repositories
			So(accessControlConfig.GetRepositories(), ShouldResemble, repositories)
		})

		Convey("Test GetAdminPolicy()", func() {
			adminPolicy := config.Policy{
				Actions: []string{"read", "write"},
				Users:   []string{"admin"},
			}
			accessControlConfig := &config.AccessControlConfig{}
			accessControlConfig.AdminPolicy = adminPolicy
			So(accessControlConfig.GetAdminPolicy(), ShouldResemble, adminPolicy)
		})

		Convey("Test GetMetrics()", func() {
			metrics := config.Metrics{
				Users: []string{"metrics-user"},
			}
			accessControlConfig := &config.AccessControlConfig{}
			accessControlConfig.Metrics = metrics
			So(accessControlConfig.GetMetrics(), ShouldResemble, metrics)
		})

		Convey("Test GetGroups()", func() {
			groups := config.Groups{
				"developers": config.Group{
					Users: []string{"dev1", "dev2"},
				},
			}
			accessControlConfig := &config.AccessControlConfig{}
			accessControlConfig.Groups = groups
			So(accessControlConfig.GetGroups(), ShouldResemble, groups)
		})
	})

	Convey("Test Config getter methods", t, func() {
		Convey("Test CopyAuthConfig()", func() {
			Convey("Test with non-nil Auth", func() {
				cfg := &config.Config{
					HTTP: config.HTTPConfig{
						Auth: &config.AuthConfig{
							FailDelay: 5,
						},
					},
				}
				authConfig := cfg.CopyAuthConfig()
				So(authConfig, ShouldNotBeNil)
				So(authConfig.GetFailDelay(), ShouldEqual, 5)
			})

			Convey("Test with nil Auth", func() {
				cfg := &config.Config{
					HTTP: config.HTTPConfig{
						Auth: nil,
					},
				}
				authConfig := cfg.CopyAuthConfig()
				So(authConfig, ShouldBeNil)
			})

			Convey("Test that returned AuthConfig is isolated from config mutations", func() {
				// Create initial config with AuthConfig containing nested structures
				cfg := &config.Config{
					HTTP: config.HTTPConfig{
						Auth: &config.AuthConfig{
							FailDelay: 5,
							HTPasswd: config.AuthHTPasswd{
								Path: "/etc/htpasswd",
							},
							LDAP: &config.LDAPConfig{
								Address: "ldap.example.com",
								Port:    389,
							},
							Bearer: &config.BearerConfig{
								Realm:   "test-realm",
								Service: "test-service",
								Cert:    "/path/to/cert",
							},
							OpenID: &config.OpenIDConfig{
								Providers: map[string]config.OpenIDProviderConfig{
									"google": {
										Name:     "Google",
										ClientID: "google-client-id",
										Scopes:   []string{"openid", "email"},
									},
								},
							},
							APIKey:            false,
							SessionKeysFile:   "/etc/session-keys",
							SessionHashKey:    []byte("hash-key"),
							SessionEncryptKey: []byte("encrypt-key"),
							SessionDriver: map[string]any{
								"type": "redis",
								"host": "localhost",
							},
							MTLS: &config.MTLSConfig{
								IdentityAttibutes: []string{"CommonName"},
								URISANPattern:     "spiffe://example.org/workload/(.*)",
							},
						},
					},
				}

				// Get the AuthConfig reference
				authConfig := cfg.CopyAuthConfig()
				So(authConfig, ShouldNotBeNil)
				So(authConfig.GetFailDelay(), ShouldEqual, 5)
				So(authConfig.IsHtpasswdAuthEnabled(), ShouldBeTrue)
				So(authConfig.IsLdapAuthEnabled(), ShouldBeTrue)
				So(authConfig.IsBearerAuthEnabled(), ShouldBeTrue)
				So(authConfig.IsOpenIDAuthEnabled(), ShouldBeTrue)
				So(authConfig.IsAPIKeyEnabled(), ShouldBeFalse)
				So(authConfig.GetMTLSConfig(), ShouldNotBeNil)
				So(authConfig.GetMTLSConfig().IdentityAttibutes[0], ShouldEqual, "CommonName")

				// Test deep copy isolation by modifying nested structures
				authConfig.LDAP.Address = "modified-ldap.example.com"
				authConfig.Bearer.Realm = "modified-realm"
				authConfig.OpenID.Providers["google"].Scopes[0] = "modified-scope"
				authConfig.SessionHashKey[0] = 'M'
				authConfig.SessionDriver["type"] = "modified-driver"
				authConfig.MTLS.IdentityAttibutes[0] = "URI"
				authConfig.MTLS.URISANPattern = "modified-pattern"

				// Verify original is unchanged
				So(cfg.HTTP.Auth.LDAP.Address, ShouldEqual, "ldap.example.com")
				So(cfg.HTTP.Auth.Bearer.Realm, ShouldEqual, "test-realm")
				So(cfg.HTTP.Auth.OpenID.Providers["google"].Scopes[0], ShouldEqual, "openid")
				So(cfg.HTTP.Auth.SessionHashKey[0], ShouldEqual, byte('h'))
				So(cfg.HTTP.Auth.SessionDriver["type"], ShouldEqual, "redis")
				So(cfg.HTTP.Auth.MTLS.IdentityAttibutes[0], ShouldEqual, "CommonName")
				So(cfg.HTTP.Auth.MTLS.URISANPattern, ShouldEqual, "spiffe://example.org/workload/(.*)")
			})

			Convey("Test that returned AuthConfig is isolated when config is updated via UpdateReloadableConfig", func() {
				// Create initial config with AuthConfig
				cfg := &config.Config{
					HTTP: config.HTTPConfig{
						Auth: &config.AuthConfig{
							FailDelay: 5,
							HTPasswd: config.AuthHTPasswd{
								Path: "/etc/htpasswd",
							},
							APIKey: false,
						},
					},
				}

				// Get the AuthConfig reference
				authConfig := cfg.CopyAuthConfig()
				So(authConfig, ShouldNotBeNil)
				So(authConfig.GetFailDelay(), ShouldEqual, 5)
				So(authConfig.IsHtpasswdAuthEnabled(), ShouldBeTrue)
				So(authConfig.IsAPIKeyEnabled(), ShouldBeFalse)

				// Create new config with updated AuthConfig
				// Note: UpdateReloadableConfig updates HTPasswd, LDAP, APIKey, and OpenID fields
				newConfig := &config.Config{
					HTTP: config.HTTPConfig{
						Auth: &config.AuthConfig{
							FailDelay: 15, // This field is NOT updated by UpdateReloadableConfig
							HTPasswd: config.AuthHTPasswd{
								Path: "/etc/updated-htpasswd", // This field IS updated by UpdateReloadableConfig
							},
							APIKey: true, // This field IS updated by UpdateReloadableConfig
						},
					},
				}

				// Update the config using UpdateReloadableConfig
				cfg.UpdateReloadableConfig(newConfig)

				// Verify that the returned AuthConfig is not affected by the update
				// CopyAuthConfig() returns a copy, so the returned object should be isolated
				So(authConfig.GetFailDelay(), ShouldEqual, 5)        // Should remain unchanged
				So(authConfig.IsHtpasswdAuthEnabled(), ShouldBeTrue) // Should remain unchanged (old path)
				So(authConfig.IsAPIKeyEnabled(), ShouldBeFalse)      // Should remain unchanged

				// Verify that a new CopyAuthConfig() call returns the updated values
				newAuthConfig := cfg.CopyAuthConfig()
				So(newAuthConfig, ShouldNotBeNil)
				// Should remain unchanged (not updated by UpdateReloadableConfig)
				So(newAuthConfig.GetFailDelay(), ShouldEqual, 5)
				So(newAuthConfig.IsHtpasswdAuthEnabled(), ShouldBeTrue) // Should be updated (new path)
				// Should be updated by UpdateReloadableConfig
				So(newAuthConfig.IsAPIKeyEnabled(), ShouldBeTrue)
			})

			Convey("Test that returned AuthConfig is isolated when config is set to nil", func() {
				// Create initial config with AuthConfig
				cfg := &config.Config{
					HTTP: config.HTTPConfig{
						Auth: &config.AuthConfig{
							FailDelay: 5,
							HTPasswd: config.AuthHTPasswd{
								Path: "/etc/htpasswd",
							},
							APIKey: false,
						},
					},
				}

				// Get the AuthConfig reference
				authConfig := cfg.CopyAuthConfig()
				So(authConfig, ShouldNotBeNil)
				So(authConfig.GetFailDelay(), ShouldEqual, 5)
				So(authConfig.IsHtpasswdAuthEnabled(), ShouldBeTrue)
				So(authConfig.IsAPIKeyEnabled(), ShouldBeFalse)

				// Set the AuthConfig to nil
				cfg.HTTP.Auth = nil

				// Verify that the returned AuthConfig is not affected by setting to nil
				So(authConfig, ShouldNotBeNil)                       // Should remain unchanged
				So(authConfig.GetFailDelay(), ShouldEqual, 5)        // Should remain unchanged
				So(authConfig.IsHtpasswdAuthEnabled(), ShouldBeTrue) // Should remain unchanged
				So(authConfig.IsAPIKeyEnabled(), ShouldBeFalse)      // Should remain unchanged

				// Verify that a new CopyAuthConfig() call returns nil
				newAuthConfig := cfg.CopyAuthConfig()
				So(newAuthConfig, ShouldBeNil) // Should be nil
			})
		})

		Convey("Test CopyAccessControlConfig()", func() {
			Convey("Test with non-nil AccessControl", func() {
				testAccessControlConfig := &config.AccessControlConfig{
					Repositories: config.Repositories{
						"repo1": config.PolicyGroup{
							Policies: []config.Policy{
								{
									Users:   []string{"user1", "user2"},
									Actions: []string{"read", "write"},
									Groups:  []string{"group1"},
								},
							},
							DefaultPolicy:   []string{"read"},
							AnonymousPolicy: []string{"read"},
						},
					},
					AdminPolicy: config.Policy{
						Users:   []string{"admin1"},
						Actions: []string{"read", "write", "delete"},
						Groups:  []string{"admin-group"},
					},
					Groups: config.Groups{
						"group1": config.Group{
							Users: []string{"user1", "user2"},
						},
					},
					Metrics: config.Metrics{
						Users: []string{"metrics-user"},
					},
				}
				cfg := &config.Config{
					HTTP: config.HTTPConfig{
						AccessControl: testAccessControlConfig,
					},
				}
				accessControlConfig := cfg.CopyAccessControlConfig()
				So(accessControlConfig, ShouldNotBeNil)
				So(accessControlConfig.IsAuthzEnabled(), ShouldBeTrue)

				// Test deep copy isolation
				accessControlConfig.Repositories["repo1"].Policies[0].Users[0] = "modified-user"
				accessControlConfig.Repositories["repo1"].DefaultPolicy[0] = "modified-policy"
				accessControlConfig.AdminPolicy.Users[0] = "modified-admin"
				accessControlConfig.Groups["group1"].Users[0] = "modified-group-user"
				accessControlConfig.Metrics.Users[0] = "modified-metrics-user"

				// Verify original is unchanged
				So(cfg.HTTP.AccessControl.Repositories["repo1"].Policies[0].Users[0], ShouldEqual, "user1")
				So(cfg.HTTP.AccessControl.Repositories["repo1"].DefaultPolicy[0], ShouldEqual, "read")
				So(cfg.HTTP.AccessControl.AdminPolicy.Users[0], ShouldEqual, "admin1")
				So(cfg.HTTP.AccessControl.Groups["group1"].Users[0], ShouldEqual, "user1")
				So(cfg.HTTP.AccessControl.Metrics.Users[0], ShouldEqual, "metrics-user")
			})

			Convey("Test with nil AccessControl", func() {
				cfg := &config.Config{
					HTTP: config.HTTPConfig{
						AccessControl: nil,
					},
				}
				accessControlConfig := cfg.CopyAccessControlConfig()
				So(accessControlConfig, ShouldBeNil)
			})
		})

		Convey("Test CopyStorageConfig()", func() {
			Convey("Test with non-nil Storage", func() {
				cfg := &config.Config{
					Storage: config.GlobalStorageConfig{
						StorageConfig: config.StorageConfig{
							RootDirectory: "/tmp/storage",
							GC:            true,
						},
					},
				}
				storageConfig := cfg.CopyStorageConfig()
				So(storageConfig, ShouldNotBeNil)
				So(storageConfig.RootDirectory, ShouldEqual, "/tmp/storage")
				So(storageConfig.GC, ShouldBeTrue)
			})

			Convey("Test with nil Storage", func() {
				cfg := &config.Config{
					Storage: config.GlobalStorageConfig{},
				}
				storageConfig := cfg.CopyStorageConfig()
				So(storageConfig, ShouldNotBeNil) // GlobalStorageConfig is a struct, not a pointer, so it's never nil
				So(storageConfig.RootDirectory, ShouldEqual, "")
				So(storageConfig.GC, ShouldBeFalse)
			})

			Convey("Test StorageConfig deep copy isolation", func() {
				cfg := &config.Config{
					Storage: config.GlobalStorageConfig{
						StorageConfig: config.StorageConfig{
							RootDirectory: "/tmp/storage",
							GC:            true,
							Retention: config.ImageRetention{
								DryRun: true,
								Policies: []config.RetentionPolicy{
									{
										Repositories: []string{"repo1", "repo2"},
										KeepTags: []config.KeepTagsPolicy{
											{
												Patterns: []string{"pattern1", "pattern2"},
											},
										},
									},
								},
							},
							StorageDriver: map[string]any{
								"type": "filesystem",
							},
							CacheDriver: map[string]any{
								"type": "redis",
							},
						},
						SubPaths: map[string]config.StorageConfig{
							"/subpath1": {
								RootDirectory: "/tmp/subpath1",
								Retention: config.ImageRetention{
									Policies: []config.RetentionPolicy{
										{
											Repositories: []string{"subrepo1"},
										},
									},
								},
								StorageDriver: map[string]any{
									"type": "s3",
								},
							},
						},
					},
				}

				// Get a copy of the storage config
				storageConfig := cfg.CopyStorageConfig()
				So(storageConfig, ShouldNotBeNil)

				// Mutate the copy's fields
				storageConfig.RootDirectory = "/modified/storage"
				storageConfig.GC = false
				storageConfig.Retention.Policies[0].Repositories[0] = "modified-repo"
				storageConfig.Retention.Policies[0].KeepTags[0].Patterns[0] = "modified-pattern"
				storageConfig.StorageDriver["type"] = "modified-driver"
				storageConfig.CacheDriver["type"] = "modified-cache"

				// Mutate SubPaths by getting a copy, modifying it, and putting it back
				subPathConfig := storageConfig.SubPaths["/subpath1"]
				subPathConfig.RootDirectory = "/modified/subpath1"
				subPathConfig.Retention.Policies[0].Repositories[0] = "modified-subrepo"
				subPathConfig.StorageDriver["type"] = "modified-s3"
				storageConfig.SubPaths["/subpath1"] = subPathConfig

				// Verify original config is unchanged
				So(cfg.Storage.RootDirectory, ShouldEqual, "/tmp/storage")
				So(cfg.Storage.GC, ShouldBeTrue)
				So(cfg.Storage.Retention.Policies[0].Repositories[0], ShouldEqual, "repo1")
				So(cfg.Storage.Retention.Policies[0].KeepTags[0].Patterns[0], ShouldEqual, "pattern1")
				So(cfg.Storage.StorageDriver["type"], ShouldEqual, "filesystem")
				So(cfg.Storage.CacheDriver["type"], ShouldEqual, "redis")
				So(cfg.Storage.SubPaths["/subpath1"].RootDirectory, ShouldEqual, "/tmp/subpath1")
				So(cfg.Storage.SubPaths["/subpath1"].Retention.Policies[0].Repositories[0], ShouldEqual, "subrepo1")
				So(cfg.Storage.SubPaths["/subpath1"].StorageDriver["type"], ShouldEqual, "s3")

				// Verify copy has the mutations
				So(storageConfig.RootDirectory, ShouldEqual, "/modified/storage")
				So(storageConfig.GC, ShouldBeFalse)
				So(storageConfig.Retention.Policies[0].Repositories[0], ShouldEqual, "modified-repo")
				So(storageConfig.Retention.Policies[0].KeepTags[0].Patterns[0], ShouldEqual, "modified-pattern")
				So(storageConfig.StorageDriver["type"], ShouldEqual, "modified-driver")
				So(storageConfig.CacheDriver["type"], ShouldEqual, "modified-cache")
				So(storageConfig.SubPaths["/subpath1"].RootDirectory, ShouldEqual, "/modified/subpath1")
				So(storageConfig.SubPaths["/subpath1"].Retention.Policies[0].Repositories[0], ShouldEqual, "modified-subrepo")
				So(storageConfig.SubPaths["/subpath1"].StorageDriver["type"], ShouldEqual, "modified-s3")
			})
		})

		Convey("Test CopyLogConfig()", func() {
			Convey("Test with non-nil Log", func() {
				cfg := &config.Config{
					Log: &config.LogConfig{
						Level:  "info",
						Output: "/tmp/logs",
					},
				}
				logConfig := cfg.CopyLogConfig()
				So(logConfig, ShouldNotBeNil)
				So(logConfig.Level, ShouldEqual, "info")
				So(logConfig.Output, ShouldEqual, "/tmp/logs")
			})

			Convey("Test with nil Log", func() {
				cfg := &config.Config{
					Log: nil,
				}
				logConfig := cfg.CopyLogConfig()
				So(logConfig, ShouldBeNil)
			})
		})

		Convey("Test CopyClusterConfig()", func() {
			Convey("Test with non-nil Cluster", func() {
				cfg := &config.Config{
					Cluster: &config.ClusterConfig{
						Members: []string{"node1", "node2"},
					},
				}
				clusterConfig := cfg.CopyClusterConfig()
				So(clusterConfig, ShouldNotBeNil)
				So(len(clusterConfig.Members), ShouldEqual, 2)
			})

			Convey("Test with nil Cluster", func() {
				cfg := &config.Config{
					Cluster: nil,
				}
				clusterConfig := cfg.CopyClusterConfig()
				So(clusterConfig, ShouldBeNil)
			})

			Convey("Test ClusterConfig deep copy isolation", func() {
				cfg := &config.Config{
					Cluster: &config.ClusterConfig{
						Members: []string{"node1", "node2"},
						HashKey: "test-key",
						TLS: &config.TLSConfig{
							Cert:   "test-cert",
							Key:    "test-key",
							CACert: "test-ca",
						},
						Proxy: &config.ClusterRequestProxyConfig{
							LocalMemberClusterSocket:      "127.0.0.1:8080",
							LocalMemberClusterSocketIndex: 1,
						},
					},
				}

				// Get a copy of the cluster config
				clusterConfig := cfg.CopyClusterConfig()
				So(clusterConfig, ShouldNotBeNil)

				// Mutate the copy
				clusterConfig.Members[0] = "modified-node"
				clusterConfig.HashKey = "modified-key"
				clusterConfig.TLS.Cert = "modified-cert"
				clusterConfig.Proxy.LocalMemberClusterSocket = "modified-socket"

				// Verify original config is unchanged
				So(cfg.Cluster.Members[0], ShouldEqual, "node1")
				So(cfg.Cluster.HashKey, ShouldEqual, "test-key")
				So(cfg.Cluster.TLS.Cert, ShouldEqual, "test-cert")
				So(cfg.Cluster.Proxy.LocalMemberClusterSocket, ShouldEqual, "127.0.0.1:8080")

				// Verify copy has the mutations
				So(clusterConfig.Members[0], ShouldEqual, "modified-node")
				So(clusterConfig.HashKey, ShouldEqual, "modified-key")
				So(clusterConfig.TLS.Cert, ShouldEqual, "modified-cert")
				So(clusterConfig.Proxy.LocalMemberClusterSocket, ShouldEqual, "modified-socket")
			})
		})

		Convey("Test CopySchedulerConfig()", func() {
			Convey("Test with non-nil Scheduler", func() {
				cfg := &config.Config{
					Scheduler: &config.SchedulerConfig{
						NumWorkers: 4,
					},
				}
				schedulerConfig := cfg.CopySchedulerConfig()
				So(schedulerConfig, ShouldNotBeNil)
				So(schedulerConfig.NumWorkers, ShouldEqual, 4)
			})

			Convey("Test with nil Scheduler", func() {
				cfg := &config.Config{
					Scheduler: nil,
				}
				schedulerConfig := cfg.CopySchedulerConfig()
				So(schedulerConfig, ShouldBeNil)
			})
		})

		Convey("Test GetVersionInfo()", func() {
			Convey("Test with non-nil version info", func() {
				cfg := &config.Config{
					Commit:          "abc123",
					BinaryType:      "server",
					GoVersion:       "go1.21",
					DistSpecVersion: "1.1.1",
				}
				commit, binaryType, goVersion, distSpecVersion := cfg.GetVersionInfo()
				So(commit, ShouldEqual, "abc123")
				So(binaryType, ShouldEqual, "server")
				So(goVersion, ShouldEqual, "go1.21")
				So(distSpecVersion, ShouldEqual, "1.1.1")
			})

			Convey("Test with empty version info", func() {
				cfg := &config.Config{
					Commit:          "",
					BinaryType:      "",
					GoVersion:       "",
					DistSpecVersion: "",
				}
				commit, binaryType, goVersion, distSpecVersion := cfg.GetVersionInfo()
				So(commit, ShouldEqual, "")
				So(binaryType, ShouldEqual, "")
				So(goVersion, ShouldEqual, "")
				So(distSpecVersion, ShouldEqual, "")
			})
		})

		Convey("Test GetRealm()", func() {
			Convey("Test with non-empty Realm", func() {
				cfg := &config.Config{
					HTTP: config.HTTPConfig{
						Realm: "my-realm",
					},
				}
				realm := cfg.GetRealm()
				So(realm, ShouldEqual, "my-realm")
			})

			Convey("Test with empty Realm", func() {
				cfg := &config.Config{
					HTTP: config.HTTPConfig{
						Realm: "",
					},
				}
				realm := cfg.GetRealm()
				So(realm, ShouldEqual, "")
			})

			Convey("Test with nil Config", func() {
				var cfg *config.Config = nil
				realm := cfg.GetRealm()
				So(realm, ShouldEqual, "")
			})
		})

		Convey("Test CopyTLSConfig()", func() {
			Convey("Test with non-empty TLS config", func() {
				cfg := &config.Config{
					HTTP: config.HTTPConfig{
						TLS: &config.TLSConfig{
							Cert:   "/path/to/cert.pem",
							Key:    "/path/to/key.pem",
							CACert: "/path/to/ca.pem",
						},
					},
				}
				tlsConfig := cfg.CopyTLSConfig()
				So(tlsConfig, ShouldNotBeNil)
				So(tlsConfig.Cert, ShouldEqual, "/path/to/cert.pem")
				So(tlsConfig.Key, ShouldEqual, "/path/to/key.pem")
				So(tlsConfig.CACert, ShouldEqual, "/path/to/ca.pem")

				// Test copy isolation
				tlsConfig.Cert = "/modified/cert.pem"

				So(cfg.HTTP.TLS.Cert, ShouldEqual, "/path/to/cert.pem")
			})

			Convey("Test with nil TLS config", func() {
				cfg := &config.Config{
					HTTP: config.HTTPConfig{
						TLS: nil,
					},
				}
				tlsConfig := cfg.CopyTLSConfig()
				So(tlsConfig, ShouldBeNil)
			})

			Convey("Test with nil Config", func() {
				var cfg *config.Config = nil
				tlsConfig := cfg.CopyTLSConfig()
				So(tlsConfig, ShouldBeNil)
			})
		})

		Convey("Test GetCompat()", func() {
			Convey("Test with non-empty compat config", func() {
				cfg := &config.Config{
					HTTP: config.HTTPConfig{
						Compat: []compat.MediaCompatibility{
							"docker2s2",
							"oci1",
						},
					},
				}
				compatConfig := cfg.GetCompat()
				So(compatConfig, ShouldNotBeNil)
				So(len(compatConfig), ShouldEqual, 2)
				So(string(compatConfig[0]), ShouldEqual, "docker2s2")
				So(string(compatConfig[1]), ShouldEqual, "oci1")

				// Test copy isolation
				compatConfig[0] = "modified-compat"

				So(string(cfg.HTTP.Compat[0]), ShouldEqual, "docker2s2")
			})

			Convey("Test with nil compat config", func() {
				cfg := &config.Config{
					HTTP: config.HTTPConfig{
						Compat: nil,
					},
				}
				compatConfig := cfg.GetCompat()
				So(compatConfig, ShouldBeNil)
			})

			Convey("Test with empty compat config", func() {
				cfg := &config.Config{
					HTTP: config.HTTPConfig{
						Compat: []compat.MediaCompatibility{},
					},
				}
				compatConfig := cfg.GetCompat()
				So(compatConfig, ShouldNotBeNil)
				So(len(compatConfig), ShouldEqual, 0)
			})

			Convey("Test with nil Config", func() {
				var cfg *config.Config = nil
				compatConfig := cfg.GetCompat()
				So(compatConfig, ShouldBeNil)
			})
		})

		Convey("Test GetHTTPAddress()", func() {
			Convey("Test with non-empty address", func() {
				cfg := &config.Config{
					HTTP: config.HTTPConfig{
						Address: "192.168.1.100",
					},
				}
				address := cfg.GetHTTPAddress()
				So(address, ShouldEqual, "192.168.1.100")
			})

			Convey("Test with empty address", func() {
				cfg := &config.Config{
					HTTP: config.HTTPConfig{
						Address: "",
					},
				}
				address := cfg.GetHTTPAddress()
				So(address, ShouldEqual, "")
			})

			Convey("Test with nil Config", func() {
				var cfg *config.Config = nil
				address := cfg.GetHTTPAddress()
				So(address, ShouldEqual, "")
			})
		})

		Convey("Test GetHTTPPort()", func() {
			Convey("Test with non-empty port", func() {
				cfg := &config.Config{
					HTTP: config.HTTPConfig{
						Port: "8080",
					},
				}
				port := cfg.GetHTTPPort()
				So(port, ShouldEqual, "8080")
			})

			Convey("Test with empty port", func() {
				cfg := &config.Config{
					HTTP: config.HTTPConfig{
						Port: "",
					},
				}
				port := cfg.GetHTTPPort()
				So(port, ShouldEqual, "")
			})

			Convey("Test with nil Config", func() {
				var cfg *config.Config = nil
				port := cfg.GetHTTPPort()
				So(port, ShouldEqual, "")
			})
		})

		Convey("Test GetAllowOrigin()", func() {
			Convey("Test with non-empty allow origin", func() {
				cfg := &config.Config{
					HTTP: config.HTTPConfig{
						AllowOrigin: "http://localhost:3000,https://example.com",
					},
				}
				allowOrigin := cfg.GetAllowOrigin()
				So(allowOrigin, ShouldEqual, "http://localhost:3000,https://example.com")
			})

			Convey("Test with empty allow origin", func() {
				cfg := &config.Config{
					HTTP: config.HTTPConfig{
						AllowOrigin: "",
					},
				}
				allowOrigin := cfg.GetAllowOrigin()
				So(allowOrigin, ShouldEqual, "")
			})

			Convey("Test with nil Config", func() {
				var cfg *config.Config = nil
				allowOrigin := cfg.GetAllowOrigin()
				So(allowOrigin, ShouldEqual, "")
			})
		})

		Convey("Test CopyRatelimit()", func() {
			Convey("Test with non-empty ratelimit config", func() {
				rate := 100
				cfg := &config.Config{
					HTTP: config.HTTPConfig{
						Ratelimit: &config.RatelimitConfig{
							Rate: &rate,
							Methods: []config.MethodRatelimitConfig{
								{
									Method: "GET",
									Rate:   50,
								},
								{
									Method: "POST",
									Rate:   25,
								},
							},
						},
					},
				}
				ratelimitConfig := cfg.CopyRatelimit()
				So(ratelimitConfig, ShouldNotBeNil)
				So(*ratelimitConfig.Rate, ShouldEqual, 100)
				So(len(ratelimitConfig.Methods), ShouldEqual, 2)
				So(ratelimitConfig.Methods[0].Method, ShouldEqual, "GET")
				So(ratelimitConfig.Methods[0].Rate, ShouldEqual, 50)
				So(ratelimitConfig.Methods[1].Method, ShouldEqual, "POST")
				So(ratelimitConfig.Methods[1].Rate, ShouldEqual, 25)

				// Test deep copy isolation
				*ratelimitConfig.Rate = 200
				ratelimitConfig.Methods[0].Rate = 75
				ratelimitConfig.Methods[0].Method = "PUT"

				So(*cfg.HTTP.Ratelimit.Rate, ShouldEqual, 100)
				So(cfg.HTTP.Ratelimit.Methods[0].Rate, ShouldEqual, 50)
				So(cfg.HTTP.Ratelimit.Methods[0].Method, ShouldEqual, "GET")
			})

			Convey("Test with nil ratelimit config", func() {
				cfg := &config.Config{
					HTTP: config.HTTPConfig{
						Ratelimit: nil,
					},
				}
				ratelimitConfig := cfg.CopyRatelimit()
				So(ratelimitConfig, ShouldBeNil)
			})

			Convey("Test with nil Config", func() {
				var cfg *config.Config = nil
				ratelimitConfig := cfg.CopyRatelimit()
				So(ratelimitConfig, ShouldBeNil)
			})
		})
	})

	Convey("Test Config utility methods", t, func() {
		Convey("Test IsMTLSAuthEnabled()", func() {
			// Test with nil Config
			var cfg *config.Config = nil

			So(cfg.IsMTLSAuthEnabled(), ShouldBeFalse)

			// Test with Config but no TLS
			cfg = &config.Config{}
			So(cfg.IsMTLSAuthEnabled(), ShouldBeFalse)

			// Test with Config and TLS but no client cert
			cfg = &config.Config{
				HTTP: config.HTTPConfig{
					TLS: &config.TLSConfig{
						Cert: "/path/to/cert.pem",
						Key:  "/path/to/key.pem",
					},
				},
			}
			So(cfg.IsMTLSAuthEnabled(), ShouldBeFalse)

			// Test with Config and TLS with CA cert (mTLS)
			cfg = &config.Config{
				HTTP: config.HTTPConfig{
					TLS: &config.TLSConfig{
						Cert:   "/path/to/cert.pem",
						Key:    "/path/to/key.pem",
						CACert: "/path/to/ca-cert.pem",
					},
				},
			}
			So(cfg.IsMTLSAuthEnabled(), ShouldBeTrue)
		})

		Convey("Test UseSecureSession()", func() {
			// Test with nil Config
			var cfg *config.Config = nil

			So(cfg.UseSecureSession(), ShouldBeFalse)

			// Test with Config but no TLS and no Auth
			cfg = &config.Config{
				HTTP: config.HTTPConfig{
					TLS:  nil,
					Auth: nil,
				},
			}
			So(cfg.UseSecureSession(), ShouldBeFalse)

			// Test with TLS configured (should return true)
			cfg = &config.Config{
				HTTP: config.HTTPConfig{
					TLS: &config.TLSConfig{
						Cert: "/path/to/cert.pem",
						Key:  "/path/to/key.pem",
					},
				},
			}
			So(cfg.UseSecureSession(), ShouldBeTrue)

			// Test with no TLS but SecureSession explicitly set to true
			secureTrue := true
			cfg = &config.Config{
				HTTP: config.HTTPConfig{
					TLS: nil,
					Auth: &config.AuthConfig{
						SecureSession: &secureTrue,
					},
				},
			}
			So(cfg.UseSecureSession(), ShouldBeTrue)

			// Test with no TLS but SecureSession explicitly set to false
			secureFalse := false
			cfg = &config.Config{
				HTTP: config.HTTPConfig{
					TLS: nil,
					Auth: &config.AuthConfig{
						SecureSession: &secureFalse,
					},
				},
			}
			So(cfg.UseSecureSession(), ShouldBeFalse)

			// Test with no TLS and Auth but SecureSession not set
			cfg = &config.Config{
				HTTP: config.HTTPConfig{
					TLS: nil,
					Auth: &config.AuthConfig{
						APIKey: true,
					},
				},
			}
			So(cfg.UseSecureSession(), ShouldBeFalse)

			// Test with TLS configured and SecureSession set (TLS should take precedence)
			secureTrue = true
			cfg = &config.Config{
				HTTP: config.HTTPConfig{
					TLS: &config.TLSConfig{
						Cert: "/path/to/cert.pem",
						Key:  "/path/to/key.pem",
					},
					Auth: &config.AuthConfig{
						SecureSession: &secureTrue,
					},
				},
			}
			So(cfg.UseSecureSession(), ShouldBeTrue) // TLS takes precedence
		})

		Convey("Test IsCompatEnabled()", func() {
			// Test with nil Config
			var cfg *config.Config = nil

			So(cfg.IsCompatEnabled(), ShouldBeFalse)

			// Test with Config but no Compat
			cfg = &config.Config{}
			So(cfg.IsCompatEnabled(), ShouldBeFalse)

			// Test with Config and Compat enabled
			cfg = &config.Config{
				HTTP: config.HTTPConfig{
					Compat: []compat.MediaCompatibility{compat.DockerManifestV2SchemaV2},
				},
			}
			So(cfg.IsCompatEnabled(), ShouldBeTrue)
		})

		Convey("Test IsOpenIDSupported()", func() {
			// Test with unsupported provider
			So(config.IsOpenIDSupported("unsupported"), ShouldBeFalse)

			// Test with supported provider
			So(config.IsOpenIDSupported("google"), ShouldBeTrue)
		})

		Convey("Test IsOauth2Supported()", func() {
			// Test with unsupported provider
			So(config.IsOauth2Supported("unsupported"), ShouldBeFalse)

			// Test with supported provider
			So(config.IsOauth2Supported("github"), ShouldBeTrue)
		})

		Convey("Test IsClustered() with nil ClusterConfig", func() {
			var clusterConfig *config.ClusterConfig = nil

			So(clusterConfig.IsClustered(), ShouldBeFalse)
		})

		Convey("Test IsClustered() with empty members", func() {
			clusterConfig := &config.ClusterConfig{
				Members: []string{},
			}
			So(clusterConfig.IsClustered(), ShouldBeFalse)
		})

		Convey("Test IsClustered() with single member", func() {
			clusterConfig := &config.ClusterConfig{
				Members: []string{"node1:8080"},
			}
			So(clusterConfig.IsClustered(), ShouldBeFalse)
		})

		Convey("Test IsClustered() with multiple members", func() {
			clusterConfig := &config.ClusterConfig{
				Members: []string{"node1:8080", "node2:8080"},
			}
			So(clusterConfig.IsClustered(), ShouldBeTrue)
		})
	})

	Convey("Test CopyExtensionsConfig methods", t, func() {
		Convey("Test IsSearchEnabled()", func() {
			// Test with nil Config
			var cfg *config.Config = nil

			So(cfg.CopyExtensionsConfig().IsSearchEnabled(), ShouldBeFalse)

			// Test with Config but nil Extensions
			cfg = &config.Config{}
			So(cfg.CopyExtensionsConfig().IsSearchEnabled(), ShouldBeFalse)

			// Test with Config and Extensions but nil Search
			cfg = &config.Config{
				Extensions: &extconf.ExtensionConfig{},
			}
			So(cfg.CopyExtensionsConfig().IsSearchEnabled(), ShouldBeFalse)

			// Test with Config and Extensions and Search but disabled
			disabled := false
			cfg = &config.Config{
				Extensions: &extconf.ExtensionConfig{
					Search: &extconf.SearchConfig{
						BaseConfig: extconf.BaseConfig{
							Enable: &disabled,
						},
					},
				},
			}
			So(cfg.CopyExtensionsConfig().IsSearchEnabled(), ShouldBeFalse)

			// Test with Config and Extensions and Search enabled
			enabled := true
			cfg = &config.Config{
				Extensions: &extconf.ExtensionConfig{
					Search: &extconf.SearchConfig{
						BaseConfig: extconf.BaseConfig{
							Enable: &enabled,
						},
					},
				},
			}
			So(cfg.CopyExtensionsConfig().IsSearchEnabled(), ShouldBeTrue)
		})
	})

	Convey("Test UpdateReloadableConfig()", t, func() {
		Convey("Test with nil Config", func() {
			var cfg *config.Config = nil
			newConfig := &config.Config{}

			So(func() { cfg.UpdateReloadableConfig(newConfig) }, ShouldNotPanic)
		})

		Convey("Test with nil newConfig.HTTP.Auth", func() {
			// Create initial config with Auth
			cfg := &config.Config{
				HTTP: config.HTTPConfig{
					Auth: &config.AuthConfig{
						FailDelay: 5,
						HTPasswd: config.AuthHTPasswd{
							Path: "/etc/htpasswd",
						},
						APIKey: false,
					},
				},
			}

			// Create new config with nil Auth
			newConfig := &config.Config{
				HTTP: config.HTTPConfig{
					Auth: nil, // This should not cause a panic
				},
			}

			// This should not panic even though newConfig.HTTP.Auth is nil
			So(func() { cfg.UpdateReloadableConfig(newConfig) }, ShouldNotPanic)

			// Verify that the original Auth config remains unchanged
			So(cfg.HTTP.Auth, ShouldNotBeNil)
			So(cfg.HTTP.Auth.FailDelay, ShouldEqual, 5)
			So(cfg.HTTP.Auth.HTPasswd.Path, ShouldEqual, "/etc/htpasswd")
			So(cfg.HTTP.Auth.APIKey, ShouldBeFalse)
		})

		Convey("Test with AccessControl update", func() {
			cfgAccessControl := &config.AccessControlConfig{}
			cfgAccessControl.AdminPolicy = config.Policy{
				Actions: []string{"read"},
			}
			cfg := &config.Config{
				HTTP: config.HTTPConfig{
					AccessControl: cfgAccessControl,
				},
			}
			newConfigAccessControl := &config.AccessControlConfig{}
			newConfigAccessControl.AdminPolicy = config.Policy{
				Actions: []string{"read", "write"},
			}
			newConfig := &config.Config{
				HTTP: config.HTTPConfig{
					AccessControl: newConfigAccessControl,
				},
			}
			cfg.UpdateReloadableConfig(newConfig)
			So(cfg.CopyAccessControlConfig().GetAdminPolicy().Actions, ShouldResemble, []string{"read", "write"})
		})

		Convey("Test with Extensions update", func() {
			// First set up a config with search enabled
			enabled := true
			cfg := &config.Config{
				Extensions: &extconf.ExtensionConfig{
					Search: &extconf.SearchConfig{
						BaseConfig: extconf.BaseConfig{
							Enable: &enabled,
						},
					},
				},
			}

			// Create new config with CVE config
			newConfig := &config.Config{
				Extensions: &extconf.ExtensionConfig{
					Search: &extconf.SearchConfig{
						BaseConfig: extconf.BaseConfig{
							Enable: &enabled,
						},
						CVE: &extconf.CVEConfig{
							UpdateInterval: time.Hour * 2,
						},
					},
				},
			}
			cfg.UpdateReloadableConfig(newConfig)
			// The search should still be enabled and CVE config should be updated
			So(cfg.CopyExtensionsConfig().IsSearchEnabled(), ShouldBeTrue)
		})

		Convey("Test search CVE config removal when new config has nil Search.CVE", func() {
			// First set up a config with search enabled and CVE config
			enabled := true
			cfg := &config.Config{
				Extensions: &extconf.ExtensionConfig{
					Search: &extconf.SearchConfig{
						BaseConfig: extconf.BaseConfig{
							Enable: &enabled,
						},
						CVE: &extconf.CVEConfig{
							UpdateInterval: time.Hour,
						},
					},
				},
			}
			So(cfg.CopyExtensionsConfig().IsSearchEnabled(), ShouldBeTrue)
			So(cfg.Extensions.Search.CVE, ShouldNotBeNil)

			// Create new config with Search but nil CVE
			newConfig := &config.Config{
				Extensions: &extconf.ExtensionConfig{
					Search: &extconf.SearchConfig{
						BaseConfig: extconf.BaseConfig{
							Enable: &enabled,
						},
						CVE: nil, // This should trigger the removal
					},
				},
			}
			cfg.UpdateReloadableConfig(newConfig)

			// Verify that the CVE config was removed
			So(cfg.Extensions.Search.CVE, ShouldBeNil)
			So(cfg.Extensions.Search.Enable, ShouldNotBeNil)
			So(*cfg.Extensions.Search.Enable, ShouldBeTrue)
		})

		Convey("Test search CVE config removal when new config has nil Search", func() {
			// First set up a config with search enabled and CVE config
			enabled := true
			cfg := &config.Config{
				Extensions: &extconf.ExtensionConfig{
					Search: &extconf.SearchConfig{
						BaseConfig: extconf.BaseConfig{
							Enable: &enabled,
						},
						CVE: &extconf.CVEConfig{
							UpdateInterval: time.Hour,
						},
					},
				},
			}
			So(cfg.CopyExtensionsConfig().IsSearchEnabled(), ShouldBeTrue)
			So(cfg.Extensions.Search.CVE, ShouldNotBeNil)

			// Create new config with Extensions but nil Search
			newConfig := &config.Config{
				Extensions: &extconf.ExtensionConfig{
					Search: nil, // This should trigger the removal
				},
			}
			cfg.UpdateReloadableConfig(newConfig)

			// Verify that the CVE config was removed
			So(cfg.Extensions.Search.CVE, ShouldBeNil)
			So(cfg.Extensions.Search.Enable, ShouldNotBeNil)
			So(*cfg.Extensions.Search.Enable, ShouldBeTrue)
		})
	})

	Convey("Test nil receiver coverage for all methods", t, func() {
		Convey("Test AuthConfig methods with nil receiver", func() {
			var authConfig *config.AuthConfig = nil

			So(authConfig.IsLdapAuthEnabled(), ShouldBeFalse)
			So(authConfig.IsHtpasswdAuthEnabled(), ShouldBeFalse)
			So(authConfig.IsBearerAuthEnabled(), ShouldBeFalse)
			So(authConfig.IsTraditionalBearerAuthEnabled(), ShouldBeFalse)
			So(authConfig.IsOIDCBearerAuthEnabled(), ShouldBeFalse)
			So(authConfig.IsOpenIDAuthEnabled(), ShouldBeFalse)
			So(authConfig.IsAPIKeyEnabled(), ShouldBeFalse)
			So(authConfig.IsBasicAuthnEnabled(), ShouldBeFalse)
			So(authConfig.GetFailDelay(), ShouldEqual, 0)
		})

		Convey("Test LDAPConfig methods with nil receiver", func() {
			var ldapConfig *config.LDAPConfig = nil

			So(ldapConfig.BindDN(), ShouldEqual, "")
			So(ldapConfig.BindPassword(), ShouldEqual, "")
			So(ldapConfig.SetBindDN("test"), ShouldBeNil)
			So(ldapConfig.SetBindPassword("test"), ShouldBeNil)
		})

		Convey("Test AccessControlConfig methods with nil receiver", func() {
			var accessControlConfig *config.AccessControlConfig = nil

			So(accessControlConfig.IsAuthzEnabled(), ShouldBeFalse)
			So(accessControlConfig.AnonymousPolicyExists(), ShouldBeFalse)
			So(accessControlConfig.ContainsOnlyAnonymousPolicy(), ShouldBeTrue)

			// Test getter methods
			So(accessControlConfig.GetRepositories(), ShouldBeNil)
			So(accessControlConfig.GetAdminPolicy(), ShouldResemble, config.Policy{})
			So(accessControlConfig.GetMetrics(), ShouldResemble, config.Metrics{})
			So(accessControlConfig.GetGroups(), ShouldBeNil)
		})

		Convey("Test Config methods with nil receiver", func() {
			var cfg *config.Config = nil

			// Test getter methods
			So(cfg.CopyAuthConfig(), ShouldBeNil)
			So(cfg.CopyAccessControlConfig(), ShouldBeNil)
			So(cfg.GetHTTPAddress(), ShouldEqual, "")
			So(cfg.GetHTTPPort(), ShouldEqual, "")
			So(cfg.GetAllowOrigin(), ShouldEqual, "")
			So(cfg.CopyTLSConfig(), ShouldBeNil)
			So(cfg.CopyRatelimit(), ShouldBeNil)
			So(cfg.GetCompat(), ShouldBeNil)
			So(cfg.CopyStorageConfig(), ShouldResemble, config.GlobalStorageConfig{})
			So(cfg.CopyExtensionsConfig(), ShouldBeNil)
			So(cfg.CopyLogConfig(), ShouldBeNil)
			So(cfg.CopyClusterConfig(), ShouldBeNil)
			So(cfg.CopySchedulerConfig(), ShouldBeNil)

			// Test GetVersionInfo
			commit, binaryType, goVersion, distSpecVersion := cfg.GetVersionInfo()
			So(commit, ShouldEqual, "")
			So(binaryType, ShouldEqual, "")
			So(goVersion, ShouldEqual, "")
			So(distSpecVersion, ShouldEqual, "")

			// Test boolean methods
			So(cfg.IsMTLSAuthEnabled(), ShouldBeFalse)
			So(cfg.IsRetentionEnabled(), ShouldBeFalse)
			So(cfg.IsCompatEnabled(), ShouldBeFalse)

			// Test Sanitize
			So(cfg.Sanitize(), ShouldBeNil)

			// Test UpdateReloadableConfig (should not panic)
			newConfig := &config.Config{}

			So(func() { cfg.UpdateReloadableConfig(newConfig) }, ShouldNotPanic)
		})
	})

	Convey("Test AccessControlConfig copy isolation through CopyAccessControlConfig()", t, func() {
		Convey("Test that mutations to retrieved AccessControlConfig copy do not affect original config", func() {
			// Create a config with initial AccessControlConfig
			cfg := &config.Config{
				HTTP: config.HTTPConfig{
					AccessControl: &config.AccessControlConfig{
						AdminPolicy: config.Policy{
							Actions: []string{"read"},
							Users:   []string{"admin"},
						},
						Repositories: config.Repositories{
							"repo1": config.PolicyGroup{
								DefaultPolicy: []string{"read"},
								Policies: []config.Policy{
									{
										Actions: []string{"read"},
									},
								},
							},
						},
					},
				},
			}

			// Retrieve the AccessControlConfig (should be a copy)
			accessControlConfig := cfg.CopyAccessControlConfig()
			So(accessControlConfig, ShouldNotBeNil)

			// Mutate the retrieved AccessControlConfig copy
			accessControlConfig.AdminPolicy = config.Policy{
				Actions: []string{"read", "write", "delete"},
				Users:   []string{"admin", "superadmin"},
			}

			// Add a new repository to the copy
			newRepositories := config.Repositories{
				"repo1": config.PolicyGroup{
					DefaultPolicy: []string{"read"},
					Policies: []config.Policy{
						{
							Actions: []string{"read"},
						},
					},
				},
				"repo2": config.PolicyGroup{
					DefaultPolicy: []string{"read", "write"},
					Policies: []config.Policy{
						{
							Actions: []string{"read", "write"},
							Users:   []string{"user1"},
						},
					},
				},
			}
			accessControlConfig.Repositories = newRepositories

			// Verify that the original config is unchanged
			originalAccessControlConfig := cfg.CopyAccessControlConfig()
			So(originalAccessControlConfig, ShouldNotBeNil)

			// Check that admin policy remains unchanged in original
			adminPolicy := originalAccessControlConfig.GetAdminPolicy()
			So(adminPolicy.Actions, ShouldResemble, []string{"read"})
			So(adminPolicy.Users, ShouldResemble, []string{"admin"})

			// Check that repositories remain unchanged in original
			repositories := originalAccessControlConfig.GetRepositories()
			So(len(repositories), ShouldEqual, 1)
			So(repositories["repo1"], ShouldNotBeNil)
			So(repositories["repo1"].DefaultPolicy, ShouldResemble, []string{"read"})
		})

		Convey("Test that mutations to retrieved AccessControlConfig copy work with nil initial config", func() {
			// Create a config with nil AccessControlConfig
			cfg := &config.Config{
				HTTP: config.HTTPConfig{
					AccessControl: nil,
				},
			}

			// Retrieve the AccessControlConfig (should return nil)
			accessControlConfig := cfg.CopyAccessControlConfig()
			So(accessControlConfig, ShouldBeNil)

			// Create a new AccessControlConfig and set it
			newAccessControlConfig := &config.AccessControlConfig{}
			newAccessControlConfig.AdminPolicy = config.Policy{
				Actions: []string{"read"},
				Users:   []string{"admin"},
			}

			// Manually set the AccessControlConfig on the original config
			cfg.HTTP.AccessControl = newAccessControlConfig

			// Now retrieve it again and verify it works
			retrievedConfig := cfg.CopyAccessControlConfig()
			So(retrievedConfig, ShouldNotBeNil)

			// Mutate the retrieved config copy
			retrievedConfig.AdminPolicy = config.Policy{
				Actions: []string{"read", "write"},
				Users:   []string{"admin", "user"},
			}

			// Verify the original config is unchanged
			finalConfig := cfg.CopyAccessControlConfig()
			adminPolicy := finalConfig.GetAdminPolicy()
			So(adminPolicy.Actions, ShouldResemble, []string{"read"})
			So(adminPolicy.Users, ShouldResemble, []string{"admin"})
		})
	})

	Convey("Test AccessControlConfig copy isolation through UpdateReloadableConfig()", t, func() {
		Convey("Test that AccessControlConfig copies are isolated from UpdateReloadableConfig changes", func() {
			// Create initial config with AccessControlConfig
			cfg := &config.Config{
				HTTP: config.HTTPConfig{
					AccessControl: &config.AccessControlConfig{
						AdminPolicy: config.Policy{
							Actions: []string{"read"},
							Users:   []string{"admin"},
						},
						Repositories: config.Repositories{
							"repo1": config.PolicyGroup{
								DefaultPolicy: []string{"read"},
								Policies: []config.Policy{
									{
										Actions: []string{"read"},
									},
								},
							},
						},
					},
				},
			}

			// Get initial reference to AccessControlConfig
			initialAccessControlConfig := cfg.CopyAccessControlConfig()
			So(initialAccessControlConfig, ShouldNotBeNil)

			// Verify initial state
			initialAdminPolicy := initialAccessControlConfig.GetAdminPolicy()
			So(initialAdminPolicy.Actions, ShouldResemble, []string{"read"})
			So(initialAdminPolicy.Users, ShouldResemble, []string{"admin"})

			initialRepositories := initialAccessControlConfig.GetRepositories()
			So(len(initialRepositories), ShouldEqual, 1)
			So(initialRepositories["repo1"], ShouldNotBeNil)

			// Create new config with updated AccessControlConfig
			newConfig := &config.Config{
				HTTP: config.HTTPConfig{
					AccessControl: &config.AccessControlConfig{
						AdminPolicy: config.Policy{
							Actions: []string{"read", "write", "delete"},
							Users:   []string{"admin", "superadmin", "user"},
						},
						Repositories: config.Repositories{
							"repo1": config.PolicyGroup{
								DefaultPolicy: []string{"read", "write"},
								Policies: []config.Policy{
									{
										Actions: []string{"read", "write"},
									},
								},
							},
							"repo2": config.PolicyGroup{
								DefaultPolicy: []string{"read"},
								Policies: []config.Policy{
									{
										Actions: []string{"read"},
										Users:   []string{"user1", "user2"},
									},
								},
							},
						},
					},
				},
			}

			// Update the config using UpdateReloadableConfig
			cfg.UpdateReloadableConfig(newConfig)

			// Verify that the old copy remains unchanged (copy isolation)
			updatedAdminPolicy := initialAccessControlConfig.GetAdminPolicy()
			So(updatedAdminPolicy.Actions, ShouldResemble, []string{"read"})
			So(updatedAdminPolicy.Users, ShouldResemble, []string{"admin"})

			updatedRepositories := initialAccessControlConfig.GetRepositories()
			So(len(updatedRepositories), ShouldEqual, 1)
			So(updatedRepositories["repo1"], ShouldNotBeNil)
			So(updatedRepositories["repo1"].DefaultPolicy, ShouldResemble, []string{"read"})

			// Verify that a new copy gets the updated data
			newAccessControlConfig := cfg.CopyAccessControlConfig()
			So(newAccessControlConfig, ShouldNotBeNil)
			So(newAccessControlConfig, ShouldNotEqual, initialAccessControlConfig) // Different copy

			newAdminPolicy := newAccessControlConfig.GetAdminPolicy()
			So(newAdminPolicy.Actions, ShouldResemble, []string{"read", "write", "delete"})
			So(newAdminPolicy.Users, ShouldResemble, []string{"admin", "superadmin", "user"})
		})

		Convey("Test that old AccessControlConfig reference works with nil initial config", func() {
			// Create config with nil AccessControlConfig
			cfg := &config.Config{
				HTTP: config.HTTPConfig{
					AccessControl: nil,
				},
			}

			// Get initial reference (should be nil)
			initialAccessControlConfig := cfg.CopyAccessControlConfig()
			So(initialAccessControlConfig, ShouldBeNil)

			// Create new config with AccessControlConfig
			newConfig := &config.Config{
				HTTP: config.HTTPConfig{
					AccessControl: &config.AccessControlConfig{
						AdminPolicy: config.Policy{
							Actions: []string{"read", "write"},
							Users:   []string{"admin"},
						},
					},
				},
			}

			// Update the config using UpdateReloadableConfig
			cfg.UpdateReloadableConfig(newConfig)

			// Verify that a new reference now gets the data
			newAccessControlConfig := cfg.CopyAccessControlConfig()
			So(newAccessControlConfig, ShouldNotBeNil)

			adminPolicy := newAccessControlConfig.GetAdminPolicy()
			So(adminPolicy.Actions, ShouldResemble, []string{"read", "write"})
			So(adminPolicy.Users, ShouldResemble, []string{"admin"})
		})

		Convey("Test that old AccessControlConfig reference works when new config has nil AccessControlConfig", func() {
			// Create initial config with AccessControlConfig
			testAccessControlConfig := &config.AccessControlConfig{}
			testAccessControlConfig.AdminPolicy = config.Policy{
				Actions: []string{"read"},
				Users:   []string{"admin"},
			}
			cfg := &config.Config{
				HTTP: config.HTTPConfig{
					AccessControl: testAccessControlConfig,
				},
			}

			// Get initial reference
			initialAccessControlConfig := cfg.CopyAccessControlConfig()
			So(initialAccessControlConfig, ShouldNotBeNil)

			// Create new config with nil AccessControlConfig
			newConfig := &config.Config{
				HTTP: config.HTTPConfig{
					AccessControl: nil,
				},
			}

			// Update the config using UpdateReloadableConfig
			cfg.UpdateReloadableConfig(newConfig)

			// Verify that a new reference now returns nil
			newAccessControlConfig := cfg.CopyAccessControlConfig()
			So(newAccessControlConfig, ShouldBeNil)
		})
	})

	Convey("Test ExtensionConfig copy isolation through CopyExtensionsConfig()", t, func() {
		Convey("Test that mutations to retrieved ExtensionConfig copy do not affect original config", func() {
			// Create a config with initial ExtensionConfig
			enabled := true
			cfg := &config.Config{
				Extensions: &extconf.ExtensionConfig{
					Search: &extconf.SearchConfig{
						BaseConfig: extconf.BaseConfig{
							Enable: &enabled,
						},
						CVE: &extconf.CVEConfig{
							UpdateInterval: time.Hour,
							Trivy: &extconf.TrivyConfig{
								DBRepository: "original/trivy-db",
							},
						},
					},
					Sync: &syncconf.Config{
						Enable: &enabled,
						Registries: []syncconf.RegistryConfig{
							{
								URLs: []string{"http://original:5000"},
							},
						},
					},
					Metrics: &extconf.MetricsConfig{
						BaseConfig: extconf.BaseConfig{
							Enable: &enabled,
						},
						Prometheus: &extconf.PrometheusConfig{
							Path: "/metrics",
						},
					},
					Scrub: &extconf.ScrubConfig{
						BaseConfig: extconf.BaseConfig{
							Enable: &enabled,
						},
						Interval: 24 * time.Hour,
					},
					UI: &extconf.UIConfig{
						BaseConfig: extconf.BaseConfig{
							Enable: &enabled,
						},
					},
				},
			}

			// Retrieve the ExtensionConfig
			extensionConfig := cfg.CopyExtensionsConfig()
			So(extensionConfig, ShouldNotBeNil)

			// Mutate the retrieved ExtensionConfig copy
			disabled := false
			extensionConfig.Search.Enable = &disabled
			extensionConfig.Search.CVE.UpdateInterval = 2 * time.Hour
			extensionConfig.Search.CVE.Trivy.DBRepository = "modified/trivy-db"
			extensionConfig.Sync.Registries[0].URLs[0] = "http://modified:5000"
			extensionConfig.Metrics.Prometheus.Path = "/custom/metrics"
			extensionConfig.Scrub.Interval = 48 * time.Hour
			extensionConfig.UI.Enable = &disabled

			// Verify that the original config is unchanged
			So(*cfg.Extensions.Search.Enable, ShouldBeTrue)
			So(cfg.Extensions.Search.CVE.UpdateInterval, ShouldEqual, time.Hour)
			So(cfg.Extensions.Search.CVE.Trivy.DBRepository, ShouldEqual, "original/trivy-db")
			So(cfg.Extensions.Sync.Registries[0].URLs[0], ShouldEqual, "http://original:5000")
			So(cfg.Extensions.Metrics.Prometheus.Path, ShouldEqual, "/metrics")
			So(cfg.Extensions.Scrub.Interval, ShouldEqual, 24*time.Hour)
			So(*cfg.Extensions.UI.Enable, ShouldBeTrue)

			// Verify that the retrieved config has the mutations
			So(*extensionConfig.Search.Enable, ShouldBeFalse)
			So(extensionConfig.Search.CVE.UpdateInterval, ShouldEqual, 2*time.Hour)
			So(extensionConfig.Search.CVE.Trivy.DBRepository, ShouldEqual, "modified/trivy-db")
			So(extensionConfig.Sync.Registries[0].URLs[0], ShouldEqual, "http://modified:5000")
			So(extensionConfig.Metrics.Prometheus.Path, ShouldEqual, "/custom/metrics")
			So(extensionConfig.Scrub.Interval, ShouldEqual, 48*time.Hour)
			So(*extensionConfig.UI.Enable, ShouldBeFalse)
		})

		Convey("Test that mutations to retrieved ExtensionConfig work with nil initial config", func() {
			// Create a config with nil ExtensionConfig
			cfg := &config.Config{
				Extensions: nil,
			}

			// Retrieve the ExtensionConfig (should return nil)
			extensionConfig := cfg.CopyExtensionsConfig()
			So(extensionConfig, ShouldBeNil)

			// Create a new ExtensionConfig and set it
			enabled := true
			newExtensionConfig := &extconf.ExtensionConfig{
				Search: &extconf.SearchConfig{
					BaseConfig: extconf.BaseConfig{
						Enable: &enabled,
					},
				},
				Metrics: &extconf.MetricsConfig{
					BaseConfig: extconf.BaseConfig{
						Enable: &enabled,
					},
					Prometheus: &extconf.PrometheusConfig{
						Path: "/metrics",
					},
				},
			}

			// Manually set the ExtensionConfig on the original config
			cfg.Extensions = newExtensionConfig

			// Now retrieve it again and verify it works
			retrievedConfig := cfg.CopyExtensionsConfig()
			So(retrievedConfig, ShouldNotBeNil)

			// Mutate the retrieved config
			retrievedConfig.Metrics.Prometheus.Path = "/new/metrics"

			// Verify the changes are NOT reflected in original config
			finalConfig := cfg.CopyExtensionsConfig()
			So(finalConfig.Metrics.Prometheus.Path, ShouldEqual, "/metrics")
		})
	})

	Convey("Test ExtensionConfig copy isolation through UpdateReloadableConfig()", t, func() {
		Convey("Test that ExtensionConfig copies are isolated from UpdateReloadableConfig changes", func() {
			// Create initial config with ExtensionConfig
			enabled := true
			cfg := &config.Config{
				Extensions: &extconf.ExtensionConfig{
					Search: &extconf.SearchConfig{
						BaseConfig: extconf.BaseConfig{
							Enable: &enabled,
						},
					},
					Metrics: &extconf.MetricsConfig{
						BaseConfig: extconf.BaseConfig{
							Enable: &enabled,
						},
						Prometheus: &extconf.PrometheusConfig{
							Path: "/metrics",
						},
					},
				},
			}

			// Get initial reference to ExtensionConfig
			initialExtensionConfig := cfg.CopyExtensionsConfig()
			So(initialExtensionConfig, ShouldNotBeNil)

			// Verify initial state
			So(initialExtensionConfig.Metrics.Prometheus.Path, ShouldEqual, "/metrics")
			So(initialExtensionConfig.Sync, ShouldBeNil)
			So(initialExtensionConfig.Search.CVE, ShouldBeNil)
			So(initialExtensionConfig.Scrub, ShouldBeNil)

			// Create new config with updated ExtensionConfig
			newConfig := &config.Config{
				Extensions: &extconf.ExtensionConfig{
					Search: &extconf.SearchConfig{
						BaseConfig: extconf.BaseConfig{
							Enable: &enabled,
						},
						CVE: &extconf.CVEConfig{
							UpdateInterval: time.Hour * 2,
							Trivy: &extconf.TrivyConfig{
								DBRepository: "updated/trivy-db",
							},
						},
					},
					Metrics: &extconf.MetricsConfig{
						BaseConfig: extconf.BaseConfig{
							Enable: &enabled,
						},
						Prometheus: &extconf.PrometheusConfig{
							Path: "/custom/metrics",
						},
					},
					Sync: &syncconf.Config{
						Enable: &enabled,
						Registries: []syncconf.RegistryConfig{
							{
								URLs: []string{"http://registry1:5000", "http://registry2:5000"},
							},
						},
					},
					Scrub: &extconf.ScrubConfig{
						BaseConfig: extconf.BaseConfig{
							Enable: &enabled,
						},
						Interval: time.Hour * 12,
					},
				},
			}

			// Update the config using UpdateReloadableConfig
			cfg.UpdateReloadableConfig(newConfig)

			// Verify that the old reference remains unchanged (copy isolation)
			So(initialExtensionConfig.Metrics.Prometheus.Path, ShouldEqual, "/metrics")
			So(initialExtensionConfig.Sync, ShouldBeNil)
			So(initialExtensionConfig.Search.CVE, ShouldBeNil)
			So(initialExtensionConfig.Scrub, ShouldBeNil)

			// Verify that a new reference gets the updated data
			newExtensionConfig := cfg.CopyExtensionsConfig()
			So(newExtensionConfig, ShouldNotBeNil)
			So(newExtensionConfig, ShouldNotEqual, initialExtensionConfig) // Different references

			So(newExtensionConfig.Metrics.Prometheus.Path, ShouldEqual, "/metrics")
			So(newExtensionConfig.Sync, ShouldNotBeNil)
			So(newExtensionConfig.Search.CVE, ShouldNotBeNil)
			So(newExtensionConfig.Scrub, ShouldNotBeNil)
		})

		Convey("Test that old ExtensionConfig reference works with nil initial config", func() {
			// Create config with nil ExtensionConfig
			cfg := &config.Config{
				Extensions: nil,
			}

			// Get initial reference (should be nil)
			initialExtensionConfig := cfg.CopyExtensionsConfig()
			So(initialExtensionConfig, ShouldBeNil)

			// Create new config with ExtensionConfig
			enabled := true
			newConfig := &config.Config{
				Extensions: &extconf.ExtensionConfig{
					Search: &extconf.SearchConfig{
						BaseConfig: extconf.BaseConfig{
							Enable: &enabled,
						},
					},
					Metrics: &extconf.MetricsConfig{
						BaseConfig: extconf.BaseConfig{
							Enable: &enabled,
						},
						Prometheus: &extconf.PrometheusConfig{
							Path: "/new/metrics",
						},
					},
				},
			}

			// Update the config using UpdateReloadableConfig
			cfg.UpdateReloadableConfig(newConfig)

			// Verify that a new reference now gets the data
			newExtensionConfig := cfg.CopyExtensionsConfig()
			So(newExtensionConfig, ShouldNotBeNil)

			// Note: UpdateReloadableConfig creates an empty ExtensionConfig when going from nil to non-nil,
			// but doesn't copy the fields from newConfig.Extensions. It only updates specific parts.
			// So the Search and Metrics fields will be nil in the new ExtensionConfig.
			So(newExtensionConfig.Search, ShouldBeNil)
			So(newExtensionConfig.Metrics, ShouldBeNil)
		})

		Convey("Test that old ExtensionConfig reference works when new config has nil ExtensionConfig", func() {
			// Create initial config with ExtensionConfig
			enabled := true
			cfg := &config.Config{
				Extensions: &extconf.ExtensionConfig{
					Search: &extconf.SearchConfig{
						BaseConfig: extconf.BaseConfig{
							Enable: &enabled,
						},
					},
				},
			}

			// Get initial reference
			initialExtensionConfig := cfg.CopyExtensionsConfig()
			So(initialExtensionConfig, ShouldNotBeNil)

			// Create new config with nil ExtensionConfig
			newConfig := &config.Config{
				Extensions: nil,
			}

			// Update the config using UpdateReloadableConfig
			cfg.UpdateReloadableConfig(newConfig)

			// Verify that the old reference remains unchanged (copy isolation)
			So(initialExtensionConfig, ShouldNotBeNil)
			So(initialExtensionConfig.Search, ShouldNotBeNil)

			// Verify that a new reference now returns nil
			newExtensionConfig := cfg.CopyExtensionsConfig()
			So(newExtensionConfig, ShouldBeNil)
		})
	})

	Convey("Test UpdateReloadableConfig LDAP config updates", t, func() {
		Convey("Test LDAP config is updated in UpdateReloadableConfig", func() {
			// Create initial config with LDAP
			cfg := &config.Config{
				HTTP: config.HTTPConfig{
					Auth: &config.AuthConfig{
						LDAP: &config.LDAPConfig{
							Address:  "ldap://old-server:389",
							Port:     389,
							Insecure: true,
						},
					},
				},
			}

			// Create new config with updated LDAP
			newConfig := &config.Config{
				HTTP: config.HTTPConfig{
					Auth: &config.AuthConfig{
						LDAP: &config.LDAPConfig{
							Address:  "ldap://new-server:636",
							Port:     636,
							Insecure: false,
							StartTLS: true,
						},
					},
				},
			}

			// Update the config
			cfg.UpdateReloadableConfig(newConfig)

			// Verify LDAP config was updated
			So(cfg.HTTP.Auth.LDAP, ShouldNotBeNil)
			So(cfg.HTTP.Auth.LDAP.Address, ShouldEqual, "ldap://new-server:636")
			So(cfg.HTTP.Auth.LDAP.Port, ShouldEqual, 636)
			So(cfg.HTTP.Auth.LDAP.Insecure, ShouldBeFalse)
			So(cfg.HTTP.Auth.LDAP.StartTLS, ShouldBeTrue)
		})

		Convey("Test LDAP config is set to nil when new config has nil LDAP", func() {
			// Create initial config with LDAP
			cfg := &config.Config{
				HTTP: config.HTTPConfig{
					Auth: &config.AuthConfig{
						LDAP: &config.LDAPConfig{
							Address: "ldap://old-server:389",
						},
					},
				},
			}

			// Create new config with nil LDAP
			newConfig := &config.Config{
				HTTP: config.HTTPConfig{
					Auth: &config.AuthConfig{
						LDAP: nil,
					},
				},
			}

			// Update the config
			cfg.UpdateReloadableConfig(newConfig)

			// Verify LDAP config was set to nil
			So(cfg.HTTP.Auth.LDAP, ShouldBeNil)
		})

		Convey("Test LDAP config is created when going from nil to non-nil", func() {
			// Create initial config with nil LDAP
			cfg := &config.Config{
				HTTP: config.HTTPConfig{
					Auth: &config.AuthConfig{
						LDAP: nil,
					},
				},
			}

			// Create new config with LDAP
			newConfig := &config.Config{
				HTTP: config.HTTPConfig{
					Auth: &config.AuthConfig{
						LDAP: &config.LDAPConfig{
							Address: "ldap://new-server:389",
							Port:    389,
						},
					},
				},
			}

			// Update the config
			cfg.UpdateReloadableConfig(newConfig)

			// Verify LDAP config was created
			So(cfg.HTTP.Auth.LDAP, ShouldNotBeNil)
			So(cfg.HTTP.Auth.LDAP.Address, ShouldEqual, "ldap://new-server:389")
			So(cfg.HTTP.Auth.LDAP.Port, ShouldEqual, 389)
		})
	})

	Convey("Test UpdateReloadableConfig MTLS config updates", t, func() {
		Convey("Test MTLS config is updated in UpdateReloadableConfig", func() {
			// Create initial config with MTLS
			cfg := &config.Config{
				HTTP: config.HTTPConfig{
					Auth: &config.AuthConfig{
						MTLS: &config.MTLSConfig{
							IdentityAttibutes: []string{"CommonName"},
							URISANPattern:     "spiffe://old.example.org/workload/(.*)",
							URISANIndex:       0,
						},
					},
				},
			}

			// Create new config with updated MTLS
			newConfig := &config.Config{
				HTTP: config.HTTPConfig{
					Auth: &config.AuthConfig{
						MTLS: &config.MTLSConfig{
							IdentityAttibutes: []string{"URI", "CommonName"},
							URISANPattern:     "spiffe://new.example.org/workload/(.*)",
							URISANIndex:       1,
							DNSANIndex:        2,
						},
					},
				},
			}

			// Update the config
			cfg.UpdateReloadableConfig(newConfig)

			// Verify MTLS config was updated
			So(cfg.HTTP.Auth.MTLS, ShouldNotBeNil)
			So(len(cfg.HTTP.Auth.MTLS.IdentityAttibutes), ShouldEqual, 2)
			So(cfg.HTTP.Auth.MTLS.IdentityAttibutes[0], ShouldEqual, "URI")
			So(cfg.HTTP.Auth.MTLS.IdentityAttibutes[1], ShouldEqual, "CommonName")
			So(cfg.HTTP.Auth.MTLS.URISANPattern, ShouldEqual, "spiffe://new.example.org/workload/(.*)")
			So(cfg.HTTP.Auth.MTLS.URISANIndex, ShouldEqual, 1)
			So(cfg.HTTP.Auth.MTLS.DNSANIndex, ShouldEqual, 2)
		})

		Convey("Test MTLS config is set to nil when new config has nil MTLS", func() {
			// Create initial config with MTLS
			cfg := &config.Config{
				HTTP: config.HTTPConfig{
					Auth: &config.AuthConfig{
						MTLS: &config.MTLSConfig{
							IdentityAttibutes: []string{"CommonName"},
						},
					},
				},
			}

			// Create new config with nil MTLS
			newConfig := &config.Config{
				HTTP: config.HTTPConfig{
					Auth: &config.AuthConfig{
						MTLS: nil,
					},
				},
			}

			// Update the config
			cfg.UpdateReloadableConfig(newConfig)

			// Verify MTLS config was set to nil
			So(cfg.HTTP.Auth.MTLS, ShouldBeNil)
		})

		Convey("Test MTLS config is created when going from nil to non-nil", func() {
			// Create initial config with nil MTLS
			cfg := &config.Config{
				HTTP: config.HTTPConfig{
					Auth: &config.AuthConfig{
						MTLS: nil,
					},
				},
			}

			// Create new config with MTLS
			newConfig := &config.Config{
				HTTP: config.HTTPConfig{
					Auth: &config.AuthConfig{
						MTLS: &config.MTLSConfig{
							IdentityAttibutes: []string{"URI"},
							URISANPattern:     "spiffe://new.example.org/workload/(.*)",
						},
					},
				},
			}

			// Update the config
			cfg.UpdateReloadableConfig(newConfig)

			// Verify MTLS config was created
			So(cfg.HTTP.Auth.MTLS, ShouldNotBeNil)
			So(len(cfg.HTTP.Auth.MTLS.IdentityAttibutes), ShouldEqual, 1)
			So(cfg.HTTP.Auth.MTLS.IdentityAttibutes[0], ShouldEqual, "URI")
			So(cfg.HTTP.Auth.MTLS.URISANPattern, ShouldEqual, "spiffe://new.example.org/workload/(.*)")
		})
	})

	Convey("Test UpdateReloadableConfig Storage.SubPaths logic", t, func() {
		Convey("Test existing SubPaths are updated", func() {
			// Create initial config with SubPaths
			cfg := &config.Config{
				Storage: config.GlobalStorageConfig{
					StorageConfig: config.StorageConfig{
						GC:     true,
						Dedupe: false,
					},
					SubPaths: map[string]config.StorageConfig{
						"/path1": {
							GC:         true,
							Dedupe:     false,
							GCDelay:    time.Hour,
							GCInterval: time.Hour * 24,
						},
						"/path2": {
							GC:         false,
							Dedupe:     true,
							GCDelay:    time.Hour * 2,
							GCInterval: time.Hour * 48,
						},
					},
				},
			}

			// Create new config with updated SubPaths
			newConfig := &config.Config{
				Storage: config.GlobalStorageConfig{
					StorageConfig: config.StorageConfig{
						GC:     true,
						Dedupe: false,
					},
					SubPaths: map[string]config.StorageConfig{
						"/path1": {
							GC:         false,          // Changed
							Dedupe:     true,           // Changed
							GCDelay:    time.Hour * 2,  // Changed
							GCInterval: time.Hour * 12, // Changed
						},
						"/path2": {
							GC:         true,           // Changed
							Dedupe:     false,          // Changed
							GCDelay:    time.Hour * 3,  // Changed
							GCInterval: time.Hour * 36, // Changed
						},
					},
				},
			}

			// Update the config
			cfg.UpdateReloadableConfig(newConfig)

			// Verify SubPaths were updated
			So(len(cfg.Storage.SubPaths), ShouldEqual, 2)

			// Check /path1
			path1Config := cfg.Storage.SubPaths["/path1"]
			So(path1Config.GC, ShouldBeFalse)
			So(path1Config.Dedupe, ShouldBeTrue)
			So(path1Config.GCDelay, ShouldEqual, time.Hour*2)
			So(path1Config.GCInterval, ShouldEqual, time.Hour*12)

			// Check /path2
			path2Config := cfg.Storage.SubPaths["/path2"]
			So(path2Config.GC, ShouldBeTrue)
			So(path2Config.Dedupe, ShouldBeFalse)
			So(path2Config.GCDelay, ShouldEqual, time.Hour*3)
			So(path2Config.GCInterval, ShouldEqual, time.Hour*36)
		})

		Convey("Test new SubPaths are not added (only existing ones are updated)", func() {
			// Create initial config with one SubPath
			cfg := &config.Config{
				Storage: config.GlobalStorageConfig{
					StorageConfig: config.StorageConfig{
						GC:     true,
						Dedupe: false,
					},
					SubPaths: map[string]config.StorageConfig{
						"/path1": {
							GC:     true,
							Dedupe: false,
						},
					},
				},
			}

			// Create new config with additional SubPath
			newConfig := &config.Config{
				Storage: config.GlobalStorageConfig{
					StorageConfig: config.StorageConfig{
						GC:     true,
						Dedupe: false,
					},
					SubPaths: map[string]config.StorageConfig{
						"/path1": {
							GC:     false, // Update existing
							Dedupe: true,  // Update existing
						},
						"/path2": { // New path - should not be added
							GC:     true,
							Dedupe: true,
						},
					},
				},
			}

			// Update the config
			cfg.UpdateReloadableConfig(newConfig)

			// Verify only existing SubPath was updated, new one was not added
			So(len(cfg.Storage.SubPaths), ShouldEqual, 1)
			_, exists := cfg.Storage.SubPaths["/path2"]
			So(exists, ShouldBeFalse) // New path not added

			// Verify existing path was updated
			path1Config := cfg.Storage.SubPaths["/path1"]
			So(path1Config.GC, ShouldBeFalse)
			So(path1Config.Dedupe, ShouldBeTrue)
		})

		Convey("Test SubPaths Retention is updated only when retention is enabled", func() {
			// Create initial config with retention enabled and SubPaths
			// Retention is enabled when there are policies with tag retention
			cfg := &config.Config{
				Storage: config.GlobalStorageConfig{
					StorageConfig: config.StorageConfig{
						GC:     true,
						Dedupe: false,
						Retention: config.ImageRetention{
							Policies: []config.RetentionPolicy{
								{
									Repositories: []string{"repo1"},
									KeepTags: []config.KeepTagsPolicy{
										{
											MostRecentlyPulledCount: 10, // This enables retention
										},
									},
								},
							},
						},
					},
					SubPaths: map[string]config.StorageConfig{
						"/path1": {
							GC:     true,
							Dedupe: false,
							Retention: config.ImageRetention{
								Policies: []config.RetentionPolicy{
									{
										Repositories: []string{"old-repo"},
									},
								},
							},
						},
					},
				},
			}

			// Create new config with updated SubPath retention
			newConfig := &config.Config{
				Storage: config.GlobalStorageConfig{
					StorageConfig: config.StorageConfig{
						GC:     true,
						Dedupe: false,
						Retention: config.ImageRetention{
							Policies: []config.RetentionPolicy{
								{
									Repositories: []string{"repo1"},
									KeepTags: []config.KeepTagsPolicy{
										{
											MostRecentlyPulledCount: 10, // This enables retention
										},
									},
								},
							},
						},
					},
					SubPaths: map[string]config.StorageConfig{
						"/path1": {
							GC:     false,
							Dedupe: true,
							Retention: config.ImageRetention{
								Policies: []config.RetentionPolicy{
									{
										Repositories: []string{"new-repo"},
									},
								},
							},
						},
					},
				},
			}

			// Update the config
			cfg.UpdateReloadableConfig(newConfig)

			// Verify SubPath was updated including Retention
			path1Config := cfg.Storage.SubPaths["/path1"]
			So(path1Config.GC, ShouldBeFalse)
			So(path1Config.Dedupe, ShouldBeTrue)
			So(len(path1Config.Retention.Policies), ShouldEqual, 1)
			So(path1Config.Retention.Policies[0].Repositories[0], ShouldEqual, "new-repo")
		})

		Convey("Test SubPaths Retention is not updated when retention is disabled", func() {
			// Create initial config with retention disabled and SubPaths
			cfg := &config.Config{
				Storage: config.GlobalStorageConfig{
					StorageConfig: config.StorageConfig{
						GC:     true,
						Dedupe: false,
						// No Retention config - retention disabled
					},
					SubPaths: map[string]config.StorageConfig{
						"/path1": {
							GC:     true,
							Dedupe: false,
							Retention: config.ImageRetention{
								Policies: []config.RetentionPolicy{
									{
										Repositories: []string{"old-repo"},
									},
								},
							},
						},
					},
				},
			}

			// Create new config with updated SubPath retention
			newConfig := &config.Config{
				Storage: config.GlobalStorageConfig{
					StorageConfig: config.StorageConfig{
						GC:     true,
						Dedupe: false,
						// No Retention config - retention disabled
					},
					SubPaths: map[string]config.StorageConfig{
						"/path1": {
							GC:     false,
							Dedupe: true,
							Retention: config.ImageRetention{
								Policies: []config.RetentionPolicy{
									{
										Repositories: []string{"new-repo"},
									},
								},
							},
						},
					},
				},
			}

			// Update the config
			cfg.UpdateReloadableConfig(newConfig)

			// Verify SubPath was updated but Retention was not
			path1Config := cfg.Storage.SubPaths["/path1"]
			So(path1Config.GC, ShouldBeFalse)
			So(path1Config.Dedupe, ShouldBeTrue)
			// Retention should remain unchanged (old value)
			So(len(path1Config.Retention.Policies), ShouldEqual, 1)
			So(path1Config.Retention.Policies[0].Repositories[0], ShouldEqual, "old-repo")
		})

		Convey("Test SubPaths with empty new config", func() {
			// Create initial config with SubPaths
			cfg := &config.Config{
				Storage: config.GlobalStorageConfig{
					StorageConfig: config.StorageConfig{
						GC:     true,
						Dedupe: false,
					},
					SubPaths: map[string]config.StorageConfig{
						"/path1": {
							GC:     true,
							Dedupe: false,
						},
						"/path2": {
							GC:     false,
							Dedupe: true,
						},
					},
				},
			}

			// Create new config with empty SubPaths
			newConfig := &config.Config{
				Storage: config.GlobalStorageConfig{
					StorageConfig: config.StorageConfig{
						GC:     true,
						Dedupe: false,
					},
					SubPaths: map[string]config.StorageConfig{},
				},
			}

			// Update the config
			cfg.UpdateReloadableConfig(newConfig)

			// Verify existing SubPaths remain unchanged (no updates applied)
			So(len(cfg.Storage.SubPaths), ShouldEqual, 2)
			path1Config := cfg.Storage.SubPaths["/path1"]
			So(path1Config.GC, ShouldBeTrue)      // Unchanged
			So(path1Config.Dedupe, ShouldBeFalse) // Unchanged
			path2Config := cfg.Storage.SubPaths["/path2"]
			So(path2Config.GC, ShouldBeFalse)    // Unchanged
			So(path2Config.Dedupe, ShouldBeTrue) // Unchanged
		})
	})
}
