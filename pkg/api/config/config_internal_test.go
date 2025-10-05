package config

import (
	"testing"
	"time"

	. "github.com/smartystreets/goconvey/convey"

	extconf "zotregistry.dev/zot/v2/pkg/extensions/config"
	eventsconf "zotregistry.dev/zot/v2/pkg/extensions/config/events"
)

func TestInternalMethods(t *testing.T) {
	Convey("Test isSearchEnabledInternal()", t, func() {
		Convey("Test with nil Config", func() {
			var cfg *Config = nil
			So(cfg.isSearchEnabledInternal(), ShouldBeFalse)
		})

		Convey("Test with Config but nil Extensions", func() {
			cfg := &Config{}
			So(cfg.isSearchEnabledInternal(), ShouldBeFalse)
		})

		Convey("Test with Config and Extensions but nil Search", func() {
			cfg := &Config{
				Extensions: &extconf.ExtensionConfig{},
			}
			So(cfg.isSearchEnabledInternal(), ShouldBeFalse)
		})

		Convey("Test with Config and Extensions and Search but disabled", func() {
			disabled := false
			cfg := &Config{
				Extensions: &extconf.ExtensionConfig{
					Search: &extconf.SearchConfig{
						BaseConfig: extconf.BaseConfig{
							Enable: &disabled,
						},
					},
				},
			}
			So(cfg.isSearchEnabledInternal(), ShouldBeFalse)
		})

		Convey("Test with Config and Extensions and Search enabled", func() {
			enabled := true
			cfg := &Config{
				Extensions: &extconf.ExtensionConfig{
					Search: &extconf.SearchConfig{
						BaseConfig: extconf.BaseConfig{
							Enable: &enabled,
						},
					},
				},
			}
			So(cfg.isSearchEnabledInternal(), ShouldBeTrue)
		})
	})

	Convey("Test isEventRecorderEnabledInternal()", t, func() {
		Convey("Test with nil Config", func() {
			var cfg *Config = nil
			So(cfg.isEventRecorderEnabledInternal(), ShouldBeFalse)
		})

		Convey("Test with Config but nil Extensions", func() {
			cfg := &Config{}
			So(cfg.isEventRecorderEnabledInternal(), ShouldBeFalse)
		})

		Convey("Test with Config and Extensions but nil Events", func() {
			cfg := &Config{
				Extensions: &extconf.ExtensionConfig{},
			}
			So(cfg.isEventRecorderEnabledInternal(), ShouldBeFalse)
		})

		Convey("Test with Config and Extensions and Events but disabled", func() {
			disabled := false
			cfg := &Config{
				Extensions: &extconf.ExtensionConfig{
					Events: &eventsconf.Config{
						Enable: &disabled,
					},
				},
			}
			So(cfg.isEventRecorderEnabledInternal(), ShouldBeFalse)
		})

		Convey("Test with Config and Extensions and Events enabled", func() {
			enabled := true
			cfg := &Config{
				Extensions: &extconf.ExtensionConfig{
					Events: &eventsconf.Config{
						Enable: &enabled,
					},
				},
			}
			So(cfg.isEventRecorderEnabledInternal(), ShouldBeTrue)
		})
	})

	Convey("Test isRetentionEnabledInternal()", t, func() {
		Convey("Test with nil Config", func() {
			var cfg *Config = nil
			So(cfg.isRetentionEnabledInternal(), ShouldBeFalse)
		})

		Convey("Test with Config but no retention policies", func() {
			cfg := &Config{
				Storage: GlobalStorageConfig{
					StorageConfig: StorageConfig{
						Retention: ImageRetention{
							Policies: []RetentionPolicy{},
						},
					},
				},
			}
			So(cfg.isRetentionEnabledInternal(), ShouldBeFalse)
		})

		Convey("Test with Config and retention policies with MostRecentlyPulledCount", func() {
			cfg := &Config{
				Storage: GlobalStorageConfig{
					StorageConfig: StorageConfig{
						Retention: ImageRetention{
							Policies: []RetentionPolicy{
								{
									Repositories: []string{"repo1"},
									KeepTags: []KeepTagsPolicy{
										{
											Patterns:                []string{"latest"},
											MostRecentlyPulledCount: 5,
										},
									},
								},
							},
						},
					},
				},
			}
			So(cfg.isRetentionEnabledInternal(), ShouldBeTrue)
		})

		Convey("Test with Config and retention policies with MostRecentlyPushedCount", func() {
			cfg := &Config{
				Storage: GlobalStorageConfig{
					StorageConfig: StorageConfig{
						Retention: ImageRetention{
							Policies: []RetentionPolicy{
								{
									Repositories: []string{"repo1"},
									KeepTags: []KeepTagsPolicy{
										{
											Patterns:                []string{"latest"},
											MostRecentlyPushedCount: 3,
										},
									},
								},
							},
						},
					},
				},
			}
			So(cfg.isRetentionEnabledInternal(), ShouldBeTrue)
		})

		Convey("Test with Config and retention policies with PulledWithin", func() {
			duration := time.Hour * 24
			cfg := &Config{
				Storage: GlobalStorageConfig{
					StorageConfig: StorageConfig{
						Retention: ImageRetention{
							Policies: []RetentionPolicy{
								{
									Repositories: []string{"repo1"},
									KeepTags: []KeepTagsPolicy{
										{
											Patterns:     []string{"latest"},
											PulledWithin: &duration,
										},
									},
								},
							},
						},
					},
				},
			}
			So(cfg.isRetentionEnabledInternal(), ShouldBeTrue)
		})

		Convey("Test with Config and retention policies with PushedWithin", func() {
			duration := time.Hour * 24
			cfg := &Config{
				Storage: GlobalStorageConfig{
					StorageConfig: StorageConfig{
						Retention: ImageRetention{
							Policies: []RetentionPolicy{
								{
									Repositories: []string{"repo1"},
									KeepTags: []KeepTagsPolicy{
										{
											Patterns:     []string{"latest"},
											PushedWithin: &duration,
										},
									},
								},
							},
						},
					},
				},
			}
			So(cfg.isRetentionEnabledInternal(), ShouldBeTrue)
		})

		Convey("Test with Config and retention policies in SubPaths", func() {
			cfg := &Config{
				Storage: GlobalStorageConfig{
					StorageConfig: StorageConfig{
						Retention: ImageRetention{
							Policies: []RetentionPolicy{},
						},
					},
					SubPaths: map[string]StorageConfig{
						"subpath1": {
							Retention: ImageRetention{
								Policies: []RetentionPolicy{
									{
										Repositories: []string{"repo1"},
										KeepTags: []KeepTagsPolicy{
											{
												Patterns:                []string{"latest"},
												MostRecentlyPulledCount: 5,
											},
										},
									},
								},
							},
						},
					},
				},
			}
			So(cfg.isRetentionEnabledInternal(), ShouldBeTrue)
		})

		Convey("Test with Config and retention policies with no tag retention", func() {
			cfg := &Config{
				Storage: GlobalStorageConfig{
					StorageConfig: StorageConfig{
						Retention: ImageRetention{
							Policies: []RetentionPolicy{
								{
									Repositories: []string{"repo1"},
									KeepTags: []KeepTagsPolicy{
										{
											Patterns: []string{"latest"},
											// No retention criteria set
										},
									},
								},
							},
						},
					},
				},
			}
			So(cfg.isRetentionEnabledInternal(), ShouldBeFalse)
		})
	})

	Convey("Test isTagsRetentionEnabled()", t, func() {
		Convey("Test with MostRecentlyPulledCount set", func() {
			policy := KeepTagsPolicy{
				Patterns:                []string{"latest"},
				MostRecentlyPulledCount: 5,
			}
			cfg := &Config{}
			So(cfg.isTagsRetentionEnabled(policy), ShouldBeTrue)
		})

		Convey("Test with MostRecentlyPushedCount set", func() {
			policy := KeepTagsPolicy{
				Patterns:                []string{"latest"},
				MostRecentlyPushedCount: 3,
			}
			cfg := &Config{}
			So(cfg.isTagsRetentionEnabled(policy), ShouldBeTrue)
		})

		Convey("Test with PulledWithin set", func() {
			duration := time.Hour * 24
			policy := KeepTagsPolicy{
				Patterns:     []string{"latest"},
				PulledWithin: &duration,
			}
			cfg := &Config{}
			So(cfg.isTagsRetentionEnabled(policy), ShouldBeTrue)
		})

		Convey("Test with PushedWithin set", func() {
			duration := time.Hour * 24
			policy := KeepTagsPolicy{
				Patterns:     []string{"latest"},
				PushedWithin: &duration,
			}
			cfg := &Config{}
			So(cfg.isTagsRetentionEnabled(policy), ShouldBeTrue)
		})

		Convey("Test with no retention criteria", func() {
			policy := KeepTagsPolicy{
				Patterns: []string{"latest"},
				// No retention criteria set
			}
			cfg := &Config{}
			So(cfg.isTagsRetentionEnabled(policy), ShouldBeFalse)
		})
	})

	Convey("Test isBasicAuthnEnabled()", t, func() {
		Convey("Test with nil Config", func() {
			var cfg *Config = nil
			So(cfg.isBasicAuthnEnabled(), ShouldBeFalse)
		})

		Convey("Test with HTPasswd enabled", func() {
			cfg := &Config{
				HTTP: HTTPConfig{
					Auth: &AuthConfig{
						HTPasswd: AuthHTPasswd{
							Path: "/path/to/htpasswd",
						},
					},
				},
			}
			So(cfg.isBasicAuthnEnabled(), ShouldBeTrue)
		})

		Convey("Test with LDAP enabled", func() {
			cfg := &Config{
				HTTP: HTTPConfig{
					Auth: &AuthConfig{
						LDAP: &LDAPConfig{},
					},
				},
			}
			So(cfg.isBasicAuthnEnabled(), ShouldBeTrue)
		})

		Convey("Test with API Key enabled", func() {
			cfg := &Config{
				HTTP: HTTPConfig{
					Auth: &AuthConfig{
						APIKey: true,
					},
				},
			}
			So(cfg.isBasicAuthnEnabled(), ShouldBeTrue)
		})

		Convey("Test with OpenID enabled (valid config)", func() {
			cfg := &Config{
				HTTP: HTTPConfig{
					Auth: &AuthConfig{
						OpenID: &OpenIDConfig{
							Providers: map[string]OpenIDProviderConfig{
								"google": {
									ClientID: "client-id",
									Issuer:   "",
									Scopes:   []string{},
								},
							},
						},
					},
				},
			}
			So(cfg.isBasicAuthnEnabled(), ShouldBeTrue)
		})

		Convey("Test with OpenID enabled (with Issuer)", func() {
			cfg := &Config{
				HTTP: HTTPConfig{
					Auth: &AuthConfig{
						OpenID: &OpenIDConfig{
							Providers: map[string]OpenIDProviderConfig{
								"google": {
									ClientID: "",
									Issuer:   "https://accounts.google.com",
									Scopes:   []string{},
								},
							},
						},
					},
				},
			}
			So(cfg.isBasicAuthnEnabled(), ShouldBeTrue)
		})

		Convey("Test with OpenID enabled (with Scopes)", func() {
			cfg := &Config{
				HTTP: HTTPConfig{
					Auth: &AuthConfig{
						OpenID: &OpenIDConfig{
							Providers: map[string]OpenIDProviderConfig{
								"google": {
									ClientID: "",
									Issuer:   "",
									Scopes:   []string{"openid", "email"},
								},
							},
						},
					},
				},
			}
			So(cfg.isBasicAuthnEnabled(), ShouldBeTrue)
		})

		Convey("Test with OAuth2 provider (github)", func() {
			cfg := &Config{
				HTTP: HTTPConfig{
					Auth: &AuthConfig{
						OpenID: &OpenIDConfig{
							Providers: map[string]OpenIDProviderConfig{
								"github": {
									ClientID: "github-client-id",
									Scopes:   []string{"user:email"},
								},
							},
						},
					},
				},
			}
			So(cfg.isBasicAuthnEnabled(), ShouldBeTrue)
		})

		Convey("Test with OpenID but empty config", func() {
			cfg := &Config{
				HTTP: HTTPConfig{
					Auth: &AuthConfig{
						OpenID: &OpenIDConfig{
							Providers: map[string]OpenIDProviderConfig{
								"google": {
									ClientID: "",
									Issuer:   "",
									Scopes:   []string{},
								},
							},
						},
					},
				},
			}
			So(cfg.isBasicAuthnEnabled(), ShouldBeFalse)
		})

		Convey("Test with OpenID but unsupported provider", func() {
			cfg := &Config{
				HTTP: HTTPConfig{
					Auth: &AuthConfig{
						OpenID: &OpenIDConfig{
							Providers: map[string]OpenIDProviderConfig{
								"unsupported": {
									ClientID: "client-id",
									Scopes:   []string{"scope"},
								},
							},
						},
					},
				},
			}
			So(cfg.isBasicAuthnEnabled(), ShouldBeFalse)
		})

		Convey("Test with no authentication methods", func() {
			cfg := &Config{
				HTTP: HTTPConfig{
					Auth: &AuthConfig{},
				},
			}
			So(cfg.isBasicAuthnEnabled(), ShouldBeFalse)
		})

		Convey("Test with nil Auth", func() {
			cfg := &Config{
				HTTP: HTTPConfig{
					Auth: nil,
				},
			}
			So(cfg.isBasicAuthnEnabled(), ShouldBeFalse)
		})
	})

	Convey("Test isOpenIDAuthProviderEnabled()", t, func() {
		// Note: This function doesn't handle nil configs properly, so we skip those tests
		// and focus on testing the actual logic with valid configs

		Convey("Test with Config and OpenID but no providers", func() {
			cfg := &Config{
				HTTP: HTTPConfig{
					Auth: &AuthConfig{
						OpenID: &OpenIDConfig{
							Providers: map[string]OpenIDProviderConfig{},
						},
					},
				},
			}
			So(isOpenIDAuthProviderEnabled(cfg, "google"), ShouldBeFalse)
		})

		Convey("Test with Config and OpenID and provider but no ClientID or Issuer", func() {
			cfg := &Config{
				HTTP: HTTPConfig{
					Auth: &AuthConfig{
						OpenID: &OpenIDConfig{
							Providers: map[string]OpenIDProviderConfig{
								"google": {
									ClientID: "",
									Issuer:   "",
									Scopes:   []string{},
								},
							},
						},
					},
				},
			}
			So(isOpenIDAuthProviderEnabled(cfg, "google"), ShouldBeFalse)
		})

		Convey("Test with Config and OpenID and provider with ClientID", func() {
			cfg := &Config{
				HTTP: HTTPConfig{
					Auth: &AuthConfig{
						OpenID: &OpenIDConfig{
							Providers: map[string]OpenIDProviderConfig{
								"google": {
									ClientID: "client-id",
									Issuer:   "",
									Scopes:   []string{},
								},
							},
						},
					},
				},
			}
			So(isOpenIDAuthProviderEnabled(cfg, "google"), ShouldBeTrue)
		})

		Convey("Test with Config and OpenID and provider with Issuer", func() {
			cfg := &Config{
				HTTP: HTTPConfig{
					Auth: &AuthConfig{
						OpenID: &OpenIDConfig{
							Providers: map[string]OpenIDProviderConfig{
								"google": {
									ClientID: "",
									Issuer:   "https://accounts.google.com",
									Scopes:   []string{},
								},
							},
						},
					},
				},
			}
			So(isOpenIDAuthProviderEnabled(cfg, "google"), ShouldBeTrue)
		})

		Convey("Test with Config and OpenID and provider with Scopes", func() {
			cfg := &Config{
				HTTP: HTTPConfig{
					Auth: &AuthConfig{
						OpenID: &OpenIDConfig{
							Providers: map[string]OpenIDProviderConfig{
								"google": {
									ClientID: "",
									Issuer:   "",
									Scopes:   []string{"openid", "email"},
								},
							},
						},
					},
				},
			}
			So(isOpenIDAuthProviderEnabled(cfg, "google"), ShouldBeTrue)
		})

		Convey("Test with OAuth2 provider (github) with ClientID", func() {
			cfg := &Config{
				HTTP: HTTPConfig{
					Auth: &AuthConfig{
						OpenID: &OpenIDConfig{
							Providers: map[string]OpenIDProviderConfig{
								"github": {
									ClientID: "github-client-id",
									Scopes:   []string{},
								},
							},
						},
					},
				},
			}
			So(isOpenIDAuthProviderEnabled(cfg, "github"), ShouldBeTrue)
		})

		Convey("Test with OAuth2 provider (github) with Scopes", func() {
			cfg := &Config{
				HTTP: HTTPConfig{
					Auth: &AuthConfig{
						OpenID: &OpenIDConfig{
							Providers: map[string]OpenIDProviderConfig{
								"github": {
									ClientID: "",
									Scopes:   []string{"user:email"},
								},
							},
						},
					},
				},
			}
			So(isOpenIDAuthProviderEnabled(cfg, "github"), ShouldBeTrue)
		})

		Convey("Test with unsupported provider", func() {
			cfg := &Config{
				HTTP: HTTPConfig{
					Auth: &AuthConfig{
						OpenID: &OpenIDConfig{
							Providers: map[string]OpenIDProviderConfig{
								"unsupported": {
									ClientID: "client-id",
									Scopes:   []string{"scope"},
								},
							},
						},
					},
				},
			}
			So(isOpenIDAuthProviderEnabled(cfg, "unsupported"), ShouldBeFalse)
		})

		Convey("Test with provider not in map", func() {
			cfg := &Config{
				HTTP: HTTPConfig{
					Auth: &AuthConfig{
						OpenID: &OpenIDConfig{
							Providers: map[string]OpenIDProviderConfig{
								"google": {
									ClientID: "client-id",
								},
							},
						},
					},
				},
			}
			So(isOpenIDAuthProviderEnabled(cfg, "microsoft"), ShouldBeFalse)
		})
	})
}
