package config_test

import (
	"errors"
	"testing"

	. "github.com/smartystreets/goconvey/convey"

	"zotregistry.dev/zot/v2/pkg/extensions/config"
	"zotregistry.dev/zot/v2/pkg/extensions/config/events"
	"zotregistry.dev/zot/v2/pkg/extensions/config/sync"
)

var (
	errIsSearchEnabledExpectedTrue     = errors.New("expected IsSearchEnabled to return true, got false")
	errIsUIEnabledExpectedTrue         = errors.New("expected IsUIEnabled to return true, got false")
	errAreUserPrefsEnabledExpectedTrue = errors.New("expected AreUserPrefsEnabled to return true, got false")
	errPanicRecovered                  = errors.New("panic recovered")
)

// Config builder functions for different extension types.
func buildSearchConfig(enabled bool) *config.ExtensionConfig {
	ext := &config.ExtensionConfig{}
	ext.Search = &config.SearchConfig{
		BaseConfig: config.BaseConfig{
			Enable: &enabled,
		},
	}

	return ext
}

func buildSearchConfigWithCVE(enabled bool) *config.ExtensionConfig {
	ext := &config.ExtensionConfig{}
	ext.Search = &config.SearchConfig{
		BaseConfig: config.BaseConfig{
			Enable: &enabled,
		},
		CVE: &config.CVEConfig{
			Trivy: &config.TrivyConfig{},
		},
	}

	return ext
}

func buildEventsConfig(enabled bool) *config.ExtensionConfig {
	ext := &config.ExtensionConfig{}
	ext.Events = &events.Config{
		Enable: &enabled,
	}

	return ext
}

func buildSyncConfig(enabled bool) *config.ExtensionConfig {
	ext := &config.ExtensionConfig{}
	ext.Sync = &sync.Config{
		Enable: &enabled,
		Registries: []sync.RegistryConfig{
			{
				URLs: []string{"localhost"},
			},
		},
	}

	return ext
}

func buildScrubConfig(enabled bool) *config.ExtensionConfig {
	ext := &config.ExtensionConfig{}
	ext.Scrub = &config.ScrubConfig{
		BaseConfig: config.BaseConfig{
			Enable: &enabled,
		},
	}

	return ext
}

func buildMetricsConfig(enabled bool) *config.ExtensionConfig {
	ext := &config.ExtensionConfig{}
	ext.Metrics = &config.MetricsConfig{
		BaseConfig: config.BaseConfig{
			Enable: &enabled,
		},
		Prometheus: &config.PrometheusConfig{
			Path: "/metrics",
		},
	}

	return ext
}

func buildTrustConfig(enabled bool) *config.ExtensionConfig {
	ext := &config.ExtensionConfig{}
	ext.Trust = &config.ImageTrustConfig{
		BaseConfig: config.BaseConfig{
			Enable: &enabled,
		},
	}

	return ext
}

func buildUIConfig(enabled bool) *config.ExtensionConfig {
	ext := &config.ExtensionConfig{}
	ext.UI = &config.UIConfig{
		BaseConfig: config.BaseConfig{
			Enable: &enabled,
		},
	}

	return ext
}

func buildSearchAndUIConfig(enabled bool) *config.ExtensionConfig {
	ext := &config.ExtensionConfig{}
	ext.Search = &config.SearchConfig{
		BaseConfig: config.BaseConfig{
			Enable: &enabled,
		},
	}
	ext.UI = &config.UIConfig{
		BaseConfig: config.BaseConfig{
			Enable: &enabled,
		},
	}

	return ext
}

func buildTrustConfigWithCosign(enabled bool) *config.ExtensionConfig {
	ext := &config.ExtensionConfig{}
	ext.Trust = &config.ImageTrustConfig{
		BaseConfig: config.BaseConfig{
			Enable: &enabled,
		},
		Cosign: true,
	}

	return ext
}

func buildTrustConfigWithNotation(enabled bool) *config.ExtensionConfig {
	ext := &config.ExtensionConfig{}
	ext.Trust = &config.ImageTrustConfig{
		BaseConfig: config.BaseConfig{
			Enable: &enabled,
		},
		Notation: true,
	}

	return ext
}

// Test helper functions to reduce code duplication

// testMethodWithNilConfig tests a method with nil ExtensionConfig.
func testMethodWithNilConfig(testFunc func(*config.ExtensionConfig) bool) {
	Convey("Test with nil ExtensionConfig", func() {
		var extensionConfig *config.ExtensionConfig = nil

		So(testFunc(extensionConfig), ShouldBeFalse)
	})
}

// testMethodWithNilSubConfig tests a method when ExtensionConfig exists but the relevant sub-config is nil.
func testMethodWithNilSubConfig(subConfigName string, testFunc func(*config.ExtensionConfig) bool) {
	Convey("Test with ExtensionConfig but nil "+subConfigName, func() {
		extensionConfig := &config.ExtensionConfig{}

		So(testFunc(extensionConfig), ShouldBeFalse)
	})
}

// testMethodWithNilEnable tests a method when ExtensionConfig and sub-config exist but Enable is nil.
func testMethodWithNilEnable(subConfigName string, testFunc func(*config.ExtensionConfig) bool) {
	Convey("Test with ExtensionConfig and "+subConfigName+" but nil Enable", func() {
		extensionConfig := &config.ExtensionConfig{}

		So(testFunc(extensionConfig), ShouldBeFalse)
	})
}

// testMethodWithDisabledEnable tests a method when Enable is explicitly set to false.
func testMethodWithDisabledEnable(
	subConfigName string,
	testFunc func(*config.ExtensionConfig) bool,
	configBuilder func(bool) *config.ExtensionConfig,
) {
	Convey("Test with ExtensionConfig and "+subConfigName+" and Enable but disabled", func() {
		disabled := false
		extensionConfig := configBuilder(disabled)
		So(testFunc(extensionConfig), ShouldBeFalse)
	})
}

// testMethodWithEnabledEnable tests a method when Enable is explicitly set to true.
func testMethodWithEnabledEnable(
	subConfigName string,
	testFunc func(*config.ExtensionConfig) bool,
	configBuilder func(bool) *config.ExtensionConfig,
) {
	Convey("Test with ExtensionConfig and "+subConfigName+" and Enable enabled", func() {
		enabled := true
		extensionConfig := configBuilder(enabled)
		So(testFunc(extensionConfig), ShouldBeTrue)
	})
}

// testConcurrentAccessWithConfig tests concurrent access to a method with a properly configured ExtensionConfig.
func testConcurrentAccessWithConfig(
	methodName string,
	testFunc func(*config.ExtensionConfig) bool,
	expectedError error,
	extensionConfig *config.ExtensionConfig,
) {
	Convey("Test concurrent access to "+methodName, func() {
		// Test concurrent access to verify thread-safety
		done := make(chan bool, 10)
		errors := make(chan error, 10)

		for range 10 {
			go func() {
				defer func() {
					if r := recover(); r != nil {
						if err, ok := r.(error); ok {
							errors <- err
						} else {
							errors <- errPanicRecovered
						}
					}
					done <- true
				}()

				for range 100 {
					result := testFunc(extensionConfig)
					if !result {
						errors <- expectedError

						return
					}
				}
			}()
		}

		// Wait for all goroutines to complete
		for range 10 {
			<-done
		}

		// Check for errors
		close(errors)

		for err := range errors {
			So(err, ShouldBeNil)
		}
	})
}

// testGetterWithNilConfig tests a getter method with nil ExtensionConfig.
func testGetterWithNilConfig[T any](testFunc func(*config.ExtensionConfig) T, expected T) {
	Convey("Test with nil ExtensionConfig", func() {
		var extensionConfig *config.ExtensionConfig = nil

		result := testFunc(extensionConfig)
		So(result, ShouldEqual, expected)
	})
}

// testGetterWithNilSubConfig tests a getter method when ExtensionConfig exists but the relevant sub-config is nil.
func testGetterWithNilSubConfig[T any](subConfigName string, testFunc func(*config.ExtensionConfig) T, expected T) {
	Convey("Test with ExtensionConfig but nil "+subConfigName, func() {
		extensionConfig := &config.ExtensionConfig{}

		result := testFunc(extensionConfig)
		So(result, ShouldEqual, expected)
	})
}

// testGetterWithValidConfig tests a getter method with valid configuration.
func testGetterWithValidConfig[T any](
	subConfigName string,
	testFunc func(*config.ExtensionConfig) T,
	configBuilder func(bool) *config.ExtensionConfig,
) {
	Convey("Test with valid "+subConfigName+" configuration", func() {
		enabled := true
		extensionConfig := configBuilder(enabled)

		result := testFunc(extensionConfig)
		So(result, ShouldNotBeNil)
	})
}

func TestExtensionConfig(t *testing.T) {
	Convey("Test public methods", t, func() {
		Convey("Test IsCveScanningEnabled()", func() {
			testMethodWithNilConfig((*config.ExtensionConfig).IsCveScanningEnabled)
			testMethodWithNilSubConfig("Search", (*config.ExtensionConfig).IsCveScanningEnabled)
			testMethodWithNilEnable("Search", (*config.ExtensionConfig).IsCveScanningEnabled)
			testMethodWithDisabledEnable("Search", (*config.ExtensionConfig).IsCveScanningEnabled, buildSearchConfig)
			testMethodWithEnabledEnable("Search", (*config.ExtensionConfig).IsCveScanningEnabled, buildSearchConfigWithCVE)
		})

		Convey("Test IsEventRecorderEnabled()", func() {
			testMethodWithNilConfig((*config.ExtensionConfig).IsEventRecorderEnabled)
			testMethodWithNilSubConfig("Events", (*config.ExtensionConfig).IsEventRecorderEnabled)
			testMethodWithNilEnable("Events", (*config.ExtensionConfig).IsEventRecorderEnabled)
			testMethodWithDisabledEnable("Events", (*config.ExtensionConfig).IsEventRecorderEnabled, buildEventsConfig)
			testMethodWithEnabledEnable("Events", (*config.ExtensionConfig).IsEventRecorderEnabled, buildEventsConfig)
		})

		Convey("Test IsSearchEnabled()", func() {
			testMethodWithNilConfig((*config.ExtensionConfig).IsSearchEnabled)
			testMethodWithNilSubConfig("Search", (*config.ExtensionConfig).IsSearchEnabled)
			testMethodWithNilEnable("Search", (*config.ExtensionConfig).IsSearchEnabled)
			testMethodWithDisabledEnable("Search", (*config.ExtensionConfig).IsSearchEnabled, buildSearchConfig)
			testMethodWithEnabledEnable("Search", (*config.ExtensionConfig).IsSearchEnabled, buildSearchConfig)
		})

		Convey("Test IsSyncEnabled()", func() {
			testMethodWithNilConfig((*config.ExtensionConfig).IsSyncEnabled)
			testMethodWithNilSubConfig("Sync", (*config.ExtensionConfig).IsSyncEnabled)
			testMethodWithNilEnable("Sync", (*config.ExtensionConfig).IsSyncEnabled)
			testMethodWithDisabledEnable("Sync", (*config.ExtensionConfig).IsSyncEnabled, buildSyncConfig)
			testMethodWithEnabledEnable("Sync", (*config.ExtensionConfig).IsSyncEnabled, buildSyncConfig)
		})

		Convey("Test IsScrubEnabled()", func() {
			testMethodWithNilConfig((*config.ExtensionConfig).IsScrubEnabled)
			testMethodWithNilSubConfig("Scrub", (*config.ExtensionConfig).IsScrubEnabled)
			testMethodWithNilEnable("Scrub", (*config.ExtensionConfig).IsScrubEnabled)
			testMethodWithDisabledEnable("Scrub", (*config.ExtensionConfig).IsScrubEnabled, buildScrubConfig)
			testMethodWithEnabledEnable("Scrub", (*config.ExtensionConfig).IsScrubEnabled, buildScrubConfig)
		})

		Convey("Test IsMetricsEnabled()", func() {
			testMethodWithNilConfig((*config.ExtensionConfig).IsMetricsEnabled)
			testMethodWithNilSubConfig("Metrics", (*config.ExtensionConfig).IsMetricsEnabled)
			testMethodWithNilEnable("Metrics", (*config.ExtensionConfig).IsMetricsEnabled)
			testMethodWithDisabledEnable("Metrics", (*config.ExtensionConfig).IsMetricsEnabled, buildMetricsConfig)
			testMethodWithEnabledEnable("Metrics", (*config.ExtensionConfig).IsMetricsEnabled, buildMetricsConfig)
		})

		Convey("Test IsCosignEnabled()", func() {
			testMethodWithNilConfig((*config.ExtensionConfig).IsCosignEnabled)
			testMethodWithNilSubConfig("Trust", (*config.ExtensionConfig).IsCosignEnabled)
			testMethodWithNilEnable("Trust", (*config.ExtensionConfig).IsCosignEnabled)
			testMethodWithDisabledEnable("Trust", (*config.ExtensionConfig).IsCosignEnabled, buildTrustConfig)
			testMethodWithEnabledEnable("Trust", (*config.ExtensionConfig).IsCosignEnabled, buildTrustConfigWithCosign)
		})

		Convey("Test IsNotationEnabled()", func() {
			testMethodWithNilConfig((*config.ExtensionConfig).IsNotationEnabled)
			testMethodWithNilSubConfig("Trust", (*config.ExtensionConfig).IsNotationEnabled)
			testMethodWithNilEnable("Trust", (*config.ExtensionConfig).IsNotationEnabled)
			testMethodWithDisabledEnable("Trust", (*config.ExtensionConfig).IsNotationEnabled, buildTrustConfig)
			testMethodWithEnabledEnable("Trust", (*config.ExtensionConfig).IsNotationEnabled, buildTrustConfigWithNotation)
		})

		Convey("Test IsImageTrustEnabled()", func() {
			testMethodWithNilConfig((*config.ExtensionConfig).IsImageTrustEnabled)
			testMethodWithNilSubConfig("Trust", (*config.ExtensionConfig).IsImageTrustEnabled)
			testMethodWithNilEnable("Trust", (*config.ExtensionConfig).IsImageTrustEnabled)
			testMethodWithDisabledEnable("Trust", (*config.ExtensionConfig).IsImageTrustEnabled, buildTrustConfig)
			testMethodWithEnabledEnable("Trust", (*config.ExtensionConfig).IsImageTrustEnabled, buildTrustConfig)
		})

		Convey("Test IsUIEnabled()", func() {
			testMethodWithNilConfig((*config.ExtensionConfig).IsUIEnabled)
			testMethodWithNilSubConfig("UI", (*config.ExtensionConfig).IsUIEnabled)
			testMethodWithNilEnable("UI", (*config.ExtensionConfig).IsUIEnabled)
			testMethodWithDisabledEnable("UI", (*config.ExtensionConfig).IsUIEnabled, buildUIConfig)
			testMethodWithEnabledEnable("UI", (*config.ExtensionConfig).IsUIEnabled, buildUIConfig)
		})

		Convey("Test AreUserPrefsEnabled()", func() {
			testMethodWithNilConfig((*config.ExtensionConfig).AreUserPrefsEnabled)
			testMethodWithNilSubConfig("Search", (*config.ExtensionConfig).AreUserPrefsEnabled)
			testMethodWithNilEnable("UI", (*config.ExtensionConfig).AreUserPrefsEnabled)
			testMethodWithDisabledEnable("Search", (*config.ExtensionConfig).AreUserPrefsEnabled, buildSearchConfig)
			testMethodWithEnabledEnable("Search", (*config.ExtensionConfig).AreUserPrefsEnabled, buildSearchAndUIConfig)
		})
	})

	// Additional tests to verify thread-safety and internal method behavior
	Convey("Test thread-safety and internal method coverage", t, func() {
		// Create properly configured ExtensionConfigs for concurrent testing
		searchEnabled := true
		uiEnabled := true
		searchConfig := &config.ExtensionConfig{}
		searchConfig.Search = &config.SearchConfig{
			BaseConfig: config.BaseConfig{
				Enable: &searchEnabled,
			},
		}
		uiConfig := &config.ExtensionConfig{}
		uiConfig.UI = &config.UIConfig{
			BaseConfig: config.BaseConfig{
				Enable: &uiEnabled,
			},
		}
		searchAndUIConfig := &config.ExtensionConfig{}
		searchAndUIConfig.Search = &config.SearchConfig{
			BaseConfig: config.BaseConfig{
				Enable: &searchEnabled,
			},
		}
		searchAndUIConfig.UI = &config.UIConfig{
			BaseConfig: config.BaseConfig{
				Enable: &uiEnabled,
			},
		}

		testConcurrentAccessWithConfig(
			"IsSearchEnabled",
			(*config.ExtensionConfig).IsSearchEnabled,
			errIsSearchEnabledExpectedTrue,
			searchConfig,
		)
		testConcurrentAccessWithConfig(
			"IsUIEnabled",
			(*config.ExtensionConfig).IsUIEnabled,
			errIsUIEnabledExpectedTrue,
			uiConfig,
		)
		testConcurrentAccessWithConfig(
			"AreUserPrefsEnabled",
			(*config.ExtensionConfig).AreUserPrefsEnabled,
			errAreUserPrefsEnabledExpectedTrue,
			searchAndUIConfig,
		)

		Convey("Test mixed concurrent access to all methods", func() {
			searchEnabled := true
			uiEnabled := true
			extensionConfig := &config.ExtensionConfig{}
			extensionConfig.Search = &config.SearchConfig{
				BaseConfig: config.BaseConfig{
					Enable: &searchEnabled,
				},
			}
			extensionConfig.UI = &config.UIConfig{
				BaseConfig: config.BaseConfig{
					Enable: &uiEnabled,
				},
			}

			// Test mixed concurrent access to verify thread-safety across all methods
			done := make(chan bool, 15)
			errors := make(chan error, 15)

			// Launch goroutines for each method
			for range 5 {
				go func() {
					defer func() {
						if r := recover(); r != nil {
							if err, ok := r.(error); ok {
								errors <- err
							} else {
								errors <- errPanicRecovered
							}
						}
						done <- true
					}()

					for range 50 {
						result := extensionConfig.IsSearchEnabled()
						if !result {
							errors <- errIsSearchEnabledExpectedTrue

							return
						}
					}
				}()
			}

			for range 5 {
				go func() {
					defer func() {
						if r := recover(); r != nil {
							if err, ok := r.(error); ok {
								errors <- err
							} else {
								errors <- errPanicRecovered
							}
						}
						done <- true
					}()

					for range 50 {
						result := extensionConfig.IsUIEnabled()
						if !result {
							errors <- errIsUIEnabledExpectedTrue

							return
						}
					}
				}()
			}

			for range 5 {
				go func() {
					defer func() {
						if r := recover(); r != nil {
							if err, ok := r.(error); ok {
								errors <- err
							} else {
								errors <- errPanicRecovered
							}
						}
						done <- true
					}()

					for range 50 {
						result := extensionConfig.AreUserPrefsEnabled()
						if !result {
							errors <- errAreUserPrefsEnabledExpectedTrue

							return
						}
					}
				}()
			}

			// Wait for all goroutines to complete
			for range 15 {
				<-done
			}

			// Check for errors
			close(errors)

			for err := range errors {
				So(err, ShouldBeNil)
			}
		})

		Convey("Test GetSearchCVEConfig()", func() {
			testGetterWithNilConfig((*config.ExtensionConfig).GetSearchCVEConfig, nil)
			testGetterWithNilSubConfig("Search", (*config.ExtensionConfig).GetSearchCVEConfig, nil)
			testGetterWithValidConfig("Search", (*config.ExtensionConfig).GetSearchCVEConfig, buildSearchConfigWithCVE)
		})

		Convey("Test GetScrubInterval()", func() {
			testGetterWithNilConfig((*config.ExtensionConfig).GetScrubInterval, 0)
			testGetterWithNilSubConfig("Scrub", (*config.ExtensionConfig).GetScrubInterval, 0)
			testGetterWithValidConfig("Scrub", (*config.ExtensionConfig).GetScrubInterval, buildScrubConfig)
		})

		Convey("Test GetSyncConfig()", func() {
			testGetterWithNilConfig((*config.ExtensionConfig).GetSyncConfig, nil)
			testGetterWithValidConfig("Sync", (*config.ExtensionConfig).GetSyncConfig, buildSyncConfig)
		})

		Convey("Test GetMetricsPrometheusConfig()", func() {
			testGetterWithNilConfig((*config.ExtensionConfig).GetMetricsPrometheusConfig, nil)
			testGetterWithNilSubConfig("Metrics", (*config.ExtensionConfig).GetMetricsPrometheusConfig, nil)
			testGetterWithValidConfig("Metrics", (*config.ExtensionConfig).GetMetricsPrometheusConfig, buildMetricsConfig)
		})

		Convey("Test GetEventsConfig()", func() {
			testGetterWithNilConfig((*config.ExtensionConfig).GetEventsConfig, nil)
			testGetterWithValidConfig("Events", (*config.ExtensionConfig).GetEventsConfig, buildEventsConfig)
		})
	})
}
