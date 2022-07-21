package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	glob "github.com/bmatcuk/doublestar/v4"
	distspec "github.com/opencontainers/distribution-spec/specs-go"
	"github.com/rs/zerolog/log"

	"zotregistry.io/zot/errors"
	"zotregistry.io/zot/pkg/extensions/sync"
	"zotregistry.io/zot/pkg/storage"
	"zotregistry.io/zot/pkg/storage/local"
)

func Validate(config *Config) error {
	if err := validateHTTP(config); err != nil {
		return err
	}

	if err := validateGC(config); err != nil {
		return err
	}

	if err := validateLDAP(config); err != nil {
		return err
	}

	if err := validateSync(config); err != nil {
		return err
	}

	if err := validateStorageConfig(config); err != nil {
		return err
	}

	if err := validateLocalStorage(config.Storage.RootDirectory); err != nil {
		return err
	}

	if config.Storage.SubPaths != nil {
		for _, subPath := range config.Storage.SubPaths {
			if err := validateLocalStorage(subPath.RootDirectory); err != nil {
				return err
			}
		}
	}

	if err := validateHtpasswd(config); err != nil {
		return err
	}

	if err := validateTLSCerts(config); err != nil {
		return err
	}

	// check authorization config, it should have basic auth enabled or ldap
	if config.HTTP.AccessControl != nil {
		// checking for anonymous policy only authorization config: no users, no policies but anonymous policy
		if err := validateAuthzPolicies(config); err != nil {
			return err
		}
	}

	if err := validateConfigExtensions(config); err != nil {
		return err
	}

	if err := validateRemoteStorage(config); err != nil {
		return err
	}

	// check glob patterns in authz config are compilable
	if config.HTTP.AccessControl != nil {
		for pattern := range config.HTTP.AccessControl.Repositories {
			ok := glob.ValidatePattern(pattern)
			if !ok {
				log.Error().Err(glob.ErrBadPattern).Str("pattern", pattern).Msg("authorization pattern could not be compiled")

				return glob.ErrBadPattern
			}
		}
	}

	updateDistSpecVersion(config)

	return nil
}

func updateDistSpecVersion(config *Config) {
	if config.DistSpecVersion == distspec.Version {
		return
	}

	log.Warn().Msgf("config dist-spec version: %s differs from version actually used: %s",
		config.DistSpecVersion, distspec.Version)

	config.DistSpecVersion = distspec.Version
}

func validateLDAP(config *Config) error {
	// LDAP mandatory configuration
	if config.HTTP.Auth != nil && config.HTTP.Auth.LDAP != nil {
		ldap := config.HTTP.Auth.LDAP
		if ldap.UserAttribute == "" {
			log.Error().Str("userAttribute", ldap.UserAttribute).
				Msg("invalid LDAP configuration, missing mandatory key: userAttribute")

			return errors.ErrLDAPConfig
		}

		if ldap.Address == "" {
			log.Error().Str("address", ldap.Address).
				Msg("invalid LDAP configuration, missing mandatory key: address")

			return errors.ErrLDAPConfig
		}

		if ldap.BaseDN == "" {
			log.Error().Str("basedn", ldap.BaseDN).
				Msg("invalid LDAP configuration, missing mandatory key: basedn")

			return errors.ErrLDAPConfig
		}
	}

	return nil
}

func validateGC(config *Config) error {
	// enforce GC params
	if config.Storage.GCDelay < 0 {
		log.Error().Err(errors.ErrBadConfig).
			Msgf("invalid garbage-collect delay %v specified", config.Storage.GCDelay)

		return errors.ErrBadConfig
	}

	if config.Storage.GCInterval < 0 {
		log.Error().Err(errors.ErrBadConfig).
			Msgf("invalid garbage-collect interval %v specified", config.Storage.GCInterval)

		return errors.ErrBadConfig
	}

	if !config.Storage.GC {
		if config.Storage.GCDelay != 0 {
			log.Warn().Err(errors.ErrBadConfig).
				Msg("garbage-collect delay specified without enabling garbage-collect, will be ignored")
		}

		if config.Storage.GCInterval != 0 {
			log.Warn().Err(errors.ErrBadConfig).
				Msg("periodic garbage-collect interval specified without enabling garbage-collect, will be ignored")
		}
	}

	return nil
}

func validateSync(config *Config) error {
	// check glob patterns in sync config are compilable
	if config.Extensions != nil && config.Extensions.Sync != nil {
		if config.Extensions.Sync.CredentialsFile != "" {
			_, err := sync.GetFileCredentials(config.Extensions.Sync.CredentialsFile)
			if err != nil {
				log.Error().Err(err).Msg("sync: couldn't read credentials file")

				return err
			}
		}

		for id, regCfg := range config.Extensions.Sync.Registries {
			// check retry options are configured for sync
			if regCfg.MaxRetries != nil && regCfg.RetryDelay == nil {
				log.Error().Err(errors.ErrBadConfig).Msgf("extensions.sync.registries[%d].retryDelay"+
					" is required when using extensions.sync.registries[%d].maxRetries", id, id)

				return errors.ErrBadConfig
			}

			if regCfg.Content != nil {
				for _, content := range regCfg.Content {
					ok := glob.ValidatePattern(content.Prefix)
					if !ok {
						log.Error().Err(glob.ErrBadPattern).Str("pattern", content.Prefix).Msg("sync pattern could not be compiled")

						return glob.ErrBadPattern
					}

					if content.StripPrefix && !strings.Contains(content.Prefix, "/*") && content.Destination == "/" {
						log.Error().Err(errors.ErrBadConfig).
							Interface("sync content", content).
							Msg("sync config: can not use stripPrefix true and destination '/' without using glob patterns in prefix")

						return errors.ErrBadConfig
					}
				}
			}
		}
	}

	return nil
}

func validateAuthzPolicies(config *Config) error {
	if (config.HTTP.Auth == nil || (config.HTTP.Auth.HTPasswd.Path == "" && config.HTTP.Auth.LDAP == nil)) &&
		!authzContainsOnlyAnonymousPolicy(config) {
		log.Error().Err(errors.ErrBadConfig).
			Msg("access control config requires httpasswd, ldap authentication " +
				"or using only 'anonymousPolicy' policies")

		return errors.ErrBadConfig
	}

	return nil
}

func authzContainsOnlyAnonymousPolicy(cfg *Config) bool {
	adminPolicy := cfg.HTTP.AccessControl.AdminPolicy
	anonymousPolicyPresent := false

	log.Info().Msg("checking if anonymous authorization is the only type of authorization policy configured")

	if len(adminPolicy.Actions)+len(adminPolicy.Users) > 0 {
		log.Info().Msg("admin policy detected, anonymous authorization is not the only authorization policy configured")

		return false
	}

	for _, repository := range cfg.HTTP.AccessControl.Repositories {
		if len(repository.DefaultPolicy) > 0 {
			log.Info().Interface("repository", repository).
				Msg("default policy detected, anonymous authorization is not the only authorization policy configured")

			return false
		}

		if len(repository.AnonymousPolicy) > 0 {
			log.Info().Msg("anonymous authorization detected")

			anonymousPolicyPresent = true
		}

		for _, policy := range repository.Policies {
			if len(policy.Actions)+len(policy.Users) > 0 {
				log.Info().Interface("repository", repository).
					Msg("repository with non-empty policy detected, " +
						"anonymous authorization is not the only authorization policy configured")

				return false
			}
		}
	}

	return anonymousPolicyPresent
}

func validateLocalStorage(rootDir string) error {
	if _, err := os.Stat(rootDir); os.IsNotExist(err) {
		if err := os.MkdirAll(rootDir, local.DefaultDirPerms); err != nil {
			log.Error().Err(err).Str("rootDir", rootDir).Msg("unable to create root dir")

			return err
		}
	}

	return nil
}

func validateRemoteStorage(config *Config) error {
	if len(config.Storage.StorageDriver) != 0 {
		// enforce s3 driver in case of using storage driver
		if config.Storage.StorageDriver["name"] != storage.S3StorageDriverName {
			log.Error().Err(errors.ErrBadConfig).Msgf("unsupported storage driver: %s", config.Storage.StorageDriver["name"])

			return errors.ErrBadConfig
		}

		// enforce filesystem storage in case sync feature is enabled
		if config.Extensions != nil && config.Extensions.Sync != nil {
			log.Error().Err(errors.ErrBadConfig).Msg("sync supports only filesystem storage")

			return errors.ErrBadConfig
		}
	}

	// enforce s3 driver on subpaths in case of using storage driver
	if config.Storage.SubPaths != nil {
		if len(config.Storage.SubPaths) > 0 {
			subPaths := config.Storage.SubPaths

			for route, storageConfig := range subPaths {
				if len(storageConfig.StorageDriver) != 0 {
					if storageConfig.StorageDriver["name"] != storage.S3StorageDriverName {
						log.Error().Err(errors.ErrBadConfig).Str("subpath",
							route).Msgf("unsupported storage driver: %s", storageConfig.StorageDriver["name"])

						return errors.ErrBadConfig
					}
				}
			}
		}
	}

	return nil
}

func validateHtpasswd(config *Config) error {
	if config.HTTP.Auth != nil && config.HTTP.Auth.HTPasswd.Path != "" {
		_, err := os.Stat(config.HTTP.Auth.HTPasswd.Path)
		if err != nil {
			log.Error().Err(err).Str("path", config.HTTP.Auth.HTPasswd.Path).Msg("authn: couldn't read htpasswd file")

			return err
		}
	}

	return nil
}

func validateHTTP(config *Config) error {
	if config.HTTP.Port != "" {
		port, err := strconv.ParseInt(config.HTTP.Port, 10, 64)
		if err != nil || (port < 0 || port > 65535) {
			log.Error().Str("port", config.HTTP.Port).Msg("invalid port")

			return errors.ErrBadConfig
		}

		fmt.Printf("HTTP port %d\n", port)
	}

	return nil
}

func validateTLSCerts(config *Config) error {
	if config.HTTP.TLS != nil {
		if config.HTTP.TLS.CACert != "" {
			_, err := os.Open(config.HTTP.TLS.CACert)
			if err != nil {
				log.Error().Err(err).Str("path", config.HTTP.TLS.CACert).Msg("authn: couldn't read TLS cacert file")

				return err
			}
		}

		if config.HTTP.TLS.Cert != "" {
			_, err := os.Open(config.HTTP.TLS.Cert)
			if err != nil {
				log.Error().Err(err).Str("path", config.HTTP.TLS.Cert).Msg("authn: couldn't read TLS cert file")

				return err
			}
		}

		if config.HTTP.TLS.Key != "" {
			_, err := os.Open(config.HTTP.TLS.Key)
			if err != nil {
				log.Error().Err(err).Str("path", config.HTTP.TLS.Key).Msg("authn: couldn't read TLS key file")

				return err
			}
		}
	}

	return nil
}

func validateConfigExtensions(config *Config) error {
	if config.Extensions != nil && config.Extensions.SysConfig != nil {
		if (config.HTTP.Auth == nil || (config.HTTP.Auth.HTPasswd.Path == "" && config.HTTP.Auth.LDAP == nil)) ||
			config.HTTP.AccessControl == nil {
			log.Error().Err(errors.ErrBadConfig).Msgf("config extensions needs auth and authorization enabled")

			return errors.ErrBadConfig
		}
	}

	return nil
}

func validateStorageConfig(cfg *Config) error {
	expConfigMap := make(map[string]StorageConfig, 0)

	defaultRootDir := cfg.Storage.RootDirectory

	for _, storageConfig := range cfg.Storage.SubPaths {
		if strings.EqualFold(defaultRootDir, storageConfig.RootDirectory) {
			log.Error().Err(errors.ErrBadConfig).Msg("storage subpaths cannot use default storage root directory")

			return errors.ErrBadConfig
		}

		expConfig, ok := expConfigMap[storageConfig.RootDirectory]
		if ok {
			equal := expConfig.ParamsEqual(storageConfig)
			if !equal {
				log.Error().Err(errors.ErrBadConfig).Msg("storage config with same root directory should have same parameters")

				return errors.ErrBadConfig
			}
		} else {
			expConfigMap[storageConfig.RootDirectory] = storageConfig
		}
	}

	return nil
}
