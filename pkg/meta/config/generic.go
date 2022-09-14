package config

type UserMetadataStoreConfig struct {
	RootDir string `json:"rootDir"`
	Driver  string `json:"driver"`
	Enabled *bool  `json:"enabled,omitempty"`
}

type MetadataStoreConfig struct {
	User *UserMetadataStoreConfig `mapstructure:"user,omitempty"`
}

const (
	UserMetadataLocalDriver = "local"
	UserMetadataLocalFile   = "metadata_user"
)

type UserState int

const (
	NotChanged UserState = iota
	Added
	Removed
)
