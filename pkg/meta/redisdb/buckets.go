package redisdb

// MetadataDB.
const (
	ImageMetaBuck       = "zot:ImageMeta"
	RepoMetaBuck        = "zot:RepoMeta"
	RepoBlobsBuck       = "zot:RepoBlobsMeta"
	RepoLastUpdatedBuck = "zot:RepoLastUpdated"
	UserDataBucket      = "zot:UserData"
	VersionBucket       = "zot:Version"
	UserAPIKeysBucket   = "zot:UserAPIKeys" //nolint: gosec // these are not hardcoded credentials
	LockBuck            = "zot:Locks"
)
