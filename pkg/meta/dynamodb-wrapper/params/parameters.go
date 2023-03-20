package params

type DBDriverParameters struct {
	Endpoint, Region, RepoMetaTablename, ManifestDataTablename, IndexDataTablename,
	ArtifactDataTablename, VersionTablename string
}
