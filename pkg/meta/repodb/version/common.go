package version

const (
	Version1 = "V1"
	Version2 = "V2"
	Version3 = "V3"

	CurrentVersion = Version1
)

const (
	versionV1Index = iota
	versionV2Index
	versionV3Index
)

const DBVersionKey = "DBVersion"

func GetVersionIndex(dbVersion string) int {
	index, ok := map[string]int{
		Version1: versionV1Index,
		Version2: versionV2Index,
		Version3: versionV3Index,
	}[dbVersion]

	if !ok {
		return -1
	}

	return index
}
