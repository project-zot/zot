package model

//nolint:tagliatelle // graphQL schema
type CVE struct {
	ID          string    `json:"Id"`
	Description string    `json:"Description"`
	Severity    string    `json:"Severity"`
	Title       string    `json:"Title"`
	PackageList []Package `json:"PackageList"`
}

//nolint:tagliatelle // graphQL schema
type Package struct {
	Name             string `json:"Name"`
	InstalledVersion string `json:"InstalledVersion"`
	FixedVersion     string `json:"FixedVersion"`
}

const (
	None = iota
	Low
	Medium
	High
	Critical
)

func SeverityValue(severity string) int {
	sevMap := map[string]int{
		"NONE":     None,
		"LOW":      Low,
		"MEDIUM":   Medium,
		"HIGH":     High,
		"CRITICAL": Critical,
	}

	return sevMap[severity]
}
