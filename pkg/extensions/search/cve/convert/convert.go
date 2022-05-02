package convert

import (
	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy/pkg/report"
	"github.com/aquasecurity/trivy/pkg/types"
	"zotregistry.io/zot/pkg/plugins/scan"
)

func ToRPCScanReport(report report.Report) *scan.ScanReport {
	return &scan.ScanReport{
		Image: &scan.Image{
			Name: report.ArtifactName,
		},
		Scanner: &scan.Scanner{
			Name:   "Trivy Cve Scanner",
			Vendor: "Aquasecurity",
		},
		Vulnerabilities: ResultsToRPCVulns(report.Results),
	}
}

func ResultsToRPCVulns(results report.Results) []*scan.ScanVulnerability {
	var vulnerabilities []types.DetectedVulnerability

	for i := range results {
		vulnerabilities = append(vulnerabilities, results[i].Vulnerabilities...)
	}

	rpcVulns := make([]*scan.ScanVulnerability, len(vulnerabilities))

	for i, vuln := range vulnerabilities {
		rpcVulns[i] = &scan.ScanVulnerability{
			VulnerabilityId: vuln.VulnerabilityID,
			Pkg:             vuln.PkgName,
			Version:         vuln.InstalledVersion,
			FixedVersion:    vuln.FixedVersion,
			Title:           vuln.Title,
			Severity:        toSeverity(vuln.Severity),
			Description:     vuln.Description,
			References:      toLinks(vuln.PrimaryURL, vuln.References),
			Layer: &scan.Layer{
				Digest: vuln.Layer.Digest,
				DiffId: vuln.Layer.DiffID,
			},
			Cvss:   toCVSS(vuln.CVSS),
			CweIds: vuln.CweIDs,
		}
	}

	return rpcVulns
}

func toSeverity(s string) scan.Severity {
	return scan.Severity(scan.Severity_value[s])
}

func toLinks(primary string, refferences []string) []string {
	return append(refferences, primary)
}

func toCVSS(vulnCVSS dbTypes.VendorCVSS) map[string]*scan.CVSS {
	scanCvss := make(map[string]*scan.CVSS)

	for k, v := range vulnCVSS {
		scanCvss[k] = &scan.CVSS{
			V2Vector: v.V2Vector,
			V3Vector: v.V3Vector,
			V2Score:  v.V2Score,
			V3Score:  v.V3Score,
		}
	}

	return scanCvss
}

/*

// ToRPCPkgs returns the list of RPC package objects
func ToRPCPkgs(pkgs []ftypes.Package) []*scan.Package {
	var rpcPkgs []*scan.Package
	for _, pkg := range pkgs {
		rpcPkgs = append(rpcPkgs, &scan.Package{
			Name:       pkg.Name,
			Version:    pkg.Version,
			Release:    pkg.Release,
			Epoch:      int32(pkg.Epoch),
			Arch:       pkg.Arch,
			SrcName:    pkg.SrcName,
			SrcVersion: pkg.SrcVersion,
			SrcRelease: pkg.SrcRelease,
			SrcEpoch:   int32(pkg.SrcEpoch),
			License:    pkg.License,
			Layer:      ToRPCLayer(pkg.Layer),
		})
	}
	return rpcPkgs
}

// FromRPCPkgs returns list of Fanal package objects
func FromRPCPkgs(rpcPkgs []*scan.Package) []ftypes.Package {
	var pkgs []ftypes.Package
	for _, pkg := range rpcPkgs {
		pkgs = append(pkgs, ftypes.Package{
			Name:       pkg.Name,
			Version:    pkg.Version,
			Release:    pkg.Release,
			Epoch:      int(pkg.Epoch),
			Arch:       pkg.Arch,
			SrcName:    pkg.SrcName,
			SrcVersion: pkg.SrcVersion,
			SrcRelease: pkg.SrcRelease,
			SrcEpoch:   int(pkg.SrcEpoch),
			License:    pkg.License,
			Layer:      FromRPCLayer(pkg.Layer),
		})
	}
	return pkgs
}

// FromRPCLibraries returns list of Fanal library
func FromRPCLibraries(rpcLibs []*scan.Library) []ftypes.Package {
	var pkgs []ftypes.Package
	for _, l := range rpcLibs {
		pkgs = append(pkgs, ftypes.Package{
			Name:    l.Name,
			Version: l.Version,
			License: l.License,
		})
	}
	return pkgs
}

// ToRPCVulns returns scan.Vulnerability
func ToRPCVulns(vulns []types.DetectedVulnerability) []*scan.Vulnerability {
	var rpcVulns []*scan.Vulnerability
	for _, vuln := range vulns {
		severity, err := dbTypes.NewSeverity(vuln.Severity)
		if err != nil {
			fmt.Println(err)
		}
		cvssMap := make(map[string]*scan.CVSS) // This is needed because protobuf generates a map[string]*CVSS type
		for vendor, vendorSeverity := range vuln.CVSS {
			cvssMap[vendor] = &scan.CVSS{
				V2Vector: vendorSeverity.V2Vector,
				V3Vector: vendorSeverity.V3Vector,
				V2Score:  vendorSeverity.V2Score,
				V3Score:  vendorSeverity.V3Score,
			}
		}

		var lastModifiedDate, publishedDate *timestamp.Timestamp
		if vuln.LastModifiedDate != nil {
			lastModifiedDate, _ = ptypes.TimestampProto(*vuln.LastModifiedDate) // nolint: errcheck
		}

		if vuln.PublishedDate != nil {
			publishedDate, _ = ptypes.TimestampProto(*vuln.PublishedDate) // nolint: errcheck
		}

		rpcVulns = append(rpcVulns, &scan.Vulnerability{
			VulnerabilityId:  vuln.VulnerabilityID,
			PkgName:          vuln.PkgName,
			InstalledVersion: vuln.InstalledVersion,
			FixedVersion:     vuln.FixedVersion,
			Title:            vuln.Title,
			Description:      vuln.Description,
			Severity:         scan.Severity(severity),
			References:       vuln.References,
			Layer:            ToRPCLayer(vuln.Layer),
			Cvss:             cvssMap,
			SeveritySource:   vuln.SeveritySource,
			CweIds:           vuln.CweIDs,
			PrimaryUrl:       vuln.PrimaryURL,
			LastModifiedDate: lastModifiedDate,
			PublishedDate:    publishedDate,
		})
	}
	return rpcVulns
}

// ToRPCMisconfs returns scan.DetectedMisconfigurations
func ToRPCMisconfs(misconfs []types.DetectedMisconfiguration) []*scan.DetectedMisconfiguration {
	var rpcMisconfs []*scan.DetectedMisconfiguration
	for _, m := range misconfs {
		severity, err := dbTypes.NewSeverity(m.Severity)
		if err != nil {
			fmt.Println(err)
		}

		rpcMisconfs = append(rpcMisconfs, &scan.DetectedMisconfiguration{
			Type:        m.Type,
			Id:          m.ID,
			Title:       m.Title,
			Description: m.Description,
			Message:     m.Message,
			Namespace:   m.Namespace,
			Resolution:  m.Resolution,
			Severity:    scan.Severity(severity),
			PrimaryUrl:  m.PrimaryURL,
			References:  m.References,
			Status:      string(m.Status),
			Layer:       ToRPCLayer(m.Layer),
		})
	}
	return rpcMisconfs
}

// ToRPCLayer returns scan.Layer
func ToRPCLayer(layer ftypes.Layer) *scan.Layer {
	return &scan.Layer{
		Digest: layer.Digest,
		DiffId: layer.DiffID,
	}
}

// FromRPCResults converts scan.Result to report.Result
func FromRPCResults(rpcResults []*scan.Result) []report.Result {
	var results []report.Result
	for _, result := range rpcResults {
		results = append(results, report.Result{
			Target:            result.Target,
			Vulnerabilities:   FromRPCVulns(result.Vulnerabilities),
			Misconfigurations: FromRPCMisconfs(result.Misconfigurations),
			Class:             report.ResultClass(result.Class),
			Type:              result.Type,
			Packages:          FromRPCPkgs(result.Packages),
		})
	}
	return results
}

// FromRPCVulns converts []*scan.Vulnerability to []types.DetectedVulnerability
func FromRPCVulns(rpcVulns []*scan.Vulnerability) []types.DetectedVulnerability {
	var vulns []types.DetectedVulnerability
	for _, vuln := range rpcVulns {
		severity := dbTypes.Severity(vuln.Severity)
		cvssMap := make(dbTypes.VendorCVSS) // This is needed because protobuf generates a map[string]*CVSS type
		for vendor, vendorSeverity := range vuln.Cvss {
			cvssMap[vendor] = dbTypes.CVSS{
				V2Vector: vendorSeverity.V2Vector,
				V3Vector: vendorSeverity.V3Vector,
				V2Score:  vendorSeverity.V2Score,
				V3Score:  vendorSeverity.V3Score,
			}
		}

		var lastModifiedDate, publishedDate *time.Time
		if vuln.LastModifiedDate != nil {
			t, _ := ptypes.Timestamp(vuln.LastModifiedDate) // nolint: errcheck
			lastModifiedDate = &t
		}
		if vuln.PublishedDate != nil {
			t, _ := ptypes.Timestamp(vuln.PublishedDate) // nolint: errcheck
			publishedDate = &t
		}

		vulns = append(vulns, types.DetectedVulnerability{
			VulnerabilityID:  vuln.VulnerabilityId,
			PkgName:          vuln.PkgName,
			InstalledVersion: vuln.InstalledVersion,
			FixedVersion:     vuln.FixedVersion,
			Vulnerability: dbTypes.Vulnerability{
				Title:            vuln.Title,
				Description:      vuln.Description,
				Severity:         severity.String(),
				CVSS:             cvssMap,
				References:       vuln.References,
				CweIDs:           vuln.CweIds,
				LastModifiedDate: lastModifiedDate,
				PublishedDate:    publishedDate,
			},
			Layer:          FromRPCLayer(vuln.Layer),
			SeveritySource: vuln.SeveritySource,
			PrimaryURL:     vuln.PrimaryUrl,
		})
	}
	return vulns
}

// FromRPCMisconfs converts []*scan.DetectedMisconfigurations to []types.DetectedMisconfiguration
func FromRPCMisconfs(rpcMisconfs []*scan.DetectedMisconfiguration) []types.DetectedMisconfiguration {
	var misconfs []types.DetectedMisconfiguration
	for _, rpcMisconf := range rpcMisconfs {
		misconfs = append(misconfs, types.DetectedMisconfiguration{
			Type:        rpcMisconf.Type,
			ID:          rpcMisconf.Id,
			Title:       rpcMisconf.Title,
			Description: rpcMisconf.Description,
			Message:     rpcMisconf.Message,
			Namespace:   rpcMisconf.Namespace,
			Resolution:  rpcMisconf.Resolution,
			Severity:    rpcMisconf.Severity.String(),
			PrimaryURL:  rpcMisconf.PrimaryUrl,
			References:  rpcMisconf.References,
			Status:      types.MisconfStatus(rpcMisconf.Status),
			Layer:       FromRPCLayer(rpcMisconf.Layer),
		})
	}
	return misconfs
}

// FromRPCLayer converts *scan.Layer to fanal.Layer
func FromRPCLayer(rpcLayer *scan.Layer) ftypes.Layer {
	return ftypes.Layer{
		Digest: rpcLayer.Digest,
		DiffID: rpcLayer.DiffId,
	}
}

// FromRPCOS converts scan.OS to fanal.OS
func FromRPCOS(rpcOS *scan.OS) *ftypes.OS {
	if rpcOS == nil {
		return nil
	}
	return &ftypes.OS{
		Family: rpcOS.Family,
		Name:   rpcOS.Name,
		Eosl:   rpcOS.Eosl,
	}
}

// FromRPCPackageInfos converts scan.PackageInfo to fanal.PackageInfo
func FromRPCPackageInfos(rpcPkgInfos []*scan.PackageInfo) []ftypes.PackageInfo {
	var pkgInfos []ftypes.PackageInfo
	for _, rpcPkgInfo := range rpcPkgInfos {
		pkgInfos = append(pkgInfos, ftypes.PackageInfo{
			FilePath: rpcPkgInfo.FilePath,
			Packages: FromRPCPkgs(rpcPkgInfo.Packages),
		})
	}
	return pkgInfos
}

// FromRPCApplications converts scan.Application to fanal.Application
func FromRPCApplications(rpcApps []*scan.Application) []ftypes.Application {
	var apps []ftypes.Application
	for _, rpcApp := range rpcApps {
		apps = append(apps, ftypes.Application{
			Type:      rpcApp.Type,
			FilePath:  rpcApp.FilePath,
			Libraries: FromRPCLibraries(rpcApp.Libraries),
		})
	}
	return apps
}

// FromRPCMisconfigurations converts scan.Misconfiguration to fanal.Misconfiguration
func FromRPCMisconfigurations(rpcMisconfs []*scan.Misconfiguration) []ftypes.Misconfiguration {
	var misconfs []ftypes.Misconfiguration
	for _, rpcMisconf := range rpcMisconfs {
		misconfs = append(misconfs, ftypes.Misconfiguration{
			FileType:   rpcMisconf.FileType,
			FilePath:   rpcMisconf.FilePath,
			Successes:  FromRPCMisconfResults(rpcMisconf.Successes),
			Warnings:   FromRPCMisconfResults(rpcMisconf.Warnings),
			Failures:   FromRPCMisconfResults(rpcMisconf.Failures),
			Exceptions: FromRPCMisconfResults(rpcMisconf.Exceptions),
			Layer:      ftypes.Layer{},
		})
	}
	return misconfs
}

// FromRPCMisconfResults converts scan.MisconfResult to fanal.MisconfResult
func FromRPCMisconfResults(rpcResults []*scan.MisconfResult) []ftypes.MisconfResult {
	var results []ftypes.MisconfResult
	for _, r := range rpcResults {
		results = append(results, ftypes.MisconfResult{
			Namespace: r.Namespace,
			Message:   r.Message,
			PolicyMetadata: ftypes.PolicyMetadata{
				ID:       r.Id,
				Type:     r.Type,
				Title:    r.Title,
				Severity: r.Severity,
			},
		})
	}
	return results
}

// ToRPCOS returns scan.OS
func ToRPCOS(fos *ftypes.OS) *scan.OS {
	if fos == nil {
		return nil
	}
	return &scan.OS{
		Family: fos.Family,
		Name:   fos.Name,
		Eosl:   fos.Eosl,
	}
}

// ToMisconfResults returns scan.MisconfResult
func ToMisconfResults(results []ftypes.MisconfResult) []*scan.MisconfResult {
	var rpcResults []*scan.MisconfResult
	for _, r := range results {
		rpcResults = append(rpcResults, &scan.MisconfResult{
			Namespace: r.Namespace,
			Message:   r.Message,
			Id:        r.ID,
			Type:      r.Type,
			Title:     r.Title,
			Severity:  r.Severity,
		})
	}
	return rpcResults
}

// ToRPCScanResponse converts report.Result to ScanResponse
func ToRPCScanResponse(results report.Results, fos *ftypes.OS) *scan.ScanResponse {
	var rpcResults []*scan.Result
	for _, result := range results {
		rpcResults = append(rpcResults, &scan.Result{
			Target:            result.Target,
			Class:             string(result.Class),
			Type:              result.Type,
			Vulnerabilities:   ToRPCVulns(result.Vulnerabilities),
			Misconfigurations: ToRPCMisconfs(result.Misconfigurations),
			Packages:          ToRPCPkgs(result.Packages),
		})
	}

	return &scan.ScanResponse{
		Os:      ToRPCOS(fos),
		Results: rpcResults,
	}
}

*/
