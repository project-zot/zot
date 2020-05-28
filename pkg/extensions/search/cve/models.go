// Package cveinfo ...
// Referred from https://github.com/kotakanbe/go-cve-dictionary/blob/master/models/models.go
package cveinfo

import (
	"github.com/anuvu/zot/pkg/log"
)

// CveInfo ...
type CveInfo struct {
	Log     log.Logger
	RootDir string
}
