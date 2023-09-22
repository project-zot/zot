package types

import (
	"time"

	ispec "github.com/opencontainers/image-spec/specs-go/v1"

	mTypes "zotregistry.io/zot/pkg/meta/types"
)

type Candidate struct {
	DigestStr     string
	MediaType     string
	Tag           string
	PushTimestamp time.Time
	PullTimestamp time.Time
	RetainedBy    string
}

type PolicyManager interface {
	HasDeleteReferrer(repo string) bool
	HasDeleteUntagged(repo string) bool
	HasTagRetention(repo string) bool
	GetRetainedTags(repoMeta mTypes.RepoMeta, index ispec.Index) []string
}

type Rule interface {
	Name() string
	Perform(candidates []*Candidate) []*Candidate
}
