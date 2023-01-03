package userdb

import (
	"time"
)

const (
	UserSecurityBucket = "UserSecurity"
	UserAPIKeysBucket  = "UserAPIKeys"
	VersionBucket      = "Version"
)

type UserSecurityDB interface {
	GetUserProfile(email string) (UserProfile, error)
	SetUserProfile(email string, userProfile UserProfile) error
	DeleteUserProfile(email string) error

	GetUserAPIKeyInfo(hashedKey string) (email string, err error)
	AddUserAPIKey(hashedKey string, email string, apiKeyDetails *APIKeyDetails) error
	DeleteUserAPIKey(id string, email string) error

	PatchDB() error
}

type UserProfile struct {
	Groups  []string
	APIKeys map[string]APIKeyDetails
}

type APIKeyDetails struct {
	CreatedAt   time.Time `json:"createdAt"`
	CreatorUA   string    `json:"creatorUa"`
	GeneratedBy string    `json:"generatedBy"`
	LastUsed    time.Time `json:"lastUsed"`
	Label       string    `json:"label"`
	Scopes      []string  `json:"scopes"`
	UUID        string    `json:"uuid"`
}
