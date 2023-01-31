package userdb

import (
	"time"

	"golang.org/x/oauth2"
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

	GetUserAPIKeyInfo(hashedKey string) (UserInfo, error)
	AddUserAPIKey(hashedKey string, email string, apiKeyDetails *ApiKeyDetails) error
	DeleteUserAPIKey(id string, email string) error

	
	PatchDB() error
}

type UserInfo struct {
	Email string
}

type Tokens struct {
	IDToken    string
	AuthzToken *oauth2.Token
}

type UserProfile struct {
	Tokens  Tokens
	Info    UserInfo
	ApiKeys map[string]ApiKeyDetails
}

type ApiKeyDetails struct {
	Created_at   time.Time
	Creator_ua   string
	Generated_by string
	Last_used    time.Time
	Label        string
	Scopes       []string
	UUID         string
}
