package api

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"zotregistry.dev/zot/v2/pkg/api/config"
	"zotregistry.dev/zot/v2/pkg/api/constants"
	"zotregistry.dev/zot/v2/pkg/log"
)

func TestPolicyExpiresAt(t *testing.T) {
	t.Parallel()

	past := time.Now().Add(-time.Hour)
	future := time.Now().Add(time.Hour)

	makeAC := func(policies []config.Policy, groups config.Groups) *AccessController {
		return &AccessController{
			Config: &config.AccessControlConfig{
				Repositories: config.Repositories{
					"**": config.PolicyGroup{Policies: policies},
				},
				Groups: groups,
			},
			Log: log.NewLogger("debug", ""),
		}
	}

	t.Run("user policy without ExpiresAt is permitted", func(t *testing.T) {
		t.Parallel()

		ac := makeAC([]config.Policy{{
			Users:   []string{"alice"},
			Actions: []string{constants.ReadPermission},
		}}, nil)

		assert.True(t, ac.isPermitted(nil, "alice", constants.ReadPermission,
			ac.Config.Repositories["**"]))
	})

	t.Run("user policy with future ExpiresAt is permitted", func(t *testing.T) {
		t.Parallel()

		ac := makeAC([]config.Policy{{
			Users:     []string{"alice"},
			Actions:   []string{constants.ReadPermission},
			ExpiresAt: &future,
		}}, nil)

		assert.True(t, ac.isPermitted(nil, "alice", constants.ReadPermission,
			ac.Config.Repositories["**"]))
	})

	t.Run("user policy with past ExpiresAt is denied", func(t *testing.T) {
		t.Parallel()

		ac := makeAC([]config.Policy{{
			Users:     []string{"alice"},
			Actions:   []string{constants.ReadPermission},
			ExpiresAt: &past,
		}}, nil)

		assert.False(t, ac.isPermitted(nil, "alice", constants.ReadPermission,
			ac.Config.Repositories["**"]))
	})

	t.Run("group policy with past ExpiresAt is denied", func(t *testing.T) {
		t.Parallel()

		ac := makeAC([]config.Policy{{
			Groups:    []string{"devs"},
			Actions:   []string{constants.ReadPermission},
			ExpiresAt: &past,
		}}, config.Groups{"devs": config.Group{Users: []string{"alice"}}})

		assert.False(t, ac.isPermitted([]string{"devs"}, "alice", constants.ReadPermission,
			ac.Config.Repositories["**"]))
	})

	t.Run("group policy with future ExpiresAt is permitted", func(t *testing.T) {
		t.Parallel()

		ac := makeAC([]config.Policy{{
			Groups:    []string{"devs"},
			Actions:   []string{constants.ReadPermission},
			ExpiresAt: &future,
		}}, config.Groups{"devs": config.Group{Users: []string{"alice"}}})

		assert.True(t, ac.isPermitted([]string{"devs"}, "alice", constants.ReadPermission,
			ac.Config.Repositories["**"]))
	})

	t.Run("expired entry does not contribute glob patterns", func(t *testing.T) {
		t.Parallel()

		ac := makeAC([]config.Policy{{
			Users:     []string{"alice"},
			Actions:   []string{constants.ReadPermission},
			ExpiresAt: &past,
		}}, nil)

		patterns := ac.getGlobPatterns("alice", nil, constants.ReadPermission)
		assert.False(t, patterns["**"])
	})

	t.Run("non-expired entry contributes glob patterns", func(t *testing.T) {
		t.Parallel()

		ac := makeAC([]config.Policy{{
			Users:     []string{"alice"},
			Actions:   []string{constants.ReadPermission},
			ExpiresAt: &future,
		}}, nil)

		patterns := ac.getGlobPatterns("alice", nil, constants.ReadPermission)
		assert.True(t, patterns["**"])
	})

	t.Run("expiry on one entry does not affect another", func(t *testing.T) {
		t.Parallel()

		ac := makeAC([]config.Policy{
			{
				Users:     []string{"alice"},
				Actions:   []string{constants.ReadPermission},
				ExpiresAt: &past,
			},
			{
				Users:   []string{"alice"},
				Actions: []string{constants.ReadPermission},
			},
		}, nil)

		assert.True(t, ac.isPermitted(nil, "alice", constants.ReadPermission,
			ac.Config.Repositories["**"]))
	})
}
