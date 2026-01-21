package cel_test

import (
	"context"
	"testing"

	. "github.com/onsi/gomega"

	"zotregistry.dev/zot/v2/pkg/api/config"
	"zotregistry.dev/zot/v2/pkg/cel"
)

func TestNewClaimProcessor(t *testing.T) {
	t.Parallel()

	for _, testCase := range []struct {
		name      string
		audiences []string
		conf      *config.CELClaimValidationAndMapping
		err       string
	}{
		{
			name:      "nil config uses defaults",
			audiences: []string{"my-audience"},
			conf:      nil,
		},
		{
			name:      "empty config uses defaults",
			audiences: []string{"my-audience"},
			conf:      &config.CELClaimValidationAndMapping{},
		},
		{
			name:      "custom username expression",
			audiences: []string{"my-audience"},
			conf: &config.CELClaimValidationAndMapping{
				Username: "claims.email",
			},
		},
		{
			name:      "custom groups expression",
			audiences: []string{"my-audience"},
			conf: &config.CELClaimValidationAndMapping{
				Groups: "claims.groups",
			},
		},
		{
			name:      "multiple audiences",
			audiences: []string{"aud1", "aud2", "aud3"},
			conf:      nil,
		},
		{
			name:      "with variables",
			audiences: []string{"my-audience"},
			conf: &config.CELClaimValidationAndMapping{
				Variables: []config.CELVariable{
					{Name: "org", Expression: "claims.org"},
					{Name: "team", Expression: "claims.team"},
				},
			},
		},
		{
			name:      "with validations",
			audiences: []string{"my-audience"},
			conf: &config.CELClaimValidationAndMapping{
				Validations: []config.CELValidation{
					{Expression: "claims.email_verified == true", Message: "email must be verified"},
				},
			},
		},
		{
			name:      "empty audiences",
			audiences: []string{},
			conf:      nil,
			err:       "at least one audience must be specified",
		},
		{
			name:      "nil audiences",
			audiences: nil,
			conf:      nil,
			err:       "at least one audience must be specified",
		},
		{
			name:      "empty audience in list",
			audiences: []string{"valid", ""},
			conf:      nil,
			err:       "audience[1]:",
		},
		{
			name:      "variable with empty name",
			audiences: []string{"my-audience"},
			conf: &config.CELClaimValidationAndMapping{
				Variables: []config.CELVariable{
					{Name: "", Expression: "claims.org"},
				},
			},
			err: "variable[0]:",
		},
		{
			name:      "variable with invalid expression",
			audiences: []string{"my-audience"},
			conf: &config.CELClaimValidationAndMapping{
				Variables: []config.CELVariable{
					{Name: "org", Expression: "claims."},
				},
			},
			err: "failed to parse CEL expression for variable[0] (name: org)",
		},
		{
			name:      "validation with empty message",
			audiences: []string{"my-audience"},
			conf: &config.CELClaimValidationAndMapping{
				Validations: []config.CELValidation{
					{Expression: "true", Message: ""},
				},
			},
			err: "validation[0]:",
		},
		{
			name:      "validation with invalid expression",
			audiences: []string{"my-audience"},
			conf: &config.CELClaimValidationAndMapping{
				Validations: []config.CELValidation{
					{Expression: "claims.", Message: "some error"},
				},
			},
			err: "failed to parse CEL expression for validation[0]",
		},
		{
			name:      "invalid username expression",
			audiences: []string{"my-audience"},
			conf: &config.CELClaimValidationAndMapping{
				Username: "claims.",
			},
			err: "failed to parse CEL expression for username",
		},
		{
			name:      "invalid groups expression",
			audiences: []string{"my-audience"},
			conf: &config.CELClaimValidationAndMapping{
				Groups: "claims.",
			},
			err: "failed to parse CEL expression for groups",
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			gomega := NewWithT(t)

			processor, err := cel.NewClaimProcessor(testCase.audiences, testCase.conf)

			if testCase.err != "" {
				gomega.Expect(err).To(HaveOccurred())
				gomega.Expect(err.Error()).To(ContainSubstring(testCase.err))
				gomega.Expect(processor).To(BeNil())
			} else {
				gomega.Expect(err).NotTo(HaveOccurred())
				gomega.Expect(processor).NotTo(BeNil())
			}
		})
	}
}

func TestClaimProcessor_Process(t *testing.T) {
	t.Parallel()

	for _, testCase := range []struct {
		name      string
		audiences []string
		conf      *config.CELClaimValidationAndMapping
		claims    map[string]any
		username  string
		groups    []string
		err       string
	}{
		{
			name:      "default config extracts iss/sub as username",
			audiences: []string{"my-audience"},
			conf:      nil,
			claims: map[string]any{
				"iss": "https://issuer.example.com",
				"sub": "user123",
				"aud": []string{"my-audience"},
			},
			username: "https://issuer.example.com/user123",
			groups:   nil,
		},
		{
			name:      "custom username from email claim",
			audiences: []string{"my-audience"},
			conf: &config.CELClaimValidationAndMapping{
				Username: "claims.email",
			},
			claims: map[string]any{
				"sub":   "user123",
				"email": "user@example.com",
				"aud":   []string{"my-audience"},
			},
			username: "user@example.com",
			groups:   nil,
		},
		{
			name:      "extract groups from claims",
			audiences: []string{"my-audience"},
			conf: &config.CELClaimValidationAndMapping{
				Groups: "claims.groups",
			},
			claims: map[string]any{
				"iss":    "https://issuer.example.com",
				"sub":    "user123",
				"groups": []string{"admin", "developers"},
				"aud":    []string{"my-audience"},
			},
			username: "https://issuer.example.com/user123",
			groups:   []string{"admin", "developers"},
		},
		{
			name:      "extract groups from any slice",
			audiences: []string{"my-audience"},
			conf: &config.CELClaimValidationAndMapping{
				Groups: "claims.groups",
			},
			claims: map[string]any{
				"iss":    "https://issuer.example.com",
				"sub":    "user123",
				"groups": []any{"admin", "developers"},
				"aud":    []string{"my-audience"},
			},
			username: "https://issuer.example.com/user123",
			groups:   []string{"admin", "developers"},
		},
		{
			name:      "audience validation - single audience match",
			audiences: []string{"my-audience"},
			conf:      nil,
			claims: map[string]any{
				"iss": "https://issuer.example.com",
				"sub": "user123",
				"aud": []string{"my-audience"},
			},
			username: "https://issuer.example.com/user123",
		},
		{
			name:      "audience validation - multiple audiences, one matches",
			audiences: []string{"aud1", "aud2"},
			conf:      nil,
			claims: map[string]any{
				"iss": "https://issuer.example.com",
				"sub": "user123",
				"aud": []string{"aud2", "other"},
			},
			username: "https://issuer.example.com/user123",
		},
		{
			name:      "audience validation - token has multiple, config has one",
			audiences: []string{"aud2"},
			conf:      nil,
			claims: map[string]any{
				"iss": "https://issuer.example.com",
				"sub": "user123",
				"aud": []string{"aud1", "aud2", "aud3"},
			},
			username: "https://issuer.example.com/user123",
		},
		{
			name:      "audience validation fails - no match",
			audiences: []string{"expected-aud"},
			conf:      nil,
			claims: map[string]any{
				"sub": "user123",
				"aud": []string{"other-aud"},
			},
			err: "token audience [other-aud] does not match any of the expected audiences [expected-aud]",
		},
		{
			name:      "audience validation fails - empty token audience",
			audiences: []string{"expected-aud"},
			conf:      nil,
			claims: map[string]any{
				"sub": "user123",
				"aud": []string{},
			},
			err: "does not match any of the expected audiences",
		},
		{
			name:      "variables can be used in username expression",
			audiences: []string{"my-audience"},
			conf: &config.CELClaimValidationAndMapping{
				Variables: []config.CELVariable{
					{Name: "prefix", Expression: "'user-'"},
				},
				Username: "vars.prefix + claims.sub",
			},
			claims: map[string]any{
				"sub": "123",
				"aud": []string{"my-audience"},
			},
			username: "user-123",
		},
		{
			name:      "variables can reference claims",
			audiences: []string{"my-audience"},
			conf: &config.CELClaimValidationAndMapping{
				Variables: []config.CELVariable{
					{Name: "domain", Expression: "claims.email.split('@')[1]"},
				},
				Username: "vars.domain + '/' + claims.sub",
			},
			claims: map[string]any{
				"sub":   "user123",
				"email": "user@example.com",
				"aud":   []string{"my-audience"},
			},
			username: "example.com/user123",
		},
		{
			name:      "variables can reference other variables",
			audiences: []string{"my-audience"},
			conf: &config.CELClaimValidationAndMapping{
				Variables: []config.CELVariable{
					{Name: "org", Expression: "claims.org"},
					{Name: "fullOrg", Expression: "'org-' + vars.org"},
				},
				Username: "vars.fullOrg + '/' + claims.sub",
			},
			claims: map[string]any{
				"sub": "user123",
				"org": "myorg",
				"aud": []string{"my-audience"},
			},
			username: "org-myorg/user123",
		},
		{
			name:      "validation passes",
			audiences: []string{"my-audience"},
			conf: &config.CELClaimValidationAndMapping{
				Validations: []config.CELValidation{
					{Expression: "claims.email_verified == true", Message: "email must be verified"},
				},
			},
			claims: map[string]any{
				"iss":            "https://issuer.example.com",
				"sub":            "user123",
				"email_verified": true,
				"aud":            []string{"my-audience"},
			},
			username: "https://issuer.example.com/user123",
		},
		{
			name:      "validation fails",
			audiences: []string{"my-audience"},
			conf: &config.CELClaimValidationAndMapping{
				Validations: []config.CELValidation{
					{Expression: "claims.email_verified == true", Message: "email must be verified"},
				},
			},
			claims: map[string]any{
				"sub":            "user123",
				"email_verified": false,
				"aud":            []string{"my-audience"},
			},
			err: "OIDC claim validation failed: email must be verified",
		},
		{
			name:      "multiple validations all pass",
			audiences: []string{"my-audience"},
			conf: &config.CELClaimValidationAndMapping{
				Validations: []config.CELValidation{
					{Expression: "claims.email_verified == true", Message: "email must be verified"},
					{Expression: "claims.org == 'myorg'", Message: "must be in myorg"},
				},
			},
			claims: map[string]any{
				"iss":            "https://issuer.example.com",
				"sub":            "user123",
				"email_verified": true,
				"org":            "myorg",
				"aud":            []string{"my-audience"},
			},
			username: "https://issuer.example.com/user123",
		},
		{
			name:      "multiple validations - second fails",
			audiences: []string{"my-audience"},
			conf: &config.CELClaimValidationAndMapping{
				Validations: []config.CELValidation{
					{Expression: "claims.email_verified == true", Message: "email must be verified"},
					{Expression: "claims.org == 'myorg'", Message: "must be in myorg"},
				},
			},
			claims: map[string]any{
				"sub":            "user123",
				"email_verified": true,
				"org":            "otherorg",
				"aud":            []string{"my-audience"},
			},
			err: "OIDC claim validation failed: must be in myorg",
		},
		{
			name:      "validation can use variables",
			audiences: []string{"my-audience"},
			conf: &config.CELClaimValidationAndMapping{
				Variables: []config.CELVariable{
					{Name: "allowedOrgs", Expression: "['org1', 'org2', 'org3']"},
				},
				Validations: []config.CELValidation{
					{Expression: "claims.org in vars.allowedOrgs", Message: "organization not allowed"},
				},
			},
			claims: map[string]any{
				"iss": "https://issuer.example.com",
				"sub": "user123",
				"org": "org2",
				"aud": []string{"my-audience"},
			},
			username: "https://issuer.example.com/user123",
		},
		{
			name:      "validation using variables fails",
			audiences: []string{"my-audience"},
			conf: &config.CELClaimValidationAndMapping{
				Variables: []config.CELVariable{
					{Name: "allowedOrgs", Expression: "['org1', 'org2', 'org3']"},
				},
				Validations: []config.CELValidation{
					{Expression: "claims.org in vars.allowedOrgs", Message: "organization not allowed"},
				},
			},
			claims: map[string]any{
				"sub": "user123",
				"org": "org4",
				"aud": []string{"my-audience"},
			},
			err: "OIDC claim validation failed: organization not allowed",
		},
		{
			name:      "username expression evaluation error",
			audiences: []string{"my-audience"},
			conf: &config.CELClaimValidationAndMapping{
				Username: "claims.nonexistent",
			},
			claims: map[string]any{
				"sub": "user123",
				"aud": []string{"my-audience"},
			},
			err: "failed to evaluate username expression",
		},
		{
			name:      "groups expression evaluation error",
			audiences: []string{"my-audience"},
			conf: &config.CELClaimValidationAndMapping{
				Username: "claims.sub",
				Groups:   "claims.nonexistent",
			},
			claims: map[string]any{
				"sub": "user123",
				"aud": []string{"my-audience"},
			},
			err: "failed to evaluate groups expression",
		},
		{
			name:      "variable expression evaluation error",
			audiences: []string{"my-audience"},
			conf: &config.CELClaimValidationAndMapping{
				Variables: []config.CELVariable{
					{Name: "bad", Expression: "claims.nonexistent"},
				},
			},
			claims: map[string]any{
				"sub": "user123",
				"aud": []string{"my-audience"},
			},
			err: "failed to evaluate variable 'bad'",
		},
		{
			name:      "complex real-world scenario - GitHub Actions OIDC",
			audiences: []string{"zot-registry"},
			conf: &config.CELClaimValidationAndMapping{
				Variables: []config.CELVariable{
					{Name: "repo", Expression: "claims.repository"},
					{Name: "owner", Expression: "claims.repository_owner"},
				},
				Validations: []config.CELValidation{
					{Expression: "vars.owner == 'myorg'", Message: "only myorg repositories allowed"},
					{Expression: "claims.ref.startsWith('refs/heads/')", Message: "must be a branch ref"},
				},
				Username: "vars.repo",
				Groups:   "['github-actions', 'ci']",
			},
			claims: map[string]any{
				"sub":              "repo:myorg/myrepo:ref:refs/heads/main",
				"repository":       "myorg/myrepo",
				"repository_owner": "myorg",
				"ref":              "refs/heads/main",
				"aud":              []string{"zot-registry"},
			},
			username: "myorg/myrepo",
			groups:   []string{"github-actions", "ci"},
		},
		{
			name:      "complex real-world scenario - Kubernetes service account",
			audiences: []string{"zot"},
			conf: &config.CELClaimValidationAndMapping{
				Variables: []config.CELVariable{
					{Name: "ns", Expression: "claims['kubernetes.io/serviceaccount/namespace']"},
					{Name: "sa", Expression: "claims['kubernetes.io/serviceaccount/service-account.name']"},
				},
				Validations: []config.CELValidation{
					{Expression: "vars.ns in ['production', 'staging']", Message: "namespace not allowed"},
				},
				Username: "vars.ns + ':' + vars.sa",
				Groups:   "['k8s-workloads']",
			},
			claims: map[string]any{
				"sub":                                    "system:serviceaccount:production:my-app",
				"kubernetes.io/serviceaccount/namespace": "production",
				"kubernetes.io/serviceaccount/service-account.name": "my-app",
				"aud": []string{"zot"},
			},
			username: "production:my-app",
			groups:   []string{"k8s-workloads"},
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			gomega := NewWithT(t)

			processor, err := cel.NewClaimProcessor(testCase.audiences, testCase.conf)
			gomega.Expect(err).NotTo(HaveOccurred())

			result, err := processor.Process(context.Background(), testCase.claims)

			if testCase.err != "" {
				gomega.Expect(err).To(HaveOccurred())
				gomega.Expect(err.Error()).To(ContainSubstring(testCase.err))
				gomega.Expect(result).To(BeNil())
			} else {
				gomega.Expect(err).NotTo(HaveOccurred())
				gomega.Expect(result).NotTo(BeNil())
				gomega.Expect(result.Username).To(Equal(testCase.username))
				gomega.Expect(result.Groups).To(Equal(testCase.groups))
			}
		})
	}
}

func TestClaimProcessor_Process_AudienceEdgeCases(t *testing.T) {
	t.Parallel()

	for _, testCase := range []struct {
		name      string
		audiences []string
		claims    map[string]any
		err       string
	}{
		{
			name:      "audience as single string converted to slice",
			audiences: []string{"my-audience"},
			claims: map[string]any{
				"sub": "user123",
				"aud": "my-audience",
			},
			err: "failed to extract audiences",
		},
		{
			name:      "missing aud claim",
			audiences: []string{"my-audience"},
			claims: map[string]any{
				"sub": "user123",
			},
			err: "failed to extract audiences",
		},
		{
			name:      "aud claim with wrong type",
			audiences: []string{"my-audience"},
			claims: map[string]any{
				"sub": "user123",
				"aud": 12345,
			},
			err: "failed to extract audiences",
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			gomega := NewWithT(t)

			processor, err := cel.NewClaimProcessor(testCase.audiences, nil)
			gomega.Expect(err).NotTo(HaveOccurred())

			result, err := processor.Process(context.Background(), testCase.claims)

			gomega.Expect(err).To(HaveOccurred())
			gomega.Expect(err.Error()).To(ContainSubstring(testCase.err))
			gomega.Expect(result).To(BeNil())
		})
	}
}
