package cel

import (
	"context"
	"fmt"
	"slices"
	"strings"

	zerr "zotregistry.dev/zot/v2/errors"
	"zotregistry.dev/zot/v2/pkg/api/config"
)

// defaultUsernameExpr is the default CEL expression for extracting the username from OIDC claims.
const defaultUsernameExpr = "claims.iss + '/' + claims.sub"

// getAudiencesExpr returns the CEL expression for extracting the audiences from OIDC claims.
//
//nolint:gochecknoglobals
var getAudiencesExpr = func() func() *Expression {
	var expr *Expression

	return func() *Expression {
		if expr != nil {
			return expr
		}

		var err error

		expr, err = NewExpression("claims.aud")
		if err != nil {
			panic(fmt.Sprintf("failed to parse default audiences expression: %v", err))
		}

		return expr
	}
}()

// ClaimResult holds the result of processing OIDC claims.
type ClaimResult struct {
	Username string
	Groups   []string
}

// ClaimProcessor processes OIDC claims using CEL expressions.
// It validates and maps claims to Zot identities.
type ClaimProcessor struct {
	variables   []variable
	validations []validation
	audiences   []string
	username    *Expression
	groups      *Expression
}

// variable contains a compiled CEL expression for extracting
// a variable from OIDC claims.
type variable struct {
	name string
	expr *Expression
}

// validation contains a compiled CEL expression for validating
// OIDC claims.
type validation struct {
	expr *Expression
	msg  string
}

// NewClaimProcessor creates a new ClaimProcessor.
func NewClaimProcessor(audiences []string, conf *config.CELClaimValidationAndMapping) (*ClaimProcessor, error) {
	// Sanitize and validate audiences.
	audiences = slices.Clone(audiences)
	if len(audiences) == 0 {
		return nil, zerr.ErrOIDCNoAudiences
	}

	for i := range audiences {
		audiences[i] = strings.TrimSpace(audiences[i])
		if audiences[i] == "" {
			return nil, fmt.Errorf("audience[%d]: %w", i, zerr.ErrOIDCEmptyAudience)
		}
	}

	// Apply defaults.
	if conf == nil {
		conf = &config.CELClaimValidationAndMapping{
			Username: defaultUsernameExpr,
		}
	}
	if conf.Username == "" {
		conf.Username = defaultUsernameExpr
	}

	// Parse variable expressions.
	variables := make([]variable, 0, len(conf.Variables))

	for i, varConf := range conf.Variables {
		if varConf.Name == "" {
			return nil, fmt.Errorf("variable[%d]: %w", i, zerr.ErrOIDCEmptyVariableName)
		}

		expr, err := NewExpression(varConf.Expression)
		if err != nil {
			return nil, fmt.Errorf("failed to parse CEL expression for variable[%d] (name: %s): %w",
				i, varConf.Name, err)
		}

		variables = append(variables, variable{
			name: varConf.Name,
			expr: expr,
		})
	}

	// Parse validation expressions.
	validations := make([]validation, 0, len(conf.Validations))

	for i, valConf := range conf.Validations {
		if valConf.Message == "" {
			return nil, fmt.Errorf("validation[%d]: %w", i, zerr.ErrOIDCEmptyValidationMsg)
		}

		expr, err := NewExpression(valConf.Expression)
		if err != nil {
			return nil, fmt.Errorf("failed to parse CEL expression for validation[%d]: %w", i, err)
		}

		validations = append(validations, validation{
			expr: expr,
			msg:  valConf.Message,
		})
	}

	// Parse username expression.
	username, err := NewExpression(conf.Username)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CEL expression for username: %w", err)
	}

	// Parse groups expression if provided.
	var groups *Expression
	if conf.Groups != "" {
		groups, err = NewExpression(conf.Groups)
		if err != nil {
			return nil, fmt.Errorf("failed to parse CEL expression for groups: %w", err)
		}
	}

	return &ClaimProcessor{
		variables:   variables,
		validations: validations,
		audiences:   audiences,
		username:    username,
		groups:      groups,
	}, nil
}

// Process processes the OIDC claims applying all validations, including CEL expressions
// and audiences, and returns the mapped username and groups.
func (c *ClaimProcessor) Process(ctx context.Context, claims map[string]any) (*ClaimResult, error) {
	// First, validate the audience.
	if err := c.validateAudience(ctx, claims); err != nil {
		return nil, err
	}

	// Next, we extract variables. The process is iterative:
	// variable expressions can refer to both the claims and
	// previously extracted variables.
	vars := make(map[string]any)
	data := map[string]any{
		"vars":   vars,
		"claims": claims,
	}

	for i := range c.variables {
		celVar := c.variables[i]

		val, err := celVar.expr.Evaluate(ctx, data)
		if err != nil {
			return nil, fmt.Errorf("failed to evaluate variable '%s': %w", celVar.name, err)
		}

		vars[celVar.name] = val
	}

	// Next, we run validations. If any validation fails, we
	// return an error. Validations can refer to both claims
	// and the extracted variables.
	for i := range c.validations {
		celVal := c.validations[i]

		val, err := celVal.expr.EvaluateBoolean(ctx, data)
		if err != nil {
			return nil, fmt.Errorf("failed to evaluate validation expression: %w", err)
		}

		if !val {
			return nil, fmt.Errorf("%w: %s", zerr.ErrOIDCValidationFailed, celVal.msg)
		}
	}

	// Next, we extract the username. It can refer to both
	// claims and the extracted variables.
	username, err := c.username.EvaluateString(ctx, data)
	if err != nil {
		return nil, fmt.Errorf("failed to evaluate username expression: %w", err)
	}

	// Finally, we extract groups if a groups expression is provided.
	// It can refer to both claims and the extracted variables.
	var groups []string
	if c.groups != nil {
		groups, err = c.groups.EvaluateStringSlice(ctx, data)
		if err != nil {
			return nil, fmt.Errorf("failed to evaluate groups expression: %w", err)
		}
	}

	return &ClaimResult{
		Username: username,
		Groups:   groups,
	}, nil
}

// validateAudience checks if the provided audiences contain at least one of the expected audiences.
func (c *ClaimProcessor) validateAudience(ctx context.Context, claims map[string]any) error {
	audiences, err := getAudiencesExpr().EvaluateStringSlice(ctx, map[string]any{"claims": claims})
	if err != nil {
		return fmt.Errorf("failed to extract audiences: %w", err)
	}

	audiencesMap := make(map[string]struct{}, len(audiences))

	for _, aud := range audiences {
		audiencesMap[aud] = struct{}{}
	}

	hasAudience := false

	for _, aud := range c.audiences {
		if _, ok := audiencesMap[aud]; ok {
			hasAudience = true

			break
		}
	}

	if !hasAudience {
		return fmt.Errorf("%w: token=%v, expected=%v", zerr.ErrOIDCAudienceMismatch, audiences, c.audiences)
	}

	return nil
}
