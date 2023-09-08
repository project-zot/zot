package mocks

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
)

type SecretsManagerMock struct {
	CreateSecretFn func(ctx context.Context, params *secretsmanager.CreateSecretInput,
		optFns ...func(*secretsmanager.Options)) (*secretsmanager.CreateSecretOutput, error)
	DeleteSecretFn func(ctx context.Context, params *secretsmanager.DeleteSecretInput,
		optFns ...func(*secretsmanager.Options)) (*secretsmanager.DeleteSecretOutput, error)
	ListSecretsFn func(ctx context.Context, params *secretsmanager.ListSecretsInput,
		optFns ...func(*secretsmanager.Options)) (*secretsmanager.ListSecretsOutput, error)
}

func (secretsManagerMock SecretsManagerMock) CreateSecret(ctx context.Context, params *secretsmanager.CreateSecretInput,
	optFns ...func(*secretsmanager.Options),
) (*secretsmanager.CreateSecretOutput, error) {
	if secretsManagerMock.CreateSecretFn != nil {
		return secretsManagerMock.CreateSecretFn(ctx, params, optFns...)
	}

	return &secretsmanager.CreateSecretOutput{}, nil
}

func (secretsManagerMock SecretsManagerMock) DeleteSecret(ctx context.Context, params *secretsmanager.DeleteSecretInput,
	optFns ...func(*secretsmanager.Options),
) (*secretsmanager.DeleteSecretOutput, error) {
	if secretsManagerMock.DeleteSecretFn != nil {
		return secretsManagerMock.DeleteSecretFn(ctx, params, optFns...)
	}

	return &secretsmanager.DeleteSecretOutput{}, nil
}

func (secretsManagerMock SecretsManagerMock) ListSecrets(ctx context.Context, params *secretsmanager.ListSecretsInput,
	optFns ...func(*secretsmanager.Options),
) (*secretsmanager.ListSecretsOutput, error) {
	if secretsManagerMock.ListSecretsFn != nil {
		return secretsManagerMock.ListSecretsFn(ctx, params, optFns...)
	}

	return &secretsmanager.ListSecretsOutput{}, nil
}

type SecretsManagerCacheMock struct {
	GetSecretStringFn func(string) (string, error)
}

func (secretsManagerCacheMock SecretsManagerCacheMock) GetSecretString(secretID string) (string, error) {
	if secretsManagerCacheMock.GetSecretStringFn != nil {
		return secretsManagerCacheMock.GetSecretStringFn(secretID)
	}

	return "", nil
}
