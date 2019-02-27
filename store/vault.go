package store

import (
	"context"
)

type Vault struct {
}

func (v *Vault) Set(ctx context.Context, tokens string) error {
	return nil
}

func (v *Vault) Get(ctx context.Context, subjectID string) (string, error) {
	return "", nil
}

func (v *Vault) Delete(ctx context.Context, subjectID string) error {
	return nil
}
