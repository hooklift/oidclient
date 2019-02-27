package store

import "context"

type LocalKeychain struct{}

func (k *LocalKeychain) Set(ctx context.Context, tokens string) error {
	return nil
}

func (k *LocalKeychain) Get(ctx context.Context, subjectID string) (string, error) {
	return "", nil
}

func (k *LocalKeychain) Delete(ctx context.Context, subjectID string) error {
	return nil
}
