package store

import "context"

type LocalFilesystem struct{}

func (k *LocalFilesystem) Set(ctx context.Context, tokens string) error {
	return nil
}

func (k *LocalFilesystem) Get(ctx context.Context, subjectID string) (string, error) {
	return "", nil
}

func (k *LocalFilesystem) Delete(ctx context.Context, subjectID string) error {
	return nil
}
