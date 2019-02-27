package store

import "context"

type Redis struct {
	Address  string
	Password string
	DB       int
}

func (r *Redis) Set(ctx context.Context, tokens string) error {
	return nil
}

func (r *Redis) Get(ctx context.Context, subjectID string) (string, error) {
	return "", nil
}

func (r *Redis) Delete(ctx context.Context, subjectID string) error {
	return nil
}
