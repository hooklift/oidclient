package store

import "context"

type Memcached struct{}

func (m *Memcached) Set(ctx context.Context, tokens string) error {
	return nil
}

func (m *Memcached) Get(ctx context.Context, subjectID string) (string, error) {
	return "", nil
}

func (m *Memcached) Delete(ctx context.Context, subjectID string) error {
	return nil
}
