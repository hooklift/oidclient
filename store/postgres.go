package store

import "context"

type Postgres struct{}

func (p *Postgres) Set(ctx context.Context, tokens string) error {
	return nil
}

func (p *Postgres) Get(ctx context.Context, subjectID string) (string, error) {
	return "", nil
}

func (p *Postgres) Delete(ctx context.Context, subjectID string) error {
	return nil
}
