package store

import (
	"context"
	"sync"
)

// Memory implements memory store for tokens.
type Memory struct {
	sync.RWMutex
}

func (m *Memory) Set(ctx context.Context, tokens string) error {
	return nil
}

func (m *Memory) Get(ctx context.Context, subjectID string) (string, error) {
	return "", nil
}

func (m *Memory) Delete(ctx context.Context, subjectID string) error {
	return nil
}
