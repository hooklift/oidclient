package oidclient

import (
	"context"
	"errors"
	"net/http"
)

// tokenOptions ...
type tokenOptions struct {
	state string
	nonce string
}

// TokenOption ...
type TokenOption func(*tokenOptions) error

func State(value string) TokenOption {
	return func(o *tokenOptions) error {
		o.state = value
		return nil
	}
}

func Nonce(value string) TokenOption {
	return func(o *tokenOptions) error {
		o.nonce = value
		return nil
	}
}

// Loopback spins up a HTTP server listening in 127.0.0.1 to receive OIDC provider's redirect with authorization code, state or errors.
// Exchanges authorization code for tokens and returns them in the tokensChan.
func (p *Provider) Loopback(ctx context.Context, tokensChan chan<- Tokens, opts ...TokenOption) (string, error) {

	return "", errors.New("not implemented yet")
}

// Tokens retrives tokens from OpenID Connect provider using a previously acquired authorization grant code.
func (p *Provider) Tokens(ctx context.Context, callbackURL *http.Request) (*Tokens, error) {
	return nil, nil
}
