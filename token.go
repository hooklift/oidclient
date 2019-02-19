package oidclient

import (
	"context"
	"errors"
)

// Tokens holds the response received by the identity provider when exchanging authorization grant codes for tokens.
// Users are encouraged to store these tokens and encrypt them at rest. ID and access tokens usually have a short life, ~4 hours,
// refresh tokens do not have an expiration time, they must be secured appropiately.
type Tokens struct {
	IDToken      string `json:"id_token,omitempty"`
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	Error        error  `json:"-"`
}

// tokenOptions holds internal options for generating tokens.
type tokenOptions struct {
	state string
	nonce string
}

// TokenOption represents an option for retrieving tokens.
type TokenOption func(*tokenOptions) error

// State sets a countermeasure for CSRF attacks.
func State(value string) TokenOption {
	return func(o *tokenOptions) error {
		o.state = value
		return nil
	}
}

// Nonce sets random value as countermeasure for replay attacks. It must have good entropy.
func Nonce(value string) TokenOption {
	return func(o *tokenOptions) error {
		o.nonce = value
		return nil
	}
}

// Loopback spins up HTTP server listening in 127.0.0.1 and an unprivileged random port. It receives OIDC provider's redirections,
// containing authorization code, state or errors. Exchanging authorization code for tokens and returning them through the tokensChan
// channel. This function exists to make it easier for users implementing native oidc/oauth2 applications such as CLIs or Electron apps.
func (p *Provider) Loopback(ctx context.Context, tokensChan <-chan Tokens, opts ...TokenOption) (string, error) {
	// Send client credentials using client_secret_basic only
	return "", errors.New("not implemented yet")
}

// Tokens retrives tokens from OpenID Connect provider using a previously acquired authorization grant code.
// The URI parameter is the full URI through which the OpenID Connect provider is sending the authorization grant code and state.
func (p *Provider) Tokens(ctx context.Context, uri string, opts ...TokenOption) (*Tokens, error) {
	// Send client credentials using client_secret_basic only
	return nil, nil
}
