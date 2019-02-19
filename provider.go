// Package oidclient implements a strict and secure OpenID Connect client.
// It does not forgive or work around broken OpenID Connect or OAuth2 providers.
// Supports verifying RSA256 and ED25519 signed ID tokens.
// Only implements authorization code flow.
package oidclient

import (
	"context"
	"errors"
)

// TokenStore defines an interface to store and retrieve tokens. Encryption at rest is highly suggested.
type TokenStore interface {
	Get(ctx context.Context, id string) (Tokens, error)
	Save(ctx context.Context, tokens *Tokens) error
}

// ErrNotSupported is returned when the OpenID Connect provider does not support a specific OIDC capability.
var ErrNotSupported = errors.New("not supported by provider")

// providerOptions ...
type providerOptions struct {
	providerURL   string
	clientID      string
	clientSecret  string
	skipTLSVerify bool
}

// ProviderOption ...
type ProviderOption func(*providerOptions) error

// ClientID...
func ClientID(id string) ProviderOption {
	return func(o *providerOptions) error {
		o.clientID = id
		return nil
	}
}

// ClientSecret...
func ClientSecret(secret string) ProviderOption {
	return func(o *providerOptions) error {
		o.clientSecret = secret
		return nil
	}
}

// SkipTLSVerify...
func SkipTLSVerify() ProviderOption {
	return func(o *providerOptions) error {
		o.skipTLSVerify = true
		return nil
	}
}

// UserInfo...
type UserInfo struct{}

// Tokens...
type Tokens struct {
	IDToken      string `json:"id_token,omitempty"`
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
}

// Provider...
type Provider struct {
	Issuer                       string   `json:"issuer,omitempty"`
	AuthorizationEndpoint        string   `json:"authorization_endpoint,omitempty"`
	TokenEndpoint                string   `json:"token_endpoint,omitempty"`
	UserinfoEndpoint             string   `json:"userinfo_endpoint,omitempty"`
	RevocationEndpoint           string   `json:"revocation_endpoint,omitempty"`
	RegistrationEndpoint         string   `json:"registration_endpoint,omitempty"`
	IntrospectionEndpoint        string   `json:"introspection_endpoint,omitempty"`
	JSONWebKeysURI               string   `json:"jwks_uri,omitempty"`
	OPPolicyURI                  string   `json:"op_policy_uri,omitempty"`
	OPTermsOfServiceURI          string   `json:"op_tos_uri,omitempty"`
	ServiceDocumentation         string   `json:"service_documentation,omitempty"`
	ResponseTypesSupported       []string `json:"response_types_supported,omitempty"`
	GrantTypesSupported          []string `json:"grant_types_supported,omitempty"`
	SubjectTypesSupported        []string `json:"subject_types_supported,omitempty"`
	IDTokenSigAlgValuesSupported []string `json:"id_token_signing_alg_values_supported,omitempty"`
	ScopesSupported              []string `json:"scopes_supported,omitempty"`
	TokenEPAuthMethodsSupported  []string `json:"token_endpoint_auth_methods_supported,omitempty"`
	ClaimsSupported              []string `json:"claims_supported,omitempty"`
}

// New fetches provider configuration and returns a new OpenID Connect provider client.
func New(ctx context.Context, providerURL string, opts ...ProviderOption) (*Provider, error) {
	// Fetch providerURL + "/.well-known/openid-configuration"
	return nil, nil
}

func (p *Provider) UserInfo(ctx context.Context) (*UserInfo, error) {
	return nil, nil
}

func (p *Provider) RegisterClient(ctx context.Context) error {
	if p.RegistrationEndpoint == "" {
		return ErrNotSupported
	}
	return nil
}

func (p *Provider) RevokeToken(ctx context.Context) error {
	if p.RevocationEndpoint == "" {
		return ErrNotSupported
	}
	return nil
}

func (p *Provider) IntrospectToken(ctx context.Context) error {
	if p.IntrospectionEndpoint == "" {
		return ErrNotSupported
	}
	return nil
}

func (p *Provider) Keys(ctx context.Context) error {
	return nil
}
