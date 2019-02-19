// Package oidclient implements a strict and secure OpenID Connect client.
// It does not forgive or work around broken OpenID Connect or OAuth2 providers.
// Supports verifying RSA256 and ED25519 signed ID tokens.
// Only implements authorization code flow.
package oidclient

import (
	"context"
	"errors"
	"net/http"
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

// ProviderOption defines a type for passing Provider instantiation parameters.
type ProviderOption func(*providerOptions) error

// ClientID sets the openidc/oauth2 client application identifier. You get client credentials when the client app
// is created in your identity provider as a native or web application, public or private.
func ClientID(id string) ProviderOption {
	return func(o *providerOptions) error {
		o.clientID = id
		return nil
	}
}

// ClientSecret sets the openidc/oauth2 client application secret. You get client credentials when the client app
// is created in your identity provider as a native or web application, public or private.
func ClientSecret(secret string) ProviderOption {
	return func(o *providerOptions) error {
		o.clientSecret = secret
		return nil
	}
}

// SkipTLSVerify allows to skip TLS verification during development. It is not recommended to enable this parameter in
// production applications.
func SkipTLSVerify() ProviderOption {
	return func(o *providerOptions) error {
		o.skipTLSVerify = true
		return nil
	}
}

// UserInfo defines the information usually returned by identity providers for the owner of an access or ID token.
type UserInfo struct{}

// Provider holds the identity provider configuration information, discovered during initialization. This configuration
// is cached and refreshed based on cache-control policies returned by the identity provider.
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

// UserInfo returns user for the ID token subject or owner.
func (p *Provider) UserInfo(ctx context.Context) (*UserInfo, error) {
	return nil, nil
}

// RegisterClient allows to dynamically register oidc/oauth2 client applications on identity providers that support https://tools.ietf.org/html/rfc7591
func (p *Provider) RegisterClient(ctx context.Context) error {
	if p.RegistrationEndpoint == "" {
		return ErrNotSupported
	}
	return nil
}

// RevokeToken allows to revoke access tokens on identity providers that support https://tools.ietf.org/html/rfc7009
func (p *Provider) RevokeToken(ctx context.Context) error {
	if p.RevocationEndpoint == "" {
		return ErrNotSupported
	}
	return nil
}

// IntrospectToken allows to gather access token information form identity providers that support https://tools.ietf.org/html/rfc7662
func (p *Provider) IntrospectToken(ctx context.Context) error {
	if p.IntrospectionEndpoint == "" {
		return ErrNotSupported
	}
	return nil
}

// Keys allows to retrieve identity provider's public token signing keys in order to verify that tokens
// have not been modified in transit.
func (p *Provider) Keys(ctx context.Context) error {
	return nil
}

// HTTPClient returns a HTTP client that auto-appends Authorization header with the bearer access tokens and that can
// also automatically refresh access tokens if they expire.
func (p *Provider) HTTPClient(ctxt context.Context, tokens *Tokens) (*http.Client, error) {
	return nil, errors.New("not implemented")
}
