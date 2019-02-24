package oidclient

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"io/ioutil"
	"net/http"
	"time"

	"github.com/hooklift/httpclient"
	"github.com/pkg/errors"
)

const (
	configEndpoint = "/.well-known/openid-configuration"
)

// TokenStore defines an interface to store and retrieve tokens. Encryption at rest is highly suggested.
type TokenStore interface {
	Get(ctx context.Context, id string) (*Tokens, error)
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
	tokenStore    TokenStore
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

// WithTokenStore sets a concrete implementation of the TokenStore interface. It is used to retrieve and persist tokens when
// using the HTTP handler.
func WithTokenStore(store TokenStore) ProviderOption {
	return func(o *providerOptions) error {
		o.tokenStore = store
		return nil
	}
}

// UserInfo defines the information usually returned by identity providers for the owner of an access or ID token.
type UserInfo struct {
	Subject    string `json:"sub"`
	Name       string `json:"name"`
	GivenName  string `json:"given_name"`
	FamilyName string `json:"family_name"`
	Email      string `json:"email"`
	Picture    string `json:"picture"`
}

// Provider holds the identity provider configuration information, discovered during initialization. This configuration
// is cached and refreshed based on cache-control policies returned by the identity provider.
type Provider struct {
	providerOptions
	httpClient                   *http.Client
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
	cfg := new(providerOptions)
	cfg.providerURL = providerURL

	for _, opt := range opts {
		if err := opt(cfg); err != nil {
			return nil, err
		}
	}

	p := &Provider{
		providerOptions: *cfg,
	}

	p.newHTTPClient()

	if err := p.loadConfig(); err != nil {
		return nil, errors.Wrapf(err, "failed loading provider configuration")
	}

	return p, nil
}

// TODO(c4milo): External caching support
func (p *Provider) loadConfig() error {
	res, err := p.httpClient.Get(p.providerURL + configEndpoint)
	if err != nil {
		return errors.Wrapf(err, "failed retrieving provider configuration from: %s", p.providerURL)
	}
	defer res.Body.Close()

	body, err := ioutil.ReadAll(io.LimitReader(res.Body, 1<<20))
	if err != nil {
		return errors.Wrapf(err, "failed reading provider configuration")
	}

	if err := json.Unmarshal(body, p); err != nil {
		return errors.Wrapf(err, "failed decoding provider configuration")
	}

	return nil
}

func (p *Provider) newHTTPClient() {
	tr := &http.Transport{
		DialContext:           httpclient.DialContext(30*time.Second, 10*time.Second),
		Proxy:                 http.ProxyFromEnvironment,
		IdleConnTimeout:       30 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		ResponseHeaderTimeout: 10 * time.Second,
	}

	if p.skipTLSVerify {
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}

	p.httpClient = &http.Client{Transport: tr}
}

// UserInfo returns user information for the access token subject.
func (p *Provider) UserInfo(ctx context.Context) (*UserInfo, error) {
	if p.UserinfoEndpoint == "" {
		return nil, ErrNotSupported
	}
	// TODO(c4milo): Send Authorization header with bearer access token
	return nil, nil
}

// RegisterClient allows to dynamically register oidc/oauth2 client applications on identity providers that support https://tools.ietf.org/html/rfc7591
func (p *Provider) RegisterClient(ctx context.Context) error {
	if p.RegistrationEndpoint == "" {
		return ErrNotSupported
	}
	// TODO(c4milo): Send Authorization header with bearer access token
	return nil
}

// RevokeToken allows to revoke access tokens on identity providers that support https://tools.ietf.org/html/rfc7009
func (p *Provider) RevokeToken(ctx context.Context) error {
	if p.RevocationEndpoint == "" {
		return ErrNotSupported
	}
	return nil
	// TODO(c4milo): Send Authorization header with client credentials
}

// IntrospectToken allows to gather access token information form identity providers that support https://tools.ietf.org/html/rfc7662
func (p *Provider) IntrospectToken(ctx context.Context) error {
	if p.IntrospectionEndpoint == "" {
		return ErrNotSupported
	}
	return nil
	// TODO(c4milo): Send Authorization header with client credentials
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
