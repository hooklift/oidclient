package oidclient

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"time"

	"github.com/hooklift/httpclient"
	"github.com/hooklift/oidclient/store"
	"github.com/pkg/errors"
)

const (
	configEndpoint = "/.well-known/openid-configuration"
)

// ErrNotSupported is returned when the OpenID Connect provider does not support a specific OIDC capability.
var ErrNotSupported = errors.New("not supported by provider")

// TokenStore defines the interface to implement for different token storages. Tokens are serialize and
// encrypted using XSalsa20 and Poly1305 before sending them over to the specific store implementation.
type TokenStore interface {
	// Set stores tokens using the ID Token Subject as key.
	Set(ctx context.Context, tokens string) error
	// Get retrieves tokens stored for the user identified by subjectID
	Get(ctx context.Context, subjectID string) (string, error)
	// Delete removes all tokens associated to the user identified by subjectID
	Delete(ctx context.Context, subjectID string) error
}

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

// WithTokenStore sets a concrete implementation of the TokenStore interface. It is used to retrieve, refresh and persist tokens when
// using the secure HTTP client of this library. By default, it uses Memory store.
func WithTokenStore(store TokenStore) ProviderOption {
	return func(o *providerOptions) error {
		o.tokenStore = store
		return nil
	}
}

// UserInfo defines the information usually returned by identity providers for the owner of an Access or ID token.
type UserInfo struct {
	Subject    string `json:"sub"`
	Name       string `json:"name"`
	GivenName  string `json:"given_name"`
	FamilyName string `json:"family_name"`
	Email      string `json:"email"`
	Picture    string `json:"picture"`
}

// Provider holds the identity provider configuration information, discovered during initialization. This configuration
// is cached in memory and refreshed based on cache-control policies returned by the identity provider service.
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
	cfg.tokenStore = new(store.Memory)

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

// TODO(c4milo): local caching support, with refresh based on cache-control directives
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
	// TODO(c4milo): Send Authorization header with client credentials
	return nil
}

// IntrospectToken allows to gather access token information form identity providers that support https://tools.ietf.org/html/rfc7662
func (p *Provider) IntrospectToken(ctx context.Context) error {
	if p.IntrospectionEndpoint == "" {
		return ErrNotSupported
	}
	// TODO(c4milo): Send Authorization header with client credentials
	return nil
}

// Keys allows to retrieve identity provider's public token signing keys in order to verify that tokens
// have not been modified in transit.
func (p *Provider) Keys(ctx context.Context) error {
	return nil
}

// HTTPClient automatically sets and refreshes Bearer access tokens in requests. It skips setting an Authorization
// header if one is already set. It will only work for HTTP requests to the resource server for which ID and Access tokens
// were granted to.
type HTTPClient struct {
	*http.Client
	p *Provider
}

type httpClientOptions struct {
	transport http.RoundTripper
}

// HTTPClientOption defines an option type for passing parameters to HTTPClient
type HTTPClientOption func(*httpClientOptions) error

// Transport allows to set a custom RoundTripper for the HTTPClient.
func Transport(tr http.RoundTripper) HTTPClientOption {
	return func(o *httpClientOptions) error {
		o.transport = tr
		return nil
	}
}

// Do refreshes access and ID tokens if they are close to expire.
func (h *HTTPClient) Do(req *http.Request) (*http.Response, error) {
	ctx := req.Context()

	// TODO(c4milo): If access token is close to expire, refresh and store it back in
	// TODO(c4milo): Validate that ID token audience matches req.URL
	// to avoid leaking the access token to another third-party

	new, err := h.p.RefreshToken(ctx, h.tks.refreshToken)
	if err != nil {
		return nil, errors.Wrap(err, "failed refreshing ID and Access tokens")
	}

	if _, ok := req.Header["Authorization"]; !ok {
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", new.AccessToken))
	}

	return h.Do(req)
}

// HTTPClient returns a HTTP client that automatically appends Authorization header with the bearer access tokens and that can
// also refresh access tokens if they expire.
func (p *Provider) HTTPClient(ctxt context.Context, tokens *Tokens, opts ...HTTPClientOption) *HTTPClient {
	cfg := new(httpClientOptions)
	cfg.transport = &http.Transport{
		DialContext:           httpclient.DialContext(30*time.Second, 10*time.Second),
		Proxy:                 http.ProxyFromEnvironment,
		IdleConnTimeout:       30 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		ResponseHeaderTimeout: 10 * time.Second,
	}

	for _, opt := range opts {
		if err := opt(cfg); err != nil {
			return nil
		}
	}

	p.tokenStore.Set(ctx, tokens.Encode())

	client := &HTTPClient{p: p}
	client.Transport = cfg.transport

	return client
}
