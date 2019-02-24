package oidclient

import (
	"context"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/pkg/errors"
)

// authOptions holds the authentication request parameters as per
// https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
type authOptions struct {
	redirectURI  string
	scope        []string
	display      string
	prompt       string
	maxAge       int
	idTokenHint  string
	loginHint    string
	uiLocales    []string
	acrValues    []string
	state        string
	nonce        string
	responseType string
}

// AuthOption defines a type to process authorization config options
// It follows http://commandcenter.blogspot.com/2014/01/self-referential-functions-and-design.html
type AuthOption func(*authOptions) error

// RedirectURI sets the redirect URI to which the OpenID provider should send the authorization code to.
func RedirectURI(uri string) AuthOption {
	return func(o *authOptions) error {
		o.redirectURI = uri
		return nil
	}
}

// Scope appends scopes to the list of scopes to request authorization for.
// There is no need to provide "openid" as scope, it is already added by default.
// Users can approve or disapprove the client app from having the requested access level.
func Scope(scope ...string) AuthOption {
	return func(o *authOptions) error {
		o.scope = append(o.scope, scope...)
		return nil
	}
}

// DisplayPage signals the identity provider to show the consent UI with a full User Agent view.
func DisplayPage() AuthOption {
	return func(o *authOptions) error {
		o.display = "page"
		return nil
	}
}

// DisplayPopup signals the identity provider to show the consent UI with a popup User Agent window.
func DisplayPopup() AuthOption {
	return func(o *authOptions) error {
		o.display = "popup"
		return nil
	}
}

// PromptNone signals the identity provider to not show any authentication or consent user interface.
// An error s returned if the end-user is not already authenticated or the client does not have pre-configured consent
// for the requested Scope or does not fulfill other conditions for processing the request.
// The error code will typically be login_required, interaction_required, or another code.
// This can be used as a method to check for existing authentication and/or consent.
func PromptNone() AuthOption {
	return func(o *authOptions) error {
		o.prompt = "none"
		return nil
	}
}

// PromptLogin signals the identity provider to prompt the user for re-authentication. If it can't re-authenticate it tipically returns
// login_required as error.
func PromptLogin() AuthOption {
	return func(o *authOptions) error {
		o.prompt = "login"
		return nil
	}
}

// PromptConsent signals the identity provider to unconditionally prompt the user for consent before returning information to the client.
func PromptConsent() AuthOption {
	return func(o *authOptions) error {
		o.prompt = "consent"
		return nil
	}
}

// PromptSelectAccount signals the identity provider to prompt the user to select an account, in case the user owns multiple accounts.
func PromptSelectAccount() AuthOption {
	return func(o *authOptions) error {
		o.prompt = "select_account"
		return nil
	}
}

// MaxAge specifies the allowable elapsed time since the last time the user was actively authenticated by the identity provider. If
// the elapsed time is greater than this value, the identity provider will attempt to re-authenticate the user. When this parameter is set,
// the ID token will include an `auth_time` claim value.
func MaxAge(d time.Duration) AuthOption {
	return func(o *authOptions) error {
		o.maxAge = int(d.Seconds())
		return nil
	}
}

// UILocales specifies the user's preferred languages for the user interface, ordered by preference.
func UILocales(locales ...string) AuthOption {
	return func(o *authOptions) error {
		o.uiLocales = locales
		return nil
	}
}

// IDTokenHint is usually set with a previously issued ID token. If the End-User identified by the ID Token is logged in or is
// logged in by the request, then the identity provider returns a positive response; otherwise, it returns an error, such as login_required.
func IDTokenHint(hint string) AuthOption {
	return func(o *authOptions) error {
		o.idTokenHint = hint
		return nil
	}
}

// LoginHint hints the identity provider with the login identifier the user might use to log in.
func LoginHint(hint string) AuthOption {
	return func(o *authOptions) error {
		o.loginHint = hint
		return nil
	}
}

// ACRValues sets the Authentication Context Class Reference values the identity provider is requested to use for processing the
// authentication request. The Authentication Context Class satisfied by the authentication performed is returned as the acr claim value
// in the ID token. Examples of ACR values are: mfa, otp, pin, pwd, rba, among others specified in https://tools.ietf.org/html/rfc8176.
func ACRValues(values ...string) AuthOption {
	return func(o *authOptions) error {
		o.acrValues = values
		return nil
	}
}

// Nonce sets a value used to associate a client session with an ID Token, and to mitigate replay attacks.
func Nonce(value string) AuthOption {
	return func(o *authOptions) error {
		o.nonce = value
		return nil
	}
}

// State is an opaque value used by the client to maintain state between the request and callback, mitigating
// potential CSRF attacks.
func State(value string) AuthOption {
	return func(o *authOptions) error {
		o.state = value
		return nil
	}
}

// AuthorizationURL generates the URL to send the user to for authentication and authorization consent.
func (p *Provider) AuthorizationURL(ctx context.Context, opts ...AuthOption) (string, error) {
	cfg := new(authOptions)
	cfg.scope = []string{"openid"}

	for _, opt := range opts {
		if err := opt(cfg); err != nil {
			return "", err
		}
	}

	redirectURI, err := url.Parse(cfg.redirectURI)
	if err != nil {
		return "", errors.Wrapf(err, "invalid redirect URI")
	}

	// FIXME(c4milo): As per rfc8252 we cannot assume IPv4
	if redirectURI.Hostname() == "localhost" {
		// Avoid DNS resolvers as per https://tools.ietf.org/html/rfc8252#section-8.3
		redirectURI.Host = "127.0.0.1"
	}

	// Forces redirect URI to use TLS as it will likely be rejected by the IdP if it isn't.
	if redirectURI.Hostname() != "127.0.0.1" && redirectURI.Scheme != "https" {
		return "", errors.New("redirect URL requires https scheme")
	}

	if cfg.responseType == "" {
		cfg.responseType = "code"
	}

	if cfg.state == "" || cfg.nonce == "" {
		return "", errors.New("state and nonce cannot be empty")
	}

	query := url.Values{}
	query.Set("response_type", cfg.responseType)
	query.Set("scope", strings.Join(cfg.scope, " "))
	query.Set("state", cfg.state)
	query.Set("nonce", cfg.nonce)
	query.Set("redirect_uri", redirectURI.String())

	if cfg.display != "" {
		query.Set("display", cfg.display)
	}

	if cfg.prompt != "" {
		query.Set("prompt", cfg.prompt)
	}

	if cfg.maxAge != 0 {
		query.Set("max_age", strconv.Itoa(cfg.maxAge))
	}

	if len(cfg.uiLocales) > 0 {
		query.Set("ui_locales", strings.Join(cfg.uiLocales, " "))
	}

	if cfg.idTokenHint != "" {
		query.Set("id_token_hint", cfg.idTokenHint)
	}

	if cfg.loginHint != "" {
		query.Set("login_hint", cfg.loginHint)
	}

	if len(cfg.acrValues) > 0 {
		query.Set("acr_values", strings.Join(cfg.acrValues, " "))
	}

	authEndpoint, err := url.Parse(p.AuthorizationEndpoint)
	if err != nil {
		return "", errors.Wrapf(err, "failed parsing authorization endpoint: %s", p.AuthorizationEndpoint)
	}

	authEndpoint.RawQuery = query.Encode()

	return authEndpoint.String(), nil
}
