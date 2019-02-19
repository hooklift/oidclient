package oidclient

import (
	"context"
	"errors"
	"net/url"
	"time"
)

// authOptions holds the authentication request parameters as per
// https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
type authOptions struct {
	redirectURI string
	scope       []string
	display     string
	prompt      string
	maxAge      int
	idTokenHint string
	loginHint   string
	uiLocales   []string
	acrValues   []string
	// The following are not exposed to be configured by users.
	clientID     string
	responseType string
	state        string
	nonce        string
}

// AuthOption defines a type to process authorization config options
// It follows http://commandcenter.blogspot.com/2014/01/self-referential-functions-and-design.html
type AuthOption func(*authOptions) error

// RedirectURI sets the redirect URI to which the OpenID provider should send the authorization code to.
func RedirectURI(uri string) AuthOption {
	return func(o *authOptions) error {
		url, err := url.Parse(uri)
		if err != nil {
			return err
		}

		if url.Hostname() == "localhost" {
			return errors.New("localhost is not allowed, use 127.0.0.1 or ::1 instead")
		}

		o.redirectURI = uri
		return nil
	}
}

// Scope appends scopes to the list of scopes to request authorization for.
// There is no need to provide "openid" as scope, it is already added by default.
// Users can approve or disapprove the client app from having the request access level.
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

// AuthURI generates the authorization URI along with state and nonce values that must be included in the subsequent request for tokens.
// The state and nonce values returned by this function must be used in the subsequent request for tokens. Otherwise, no tokens
// will be returned.
func (p *Provider) AuthURI(ctx context.Context, opts ...AuthOption) (string, string, string, error) {
	cfg := new(authOptions)
	cfg.scope = []string{"openid"}

	for _, opt := range opts {
		if err := opt(cfg); err != nil {
			return "", "", "", err
		}
	}

	// Generate nonce
	// Generate state
	// Set response_type to code
	// Verify that redirect_uri doesn't use "localhost"
	// Verify that redirect_uri uses TLS unless it is 127.0.0.1 or 127.0.1.1"
	// Send client credentials using client_secret_basic only

	return "", "", "", nil
}
