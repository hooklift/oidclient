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
// http://commandcenter.blogspot.com/2014/01/self-referential-functions-and-design.html
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
func Scope(scope ...string) AuthOption {
	return func(o *authOptions) error {
		o.scope = append(o.scope, scope...)
		return nil
	}
}

func DisplayPage() AuthOption {
	return func(o *authOptions) error {
		o.display = "page"
		return nil
	}
}

func DisplayPopup() AuthOption {
	return func(o *authOptions) error {
		o.display = "popup"
		return nil
	}
}

func PromptNone() AuthOption {
	return func(o *authOptions) error {
		o.prompt = "none"
		return nil
	}
}

func PromptLogin() AuthOption {
	return func(o *authOptions) error {
		o.prompt = "login"
		return nil
	}
}

func PromptConsent() AuthOption {
	return func(o *authOptions) error {
		o.prompt = "consent"
		return nil
	}
}

func PromptSelectAccount() AuthOption {
	return func(o *authOptions) error {
		o.prompt = "select_account"
		return nil
	}
}

func MaxAge(d time.Duration) AuthOption {
	return func(o *authOptions) error {
		o.maxAge = int(d.Seconds())
		return nil
	}
}

func UILocales(locales ...string) AuthOption {
	return func(o *authOptions) error {
		o.uiLocales = locales
		return nil
	}
}

func IDTokenHint(hint string) AuthOption {
	return func(o *authOptions) error {
		o.idTokenHint = hint
		return nil
	}
}

func LoginHint(hint string) AuthOption {
	return func(o *authOptions) error {
		o.loginHint = hint
		return nil
	}
}

func ACRValues(values ...string) AuthOption {
	return func(o *authOptions) error {
		o.acrValues = values
		return nil
	}
}

// AuthURI ...
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
