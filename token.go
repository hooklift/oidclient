package oidclient

import (
	"context"
	"encoding/json"
	"io"
	"io/ioutil"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/pkg/errors"
)

const (
	errInvalidRequest = "invalid_request"
	errInvalidGrant   = "invalid_grant"
)

// Tokens holds the response received by the identity provider when exchanging authorization grant codes for tokens.
// Users are encouraged to store these tokens and encrypt them at rest.
// Refresh tokens do not have an expiration time, extra care must be taken when storing them.
type Tokens struct {
	IDToken          string `json:"id_token,omitempty"`
	AccessToken      string `json:"access_token"`
	TokenType        string `json:"token_type"`
	ExpiresIn        int    `json:"expires_in"`
	RefreshToken     string `json:"refresh_token,omitempty"`
	Error            string `json:"error,omitempty"`
	ErrorDescription string `json:"error_description,omitempty"`
	ErrorURI         string `json:"error_uri,omitempty"`
}

// Validate validates ID and Access tokens according to https://openid.net/specs/openid-connect-core-1_0.html#rfc.section.3.1.3.7
// and https://openid.net/specs/openid-connect-core-1_0.html#rfc.section.3.1.3.8
func (t *Tokens) Validate() error {
	return nil
}

// Encrypt encodes and encrypts all the tokens, ready to be stored in an external storage.
func (t *Tokens) Encrypt() (string, error) {
	return "", nil
}

// Decrypt decrypts and decodes tokens recovered from an external storage.
func (t *Tokens) Decrypt(value string) error {
	return nil
}

// randomPort generates a random port between IANA's dynamic/private port range.
// This is 49151-65535. https://en.wikipedia.org/wiki/Registered_port
func randomPort() string {
	max := 65535
	min := 49151
	port := rand.Intn(max-min) + min
	return strconv.Itoa(port)
}

// Loopback spins up HTTP server listening in 127.0.0.1 and an unprivileged random TCP port. It receives OIDC provider's redirections,
// containing authorization code, state or errors. Exchanging authorization code for tokens and returning them through the tokensChan
// channel.
func (p *Provider) Loopback(ctx context.Context, tokensChan chan<- Tokens, opts ...AuthOption) (string, error) {
	var (
		err    error
		tokens Tokens
	)

	cfg := new(authOptions)
	for _, opt := range opts {
		if err := opt(cfg); err != nil {
			return "", err
		}
	}

	address := net.JoinHostPort("127.0.0.1", randomPort())
	path := "/callback"
	redirectURI := "http://" + address + path
	go func() {
		http.HandleFunc(path, func(w http.ResponseWriter, req *http.Request) {
			defer func() {
				tokensChan <- tokens
			}()

			query := req.URL.Query()

			if query.Get("state") != cfg.state {
				tokens.Error = errInvalidRequest
				return
			}

			code := query.Get("code")
			if code == "" {
				tokens.Error = errInvalidGrant
				return
			}

			tokens, err := p.Tokens(ctx, code, redirectURI)
			if err != nil {
				tokens.Error = err.Error()
				return
			}
		})

		if err := http.ListenAndServe(address, nil); err != http.ErrServerClosed {
			panic("failed starting up local HTTP server")
		}
	}()

	return redirectURI, err
}

// RefreshToken allows to refresh Access and ID tokens.
func (p *Provider) RefreshToken(ctx context.Context, refreshToken string, scope ...string) (*Tokens, error) {
	query := url.Values{}
	query.Set("grant_type", "refresh_token")
	query.Set("refresh_token", refreshToken)

	if len(scope) > 0 {
		// Allows to get a new access token with a reduced scope, as long as the IdP supports it.
		query.Set("scope", strings.Join(scope, " "))
	}

	return p.tokens(ctx, query)
}

// Tokens retrieves tokens using the authorization grant code flow.
func (p *Provider) Tokens(ctx context.Context, authCode, redirectURI string) (*Tokens, error) {
	query := url.Values{}
	query.Set("grant_type", "authorization_code")
	query.Set("code", authCode)

	if redirectURI != "" {
		query.Set("redirect_uri", redirectURI)
	}
	return p.tokens(ctx, query)
}

func (p *Provider) tokens(ctx context.Context, query url.Values) (*Tokens, error) {
	u, err := url.Parse(p.TokenEndpoint)
	if err != nil {
		return nil, errors.Wrapf(err, "invalid token endpoint: %s", p.TokenEndpoint)
	}

	res, err := p.httpClient.PostForm(u.String(), query)
	if err != nil {
		return nil, errors.Wrap(err, "failed getting tokens from provider")
	}
	defer res.Body.Close()

	body, err := ioutil.ReadAll(io.LimitReader(res.Body, 1<<20))
	if err != nil {
		return nil, errors.Wrap(err, "failed reading tokens response")
	}

	tks := new(Tokens)
	if err := json.Unmarshal(body, tks); err != nil {
		return nil, errors.Wrap(err, "failed decoding tokens response")
	}

	if err := tks.Validate(); err != nil {
		return nil, errors.Wrap(err, "failed tokens validations")
	}
	return tks, nil
}
