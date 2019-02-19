package oidclient

import "net/http"

// Handler is a convenience function for HTTP APIs federating authentication to OpenID Connect or OAuth2 providers.
// It sets in the request context a HTTP client that automatically sets the Authorization header with the bearer access token on
// any outgoing HTTP request. The HTTP client also automatically refreshes access tokens if needed.
func (p *Provider) Handler(h http.Handler, opts ...AuthOption) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	})
}
