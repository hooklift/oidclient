package oidclient

import "net/http"

func (p *Provider) Handler(h http.Handler, opts ...AuthOption) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	})
}
