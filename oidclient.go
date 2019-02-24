// Package oidclient implements a strict and secure OpenID Connect client.
// It does not forgive or work around broken OpenID Connect or OAuth2 providers.
package oidclient

import (
	"crypto/rand"
	"encoding/hex"
	"io"
)

// GenerateNonce is a convenient function to generate cryptographic nonces. Needed
// for state and nonce parameters sent in authorization requests.
func GenerateNonce() string {
	p := make([]byte, 32)
	_, err := io.ReadFull(rand.Reader, p)
	if err != nil {
		panic(err)
	}

	return hex.EncodeToString(p)
}
