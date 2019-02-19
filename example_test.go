package oidclient_test

import (
	"context"
	"fmt"
	"log"
	"net/http"

	"github.com/hooklift/oidclient"
)

func Example_desktop() {
	ctx := context.Background()

	// 1. Discover provider configuration
	provider, err := oidclient.New(ctx, "https://id.hooklift.io", []oidclient.ProviderOption{
		oidclient.ClientID("blah"),
		oidclient.ClientSecret("blah"),
		oidclient.SkipTLSVerify(),
	})
	if err != nil {
		log.Fatalf("error retrieving provider's configuration: %v", err)
	}

	// 2. Generate provider authorization URI for the user to open.
	authURI, state, nonce, err := provider.AuthURI(ctx, []oidclient.AuthOption{
		oidclient.RedirectURI(redirectURI),
		oidclient.Scope("profile", "email", "offline"),
	})
	if err != nil {
		log.Fatalf("error building authorize URL: %v", err)
	}

	// 3. Start a HTTP server on loopback network interface. It receives authorization code and exchanges it for tokens.
	tokensCh := make(chan<- oidclient.Tokens)
	redirectURI, err := provider.Loopback(ctx, tokensCh, []oidclient.TokenOption{
		oidclient.State(state),
		oidclient.Nonce(nonce),
	})
	if err != nil {
		log.Fatalf("failed to start local HTTP server: %v", err)
	}

	log.Println("Open the following URL in your browser: %s", authURI)

	// 4. OpenID Connect provider authenticates user and asks for consent for "client_blah" to get tokens
	// 5. User approves or disapproves
	// 6. OpenID Connect Provider sends user back to us through redirectURI with query parameters: code and state, or
	// error and error_description.
	// 7. HTTP server handler on loopback interface validates state value and exchanges authorization code for tokens
	// 8. HTTP server handler validates token signatures, intended audience, state and nonce.
	// 9. HTTP server handler returns tokens through the channel
	tokens := <-tokensCh

	// 10. Check for any errors
	if tokens.Error != nil {
		log.Fatalf("failed retrieving tokens: %+v", tokens.Error)
	}

	// 11. Print out received tokens
	log.Println("Tokens: %+v", tokens)

	httpClient := provider.HTTPClient(ctx, tokens)
}

func Example_mobile() {
	ctx := context.Background()

	// 1. Discover provider configuration
	provider, err := oidclient.New(ctx, "https://id.hooklift.io", []oidclient.ProviderOption{
		oidclient.ClientID("client_blah"),
		oidclient.ClientSecret("secret_blah"),
		oidclient.SkipTLSVerify(),
	})
	if err != nil {
		log.Fatalf("error retrieving provider's configuration: %v", err)
	}

	// 2. Get provider authorization URI for the user to open.
	redirectURI := "app.hooklift.flappy:/oauth/callback"
	authURI, state, nonce, err := provider.AuthURI(ctx, []oidclient.AuthOption{
		oidclient.RedirectURI(redirectURI),
		oidclient.Scope("profile", "email", "offline"),
	})
	if err != nil {
		log.Fatalf("error building authorize URL: %v", err)
	}

	// 3. Native app opens a browser or asks user to follow the authorization URL: authURI
	// 4. OpenID Connect provider authenticates user and asks for consent for "client_blah" to get tokens
	// 5. User approves or disapproves
	// 6. OpenID Connect Provider redirects user back to us through redirectURI with query parameters: code and state, or
	// error and error_description.

	// 7. Our Application Delegate gets called with RedirectURI containing the code, state or error and error_description as query parameters
	// 8. Get tokens using received redirectURI, authorization code and state. Validate state, nonce, intended audience and token's signatures;
	// then return tokens.
	redirectURI = "app.hooklift.flappy://oauth-callback/?code=abasfasdf&state=dasdfasdfasdf"
	tokens, err := provider.Tokens(ctx, redirectURI, []oidclient.TokenOption{
		oidclient.State(state),
		oidclient.Nonce(nonce),
	})
	if err != nil {
		log.Fatalf("failed to retrieve tokens: %v", err)
	}

	log.Println("Tokens: %+v", tokens)

	httpClient := provider.HTTPClient(ctx, tokens)
}

func Example_web() {
	ctx := context.Background()
	provider, err := oidclient.New(ctx, "https://id.hooklift.io", []oidclient.ProviderOption{
		oidclient.ClientID("blah"),
		oidclient.ClientSecret("blah"),
		oidclient.SkipTLSVerify(),
		oidclient.TokenStore(&RedisTokenStore{
			Address:  "localhost:6379",
			Password: "",
			DB:       0,
		}),
	})
	if err != nil {
		log.Fatal("error retrieving provider's configuration %v", err)
	}

	mux := http.DefaultServeMux
	mux.HandleFunc("/", func(w http.ResponseWriter, req *http.Request) {
		httpClient := oidclient.FromContext(req.Context())
		fmt.Fprintf(w, "Hola Mundo!")
	})

	// Initialize authentication handler, it will redirect user to OpenID Connect provider for authentication and consent
	// if a httpClient is not found in the request's Context.
	handler = provider.Handler(mux, []oidclient.AuthOption{
		oidclient.RedirectURI("http://localhost:3000/oauth/callback"),
		oidclient.Scope("profile", "email", "offline"),
	})

	srv := &http.Server{
		Addr:    "localhost:8080",
		Handler: handler,
	}

	done := make(chan bool)
	fmt.Printf("Starting server in %q... ", srv.Addr)
	go func() {
		if err := srv.ListenAndServe(); err != nil {
			done <- true
			if err != http.ErrServerClosed {
				panic(err)
			}
		} else {
			done <- true
		}
	}()
	<-done
	fmt.Println("done")
}
