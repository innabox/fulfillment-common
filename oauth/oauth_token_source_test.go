/*
Copyright (c) 2025 Red Hat Inc.

Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the
License. You may obtain a copy of the License at

  http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an
"AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific
language governing permissions and limitations under the License.
*/

package oauth

import (
	"context"
	"fmt"
	"net/http"
	"time"

	. "github.com/onsi/ginkgo/v2/dsl/core"
	. "github.com/onsi/gomega"
	. "github.com/onsi/gomega/ghttp"
	"go.uber.org/mock/gomock"

	"github.com/innabox/fulfillment-common/auth"
)

var _ = Describe("Token source", func() {
	var (
		ctx    context.Context
		ctrl   *gomock.Controller
		store  auth.TokenStore
		server *Server
	)

	BeforeEach(func() {
		var err error

		// Create the context:
		ctx = context.Background()

		// Create the mock controller:
		ctrl = gomock.NewController(GinkgoT())
		DeferCleanup(ctrl.Finish)

		// Create an empty token store:
		store, err = auth.NewMemoryTokenStore().
			SetLogger(logger).
			Build()
		Expect(err).ToNot(HaveOccurred())

		// Create the server that responds to the discovery requests any number of times. Other responses will
		// be added in specific tests.
		server = NewServer()
		DeferCleanup(server.Close)
		server.RouteToHandler(
			http.MethodGet,
			"/.well-known/oauth-authorization-server",
			RespondWithJSONEncoded(
				http.StatusOK,
				&ServerMetadata{
					Issuer:        server.URL(),
					TokenEndpoint: fmt.Sprintf("%s/token", server.URL()),
				},
				http.Header{
					"Content-Type": {
						"application/json",
					},
				},
			),
		)
	})

	It("Can be created with all the mandatory parameters", func() {
		source, err := NewTokenSource().
			SetLogger(logger).
			SetIssuer(server.URL()).
			SetFlow(CredentialsFlow).
			SetClientId("my_client").
			SetClientSecret("my_secret").
			SetStore(store).
			Build()
		Expect(err).ToNot(HaveOccurred())
		Expect(source).ToNot(BeNil())
	})

	It("Can be created with optional scopes", func() {
		source, err := NewTokenSource().
			SetLogger(logger).
			SetIssuer(server.URL()).
			SetFlow(CredentialsFlow).
			SetClientId("my_client").
			SetClientSecret("my_secret").
			SetScopes("read", "write").
			SetStore(store).
			Build()
		Expect(err).ToNot(HaveOccurred())
		Expect(source).ToNot(BeNil())
	})

	It("Can be created with insecure TLS option", func() {
		source, err := NewTokenSource().
			SetLogger(logger).
			SetIssuer(server.URL()).
			SetFlow(CredentialsFlow).
			SetClientId("my_client").
			SetClientSecret("my_secret").
			SetInsecure(true).
			SetStore(store).
			Build()
		Expect(err).ToNot(HaveOccurred())
		Expect(source).ToNot(BeNil())
	})

	It("Can't be created without a logger", func() {
		source, err := NewTokenSource().
			SetIssuer(server.URL()).
			SetFlow(CredentialsFlow).
			SetClientId("my_client").
			SetClientSecret("my_secret").
			SetStore(store).
			Build()
		Expect(err).To(MatchError("logger is mandatory"))
		Expect(source).To(BeNil())
	})

	It("Can't be created without an issuer", func() {
		source, err := NewTokenSource().
			SetLogger(logger).
			SetFlow(CredentialsFlow).
			SetClientId("my_client").
			SetClientSecret("my_secret").
			SetStore(store).
			Build()
		Expect(err).To(MatchError("issuer is mandatory"))
		Expect(source).To(BeNil())
	})

	It("Can't be created without a client identifier for the client credentials flow", func() {
		source, err := NewTokenSource().
			SetLogger(logger).
			SetIssuer(server.URL()).
			SetFlow(CredentialsFlow).
			SetClientSecret("my_secret").
			SetStore(store).
			Build()
		Expect(err).To(MatchError("client identifier is mandatory"))
		Expect(source).To(BeNil())
	})

	It("Can't be created without a client secret for client credentials flow", func() {
		source, err := NewTokenSource().
			SetLogger(logger).
			SetIssuer(server.URL()).
			SetFlow(CredentialsFlow).
			SetClientId("my_client").
			SetStore(store).
			Build()
		Expect(err).To(MatchError("client secret is mandatory for the client credentials flow"))
		Expect(source).To(BeNil())
	})

	It("Can't be created without a token store", func() {
		source, err := NewTokenSource().
			SetLogger(logger).
			SetIssuer(server.URL()).
			SetFlow(CredentialsFlow).
			SetClientId("my_client").
			SetClientSecret("my_secret").
			Build()
		Expect(err).To(MatchError("token store is mandatory"))
		Expect(source).To(BeNil())
	})

	It("Can't be created without a listener in interactive mode and with the code flow", func() {
		source, err := NewTokenSource().
			SetLogger(logger).
			SetStore(store).
			SetIssuer(server.URL()).
			SetFlow(CodeFlow).
			SetInteractive(true).
			SetClientId("my_client").
			Build()
		Expect(err).To(MatchError("listener is mandatory for the authorization code flow"))
		Expect(source).To(BeNil())
	})

	It("Can't be created without a listener in interactive mode and with the device flow", func() {
		source, err := NewTokenSource().
			SetLogger(logger).
			SetStore(store).
			SetIssuer(server.URL()).
			SetFlow(DeviceFlow).
			SetInteractive(true).
			SetClientId("my_client").
			Build()
		Expect(err).To(MatchError("listener is mandatory for the device flow"))
		Expect(source).To(BeNil())
	})

	It("Uses the token loaded from storage if it is still fresh", func() {
		// Prepare the store with a valid token:
		err := store.Save(ctx, &auth.Token{
			Access:  "my_access_token",
			Refresh: "my_refresh_token",
			Expiry:  time.Now().Add(1 * time.Hour),
		})
		Expect(err).ToNot(HaveOccurred())

		// Create the source:
		source, err := NewTokenSource().
			SetLogger(logger).
			SetIssuer(server.URL()).
			SetStore(store).
			SetFlow(CredentialsFlow).
			SetClientId("my_client").
			SetClientSecret("my_secret").
			Build()
		Expect(err).ToNot(HaveOccurred())

		// Request the token:
		token, err := source.Token(ctx)
		Expect(err).ToNot(HaveOccurred())

		// Verify that the token is the one loaded from the store:
		Expect(token).ToNot(BeNil())
		Expect(token.Access).To(Equal("my_access_token"))
	})

	It("Refreshes the access token it is expired", func() {
		// Prepare the server so that it responds to the token refresh request with a valid token:
		server.AppendHandlers(
			CombineHandlers(
				VerifyRequest(http.MethodPost, "/token"),
				VerifyContentType("application/x-www-form-urlencoded"),
				VerifyFormKV("client_id", "my_client"),
				VerifyFormKV("grant_type", "refresh_token"),
				VerifyFormKV("refresh_token", "my_refresh_token"),
				RespondWithJSONEncoded(
					http.StatusOK,
					map[string]any{
						"access_token":  "my_new_access_token",
						"refresh_token": "my_new_refresh_token",
						"token_type":    "Bearer",
						"expires_in":    3600,
					},
					http.Header{
						"Content-Type": {
							"application/json",
						},
					},
				),
			),
		)
		// Prepare the store with a token that is expired:
		err := store.Save(ctx, &auth.Token{
			Access:  "my_access_token",
			Refresh: "my_refresh_token",
			Expiry:  time.Now().Add(-1 * time.Hour),
		})
		Expect(err).ToNot(HaveOccurred())

		// Create the source:
		source, err := NewTokenSource().
			SetLogger(logger).
			SetIssuer(server.URL()).
			SetStore(store).
			SetFlow(CredentialsFlow).
			SetClientId("my_client").
			SetClientSecret("my_secret").
			Build()
		Expect(err).ToNot(HaveOccurred())

		// Request the token:
		token, err := source.Token(ctx)
		Expect(err).ToNot(HaveOccurred())

		// Verify that the token is the one returned by the server:
		Expect(token).ToNot(BeNil())
		Expect(token.Access).To(Equal("my_new_access_token"))
		Expect(token.Refresh).To(Equal("my_new_refresh_token"))
		Expect(token.Expiry).To(BeTemporally("~", time.Now().Add(3600*time.Second), time.Second))
	})

	It("Refreshes the access token ins't expired yet, but about to expire", func() {
		// Prepare the server so that it responds to the token refresh request with a valid token:
		server.AppendHandlers(
			CombineHandlers(
				VerifyRequest(http.MethodPost, "/token"),
				VerifyContentType("application/x-www-form-urlencoded"),
				VerifyFormKV("client_id", "my_client"),
				VerifyFormKV("grant_type", "refresh_token"),
				VerifyFormKV("refresh_token", "my_refresh_token"),
				RespondWithJSONEncoded(
					http.StatusOK,
					map[string]any{
						"access_token":  "my_new_access_token",
						"refresh_token": "my_new_refresh_token",
						"token_type":    "Bearer",
						"expires_in":    3600,
					},
					http.Header{
						"Content-Type": {
							"application/json",
						},
					},
				),
			),
		)

		// Prepare the store with a token that is about to expire:
		err := store.Save(ctx, &auth.Token{
			Access:  "my_access_token",
			Refresh: "my_refresh_token",
			Expiry:  time.Now().Add(1 * time.Second),
		})
		Expect(err).ToNot(HaveOccurred())

		// Create the source:
		source, err := NewTokenSource().
			SetLogger(logger).
			SetIssuer(server.URL()).
			SetStore(store).
			SetFlow(CredentialsFlow).
			SetClientId("my_client").
			SetClientSecret("my_secret").
			Build()
		Expect(err).ToNot(HaveOccurred())

		// Request the token:
		token, err := source.Token(ctx)
		Expect(err).ToNot(HaveOccurred())

		// Verify that the token is the one returned by the server:
		Expect(token).ToNot(BeNil())
		Expect(token.Access).To(Equal("my_new_access_token"))
		Expect(token.Refresh).To(Equal("my_new_refresh_token"))
		Expect(token.Expiry).To(BeTemporally("~", time.Now().Add(3600*time.Second), time.Second))
	})

	It("Saves the refreshed access and refresh tokens", func() {
		// Prepare the server so that it responds to the token refresh request with a valid token:
		server.AppendHandlers(
			CombineHandlers(
				VerifyRequest(http.MethodPost, "/token"),
				VerifyContentType("application/x-www-form-urlencoded"),
				VerifyFormKV("grant_type", "refresh_token"),
				RespondWithJSONEncoded(
					http.StatusOK,
					map[string]any{
						"access_token":  "my_new_access_token",
						"refresh_token": "my_new_refresh_token",
						"token_type":    "Bearer",
						"expires_in":    3600,
					},
					http.Header{
						"Content-Type": {
							"application/json",
						},
					},
				),
			),
		)

		// Prepare the store with a token that is expired:
		err := store.Save(ctx, &auth.Token{
			Access:  "my_access_token",
			Refresh: "my_refresh_token",
			Expiry:  time.Now().Add(-1 * time.Hour),
		})
		Expect(err).ToNot(HaveOccurred())

		// Create the source:
		source, err := NewTokenSource().
			SetLogger(logger).
			SetIssuer(server.URL()).
			SetStore(store).
			SetFlow(CredentialsFlow).
			SetClientId("my_client").
			SetClientSecret("my_secret").
			Build()
		Expect(err).ToNot(HaveOccurred())

		// Request the token:
		_, err = source.Token(ctx)
		Expect(err).ToNot(HaveOccurred())

		// Verify that the new access and refresh tokens were saved:
		token, err := store.Load(ctx)
		Expect(err).ToNot(HaveOccurred())
		Expect(token).ToNot(BeNil())
		Expect(token.Access).To(Equal("my_new_access_token"))
		Expect(token.Refresh).To(Equal("my_new_refresh_token"))
		Expect(token.Expiry).To(BeTemporally("~", time.Now().Add(3600*time.Second), time.Second))
	})

	It("Preserves the refrest token if the server doesn't return a new one", func() {
		// Prepare the server so that it responds to the token refresh request with a valid access toke, but
		// without a new refresh token:
		server.AppendHandlers(
			CombineHandlers(
				VerifyRequest(http.MethodPost, "/token"),
				VerifyContentType("application/x-www-form-urlencoded"),
				VerifyFormKV("grant_type", "refresh_token"),
				RespondWithJSONEncoded(
					http.StatusOK,
					map[string]any{
						"access_token": "my_new_access_token",
						"token_type":   "Bearer",
						"expires_in":   3600,
					},
					http.Header{
						"Content-Type": {
							"application/json",
						},
					},
				),
			),
		)

		// Prepare the store with a token that is expired:
		err := store.Save(ctx, &auth.Token{
			Access:  "my_access_token",
			Refresh: "my_refresh_token",
			Expiry:  time.Now().Add(-1 * time.Hour),
		})
		Expect(err).ToNot(HaveOccurred())

		// Create the source:
		source, err := NewTokenSource().
			SetLogger(logger).
			SetIssuer(server.URL()).
			SetStore(store).
			SetFlow(CredentialsFlow).
			SetClientId("my_client").
			SetClientSecret("my_secret").
			Build()
		Expect(err).ToNot(HaveOccurred())

		// Request the token:
		_, err = source.Token(ctx)
		Expect(err).ToNot(HaveOccurred())

		// Verify that the old refresh token was preserved:
		token, err := store.Load(ctx)
		Expect(err).ToNot(HaveOccurred())
		Expect(token).ToNot(BeNil())
		Expect(token.Refresh).To(Equal("my_refresh_token"))
	})

	It("Requests a new access token if it is expired and there is no refresh token", func() {
		// Prepare the server so that it responds to the request to refresh the token with an error, and to
		// the request to generate a new token with a valid token.
		server.AppendHandlers(

			// First request should be to refresh the token, and this should fail:
			CombineHandlers(
				VerifyRequest(http.MethodPost, "/token"),
				VerifyContentType("application/x-www-form-urlencoded"),
				VerifyFormKV("grant_type", "refresh_token"),
				VerifyFormKV("refresh_token", "my_refresh_token"),
				VerifyFormKV("client_id", "my_client"),
				RespondWithJSONEncoded(
					http.StatusBadRequest,
					map[string]any{
						"error":             "invalid_grant",
						"error_description": "The refresh token is invalid or expired",
					},
					http.Header{
						"Content-Type": {
							"application/json",
						},
					},
				),
			),

			// Second request should be to generate a new token:
			CombineHandlers(
				VerifyRequest(http.MethodPost, "/token"),
				VerifyContentType("application/x-www-form-urlencoded"),
				VerifyFormKV("grant_type", "client_credentials"),
				VerifyFormKV("client_id", "my_client"),
				VerifyFormKV("client_secret", "my_secret"),
				RespondWithJSONEncoded(
					http.StatusOK,
					map[string]any{
						"access_token":  "my_new_access_token",
						"refresh_token": "my_new_refresh_token",
						"token_type":    "Bearer",
						"expires_in":    3600,
					},
					http.Header{
						"Content-Type": {
							"application/json",
						},
					},
				),
			),
		)

		// Prepare the store with a token that is expired:
		err := store.Save(ctx, &auth.Token{
			Access:  "my_access_token",
			Refresh: "my_refresh_token",
			Expiry:  time.Now().Add(-1 * time.Hour),
		})
		Expect(err).ToNot(HaveOccurred())

		// Create the source:
		source, err := NewTokenSource().
			SetLogger(logger).
			SetIssuer(server.URL()).
			SetStore(store).
			SetFlow(CredentialsFlow).
			SetClientId("my_client").
			SetClientSecret("my_secret").
			Build()
		Expect(err).ToNot(HaveOccurred())

		// Request the token:
		token, err := source.Token(ctx)
		Expect(err).ToNot(HaveOccurred())

		// Verify that the token is the one returned by the server:
		Expect(token).ToNot(BeNil())
		Expect(token.Access).To(Equal("my_new_access_token"))
		Expect(token.Refresh).To(Equal("my_new_refresh_token"))
	})

	It("It uses the access token that isn't fresh, but not expired, if there is no alternative", func() {
		// Prepare the store with a token that isn't fresh (expires in less than 30 seconds) but not
		// expired yet, and no refresh token.
		err := store.Save(ctx, &auth.Token{
			Access: "my_access_token",
			Expiry: time.Now().Add(10 * time.Second),
		})
		Expect(err).ToNot(HaveOccurred())

		// Create the source with a flow that can't be used because it is interactive and interactive mode is
		// disabled. This should force it to use the token from the store.
		source, err := NewTokenSource().
			SetLogger(logger).
			SetIssuer(server.URL()).
			SetStore(store).
			SetFlow(CodeFlow).
			SetInteractive(false).
			SetClientId("my_client").
			Build()
		Expect(err).ToNot(HaveOccurred())

		// Request the token:
		token, err := source.Token(ctx)
		Expect(err).ToNot(HaveOccurred())

		// Verify that the token is the old one:
		Expect(token).ToNot(BeNil())
		Expect(token.Access).To(Equal("my_access_token"))
	})
})
