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
	"encoding/json"
	"fmt"
	"net/http"

	. "github.com/onsi/ginkgo/v2/dsl/core"
	. "github.com/onsi/gomega"
	. "github.com/onsi/gomega/ghttp"
)

var _ = Describe("OAuth discovery tool", func() {
	var ctx context.Context
	var server *Server

	BeforeEach(func() {
		ctx = context.Background()
		server = NewServer()
		DeferCleanup(server.Close)
	})

	Describe("Creation", func() {
		It("Can be created with all mandatory parameters", func() {
			tool, err := NewDiscoveryTool().
				SetLogger(logger).
				SetIssuer("https://example.com").
				Build()
			Expect(err).ToNot(HaveOccurred())
			Expect(tool).ToNot(BeNil())
		})

		It("Can be created with optional insecure flag", func() {
			tool, err := NewDiscoveryTool().
				SetLogger(logger).
				SetIssuer("https://example.com").
				SetInsecure(true).
				Build()
			Expect(err).ToNot(HaveOccurred())
			Expect(tool).ToNot(BeNil())
		})

		It("Can't be created without a logger", func() {
			tool, err := NewDiscoveryTool().
				SetIssuer("https://example.com").
				Build()
			Expect(err).To(MatchError("logger is mandatory"))
			Expect(tool).To(BeNil())
		})

		It("Can't be created without an issuer", func() {
			tool, err := NewDiscoveryTool().
				SetLogger(logger).
				Build()
			Expect(err).To(MatchError("issuer is mandatory"))
			Expect(tool).To(BeNil())
		})
	})

	Describe("Discovery", func() {
		makeServer := func(metadata string, code int) {
			server.RouteToHandler(
				http.MethodGet,
				"/.well-known/oauth-authorization-server",
				RespondWith(code, metadata, http.Header{"Content-Type": {"application/json"}}),
			)
		}

		makeMetadata := func(issuer, tokenEndpoint, authEndpoint, deviceEndpoint string) string {
			doc := map[string]any{
				"issuer":                        issuer,
				"token_endpoint":                tokenEndpoint,
				"authorization_endpoint":        authEndpoint,
				"device_authorization_endpoint": deviceEndpoint,
			}
			data, err := json.Marshal(doc)
			Expect(err).ToNot(HaveOccurred())
			return string(data)
		}

		It("Successfully discovers endpoints from issuer URL", func() {
			makeServer(
				makeMetadata(
					"https://example.com/auth",
					"https://example.com/auth/token",
					"https://example.com/auth/authorize",
					"https://example.com/auth/device",
				),
				http.StatusOK,
			)

			tool, err := NewDiscoveryTool().
				SetLogger(logger).
				SetIssuer(server.URL()).
				SetInsecure(true).
				Build()
			Expect(err).ToNot(HaveOccurred())
			Expect(tool).ToNot(BeNil())

			serverMetadata, err := tool.Discover(ctx)

			Expect(err).ToNot(HaveOccurred())
			Expect(serverMetadata).ToNot(BeNil())
			Expect(serverMetadata.Issuer).To(Equal("https://example.com/auth"))
			Expect(serverMetadata.TokenEndpoint).To(Equal("https://example.com/auth/token"))
			Expect(serverMetadata.AuthorizationEndpoint).To(Equal("https://example.com/auth/authorize"))
			Expect(serverMetadata.DeviceAuthorizationEndpoint).To(Equal("https://example.com/auth/device"))
		})

		It("Returns error when discovery endpoint fails", func() {
			server.RouteToHandler(
				http.MethodGet,
				"/.well-known/oauth-authorization-server",
				RespondWith(http.StatusNotFound, ""),
			)

			tool, err := NewDiscoveryTool().
				SetLogger(logger).
				SetIssuer(server.URL()).
				SetInsecure(true).
				Build()
			Expect(err).ToNot(HaveOccurred())

			metadata, err := tool.Discover(ctx)
			Expect(err).To(MatchError(fmt.Sprintf(
				"failed to fetch metadata from '%s/.well-known/oauth-authorization-server': 404 Not Found",
				server.URL(),
			)))
			Expect(metadata).To(BeNil())
		})

		It("Returns error for invalid issuer URL", func() {
			tool, err := NewDiscoveryTool().
				SetLogger(logger).
				SetIssuer("://invalid-url").
				SetInsecure(true).
				Build()
			Expect(err).ToNot(HaveOccurred())

			metadata, err := tool.Discover(ctx)

			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("invalid issuer URL"))
			Expect(metadata).To(BeNil())
		})

		It("Returns error when discovery document is missing required fields", func() {
			incompleteDoc := `{"issuer": "https://example.com"}`
			makeServer(incompleteDoc, 200)

			tool, err := NewDiscoveryTool().
				SetLogger(logger).
				SetIssuer(server.URL()).
				SetInsecure(true).
				Build()
			Expect(err).ToNot(HaveOccurred())

			metadata, err := tool.Discover(ctx)

			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("discovery document missing required 'token_endpoint' field"))
			Expect(metadata).To(BeNil())
		})

		It("Returns error when discovery document has invalid JSON", func() {
			invalidDoc := `{"issuer": "https://example.com", "token_endpoint":`
			makeServer(invalidDoc, 200)

			tool, err := NewDiscoveryTool().
				SetLogger(logger).
				SetIssuer(server.URL()).
				SetInsecure(true).
				Build()
			Expect(err).ToNot(HaveOccurred())

			metadata, err := tool.Discover(ctx)

			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("failed to parse metadata"))
			Expect(metadata).To(BeNil())
		})
	})
})
