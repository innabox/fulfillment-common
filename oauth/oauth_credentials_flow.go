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
	"log/slog"

	"github.com/innabox/fulfillment-common/auth"
)

type credentialsFlow struct {
	source *TokenSource
	logger *slog.Logger
}

func (f *credentialsFlow) run(ctx context.Context) (result *auth.Token, err error) {
	tokenRequest := tokenEndpointRequest{
		ClientId:     f.source.clientId,
		ClientSecret: f.source.clientSecret,
		GrantType:    "client_credentials",
		Scope:        f.source.scopes,
	}
	tokenResponse, err := f.source.sendTokenForm(ctx, tokenRequest)
	if err != nil {
		f.logger.ErrorContext(
			ctx,
			"Failed to request token",
			slog.String("url", f.source.tokenEndpoint),
			slog.Any("request", tokenRequest),
			slog.Any("error", err),
		)
		return
	}
	f.logger.DebugContext(
		ctx,
		"Received token response",
		slog.Any("response", tokenRequest),
		slog.Any("request", tokenResponse),
	)
	result = &auth.Token{
		Access:  tokenResponse.AccessToken,
		Refresh: tokenResponse.RefreshToken,
		Expiry:  f.source.secondsToTime(tokenResponse.ExpiresIn),
	}
	return
}
