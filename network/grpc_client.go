/*
Copyright (c) 2025 Red Hat Inc.

Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the
License. You may obtain a copy of the License at

  http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an
"AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific
language governing permissions and limitations under the License.
*/

package network

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"path/filepath"
	"time"

	"github.com/innabox/fulfillment-common/auth"
	"github.com/spf13/pflag"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	experiementalcredentials "google.golang.org/grpc/experimental/credentials"
	"google.golang.org/grpc/keepalive"
)

// GrpcClientBuilder contains the data and logic needed to create a gRPC client. Don't create instances of this object
// directly, use the NewClient function instead.
type GrpcClientBuilder struct {
	logger      *slog.Logger
	network     string
	Address     string
	plaintext   bool
	insecure    bool
	caPool      *x509.CertPool
	tokenSource auth.TokenSource
	keepAlive   time.Duration
}

// NewClient creates a builder that can then used to configure and create a gRPC client.
func NewClient() *GrpcClientBuilder {
	return &GrpcClientBuilder{}
}

// SetLogger sets the logger that the client will use to send messages to the log. This is mandatory.
func (b *GrpcClientBuilder) SetLogger(value *slog.Logger) *GrpcClientBuilder {
	b.logger = value
	return b
}

// SetFlags sets the command line flags that should be used to configure the client.
//
// The name is used to select the options when there are multiple clients. For example, if it is 'API' then it will only
// take into accounts the flags starting with '--api'.
//
// This is optional.
func (b *GrpcClientBuilder) SetFlags(flags *pflag.FlagSet, name string) *GrpcClientBuilder {
	if flags == nil {
		return b
	}

	var (
		flag string
		err  error
	)
	failure := func() {
		b.logger.Error(
			"Failed to get flag value",
			slog.String("flag", flag),
			slog.Any("error", err),
		)
	}

	// Server network:
	flag = grpcClientFlagName(name, grpcClientServerNetworkFlagSuffix)
	serverNetworkValue, err := flags.GetString(flag)
	if err != nil {
		failure()
	} else {
		b.SetNetwork(serverNetworkValue)
	}

	// Server address:
	flag = grpcClientFlagName(name, grpcClientServerAddrFlagSuffix)
	serverAddrValue, err := flags.GetString(flag)
	if err != nil {
		failure()
	} else {
		b.SetAddress(serverAddrValue)
	}

	// Server plaintext:
	flag = grpcClientFlagName(name, grpcClientServerPlaintextFlagSuffix)
	serverPlaintextValue, err := flags.GetBool(flag)
	if err != nil {
		failure()
	} else {
		b.SetPlaintext(serverPlaintextValue)
	}

	// Server insecure:
	flag = grpcClientFlagName(name, grpcClientServerInsecureFlagSuffix)
	serverInsecureValue, err := flags.GetBool(flag)
	if err != nil {
		failure()
	} else {
		b.SetInsecure(serverInsecureValue)
	}

	// Keep alive:
	flag = grpcClientFlagName(name, grpcClientKeepAliveFlagSuffix)
	keepAliveValue, err := flags.GetDuration(flag)
	if err != nil {
		failure()
	} else {
		b.SetKeepAlive(keepAliveValue)
	}

	return b
}

// SetNetwork sets the server network.
func (b *GrpcClientBuilder) SetNetwork(value string) *GrpcClientBuilder {
	b.network = value
	return b
}

// SetAddress sets the server address.
func (b *GrpcClientBuilder) SetAddress(value string) *GrpcClientBuilder {
	b.Address = value
	return b
}

// SetPlaintext when set to true configures the client for a server that doesn't use TLS. The default is false.
func (b *GrpcClientBuilder) SetPlaintext(value bool) *GrpcClientBuilder {
	b.plaintext = value
	return b
}

// SetInsecure when set to true configures the client for use TLS but to not verify the certificate presented
// by the server. This shouldn't be used in production environments. The default is false.
func (b *GrpcClientBuilder) SetInsecure(value bool) *GrpcClientBuilder {
	b.insecure = value
	return b
}

// SetCaPool sets the certificate pool that contains the certificates of the certificate authorities that are trusted
// when connecting using TLS. This is optional, and the default is to use trust the certificate authorities trusted by
// the operating system.
func (b *GrpcClientBuilder) SetCaPool(value *x509.CertPool) *GrpcClientBuilder {
	b.caPool = value
	return b
}

// SetTokenSource sets the token source that the client will use to authenticate to the server. This is optional, by
// default no authentication credentials are sent.
func (b *GrpcClientBuilder) SetTokenSource(value auth.TokenSource) *GrpcClientBuilder {
	b.tokenSource = value
	return b
}

// SetKeepAlive sets the keep alive interval. This is optional, by default no keep alive is used.
func (b *GrpcClientBuilder) SetKeepAlive(value time.Duration) *GrpcClientBuilder {
	b.keepAlive = value
	return b
}

// Build uses the data stored in the builder to create a new network client.
func (b *GrpcClientBuilder) Build() (result *grpc.ClientConn, err error) {
	// Check parameters:
	if b.logger == nil {
		err = errors.New("logger is mandatory")
		return
	}
	if b.network == "" {
		err = errors.New("server network is mandatory")
		return
	}
	if b.Address == "" {
		err = errors.New("server address is mandatory")
		return
	}
	if b.keepAlive < 0 {
		err = fmt.Errorf("keep alive interval should be positive, but it is %s", b.keepAlive)
		return
	}

	// Calculate the endpoint:
	var endpoint string
	switch b.network {
	case "tcp":
		endpoint = fmt.Sprintf("dns:///%s", b.Address)
	case "unix":
		if filepath.IsAbs(b.Address) {
			endpoint = fmt.Sprintf("unix://%s", b.Address)
		} else {
			endpoint = fmt.Sprintf("unix:%s", b.Address)
		}
	default:
		err = fmt.Errorf("unknown network '%s'", b.network)
		return
	}

	// Set the default CA pool:
	caPool := b.caPool
	if caPool == nil {
		caPool, err = NewCertPool().
			SetLogger(b.logger).
			AddSystemFiles(true).
			AddKubernertesFiles(true).
			Build()
		if err != nil {
			err = fmt.Errorf("failed to build CA pool: %w", err)
			return
		}
	}

	// Set the TLS options:
	var options []grpc.DialOption
	var transportCredentials credentials.TransportCredentials
	if b.plaintext {
		transportCredentials = insecure.NewCredentials()
	} else {
		tlsConfig := &tls.Config{}
		if b.insecure {
			tlsConfig.InsecureSkipVerify = true
		}
		tlsConfig.RootCAs = caPool

		// TODO: This should have been the non-experimental package, but we need to use this one because
		// currently the OpenShift router doesn't seem to support ALPN, and the regular credentials package
		// requires it since version 1.67. See here for details:
		//
		// https://github.com/grpc/grpc-go/issues/434
		// https://github.com/grpc/grpc-go/pull/7980
		//
		// Is there a way to configure the OpenShift router to avoid this?
		transportCredentials = experiementalcredentials.NewTLSWithALPNDisabled(tlsConfig)
	}
	if transportCredentials != nil {
		options = append(options, grpc.WithTransportCredentials(transportCredentials))
	}

	// Set the token options:
	if b.tokenSource != nil {
		var tokenCredentials credentials.PerRPCCredentials
		tokenCredentials, err = auth.NewTokenCredentials().
			SetLogger(b.logger).
			SetSource(b.tokenSource).
			Build()
		if err != nil {
			err = fmt.Errorf("failed to create token credentials: %w", err)
			return
		}
		options = append(options, grpc.WithPerRPCCredentials(tokenCredentials))
	}

	// Set the keep alive options:
	if b.keepAlive > 0 {
		options = append(options, grpc.WithKeepaliveParams(keepalive.ClientParameters{
			Time: b.keepAlive,
		}))
	}

	// Create the client:
	result, err = grpc.NewClient(endpoint, options...)
	return
}

// Common client names:
const (
	GrpcClientName = "gRPC"
	HttpClientName = "HTTP"
)
