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
	"context"
	"crypto/tls"
	"net"
	"time"

	. "github.com/onsi/ginkgo/v2/dsl/core"
	. "github.com/onsi/gomega"
	"google.golang.org/grpc"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"

	"github.com/innabox/fulfillment-common/testing"
)

var _ = Describe("gRPC client", func() {
	var (
		ctx    context.Context
		cancel context.CancelFunc
	)

	BeforeEach(func() {
		ctx, cancel = context.WithTimeout(context.Background(), 30*time.Second)
		DeferCleanup(cancel)
	})

	It("Can't be created without a logger", func() {
		client, err := NewGrpcClient().
			SetAddress("127.0.0.1:0").
			Build()
		Expect(err).To(HaveOccurred())
		Expect(client).To(BeNil())
		msg := err.Error()
		Expect(msg).To(ContainSubstring("logger"))
		Expect(msg).To(ContainSubstring("mandatory"))
	})

	It("Can't be created without an address", func() {
		client, err := NewGrpcClient().
			SetLogger(logger).
			Build()
		Expect(err).To(HaveOccurred())
		Expect(client).To(BeNil())
		msg := err.Error()
		Expect(msg).To(ContainSubstring("address"))
		Expect(msg).To(ContainSubstring("mandatory"))
	})

	It("Can connect to a real gRPC server using plaintext", func() {
		// Create a test gRPC server with a random port:
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		Expect(err).ToNot(HaveOccurred())

		// Create and start the gRPC server with health service:
		server := grpc.NewServer()
		healthServer := health.NewServer()
		healthpb.RegisterHealthServer(server, healthServer)
		healthServer.SetServingStatus("", healthpb.HealthCheckResponse_SERVING)
		go func() {
			defer GinkgoRecover()
			_ = server.Serve(listener)
		}()
		defer server.Stop()

		// Create the client:
		client, err := NewGrpcClient().
			SetLogger(logger).
			SetAddress(listener.Addr().String()).
			SetPlaintext(true).
			Build()
		Expect(err).ToNot(HaveOccurred())
		Expect(client).ToNot(BeNil())
		defer func() {
			err := client.Close()
			Expect(err).ToNot(HaveOccurred())
		}()

		// Verify the connection by calling the health service:
		healthClient := healthpb.NewHealthClient(client)
		response, err := healthClient.Check(ctx, &healthpb.HealthCheckRequest{
			Service: "",
		})
		Expect(err).ToNot(HaveOccurred())
		Expect(response).ToNot(BeNil())
		Expect(response.Status).To(Equal(healthpb.HealthCheckResponse_SERVING))
	})

	It("Can connect to a real gRPC server using TLS", func() {
		// Create a test gRPC server with TLS and a random port
		tcpListener, err := net.Listen("tcp", "127.0.0.1:0")
		Expect(err).ToNot(HaveOccurred())
		tlsListener := tls.NewListener(tcpListener, &tls.Config{
			Certificates: []tls.Certificate{
				testing.LocalhostCertificate(),
			},
		})

		// Create and start the gRPC server with health service:
		server := grpc.NewServer()
		healthServer := health.NewServer()
		healthpb.RegisterHealthServer(server, healthServer)
		healthServer.SetServingStatus("", healthpb.HealthCheckResponse_SERVING)
		go func() {
			defer GinkgoRecover()
			_ = server.Serve(tlsListener)
		}()
		defer server.Stop()

		// Create the client:
		client, err := NewGrpcClient().
			SetLogger(logger).
			SetAddress(tcpListener.Addr().String()).
			SetInsecure(true).
			Build()
		Expect(err).ToNot(HaveOccurred())
		Expect(client).ToNot(BeNil())
		defer func() {
			err := client.Close()
			Expect(err).ToNot(HaveOccurred())
		}()

		// Verify the connection by calling the health service:
		healthClient := healthpb.NewHealthClient(client)
		response, err := healthClient.Check(ctx, &healthpb.HealthCheckRequest{
			Service: "",
		})
		Expect(err).ToNot(HaveOccurred())
		Expect(response).ToNot(BeNil())
		Expect(response.Status).To(Equal(healthpb.HealthCheckResponse_SERVING))
	})

	It("Fails to connect to non-existent server", func() {
		// Create a client that tries to connect to a non existent server:
		client, err := NewGrpcClient().
			SetLogger(logger).
			SetAddress("127.0.0.1:0").
			SetPlaintext(true).
			Build()
		Expect(err).ToNot(HaveOccurred())
		Expect(client).ToNot(BeNil())
		defer func() {
			err := client.Close()
			Expect(err).ToNot(HaveOccurred())
		}()

		// Try to call the health service, and verify that it fails:
		healthClient := healthpb.NewHealthClient(client)
		_, err = healthClient.Check(ctx, &healthpb.HealthCheckRequest{
			Service: "",
		})
		Expect(err).To(HaveOccurred())
	})

	It("Can use custom interceptors", func() {
		// Create a test gRPC server with a random port:
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		Expect(err).ToNot(HaveOccurred())

		// Create and start the gRPC server with health service
		server := grpc.NewServer()
		healthServer := health.NewServer()
		healthpb.RegisterHealthServer(server, healthServer)
		healthServer.SetServingStatus("", healthpb.HealthCheckResponse_SERVING)
		go func() {
			defer GinkgoRecover()
			_ = server.Serve(listener)
		}()
		defer server.Stop()

		// Create a custom interceptor that adds a header
		called := false
		interceptor := func(ctx context.Context, method string, request, reply any, cc *grpc.ClientConn,
			invoker grpc.UnaryInvoker, opts ...grpc.CallOption) error {
			called = true
			return invoker(ctx, method, request, reply, cc, opts...)
		}

		// Create the client:
		client, err := NewGrpcClient().
			SetLogger(logger).
			SetAddress(listener.Addr().String()).
			SetPlaintext(true).
			AddUnaryInterceptor(interceptor).
			Build()
		Expect(err).ToNot(HaveOccurred())
		Expect(client).ToNot(BeNil())
		defer func() {
			err := client.Close()
			Expect(err).ToNot(HaveOccurred())
		}()

		// Verify the connection and that the interceptor was called:
		healthClient := healthpb.NewHealthClient(client)
		response, err := healthClient.Check(ctx, &healthpb.HealthCheckRequest{
			Service: "",
		})
		Expect(err).ToNot(HaveOccurred())
		Expect(response).ToNot(BeNil())
		Expect(response.Status).To(Equal(healthpb.HealthCheckResponse_SERVING))
		Expect(called).To(BeTrue())
	})
})
