// package github.com/HPInc/krypton-ca/service/rpc
// Author: Mahesh Unnikrishnan
// Component: Krypton Certificate Authority
// (C) HP Development Company, LP
// Purpose:
// Initializes and configures the RPC server for the Krypton CA service.
package rpc

import (
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/HPInc/krypton-ca/service/certmgr/kms_providers"
	"github.com/HPInc/krypton-ca/service/config"
	"github.com/HPInc/krypton-ca/service/metrics"
	"go.uber.org/zap"

	pb "github.com/HPInc/krypton-ca/caprotos"
	"google.golang.org/grpc"
	"google.golang.org/grpc/keepalive"
)

var (
	caLogger        *zap.Logger
	rpcServerConfig *config.Server
)

const (
// TODO: re-enable TLS after certificate generation is in place.
// caCertPath    = "config/ca.pem"
// caKeyFilePath = "config/ca.key"
)

// CertificateAuthorityServer - Connection and other state information for the HP
// Certificate authority.
type CertificateAuthorityServer struct {
	// Certificate authority gRPC server.
	cagRPCServer *grpc.Server

	pb.UnimplementedCertificateAuthorityServer

	// KMS (Key Management Service) provider used to sign certificates.
	kmsProvider kms_providers.KmsProvider

	// Signal handling to support SIGTERM and SIGINT.
	errChannel  chan error
	stopChannel chan os.Signal
}

// Init - initialize and start the Krypton Certificate Authority's gRPC server
func Init(logger *zap.Logger, serverConfig *config.Server,
	kmsProvider kms_providers.KmsProvider) error {
	caLogger = logger
	rpcServerConfig = serverConfig

	// Create a new certificate authority gRPC server instance.
	s := &CertificateAuthorityServer{
		kmsProvider: kmsProvider,
	}
	err := s.NewServer()
	if err != nil {
		caLogger.Error("Unable to configure gRPC server. Error!",
			zap.Error(err),
		)
		fmt.Println("Failed to configure gRPC server. Exiting!")
		return err
	}

	// Start serving requests at the gRPC endpoint.
	err = s.startServing()
	if err != nil {
		caLogger.Error("CA gRPC server failed to start up.",
			zap.String("Hostname:", rpcServerConfig.Host),
			zap.Int("Port:", rpcServerConfig.RpcPort),
			zap.Error(err),
		)
		fmt.Println("Failed to start CA gRPC server. Exiting!")
		return err
	}

	s.awaitTermination()
	return nil
}

// NewServer creates and registers a new gRPC server instance for the CA.
func (s *CertificateAuthorityServer) NewServer() error {
	// Handle SIGTERM and SIGINT.
	s.errChannel = make(chan error)
	s.stopChannel = make(chan os.Signal, 1)
	signal.Notify(s.stopChannel, syscall.SIGINT, syscall.SIGTERM)

	var defaultKeepAliveParams = keepalive.ServerParameters{
		Time:    20 * time.Second,
		Timeout: 5 * time.Second,
	}

	// TODO: re-enable TLS after certificate generation is in place.
	/*
		creds, err := credentials.NewServerTLSFromFile(caCertPath, caKeyFilePath)
		if err != nil {
			caLogger.Error("Failed to generate credentials for TLS!",
				zap.Error(err),
			)
			return err
		}
	*/

	// Initialize and register the gRPC server.
	s.cagRPCServer = grpc.NewServer(
		//	grpc.Creds(creds),
		grpc.KeepaliveParams(defaultKeepAliveParams),
		grpc.UnaryInterceptor(unaryInterceptor),
	)

	pb.RegisterCertificateAuthorityServer(s.cagRPCServer, s)
	return nil
}

// Start listening on the configured port. Creates a separate goroutine to
// serve gRPC requests.
func (s *CertificateAuthorityServer) startServing() error {
	metrics.RegisterPrometheusMetrics()

	go s.listenAndServe()
	return nil
}

// Goroutine to listen for and serve gRPC requests.
func (s *CertificateAuthorityServer) listenAndServe() {
	// Start the server and listen to the specified port.
	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", rpcServerConfig.RpcPort))
	if err != nil {
		caLogger.Error("Failed to initialize a listener for the gRPC server!",
			zap.Error(err),
		)
		s.errChannel <- err
		return
	}

	// Start accepting incoming connection requests.
	err = s.cagRPCServer.Serve(listener)
	if err != nil {
		caLogger.Error("Failed to start serving incoming gRPC requests!",
			zap.Error(err),
		)
		s.errChannel <- err
		return
	}

	caLogger.Info("HP CA: Serving gRPC requests.",
		zap.Int("Port", rpcServerConfig.RpcPort),
	)
}

// Wait for a signal to shutdown the gRPC server and cleanup.
func (s *CertificateAuthorityServer) awaitTermination() {
	// Block until we receive either an OS signal, or encounter a server
	// fatal error and need to terminate.
	select {
	case err := <-s.errChannel:
		caLogger.Error("HP CA: Shutting down due to a fatal error.",
			zap.Error(err),
		)
	case sig := <-s.stopChannel:
		caLogger.Error("HP CA: Received an OS signal and shutting down.",
			zap.String("Signal:", sig.String()),
		)
	}

	// Cleanup.
	s.cagRPCServer.GracefulStop()
}
