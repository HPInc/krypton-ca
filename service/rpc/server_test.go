package rpc

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"testing"

	"github.com/HPInc/krypton-ca/service/certmgr"
	"github.com/HPInc/krypton-ca/service/certmgr/kms_providers"
	"github.com/HPInc/krypton-ca/service/common"
	"github.com/HPInc/krypton-ca/service/config"
	"github.com/google/uuid"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/types/known/timestamppb"

	pb "github.com/HPInc/krypton-ca/caprotos"
)

const (
	bufSize                 = 1024 * 1024
	ENV_KMS_PROVIDER        = "KMS_PROVIDER"
	ENV_CERT_STORE_PROVIDER = "CERT_STORE_PROVIDER"
)

var (
	gListener      *bufconn.Listener
	gClient        pb.CertificateAuthorityClient
	gConnection    *grpc.ClientConn
	gCtx           context.Context
	grpcTestServer *grpc.Server
)

func newCaProtocolHeader() *pb.CaRequestHeader {
	return &pb.CaRequestHeader{
		ProtocolVersion: "v1",
		RequestId:       uuid.New().String(),
		RequestTime:     timestamppb.Now(),
	}
}

func newCaInvalidVersionProtocolHeader() *pb.CaRequestHeader {
	return &pb.CaRequestHeader{
		ProtocolVersion: "vx",
		RequestId:       uuid.New().String(),
		RequestTime:     timestamppb.Now(),
	}
}

func bufDialer(context.Context, string) (net.Conn, error) {
	return gListener.Dial()
}

func shutdownLogger() {
	_ = caLogger.Sync()
}

func initConnection() bool {
	var err error
	gCtx = context.Background()
	gConnection, err = grpc.DialContext(gCtx, "bufnet",
		grpc.WithContextDialer(bufDialer),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		fmt.Printf("Failed to init bufnet connection: %v\n", err)
		return false
	}
	gClient = pb.NewCertificateAuthorityClient(gConnection)
	return true
}

func initTestRpcServer(logger *zap.Logger,
	provider kms_providers.KmsProvider) {
	caLogger = logger

	gListener = bufconn.Listen(bufSize)
	grpcTestServer = grpc.NewServer()

	s := &CertificateAuthorityServer{
		kmsProvider: provider,
	}
	err := s.NewServer()
	if err != nil {
		caLogger.Error("Unable to configure certificate authority server!",
			zap.Error(err),
		)
		_ = caLogger.Sync()
		os.Exit(2)
	}

	pb.RegisterCertificateAuthorityServer(grpcTestServer, s)

	go func() {
		err := grpcTestServer.Serve(gListener)
		if err != nil {
			_ = caLogger.Sync()
			log.Fatalf("CA test: Server exited with error: %v", err)
		}
	}()

	if false == initConnection() {
		_ = caLogger.Sync()
		log.Fatalf("CA test: Failed to initialize test environment. Exiting!")
	}
}

func shutdownTestRpcServer() {
	grpcTestServer.GracefulStop()
}

func initTestEnvironment() error {
	createRequest := &pb.CreateTenantSigningCertificateRequest{
		Header:     newCaProtocolHeader(),
		Version:    CaProtocolVersion,
		Tid:        testTenantID,
		Name:       testTenantName,
		DomainName: testTenantDomain,
	}

	response, err := gClient.CreateTenantSigningCertificate(gCtx, createRequest)
	if err != nil {
		log.Fatalf("TestCreateTenantSigningCertificate: RPC failed %v", err)
		return err
	}

	if response.Header.Status != uint32(codes.OK) {
		log.Fatalf("Response from certificate authority: %+v\n", response)
		return errors.New("failed to create tenant signing certifiate!")
	}

	return nil
}

func init() {
	// Parse the command line flags.
	flag.Parse()
}

func TestMain(m *testing.M) {
	// Initialize logging for the test run.
	logger, err := zap.NewProduction(zap.AddCaller())
	if err != nil {
		fmt.Println("Failed to intialize structured logging for the RPC test server!")
		os.Exit(2)
	}
	caLogger = logger

	// Read and parse the configuration file.
	cfgMgr := config.NewConfigMgr(caLogger, common.ServiceName)
	if !cfgMgr.Load(true) {
		caLogger.Error("Failed to load configuration. Exiting!")
		shutdownLogger()
		os.Exit(2)
	}

	// Initialize the certificate authority.
	certProvider, err := certmgr.Init(caLogger, cfgMgr)
	if err != nil {
		caLogger.Error("Failed to initialize the certificate authority!",
			zap.Error(err),
		)
		shutdownLogger()
		os.Exit(2)
	}

	// Initialize a test RPC server using which the unit tests run.
	initTestRpcServer(caLogger, certProvider)
	err = initTestEnvironment()
	if err != nil {
		fmt.Println("Failed to initialize test environment.")
		shutdownTestRpcServer()
		shutdownLogger()
		os.Exit(2)
	}
	retCode := m.Run()

	// Cleanup after ourselves.
	shutdownTestRpcServer()
	shutdownLogger()
	fmt.Println("Finished running the certificate authority RPC server unit tests!")
	os.Exit(retCode)
}
