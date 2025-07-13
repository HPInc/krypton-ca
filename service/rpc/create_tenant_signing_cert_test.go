package rpc

import (
	"reflect"
	"testing"

	pb "github.com/HPInc/krypton-ca/caprotos"
	"github.com/google/uuid"
	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
)

var (
	testTenantID, testTenantName, testTenantDomain string
)

func assertEqual(t *testing.T, a interface{}, b interface{}) {
	if a == b {
		return
	}
	caLogger.Error("assertEqual failed",
		zap.Any("Received:", a),
		zap.Any("Type:", reflect.TypeOf(a)),
		zap.Any("Expected:", b),
		zap.Any("Type:", reflect.TypeOf(b)),
	)
}

func init() {
	testTenantID = uuid.New().String()
	testTenantName = "Unreliable Corporation"
	testTenantDomain = "unreliable.com"
}

func TestCreateTenantSigningCertificate(t *testing.T) {
	createRequest := &pb.CreateTenantSigningCertificateRequest{
		Header:     newCaProtocolHeader(),
		Version:    CaProtocolVersion,
		Tid:        uuid.New().String(),
		Name:       testTenantName,
		DomainName: testTenantDomain,
	}

	response, err := gClient.CreateTenantSigningCertificate(gCtx, createRequest)
	if err != nil {
		caLogger.Error("TestCreateTenantSigningCertificate: RPC failed",
			zap.Error(err))
		t.Fail()
		return
	}

	assertEqual(t, response.Header.Status, uint32(codes.OK))
	caLogger.Info("Response from certificate authority",
		zap.Any("Response", response))
}

// Attempt to create a tenant signing certificate without specifying a tenant ID.
func TestCreateTenantSigningCertificate_NoTenantID(t *testing.T) {
	createRequest := &pb.CreateTenantSigningCertificateRequest{
		Header:     newCaProtocolHeader(),
		Version:    CaProtocolVersion,
		Name:       testTenantName,
		DomainName: testTenantDomain,
	}

	response, err := gClient.CreateTenantSigningCertificate(gCtx, createRequest)
	if err != nil {
		caLogger.Error("TestCreateTenantSigningCertificate_NoTenantID: RPC failed",
			zap.Error(err))
		t.Fail()
		return
	}

	assertEqual(t, response.Header.Status, uint32(codes.InvalidArgument))
	caLogger.Info("Response from certificate authority",
		zap.Any("Response", response))
}

// Attempt to create a tenant signing certificate without specifying a tenant name.
func TestCreateTenantSigningCertificate_NoTenantName(t *testing.T) {
	createRequest := &pb.CreateTenantSigningCertificateRequest{
		Header:     newCaProtocolHeader(),
		Version:    CaProtocolVersion,
		Tid:        testTenantName,
		DomainName: testTenantDomain,
	}

	response, err := gClient.CreateTenantSigningCertificate(gCtx, createRequest)
	if err != nil {
		caLogger.Error("TestCreateTenantSigningCertificate_NoTenantName: RPC failed",
			zap.Error(err))
		t.Fail()
		return
	}

	assertEqual(t, response.Header.Status, uint32(codes.InvalidArgument))
	caLogger.Info("Response from certificate authority",
		zap.Any("Response", response))
}

// Attempt to create a tenant signing certificate using an invalid protocol version.
func TestCreateTenantSigningCertificate_InvalidProtocol(t *testing.T) {
	createRequest := &pb.CreateTenantSigningCertificateRequest{
		Header:     newCaInvalidVersionProtocolHeader(),
		Version:    "v1",
		Tid:        testTenantID,
		Name:       testTenantName,
		DomainName: testTenantDomain,
	}

	response, err := gClient.CreateTenantSigningCertificate(gCtx, createRequest)
	if err != nil {
		caLogger.Error("TestCreateTenantSigningCertificate_InvalidProtocol: RPC failed",
			zap.Error(err))
		t.Fail()
		return
	}

	assertEqual(t, response.Header.Status, uint32(codes.InvalidArgument))
	caLogger.Info("Response from certificate authority",
		zap.Any("Response", response))
}
