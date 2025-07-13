package rpc

import (
	"testing"

	pb "github.com/HPInc/krypton-ca/caprotos"
	"github.com/google/uuid"
	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
)

func TestGetTenantSigningCertificate(t *testing.T) {
	createRequest := &pb.GetTenantSigningCertificateRequest{
		Header:  newCaProtocolHeader(),
		Version: CaProtocolVersion,
		Tid:     testTenantID,
	}

	response, err := gClient.GetTenantSigningCertificate(gCtx, createRequest)
	if err != nil {
		caLogger.Error("TestGetTenantSigningCertificate: RPC failed",
			zap.Error(err))
		t.Fail()
		return
	}

	assertEqual(t, response.Header.Status, uint32(codes.OK))
	caLogger.Info("Response from certificate authority:",
		zap.Any("Response", response))
}

func TestGetTenantSigningCertificate_UnknownTenantID(t *testing.T) {
	createRequest := &pb.GetTenantSigningCertificateRequest{
		Header:  newCaProtocolHeader(),
		Version: CaProtocolVersion,
		Tid:     uuid.New().String(),
	}

	response, err := gClient.GetTenantSigningCertificate(gCtx, createRequest)
	if err != nil {
		caLogger.Error("TestGetTenantSigningCertificate_UnknownTenantID: RPC failed",
			zap.Error(err))
		t.Fail()
		return
	}

	assertEqual(t, response.Header.Status, uint32(codes.Internal))
	caLogger.Info("Response from certificate authority:",
		zap.Any("Response", response))
}

func TestGetTenantSigningCertificate_NoTenantID(t *testing.T) {
	createRequest := &pb.GetTenantSigningCertificateRequest{
		Header:  newCaProtocolHeader(),
		Version: CaProtocolVersion,
	}

	response, err := gClient.GetTenantSigningCertificate(gCtx, createRequest)
	if err != nil {
		caLogger.Error("TestGetTenantSigningCertificate_NoTenantID: RPC failed %v",
			zap.Error(err))
		t.Fail()
		return
	}

	assertEqual(t, response.Header.Status, uint32(codes.InvalidArgument))
	caLogger.Info("Response from certificate authority",
		zap.Any("Response", response))
}
