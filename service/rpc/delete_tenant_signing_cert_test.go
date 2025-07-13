package rpc

import (
	"testing"

	pb "github.com/HPInc/krypton-ca/caprotos"
	"github.com/google/uuid"
	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
)

func TestDeleteTenantSigningCertificate(t *testing.T) {
	// Create a new tenant signing certificate.
	createRequest := &pb.CreateTenantSigningCertificateRequest{
		Header:     newCaProtocolHeader(),
		Version:    CaProtocolVersion,
		Tid:        uuid.New().String(),
		Name:       "ToBeDeleted Corporation",
		DomainName: "tobedeleted.com",
	}

	response, err := gClient.CreateTenantSigningCertificate(gCtx, createRequest)
	if err != nil {
		caLogger.Error("CreateTeanantSigningCertificate RPC failed", zap.Error(err))
		t.Fail()
		return
	}

	assertEqual(t, response.Header.Status, uint32(codes.OK))
	caLogger.Info("Response from certificate authority",
		zap.Any("Response", response))

	// Attempt to delete the newly created tenant signing certificate.
	deleteRequest := &pb.DeleteTenantSigningCertificateRequest{
		Header:  newCaProtocolHeader(),
		Version: CaProtocolVersion,
		Tid:     createRequest.Tid,
	}

	deleteResponse, err := gClient.DeleteTenantSigningCertificate(gCtx, deleteRequest)
	if err != nil {
		caLogger.Error("DeleteTenantSigningCertificate RPC failed",
			zap.Error(err))
		t.Fail()
		return
	}

	assertEqual(t, deleteResponse.Header.Status, uint32(codes.OK))
	caLogger.Info("Response from certificate authority",
		zap.Any("Response", deleteResponse))
}

func TestDeleteTenantSigningCertificate_NoTenantID(t *testing.T) {
	deleteRequest := &pb.DeleteTenantSigningCertificateRequest{
		Header:  newCaProtocolHeader(),
		Version: CaProtocolVersion,
	}

	deleteResponse, err := gClient.DeleteTenantSigningCertificate(gCtx, deleteRequest)
	if err != nil {
		caLogger.Error("TestDeleteTenantSigningCertificate_NoTenantID: RPC failed",
			zap.Error(err))
		t.Fail()
		return
	}

	assertEqual(t, deleteResponse.Header.Status, uint32(codes.InvalidArgument))
	caLogger.Info("Response from certificate authority",
		zap.Any("Response", deleteResponse))
}

func TestDeleteTenantSigningCertificate_InvalidTenant(t *testing.T) {
	deleteRequest := &pb.DeleteTenantSigningCertificateRequest{
		Header:  newCaProtocolHeader(),
		Version: CaProtocolVersion,
		Tid:     uuid.New().String(),
	}

	deleteResponse, err := gClient.DeleteTenantSigningCertificate(gCtx, deleteRequest)
	if err != nil {
		caLogger.Error("TestDeleteTenantSigningCertificate_InvalidTenant: RPC failed",
			zap.Error(err))
		t.Fail()
		return
	}

	assertEqual(t, deleteResponse.Header.Status, uint32(codes.Internal))
	caLogger.Info("Response from certificate authority",
		zap.Any("Response", deleteResponse))
}
