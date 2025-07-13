package rpc

import (
	"testing"

	pb "github.com/HPInc/krypton-ca/caprotos"
	"github.com/HPInc/krypton-ca/service/common"
	"github.com/google/uuid"
	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
)

func TestCreateDeviceCertificate(t *testing.T) {
	csr, err := common.CreateDeviceCertificateSigningRequest()
	if err != nil {
		caLogger.Error("TestCreateDeviceCertificate: Error creating CSR",
			zap.Error(err),
		)
		t.Fail()
		return
	}

	createRequest := &pb.CreateDeviceCertificateRequest{
		Header:  newCaProtocolHeader(),
		Version: CaProtocolVersion,
		Tid:     testTenantID,
		Csr:     csr,
	}

	response, err := gClient.CreateDeviceCertificate(gCtx, createRequest)
	if err != nil {
		caLogger.Error("TestCreateDeviceCertificate: RPC failed",
			zap.Error(err),
		)
		t.Fail()
		return
	}

	assertEqual(t, response.Header.Status, uint32(codes.OK))
	caLogger.Info("Response from certificate authority",
		zap.Any("Response", response),
	)
}

func TestCreateDeviceCertificateCommonSigningKey(t *testing.T) {
	csr, err := common.CreateDeviceCertificateSigningRequest()
	if err != nil {
		caLogger.Error("TestCreateDeviceCertificateCommonSigningKey: Error creating CSR",
			zap.Error(err))
		t.Fail()
		return
	}

	createRequest := &pb.CreateDeviceCertificateRequest{
		Header:  newCaProtocolHeader(),
		Version: CaProtocolVersion,
		Tid:     uuid.NewString(),
		Csr:     csr,
	}

	response, err := gClient.CreateDeviceCertificate(gCtx, createRequest)
	if err != nil {
		caLogger.Error("TestCreateDeviceCertificateCommonSigningKey: RPC failed",
			zap.Error(err))
		t.Fail()
		return
	}

	assertEqual(t, response.Header.Status, uint32(codes.OK))
	caLogger.Info("Response from certificate authority",
		zap.Any("Response", response),
	)
}

func TestCreateDeviceCertificate_NoCsr(t *testing.T) {
	createRequest := &pb.CreateDeviceCertificateRequest{
		Header:  newCaProtocolHeader(),
		Version: CaProtocolVersion,
		Tid:     testTenantID,
	}

	response, err := gClient.CreateDeviceCertificate(gCtx, createRequest)
	if err != nil {
		caLogger.Error("TestCreateDeviceCertificate_NoCsr: RPC failed %v",
			zap.Error(err))
		t.Fail()
		return
	}

	assertEqual(t, response.Header.Status, uint32(codes.InvalidArgument))
	caLogger.Info("Response from certificate authority",
		zap.Any("Response", response),
	)
}

func TestCreateDeviceCertificate_NoTenantID(t *testing.T) {
	csr, err := common.CreateDeviceCertificateSigningRequest()
	if err != nil {
		caLogger.Error("TestCreateDeviceCertificate_NoTenantID: Error creating CSR %v",
			zap.Error(err))
		t.Fail()
		return
	}

	createRequest := &pb.CreateDeviceCertificateRequest{
		Header:  newCaProtocolHeader(),
		Version: CaProtocolVersion,
		Csr:     csr,
	}

	response, err := gClient.CreateDeviceCertificate(gCtx, createRequest)
	if err != nil {
		caLogger.Error("TestCreateDeviceCertificate_NoTenantID: RPC failed %v",
			zap.Error(err))
		t.Fail()
		return
	}

	assertEqual(t, response.Header.Status, uint32(codes.InvalidArgument))
	caLogger.Info("Response from certificate authority",
		zap.Any("Response", response),
	)
}
