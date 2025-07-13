package rpc

import (
	"testing"

	pb "github.com/HPInc/krypton-ca/caprotos"
	"github.com/HPInc/krypton-ca/service/common"
	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
)

func TestRenewDeviceCertificate(t *testing.T) {
	csr, err := common.CreateDeviceCertificateSigningRequest()
	if err != nil {
		caLogger.Error("TestRenewDeviceCertificate: Error creating CSR",
			zap.Error(err))
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
		caLogger.Error("TestRenewDeviceCertificate: CreateDeviceCertificate RPC failed",
			zap.Error(err))
		t.Fail()
		return
	}

	assertEqual(t, response.Header.Status, uint32(codes.OK))
	caLogger.Info("Response from certificate authority",
		zap.Any("Response", response))

	// Now create fresh CSR so we can request a renewed device certificate.
	newCsr, err := common.CreateDeviceCertificateSigningRequest()
	if err != nil {
		caLogger.Error("TestRenewDeviceCertificate: Error creating new CSR",
			zap.Error(err))
		t.Fail()
		return
	}

	renewRequest := &pb.RenewDeviceCertificateRequest{
		Header:   newCaProtocolHeader(),
		Version:  CaProtocolVersion,
		Tid:      testTenantID,
		DeviceId: response.DeviceId,
		Csr:      newCsr,
	}

	renewResponse, err := gClient.RenewDeviceCertificate(gCtx, renewRequest)
	if err != nil {
		caLogger.Error("TestRenewDeviceCertificate: RenewDeviceCertificate RPC failed",
			zap.Error(err))
		t.Fail()
		return
	}

	assertEqual(t, renewResponse.Header.Status, uint32(codes.OK))
	caLogger.Info("Response from certificate authority",
		zap.Any("Response", renewResponse))
}
