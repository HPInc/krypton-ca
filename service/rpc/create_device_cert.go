// package github.com/HPInc/krypton-ca/service/rpc
// Author: Mahesh Unnikrishnan
// Component: Krypton Certificate Authority
// (C) HP Development Company, LP
// Purpose:
// Implements the CreateDeviceCertificate RPC used to create a new device
// certificate for the specified device. It assigns a new device identifier for
// the device and asserts the identifier within the issued certificate.
package rpc

import (
	"context"
	"time"

	pb "github.com/HPInc/krypton-ca/caprotos"
	"github.com/HPInc/krypton-ca/service/metrics"
	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// CreateDeviceCertificate RPC is used to issue a device certificate to the
// specified device.
func (s *CertificateAuthorityServer) CreateDeviceCertificate(ctx context.Context,
	request *pb.CreateDeviceCertificateRequest) (*pb.CreateDeviceCertificateResponse, error) {

	// Validate the request header and extract the request identifier for
	// end-to-end request tracing.
	requestID, ok := isValidRequestHeader(request.Header)
	if !ok {
		caLogger.Error("CreateDeviceCertificate: Invalid request header specified!")
		response := invalidCreateDeviceCertificateResponse(requestID)
		return response, nil
	}

	if (request.Tid == "") || (request.Csr == nil) {
		caLogger.Error("CreateDeviceCertificate: TenantID or CSR were not specified",
			zap.String("Request ID:", requestID),
		)
		response := invalidCreateDeviceCertificateResponse(requestID)
		return response, nil
	}

	// Invoke the certificate store provider to issue a new device certificate.
	deviceID, deviceCert, parentCerts, expiresAt, err := s.kmsProvider.CreateDeviceCertificate(
		request.Tid, request.Csr)
	if err != nil {
		caLogger.Error("CreateDeviceCertificate: Failed to generate device certificate!",
			zap.String("Request ID:", requestID),
			zap.String("Tenant ID:", request.Tid),
			zap.Error(err),
		)
		response := internalErrorCreateDeviceCertificateResponse(requestID)
		return response, nil
	}

	response := successCreateDeviceCertificateResponse(requestID, deviceID,
		deviceCert, parentCerts, expiresAt)
	return response, nil
}

func invalidCreateDeviceCertificateResponse(
	requestID string) *pb.CreateDeviceCertificateResponse {
	response := &pb.CreateDeviceCertificateResponse{
		Header: &pb.CaResponseHeader{
			ProtocolVersion: CaProtocolVersion,
			Status:          uint32(codes.InvalidArgument),
			StatusMessage:   "CreateDeviceCertificate RPC failed",
			RequestId:       requestID,
			ResponseTime:    timestamppb.Now(),
		},
	}

	metrics.MetricCreateDeviceCertificateBadRequests.Inc()
	return response
}

func successCreateDeviceCertificateResponse(
	requestID string, deviceID string, deviceCert []byte,
	parentCerts []byte, expiresAt time.Time) *pb.CreateDeviceCertificateResponse {
	response := &pb.CreateDeviceCertificateResponse{
		Header: &pb.CaResponseHeader{
			ProtocolVersion: CaProtocolVersion,
			Status:          uint32(codes.OK),
			StatusMessage:   "CreateDeviceCertificate RPC successful",
			RequestId:       requestID,
			ResponseTime:    timestamppb.Now(),
		},
		IssuedTime:         timestamppb.Now(),
		ExpiryTime:         timestamppb.New(expiresAt),
		DeviceId:           deviceID,
		DeviceCertificate:  deviceCert,
		ParentCertificates: parentCerts,
	}

	metrics.MetricDeviceCertificatesIssued.Inc()
	return response
}

func internalErrorCreateDeviceCertificateResponse(
	requestID string) *pb.CreateDeviceCertificateResponse {
	response := &pb.CreateDeviceCertificateResponse{
		Header: &pb.CaResponseHeader{
			ProtocolVersion: CaProtocolVersion,
			Status:          uint32(codes.Internal),
			StatusMessage:   "CreateDeviceCertificate RPC failed",
			RequestId:       requestID,
			ResponseTime:    timestamppb.Now(),
		},
	}

	metrics.MetricCreateDeviceCertificateInternalErrors.Inc()
	return response
}
