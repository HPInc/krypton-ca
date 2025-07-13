// package github.com/HPInc/krypton-ca/service/rpc
// Author: Mahesh Unnikrishnan
// Component: Krypton Certificate Authority
// (C) HP Development Company, LP
// Purpose:
// Implements the RenewDeviceCertificate RPC used to renew a device certificate
// issued to a device. In the renew device certificate flow, the device provides
// a fresh CSR to obtain a new device certificate. The device ID issued to the
// device however is unchanged. The expectation is that the caller will verify
// the device access token and extract the device ID from that token to ensure
// the device ID is valid.
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

// RenewDeviceCertificate RPC is used to renew a device certificate issued to
// a device.
func (s *CertificateAuthorityServer) RenewDeviceCertificate(ctx context.Context,
	request *pb.RenewDeviceCertificateRequest) (*pb.RenewDeviceCertificateResponse,
	error) {
	// Validate the request header and extract the request identifier for
	// end-to-end request tracing.
	requestID, ok := isValidRequestHeader(request.Header)
	if !ok {
		caLogger.Error("RenewDeviceCertificate: Invalid request header specified!")
		response := invalidRenewDeviceCertificateResponse(requestID)
		return response, nil
	}

	// Ensure that the required request parameters were specified.
	if (request.Tid == "") || (request.DeviceId == "") || (request.Csr == nil) {
		caLogger.Error("RenewDeviceCertificate: TenantID, DeviceID or CSR were not specified",
			zap.String("Request ID:", requestID),
		)
		response := invalidRenewDeviceCertificateResponse(requestID)
		return response, nil
	}

	// Invoke the configured KMS provider to renew the device certificate.
	_, deviceCert, parentCerts, expiresAt, err := s.kmsProvider.RenewDeviceCertificate(
		request.Tid, request.DeviceId, request.Csr)
	if err != nil {
		caLogger.Error("RenewDeviceCertificate: Failed to generate device certificate!",
			zap.String("Request ID:", requestID),
			zap.String("Tenant ID:", request.Tid),
			zap.String("Device ID:", request.DeviceId),
			zap.Error(err),
		)
		response := internalErrorRenewDeviceCertificateResponse(requestID)
		return response, nil
	}

	response := successRenewDeviceCertificateResponse(requestID,
		request.DeviceId, deviceCert, parentCerts, expiresAt)
	return response, nil
}

func invalidRenewDeviceCertificateResponse(
	requestID string) *pb.RenewDeviceCertificateResponse {
	response := &pb.RenewDeviceCertificateResponse{
		Header: &pb.CaResponseHeader{
			ProtocolVersion: CaProtocolVersion,
			Status:          uint32(codes.InvalidArgument),
			StatusMessage:   "RenewDeviceCertificate RPC failed",
			RequestId:       requestID,
			ResponseTime:    timestamppb.Now(),
		},
	}

	metrics.MetricRenewDeviceCertificateBadRequests.Inc()
	return response
}

func successRenewDeviceCertificateResponse(
	requestID string, deviceID string, deviceCert []byte,
	parentCerts []byte, expiresAt time.Time) *pb.RenewDeviceCertificateResponse {
	response := &pb.RenewDeviceCertificateResponse{
		Header: &pb.CaResponseHeader{
			ProtocolVersion: CaProtocolVersion,
			Status:          uint32(codes.OK),
			StatusMessage:   "RenewDeviceCertificate RPC successful",
			RequestId:       requestID,
			ResponseTime:    timestamppb.Now(),
		},
		IssuedTime:         timestamppb.Now(),
		ExpiryTime:         timestamppb.New(expiresAt),
		DeviceId:           deviceID,
		DeviceCertificate:  deviceCert,
		ParentCertificates: parentCerts,
	}

	metrics.MetricDeviceCertificatesRenewed.Inc()
	return response
}

func internalErrorRenewDeviceCertificateResponse(
	requestID string) *pb.RenewDeviceCertificateResponse {
	response := &pb.RenewDeviceCertificateResponse{
		Header: &pb.CaResponseHeader{
			ProtocolVersion: CaProtocolVersion,
			Status:          uint32(codes.Internal),
			StatusMessage:   "RenewDeviceCertificate RPC failed",
			RequestId:       requestID,
			ResponseTime:    timestamppb.Now(),
		},
	}

	metrics.MetricRenewDeviceCertificateInternalErrors.Inc()
	return response
}
