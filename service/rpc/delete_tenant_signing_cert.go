// package github.com/HPInc/krypton-ca/service/rpc
// Author: Mahesh Unnikrishnan
// Component: Krypton Certificate Authority
// (C) HP Development Company, LP
// Purpose:
// Implements the DeleteTenantSigningCertificate RPC used to delete the signing
// certificate used for the specified tenant.
package rpc

import (
	"context"

	pb "github.com/HPInc/krypton-ca/caprotos"
	"github.com/HPInc/krypton-ca/service/metrics"
	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// DeleteTenantSigningCertificate - deletes the signing certificate used for the
// specified tenant.
func (s *CertificateAuthorityServer) DeleteTenantSigningCertificate(ctx context.Context,
	request *pb.DeleteTenantSigningCertificateRequest) (*pb.DeleteTenantSigningCertificateResponse, error) {

	// Validate the request header and extract the request identifier for
	// end-to-end request tracing.
	requestID, ok := isValidRequestHeader(request.Header)
	if !ok {
		caLogger.Error("DeleteTenantSigningCertificate: Invalid request header specified!")
		response := invalidDeleteTenantSigningCertificateResponse(requestID)
		return response, nil
	}

	if request.Tid == "" {
		caLogger.Error("DeleteTenantSigningCertificate: TenantID was not specified!",
			zap.String("Request ID:", requestID),
		)
		response := invalidDeleteTenantSigningCertificateResponse(requestID)
		return response, nil
	}

	// Invoke the corresponding KMS provider to delete the configured tenant
	// signing certificate.
	err := s.kmsProvider.DeleteTenantSigningCertificate(request.Tid)
	if err != nil {
		caLogger.Error("Failed to delete tenant signing certificate!",
			zap.String("Tenant ID:", request.Tid),
			zap.String("Request ID:", requestID),
			zap.Error(err),
		)
		response := internalErrorDeleteTenantSigningCertificateResponse(requestID)
		return response, nil
	}

	response := successDeleteTenantSigningCertificateResponse(requestID)
	return response, nil
}

func invalidDeleteTenantSigningCertificateResponse(
	requestID string) *pb.DeleteTenantSigningCertificateResponse {
	response := &pb.DeleteTenantSigningCertificateResponse{
		Header: &pb.CaResponseHeader{
			ProtocolVersion: CaProtocolVersion,
			Status:          uint32(codes.InvalidArgument),
			StatusMessage:   "DeleteTenantSigningCertificate RPC failed",
			RequestId:       requestID,
			ResponseTime:    timestamppb.Now(),
		},
	}

	metrics.MetricDeleteTenantCertificateBadRequests.Inc()
	return response
}

func successDeleteTenantSigningCertificateResponse(
	requestID string) *pb.DeleteTenantSigningCertificateResponse {
	response := &pb.DeleteTenantSigningCertificateResponse{
		Header: &pb.CaResponseHeader{
			ProtocolVersion: CaProtocolVersion,
			Status:          uint32(codes.OK),
			StatusMessage:   "DeleteTenantSigningCertificate RPC successful",
			RequestId:       requestID,
			ResponseTime:    timestamppb.Now(),
		},
		DeleteTime: timestamppb.Now(),
	}

	metrics.MetricTenantCertificatesDeleted.Inc()
	return response
}

func internalErrorDeleteTenantSigningCertificateResponse(
	requestID string) *pb.DeleteTenantSigningCertificateResponse {
	response := &pb.DeleteTenantSigningCertificateResponse{
		Header: &pb.CaResponseHeader{
			ProtocolVersion: CaProtocolVersion,
			Status:          uint32(codes.Internal),
			StatusMessage:   "DeleteTenantSigningCertificate RPC failed",
			RequestId:       requestID,
			ResponseTime:    timestamppb.Now(),
		},
	}

	metrics.MetricDeleteTenantCertificateInternalErrors.Inc()
	return response
}
