// package github.com/HPInc/krypton-ca/service/rpc
// Author: Mahesh Unnikrishnan
// Component: Krypton Certificate Authority
// (C) HP Development Company, LP
// Purpose:
// Implements the DeleteTenantSigningCertificate RPC used to create a signing
// certificate used for the specified tenant.
package rpc

import (
	"context"

	"go.uber.org/zap"

	pb "github.com/HPInc/krypton-ca/caprotos"
	"github.com/HPInc/krypton-ca/service/metrics"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// CreateTenantSigningCertificate RPC is used to create a new tenant signing
// certificate for the specified tenant.
func (s *CertificateAuthorityServer) CreateTenantSigningCertificate(ctx context.Context,
	request *pb.CreateTenantSigningCertificateRequest) (*pb.CreateTenantSigningCertificateResponse, error) {

	// Validate the request header and extract the request identifier for
	// end-to-end request tracing.
	requestID, ok := isValidRequestHeader(request.Header)
	if !ok {
		caLogger.Error("CreateTenantSigningCertificate: Invalid request header specified!")
		response := invalidCreateTenantSigningCertificateResponse(requestID)
		return response, nil
	}

	if (request.Tid == "") || (request.Name == "") {
		caLogger.Error("CreateTenantSigningCertificate: TenantID or tenant name was not specified!",
			zap.String("Request ID:", requestID),
		)
		response := invalidCreateTenantSigningCertificateResponse(requestID)
		return response, nil
	}

	// Invoke the configured KMS provider to create a new tenant signing certificate
	// for the specified tenant.
	certID, err := s.kmsProvider.CreateTenantSigningCertificate(request.Tid,
		request.Name)
	if err != nil {
		caLogger.Error("Failed to create tenant signing certificate!",
			zap.String("Tenant ID:", request.Tid),
			zap.String("Request ID:", requestID),
			zap.Error(err),
		)
		response := internalErrorCreateTenantSigningCertificateResponse(requestID)
		return response, nil
	}

	response := successCreateTenantSigningCertificateResponse(requestID, certID)
	return response, nil
}

func invalidCreateTenantSigningCertificateResponse(
	requestID string) *pb.CreateTenantSigningCertificateResponse {
	response := &pb.CreateTenantSigningCertificateResponse{
		Header: &pb.CaResponseHeader{
			ProtocolVersion: CaProtocolVersion,
			Status:          uint32(codes.InvalidArgument),
			StatusMessage:   "CreateTenantSigningCertificate RPC failed",
			RequestId:       requestID,
			ResponseTime:    timestamppb.Now(),
		},
	}

	metrics.MetricCreateTenantCertificateBadRequests.Inc()
	return response
}

func successCreateTenantSigningCertificateResponse(
	requestID string, certID string) *pb.CreateTenantSigningCertificateResponse {
	response := &pb.CreateTenantSigningCertificateResponse{
		Header: &pb.CaResponseHeader{
			ProtocolVersion: CaProtocolVersion,
			Status:          uint32(codes.OK),
			StatusMessage:   "CreateTenantSigningCertificate RPC successful",
			RequestId:       requestID,
			ResponseTime:    timestamppb.Now(),
		},
		CreateTime: timestamppb.Now(),
	}

	metrics.MetricTenantCertificatesIssued.Inc()
	return response
}

func internalErrorCreateTenantSigningCertificateResponse(
	requestID string) *pb.CreateTenantSigningCertificateResponse {
	response := &pb.CreateTenantSigningCertificateResponse{
		Header: &pb.CaResponseHeader{
			ProtocolVersion: CaProtocolVersion,
			Status:          uint32(codes.Internal),
			StatusMessage:   "CreateTenantSigningCertificate RPC failed",
			RequestId:       requestID,
			ResponseTime:    timestamppb.Now(),
		},
	}

	metrics.MetricCreateTenantCertificateInternalErrors.Inc()
	return response
}
