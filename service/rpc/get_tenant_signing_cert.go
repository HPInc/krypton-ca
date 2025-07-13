// package github.com/HPInc/krypton-ca/service/rpc
// Author: Mahesh Unnikrishnan
// Component: Krypton Certificate Authority
// (C) HP Development Company, LP
// Purpose:
// Implements the GetTenantSigningCertificate RPC used to retrieve the signing
// certificate used for the specified tenant.
package rpc

import (
	"context"

	pb "github.com/HPInc/krypton-ca/caprotos"
	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func (s *CertificateAuthorityServer) GetTenantSigningCertificate(ctx context.Context,
	request *pb.GetTenantSigningCertificateRequest) (*pb.GetTenantSigningCertificateResponse, error) {

	// Validate the request header and extract the request identifier for
	// end-to-end request tracing.
	requestID, ok := isValidRequestHeader(request.Header)
	if !ok {
		caLogger.Error("GetTenantSigningCertificate: Invalid request header specified!")
		response := invalidGetTenantSigningCertificateResponse(requestID)
		return response, nil
	}

	if request.Tid == "" {
		caLogger.Error("GetTenantSigningCertificate: TenantID was not specified!",
			zap.String("Request ID:", requestID),
		)
		response := invalidGetTenantSigningCertificateResponse(requestID)
		return response, nil
	}

	// Invoke the configured KMS provider to retrieve the tenant signing
	// certificate.
	certBytes, err := s.kmsProvider.GetTenantSigningCertificate(request.Tid)
	if err != nil {
		caLogger.Error("Failed to get tenant signing certificate!",
			zap.String("Tenant ID:", request.Tid),
			zap.String("Request ID:", requestID),
			zap.Error(err),
		)
		response := internalErrorGetTenantSigningCertificateResponse(requestID)
		return response, nil
	}

	response := successGetTenantSigningCertificateResponse(requestID, certBytes)
	return response, nil
}

func invalidGetTenantSigningCertificateResponse(
	requestID string) *pb.GetTenantSigningCertificateResponse {
	response := &pb.GetTenantSigningCertificateResponse{
		Header: &pb.CaResponseHeader{
			ProtocolVersion: CaProtocolVersion,
			Status:          uint32(codes.InvalidArgument),
			StatusMessage:   "GetTenantSigningCertificate RPC failed",
			RequestId:       requestID,
			ResponseTime:    timestamppb.Now(),
		},
		SigningCertificate: nil,
	}

	return response
}

func successGetTenantSigningCertificateResponse(
	requestID string,
	certBytes []byte) *pb.GetTenantSigningCertificateResponse {
	response := &pb.GetTenantSigningCertificateResponse{
		Header: &pb.CaResponseHeader{
			ProtocolVersion: CaProtocolVersion,
			Status:          uint32(codes.OK),
			StatusMessage:   "GetTenantSigningCertificate RPC successful",
			RequestId:       requestID,
			ResponseTime:    timestamppb.Now(),
		},
		SigningCertificate: certBytes,
	}

	return response
}

func internalErrorGetTenantSigningCertificateResponse(
	requestID string) *pb.GetTenantSigningCertificateResponse {
	response := &pb.GetTenantSigningCertificateResponse{
		Header: &pb.CaResponseHeader{
			ProtocolVersion: CaProtocolVersion,
			Status:          uint32(codes.Internal),
			StatusMessage:   "GetTenantSigningCertificate RPC failed",
			RequestId:       requestID,
			ResponseTime:    timestamppb.Now(),
		},
		SigningCertificate: nil,
	}

	return response
}
