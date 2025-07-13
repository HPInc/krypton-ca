// package github.com/HPInc/krypton-ca/service/rpc
// Author: Mahesh Unnikrishnan
// Component: Krypton Certificate Authority
// (C) HP Development Company, LP
// Purpose:
// Implements validation logic used to validate the common request header
// attached to RPC requests received by the CA gRPC server.
package rpc

import (
	pb "github.com/HPInc/krypton-ca/caprotos"
	"github.com/google/uuid"
)

const (
	// CaProtocolVersion - version of the CA's gRPC protocol.
	CaProtocolVersion = "v1"
)

// Validate the common gRPC request header attached to RPC messages received
// at the CA gRPC endpoint.
func isValidRequestHeader(header *pb.CaRequestHeader) (string, bool) {
	// If the request didn't specify a header, reject it.
	if header == nil {
		caLogger.Error("Request header was not specified!")
		return "", false
	}

	// Ensure the CA protocol being requested is supported by this server.
	if header.ProtocolVersion != CaProtocolVersion {
		caLogger.Error("Unsupported protocol version requested!")
		return "", false
	}

	// Extract the request ID, if it has been specified. If not, generate a
	// unique request ID to be used for logging information related to this
	// request.
	if header.RequestId == "" {
		return uuid.New().String(), true
	}

	return header.RequestId, true
}
