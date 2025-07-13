// package github.com/HPInc/krypton-ca/service/rpc
// Author: Mahesh Unnikrishnan
// Component: Krypton Certificate Authority
// (C) HP Development Company, LP
// Purpose:
// Implements the Ping RPC used to perform health/uptime checks for the CA
// gRPC service.
package rpc

import (
	"context"
	"fmt"

	pb "github.com/HPInc/krypton-ca/caprotos"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const (
	// Maximum allowable length of ping messages served by the CA.
	maxLengthPingMessage = 25
)

// Ping RPC is used to perform health/uptime checks for the CA service.
func (s *CertificateAuthorityServer) Ping(ctx context.Context,
	request *pb.PingRequest) (*pb.PingResponse, error) {

	// Reject overly long ping requests.
	if len(request.Message) > maxLengthPingMessage {
		return nil, fmt.Errorf("invalid ping request - message too long")
	}

	// Respond with the caller's ping message and the current timestamp to
	// indicate liveness.
	return &pb.PingResponse{
		Message:      request.Message,
		ResponseTime: timestamppb.Now()}, nil
}
