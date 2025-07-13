// package github.com/HPInc/krypton-ca/service/rpc
// Author: Mahesh Unnikrishnan
// Component: Krypton Certificate Authority
// (C) HP Development Company, LP
// Purpose:
// Implements a common interceptor used to intercept all unary RPC requests
// received by the CA gRPC server. This interceptor is used to calculate
// request latencies while processing RPC requests, and track RPC error metrics
// and RPC served metrics.
package rpc

import (
	"context"
	"time"

	"github.com/HPInc/krypton-ca/service/metrics"
	"go.uber.org/zap"
	"google.golang.org/grpc"
)

// Interceptor for unary gRPCs served by the Certificate Authority.
func unaryInterceptor(ctx context.Context,
	req interface{},
	info *grpc.UnaryServerInfo,
	handler grpc.UnaryHandler) (interface{}, error) {
	start := time.Now()

	// Calculate and report RPC latency metric when the interceptor is done.
	defer metrics.ReportLatencyMetric(metrics.MetricRPCLatency, start,
		info.FullMethod)

	// Invoke the handler to process the gRPC request and update RPC metrics.
	h, err := handler(ctx, req)
	if err != nil {
		metrics.MetricRPCErrors.Inc()
	} else {
		metrics.MetricRPCsServed.Inc()
	}

	caLogger.Info("Processed gRPC request.",
		zap.String("Method:", info.FullMethod),
		zap.String("Duration:", time.Since(start).String()),
		zap.Error(err),
	)
	return h, err
}
