// package github.com/HPInc/krypton-ca/service/metrics
// Author: Mahesh Unnikrishnan
// Component: Krypton Certificate Authority
// (C) HP Development Company, LP
// Purpose:
// Defines prometheus metrics used to track the performance of various RPC
// calls exposed by the CA over its gRPC server.
package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	// Number of gRPC requests served by the CA.
	MetricRPCsServed = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "ca_rpc_requests",
			Help: "Total number of RPCs served by the CA",
		})

	// Number of failed gRPC requests.
	MetricRPCErrors = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "ca_rpc_errors",
			Help: "Total number of failed RPC requests to the CA",
		})

	// RPC request processing latency is partitioned by the RPC method. It uses
	// custom buckets based on the expected request duration.
	MetricRPCLatency = prometheus.NewSummaryVec(
		prometheus.SummaryOpts{
			Name:       "ca_rpc_latency_milliseconds",
			Help:       "A latency histogram for RPC requests served by the CA",
			Objectives: map[float64]float64{0.5: 0.05, 0.9: 0.01, 0.99: 0.001},
		},
		[]string{"method"},
	)

	// REST request processing latency is partitioned by the REST method. It uses
	// custom buckets based on the expected request duration.
	MetricRestLatency = prometheus.NewSummaryVec(
		prometheus.SummaryOpts{
			Name:       "ca_rest_latency_milliseconds",
			Help:       "A latency histogram for REST requests served by the CA",
			Objectives: map[float64]float64{0.5: 0.05, 0.9: 0.01, 0.99: 0.001},
		},
		[]string{"method"},
	)

	// Number of bad/invalid create certificate requests to the CA.
	MetricCreateDeviceCertificateBadRequests = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "ca_rpc_create_cert_bad_requests",
			Help: "Total number of bad create device certificate requests to the CA",
		})

	// Number of bad/invalid renew certificate requests to the CA.
	MetricRenewDeviceCertificateBadRequests = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "ca_rpc_renew_cert_bad_requests",
			Help: "Total number of bad renew device certificate requests to the CA",
		})

	// Number of bad/invalid create tenant signing certificate requests to the CA.
	MetricCreateTenantCertificateBadRequests = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "ca_rpc_create_tenant_cert_bad_requests",
			Help: "Total number of bad create tenant signing certificate requests to the CA",
		})

	// Number of bad/invalid delete tenant signing certificate requests to the CA.
	MetricDeleteTenantCertificateBadRequests = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "ca_rpc_delete_tenant_cert_bad_requests",
			Help: "Total number of bad delete tenant signing certificate requests to the CA",
		})

	// Number of create certificate requests to the CA, resulting in internal
	// errors.
	MetricCreateDeviceCertificateInternalErrors = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "ca_rpc_create_cert_internal_errors",
			Help: "Total number of internal errors processing create device certificate requests",
		})

	// Number of renew certificate requests to the CA, resulting in internal
	// errors.
	MetricRenewDeviceCertificateInternalErrors = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "ca_rpc_renew_cert_internal_errors",
			Help: "Total number of internal errors processing renew device certificate requests",
		})

	// Number of bad/invalid create tenant signing certificate requests to the CA.
	MetricCreateTenantCertificateInternalErrors = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "ca_rpc_create_tenant_cert_internal_errors",
			Help: "Total number of internal errors processing create tenant signing certificate requests",
		})

	// Number of bad/invalid delete tenant signing certificate requests to the CA.
	MetricDeleteTenantCertificateInternalErrors = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "ca_rpc_delete_tenant_cert_internal_errors",
			Help: "Total number of internal errors processing delete tenant signing certificate requests",
		})
)
