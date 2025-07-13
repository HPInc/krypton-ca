// package github.com/HPInc/krypton-ca/service/metrics
// Author: Mahesh Unnikrishnan
// Component: Krypton Certificate Authority
// (C) HP Development Company, LP
// Purpose:
// Defines prometheus metrics used to track certificate issuance, renewal and
// other certificate lifecycle operations performed by the CA.
package metrics

import "github.com/prometheus/client_golang/prometheus"

var (
	// Number of device certificates issued by the CA.
	MetricDeviceCertificatesIssued = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "ca_device_certs_issued",
			Help: "Total number of device certificates issued by the CA",
		})

	// Number of device certificates renewed by the CA.
	MetricDeviceCertificatesRenewed = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "ca_device_certs_renewed",
			Help: "Total number of device certificates renewed by the CA",
		})

	// Number of tenant signing certificates issued by the CA.
	MetricTenantCertificatesIssued = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "ca_tenant_certs_issued",
			Help: "Total number of tenant signing certificates issued by the CA",
		})

	// Number of tenant signing certificates deleted.
	MetricTenantCertificatesDeleted = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "ca_tenant_certs_deleted",
			Help: "Total number of tenant signing certificates deleted by the CA",
		})
)
