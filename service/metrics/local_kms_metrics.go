// package github.com/HPInc/krypton-ca/service/metrics
// Author: Mahesh Unnikrishnan
// Component: Krypton Certificate Authority
// (C) HP Development Company, LP
// Purpose:
// Defines prometheus metrics used to track certificate signing operations
// performed by the CA when using the local KMS provider.
package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	// Number of sign operations performed using Local KMS.
	MetricLocalKmsSignatureSuccess = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "ca_local_kms_sign_success",
			Help: "Total number of successful signature operations using Local KMS",
		})

	// Number of sign operations performed using Local KMS.
	MetricLocalKmsSignatureFailures = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "ca_local_kms_sign_failures",
			Help: "Total number of failed signature operations using Local KMS",
		})
)
