// package github.com/HPInc/krypton-ca/service/metrics
// Author: Mahesh Unnikrishnan
// Component: Krypton Certificate Authority
// (C) HP Development Company, LP
// Purpose:
// Defines prometheus metrics used for monitoring AWS KMS operations issued by
// the CA.
package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	// AWS KMS request processing latency is partitioned by the method. It uses
	// custom buckets based on the expected request duration.
	MetricAwsKmsRequestLatency = prometheus.NewSummaryVec(
		prometheus.SummaryOpts{
			Name:       "ca_aws_kms_latency_milliseconds",
			Help:       "A latency histogram for requests to AWS KMS",
			Objectives: map[float64]float64{0.5: 0.05, 0.9: 0.01, 0.99: 0.001},
		},
		[]string{"method"},
	)

	// Number of keys created in AWS KMS.
	MetricAwsKmsKeyCreated = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "ca_aws_kms_key_creates",
			Help: "Total number of keys created in AWS KMS",
		})

	// Number of failures creating keys in AWS KMS.
	MetricAwsKmsKeyCreationFailures = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "ca_aws_kms_key_create_failures",
			Help: "Total number of failures creating keys in AWS KMS",
		})

	// Number of keys scheduled for deletion in AWS KMS.
	MetricAwsKmsKeyDeleted = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "ca_aws_kms_key_deletes",
			Help: "Total number of keys scheduled for deletion in AWS KMS",
		})

	// Number of failures deleting keys in AWS KMS.
	MetricAwsKmsKeyDeletionFailures = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "ca_aws_kms_key_delete_failures",
			Help: "Total number of failures creating keys in AWS KMS",
		})

	// Number of keys (public keys) retrieved from AWS KMS.
	MetricAwsKmsKeyRetrieved = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "ca_aws_kms_key_gets",
			Help: "Total number of keys retrieved from AWS KMS",
		})

	// Number of failures retrieving keys from AWS KMS.
	MetricAwsKmsKeyRetrievalFailures = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "ca_aws_kms_key_get_failures",
			Help: "Total number of failures retrieving keys from AWS KMS",
		})

	// Number of times the CA key was retrieved from AWS KMS.
	MetricAwsKmsCAKeyRetrieved = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "ca_aws_kms_ca_key_gets",
			Help: "Total number of times the CA key was retrieved from AWS KMS",
		})

	// Number of failures retrieving the CA key from AWS KMS.
	MetricAwsKmsCAKeyRetrievalFailures = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "ca_aws_kms_ca_key_get_failures",
			Help: "Total number of failures retrieving the CA key from AWS KMS",
		})

	// Number of aliases created in AWS KMS.
	MetricAwsKmsAliasCreated = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "ca_aws_kms_alias_creates",
			Help: "Total number of key aliases created in AWS KMS",
		})

	// Number of failures creating aliases in AWS KMS.
	MetricAwsKmsAliasCreationFailures = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "ca_aws_kms_alias_create_failures",
			Help: "Total number of failures creating key aliases in AWS KMS",
		})

	// Number of aliases deketed from AWS KMS.
	MetricAwsKmsAliasDeleted = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "ca_aws_kms_alias_deletes",
			Help: "Total number of key aliases deleted from AWS KMS",
		})

	// Number of failures deleting aliases from AWS KMS.
	MetricAwsKmsAliasDeletionFailures = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "ca_aws_kms_alias_delete_failures",
			Help: "Total number of failures deleting key aliases from AWS KMS",
		})

	// Number of sign operations performed using AWS KMS.
	MetricAwsKmsSignatureSuccess = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "ca_aws_kms_sign_success",
			Help: "Total number of successful signature operations using AWS KMS",
		})

	// Number of sign operations performed using AWS KMS.
	MetricAwsKmsSignatureFailures = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "ca_aws_kms_sign_failures",
			Help: "Total number of failed signature operations using AWS KMS",
		})
)
