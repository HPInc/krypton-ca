// package github.com/HPInc/krypton-ca/service/metrics
// Author: Mahesh Unnikrishnan
// Component: Krypton Certificate Authority
// (C) HP Development Company, LP
// Purpose:
// Defines prometheus metrics used to track AWS Dyanamo DB operations issued
// by the CA, when using Dynamo DB as the certificate store.
package metrics

import "github.com/prometheus/client_golang/prometheus"

var (
	// DynamoDB request processing latency is partitioned by the method. It uses
	// custom buckets based on the expected request duration.
	MetricAwsDynamoDbRequestLatency = prometheus.NewSummaryVec(
		prometheus.SummaryOpts{
			Name:       "ca_aws_dynamodb_latency_milliseconds",
			Help:       "A latency histogram for requests to AWS Dynamo DB",
			Objectives: map[float64]float64{0.5: 0.05, 0.9: 0.01, 0.99: 0.001},
		},
		[]string{"method"},
	)

	// Number of requests to Amazon Dynamo DB, resulting in internal server
	// error responses.
	MetricAwsDynamoDbInternalErrors = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "ca_aws_dynamodb_internal_errors",
			Help: "Total number of internal error responses returned by Amazon Dynamo DB",
		})

	// Number of requests to Amazon Dynamo DB, resulting in resource not found
	// error responses.
	MetricAwsDynamoDbNotFoundErrors = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "ca_aws_dynamodb_not_found_errors",
			Help: "Total number of resource not found error responses returned by Amazon Dynamo DB",
		})

	// Number of requests to Amazon Dynamo DB, resulting in AWS error responses.
	MetricAwsDynamoDbOtherAwsErrors = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "ca_aws_dynamodb_other_aws_errors",
			Help: "Total number of AWS error responses returned by Amazon Dynamo DB",
		})

	// Number of requests to Amazon Dynamo DB, resulting in non-AWS error responses.
	MetricAwsDynamoDbNonAwsErrors = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "ca_aws_dynamodb_non_aws_errors",
			Help: "Total number of non AWS error responses returned by Amazon Dynamo DB",
		})
)
