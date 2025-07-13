// package github.com/HPInc/krypton-ca/service/certmgr/certstore/dynamodb
// Author: Mahesh Unnikrishnan
// Component: Krypton Certificate Authority
// (C) HP Development Company, LP
// Purpose:
// Deletes the specified tenant signing certificate from the Dynamo DB
// certificate store.
package dynamodb

import (
	"context"
	"time"

	"github.com/HPInc/krypton-ca/service/metrics"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"go.uber.org/zap"
)

// DeleteCertificate - Removes the signing certificate for the specified tenant
// from the Dynamo DB certificate store.
func (p *DynamoDbProvider) DeleteCertificate(certID string) error {

	start := time.Now()
	ctx, cancelFunc := context.WithTimeout(p.ctx, dynamoDbCallTimeout)
	defer cancelFunc()

	entry := DynamoEntry{CertID: certID}
	key, err := entry.GetKey()
	if err != nil {
		caLogger.Error("Failed to get the key for the certificate!",
			zap.Error(err),
		)
		return err
	}

	_, err = p.client.DeleteItem(ctx, &dynamodb.DeleteItemInput{
		TableName: aws.String(certsTableName),
		Key:       key,
	})
	metrics.ReportLatencyMetric(metrics.MetricAwsDynamoDbRequestLatency, start,
		awsDynamoDbOpDeleteItem)
	if err != nil {
		caLogger.Error("Failed to delete the specified signing certificate!",
			zap.String("Certificate ID: ", certID),
			zap.Error(err),
		)
		metrics.MetricAwsDynamoDbNonAwsErrors.Inc()
		return err
	}

	return nil
}
