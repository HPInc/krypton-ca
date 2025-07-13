// package github.com/HPInc/krypton-ca/service/certmgr/certstore/dynamodb
// Author: Mahesh Unnikrishnan
// Component: Krypton Certificate Authority
// (C) HP Development Company, LP
// Purpose:
// Retrieves the specified tenant signing certificate from the Dynamo DB
// certificate store.
package dynamodb

import (
	"context"
	"time"

	"github.com/HPInc/krypton-ca/service/common"
	"github.com/HPInc/krypton-ca/service/metrics"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"go.uber.org/zap"
)

// GetCertificate - Returns the signing certificate for the specified tenant ID
// from the Dynamo DB certificate store.
func (p *DynamoDbProvider) GetCertificate(
	certID string) (*common.SigningCertificate, error) {

	start := time.Now()
	ctx, cancelFunc := context.WithTimeout(p.ctx, dynamoDbCallTimeout)
	defer cancelFunc()

	item := DynamoEntry{CertID: certID}
	key, err := item.GetKey()
	if err != nil {
		caLogger.Error("Failed to get the key for the certificate!",
			zap.String("Certificate ID: ", certID),
			zap.Error(err),
		)
		return nil, err
	}

	result, err := p.client.GetItem(ctx,
		&dynamodb.GetItemInput{
			TableName: aws.String(certsTableName),
			Key:       key,
		})
	metrics.ReportLatencyMetric(metrics.MetricAwsDynamoDbRequestLatency, start,
		awsDynamoDbOpGetItem)
	if err != nil {
		caLogger.Error("Failed to query for the signing certificate!",
			zap.String("Certificate ID: ", certID),
			zap.Error(err),
		)
		metrics.MetricAwsDynamoDbOtherAwsErrors.Inc()
		return nil, err
	}

	if result.Item == nil {
		caLogger.Error("No signing certificate record was found for the specified tenant!",
			zap.String("Certificate ID: ", certID),
		)
		metrics.MetricAwsDynamoDbNotFoundErrors.Inc()
		return nil, common.ErrCertStoreNotFound
	}

	// Decode the item returned from Dynamo DB into a signing certificate entry.
	err = attributevalue.UnmarshalMap(result.Item, &item)
	if err != nil {
		caLogger.Error("Failed to unmarshal response from Dynamo DB",
			zap.String("Certificate ID: ", certID),
			zap.Error(err),
		)
		return nil, err
	}

	entry, err := common.DecodeSigningCertificate(item.SigningCertBytes)
	if err != nil {
		caLogger.Error("Failed to decode the signing certificate entry!",
			zap.String("Certificate ID: ", certID),
			zap.Error(err),
		)
		return nil, err
	}

	return entry, nil
}
