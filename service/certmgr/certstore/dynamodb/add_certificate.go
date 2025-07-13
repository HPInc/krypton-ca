// package github.com/HPInc/krypton-ca/service/certmgr/certstore/dynamodb
// Author: Mahesh Unnikrishnan
// Component: Krypton Certificate Authority
// (C) HP Development Company, LP
// Purpose:
// Adds the specified tenant signing certificate to the Dynamo DB certificate
// store.
package dynamodb

import (
	"context"
	"time"

	"github.com/HPInc/krypton-ca/service/common"
	"github.com/HPInc/krypton-ca/service/metrics"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"go.uber.org/zap"
)

type DynamoEntry struct {
	CertID           string `dynamodbav:"cert_id"`
	SigningCertBytes []byte `dynamodbav:"cert"`
}

func (entry DynamoEntry) GetKey() (map[string]types.AttributeValue, error) {
	certID, err := attributevalue.Marshal(entry.CertID)
	if err != nil {
		caLogger.Error("Failed to marshal key for storage in Dynamo DB",
			zap.String("Key ID", entry.CertID),
			zap.Error(err),
		)
		return nil, err
	}
	return map[string]types.AttributeValue{"cert_id": certID}, nil
}

// AddCertificate - Adds the specified tenant signing certificate to the Dynamo
// DB certificate store.
func (p *DynamoDbProvider) AddCertificate(entry *common.SigningCertificate) error {
	// Encode the tenant signing certificate entry.
	encodedEntry, err := common.EncodeSigningCertificate(entry)
	if err != nil {
		caLogger.Error("Failed to encode the signing certificate entry!",
			zap.Error(err),
		)
		return err
	}

	item, err := attributevalue.MarshalMap(DynamoEntry{
		CertID:           entry.TenantID,
		SigningCertBytes: encodedEntry,
	})
	if err != nil {
		caLogger.Error("Failed to marshal dynamo DB entry!",
			zap.Error(err),
		)
		return err
	}

	// Add the tenant signing certificate to the Dynamo DB table.
	start := time.Now()
	ctx, cancelFunc := context.WithTimeout(p.ctx, dynamoDbCallTimeout)
	defer cancelFunc()

	_, err = p.client.PutItem(ctx, &dynamodb.PutItemInput{
		TableName: aws.String(certsTableName),
		Item:      item,
	})
	metrics.ReportLatencyMetric(metrics.MetricAwsDynamoDbRequestLatency, start,
		awsDynamoDbOpPutItem)
	if err != nil {
		caLogger.Error("Error while adding the signing key entry to the database!",
			zap.String("Tenant ID: ", entry.TenantID),
			zap.Error(err),
		)
		metrics.MetricAwsDynamoDbNonAwsErrors.Inc()
		return err
	}

	return nil
}
