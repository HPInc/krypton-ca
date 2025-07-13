// package github.com/HPInc/krypton-ca/service/certmgr/certstore/dynamodb
// Author: Mahesh Unnikrishnan
// Component: Krypton Certificate Authority
// (C) HP Development Company, LP
// Purpose:
// Implements the local certificate store using a Dynamo DB instance.
package dynamodb

import (
	"context"
	"errors"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"go.uber.org/zap"
)

var (
	caLogger *zap.Logger
)

// Name of the table in the Dynamo DB instance which is used to store the
// signing certificates.
var certsTableName = "SigningCertificates"

const (
	// Timeout for calls to Dynamo DB.
	dynamoDbCallTimeout = (time.Second * 10)

	// Dynamo DB operation names.
	awsDynamoDbOpGetItem    = "GetItem"
	awsDynamoDbOpPutItem    = "PutItem"
	awsDynamoDbOpDeleteItem = "DeleteItem"
)

// Implements a signing certificate store provider backed by a Dynamo DB
// instance.
type DynamoDbProvider struct {
	// Instance of the Dynamo DB client.
	client *dynamodb.Client

	// Context used for calls to Dynamo DB.
	ctx context.Context
}

// Init - initialize the connection to the Dynamo DB database instance used to
// store signing certificates.
func (p *DynamoDbProvider) Init(logger *zap.Logger) error {
	caLogger = logger

	// Initialize the context used for calls to Dynamo DB.
	p.ctx = context.Background()

	// Load the default AWS configuration and initialize a client to the
	// AWS KMS service.
	awsConfig, err := config.LoadDefaultConfig(p.ctx)
	if err != nil {
		caLogger.Error("Failed to load the default AWS configuration!",
			zap.Error(err),
		)
		return err
	}

	// Create a new instance of the Dynamo DB client.
	p.client = dynamodb.NewFromConfig(awsConfig)

	// Check if the table to store signing certificates exists.
	ctx, cancelFunc := context.WithTimeout(p.ctx, dynamoDbCallTimeout)
	defer cancelFunc()

	result, err := p.client.DescribeTable(ctx,
		&dynamodb.DescribeTableInput{
			TableName: aws.String(certsTableName),
		})
	if err != nil {
		var notFoundEx *types.ResourceNotFoundException
		if errors.As(err, &notFoundEx) {
			caLogger.Error("Table does not exist!",
				zap.String("Table name", certsTableName))
		} else {
			caLogger.Error("Error while checking if the signing key table exists!",
				zap.Error(err),
			)

		}
		return err
	}

	caLogger.Info("Successfully initialized the Dynamo DB certificate database!",
		zap.String("Table name: ", aws.ToString(result.Table.TableName)),
		zap.String("Table status: ", string(result.Table.TableStatus)),
	)
	return nil
}

// Shutdown - shutdown the connection to the Dynamo DB database used to store
// signing certificates.
func (p *DynamoDbProvider) Shutdown() {
	p.ctx.Done()
	caLogger.Info("Successfully shut down the Dynamo DB certificate database!")
}
