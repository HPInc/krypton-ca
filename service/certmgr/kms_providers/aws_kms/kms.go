// package github.com/HPInc/krypton-ca/service/certmgr/kms_providers/aws_kms
// Author: Mahesh Unnikrishnan
// Component: Krypton Certificate Authority
// (C) HP Development Company, LP
// Purpose:
// Implements various operations exposed by the AWS KMS service. These
// capabilities are used by the AWS KMS provider to create and manage keys
// in the AWS KMS service and sign certificates using the right keys.
package aws_kms

import (
	"context"
	"crypto"
	"crypto/x509"
	"errors"
	"time"

	"github.com/HPInc/krypton-ca/service/metrics"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"go.uber.org/zap"
)

const (
	// Timeouts that apply to requests made to the KMS.
	awsKmsRequestTimeout = 5 * time.Second

	// Schedule deletion of the key from KMS after these many days:
	awsKmsKeyDeletionPendingWindowDays = 7

	// The key alias assigned to the CA key. The CA key can be found in
	// AWS KMS using this key alias.
	awsKmsCAKeyAlias = "alias/CAKey"

	// "alias/CommonSigningKey" - This is the key alias assigned to the
	// common signing key. This key can be found in AWS KMS using the
	// above key alias. The common signing key is used to sign device
	// certificates for tenants that do not have a dedicated/distinct
	// tenant signing key.

	// KMS operation names
	awsKmsOpCreateKey           = "CreateKey"
	awsKmsOpCreateAlias         = "CreateAlias"
	awsKmsOpDeleteAlias         = "DeleteAlias"
	awsKmsOpDescribeKey         = "DescribeKey"
	awsKmsOpScheduleKeyDeletion = "ScheduleKeyDeletion"
	awsKmsOpGetPublicKey        = "GetPublicKey"
	awsKmsOpSign                = "Sign"
)

// An interface exposing KMS methods consumed by the provider.
type KMSClient interface {
	CreateKey(context.Context, *kms.CreateKeyInput, ...func(*kms.Options)) (*kms.CreateKeyOutput, error)
	CreateAlias(context.Context, *kms.CreateAliasInput, ...func(*kms.Options)) (*kms.CreateAliasOutput, error)
	DeleteAlias(context.Context, *kms.DeleteAliasInput, ...func(*kms.Options)) (*kms.DeleteAliasOutput, error)
	DescribeKey(context.Context, *kms.DescribeKeyInput, ...func(*kms.Options)) (*kms.DescribeKeyOutput, error)
	ListResourceTags(context.Context, *kms.ListResourceTagsInput, ...func(*kms.Options)) (*kms.ListResourceTagsOutput, error)
	ScheduleKeyDeletion(context.Context, *kms.ScheduleKeyDeletionInput, ...func(*kms.Options)) (*kms.ScheduleKeyDeletionOutput, error)
	GetPublicKey(context.Context, *kms.GetPublicKeyInput, ...func(*kms.Options)) (*kms.GetPublicKeyOutput, error)
	Sign(context.Context, *kms.SignInput, ...func(*kms.Options)) (*kms.SignOutput, error)
}

// newKmsKey - Generate a new key in AWS KMS, associate it with the
// requested key alias and return the KMS key ID of the key.
func (p *AwsKmsProvider) newKmsKey(keyDescription string,
	keyAlias string) (string, error) {
	select {
	case <-p.ctx.Done():
		return "", p.ctx.Err()
	default:
	}

	// Generate a context and specify the timeout for the KMS call.
	ctx, cancel := context.WithTimeout(p.ctx, awsKmsRequestTimeout)
	defer cancel()

	// Check if the requested key already exists in KMS
	start := time.Now()
	response, err := p.client.DescribeKey(ctx, &kms.DescribeKeyInput{
		KeyId: aws.String(keyAlias),
	})
	metrics.ReportLatencyMetric(metrics.MetricAwsKmsRequestLatency, start,
		awsKmsOpDescribeKey)
	if err == nil {
		caLogger.Info("Requested key already exists in KMS!",
			zap.String("Key alias: ", keyAlias),
			zap.String("Existing key ID: ", aws.ToString(response.KeyMetadata.KeyId)),
		)
		return aws.ToString(response.KeyMetadata.KeyId), nil
	}

	// if the error returned isn't a NotFoundException, then raise it and bail.
	var nsk *types.NotFoundException
	if !errors.As(err, &nsk) {
		caLogger.Error("Encountered an error checking if key exists in KMS!",
			zap.String("Key alias: ", keyAlias),
			zap.Error(err),
		)
		return "", err
	}

	// Generate a new key in KMS.
	start = time.Now()
	createdKey, err := p.client.CreateKey(ctx, &kms.CreateKeyInput{
		Description: aws.String(keyDescription),
		KeySpec:     types.KeySpec(types.CustomerMasterKeySpecRsa4096),
		KeyUsage:    types.KeyUsageTypeSignVerify,
	})
	metrics.ReportLatencyMetric(metrics.MetricAwsKmsRequestLatency, start,
		awsKmsOpCreateKey)
	if err != nil {
		caLogger.Error("Failed to create the requested key in KMS",
			zap.String("Key alias: ", keyAlias),
			zap.Error(err),
		)
		metrics.MetricAwsKmsKeyCreationFailures.Inc()
		return "", err
	}
	metrics.MetricAwsKmsKeyCreated.Inc()

	// Create an alias for the newly created key in KMS.
	start = time.Now()
	_, err = p.client.CreateAlias(ctx, &kms.CreateAliasInput{
		TargetKeyId: createdKey.KeyMetadata.KeyId,
		AliasName:   aws.String(keyAlias),
	})
	metrics.ReportLatencyMetric(metrics.MetricAwsKmsRequestLatency, start,
		awsKmsOpCreateAlias)
	if err != nil {
		caLogger.Error("Failed to create an alias for the key in KMS",
			zap.String("Key alias: ", keyAlias),
			zap.Error(err),
		)
		metrics.MetricAwsKmsAliasCreationFailures.Inc()
		return "", err
	}
	metrics.MetricAwsKmsAliasCreated.Inc()

	// Return the KMS key ID assigned to the newly created key.
	keyID := aws.ToString(createdKey.KeyMetadata.KeyId)
	caLogger.Info("Created the requested key in AWS KMS",
		zap.String("Key ID:", keyID),
		zap.String("Key alias: ", keyAlias),
	)
	return keyID, nil
}

// deleteKmsKey - Schedule deletion of the key mapped to the specified alias from
// KMS. Also delete the alias for the key in KMS.
func (p *AwsKmsProvider) deleteKmsKey(keyAlias string) error {
	select {
	case <-p.ctx.Done():
		return p.ctx.Err()
	default:
	}

	// Generate a context and specify the timeout for the KMS call.
	ctx, cancel := context.WithTimeout(p.ctx, awsKmsRequestTimeout)
	defer cancel()

	// Retrieve the key ID for the key from KMS.
	start := time.Now()
	response, err := p.client.DescribeKey(ctx, &kms.DescribeKeyInput{
		KeyId: aws.String(keyAlias),
	})
	metrics.ReportLatencyMetric(metrics.MetricAwsKmsRequestLatency, start,
		awsKmsOpDescribeKey)
	if err != nil {
		caLogger.Error("Failed to get information about the key from KMS!",
			zap.String("Key Alias:", keyAlias),
			zap.Error(err),
		)
		return err
	}

	// Schedule deletion of the specified key in KMS.
	start = time.Now()
	_, err = p.client.ScheduleKeyDeletion(ctx, &kms.ScheduleKeyDeletionInput{
		KeyId:               response.KeyMetadata.KeyId,
		PendingWindowInDays: aws.Int32(awsKmsKeyDeletionPendingWindowDays),
	})
	metrics.ReportLatencyMetric(metrics.MetricAwsKmsRequestLatency, start,
		awsKmsOpScheduleKeyDeletion)
	if err != nil {
		caLogger.Error("Failed to schedule key deletion in KMS!",
			zap.String("Key ID:", aws.ToString(response.KeyMetadata.KeyId)),
			zap.Error(err),
		)
		metrics.MetricAwsKmsKeyDeletionFailures.Inc()
		return err
	}
	metrics.MetricAwsKmsKeyDeleted.Inc()

	// Delete the alias for the key in KMS.
	start = time.Now()
	_, err = p.client.DeleteAlias(ctx, &kms.DeleteAliasInput{
		AliasName: aws.String(keyAlias),
	})
	metrics.ReportLatencyMetric(metrics.MetricAwsKmsRequestLatency, start,
		awsKmsOpDeleteAlias)
	if err != nil {
		caLogger.Error("Failed to delete the alias for the specified key in KMS!",
			zap.String("Key Alias:", keyAlias),
			zap.Error(err),
		)
		metrics.MetricAwsKmsAliasDeletionFailures.Inc()
		return err
	}
	metrics.MetricAwsKmsAliasDeleted.Inc()
	return nil
}

// getKmsPublicKey - retrieve the public key associated with the specified KMS key.
func (p *AwsKmsProvider) getKmsPublicKey(keyID string) (crypto.PublicKey, error) {
	select {
	case <-p.ctx.Done():
		return nil, p.ctx.Err()
	default:
	}

	// Generate a context and specify the timeout for the KMS call.
	ctx, cancel := context.WithTimeout(p.ctx, awsKmsRequestTimeout)
	defer cancel()

	// Retrieve the public key from KMS.
	start := time.Now()
	response, err := p.client.GetPublicKey(ctx, &kms.GetPublicKeyInput{
		KeyId: aws.String(keyID),
	})
	metrics.ReportLatencyMetric(metrics.MetricAwsKmsRequestLatency, start,
		awsKmsOpGetPublicKey)
	if err != nil {
		caLogger.Error("Failed to get public key associated with key in KMS",
			zap.String("Key ID: ", keyID),
		)
		metrics.MetricAwsKmsKeyRetrievalFailures.Inc()
		return "", errors.New("cannot get public key")
	}
	metrics.MetricAwsKmsKeyRetrieved.Inc()

	// Parse the public key retrieved from KMS.
	publicKey, err := x509.ParsePKIXPublicKey(response.PublicKey)
	if err != nil {
		caLogger.Error("Failed to parse public key associated with key in KMS",
			zap.String("Tenant Key ID: ", keyID),
		)
		return "", errors.New("cannot parse tenant public key")
	}

	return publicKey, nil
}
