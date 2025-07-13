// package github.com/HPInc/krypton-ca/service/certmgr/kms_providers/aws_kms
// Author: Mahesh Unnikrishnan
// Component: Krypton Certificate Authority
// (C) HP Development Company, LP
// Purpose:
// Implements a crypto signer interface that is used to sign certificates using
// the AWS KMS service.
package aws_kms

import (
	"context"
	"crypto"
	"crypto/x509"
	"io"
	"time"

	"github.com/HPInc/krypton-ca/service/metrics"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"go.uber.org/zap"
)

// KMSSigner implements the crypto/Signer interface that can be used for signing operations
// using an AWS KMS key. see https://golang.org/pkg/crypto/#Signer
type KMSSigner struct {
	// An instance of the KMS Client.
	client KMSClient

	// AWS KMS key ID used for signing.
	keyID string

	// Public key.
	publicKey crypto.PublicKey

	// Parent context.
	ctx context.Context
}

// Initializes a new instance of the KMS signer using the requested key ID.
func newKMSSigner(ctx context.Context, client KMSClient,
	keyID string) (*KMSSigner, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	// Generate a context and specify the timeout for the KMS call.
	newCtx, cancel := context.WithTimeout(ctx, awsKmsRequestTimeout)
	defer cancel()

	// Request the public key corresponding to the specified key ID from AWS KMS.
	start := time.Now()
	response, err := client.GetPublicKey(newCtx, &kms.GetPublicKeyInput{
		KeyId: &keyID,
	})
	metrics.ReportLatencyMetric(metrics.MetricAwsKmsRequestLatency, start,
		awsKmsOpGetPublicKey)
	if err != nil {
		caLogger.Error("Failed to get the public key from AWS KMS!",
			zap.Error(err),
		)
		metrics.MetricAwsKmsKeyRetrievalFailures.Inc()
		return nil, err
	}
	metrics.MetricAwsKmsKeyRetrieved.Inc()

	// Parse the KMS response and extract the public key.
	key, err := x509.ParsePKIXPublicKey(response.PublicKey)
	if err != nil {
		caLogger.Error("Failed to parse the public key from AWS KMS response!",
			zap.Error(err),
		)
		return nil, err
	}

	return &KMSSigner{
		client:    client,
		keyID:     keyID,
		publicKey: key,
		ctx:       ctx,
	}, nil
}

// Public returns the public key used by the signer.
func (s *KMSSigner) Public() crypto.PublicKey {
	return s.publicKey
}

// Sign the requested message using AWS KMS.
func (s *KMSSigner) Sign(rand io.Reader, digest []byte,
	opts crypto.SignerOpts) ([]byte, error) {
	select {
	case <-s.ctx.Done():
		return nil, s.ctx.Err()
	default:
	}

	// Generate a context and specify the timeout for the KMS call.
	ctx, cancel := context.WithTimeout(s.ctx, awsKmsRequestTimeout)
	defer cancel()

	start := time.Now()
	response, err := s.client.Sign(ctx, &kms.SignInput{
		KeyId:            &s.keyID,
		Message:          digest,
		MessageType:      types.MessageTypeDigest,
		SigningAlgorithm: types.SigningAlgorithmSpecRsassaPkcs1V15Sha256,
	})
	metrics.ReportLatencyMetric(metrics.MetricAwsKmsRequestLatency, start,
		awsKmsOpSign)
	if err != nil {
		caLogger.Error("Failed to sign using AWS KMS!",
			zap.Error(err),
		)
		metrics.MetricAwsKmsSignatureFailures.Inc()
		return nil, err
	}

	metrics.MetricAwsKmsSignatureSuccess.Inc()
	return response.Signature, nil
}
