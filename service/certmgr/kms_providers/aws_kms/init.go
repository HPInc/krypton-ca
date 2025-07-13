// package github.com/HPInc/krypton-ca/service/certmgr/kms_providers/aws_kms
// Author: Mahesh Unnikrishnan
// Component: Krypton Certificate Authority
// (C) HP Development Company, LP
// Purpose:
// Initializes the AWS KMS provider.
package aws_kms

import (
	"context"
	"crypto/x509"

	"github.com/HPInc/krypton-ca/service/certmgr/certstore"
	"github.com/HPInc/krypton-ca/service/common"
	cacfg "github.com/HPInc/krypton-ca/service/config"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"go.uber.org/zap"
)

var (
	caLogger *zap.Logger
)

// AwsKmsProvider - uses the AWS KMS (Key Management Service) for cryptographic
// operations and provides a more secure option for production. Private keys
// are bound to the HSM within the AWS KMS service and do not leave the KMS
// service when consumed for signing operations.
type AwsKmsProvider struct {
	// KMS methods exposed by the AWS KMS provider.
	client KMSClient

	// Parent context for the AWS KMS provider.
	ctx context.Context

	// The CA root certificate.
	caKeyID     string
	caCert      *x509.Certificate
	caCertBytes []byte

	// The common signing certificate.
	commonSigningCert *common.SigningCertificate

	// Certificate store used to persist tenant signing certificates.
	store certstore.CertStore
}

// Init - initialize the AWS KMS provider.
func (p *AwsKmsProvider) Init(logger *zap.Logger, cfgMgr *cacfg.ConfigMgr) error {
	caLogger = logger
	p.ctx = context.Background()
	p.caKeyID = awsKmsCAKeyAlias

	// Load the default AWS configuration and initialize a client to the
	// AWS KMS service.
	awsConfig, err := config.LoadDefaultConfig(p.ctx)
	if err != nil {
		caLogger.Error("Failed to load the default AWS configuration!",
			zap.Error(err),
		)
		return err
	}
	p.client = kms.NewFromConfig(awsConfig)

	// Initialize the certificate store provider.
	p.store, err = certstore.Init(caLogger, cfgMgr.GetCertStoreProvider())
	if err != nil {
		caLogger.Error("Failed to initialize certificate store provider!",
			zap.String("Provider name: ", cfgMgr.GetCertStoreProvider()),
			zap.Error(err),
		)
		return err
	}

	// Initialize the CA certificate.
	if cfgMgr.IsTestModeEnabled() {
		/////////////////////// *** IN TEST MODE only *** /////////////////////
		// Generate a private key for the CA certificate in KMS & use it to
		// generate the CA certificate, which will be used for signing tenant
		// signing certificates.
		///////////////////////////////////////////////////////////////////////
		err = p.generateCACertificate(cfgMgr.GetIssuerName())
		if err != nil {
			caLogger.Error("Test Mode: Failed to generate CA certificate!",
				zap.Error(err),
			)
			return err
		}
	} else {
		///////////////////////////// Production mode /////////////////////////
		// Retrieve the CA certificate from the certificate store and check if
		// it matches the CA key retrieved from KMS.
		///////////////////////////////////////////////////////////////////////
		err = p.getCACertificate()
		if err != nil {
			caLogger.Error("Production Mode: Failed to initialize CA certificate!",
				zap.Error(err),
			)
			return err
		}
	}

	// Initialize the common signing certificate.
	p.commonSigningCert, err = p.getCommonSigningCertificate()
	if err != nil {
		caLogger.Error("Failed to get the common signing certificate from certificate store!",
			zap.Error(err),
		)
		return err
	}

	caLogger.Info("AWS KMS provider initialized successfully!")
	return nil
}

// Shutdown - clean up and shutdown the AWS KMS provider.
func (p *AwsKmsProvider) Shutdown() {
	p.ctx.Done()

	// Shutdown the certificate store provider.
	p.store.Shutdown()
	caLogger.Info("AWS KMS provider shutdown!")
}
