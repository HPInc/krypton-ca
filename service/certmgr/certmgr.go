// package github.com/HPInc/krypton-ca/service/certmgr
// Author: Mahesh Unnikrishnan
// Component: Krypton Certificate Authority
// (C) HP Development Company, LP
// Purpose:
// Implements the Certificate Manager component within the CA. The certificate
// manager initializes the certificate template configuration based on the
// information parsed from the configuration YAML file. It also selects and
// initializes the key management service (KMS) provider to be used for actual
// certificate issuance based on the configuration.
package certmgr

import (
	"errors"

	"github.com/HPInc/krypton-ca/service/certmgr/kms_providers"
	"github.com/HPInc/krypton-ca/service/certmgr/kms_providers/aws_kms"
	"github.com/HPInc/krypton-ca/service/certmgr/kms_providers/local_kms"
	"github.com/HPInc/krypton-ca/service/common"
	"github.com/HPInc/krypton-ca/service/config"
	"go.uber.org/zap"
)

var (
	caLogger *zap.Logger
)

// Init is used to initialize the certificate manager and select the right KMS
// provider to use for issuing certificates, depending on the CA's configuration.
func Init(logger *zap.Logger,
	cfgMgr *config.ConfigMgr) (kms_providers.KmsProvider, error) {
	caLogger = logger

	// Initialize the certificate template with configuration information
	// parsed from the configuration file.
	common.InitTemplateConfiguration(cfgMgr.GetCertificateTemplateConfig())

	// Determine the KMS provider to use, based on input from the
	// configuration file.
	switch cfgMgr.GetKmsProvider() {
	case common.KmsProviderAws:
		// Use AWS Key Management Service (KMS) as the provider.
		provider := aws_kms.AwsKmsProvider{}
		err := provider.Init(caLogger, cfgMgr)
		if err != nil {
			caLogger.Error("Failed to initialize certificate authority with AWS KMS provider!",
				zap.Error(err),
			)
			return nil, err
		}

		caLogger.Info("Successfully initialized the certificate authority with AWS KMS provider.")
		return &provider, nil

	case common.KmsProviderLocal:
		// The local certificate store provider is only recommended for use in
		// test mode. For production use a proper KMS provider.
		provider := local_kms.LocalProvider{}
		err := provider.Init(caLogger, cfgMgr)
		if err != nil {
			caLogger.Error("Failed to initialize certificate authority with local KMS provider!",
				zap.Error(err),
			)
			return nil, err
		}
		caLogger.Info("Successfully initialized the certificate authority with local KMS provider.")
		return &provider, nil

	default:
		caLogger.Error("Invalid KMS provider requested!",
			zap.String("Requested provider:", cfgMgr.GetKmsProvider()),
		)
	}
	return nil, errors.New("unsupported kms provider requested")
}
