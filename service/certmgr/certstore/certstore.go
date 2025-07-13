// package github.com/HPInc/krypton-ca/service/certmgr/certstore
// Author: Mahesh Unnikrishnan
// Component: Krypton Certificate Authority
// (C) HP Development Company, LP
// Purpose:
// Implements the CertStore interface which is used to plug in various
// certificate stores. The certificate stores are used to store signing
// certificates used by the KMS providers configured for the CA service.
package certstore

import (
	"github.com/HPInc/krypton-ca/service/certmgr/certstore/dynamodb"
	"github.com/HPInc/krypton-ca/service/certmgr/certstore/localdb"
	"github.com/HPInc/krypton-ca/service/common"
	"go.uber.org/zap"
)

var (
	caLogger *zap.Logger
)

// CertStore - defines an interface that must be implemented by certificate store
// providers. Certificate store providers store the tenant signing key which is
// used to sign device certificates.
type CertStore interface {
	// Initialize the provider.
	Init(*zap.Logger) error

	// Shutdown the provider and free up resources.
	Shutdown()

	// Add a certificate to the store. This API can be used to store
	// the following types of signing certificates in the store:
	// - CA certificate: used to sign tenant signing certificates
	// - Tenant signing certificate: used to sign device certificates
	//                               issued within the tenant.
	AddCertificate(entry *common.SigningCertificate) error

	// Get the signing certificate for the specified ID from the store.
	// Possible values of ID:
	//  - alias/CAKey: returns the CA certificate.
	//  - tenantID: returns the signing certificate for the tenant.
	GetCertificate(certID string) (*common.SigningCertificate, error)

	// Remove the signing certificate for the specified tenant ID from the store.
	DeleteCertificate(certID string) error
}

// Initialize the certificate store interface and determine which certificate
// store provider to enable based on the configuration of the CA service.
func Init(logger *zap.Logger, certStoreProviderName string) (CertStore, error) {
	caLogger = logger

	switch certStoreProviderName {
	case common.CertStoreDynamoDb:
		// Use Dynamo DB as the certificate store provider.
		provider := dynamodb.DynamoDbProvider{}
		err := provider.Init(caLogger)
		if err != nil {
			caLogger.Error("Failed to initialize the Dynamo DB database certificate store!",
				zap.Error(err),
			)
			return nil, err
		}
		caLogger.Info("Successfully initialized the Dynamo DB certificate store.")
		return &provider, nil

	case common.CertStoreLocalDb:
		// Use a local Bolt DB instance as the certificate store provider. Only
		// recommended for use in test mode. For production use a proper
		// certificate store provider.
		provider := localdb.LocalDbProvider{}
		err := provider.Init(caLogger)
		if err != nil {
			caLogger.Error("Failed to initialize the local database certificate store!",
				zap.Error(err),
			)
			return nil, err
		}
		caLogger.Info("Successfully initialized the local database certificate store.")
		return &provider, nil

	default:
		caLogger.Error("Invalid certificate store provider requested!",
			zap.String("Requested provider:", certStoreProviderName),
		)
	}
	return nil, common.ErrInvalidCertStore
}
