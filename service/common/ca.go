// package github.com/HPInc/krypton-ca/service/common
// Author: Mahesh Unnikrishnan
// Component: Krypton Certificate Authority
// (C) HP Development Company, LP
// Purpose:
// Constants and definitions used by the CA service.
package common

const (
	ServiceName = "HP Device Certificate Authority"

	// Size of the RSA keys used by the CA.
	KeySize = 4096

	// Certificate lifetime.
	CACertificateLifetimeYears     = 10
	TenantCertificateLifetimeYears = 10
	DeviceCertificateLifetimeYears = 1

	// Common signing certificate information
	CommonSigningKeyId                  = "SharedTenantSigningKey"
	CommonTenantDeviceCertificateIssuer = "HP Device Certificate Issuer"
	TenantDeviceCertificateIssuer       = "Device Certificate Issuer: %s"

	// Key Management Service (KMS) provider types.
	KmsProviderLocal = "local_kms"
	KmsProviderAws   = "aws_kms"

	// Certificate store provider types
	CertStoreLocalDb  = "localdb"
	CertStoreDynamoDb = "dynamodb"
)
