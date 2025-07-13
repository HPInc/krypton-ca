// package github.com/HPInc/krypton-ca/service/certmgr/kms_providers
// Author: Mahesh Unnikrishnan
// Component: Krypton Certificate Authority
// (C) HP Development Company, LP
// Purpose:
// Implements the KmsProvider interface which is used to plug in various KMS
// (key management service) providers into the CA. Currently supported KMS
// providers are:
//   - local KMS provider - uses the local filesystem and crypto API to issue
//     certificates.
//   - AWS KSM provider - uses the AWS Key Management Service (KMS) to issue
//     certificates. This option is much more secure since it relies on the
//     hardware backed HSM module to store the certificate signing private key.
package kms_providers

import (
	"time"

	"github.com/HPInc/krypton-ca/service/config"
	"go.uber.org/zap"
)

// KmsProvider - defines an interface that must be implemented by key management
// service providers (eg. AWS KMS)
type KmsProvider interface {
	// Init - Initialize the provider.
	Init(*zap.Logger, *config.ConfigMgr) error

	// CreateTenantSigningCertificate - Initialize a new signing certificate for
	// the specified tenant.
	CreateTenantSigningCertificate(tenantID string,
		tenantName string) (string, error)

	// GetTenantSigningCertificate - Return the signing certificate for the
	// specified tenant.
	GetTenantSigningCertificate(tenantID string) ([]byte, error)

	// DeleteTenantSigningCertificate - Delete the signing certificate for the
	// specified tenant.
	DeleteTenantSigningCertificate(tenantID string) error

	// CreateDeviceCertificate - Issue a new device certificate within the
	// specified tenant in exchange for the specified certificate signing
	// request (CSR). This action issues a unique device identifier for the
	// device and persists it inside the signed device certificate.
	CreateDeviceCertificate(tenantID string,
		deviceCSR []byte) (string, []byte, []byte, time.Time, error)

	// RenewDeviceCertificate - Issue a fresh device certificate within the
	// specified tenant in exchange for the specified CSR. The existing
	// device ID of the device is re-used and persisted within the signed
	// device certificate. This API is invoked when the currently issued device
	// certificate has expired.
	RenewDeviceCertificate(tenantID string, deviceID string,
		deviceCSR []byte) (string, []byte, []byte, time.Time, error)
}
