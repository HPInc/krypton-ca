// package github.com/HPInc/krypton-ca/service/certmgr/kms_providers/aws_kms
// Author: Mahesh Unnikrishnan
// Component: Krypton Certificate Authority
// (C) HP Development Company, LP
// Purpose:
// Implements the ability to create and manage tenant signing certificates. The
// tenant signing certificate is used to sign device certificate requests. The CA
// supports the use of both common and per-tenant signing certificates.
package aws_kms

import (
	"crypto/rand"
	"crypto/x509"
	"fmt"

	"github.com/HPInc/krypton-ca/service/common"
	"go.uber.org/zap"
)

var (
	// Format for key aliases in AWS KMS.
	keyAliasFormat = "alias/%s"
)

// createCommonSigningCertificate - create a new signing certificate which
// is used to sign device certificates for tenants that do not have a
// distinct/separate tenant signing certificate. This common signing
// certificate also helps us save on the costs associated with KMS.
func (p *AwsKmsProvider) createCommonSigningCertificate() (string, error) {
	// For the common signing certificate, we do not provide a tenant name
	// to the certificate template. This certificate will have only the issuer
	// name.
	return p.CreateTenantSigningCertificate(common.CommonSigningKeyId, "")
}

// getCommonSigningCertificate - Get the common signing certificate which
// is used to sign device certificates for tenants that do not have a
// distinct/separate tenant signing certificate. If one doesn't already exist
// in the certificate store, a new common signing certificate is created.
func (p *AwsKmsProvider) getCommonSigningCertificate() (*common.SigningCertificate, error) {
	// Check to see if the common tenant signing certificate exists within the
	// certificate store. If it is not found, attempt to create it.
	// Retrieve the tenant signing certificate for the specified tenant.
	tenantCert, err := p.store.GetCertificate(common.CommonSigningKeyId)
	if err != nil {
		caLogger.Error("Failed to get the common signing certificate from certificate store!",
			zap.Error(err),
		)

		// Attempt to create the common signing certificate.
		_, err := p.createCommonSigningCertificate()
		if err != nil {
			caLogger.Error("Failed to create the common signing certificate!",
				zap.Error(err),
			)
			return nil, err
		}

		// Now, return the newly created common signing certificate.
		tenantCert, err = p.store.GetCertificate(common.CommonSigningKeyId)
		if err != nil {
			caLogger.Error("Failed to get the common signing certificate from certificate store!",
				zap.Error(err),
			)
			return nil, err
		}
	}

	return tenantCert, nil
}

// CreateTenantSigningCertificate - create a new tenant signing certificate for
// the specified tenant.
func (p *AwsKmsProvider) CreateTenantSigningCertificate(tenantID string,
	tenantName string) (string, error) {
	var certEntry common.SigningCertificate

	// Generate a new private key within KMS for the tenant signing certificate.
	// The KMS alias for this key is the tenant ID.
	tenantKeyID, err := p.newKmsKey(
		fmt.Sprintf("Signing key: %s", tenantID),
		fmt.Sprintf(keyAliasFormat, tenantID))
	if err != nil {
		caLogger.Error("Failed to generate a signing key in KMS!",
			zap.String("Tenant ID: ", tenantID),
			zap.Error(err),
		)
		return "", err
	}

	// Initialize the tenant signing certificate template.
	tenantCertTpl, err := common.NewTenantSigningCertificateTemplate(tenantID,
		tenantName)
	if err != nil {
		caLogger.Error("Failed to initialize a new tenant signing certificate template!",
			zap.String("Tenant ID:", tenantID),
			zap.Error(err),
		)
		return "", err
	}

	// Initialize a crypto signer that will be used to sign the tenant
	// signing certificate.
	tenantSigner, err := newKMSSigner(p.ctx, p.client, p.caKeyID)
	if err != nil {
		caLogger.Error("Failed to initialize a crypto signer for the signing key!",
			zap.String("Tenant ID: ", tenantID),
			zap.String("Tenant Key ID: ", tenantKeyID),
			zap.Error(err),
		)
		return "", err
	}

	// Get the public key associated with the newly created tenant key from KMS.
	tenantPublicKey, err := p.getKmsPublicKey(tenantKeyID)
	if err != nil {
		caLogger.Error("Failed to get public key associated with signing key in KMS",
			zap.String("Tenant ID: ", tenantID),
			zap.String("Tenant Key ID: ", tenantKeyID),
		)
		return "", err
	}

	// Generate the tenant signing certificate and sign it using the crypto
	// signer. This will cause the certificate to be signed using the CA
	// certificate.
	tenantCertBytes, err := x509.CreateCertificate(rand.Reader, tenantCertTpl,
		p.caCert, tenantPublicKey, tenantSigner)
	if err != nil {
		caLogger.Error("Failed to generate the signing certificate!",
			zap.String("Tenant ID: ", tenantID),
			zap.String("Tenant Key ID: ", tenantKeyID),
			zap.Error(err),
		)
		return "", err
	}

	// Persist the tenant signing certificate in the certificate store.
	certEntry.Certificate = tenantCertBytes
	certEntry.TenantID = tenantID
	certEntry.KmsKeyID = tenantKeyID

	err = p.store.AddCertificate(&certEntry)
	if err != nil {
		caLogger.Error("Failed to add the tenant signing certificate to the store!",
			zap.String("Tenant ID:", tenantID),
			zap.Error(err),
		)
		return "", err
	}

	caLogger.Info("Successfully generated the tenant signing certificate!",
		zap.String("Tenant Key ID:", tenantKeyID),
	)
	return string(tenantCertTpl.SubjectKeyId), nil
}

// GetTenantSigningCertificate - get the tenant signing certificate for
// the specified tenant.
func (p *AwsKmsProvider) GetTenantSigningCertificate(
	tenantID string) ([]byte, error) {

	// Retrieve the tenant signing certificate for the specified tenant.
	tenantCert, err := p.store.GetCertificate(tenantID)
	if err != nil {
		caLogger.Error("Failed to retrieve the tenant signing certificate for the tenant.",
			zap.String("Tenant ID:", tenantID),
		)
		return nil, err
	}

	return tenantCert.Certificate, nil
}

// DeleteTenantSigningCertificate - delete the tenant signing certificate for
// the specified tenant.
func (p *AwsKmsProvider) DeleteTenantSigningCertificate(tenantID string) error {

	// Delete the tenant signing certificate for the specified tenant.
	err := p.store.DeleteCertificate(tenantID)
	if err != nil {
		caLogger.Error("Failed to delete the tenant signing certificate!",
			zap.String("Tenant ID:", tenantID),
			zap.Error(err),
		)
		return err
	}

	// Delete the key for the tenant from KMS.
	err = p.deleteKmsKey(fmt.Sprintf(keyAliasFormat, tenantID))
	if err != nil {
		caLogger.Error("Failed to delete the tenant key from KMS!",
			zap.String("Tenant ID:", tenantID),
			zap.Error(err),
		)
		return err
	}

	return nil
}
