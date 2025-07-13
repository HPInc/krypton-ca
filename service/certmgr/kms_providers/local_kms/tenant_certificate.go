// package github.com/HPInc/krypton-ca/service/certmgr/kms_providers/local_kms
// Author: Mahesh Unnikrishnan
// Component: Krypton Certificate Authority
// (C) HP Development Company, LP
// Purpose:
// Implements the ability to create and manage tenant signing certificates. The
// tenant signing certificate is used to sign device certificate requests. The CA
// supports the use of both common and per-tenant signing certificates.
package local_kms

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"

	"github.com/HPInc/krypton-ca/service/common"
	"go.uber.org/zap"
)

// createCommonSigningCertificate - create a new signing certificate which
// is used to sign device certificates for tenants that do not have a
// distinct/separate tenant signing certificate.
func (p *LocalProvider) createCommonSigningCertificate() (string, error) {
	// For the common signing certificate, we do not provide a tenant name
	// to the certificate template. This certificate will have only the issuer
	// name.
	return p.CreateTenantSigningCertificate(common.CommonSigningKeyId, "")
}

// getCommonSigningCertificate - Get the common signing certificate which
// is used to sign device certificates for tenants that do not have a
// distinct/separate tenant signing certificate. If one doesn't already exist
// in the certificate store, a new common signing certificate is created.
func (p *LocalProvider) getCommonSigningCertificate() (*common.SigningCertificate, error) {
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
func (p *LocalProvider) CreateTenantSigningCertificate(tenantID string,
	tenantName string) (string, error) {
	var certEntry common.SigningCertificate

	// Generate a private key for the tenant signing certificate.
	tenantPrivateKey, err := rsa.GenerateKey(rand.Reader, common.KeySize)
	if err != nil {
		caLogger.Error("Failed to generate private key for the tenant signing certificate!",
			zap.String("Tenant ID:", tenantID),
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

	// Generate the tenant signing certificate.
	tenantCertBytes, err := x509.CreateCertificate(rand.Reader, tenantCertTpl,
		p.caCert, &tenantPrivateKey.PublicKey, p.caPrivateKey)
	if err != nil {
		caLogger.Error("Failed to generate the tenant signing certificate!",
			zap.String("Tenant ID:", tenantID),
			zap.Error(err),
		)
		return "", err
	}

	// PEM encode the locally generated tenant signing certificate's private key
	// & persist locally.
	err = storeTenantSigningCertificatePrivateKey(tenantID, tenantPrivateKey)
	if err != nil {
		caLogger.Error("Failed to encode the tenant signing certificate!",
			zap.String("Tenant ID:", tenantID),
			zap.Error(err),
		)
		return "", err
	}

	// Persist the tenant signing certificate in the certificate store.
	certEntry.Certificate = tenantCertBytes
	certEntry.TenantID = tenantID
	certEntry.KmsKeyID = ""

	err = p.store.AddCertificate(&certEntry)
	if err != nil {
		caLogger.Error("Failed to add the tenant signing certificate to the store!",
			zap.String("Tenant ID:", tenantID),
			zap.Error(err),
		)
		return "", err
	}

	caLogger.Info("Successfully generated the tenant signing certificate!",
		zap.String("Tenant ID:", tenantID),
	)
	return string(tenantCertTpl.SubjectKeyId), nil
}

// GetTenantSigningCertificate - get the tenant signing certificate for
// the specified tenant.
func (p *LocalProvider) GetTenantSigningCertificate(
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
func (p *LocalProvider) DeleteTenantSigningCertificate(
	tenantID string) error {

	// Delete the tenant signing certificate for the specified tenant.
	err := p.store.DeleteCertificate(tenantID)
	if err != nil {
		caLogger.Error("Failed to delete the tenant signing certificate!",
			zap.String("Tenant ID:", tenantID),
			zap.Error(err),
		)
		return err
	}

	// Locate the private key for the tenant signing certificate from the local
	// certificate store and delete it.
	err = os.Remove(tenantID + ".key")
	if err != nil {
		caLogger.Error("Error deleting the private key for tenant signing certificate!",
			zap.String("Tenant ID:", tenantID),
			zap.Error(err),
		)
		return err
	}

	return nil
}

// storeTenantSigningCertificatePrivateKey - PEM encode the tenant signing certificate's
// private key and save locally to file.
func storeTenantSigningCertificatePrivateKey(tenantID string,
	tenantPrivateKey *rsa.PrivateKey) error {

	// PEM encode the private key for the local tenant signing certificate and
	// write to file.
	err := common.EncodeAndStorePrivateKey(tenantID+".key", tenantPrivateKey)
	if err != nil {
		caLogger.Error("Failed to store the tenant signing private key!",
			zap.String("Tenant ID:", tenantID),
			zap.Error(err),
		)
		return err
	}

	return nil
}

// getTenantPrivateKey - retrieve the tenant signing certificate's private key
// for the specified tenant ID.
func (p *LocalProvider) getTenantPrivateKey(
	tenantID string) (*rsa.PrivateKey, error) {
	// Locate the private key for the tenant signing certificate from the local
	// certificate store and parse it.
	pemPkey, err := os.ReadFile(filepath.Clean(tenantID + ".key"))
	if err != nil {
		caLogger.Error("Error reading the private key for tenant signing certificate from file!",
			zap.String("Tenant ID:", tenantID),
			zap.Error(err),
		)
		return nil, err
	}

	pemPkeyBlock, _ := pem.Decode(pemPkey)
	if pemPkeyBlock == nil {
		caLogger.Error("Failed to decode the private key for the tenant signing certificate!",
			zap.String("Tenant ID:", tenantID),
		)
		return nil, errors.New("failed to decode private key for the tenant signing certificate")
	}

	tenantPkey, err := x509.ParsePKCS1PrivateKey(pemPkeyBlock.Bytes)
	if err != nil {
		caLogger.Error("Failed to parse the private key for the tenant signing certificate from file!",
			zap.String("Tenant ID:", tenantID),
			zap.Error(err),
		)
		return nil, err
	}

	return tenantPkey, nil
}
