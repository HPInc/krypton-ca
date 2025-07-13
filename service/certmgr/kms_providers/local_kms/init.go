// package github.com/HPInc/krypton-ca/service/certmgr/kms_providers/local_kms
// Author: Mahesh Unnikrishnan
// Component: Krypton Certificate Authority
// (C) HP Development Company, LP
// Purpose:
// Initializes the local KMS provider.
package local_kms

import (
	"crypto/rsa"
	"crypto/x509"

	"github.com/HPInc/krypton-ca/service/certmgr/certstore"
	"github.com/HPInc/krypton-ca/service/config"
	"go.uber.org/zap"
)

var (
	caLogger *zap.Logger
)

const (
	pemCAPrivateKeyFile  = "ca.key"
	pemCACertificateFile = "ca.cert"
)

// LocalProvider - a local file system based key management service provider.
// This provider is meant only for testing purposes and does not provide much
// security guarantees for keys generated using it. In production, we expect
// to use something like AWS KMS (Key Management Service), which can provide
// guarantees such as hardware bound protection (HSM) for private keys.
type LocalProvider struct {
	// The private key for the CA root certificate.
	caPrivateKey *rsa.PrivateKey

	// The CA root certificate.
	caCert      *x509.Certificate
	caCertBytes []byte

	// The common signing certificate.
	commonSigningCert     *x509.Certificate
	commonSigningCertPkey *rsa.PrivateKey

	// Whether to use a per-tenant signing certificate to sign device
	// certificates issued by the CA.
	perTenantSigningEnabled bool

	// Certificate store used to persist tenant signing certificates.
	store certstore.CertStore
}

// Init - initialize the local store certificate provider.
func (p *LocalProvider) Init(logger *zap.Logger, cfgMgr *config.ConfigMgr) error {
	var err error
	caLogger = logger

	p.perTenantSigningEnabled = cfgMgr.IsPerTenantSigningEnabled()

	// Initialize the certificate store provider.
	p.store, err = certstore.Init(caLogger, cfgMgr.GetCertStoreProvider())
	if err != nil {
		caLogger.Error("Failed to initialize certificate store provider!",
			zap.String("Provider name: ", cfgMgr.GetCertStoreProvider()),
			zap.Error(err),
		)
		return err
	}

	// Generate a local CA certificate and its private key. The local
	// CA root certificate will be used for signing.
	err = p.generateLocalCACertificate()
	if err != nil {
		caLogger.Error("Failed to initialize local CA certificate provider!",
			zap.Error(err),
		)
		return err
	}

	// Initialize the common signing certificate & its signing key.
	commonSigningCert, err := p.getCommonSigningCertificate()
	if err != nil {
		caLogger.Error("Failed to get the common signing certificate from certificate store!",
			zap.Error(err),
		)
		return err
	}

	p.commonSigningCert, err = x509.ParseCertificate(commonSigningCert.Certificate)
	if err != nil {
		caLogger.Error("Failed to parse the common signing certificate!",
			zap.Error(err),
		)
		return err
	}

	p.commonSigningCertPkey, err = p.getTenantPrivateKey(commonSigningCert.TenantID)
	if err != nil {
		caLogger.Error("Failed to retrieve the common certificate signing private key!",
			zap.Error(err),
		)
		return err
	}

	return nil
}
