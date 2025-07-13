// package github.com/HPInc/krypton-ca/service/certmgr/kms_providers/local_kms
// Author: Mahesh Unnikrishnan
// Component: Krypton Certificate Authority
// (C) HP Development Company, LP
// Purpose:
// Generates the CA certificate used for signing certificate requests by the local
// KMS Provider.
package local_kms

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"

	"github.com/HPInc/krypton-ca/service/common"
	"go.uber.org/zap"
)

// Create a local CA certificate. This provider is used only for testing
// purposes. For production, the CA certificate will be stored in the
// Key Management Service (KMS).
func (p *LocalProvider) generateLocalCACertificate() error {
	var err error

	// Generate a private key for the CA certificate.
	p.caPrivateKey, err = rsa.GenerateKey(rand.Reader, common.KeySize)
	if err != nil {
		caLogger.Error("Failed to generate private key for local CA certificate!",
			zap.Error(err),
		)
		return err
	}

	// Initialize the CA certificate template.
	p.caCert, err = common.NewCACertificateTemplate()
	if err != nil {
		caLogger.Error("Failed to initialize CA certificate template!",
			zap.Error(err),
		)
		return err
	}

	// Generate the CA certificate.
	p.caCertBytes, err = x509.CreateCertificate(rand.Reader, p.caCert, p.caCert,
		&p.caPrivateKey.PublicKey, p.caPrivateKey)
	if err != nil {
		caLogger.Error("Failed to generate local CA certificate!",
			zap.Error(err),
		)
		return err
	}

	// Parse and store the signed CA certificate in memory.
	p.caCert, err = x509.ParseCertificate(p.caCertBytes)
	if err != nil {
		caLogger.Error("Failed to parse the signed CA certificate!",
			zap.Error(err),
		)
		return err
	}

	// PEM encode and store the locally generated CA certificate and
	// its private key.
	err = p.encodeLocalCACertificate()
	if err != nil {
		caLogger.Error("Failed to encode CA certificate!",
			zap.Error(err),
		)
		return err
	}

	return nil
}

// PEM encode and store the CA certificate to file.
func (p *LocalProvider) encodeLocalCACertificate() error {
	// PEM encode the generated CA certificate and write to file.
	certfh, err := os.Create(pemCACertificateFile)
	if err != nil {
		caLogger.Error("Failed to create a file to store CA certificate",
			zap.Error(err),
		)
		return err
	}

	err = pem.Encode(certfh, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: p.caCertBytes,
	})
	if err != nil {
		caLogger.Error("Failed to PEM encode the local CA certificate",
			zap.Error(err),
		)
		_ = certfh.Close()
		return err
	}
	_ = certfh.Close()

	// PEM encode the private key for the local CA certificate and write
	// to file.
	pkeyfh, err := os.Create(pemCAPrivateKeyFile)
	if err != nil {
		caLogger.Error("Failed to PEM encode the local CA certificate",
			zap.Error(err),
		)
		return err
	}

	err = pem.Encode(pkeyfh, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(p.caPrivateKey),
	})
	if err != nil {
		caLogger.Error("Failed to PEM encode the local CA private key",
			zap.Error(err),
		)
		_ = pkeyfh.Close()
		return err
	}
	_ = pkeyfh.Close()

	return nil
}
