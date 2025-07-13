// package github.com/HPInc/krypton-ca/service/certmgr/kms_providers/aws_kms
// Author: Mahesh Unnikrishnan
// Component: Krypton Certificate Authority
// (C) HP Development Company, LP
// Purpose:
// Generates the CA certificate used for signing certificate requests by the AWS
// KMS Provider.
package aws_kms

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"

	"github.com/HPInc/krypton-ca/service/common"
	"github.com/HPInc/krypton-ca/service/metrics"
	"go.uber.org/zap"
)

// getCACertificate - Retrieve the CA certificate from the certificate store
// and check to see if its public key matches the corresponding CA key stored
// in KMS.
func (p *AwsKmsProvider) getCACertificate() error {
	// Retrieve the public key associated with the CA key from KMS.
	caPublicKey, err := p.getCAKey()
	if err != nil {
		caLogger.Error("Failed to get public key associated with CA key in KMS",
			zap.Error(err),
		)
		return err
	}

	// Retrieve the CA certificate from the certificate store.
	certEntry, err := p.store.GetCertificate(p.caKeyID)
	if err != nil {
		caLogger.Error("Failed to get the CA certificate from the cert store",
			zap.Error(err),
		)
		return err
	}

	p.caCert, err = x509.ParseCertificate(certEntry.Certificate)
	if err != nil {
		caLogger.Error("Failed to parse the CA certificate!",
			zap.Error(err),
		)
		return err
	}

	// Check if the public key within the CA certificate matches that retrieved
	// from KMS. These must match in order to use the CA certificate successfully
	// for signing purposes.
	if !p.caCert.PublicKey.(*rsa.PublicKey).Equal(caPublicKey) {
		caLogger.Error("CA certificate public key doesn't match CA key stored in KMS!",
			zap.Error(err),
		)
		return fmt.Errorf("key mismatch: CA certificate public key doesn't match CA key in KMS")
	}

	return nil
}

// ///////////////////// *** IN TEST MODE only *** ///////////////////////////
// Generate a CA certificate using the AWS KMS provider. We do not expect to
// create the CA certificate in production from within the service. In prod,
// the CA certificate should already be present within the KMS store and the
// KMS key ID (alias) for the certificate should be provided to the service.
// ///////////////////////////////////////////////////////////////////////////
func (p *AwsKmsProvider) generateCACertificate(issuerName string) error {
	// Instantiate a new CA certificate template.
	caCertTpl, err := common.NewCACertificateTemplate()
	if err != nil {
		caLogger.Error("Failed to initialize the CA certificate template!",
			zap.Error(err),
		)
		return err
	}

	// Check if the CA key exists in KMS. If so, use that to generate a CA
	// certificate. Else, create a new CA key and use the new key to
	// generate the CA certificate.
	_, err = p.getCAKey()
	if err != nil {
		// Generate a new CA key within KMS to use for the CA certificate.
		p.caKeyID, err = p.generateCAKey(issuerName)
		if err != nil {
			caLogger.Error("Failed to generate the CA key in KMS!",
				zap.Error(err),
			)
			return err
		}
	}

	// Initialize a crypto signer that will be used to sign the CA
	// certificate.
	caSigner, err := newKMSSigner(p.ctx, p.client, p.caKeyID)
	if err != nil {
		caLogger.Error("Failed to initialize a crypto signer for the CA!",
			zap.Error(err),
		)
		return err
	}

	caPublicKey := caSigner.Public()
	if caPublicKey == nil {
		caLogger.Error("Failed to get public key associated with CA key in KMS",
			zap.String("CA Key ID: ", p.caKeyID),
		)
		return errors.New("cannot get CA public key")
	}

	// Generate the CA certificate and sign it using the crypto signer.
	// This will cause the certificate to be signed using the CA key stored
	// within KMS.
	p.caCertBytes, err = x509.CreateCertificate(rand.Reader, caCertTpl,
		caCertTpl, caPublicKey, caSigner)
	if err != nil {
		caLogger.Error("Failed to sign the CA certificate using AWS KMS!",
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

	p.caCert.PublicKey = caPublicKey
	return nil
}

func (p *AwsKmsProvider) generateCAKey(issuerName string) (string, error) {
	return p.newKmsKey(issuerName, p.caKeyID)
}

func (p *AwsKmsProvider) getCAKey() (crypto.PublicKey, error) {
	// Retrieve the public key associated with the CA key from KMS.
	caPublicKey, err := p.getKmsPublicKey(p.caKeyID)
	if err != nil {
		caLogger.Error("Failed to get public key associated with CA key in KMS",
			zap.Error(err),
		)
		metrics.MetricAwsKmsCAKeyRetrievalFailures.Inc()
		return nil, err
	}

	metrics.MetricAwsKmsCAKeyRetrieved.Inc()
	return caPublicKey, nil
}
