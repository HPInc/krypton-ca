// package github.com/HPInc/krypton-ca/service/certmgr/kms_providers/aws_kms
// Author: Mahesh Unnikrishnan
// Component: Krypton Certificate Authority
// (C) HP Development Company, LP
// Purpose:
// Implements the ability to create and renew device certificates using the AWS
// KMS provider.
package aws_kms

import (
	"crypto/rand"
	"crypto/x509"
	"errors"
	"time"

	"github.com/HPInc/krypton-ca/service/common"
	"github.com/google/uuid"
	"go.mozilla.org/pkcs7"
	"go.uber.org/zap"
)

// CreateDeviceCertificate - Register a new device ID and issue a device
// certificate.
func (p *AwsKmsProvider) CreateDeviceCertificate(tenantID string,
	deviceCSR []byte) (string, []byte, []byte, time.Time, error) {

	// Validate the specified parameters.
	if (deviceCSR == nil) || (tenantID == "") {
		caLogger.Error("Invalid CSR or tenant ID!")
		return "", nil, nil, time.Now(), errors.New("invalid parameter")
	}

	// Parse and validate the device CSR received from the caller.
	parsedCSR, err := common.ParseDeviceCertificateSigningRequest(caLogger,
		deviceCSR)
	if err != nil {
		caLogger.Error("Failed to parse and validate the CSR!",
			zap.String("Tenant ID:", tenantID),
			zap.Error(err),
		)
		return "", nil, nil, time.Now(), err
	}

	// Retrieve the tenant signing certificate for the tenant from the
	// certificate store.
	certEntry, err := p.store.GetCertificate(tenantID)
	if err != nil {
		if err == common.ErrCertStoreNotFound {
			// If a distint tenant signing certificate was not found in the
			// certificate store, use the common signing certificate.
			certEntry = p.commonSigningCert
		} else {
			caLogger.Error("Failed to retrieve the tenant signing certificate",
				zap.String("Tenant ID:", tenantID),
				zap.Error(err),
			)
			return "", nil, nil, time.Now(), err
		}
	}

	tenantSigningCert, err := x509.ParseCertificate(certEntry.Certificate)
	if err != nil {
		caLogger.Error("Failed to parse the tenant signing certificate!",
			zap.String("Tenant ID:", tenantID),
			zap.Error(err),
		)
		return "", nil, nil, time.Now(), err
	}

	// Generate a device ID for the device.
	deviceID := uuid.New().String()

	// Initialize the device certificate template.
	deviceCertTpl, err := common.NewDeviceCertificateTemplate(tenantID, deviceID,
		parsedCSR)
	if err != nil {
		caLogger.Error("Failed to initialize a device certificate template!",
			zap.String("Tenant ID:", tenantID),
			zap.Error(err),
		)
		return "", nil, nil, time.Now(), err
	}

	// Initialize a crypto signer that will be used to sign the device
	// certificate.
	deviceSigner, err := newKMSSigner(p.ctx, p.client, certEntry.KmsKeyID)
	if err != nil {
		caLogger.Error("Failed to initialize a crypto signer for the device!",
			zap.String("Tenant ID:", tenantID),
			zap.Error(err),
		)
		return "", nil, nil, time.Now(), err
	}

	// Generate and sign the device certificate.
	deviceCertBytes, err := x509.CreateCertificate(rand.Reader, deviceCertTpl,
		tenantSigningCert, parsedCSR.PublicKey, deviceSigner)
	if err != nil {
		caLogger.Error("Failed to generate the device certificate!",
			zap.String("Tenant ID:", tenantID),
			zap.Error(err),
		)
		return "", nil, nil, time.Now(), err
	}

	// Return the tenant signing certificate and the CA certificate.
	parentCerts := []byte{}
	parentCerts = append(parentCerts, p.caCertBytes...)
	parentCerts = append(parentCerts, tenantSigningCert.Raw...)

	// Build a PKCS#7 degenerate "certs only" structure from
	// that ASN.1 certificates data.
	parentCerts, err = pkcs7.DegenerateCertificate(parentCerts)
	if err != nil {
		caLogger.Error("Failed to create degenerate PKCS7 object: %v",
			zap.Error(err),
		)
		return "", nil, nil, time.Now(), err
	}

	return deviceID, deviceCertBytes, parentCerts, deviceCertTpl.NotAfter, nil
}

// RenewDeviceCertificate - Issue a fresh device certificate for the device with
// the specified device ID.
func (p *AwsKmsProvider) RenewDeviceCertificate(tenantID string, deviceID string,
	deviceCSR []byte) (string, []byte, []byte, time.Time, error) {
	// Validate the specified parameters.
	if (deviceCSR == nil) || (tenantID == "") || (deviceID == "") {
		caLogger.Error("Invalid CSR, tenant ID or device ID!")
		return "", nil, nil, time.Now(), errors.New("invalid parameter")
	}

	// Parse and validate the device CSR received from the caller.
	parsedCSR, err := common.ParseDeviceCertificateSigningRequest(caLogger,
		deviceCSR)
	if err != nil {
		caLogger.Error("Failed to parse and validate the CSR!",
			zap.String("Tenant ID:", tenantID),
			zap.Error(err),
		)
		return "", nil, nil, time.Now(), err
	}

	// Retrieve the tenant signing certificate for the tenant from the
	// certificate store.
	certEntry, err := p.store.GetCertificate(tenantID)
	if err != nil {
		if err == common.ErrCertStoreNotFound {
			// If a distint tenant signing certificate was not found in the
			// certificate store, use the common signing certificate.
			certEntry = p.commonSigningCert
		} else {
			caLogger.Error("Failed to retrieve the tenant signing certificate",
				zap.String("Tenant ID:", tenantID),
				zap.Error(err),
			)
			return "", nil, nil, time.Now(), err
		}
	}

	tenantSigningCert, err := x509.ParseCertificate(certEntry.Certificate)
	if err != nil {
		caLogger.Error("Failed to parse the tenant signing certificate!",
			zap.String("Tenant ID:", tenantID),
			zap.Error(err),
		)
		return "", nil, nil, time.Now(), err
	}

	// Initialize the device certificate template.
	deviceCertTpl, err := common.NewDeviceCertificateTemplate(tenantID, deviceID,
		parsedCSR)
	if err != nil {
		caLogger.Error("Failed to initialize a device certificate template!",
			zap.String("Tenant ID:", tenantID),
			zap.Error(err),
		)
		return "", nil, nil, time.Now(), err
	}

	// Initialize a crypto signer that will be used to sign the device
	// certificate.
	deviceSigner, err := newKMSSigner(p.ctx, p.client, certEntry.KmsKeyID)
	if err != nil {
		caLogger.Error("Failed to initialize a crypto signer for the device!",
			zap.String("Tenant ID:", tenantID),
			zap.Error(err),
		)
		return "", nil, nil, time.Now(), err
	}

	// Generate and sign the device certificate.
	deviceCertBytes, err := x509.CreateCertificate(rand.Reader, deviceCertTpl,
		tenantSigningCert, parsedCSR.PublicKey, deviceSigner)
	if err != nil {
		caLogger.Error("Failed to generate the device certificate!",
			zap.String("Tenant ID:", tenantID),
			zap.Error(err),
		)
		return "", nil, nil, time.Now(), err
	}

	// Return the tenant signing certificate and the CA certificate.
	parentCerts := []byte{}
	parentCerts = append(parentCerts, tenantSigningCert.Raw...)
	parentCerts = append(parentCerts, p.caCertBytes...)

	// Build a PKCS#7 degenerate "certs only" structure from
	// that ASN.1 certificates data.
	parentCerts, err = pkcs7.DegenerateCertificate(parentCerts)
	if err != nil {
		caLogger.Error("Failed to create degenerate PKCS7 object: %v",
			zap.Error(err),
		)
		return "", nil, nil, time.Now(), err
	}

	return deviceID, deviceCertBytes, parentCerts, deviceCertTpl.NotAfter, nil
}
