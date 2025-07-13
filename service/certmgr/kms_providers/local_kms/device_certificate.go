// package github.com/HPInc/krypton-ca/service/certmgr/kms_providers/local_kms
// Author: Mahesh Unnikrishnan
// Component: Krypton Certificate Authority
// (C) HP Development Company, LP
// Purpose:
// Implements the ability to create and renew device certificates using the local
// KMS provider.
package local_kms

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"time"

	"github.com/HPInc/krypton-ca/service/common"
	"github.com/google/uuid"
	"go.mozilla.org/pkcs7"
	"go.uber.org/zap"
)

// CreateDeviceCertificate API is used to create a new device certificate using
// the local KMS provider. The device certificate is signed by either the common
// signing certificate or the tenant specific signing certificate (if configured)
func (p *LocalProvider) CreateDeviceCertificate(tenantID string,
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
		caLogger.Error("Failed to parse and validate the device CSR!",
			zap.String("Tenant ID:", tenantID),
			zap.Error(err),
		)
		return "", nil, nil, time.Now(), err
	}

	// Issue a new device ID for the device & generate a device certificate.
	return p.generateDeviceCertificate(tenantID, uuid.NewString(), parsedCSR)
}

// RenewDeviceCertificate API is used to provide a renewed device certificate
// using the local KMS provider. The device ID previously issued to the device
// is maintained and the certificate is signed by either the common signing
// certificate or the tenant specific signing certificate (if configured)
func (p *LocalProvider) RenewDeviceCertificate(tenantID string, deviceID string,
	deviceCSR []byte) (string, []byte, []byte, time.Time, error) {

	// Validate the specified parameters.
	if (deviceCSR == nil) || (tenantID == "") || (deviceID == "") {
		caLogger.Error("Invalid CSR, tenant ID or device ID!")
		return "", nil, nil, time.Now(), errors.New("invalid parameter")
	}

	// Parse and validate the device CSR received from the caller.
	parsedCSR, err := common.ParseDeviceCertificateSigningRequest(caLogger, deviceCSR)
	if err != nil {
		caLogger.Error("Failed to parse and validate the device CSR!",
			zap.String("Tenant ID:", tenantID),
			zap.Error(err),
		)
		return "", nil, nil, time.Now(), err
	}

	// Use the existing device ID and generate a renewed device certificate.
	return p.generateDeviceCertificate(tenantID, deviceID, parsedCSR)
}

func (p *LocalProvider) generateDeviceCertificate(tenantID string, deviceID string,
	parsedCSR *x509.CertificateRequest) (string, []byte, []byte, time.Time, error) {
	var (
		err               error
		tenantSigningCert *x509.Certificate
		tenantPkey        *rsa.PrivateKey
	)

	// Retrieve the tenant signing certificate and private key for the
	// specified tenant.
	if p.perTenantSigningEnabled {
		certEntry, err := p.store.GetCertificate(tenantID)
		if err != nil {
			if err != common.ErrCertStoreNotFound {
				caLogger.Error("Failed to retrieve the tenant signing certificate",
					zap.String("Tenant ID:", tenantID),
					zap.Error(err),
				)
				return "", nil, nil, time.Now(), err
			}
			// Fall through to using the common signing certificate to sign the
			// device certificate for this tenant. This is because no tenant specific
			// signing certificate is configured for this tenant.
		} else {
			// Tenant signing certificate is configured for this tenant. Parse the
			// tenant signing certificate and private key retrieved from the store.
			tenantSigningCert, err = x509.ParseCertificate(certEntry.Certificate)
			if err != nil {
				caLogger.Error("Failed to parse the tenant signing certificate!",
					zap.String("Tenant ID:", tenantID),
					zap.Error(err),
				)
				return "", nil, nil, time.Now(), err
			}

			tenantPkey, err = p.getTenantPrivateKey(certEntry.TenantID)
			if err != nil {
				caLogger.Error("Failed to retrieve the certificate signing private key for the tenant.",
					zap.String("Tenant ID:", tenantID),
				)
				return "", nil, nil, time.Now(), err
			}
		}
	}

	// Use the common tenant signing key if:
	//  - Per tenant signing is disabled -
	//  - Specific tenant signing certificate is not configured
	if tenantSigningCert == nil {
		tenantSigningCert = p.commonSigningCert
		tenantPkey = p.commonSigningCertPkey
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

	// Generate the device certificate.
	deviceCertBytes, err := x509.CreateCertificate(rand.Reader, deviceCertTpl,
		tenantSigningCert, parsedCSR.PublicKey, tenantPkey)
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
