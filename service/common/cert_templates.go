// package github.com/HPInc/krypton-ca/service/common
// Author: Mahesh Unnikrishnan
// Component: Krypton Certificate Authority
// (C) HP Development Company, LP
// Purpose:
// Defines certificate templates used to issue device certificates and tenant
// signing certificates. Also contains the certificate template used to issue
// the root CA signing certificate.
package common

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"time"
)

var (
	// OID format:
	// 1.3.6.1.4.1.58515         -> HP OID
	// 1.3.6.1.4.1.58515.7       -> WSS
	// 1.3.6.1.4.1.58515.7.1     -> Infrastructure
	// 1.3.6.1.4.1.58515.7.1.1   -> Krypton
	// 1.3.6.1.4.1.58515.7.1.1.1 -> CA root signing certificate
	// 1.3.6.1.4.1.58515.7.1.1.2 -> Tenant signing certificate
	// 1.3.6.1.4.1.58515.7.1.1.3 -> Device signing certificate
	CACertificateOid     = []int{1, 3, 6, 1, 4, 1, 58515, 7, 1, 1, 1}
	TenantCertificateOid = []int{1, 3, 6, 1, 4, 1, 58515, 7, 1, 1, 2}
	DeviceCertificateOid = []int{1, 3, 6, 1, 4, 1, 58515, 7, 1, 1, 3}
)

// CertTemplateConfig defines values used within CA certificate templates. The
// CA issues certificates using these values for various certificate
// fields/OIDs.
type CertTemplateConfig struct {
	// The name of the issuer of the certificate.
	IssuerName string `yaml:"issuer_name"`

	// The country to which the issuer belongs.
	Country string `yaml:"country"`

	// The province of the issuer's address.
	Province string `yaml:"province"`

	// The locality of the issuer.
	Locality string `yaml:"locality"`

	// The street address of the issuer.
	StreetAddress string `yaml:"street_address"`

	// The postal code of the issuer.
	PostalCode string `yaml:"postal_code"`

	// The organization issuing the certificate.
	Organization string `yaml:"organization"`
}

var templateConfig *CertTemplateConfig

// InitTemplateConfiguration initializes the certificate template configuration
// based on information parsed from the configuration file. See the config
// package, where the template information is parsed from the YAML configuration
// file.
func InitTemplateConfiguration(tplConfig *CertTemplateConfig) {
	templateConfig = tplConfig
}

// NewCACertificateTemplate - initialize a certificate template used
// to issue the CA certificate.
func NewCACertificateTemplate() (*x509.Certificate, error) {
	var err error

	// Initialize the CA certificate template.
	caCert := &x509.Certificate{
		SerialNumber: nil,
		Subject: pkix.Name{
			Country:            []string{templateConfig.Country},
			Province:           []string{templateConfig.Province},
			Locality:           []string{templateConfig.Locality},
			StreetAddress:      []string{templateConfig.StreetAddress},
			PostalCode:         []string{templateConfig.PostalCode},
			Organization:       []string{templateConfig.Organization},
			OrganizationalUnit: []string{templateConfig.IssuerName},
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().AddDate(CACertificateLifetimeYears, 0, 0),
		IsCA:      true,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth,
			x509.ExtKeyUsageServerAuth},
		KeyUsage: x509.KeyUsageDigitalSignature |
			x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		SignatureAlgorithm:    x509.SHA256WithRSA,
		ExtraExtensions: []pkix.Extension{{
			Id:       CACertificateOid,
			Critical: false,
		}},
	}

	// Issue a certificate serial number.
	caCert.SerialNumber, err = NewSerialNumber()
	if err != nil {
		return nil, err
	}

	return caCert, nil
}

// NewTenantSigningCertificateTemplate - initialize a certificate template used
// to issue tenant signing certificates.
func NewTenantSigningCertificateTemplate(tenantID string,
	tenantName string) (*x509.Certificate, error) {
	var err error

	// Initialize the tenant signing certificate template.
	tenantCert := &x509.Certificate{
		SerialNumber: nil,
		Subject: pkix.Name{
			Organization: []string{tenantName},
			CommonName:   "",
			ExtraNames:   nil,
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(TenantCertificateLifetimeYears, 0, 0),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		SignatureAlgorithm:    x509.SHA256WithRSA,
		ExtraExtensions: []pkix.Extension{{
			Id:       TenantCertificateOid,
			Critical: false,
		}},
	}

	// When creating the common signing key, do not assert the tenant ID in
	// the certificate template as an extra name.
	if tenantID == CommonSigningKeyId {
		tenantCert.Subject.CommonName = CommonTenantDeviceCertificateIssuer
	} else {
		tenantCert.Subject.CommonName = fmt.Sprintf(TenantDeviceCertificateIssuer, tenantName)
		tenantCert.Subject.ExtraNames = []pkix.AttributeTypeAndValue{
			{
				Type:  []int{2, 5, 4, 10},
				Value: tenantID,
			},
		}
	}

	// Issue a serial number for the certificate template.
	tenantCert.SerialNumber, err = NewSerialNumber()
	if err != nil {
		return nil, err
	}

	return tenantCert, nil
}

// NewDeviceCertificateTemplate - initialize a certificate template used to
// issue device certificates.
func NewDeviceCertificateTemplate(tenantID string, deviceID string,
	deviceCSR *x509.CertificateRequest) (*x509.Certificate, error) {
	var err error

	deviceCertTpl := &x509.Certificate{
		SerialNumber: nil,
		Subject: pkix.Name{
			CommonName: deviceID,
			ExtraNames: []pkix.AttributeTypeAndValue{
				{
					Type:  []int{2, 5, 4, 10},
					Value: tenantID,
				},
			},
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().AddDate(DeviceCertificateLifetimeYears, 0, 0),
		IsCA:      false,
		KeyUsage:  x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth,
			x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,

		Signature:          deviceCSR.Signature,
		SignatureAlgorithm: x509.SHA256WithRSA,

		PublicKeyAlgorithm: x509.RSA,
		PublicKey:          deviceCSR.PublicKey,
		ExtraExtensions: []pkix.Extension{{
			Id:       DeviceCertificateOid,
			Critical: false,
		}},
	}

	// Issue a serial number for the device certificate template.
	deviceCertTpl.SerialNumber, err = NewSerialNumber()
	if err != nil {
		return nil, err
	}

	return deviceCertTpl, nil
}
