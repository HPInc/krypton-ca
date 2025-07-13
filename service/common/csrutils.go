// package github.com/HPInc/krypton-ca/service/common
// Author: Mahesh Unnikrishnan
// Component: Krypton Certificate Authority
// (C) HP Development Company, LP
// Purpose:
// Utility functions to create, parse and validate certificate signing requests.
package common

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"

	"go.uber.org/zap"
)

// CreateDeviceCertificateSigningRequest - Generate a certificate signing
// request that can be used to request a device certificate.
func CreateDeviceCertificateSigningRequest() ([]byte, error) {
	devicePKey, err := rsa.GenerateKey(rand.Reader, KeySize)
	if err != nil {
		return nil, err
	}

	deviceCsrTpl := x509.CertificateRequest{
		Subject:            pkix.Name{},
		SignatureAlgorithm: x509.SHA256WithRSA,
		PublicKeyAlgorithm: x509.RSA,
		PublicKey:          devicePKey.PublicKey,
	}

	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, &deviceCsrTpl, devicePKey)
	if err != nil {
		return nil, err
	}

	return csrBytes, err
}

// ParseDeviceCertificateSigningRequest - parse the specified device signing
// certificate request.
func ParseDeviceCertificateSigningRequest(caLogger *zap.Logger,
	deviceCSR []byte) (*x509.CertificateRequest, error) {
	// Parse the CSR.
	parsedCSR, err := x509.ParseCertificateRequest(deviceCSR)
	if err != nil {
		caLogger.Error("Failed to parse the specified CSR.")
		return nil, errors.New("failed to parse csr")
	}

	// Check the signature of the specified CSR.
	err = parsedCSR.CheckSignature()
	if err != nil {
		caLogger.Error("Failed to check the signature of the specified CSR.")
		return nil, errors.New("failed to check csr signature")
	}

	err = validateCertificateSigningRequest(caLogger, parsedCSR)
	if err != nil {
		caLogger.Error("Validation checks failed for the specified CSR.")
		return nil, errors.New("failed to validate csr")
	}

	return parsedCSR, nil
}

// Perform validation checks on the device certificate signing request.
func validateCertificateSigningRequest(caLogger *zap.Logger,
	deviceCSR *x509.CertificateRequest) error {
	// Check the signature algorithm specified in the CSR.
	if deviceCSR.SignatureAlgorithm != x509.SHA256WithRSA {
		caLogger.Error("Unsupported signature algorithm specified in CSR")
		return errors.New("unsupported signature algorithm")
	}

	if deviceCSR.PublicKeyAlgorithm != x509.RSA {
		caLogger.Error("Unsupported public key algorithm specified in CSR")
		return errors.New("unsupported public key algorithm")
	}

	return nil
}
