// package github.com/HPInc/krypton-ca/service/common
// Author: Mahesh Unnikrishnan
// Component: Krypton Certificate Authority
// (C) HP Development Company, LP
// Purpose:
// Utility functions to encode and store the certificate and its private key to
// file. Also contains logic to issue serial numbers to certificates.
package common

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
)

// Specifies the max (top end of the) range for certificate serial numbers.
var maxSerialNumber = big.NewInt(0).Exp(big.NewInt(2), big.NewInt(130), nil)

// NewSerialNumber generates cryptographically strong pseudo-random between
// 0 - maxSerialNumber
func NewSerialNumber() (*big.Int, error) {
	n, err := rand.Int(rand.Reader, maxSerialNumber)
	return n, err
}

// EncodeAndStoreCertificate - PEM encode the specified certificate bytes
// and write to the specified file.
func EncodeAndStoreCertificate(fileName string, certBytes []byte) error {
	// Create and open a handle to the file within which to store the
	// certificate.
	certfh, err := os.Create(filepath.Clean(fileName))
	if err != nil {
		return err
	}

	// PEM encode the certificate and write to file.
	err = pem.Encode(certfh, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	})
	if err != nil {
		_ = certfh.Close()
		return err
	}

	err = certfh.Close()
	if err != nil {
		return err
	}

	return nil
}

// EncodeAndStorePrivateKey is used to PEM encode the specified RSA private
// key and write it to the specified file.
func EncodeAndStorePrivateKey(fileName string, key *rsa.PrivateKey) error {
	// Open a handle to the file within which to store the RSA private key.
	pkeyfh, err := os.OpenFile(filepath.Clean(fileName),
		os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}

	// Marshal the private key into PKCS1 format for storage.
	pKeyBytes := x509.MarshalPKCS1PrivateKey(key)
	if pKeyBytes == nil {
		_ = pkeyfh.Close()
		return errors.New("failed to marshal private key")
	}

	// PEM encode the marshalled private key and write to file.
	err = pem.Encode(pkeyfh, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: pKeyBytes,
	})
	if err != nil {
		_ = pkeyfh.Close()
		return err
	}

	err = pkeyfh.Close()
	if err != nil {
		return err
	}

	return nil
}
