// package github.com/HPInc/krypton-ca/service/common
// Author: Mahesh Unnikrishnan
// Component: Krypton Certificate Authority
// (C) HP Development Company, LP
// Purpose:
// Utility functions to GOB encode and decode signing certificate entries. The
// signing certificates are GOB encoded and stored within the certificate store.
// The certificates read back from the certificate store are GOB decoded.
package common

import (
	"bytes"
	"encoding/gob"
)

// SigningCertificate - represents a signing certificate stored within the
// certificate store.
type SigningCertificate struct {
	// The unique identifier for the tenant represented by this entry.
	TenantID string

	// The KMS key ID for the signing key for this tenant.
	KmsKeyID string

	// The signing certificate for this tenant.
	Certificate []byte
}

// EncodeSigningCertificate - returns a gob encoded byte array representation of a
// signing certificate to be stored in the Bolt DB instance.
func EncodeSigningCertificate(entry *SigningCertificate) ([]byte, error) {
	buffer := &bytes.Buffer{}
	encoder := gob.NewEncoder(buffer)

	err := encoder.Encode(entry)
	if err != nil {
		return nil, err
	}

	return buffer.Bytes(), nil
}

// DecodeSigningCertificate - decodes the gob encoded entry and returns an entry
// containing information about the tenant's signing certificate.
func DecodeSigningCertificate(encodedEntry []byte) (*SigningCertificate, error) {
	buffer := bytes.NewReader(encodedEntry)
	decoder := gob.NewDecoder(buffer)

	entry := SigningCertificate{}
	err := decoder.Decode(&entry)
	if err != nil {
		return nil, err
	}

	return &entry, nil
}
