// package github.com/HPInc/krypton-ca/service/common
// Author: Mahesh Unnikrishnan
// Component: Krypton Certificate Authority
// (C) HP Development Company, LP
// Purpose:
// Errors returned by various components of the CA.
package common

import "errors"

var (
	// The requested signing certificate was not found in the certificate store
	ErrCertStoreNotFound = errors.New("certificate not found in store")

	// The configuration for the CA has requested the use of an invalid or
	// unsupported certificate store.
	ErrInvalidCertStore = errors.New("unsupported certificate store provider requested")

	// The configuration for the CA has requested the user of an invalid or
	// unsupported KMS provider.
	ErrInvalidKmsProvider = errors.New("unsupported KMS provider requested")
)
