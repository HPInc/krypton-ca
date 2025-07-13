// package github.com/HPInc/krypton-ca/service/certmgr/certstore/localdb
// Author: Mahesh Unnikrishnan
// Component: Krypton Certificate Authority
// (C) HP Development Company, LP
// Purpose:
// Implements the local certificate store using an embedded Bolt DB instance.
package localdb

import (
	"fmt"
	"time"

	bolt "go.etcd.io/bbolt"
	"go.uber.org/zap"
)

var (
	caLogger *zap.Logger
)

const (
	// Name of the Bolt DB database file.
	certDBName = "certs.db"

	// Bucket within the database where signing certificates are stored.
	certsBucketName = "SigningCertificates"
)

// Implements a local signing certificate store provider using a local
// Bolt DB instance.
type LocalDbProvider struct {
	// Handle to the Bolt database used to store the signing certificates.
	dbHandle *bolt.DB
}

// Init - intialize a BoltDB based local database used to store signing
// certificates.
func (p *LocalDbProvider) Init(logger *zap.Logger) error {
	var err error
	caLogger = logger

	p.dbHandle, err = bolt.Open(certDBName, 0600,
		&bolt.Options{Timeout: 1 * time.Second})
	if err != nil {
		caLogger.Error("Failed to open the local cert database!",
			zap.Error(err),
		)
		return err
	}

	// Create a bucket to store signing certificates , if it doesn't already
	// exist.
	err = p.dbHandle.Update(func(tx *bolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists([]byte(certsBucketName))
		if err != nil {
			return fmt.Errorf("create bucket failed with error: %s", err)
		}
		return nil
	})
	if err != nil {
		caLogger.Error("Failed to create a bucket to store certificates!",
			zap.Error(err),
		)
		_ = p.dbHandle.Close()
		return err
	}

	caLogger.Info("Successfully initialized the local certificate database!")
	return nil
}

// Shutdown - shutdown the local BoltDB instance used to store signing
// certificates.
func (p *LocalDbProvider) Shutdown() {
	err := p.dbHandle.Close()
	if err != nil {
		caLogger.Error("Failed to shut down the local certificate database!",
			zap.Error(err),
		)
		return
	}

	caLogger.Info("Successfully shut down the local certificate database!")
}
