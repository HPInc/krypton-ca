// package github.com/HPInc/krypton-ca/service/certmgr/certstore/localdb
// Author: Mahesh Unnikrishnan
// Component: Krypton Certificate Authority
// (C) HP Development Company, LP
// Purpose:
// Implements the APIs used to manage the lifetime of certificates stored in the
// localdb certificate store.
package localdb

import (
	"github.com/HPInc/krypton-ca/service/common"
	bolt "go.etcd.io/bbolt"
	"go.uber.org/zap"
)

// AddCertificate - Adds the specified signing certificate to the local
// certificate store (bolt instance).
func (p *LocalDbProvider) AddCertificate(entry *common.SigningCertificate) error {
	err := p.dbHandle.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(certsBucketName))
		encodedEntry, err := common.EncodeSigningCertificate(entry)
		if err != nil {
			return err
		}

		return b.Put([]byte(entry.TenantID), encodedEntry)
	})
	if err != nil {
		caLogger.Error("Failed to add the certificate to the store!",
			zap.Error(err),
		)
		return err
	}

	caLogger.Debug("Added the certificate to the store!",
		zap.String("Tenant ID:", entry.TenantID),
	)
	return nil
}

// GetCertificate - Returns the signing certificate for the specified ID
// from the local certificate store.
func (p *LocalDbProvider) GetCertificate(
	certID string) (*common.SigningCertificate, error) {
	var entry *common.SigningCertificate

	err := p.dbHandle.View(func(tx *bolt.Tx) error {
		var err error
		b := tx.Bucket([]byte(certsBucketName))
		encodedEntry := b.Get([]byte(certID))
		if encodedEntry == nil {
			caLogger.Error("Specified signing certificate was not found in the store!",
				zap.String("Certificate ID:", certID),
			)
			return common.ErrCertStoreNotFound
		}

		// Decode the certificate entry.
		entry, err = common.DecodeSigningCertificate(encodedEntry)
		return err
	})

	return entry, err
}

// DeleteCertificate - Removes the specified signing certificate
// from the local certificate store.
func (p *LocalDbProvider) DeleteCertificate(certID string) error {
	err := p.dbHandle.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(certsBucketName))

		err := b.Delete([]byte(certID))
		return err
	})

	if err != nil {
		caLogger.Error("Failed to remove the signing certificate from the store!",
			zap.String("Certificate ID:", certID),
			zap.Error(err),
		)
		return err
	}
	caLogger.Debug("Successfully removed the signing certificate from the store!",
		zap.String("Certificate ID:", certID),
	)
	return nil
}
