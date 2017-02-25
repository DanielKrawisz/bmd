// Originally derived from: btcsuite/btcd/database/db.go
// Copyright (c) 2013-2015 Conformal Systems LLC.

// Copyright (c) 2015 Monetas.
// Copyright 2016 Daniel Krawisz.
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package database

import (
	"errors"
	"time"

	"github.com/DanielKrawisz/bmutil"
	"github.com/DanielKrawisz/bmutil/cipher"
	"github.com/DanielKrawisz/bmutil/hash"
	"github.com/DanielKrawisz/bmutil/identity"
	"github.com/DanielKrawisz/bmutil/wire"
	"github.com/DanielKrawisz/bmutil/wire/obj"
)

// ExpiredCacheTime is how long we store expired objects, just in case.
const ExpiredCacheTime = -time.Hour * 3

// Errors that the various database functions may return.
var (
	ErrDbClosed          = errors.New("database is closed")
	ErrDuplicateObject   = errors.New("duplicate insert attempted")
	ErrDbDoesNotExist    = errors.New("non-existent database")
	ErrDbUnknownType     = errors.New("non-existent database type")
	ErrExpired           = errors.New("object is expired")
	ErrNotImplemented    = errors.New("method has not yet been implemented")
	ErrNonexistentObject = errors.New("object doesn't exist in database")
)

// ObjectWithCounter is a struct to couple an object message with its counter
// value. It's returned by FetchObjectsFromCounter.
type ObjectWithCounter struct {
	Counter uint64
	Object  obj.Object
}

// Db defines a generic interface that is used to request and insert data into
// the database. This interface is intended to be agnostic to actual mechanism
// used for backend data storage. The AddDBDriver function can be used to add a
// new backend data storage method.
type Db interface {
	// Close cleanly shuts down the database and syncs all data.
	Close() error

	// ExistsObject returns whether or not an object with the given inventory
	// hash exists in the database.
	ExistsObject(*hash.Sha) (bool, error)

	// FetchObjectByHash returns an object from the database as a wire.MsgObject.
	FetchObjectByHash(*hash.Sha) (obj.Object, error)

	// FetchObjectByCounter returns the corresponding object based on the
	// counter. Note that each object type has a different counter, with unknown
	// objects being consolidated into one counter. Counters are meant for use
	// as a convenience method for fetching new data from database since last
	// check.
	FetchObjectByCounter(wire.ObjectType, uint64) (obj.Object, error)

	// FetchObjectsFromCounter returns a slice of `count' objects which have a
	// counter position starting from `counter'. It also returns the counter
	// value of the last object, which could be useful for more queries to the
	// function.
	FetchObjectsFromCounter(objType wire.ObjectType, counter uint64,
		count uint64) ([]ObjectWithCounter, uint64, error)

	// FetchIdentityByAddress returns identity.Public stored in the form
	// of a PubKey message in the pubkey database.
	FetchIdentityByAddress(bmutil.Address) (*identity.Public, error)

	// FetchRandomInvHashes returns at most the specified number of
	// inventory hashes corresponding to random unexpired objects from
	// the database. It does not guarantee that the number of returned
	// inventory vectors would be `count'.
	FetchRandomInvHashes(count uint64) ([]*wire.InvVect, error)

	// GetCounter returns the highest value of counter that exists for objects
	// of the given type.
	GetCounter(wire.ObjectType) (uint64, error)

	// InsertObject inserts the given object into the database and returns the
	// counter position. If the object is a PubKey, it inserts it into a
	// separate place where it isn't touched by RemoveObject or
	// RemoveExpiredObjects and has to be removed using RemovePubKey.
	InsertObject(obj.Object) (uint64, error)

	// RemoveObject removes the object with the specified hash from the
	// database. Does not remove PubKeys.
	RemoveObject(*hash.Sha) error

	// RemoveObjectByCounter removes the object with the specified counter value
	// from the database.
	RemoveObjectByCounter(wire.ObjectType, uint64) error

	// RemoveExpiredObjects prunes all objects in the main circulation store
	// whose expiry time has passed (along with a margin of 3 hours). This does
	// not touch the pubkeys stored in the public key collection.
	RemoveExpiredObjects() ([]*hash.Sha, error)

	// RemoveEncryptedPubKey removes a v4 PubKey with the specified tag from the
	// encrypted PubKey store. Note that it doesn't touch the general object
	// store and won't remove the public key from there.
	RemoveEncryptedPubKey(*hash.Sha) error

	// RemovePublicIdentity removes the public identity corresponding the given
	// address from the database. This includes any v2/v3/previously used v4
	// identities. Note that it doesn't touch the general object store and won't
	// remove the public key object from there.
	RemovePublicIdentity(bmutil.Address) error
}

// DriverDB defines a structure for backend drivers to use when they registered
// themselves as a backend which implements the Db interface.
type DriverDB struct {
	DbType string
	OpenDB func(args ...interface{}) (pbdb Db, err error)
}

// driverList holds all of the registered database backends.
var driverList []DriverDB

// AddDBDriver adds a back end database driver to available interfaces.
func AddDBDriver(instance DriverDB) {
	for _, drv := range driverList {
		if drv.DbType == instance.DbType {
			return
		}
	}
	driverList = append(driverList, instance)
}

// OpenDB opens a database, initializing it if necessary.
func OpenDB(dbtype string, args ...interface{}) (pbdb Db, err error) {
	for _, drv := range driverList {
		if drv.DbType == dbtype {
			return drv.OpenDB(args...)
		}
	}
	return nil, ErrDbUnknownType
}

// SupportedDBs returns a slice of strings that represent the database drivers
// that have been registered and are therefore supported.
func SupportedDBs() []string {
	var supportedDBs []string
	for _, drv := range driverList {
		supportedDBs = append(supportedDBs, drv.DbType)
	}
	return supportedDBs
}

// CheckPubKey is used to check
func CheckPubKey(pubkey cipher.PubKey) (id *identity.Public, err error) {
	// Check signing key.
	signKey, err := pubkey.VerificationKey().ToBtcec()
	if err != nil {
		return
	}

	// Check encryption key.
	encKey, err := pubkey.EncryptionKey().ToBtcec()
	if err != nil {
		return
	}

	header := pubkey.Object().Header()

	id, err = identity.NewPublic(signKey, encKey, pubkey.Behavior(), pubkey.Pow(), header.Version, header.StreamNumber)
	if err != nil {
		return nil, err
	}
	return id, err
}
