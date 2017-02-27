// Originally derived from: btcsuite/btcd/database/memdb/memdb.go
// Copyright (c) 2013-2015 Conformal Systems LLC.

// Copyright (c) 2015 Monetas.
// Copyright 2016 Daniel Krawisz.
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package memdb

import (
	"sort"
	"sync"
	"time"

	"github.com/DanielKrawisz/bmd/database"
	"github.com/DanielKrawisz/bmutil"
	"github.com/DanielKrawisz/bmutil/cipher"
	"github.com/DanielKrawisz/bmutil/hash"
	"github.com/DanielKrawisz/bmutil/identity"
	"github.com/DanielKrawisz/bmutil/wire"
	"github.com/DanielKrawisz/bmutil/wire/obj"
)

// expiredSliceSize is the initial capacity of the slice that holds hashes of
// expired objects returned by RemoveExpiredObjects.
const expiredSliceSize = 50

// counters type serves to enable sorting of uint64 slices using sort.Sort
// function. Implements sort.Interface.
type counters []uint64

func (c counters) Len() int {
	return len(c)
}

func (c counters) Less(i, j int) bool {
	return c[i] < c[j]
}

func (c counters) Swap(i, j int) {
	c[i], c[j] = c[j], c[i]
}

// counter includes a map to a kind of object and the counter value of the last
// element added.
type counter struct {
	// Holds a mapping from counter to shahash for some object types.
	ByCounter map[uint64]*hash.Sha
	// Keep track of current counter positions (last element added)
	CounterPos uint64
}

func (cmap *counter) Insert(hash *hash.Sha) {
	cmap.CounterPos++                      // increment, new item.
	cmap.ByCounter[cmap.CounterPos] = hash // insert to counter map
}

// memDB is a concrete implementation of the database.Db interface which
// provides a memory-only database. Since it is memory-only, it is obviously not
// persistent and is mostly only useful for testing purposes.
type memDB struct {
	// Embed a mutex for safe concurrent access.
	sync.RWMutex

	// objectsByHash keeps track of unexpired objects by their inventory hash.
	objectsByHash map[hash.Sha]obj.Object

	// encryptedPubkeyByTag keeps track of all encrypted public keys (even
	// expired) by their tag (which is embedded in the message). When pubkeys
	// are decrypted, they are removed from here and put in pubIDByAddress.
	encryptedPubKeyByTag map[hash.Sha]obj.Object

	// pubIDByAddress keeps track of all v2/v3 and previously decrypted v4
	// public keys converted into Public identity structs.
	pubIDByAddress map[string]identity.Public

	// counters for respective object types.
	msgCounter       *counter
	broadcastCounter *counter
	pubKeyCounter    *counter
	getPubKeyCounter *counter

	// counters for unknown objects.
	unknownObjCounter *counter

	// closed indicates whether or not the database has been closed and is
	// therefore invalidated.
	closed bool
}

// getCounterMap is a helper function used to get the map which maps counter to
// object hash based on `objType'.
func (db *memDB) getCounter(objType wire.ObjectType) *counter {
	switch objType {
	case wire.ObjectTypeBroadcast:
		return db.broadcastCounter
	case wire.ObjectTypeMsg:
		return db.msgCounter
	case wire.ObjectTypePubKey:
		return db.pubKeyCounter
	case wire.ObjectTypeGetPubKey:
		return db.getPubKeyCounter
	default:
		return db.unknownObjCounter
	}
}

// Close cleanly shuts down database. This is part of the database.Db interface
// implementation.
//
// All data is purged upon close with this implementation since it is a
// memory-only database.
func (db *memDB) Close() error {
	db.Lock()
	defer db.Unlock()

	if db.closed {
		return database.ErrDbClosed
	}

	db.objectsByHash = nil
	db.encryptedPubKeyByTag = nil
	db.pubIDByAddress = nil
	db.msgCounter = nil
	db.broadcastCounter = nil
	db.pubKeyCounter = nil
	db.getPubKeyCounter = nil
	db.unknownObjCounter = nil
	db.closed = true
	return nil
}

// ExistsObject returns whether or not an object with the given inventory hash
// exists in the database. This is part of the database.Db interface
// implementation.
func (db *memDB) ExistsObject(hash *hash.Sha) (bool, error) {
	db.RLock()
	defer db.RUnlock()

	if db.closed {
		return false, database.ErrDbClosed
	}

	if _, exists := db.objectsByHash[*hash]; exists {
		return true, nil
	}

	return false, nil
}

// No locks here, meant to be used inside public facing functions.
func (db *memDB) fetchObjectByHash(hash *hash.Sha) (obj.Object, error) {
	if object, exists := db.objectsByHash[*hash]; exists {
		return object, nil
	}

	return nil, database.ErrNonexistentObject
}

// FetchObjectByHash returns an object from the database as a wire.MsgObject.
func (db *memDB) FetchObjectByHash(hash *hash.Sha) (obj.Object, error) {
	db.RLock()
	defer db.RUnlock()

	if db.closed {
		return nil, database.ErrDbClosed
	}

	return db.fetchObjectByHash(hash)
}

// FetchObjectByCounter returns an object from the database as a byte array
// based on the object type and counter value. The implementation may cache the
// underlying data if desired. This is part of the database.Db interface
// implementation.
func (db *memDB) FetchObjectByCounter(objType wire.ObjectType,
	counter uint64) (obj.Object, error) {
	db.RLock()
	defer db.RUnlock()
	if db.closed {
		return nil, database.ErrDbClosed
	}

	counterMap := db.getCounter(objType)
	hash, ok := counterMap.ByCounter[counter]
	if !ok {
		return nil, database.ErrNonexistentObject
	}
	obj, _ := db.fetchObjectByHash(hash)
	return obj, nil
}

// FetchObjectsFromCounter returns a slice of `count' objects which have a
// counter position starting from `counter'. It also returns the counter value
// of the last object, which could be useful for more queries to the function.
// This is part of the database.Db interface implementation.
func (db *memDB) FetchObjectsFromCounter(objType wire.ObjectType, counter uint64,
	count uint64) ([]database.ObjectWithCounter, uint64, error) {
	db.RLock()
	defer db.RUnlock()
	if db.closed {
		return nil, 0, database.ErrDbClosed
	}

	counterMap := db.getCounter(objType)

	var c uint64 // count

	keys := make([]uint64, 0, count)

	// make a slice of keys to retrieve
	for k := range counterMap.ByCounter {
		if k < counter { // discard this element
			continue
		}
		keys = append(keys, k)
		c++
	}
	sort.Sort(counters(keys)) // sort retrieved keys
	var newCounter uint64
	if len(keys) == 0 {
		newCounter = 0
	} else if uint64(len(keys)) <= count {
		newCounter = keys[len(keys)-1] // counter value of last element
	} else { // more keys than required
		newCounter = keys[count-1] // Get counter'th element
		keys = keys[:count]        // we don't need excess elements
	}
	objects := make([]database.ObjectWithCounter, 0, len(keys))

	// start fetching objects in ascending order
	for _, v := range keys {
		hash := counterMap.ByCounter[v]
		obj, _ := db.fetchObjectByHash(hash)

		objects = append(objects, database.ObjectWithCounter{Counter: v, Object: obj})
	}

	return objects, newCounter, nil
}

// FetchIdentityByAddress returns identity.Public stored in the form
// of a PubKey message in the pubkey database. It needs to go through all the
// public keys in the database to find this. The implementation must thus cache
// results, if needed. This is part of the database.Db interface implementation.
func (db *memDB) FetchIdentityByAddress(addr bmutil.Address) (identity.Public,
	error) {

	db.RLock()
	defer db.RUnlock()
	if db.closed {
		return nil, database.ErrDbClosed
	}

	address := addr.String()

	// Check if we already have the public keys.
	id, ok := db.pubIDByAddress[address]
	if ok {
		return id, nil
	}

	if addr.Version() == obj.SimplePubKeyVersion {
		// There's no way that we can have these unencrypted keys since they are
		// always added to db.pubIDByAddress.
		return nil, database.ErrNonexistentObject
	}

	// We don't support any other version.
	if addr.Version() != obj.EncryptedPubKeyVersion && addr.Version() != obj.ExtendedPubKeyVersion {
		return nil, database.ErrNotImplemented
	}

	// Try finding the public key with the required tag and then decrypting it.
	var tag hash.Sha
	copy(tag[:], bmutil.Tag(addr))

	// Find pubkey to decrypt.
	msg, ok := db.encryptedPubKeyByTag[tag]
	if !ok {
		return nil, database.ErrNonexistentObject
	}

	pubkey, err := cipher.TryDecryptAndVerifyPubKey(msg, addr)
	if err != nil {
		return nil, err
	}

	id, err = cipher.ToIdentity(pubkey)
	if err != nil {
		return nil, err
	}

	// Add public key to database.
	db.pubIDByAddress[address] = id

	// Delete from map of encrypted pubkeys.
	delete(db.encryptedPubKeyByTag, tag)

	return id, nil

}

// FetchRandomInvHashes returns the specified number of inventory hashes
// corresponding to random unexpired objects from the database.
//
// This is part of the database.Db interface implementation.
func (db *memDB) FetchRandomInvHashes(count uint64) ([]*wire.InvVect, error) {

	db.RLock()
	defer db.RUnlock()
	if db.closed {
		return nil, database.ErrDbClosed
	}
	// number of objects to be returned
	counter := uint64(0)
	res := make([]*wire.InvVect, 0, count)

	// current time.
	t := time.Now()
	tu := t.Add(database.ExpiredCacheTime)

	// golang ensures that iteration over maps is psuedorandom
	for hash, o := range db.objectsByHash {
		if counter >= count { // we have all we need
			break
		}
		expiration := o.Header().Expiration()

		// Remove object from database if it is expired.
		if tu.After(expiration) {
			delete(db.objectsByHash, hash)
		}

		if t.Before(expiration) {
			res = append(res, (*wire.InvVect)(&hash))
			counter++
		}
	}

	return res, nil
}

// GetCounter returns the highest value of counter that exists for objects
// of the given type. This is part of the database.Db interface implementation.
func (db *memDB) GetCounter(objType wire.ObjectType) (uint64, error) {
	db.RLock()
	defer db.RUnlock()
	if db.closed {
		return 0, database.ErrDbClosed
	}

	c := db.getCounter(objType)
	return c.CounterPos, nil
}

// insertPubkey inserts a pubkey into the database. It's a helper method called
// from within InsertObject.
func (db *memDB) insertPubkey(object obj.Object) error {
	// If this object is a pubkey object, we need to keep it in case
	// we can decrypt it.
	switch pubkey := object.(type) {
	case *obj.SimplePubKey:
		id, err := cipher.ToIdentity(pubkey)
		if err != nil {
			return err
		}

		addr := id.Address().String()

		// Add public key to database.
		db.pubIDByAddress[addr] = id
	case *obj.ExtendedPubKey:
		id, err := cipher.ToIdentity(pubkey)
		if err != nil {
			return err
		}

		var tag hash.Sha
		copy(tag[:], bmutil.Tag(id.Address()))

		// Add message to database.
		db.encryptedPubKeyByTag[tag] = pubkey // insert pubkey
	case *obj.EncryptedPubKey:
		// Add message to database.
		db.encryptedPubKeyByTag[*pubkey.Tag] = pubkey // insert pubkey
	}

	return nil
}

// InsertObject inserts data of the given type and hash into the database.
// It returns the calculated/stored inventory hash as well as the counter
// position (if object type has a counter associated with it). If the object
// is a PubKey, it inserts it into a separate place where it isn't touched
// by RemoveObject or RemoveExpiredObjects and has to be removed using
// RemovePubKey. This is part of the database.Db interface implementation.
func (db *memDB) InsertObject(o obj.Object) (uint64, error) {
	db.Lock()
	defer db.Unlock()
	if db.closed {
		return 0, database.ErrDbClosed
	}

	hash := obj.InventoryHash(o)
	if _, ok := db.objectsByHash[*hash]; ok {
		return 0, database.ErrDuplicateObject
	}

	// There shouldn't be an error here.
	object, _ := obj.ReadObject(wire.Encode(o))

	// insert object into the object hash table
	db.objectsByHash[*hash] = object

	// increment counter
	counterMap := db.getCounter(o.Header().ObjectType)
	counterMap.Insert(hash)
	pos := counterMap.CounterPos

	// Insert into pubkey bucket if it is a pubkeys.
	if object.Header().ObjectType == wire.ObjectTypePubKey {
		db.insertPubkey(object)
	}

	return pos, nil
}

// RemoveObject removes the object with the specified hash from the database.
// This is part of the database.Db interface implementation.
func (db *memDB) RemoveObject(hash *hash.Sha) error {
	db.Lock()
	defer db.Unlock()
	if db.closed {
		return database.ErrDbClosed
	}

	obj, ok := db.objectsByHash[*hash]
	if !ok {
		return database.ErrNonexistentObject
	}

	// check and remove object from counter maps
	counterMap := db.getCounter(obj.Header().ObjectType)

	for k, v := range counterMap.ByCounter { // go through each element
		if v.IsEqual(hash) { // we got a match, so delete
			delete(counterMap.ByCounter, k)
			break
		}
	}

	// remove object from object map
	delete(db.objectsByHash, *hash) // done!

	return nil
}

// RemoveObjectByCounter removes the object with the specified counter value
// from the database. This is part of the database.Db interface implementation.
func (db *memDB) RemoveObjectByCounter(objType wire.ObjectType,
	counter uint64) error {

	db.Lock()
	defer db.Unlock()
	if db.closed {
		return database.ErrDbClosed
	}

	counterMap := db.getCounter(objType)
	hash, ok := counterMap.ByCounter[counter]
	if !ok {
		return database.ErrNonexistentObject
	}

	delete(counterMap.ByCounter, counter) // delete counter reference
	delete(db.objectsByHash, *hash)       // delete object itself
	return nil
}

// RemoveExpiredObjects prunes all objects in the main circulation store
// whose expiry time has passed (along with a margin of 3 hours). This does
// not touch the pubkeys stored in the public key collection. This is part of
// the database.Db interface implementation.
func (db *memDB) RemoveExpiredObjects() ([]*hash.Sha, error) {
	db.Lock()
	defer db.Unlock()
	if db.closed {
		return nil, database.ErrDbClosed
	}

	removedHashes := make([]*hash.Sha, 0, expiredSliceSize)

	// current time - 3 hours
	t := time.Now().Add(database.ExpiredCacheTime)

	for hash, obj := range db.objectsByHash {
		header := obj.Header()
		if t.After(header.Expiration()) { // expired
			// remove from counter map
			counterMap := db.getCounter(header.ObjectType)

			for k, v := range counterMap.ByCounter { // go through each element
				if v.IsEqual(&hash) { // we got a match, so delete
					delete(counterMap.ByCounter, k)
					break
				}
			}

			// remove object from object map
			delete(db.objectsByHash, hash)

			// we removed this hash
			removedHashes = append(removedHashes, &hash)
		}
	}

	return removedHashes, nil
}

// RemoveEncryptedPubKey removes a v4 PubKey with the specified tag from the
// encrypted PubKey store. Note that it doesn't touch the general object store
// and won't remove the public key from there. This is part of the database.Db
// interface implementation.
func (db *memDB) RemoveEncryptedPubKey(tag *hash.Sha) error {
	db.Lock()
	defer db.Unlock()
	if db.closed {
		return database.ErrDbClosed
	}

	_, ok := db.encryptedPubKeyByTag[*tag]
	if !ok {
		return database.ErrNonexistentObject
	}

	delete(db.encryptedPubKeyByTag, *tag) // remove
	return nil
}

// RemovePublicIdentity removes the public identity corresponding the given
// address from the database. This includes any v2/v3/previously used v4
// identities. Note that it doesn't touch the general object store and won't
// remove the public key object from there. This is part of the database.Db
// interface implementation.
func (db *memDB) RemovePublicIdentity(addr bmutil.Address) error {
	db.Lock()
	defer db.Unlock()
	if db.closed {
		return database.ErrDbClosed
	}

	addrStr := addr.String()

	_, ok := db.pubIDByAddress[addrStr]
	if !ok {
		return database.ErrNonexistentObject
	}

	delete(db.pubIDByAddress, addrStr) // remove
	return nil

}

// newMemDb returns a new memory-only database ready for object insertion.
func newMemDb() *memDB {
	db := memDB{
		objectsByHash:        make(map[hash.Sha]obj.Object),
		encryptedPubKeyByTag: make(map[hash.Sha]obj.Object),
		pubIDByAddress:       make(map[string]identity.Public),
		msgCounter:           &counter{make(map[uint64]*hash.Sha), 0},
		broadcastCounter:     &counter{make(map[uint64]*hash.Sha), 0},
		pubKeyCounter:        &counter{make(map[uint64]*hash.Sha), 0},
		getPubKeyCounter:     &counter{make(map[uint64]*hash.Sha), 0},
		unknownObjCounter:    &counter{make(map[uint64]*hash.Sha), 0},
	}
	return &db
}
