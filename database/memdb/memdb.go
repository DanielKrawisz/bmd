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

// newMemDb returns a new memory-only database ready for object insertion.
// It is a concrete implementation of the database.Db which
// provides a memory-only database. Since it is memory-only, it is obviously not
// persistent and is mostly only useful for testing purposes.
func newMemDb() *database.Db {
	// Embed a mutex for safe concurrent access.
	var mtx sync.RWMutex

	// closed indicates whether or not the database has been closed and is
	// therefore invalidated.
	var closed bool

	// objectsByHash keeps track of unexpired objects by their inventory hash.
	objectsByHash := make(map[hash.Sha]obj.Object)
	encryptedPubKeyByTag := make(map[hash.Sha]obj.Object)
	pubIDByAddress := make(map[string]identity.Public)
	msgCounter := &counter{make(map[uint64]*hash.Sha), 0}
	broadcastCounter := &counter{make(map[uint64]*hash.Sha), 0}
	pubKeyCounter := &counter{make(map[uint64]*hash.Sha), 0}
	getPubKeyCounter := &counter{make(map[uint64]*hash.Sha), 0}
	unknownObjCounter := &counter{make(map[uint64]*hash.Sha), 0}

	// getCounterMap is a helper function used to get the map which maps counter to
	// object hash based on `objType'.
	getCounter := func(objType wire.ObjectType) *counter {
		switch objType {
		case wire.ObjectTypeBroadcast:
			return broadcastCounter
		case wire.ObjectTypeMsg:
			return msgCounter
		case wire.ObjectTypePubKey:
			return pubKeyCounter
		case wire.ObjectTypeGetPubKey:
			return getPubKeyCounter
		default:
			return unknownObjCounter
		}
	}

	// No locks here, meant to be used inside public facing functions.
	fetchObjectByHash := func(hash *hash.Sha) (obj.Object, error) {
		if object, exists := objectsByHash[*hash]; exists {
			return object, nil
		}

		return nil, database.ErrNonexistentObject
	}

	// insertPubkey inserts a pubkey into the database. It's a helper method called
	// from within InsertObject.
	insertPubkey := func(object obj.Object) error {
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
			pubIDByAddress[addr] = id
		case *obj.ExtendedPubKey:
			id, err := cipher.ToIdentity(pubkey)
			if err != nil {
				return err
			}

			tag := bmutil.Tag(id.Address())

			// Add message to database.
			encryptedPubKeyByTag[*tag] = pubkey // insert pubkey
		case *obj.EncryptedPubKey:
			// Add message to database.
			encryptedPubKeyByTag[*pubkey.Tag] = pubkey // insert pubkey
		}

		return nil
	}

	return &database.Db{
		// Close cleanly shuts down the database and syncs all data.
		//
		// All data is purged upon close with this implementation since it is a
		// memory-only database.
		Close: func() error {
			mtx.Lock()
			defer mtx.Unlock()

			if closed {
				return database.ErrDbClosed
			}

			objectsByHash = nil
			encryptedPubKeyByTag = nil
			pubIDByAddress = nil
			msgCounter = nil
			broadcastCounter = nil
			pubKeyCounter = nil
			getPubKeyCounter = nil
			unknownObjCounter = nil
			closed = true
			return nil
		},

		// ExistsObject returns whether or not an object with the given inventory
		// hash exists in the database.
		ExistsObject: func(hash *hash.Sha) (bool, error) {
			mtx.RLock()
			defer mtx.RUnlock()

			if closed {
				return false, database.ErrDbClosed
			}

			if _, exists := objectsByHash[*hash]; exists {
				return true, nil
			}

			return false, nil
		},

		// FetchObjectByHash returns an object from the database as a wire.MsgObject.
		FetchObjectByHash: func(hash *hash.Sha) (obj.Object, error) {
			mtx.RLock()
			defer mtx.RUnlock()

			if closed {
				return nil, database.ErrDbClosed
			}

			return fetchObjectByHash(hash)
		},

		// FetchObjectByCounter returns the corresponding object based on the
		// counter. Note that each object type has a different counter, with unknown
		// objects being consolidated into one counter. Counters are meant for use
		// as a convenience method for fetching new data from database since last
		// check.
		FetchObjectByCounter: func(objType wire.ObjectType, counter uint64) (obj.Object, error) {
			mtx.RLock()
			defer mtx.RUnlock()
			if closed {
				return nil, database.ErrDbClosed
			}

			counterMap := getCounter(objType)
			hash, ok := counterMap.ByCounter[counter]
			if !ok {
				return nil, database.ErrNonexistentObject
			}
			obj, _ := fetchObjectByHash(hash)
			return obj, nil
		},

		// FetchObjectsFromCounter returns a slice of `count' objects which have a
		// counter position starting from `counter'. It also returns the counter
		// value of the last object, which could be useful for more queries to the
		// function.
		FetchObjectsFromCounter: func(objType wire.ObjectType, counter uint64,
			count uint64) ([]database.ObjectWithCounter, uint64, error) {
			mtx.RLock()
			defer mtx.RUnlock()
			if closed {
				return nil, 0, database.ErrDbClosed
			}

			counterMap := getCounter(objType)

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
				obj, _ := fetchObjectByHash(hash)

				objects = append(objects, database.ObjectWithCounter{Counter: v, Object: obj})
			}

			return objects, newCounter, nil
		},

		// FetchIdentityByAddress returns identity.PublicID stored in the form
		// of a PubKey message in the pubkey database.
		FetchIdentityByAddress: func(addr bmutil.Address) (identity.Public, error) {
			mtx.RLock()
			defer mtx.RUnlock()
			if closed {
				return nil, database.ErrDbClosed
			}

			address := addr.String()

			// Check if we already have the public keys.
			id, ok := pubIDByAddress[address]
			if ok {
				return id, nil
			}

			if addr.Version() == obj.SimplePubKeyVersion {
				// There's no way that we can have these unencrypted keys since they are
				// always added to pubIDByAddress.
				return nil, database.ErrNonexistentObject
			}

			// We don't support any other version.
			if addr.Version() != obj.EncryptedPubKeyVersion && addr.Version() != obj.ExtendedPubKeyVersion {
				return nil, database.ErrNotImplemented
			}

			// Try finding the public key with the required tag and then decrypting it.
			tag := bmutil.Tag(addr)

			// Find pubkey to decrypt.
			msg, ok := encryptedPubKeyByTag[*tag]
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
			pubIDByAddress[address] = id

			// Delete from map of encrypted pubkeys.
			delete(encryptedPubKeyByTag, *tag)

			return id, nil
		},

		// FetchRandomInvHashes returns at most the specified number of
		// inventory hashes corresponding to random unexpired objects from
		// the database. It does not guarantee that the number of returned
		// inventory vectors would be `count'.
		FetchRandomInvHashes: func(count uint64) ([]*wire.InvVect, error) {
			mtx.RLock()
			defer mtx.RUnlock()
			if closed {
				return nil, database.ErrDbClosed
			}
			// number of objects to be returned
			counter := uint64(0)
			res := make([]*wire.InvVect, 0, count)

			// current time.
			t := time.Now()
			tu := t.Add(database.ExpiredCacheTime)

			// golang ensures that iteration over maps is psuedorandom
			for hash, o := range objectsByHash {
				if counter >= count { // we have all we need
					break
				}
				expiration := o.Header().Expiration()

				// Remove object from database if it is expired.
				if tu.After(expiration) {
					delete(objectsByHash, hash)
				}

				if t.Before(expiration) {
					res = append(res, (*wire.InvVect)(&hash))
					counter++
				}
			}

			return res, nil
		},

		// GetCounter returns the highest value of counter that exists for objects
		// of the given type.
		GetCounter: func(objType wire.ObjectType) (uint64, error) {
			mtx.RLock()
			defer mtx.RUnlock()
			if closed {
				return 0, database.ErrDbClosed
			}

			c := getCounter(objType)
			return c.CounterPos, nil
		},

		// InsertObject inserts the given object into the database and returns the
		// counter position. If the object is a PubKey, it inserts it into a
		// separate place where it isn't touched by RemoveObject or
		// RemoveExpiredObjects and has to be removed using RemovePubKey.
		InsertObject: func(o obj.Object) (uint64, error) {
			mtx.Lock()
			defer mtx.Unlock()
			if closed {
				return 0, database.ErrDbClosed
			}

			hash := obj.InventoryHash(o)
			if _, ok := objectsByHash[*hash]; ok {
				return 0, database.ErrDuplicateObject
			}

			// There shouldn't be an error here.
			object, _ := obj.ReadObject(wire.Encode(o))

			// insert object into the object hash table
			objectsByHash[*hash] = object

			// increment counter
			counterMap := getCounter(o.Header().ObjectType)
			counterMap.Insert(hash)
			pos := counterMap.CounterPos

			// Insert into pubkey bucket if it is a pubkeys.
			if object.Header().ObjectType == wire.ObjectTypePubKey {
				insertPubkey(object)
			}

			return pos, nil
		},

		// RemoveObject removes the object with the specified hash from the
		// database. Does not remove PubKeys.
		RemoveObject: func(hash *hash.Sha) error {
			mtx.Lock()
			defer mtx.Unlock()
			if closed {
				return database.ErrDbClosed
			}

			obj, ok := objectsByHash[*hash]
			if !ok {
				return database.ErrNonexistentObject
			}

			// check and remove object from counter maps
			counterMap := getCounter(obj.Header().ObjectType)

			for k, v := range counterMap.ByCounter { // go through each element
				if v.IsEqual(hash) { // we got a match, so delete
					delete(counterMap.ByCounter, k)
					break
				}
			}

			// remove object from object map
			delete(objectsByHash, *hash) // done!

			return nil
		},

		// RemoveObjectByCounter removes the object with the specified counter value
		// from the database.
		RemoveObjectByCounter: func(objType wire.ObjectType, counter uint64) error {
			mtx.Lock()
			defer mtx.Unlock()
			if closed {
				return database.ErrDbClosed
			}

			counterMap := getCounter(objType)
			hash, ok := counterMap.ByCounter[counter]
			if !ok {
				return database.ErrNonexistentObject
			}

			delete(counterMap.ByCounter, counter) // delete counter reference
			delete(objectsByHash, *hash)          // delete object itself
			return nil
		},

		// RemoveExpiredObjects prunes all objects in the main circulation store
		// whose expiry time has passed (along with a margin of 3 hours). This does
		// not touch the pubkeys stored in the public key collection.
		RemoveExpiredObjects: func() ([]*hash.Sha, error) {
			mtx.Lock()
			defer mtx.Unlock()
			if closed {
				return nil, database.ErrDbClosed
			}

			removedHashes := make([]*hash.Sha, 0, expiredSliceSize)

			// current time - 3 hours
			t := time.Now().Add(database.ExpiredCacheTime)

			for hash, obj := range objectsByHash {
				header := obj.Header()
				if t.After(header.Expiration()) { // expired
					// remove from counter map
					counterMap := getCounter(header.ObjectType)

					for k, v := range counterMap.ByCounter { // go through each element
						if v.IsEqual(&hash) { // we got a match, so delete
							delete(counterMap.ByCounter, k)
							break
						}
					}

					// remove object from object map
					delete(objectsByHash, hash)

					// we removed this hash
					removedHashes = append(removedHashes, &hash)
				}
			}

			return removedHashes, nil
		},

		// RemoveEncryptedPubKey removes a v4 PubKey with the specified tag from the
		// encrypted PubKey store. Note that it doesn't touch the general object
		// store and won't remove the public key from there.
		RemoveEncryptedPubKey: func(tag *hash.Sha) error {
			mtx.Lock()
			defer mtx.Unlock()
			if closed {
				return database.ErrDbClosed
			}

			_, ok := encryptedPubKeyByTag[*tag]
			if !ok {
				return database.ErrNonexistentObject
			}

			delete(encryptedPubKeyByTag, *tag) // remove
			return nil
		},

		// RemoveIdentity removes the public identity corresponding the given
		// address from the database. This includes any v2/v3/previously used v4
		// identities. Note that it doesn't touch the general object store and won't
		// remove the public key object from there.
		RemoveIdentity: func(addr bmutil.Address) error {
			mtx.Lock()
			defer mtx.Unlock()
			if closed {
				return database.ErrDbClosed
			}

			addrStr := addr.String()

			_, ok := pubIDByAddress[addrStr]
			if !ok {
				return database.ErrNonexistentObject
			}

			delete(pubIDByAddress, addrStr) // remove
			return nil
		},

		// Get the addresses corresponding to all public identities in the database.
		GetAllIdentities: func() ([]bmutil.Address, error) {
			mtx.Lock()
			defer mtx.Unlock()
			if closed {
				return nil, database.ErrDbClosed
			}

			addrs := make([]bmutil.Address, 0, len(pubIDByAddress))
			for addr := range pubIDByAddress {
				address, err := bmutil.DecodeAddress(addr)
				if err != nil {
					return nil, err
				}
				addrs = append(addrs, address)
			}

			return addrs, nil
		},

		ForAllObjects: func(f func(*hash.Sha, obj.Object) error) error {
			mtx.RLock()
			defer mtx.RUnlock()

			for h, o := range objectsByHash {
				err := f(&h, o)
				if err != nil {
					return nil
				}
			}

			return nil
		},
	}
}
