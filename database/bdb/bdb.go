// Copyright (c) 2015 Monetas.
// Copyright 2016 Daniel Krawisz.
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package bdb

import (
	"bytes"
	"encoding/binary"
	"errors"
	prand "math/rand"
	"time"

	"github.com/DanielKrawisz/bmd/database"
	"github.com/DanielKrawisz/bmutil"
	"github.com/DanielKrawisz/bmutil/cipher"
	"github.com/DanielKrawisz/bmutil/identity"
	"github.com/DanielKrawisz/bmutil/pow"
	"github.com/DanielKrawisz/bmutil/wire"
	"github.com/DanielKrawisz/bmutil/wire/obj"
	"github.com/boltdb/bolt"
	"github.com/btcsuite/btcd/btcec"
)

const (
	// expiredSliceSize is the initial capacity of the slice that holds hashes
	// of expired objects returned by RemoveExpiredObjects.
	expiredSliceSize = 50
)

// Various buckets and keys used for the database.
var (
	// Inventory hash (32 bytes) -> Object data
	objectsBucket = []byte("objectsByHashes")

	// - Getpubkey/Pubkey/Msg/Broadcast/Unknown (bucket)
	// -- Counter value (uint64) -> Inventory hash (32 bytes)
	countersBucket = []byte("objectsByCounters")

	// Used to keep track of the last assigned counter value. Needed because
	// expired objects may be removed and if the expired object was the most
	// recently added object, counter values could mess up.
	//
	// Getpubkey/Pubkey/Msg/Broadcast/Unknown -> uint64
	counterPosBucket = []byte("counterPositions")

	// Tag (32 bytes) -> Encrypted pubkey
	encPubkeysBucket = []byte("encryptedPubkeysByTag")

	// - Address (string starting with BM-) (bucket)
	pubIDBucket = []byte("publicIdentityByAddress")
	// -- Keys:
	nonceTrialsKey = []byte("nonceTrials")
	extraBytesKey  = []byte("extraBytes")
	signKeyKey     = []byte("signingKey")
	encKeyKey      = []byte("encryptionKey")
	behaviorKey    = []byte("behavior")

	// miscBucket is used for storing misc data like database version.
	miscBucket = []byte("misc")
	versionKey = []byte("version")
)

var (
	errBreakEarly = errors.New("loop broken early because we have what we need")

	objTypes = []wire.ObjectType{wire.ObjectTypeGetPubKey, wire.ObjectTypePubKey,
		wire.ObjectTypeMsg, wire.ObjectTypeBroadcast, wire.ObjectType(999)}
)

// BoltDB is an implementation of database.Database interface with BoltDB
// as a backend store.
type BoltDB struct {
	*bolt.DB
}

// ExistsObject returns whether or not an object with the given inventory
// hash exists in the database.
func (db *BoltDB) ExistsObject(hash *wire.ShaHash) (bool, error) {
	err := db.View(func(tx *bolt.Tx) error {
		if tx.Bucket(objectsBucket).Get(hash[:]) == nil {
			return database.ErrNonexistentObject
		}
		return nil
	})
	if err == database.ErrNonexistentObject {
		return false, nil
	} else if err != nil {
		return false, err
	}
	return true, nil
}

// objectByHash is a helper method for returning a *wire.MsgObject with the
// given hash.
func (db *BoltDB) objectByHash(tx *bolt.Tx, hash []byte) (obj.Object, error) {
	b := tx.Bucket(objectsBucket).Get(hash)
	if b == nil {
		return nil, database.ErrNonexistentObject
	}

	o, err := obj.DecodeObject(bytes.NewReader(b))
	if err != nil {
		log.Criticalf("Decoding object with hash %v failed: %v", hash, err)
		return nil, err
	}
	return o, nil
}

// FetchObjectByHash returns an object from the database as a wire.MsgObject.
func (db *BoltDB) FetchObjectByHash(hash *wire.ShaHash) (obj.Object, error) {
	var o obj.Object
	var err error

	err = db.View(func(tx *bolt.Tx) error {
		o, err = db.objectByHash(tx, hash[:])
		if err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return o, nil
}

// FetchObjectByCounter returns the corresponding object based on the
// counter. Note that each object type has a different counter, with unknown
// objects being consolidated into one counter. Counters are meant for use
// as a convenience method for fetching new data from database since last
// check.
func (db *BoltDB) FetchObjectByCounter(objType wire.ObjectType,
	counter uint64) (obj.Object, error) {

	bCounter := make([]byte, 8)
	binary.BigEndian.PutUint64(bCounter, counter)

	var o obj.Object
	var err error

	err = db.View(func(tx *bolt.Tx) error {
		hash := tx.Bucket(countersBucket).Bucket([]byte(objType.String())).Get(bCounter)
		if hash == nil {
			return database.ErrNonexistentObject
		}

		o, err = db.objectByHash(tx, hash)
		if err != nil {
			log.Criticalf("For %s with counter %d, counter value exists but"+
				" failed to get object: %v", objType, counter, err)
			return err
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return o, nil
}

// FetchObjectsFromCounter returns a slice of `count' objects which have a
// counter position starting from `counter'. It also returns the counter
// value of the last object, which could be useful for more queries to the
// function.
func (db *BoltDB) FetchObjectsFromCounter(objType wire.ObjectType, counter uint64,
	count uint64) ([]database.ObjectWithCounter, uint64, error) {

	bCounter := make([]byte, 8)
	binary.BigEndian.PutUint64(bCounter, counter)

	objects := make([]database.ObjectWithCounter, 0, count)
	var lastCounter uint64

	err := db.View(func(tx *bolt.Tx) error {
		cursor := tx.Bucket(countersBucket).Bucket([]byte(objType.String())).Cursor()

		i := uint64(0)
		k, v := cursor.Seek(bCounter)

		// Loop as long we don't have the required number of elements or we
		// don't reach the end.
		for ; i < count && k != nil && v != nil; k, v = cursor.Next() {
			c := binary.BigEndian.Uint64(k)

			o, err := db.objectByHash(tx, v)
			if err != nil {
				log.Criticalf("For %s with counter %d, counter value exists "+
					"but failed to get object: %v", objType, c, err)
				return err
			}

			objects = append(objects, database.ObjectWithCounter{
				Counter: c,
				Object:  o,
			})
			lastCounter = c
			i++
		}
		return nil
	})
	if err != nil {
		return nil, 0, err
	}

	return objects, lastCounter, nil

}

// FetchIdentityByAddress returns identity.Public stored in the form
// of a PubKey message in the pubkey database.
func (db *BoltDB) FetchIdentityByAddress(addr *bmutil.Address) (*identity.Public, error) {
	address, err := addr.Encode()
	if err != nil {
		return nil, err
	}

	// Check if we already have the public keys.
	var id *identity.Public
	err = db.View(func(tx *bolt.Tx) error {
		bucket := tx.Bucket(pubIDBucket).Bucket([]byte(address))
		if bucket == nil {
			return database.ErrNonexistentObject
		}

		signKey, err := btcec.ParsePubKey(bucket.Get(signKeyKey), btcec.S256())
		if err != nil {
			log.Criticalf("Failed to parse public signing key for %s: %v",
				address, err)
			return err
		}

		encKey, err := btcec.ParsePubKey(bucket.Get(encKeyKey), btcec.S256())
		if err != nil {
			log.Criticalf("Failed to parse public encryption key for %s: %v",
				address, err)
			return err
		}

		id = identity.NewPublic(signKey, encKey,
			&pow.Data{
				binary.BigEndian.Uint64(bucket.Get(nonceTrialsKey)),
				binary.BigEndian.Uint64(bucket.Get(extraBytesKey)),
			},
			addr.Version, addr.Stream)
		return nil
	})

	// Found it!
	if id != nil {
		return id, nil
	}

	// Possible that encrypted pubkeys not yet decrypted and stored here.
	if err != nil && err != database.ErrNonexistentObject {
		return nil, err
	}

	if addr.Version == obj.SimplePubKeyVersion {
		// There's no way that we can have these unencrypted keys since they are
		// always added to db.pubIDByAddress.
		return nil, database.ErrNonexistentObject
	}

	// We don't support any other version.
	if addr.Version != obj.EncryptedPubKeyVersion && addr.Version != obj.ExtendedPubKeyVersion {
		return nil, database.ErrNotImplemented
	}

	// Try finding the public key with the required tag and then decrypting it.
	addrTag := addr.Tag()

	err = db.Update(func(tx *bolt.Tx) error {
		v := tx.Bucket(encPubkeysBucket).Get(addrTag)
		if v == nil {
			return database.ErrNonexistentObject
		}

		msg, err := obj.DecodePubKey(bytes.NewReader(v))
		if err != nil {
			log.Criticalf("Failed to decode pubkey with tag %x: %v", addrTag, err)
			return err
		}

		// Decrypt the pubkey.
		pubkey, err := cipher.TryDecryptAndVerifyPubKey(msg, addr)
		if err != nil {
			// It's an invalid pubkey so remove it.
			tx.Bucket(encPubkeysBucket).Delete(addrTag)
			return err
		}

		// Already verified them in TryDecryptAndVerifyPubKey.
		signKey, _ := pubkey.VerificationKey().ToBtcec()
		encKey, _ := pubkey.EncryptionKey().ToBtcec()

		// And we have the identity.
		id = identity.NewPublic(signKey, encKey, pubkey.Pow(), msg.Header().Version, msg.Header().StreamNumber)

		// Add public key to database.
		b, err := tx.Bucket(pubIDBucket).CreateBucketIfNotExists([]byte(address))
		if err != nil {
			return err
		}

		ntb := make([]byte, 8)
		binary.BigEndian.PutUint64(ntb, id.NonceTrialsPerByte)

		ebb := make([]byte, 8)
		binary.BigEndian.PutUint64(ebb, id.ExtraBytes)

		bb := make([]byte, 4)
		binary.BigEndian.PutUint32(bb, id.Behavior)

		b.Put(nonceTrialsKey, ntb)
		b.Put(extraBytesKey, ebb)
		b.Put(behaviorKey, bb)
		b.Put(signKeyKey, id.SigningKey.SerializeCompressed())
		b.Put(encKeyKey, id.EncryptionKey.SerializeCompressed())

		// Delete from encrypted pubkeys.
		return tx.Bucket(encPubkeysBucket).Delete(addrTag)
	})
	if err != nil {
		return nil, err
	}

	return id, nil
}

// FetchRandomInvHashes returns the specified number of inventory hashes
// corresponding to random unexpired objects from the database. It does not
// guarantee that the number of returned inventory vectors would be `count'.
func (db *BoltDB) FetchRandomInvHashes(count uint64) ([]*wire.InvVect, error) {
	hashes := make([]*wire.InvVect, 0, count)

	err := db.View(func(tx *bolt.Tx) error {
		bucket := tx.Bucket(objectsBucket)
		numHashes := bucket.Stats().KeyN

		// Calculate the probability so as to produce the required number.
		var prob float64
		if uint64(numHashes) <= count {
			prob = 1.0
		} else {
			// Multiply arbitrarily by 2, increase chances of success.
			// TODO figure out something better
			prob = (float64(count) / float64(numHashes)) * 2
		}

		return tx.Bucket(objectsBucket).ForEach(func(k, _ []byte) error {
			if uint64(len(hashes)) == count {
				return errBreakEarly
			}

			if prand.Float64() < prob {
				inv := &wire.InvVect{}
				copy(inv[:], k)

				hashes = append(hashes, inv)
			}
			return nil
		})
	})
	if err != nil && err != errBreakEarly {
		return nil, err
	}

	return hashes, nil
}

// GetCounter returns the highest value of counter that exists for objects
// of the given type.
func (db *BoltDB) GetCounter(objType wire.ObjectType) (uint64, error) {
	var counter uint64

	err := db.View(func(tx *bolt.Tx) error {
		k, _ := tx.Bucket(countersBucket).Bucket([]byte(objType.String())).Cursor().Last()
		if k == nil {
			counter = 0
		} else {
			counter = binary.BigEndian.Uint64(k)
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	return counter, nil
}

// insertPubkey inserts a pubkey into the database. It's a helper method called
// from within InsertObject.
func (db *BoltDB) insertPubkey(o obj.Object) error {
	switch pubkeyMsg := o.(type) {
	case *obj.SimplePubKey:
		id, err := database.CheckPubKey(pubkeyMsg)
		if err != nil {
			return err
		}

		address, err := id.Address.Encode()
		if err != nil {
			return err
		}

		// Now that all is well, insert it into the database.
		return db.Update(func(tx *bolt.Tx) error {
			b, err := tx.Bucket(pubIDBucket).CreateBucketIfNotExists([]byte(address))
			if err != nil {
				return err
			}

			ntb := make([]byte, 8)
			binary.BigEndian.PutUint64(ntb, id.NonceTrialsPerByte)

			ebb := make([]byte, 8)
			binary.BigEndian.PutUint64(ebb, id.ExtraBytes)

			bb := make([]byte, 4)
			binary.BigEndian.PutUint32(bb, id.Behavior)

			b.Put(nonceTrialsKey, ntb)
			b.Put(extraBytesKey, ebb)
			b.Put(behaviorKey, bb)
			b.Put(signKeyKey, id.SigningKey.SerializeCompressed())
			b.Put(encKeyKey, id.EncryptionKey.SerializeCompressed())

			return nil
		})

	case *obj.ExtendedPubKey:
		id, err := database.CheckPubKey(pubkeyMsg)
		if err != nil {
			return err
		}

		var b bytes.Buffer
		pubkeyMsg.Encode(&b)

		// Add it to database, along with the tag.
		return db.Update(func(tx *bolt.Tx) error {
			return tx.Bucket(encPubkeysBucket).Put(id.Address.Tag(), b.Bytes())
		})

	case *obj.EncryptedPubKey:
		var b bytes.Buffer
		pubkeyMsg.Encode(&b)

		// Add it to database, along with the tag.
		return db.Update(func(tx *bolt.Tx) error {
			return tx.Bucket(encPubkeysBucket).Put(pubkeyMsg.Tag[:], b.Bytes())
		})
	}

	return nil
}

// InsertObject inserts the given object into the database and returns the
// counter position. If the object is a PubKey, it inserts it into a
// separate place where it isn't touched by RemoveObject or
// RemoveExpiredObjects and has to be removed using RemovePubKey.
func (db *BoltDB) InsertObject(o obj.Object) (uint64, error) {
	// Check if we already have the object.
	hash := obj.InventoryHash(o)
	exists, err := db.ExistsObject(hash)
	if err != nil {
		return 0, err
	}
	if exists {
		return 0, database.ErrDuplicateObject
	}

	object, _ := obj.ReadObject(wire.Encode(o))

	header := o.Header()
	// Insert into pubkey bucket if it is a pubkeys.
	if header.ObjectType == wire.ObjectTypePubKey {
		err = db.insertPubkey(object)
		if err != nil {
			log.Infof("Failed to insert pubkey: %v", err)
		}
		// We don't care much about error. Ignore it.
	}

	var counter uint64
	var b bytes.Buffer
	err = o.Encode(&b)
	if err != nil {
		return 0, err
	}

	err = db.Update(func(tx *bolt.Tx) error {

		// Insert object along with its hash.
		err = tx.Bucket(objectsBucket).Put(obj.InventoryHash(o)[:], b.Bytes())
		if err != nil {
			return err
		}

		// Get latest counter value.
		v := tx.Bucket(counterPosBucket).Get([]byte(header.ObjectType.String()))
		counter = binary.BigEndian.Uint64(v) + 1

		bCounter := make([]byte, 8)
		binary.BigEndian.PutUint64(bCounter, counter)

		// Store counter value along with hash.
		err = tx.Bucket(countersBucket).Bucket([]byte(header.ObjectType.String())).
			Put(bCounter, obj.InventoryHash(o)[:])
		if err != nil {
			return err
		}

		// Store new counter value.
		return tx.Bucket(counterPosBucket).Put([]byte(header.ObjectType.String()),
			bCounter)
	})
	if err != nil {
		return 0, err
	}

	return counter, err
}

// RemoveObject removes the object with the specified hash from the
// database. Does not remove PubKeys.
func (db *BoltDB) RemoveObject(hash *wire.ShaHash) error {
	return db.Update(func(tx *bolt.Tx) error {
		obj := tx.Bucket(objectsBucket).Get(hash[:])
		if obj == nil {
			return database.ErrNonexistentObject
		}

		// Get the object type.
		header, err := wire.DecodeObjectHeader(bytes.NewReader(obj))
		if err != nil {
			log.Criticalf("Failed to decode object with hash %s: %v", hash, err)
			return err
		}

		// Delete object.
		err = tx.Bucket(objectsBucket).Delete(hash[:])
		if err != nil {
			return err
		}

		// Delete object from the counters bucket.
		cursor := tx.Bucket(countersBucket).Bucket([]byte(header.ObjectType.String())).Cursor()
		for k, v := cursor.First(); k != nil || v != nil; k, v = cursor.Next() {
			if bytes.Equal(v, hash[:]) { // We found a match so delete this.
				return cursor.Delete()
			}
		}

		log.Criticalf("Didn't find object with inv. hash %s in counter bucket!",
			hash)
		return errors.New("Critical error. Check logs.")
	})
}

// RemoveObjectByCounter removes the object with the specified counter value
// from the database.
func (db *BoltDB) RemoveObjectByCounter(objType wire.ObjectType, counter uint64) error {
	bCounter := make([]byte, 8)
	binary.BigEndian.PutUint64(bCounter, counter)

	return db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket(countersBucket).Bucket([]byte(objType.String()))
		hash := bucket.Get(bCounter)
		if hash == nil {
			return database.ErrNonexistentObject
		}

		// Delete object hash.
		err := tx.Bucket(objectsBucket).Delete(hash)
		if err != nil {
			return err
		}

		// Delete counter value.
		return bucket.Delete(bCounter)
	})
}

// RemoveExpiredObjects prunes all objects in the main circulation store
// whose expiry time has passed (along with a margin of 3 hours). This does
// not touch the pubkeys stored in the public key collection.
func (db *BoltDB) RemoveExpiredObjects() ([]*wire.ShaHash, error) {
	removedHashes := make([]*wire.ShaHash, 0, expiredSliceSize)

	// Go through counter buckets of all the object types, checking if the
	// corresponding objects have expired, removing and adding them to
	// removedHashes if they have.
	//
	// The downside of going through the object hashes is that the complexity
	// rises to O(n^2) instead of O(n log n) because counter values of the
	// objects also have to be found (which can only be done in linear time).
	err := db.Update(func(tx *bolt.Tx) error {
		for _, objType := range objTypes {

			cursor := tx.Bucket(countersBucket).Bucket([]byte(objType.String())).Cursor()
			for k, v := cursor.First(); k != nil || v != nil; k, v = cursor.Next() {
				obj, err := db.objectByHash(tx, v)
				if err != nil {
					log.Criticalf("Failed to get %s object #%d by hash: %v",
						objType, binary.BigEndian.Uint64(k), err)
				}

				// Current time - 3 hours
				if time.Now().Add(-time.Hour * 3).After(obj.Header().Expiration()) { // Expired

					// Remove object from objects bucket.
					err = tx.Bucket(objectsBucket).Delete(v)
					if err != nil {
						return err
					}

					// Remove from counters bucket.
					err = cursor.Delete()
					if err != nil {
						return err
					}

					// Add to the list of removed hashes.
					hash, _ := wire.NewShaHash(v)
					removedHashes = append(removedHashes, hash)
				}
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	return removedHashes, nil
}

// RemoveEncryptedPubKey removes a v4 PubKey with the specified tag from the
// encrypted PubKey store. Note that it doesn't touch the general object
// store and won't remove the public key from there.
func (db *BoltDB) RemoveEncryptedPubKey(tag *wire.ShaHash) error {
	return db.Update(func(tx *bolt.Tx) error {
		if tx.Bucket(encPubkeysBucket).Get(tag[:]) == nil {
			return database.ErrNonexistentObject
		}
		return tx.Bucket(encPubkeysBucket).Delete(tag[:])
	})
}

// RemovePublicIdentity removes the public identity corresponding the given
// address from the database. This includes any v2/v3/previously used v4
// identities. Note that it doesn't touch the general object store and won't
// remove the public key object from there.
func (db *BoltDB) RemovePublicIdentity(addr *bmutil.Address) error {
	address, err := addr.Encode()
	if err != nil {
		return err
	}

	return db.Update(func(tx *bolt.Tx) error {
		if tx.Bucket(pubIDBucket).Bucket([]byte(address)) == nil {
			return database.ErrNonexistentObject
		}
		return tx.Bucket(pubIDBucket).DeleteBucket([]byte(address))
	})
}

func init() {
	// Seed the random number generator.
	prand.Seed(time.Now().UnixNano())
}
