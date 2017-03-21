// Copyright (c) 2015 Monetas.
// Copyright 2016 Daniel Krawisz.
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package bdb

import (
	"bytes"
	"container/heap"
	"encoding/binary"
	"errors"
	prand "math/rand"
	"sync"
	"time"

	"github.com/DanielKrawisz/bmd/database"
	"github.com/DanielKrawisz/bmutil"
	"github.com/DanielKrawisz/bmutil/cipher"
	"github.com/DanielKrawisz/bmutil/hash"
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
	expiredSliceSize = 300

	objectTypeUnknown wire.ObjectType = wire.ObjectType(999)
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
		wire.ObjectTypeMsg, wire.ObjectTypeBroadcast, objectTypeUnknown}
)

type counter struct {
	ObjectType wire.ObjectType
	counter    uint64
}

// BoltDB is an implementation of database.Database interface with boltDB
// as a backend store.
/*type boltDB struct {
	*bolt.DB

	// A queue used to find the expired objects in order.
	expiration *expiredQueue

	// A map of object hashes to counters.
	counters map[hash.Sha]counter

	// A stats recorder that tracks data on objects in the network.
	stats database.Stats
}*/

/*func newBoltDBStats(db *bolt.DB, ) (*database.Db, error) {
	bdb, err := newBoltDB(db)
	if err != nil {
		return nil, err
	}

	bdb.stats = r
	return bdb, nil
}*/

// newBoltDB creates aan implementation of database.Database interface
// with boltDB as a backend store.
func newBoltDB(db *bolt.DB, stats database.Stats) (*database.Db, error) {
	q := expiredQueue(make([]*expiration, 0))
	ex := &q
	heap.Init(ex)

	counters := make(map[hash.Sha]counter)

	// Initialize database.
	err := db.Update(func(tx *bolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists(objectsBucket)
		if err != nil {
			return err
		}

		b, err := tx.CreateBucket(countersBucket)
		if err == nil { // Create all sub-buckets with object types.
			for _, objType := range objTypes {
				_, err = b.CreateBucket([]byte(objType.String()))
				if err != nil {
					return err
				}
			}
		} else if err != bolt.ErrBucketExists {
			return err
		}

		b, err = tx.CreateBucket(counterPosBucket)
		if err == nil { // Initialize all the counter values.
			zero := []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
			for _, objType := range objTypes {
				err = b.Put([]byte(objType.String()), zero)
				if err != nil {
					return err
				}
			}
		} else if err != bolt.ErrBucketExists {
			return err
		}

		_, err = tx.CreateBucketIfNotExists(encPubkeysBucket)
		if err != nil {
			return err
		}

		_, err = tx.CreateBucketIfNotExists(pubIDBucket)
		if err != nil {
			return err
		}

		b, err = tx.CreateBucket(miscBucket)
		if err == nil {
			// Set misc parameters.
			err = b.Put(versionKey, []byte{latestDbVersion})
			if err != nil {
				return err
			}
		} else if err != bolt.ErrBucketExists {
			return err
		}

		err = checkAndUpgrade(tx)
		if err != nil {
			return err
		}

		return nil
	})
	if err != nil {
		return nil, err
	}

	err = db.View(func(tx *bolt.Tx) error {
		// Recreate the expired queue.
		err := tx.Bucket(objectsBucket).ForEach(func(k, v []byte) error {
			header, err := wire.DecodeObjectHeader(bytes.NewReader(v))
			if err != nil {
				return err
			}

			hash, _ := hash.NewSha(k)

			// push the object onto the expired queue.
			heap.Push(ex, &expiration{
				exp:  header.Expiration(),
				hash: hash,
			})

			return nil
		})
		if err != nil {
			return err
		}

		// make a map of hashes to counters.
		countersBucket := tx.Bucket(countersBucket)
		for _, objType := range objTypes {
			countersBucket.Bucket([]byte(objType.String())).ForEach(func(k, v []byte) error {
				count := binary.BigEndian.Uint64(k)
				hash, _ := hash.NewSha(v)
				counters[*hash] = counter{ObjectType: objType, counter: count}
				return nil
			})
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	// existsObject is a helper method that returns whether or not an object
	// with the given inventory hash exists in the database.
	existsObject := func(hash *hash.Sha) bool {
		if _, ok := counters[*hash]; ok {
			return true
		}

		return false
	}

	// objectByHash is a helper method for returning a *wire.MsgObject with the
	// given hash.
	objectByHash := func(tx *bolt.Tx, hash []byte) (obj.Object, error) {
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

	// headerByHash is a helper method for returning a *wire.MsgObject with the
	// given hash.
	/*headerByHash := func(tx *bolt.Tx, hash []byte) (*wire.ObjectHeader, error) {
		b := tx.Bucket(objectsBucket).Get(hash)
		if b == nil {
			return nil, database.ErrNonexistentObject
		}

		o, err := wire.DecodeObjectHeader(bytes.NewReader(b))
		if err != nil {
			log.Criticalf("Decoding header with hash %v failed: %v", hash, err)
			return nil, err
		}
		return o, nil
	}*/

	// remove removes the object with the specified counter value
	// from the database.
	remove := func(counts []counter) error {
		return db.Update(func(tx *bolt.Tx) error {
			for _, count := range counts {
				bCounter := make([]byte, 8)
				binary.BigEndian.PutUint64(bCounter, count.counter)

				bucket := tx.Bucket(countersBucket).Bucket([]byte(count.ObjectType.String()))
				v := bucket.Get(bCounter)
				if v == nil {
					return database.ErrNonexistentObject
				}

				// Delete object hash.
				err := tx.Bucket(objectsBucket).Delete(v)
				if err != nil {
					return err
				}

				hash, _ := hash.NewSha(v)

				// Delete counter value.
				err = bucket.Delete(bCounter)
				if err != nil {
					return err
				}

				// Remove object from index.
				delete(counters, *hash)
			}

			return nil
		})
	}

	// insertPubkey inserts a pubkey into the database. It's a helper method called
	// from within InsertObject.
	insertPubkey := func(o obj.Object) error {
		switch pubkeyMsg := o.(type) {
		case *obj.SimplePubKey:
			id, err := cipher.ToIdentity(pubkeyMsg)
			if err != nil {
				return err
			}

			address := id.Address().String()
			data := pubkeyMsg.Data()

			// Now that all is well, insert it into the database.
			return db.Update(func(tx *bolt.Tx) error {
				b, err := tx.Bucket(pubIDBucket).CreateBucketIfNotExists([]byte(address))
				if err != nil {
					return err
				}

				ntb := make([]byte, 8)
				binary.BigEndian.PutUint64(ntb, pow.Default.NonceTrialsPerByte)

				ebb := make([]byte, 8)
				binary.BigEndian.PutUint64(ebb, pow.Default.ExtraBytes)

				bb := make([]byte, 4)
				binary.BigEndian.PutUint32(bb, data.Behavior)

				b.Put(nonceTrialsKey, ntb)
				b.Put(extraBytesKey, ebb)
				b.Put(behaviorKey, bb)
				b.Put(signKeyKey, data.Verification.Bytes())
				b.Put(encKeyKey, data.Encryption.Bytes())

				return nil
			})

		case *obj.ExtendedPubKey:
			id, err := cipher.ToIdentity(pubkeyMsg)
			if err != nil {
				return err
			}

			var b bytes.Buffer
			pubkeyMsg.Encode(&b)

			// Add it to database, along with the tag.
			return db.Update(func(tx *bolt.Tx) error {
				return tx.Bucket(encPubkeysBucket).Put(bmutil.Tag(id.Address())[:], b.Bytes())
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

	// Embed a mutex for safe concurrent access.
	var mtx sync.RWMutex

	return &database.Db{
		// ExistsObject returns whether or not an object with the given inventory
		// hash exists in the database.
		ExistsObject: func(hash *hash.Sha) (bool, error) {
			mtx.Lock()
			defer mtx.Unlock()

			return existsObject(hash), nil
		},

		// FetchObjectByHash returns an object from the database as a wire.MsgObject.
		FetchObjectByHash: func(hash *hash.Sha) (obj.Object, error) {
			var o obj.Object
			var err error

			err = db.View(func(tx *bolt.Tx) error {
				o, err = objectByHash(tx, hash[:])
				if err != nil {
					return err
				}
				return nil
			})
			if err != nil {
				return nil, err
			}
			return o, nil
		},

		// FetchObjectByCounter returns the corresponding object based on the
		// counter. Note that each object type has a different counter, with unknown
		// objects being consolidated into one counter. Counters are meant for use
		// as a convenience method for fetching new data from database since last
		// check.
		FetchObjectByCounter: func(objType wire.ObjectType,
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

				o, err = objectByHash(tx, hash)
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
		},

		// FetchObjectsFromCounter returns a slice of `count' objects which have a
		// counter position starting from `counter'. It also returns the counter
		// value of the last object, which could be useful for more queries to the
		// function.
		FetchObjectsFromCounter: func(objType wire.ObjectType, counter uint64,
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

					o, err := objectByHash(tx, v)
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

		},

		// FetchIdentityByAddress returns identity.Public stored in the form
		// of a PubKey message in the pubkey database.
		FetchIdentityByAddress: func(addr bmutil.Address) (identity.Public, error) {
			address := addr.String()

			// Check if we already have the public keys.
			var id identity.Public
			err := db.View(func(tx *bolt.Tx) error {
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

				var behavior uint32
				if b := bucket.Get(behaviorKey); b != nil {
					behavior = binary.BigEndian.Uint32(b)
				} else {
					behavior = 0
				}

				id, err = identity.NewPublic(
					&identity.PublicKey{
						Verification: (*identity.PubKey)(signKey),
						Encryption:   (*identity.PubKey)(encKey),
					},
					addr.Version(), addr.Stream(),
					behavior,
					&pow.Data{
						binary.BigEndian.Uint64(bucket.Get(nonceTrialsKey)),
						binary.BigEndian.Uint64(bucket.Get(extraBytesKey)),
					})
				if err != nil {
					return err
				}
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
			addrTag := bmutil.Tag(addr)[:]

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
				data := pubkey.Data()
				signKey, _ := data.Verification.ToBtcec()
				encKey, _ := data.Encryption.ToBtcec()

				// And we have the identity.
				id, err = identity.NewPublic(
					&identity.PublicKey{
						Verification: (*identity.PubKey)(signKey),
						Encryption:   (*identity.PubKey)(encKey),
					},
					msg.Header().Version, msg.Header().StreamNumber,
					pubkey.Behavior(), pubkey.Pow())
				if err != nil {
					return err
				}

				// Add public key to database.
				b, err := tx.Bucket(pubIDBucket).CreateBucketIfNotExists([]byte(address))
				if err != nil {
					return err
				}

				ntb := make([]byte, 8)
				binary.BigEndian.PutUint64(ntb, data.Pow.NonceTrialsPerByte)

				ebb := make([]byte, 8)
				binary.BigEndian.PutUint64(ebb, data.Pow.ExtraBytes)

				bb := make([]byte, 4)
				binary.BigEndian.PutUint32(bb, data.Behavior)

				b.Put(nonceTrialsKey, ntb)
				b.Put(extraBytesKey, ebb)
				b.Put(behaviorKey, bb)
				b.Put(signKeyKey, data.Verification.Bytes())
				b.Put(encKeyKey, data.Encryption.Bytes())

				// Delete from encrypted pubkeys.
				return tx.Bucket(encPubkeysBucket).Delete(addrTag)
			})
			if err != nil {
				return nil, err
			}

			return id, nil
		},

		// GetCounter returns the highest value of counter that exists for objects
		// of the given type.
		GetCounter: func(objType wire.ObjectType) (uint64, error) {
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
		},

		// InsertObject inserts the given object into the database and returns the
		// counter position. If the object is a PubKey, it inserts it into a
		// separate place where it isn't touched by RemoveObject or
		// RemoveExpiredObjects and has to be removed using RemovePubKey.
		InsertObject: func(o obj.Object) (uint64, error) {
			mtx.Lock()
			defer mtx.Unlock()

			// Check if we already have the object.
			hash := obj.InventoryHash(o)
			exists := existsObject(hash)
			if exists {
				return 0, database.ErrDuplicateObject
			}

			object, _ := obj.ReadObject(wire.Encode(o))

			header := o.Header()

			// Don't insert an object if it is already expired.
			now := time.Now()
			if now.Add(database.ExpiredCacheTime).After(header.Expiration()) {
				return 0, database.ErrExpired
			}

			// Insert into pubkey bucket if it is a pubkey.
			if header.ObjectType == wire.ObjectTypePubKey {
				err := insertPubkey(object)
				if err != nil {
					log.Infof("Failed to insert pubkey: %v", err)
				}
				// We don't care much about error. Ignore it.
			}

			var count uint64
			var b bytes.Buffer
			err := o.Encode(&b)
			if err != nil {
				return 0, err
			}

			bytes := b.Bytes()

			stats.RecordObject(hash, uint64(len(bytes)), now)

			err = db.Update(func(tx *bolt.Tx) error {

				// Insert object along with its hash.
				err = tx.Bucket(objectsBucket).Put(hash[:], bytes)
				if err != nil {
					return err
				}

				// Get latest counter value.
				v := tx.Bucket(counterPosBucket).Get([]byte(header.ObjectType.String()))
				count = binary.BigEndian.Uint64(v) + 1

				bCounter := make([]byte, 8)
				binary.BigEndian.PutUint64(bCounter, count)

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

			objectType := header.ObjectType
			if objectType > wire.HighestKnownObjectType {
				objectType = objectTypeUnknown
			}
			counters[*hash] = counter{counter: count, ObjectType: objectType}

			heap.Push(ex, &expiration{exp: header.Expiration(), hash: hash})

			return count, err
		},

		// RemoveObject removes the object with the specified hash from the
		// database. Does not remove PubKeys.
		RemoveObject: func(hash *hash.Sha) error {
			mtx.Lock()
			defer mtx.Unlock()

			count, ok := counters[*hash]
			if !ok {
				return database.ErrNonexistentObject
			}

			return remove([]counter{count})
		},

		// RemoveObjectByCounter removes the object with the specified counter value
		// from the database.
		RemoveObjectByCounter: func(objType wire.ObjectType, count uint64) error {
			mtx.Lock()
			defer mtx.Unlock()

			return remove([]counter{counter{ObjectType: objType, counter: count}})
		},

		// RemoveExpiredObjects prunes all objects in the main circulation store
		// whose expiry time has passed (along with a margin of 3 hours). This does
		// not touch the pubkeys stored in the public key collection.
		RemoveExpiredObjects: func() ([]*hash.Sha, error) {
			mtx.Lock()
			defer mtx.Unlock()

			// Current time - 3 hours
			t := time.Now().Add(database.ExpiredCacheTime)

			r := make([]*hash.Sha, 0, expiredSliceSize)

			for {
				last := ex.Peek()

				if last == nil || t.Before(last.exp) {
					break
				}

				r = append(r, last.hash)

				heap.Pop(ex)
			}

			counts := make([]counter, 0, len(r))

			for _, hash := range r {
				counts = append(counts, counters[*hash])
			}

			return r, remove(counts)
		},

		// RemoveEncryptedPubKey removes a v4 PubKey with the specified tag from the
		// encrypted PubKey store. Note that it doesn't touch the general object
		// store and won't remove the public key from there.
		RemoveEncryptedPubKey: func(tag *hash.Sha) error {
			return db.Update(func(tx *bolt.Tx) error {
				if tx.Bucket(encPubkeysBucket).Get(tag[:]) == nil {
					return database.ErrNonexistentObject
				}
				return tx.Bucket(encPubkeysBucket).Delete(tag[:])
			})
		},

		// RemoveIdentity removes the public identity corresponding the given
		// address from the database. This includes any v2/v3/previously used v4
		// identities. Note that it doesn't touch the general object store and won't
		// remove the public key object from there.
		RemoveIdentity: func(addr bmutil.Address) error {
			address := []byte(addr.String())

			return db.Update(func(tx *bolt.Tx) error {
				if tx.Bucket(pubIDBucket).Bucket(address) == nil {
					return database.ErrNonexistentObject
				}
				return tx.Bucket(pubIDBucket).DeleteBucket(address)
			})
		},

		// FetchRandomInvHashes returns the specified number of inventory hashes
		// corresponding to random unexpired objects from the database. It does not
		// guarantee that the number of returned inventory vectors would be `count'.
		FetchRandomInvHashes: func(count uint64) ([]*wire.InvVect, error) {
			mtx.Lock()
			defer mtx.Unlock()

			hashes := make([]*wire.InvVect, 0, count)
			now := time.Now()
			randomizer := make(map[*hash.Sha]struct{})

			for _, e := range *ex {
				if now.Before(e.exp) {
					randomizer[e.hash] = struct{}{}
				}
			}

			i := uint64(0)
			// go ensures that the iteration order is random.
			for hash := range randomizer {
				inv := &wire.InvVect{}
				copy(inv[:], (*hash)[:])
				hashes = append(hashes, inv)
				i++
				if i > count {
					break
				}
			}

			return hashes, nil
		},

		// Get the addresses corresponding to all public identities in the database.
		GetAllIdentities: func() ([]bmutil.Address, error) {
			var addrs []bmutil.Address
			err := db.View(func(tx *bolt.Tx) error {
				return tx.Bucket(pubIDBucket).ForEach(func(k, v []byte) error {
					address, err := bmutil.DecodeAddress(string(k))
					if err != nil {
						return nil
					}
					addrs = append(addrs, address)
					return nil
				})
			})
			if err != nil {
				return nil, err
			}

			return addrs, nil
		},
	}, nil
}

func init() {
	// Seed the random number generator.
	prand.Seed(time.Now().UnixNano())
}
