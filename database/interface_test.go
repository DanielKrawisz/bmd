// Originally derived from: btcsuite/btcd/database/interface_test.go
// Copyright (c) 2013-2015 Conformal Systems LLC.

// Copyright (c) 2015 Monetas.
// Copyright 2016 Daniel Krawisz.
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package database_test

import (
	"bytes"
	"encoding/hex"
	"reflect"
	"testing"
	"time"

	"github.com/DanielKrawisz/bmd/database"
	"github.com/DanielKrawisz/bmutil"
	"github.com/DanielKrawisz/bmutil/wire"
	"github.com/DanielKrawisz/bmutil/wire/obj"
)

// testContext is used to store context information about a running test which
// is passed into helper functions.
type testContext struct {
	t      *testing.T
	dbType string
	db     database.Db
}

// create a new database after clearing out the old one and return the teardown
// function
func (tc *testContext) newDb() func() {
	// create fresh database
	db, teardown, err := createDB(tc.dbType)
	if err != nil {
		tc.t.Fatalf("Failed to create test database (%s) %v", tc.dbType, err)
	}
	tc.db = db
	return teardown
}

var expires = time.Now().Add(10 * time.Minute)
var expired = time.Now().Add(-10 * time.Minute).Add(-3 * time.Hour)

// A set of pub keys to create fake objects for testing the database.
var pubkey = []wire.PubKey{
	wire.PubKey([wire.PubKeySize]byte{
		23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38,
		39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54,
		55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70,
		71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86}),
	wire.PubKey([wire.PubKeySize]byte{
		87, 88, 89, 90, 91, 92, 93, 94, 95, 96, 97, 98, 99, 100, 101, 102,
		103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116, 117, 118,
		119, 120, 121, 122, 123, 124, 125, 126, 127, 128, 129, 130, 131, 132, 133, 134,
		135, 136, 137, 138, 139, 140, 141, 142, 143, 144, 145, 146, 147, 148, 149, 150}),
	wire.PubKey([wire.PubKeySize]byte{
		54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69,
		70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85,
		86, 87, 88, 89, 90, 91, 92, 93, 94, 95, 96, 97, 98, 99, 100, 101,
		102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116, 117}),
	wire.PubKey([wire.PubKeySize]byte{
		118, 119, 120, 121, 122, 123, 124, 125, 126, 127, 128, 129, 130, 131, 132, 133,
		134, 135, 136, 137, 138, 139, 140, 141, 142, 143, 144, 145, 146, 147, 148, 149,
		150, 151, 152, 153, 154, 155, 156, 157, 158, 159, 160, 161, 162, 163, 164, 165,
		166, 167, 168, 169, 170, 171, 172, 173, 174, 175, 176, 177, 178, 179, 180, 181}),
}

var shahash = []wire.ShaHash{
	wire.ShaHash([wire.HashSize]byte{
		98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113,
		114, 115, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125, 126, 127, 128, 129}),
	wire.ShaHash([wire.HashSize]byte{
		100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115,
		116, 117, 118, 119, 120, 121, 122, 123, 124, 125, 126, 127, 128, 129, 130, 131}),
}

var ripehash = []wire.RipeHash{
	wire.RipeHash([wire.RipeHashSize]byte{
		78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95, 96, 97}),
	wire.RipeHash([wire.RipeHashSize]byte{
		80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95, 96, 97, 98, 99}),
}

// Some bitmessage objects that we use for testing. Two of each.
var testObj = [][]obj.Object{
	[]obj.Object{
		obj.NewGetPubKey(654, expires, 4, 1, &ripehash[0], &shahash[0]),
		obj.NewGetPubKey(654, expired, 4, 1, &ripehash[1], &shahash[1]),
	},
	[]obj.Object{
		obj.NewEncryptedPubKey(543, expires, 1, &shahash[0], []byte{11, 12, 13, 14, 15, 16, 17, 18}),
		obj.NewEncryptedPubKey(543, expired, 1, &shahash[1], []byte{11, 12, 13, 14, 15, 16, 17, 18}),
	},
	[]obj.Object{
		obj.NewMessage(765, expires, 1,
			[]byte{90, 87, 66, 45, 3, 2, 120, 101, 78, 78, 78, 7, 85, 55, 2, 23}),
		obj.NewMessage(765, expired, 1,
			[]byte{90, 87, 66, 45, 3, 2, 120, 101, 78, 78, 78, 7, 85, 55}),
	},
	[]obj.Object{
		obj.NewTaggedBroadcast(876, expires, 1, &shahash[0],
			[]byte{90, 87, 66, 45, 3, 2, 120, 101, 78, 78, 78, 7, 85, 55, 2, 23}),
		obj.NewTaggedBroadcast(876, expired, 1, &shahash[1],
			[]byte{90, 87, 66, 45, 3, 2, 120, 101, 78, 78, 78, 7, 85, 55}),
	},
	[]obj.Object{
		wire.NewMsgObject(wire.NewObjectHeader(345, expires, wire.ObjectType(4), 1, 1),
			[]byte{77, 82, 53, 48, 96, 1}),
		wire.NewMsgObject(wire.NewObjectHeader(987, expired, wire.ObjectType(4), 1, 1),
			[]byte{1, 2, 3, 4, 5, 0, 6, 7, 8, 9, 100}),
	},
	[]obj.Object{
		wire.NewMsgObject(wire.NewObjectHeader(7288, expires, wire.ObjectType(5), 1, 1),
			[]byte{0, 0, 0, 0, 1, 0, 0}),
		wire.NewMsgObject(wire.NewObjectHeader(7288, expired, wire.ObjectType(5), 1, 1),
			[]byte{0, 0, 0, 0, 0, 0, 0, 99, 98, 97}),
	},
}

// testObject tests InsertObject, ExistsObject, FetchObjectByHash, and RemoveObject
func testObject(tc *testContext) {
	teardown := tc.newDb()
	defer teardown()

	for i, object := range testObj {
		msg := object[0]
		_, err := tc.db.InsertObject(msg.MsgObject())
		if err != nil {
			tc.t.Errorf("InsertObject (%s): object #%d,"+
				" got error %v", tc.dbType, i, err)
		}

		// Check for error on duplicate insertion.
		_, err = tc.db.InsertObject(msg.MsgObject())
		if err == nil {
			tc.t.Errorf("InsertObject (%s): inserting duplicate object #%d,"+
				" did not get error", tc.dbType, i)
		}

		hash := msg.InventoryHash()

		exists, err := tc.db.ExistsObject(hash)
		if err != nil {
			tc.t.Errorf("ExistsObject (%s): object #%d,"+
				" got error %v", tc.dbType, i, err)
		}
		if !exists {
			tc.t.Errorf("ExistsObject (%s): object #%d should be in db"+
				" but it is not", tc.dbType, i)
		}

		testMsg, err := tc.db.FetchObjectByHash(hash)
		testMsg.InventoryHash() // to make sure it's equal

		if err != nil {
			tc.t.Errorf("FetchObjectByHash (%s): object #%d, got error %v",
				tc.dbType, i, err)
		}
		if !reflect.DeepEqual(msg.MsgObject(), testMsg.MsgObject()) {
			tc.t.Errorf("FetchObjectByHash (%s): object #%d,"+
				" data does not match", tc.dbType, i)
		}

		err = tc.db.RemoveObject(hash)
		if err != nil {
			tc.t.Errorf("RemoveObject (%s): object #%d, got error %v",
				tc.dbType, i, err)
		}

		err = tc.db.RemoveObject(hash)
		if err == nil {
			tc.t.Errorf("RemoveObject (%s): object #%d, removing"+
				" nonexistent object, expected error got none", tc.dbType, i)
		}

		exists, err = tc.db.ExistsObject(hash)
		if err != nil {
			tc.t.Errorf("ExistsObject (%s): object #%d, got error %v",
				tc.dbType, i, err)
		}
		if exists {
			tc.t.Errorf("ExistsObject (%s): object #%d, should not exist"+
				" in db but does", tc.dbType, i)
		}

		_, err = tc.db.FetchObjectByHash(hash)
		if err == nil {
			tc.t.Errorf("FetchObjectByHash (%s): object #%d, fetching"+
				" nonexistent object, expected error got none", tc.dbType, i)
		}
	}
}

// testCounter tests FetchObjectByCounter, FetchObjectsFromCounter,
// RemoveObjectByCounter, and GetCounter
func testCounter(tc *testContext) {
	for i := 0; i < len(testObj); i++ { // test objects that aren't unknown
		teardown := tc.newDb()

		objType := wire.ObjectType(i)

		// Test that the counter starts at zero.
		count, err := tc.db.GetCounter(objType)
		if err != nil {
			tc.t.Errorf("GetCounter (%s): object type %s, got error %v.",
				tc.dbType, objType, err)
		}
		if count != 0 {
			tc.t.Errorf("GetCounter (%s): expected 0, got %d", tc.dbType, count)
		}

		// Try to grab an element that is not there.
		_, err = tc.db.FetchObjectByCounter(objType, 1)
		if err == nil {
			tc.t.Errorf("FetchObjectByCounter (%s): fetching nonexistent"+
				" object, expected error got none", tc.dbType)
		}

		// Try to remove an element that is not there.
		err = tc.db.RemoveObjectByCounter(objType, 1)
		if err == nil {
			tc.t.Errorf("RemoveObjectByCounter (%s): removing nonexistent"+
				" object of type %s, expected error got none",
				tc.dbType, objType)
		}

		// Insert an element and make sure the counter comes out correct.
		msg := testObj[i][0]
		count, err = tc.db.InsertObject(msg.MsgObject())
		if err != nil {
			tc.t.Errorf("InsertObject (%s): object #%d #%d of type %s,"+
				" got error %v", tc.dbType, i, 0, objType, err)
		}
		if count != 1 {
			tc.t.Errorf("InsertObject (%s): for counter, expected 1 got %d",
				tc.dbType, count)
		}

		// Try to fetch an object that should be there now.
		testMsg, err := tc.db.FetchObjectByCounter(objType, 1)
		testMsg.InventoryHash() // to make sure it's equal

		if err != nil {
			tc.t.Errorf("FetchObjectByCounter (%s): fetching object"+
				" of type %s, got error %v", tc.dbType, objType, err)
		}
		if !reflect.DeepEqual(testMsg.MsgObject(), msg.MsgObject()) {
			tc.t.Errorf("FetchObjectByCounter (%s): data mismatch", tc.dbType)
		}

		msg1 := testObj[i][1]

		count, err = tc.db.InsertObject(msg1.MsgObject())
		if err != nil {
			tc.t.Errorf("InsertObject (%s): object #%d #%d of type %s,"+
				" got error %v", tc.dbType, i, 1, objType, err)
		}
		if count != 2 {
			tc.t.Errorf("InsertObject (%s): object #%d #%d of type %s,"+
				" count error, expected 2, got %d", tc.dbType, i, 1,
				objType, count)
		}

		// Try fetching the new object.
		testMsg, err = tc.db.FetchObjectByCounter(objType, 2)
		testMsg.InventoryHash() // to make sure it's equal

		if err != nil {
			tc.t.Errorf("FetchObjectByCounter (%s): fetching existing object"+
				" of type %s, got error %v", tc.dbType, objType, err)
		}
		if !reflect.DeepEqual(testMsg.MsgObject(), msg1.MsgObject()) {
			tc.t.Errorf("FetchObjectByCounter (%s): data mismatch", tc.dbType)
		}

		// Test that the counter has incremented.
		count, err = tc.db.GetCounter(objType)
		if err != nil {
			tc.t.Errorf("GetCounter (%s): object type %s, got error %v",
				tc.dbType, objType, err)
		}
		if count != 2 {
			tc.t.Errorf("GetCounter (%s): object type %s, expected 2, got %d",
				tc.dbType, objType, count)
		}

		// Test FetchObjectsFromCounter for various input values.
		fetch, n, err := tc.db.FetchObjectsFromCounter(objType, 3, 2)
		if err != nil {
			tc.t.Errorf("FetchObjectsFromCounter (%s): object type %s, "+
				"expected empty slice got error %v", tc.dbType, objType, err)
		}
		if len(fetch) != 0 {
			tc.t.Errorf("FetchObjectsFromCounter (%s): object type %s, "+
				"incorrect slice size, expected 0, got %d", tc.dbType,
				objType, len(fetch))
		}
		if n != 0 {
			tc.t.Errorf("FetchObjectsFromCounter (%s): object type %s, "+
				"incorrect counter value, expected 0, got %d", tc.dbType,
				objType, n)
		}

		fetch, n, err = tc.db.FetchObjectsFromCounter(objType, 1, 3)
		if err != nil {
			tc.t.Errorf("FetchObjectsFromCounter (%s): object type %s,"+
				" got error %v", tc.dbType, objType, err)
		}
		if len(fetch) != 2 {
			tc.t.Errorf("FetchObjectsFromCounter (%s): object type %s,"+
				" incorrect slice size: expected 2, got %d", tc.dbType,
				objType, len(fetch))
		}
		if n != 2 {
			tc.t.Errorf("FetchObjectsFromCounter (%s): object type %s,"+
				" incorrect counter value: expected 2, got %d", tc.dbType,
				objType, n)
		}

		fetch, n, err = tc.db.FetchObjectsFromCounter(objType, 1, 1)
		if err != nil {
			tc.t.Errorf("FetchObjectsFromCounter (%s): object type %s,"+
				" got error %v", tc.dbType, objType, err)
		}
		if len(fetch) != 1 {
			tc.t.Errorf("FetchObjectsFromCounter (%s): object type %s,"+
				" incorrect slice size: expected 1, got %d", tc.dbType,
				objType, len(fetch))
		}
		if n != 1 {
			tc.t.Errorf("FetchObjectsFromCounter (%s): object type %s,"+
				" incorrect counter value: expected 1, got %d", tc.dbType,
				objType, n)
		}

		fetch, n, err = tc.db.FetchObjectsFromCounter(objType, 2, 3)
		if err != nil {
			tc.t.Errorf("FetchObjectsFromCounter (%s): object type %s,"+
				" got error %v", tc.dbType, objType, err)
		}
		if len(fetch) != 1 {
			tc.t.Errorf("FetchObjectsFromCounter (%s): object type %s,"+
				" incorrect slice size: expected 2, got %d", tc.dbType,
				objType, len(fetch))
		}
		if n != 2 {
			tc.t.Errorf("FetchObjectsFromCounter (%s): object type %s,"+
				" incorrect counter value, expected 2 got %d", tc.dbType,
				objType, n)
		}

		// Test that objects can be removed after being added.
		err = tc.db.RemoveObjectByCounter(objType, 1)
		if err != nil {
			tc.t.Errorf("RemoveObjectByCounter (%s): object type %s,"+
				" got error %v", tc.dbType, objType, err)
		}

		// Removing an object that has already been removed.
		err = tc.db.RemoveObjectByCounter(objType, 1)
		if err == nil {
			tc.t.Errorf("RemoveObjectByCounter (%s): removing already removed"+
				" object of type %s, got no error", tc.dbType, objType)
		}

		// Removing a nonexistent object
		err = tc.db.RemoveObjectByCounter(objType, 3)
		if err == nil {
			tc.t.Errorf("RemoveObjectByCounter (%s): removing nonexistent"+
				" object of type %s, got no error", tc.dbType, objType)
		}

		// Test that objects cannot be fetched after being removed.
		_, err = tc.db.FetchObjectByCounter(objType, 1)
		if err == nil {
			tc.t.Errorf("FetchObjectByCounter (%s): fetching nonexistent"+
				" object of type %s, got no error", tc.dbType, objType)
		}

		// Test that the counter values returned by FetchObjectsFromCounter are
		// correct after some objects have been removed.
		fetch, n, err = tc.db.FetchObjectsFromCounter(objType, 1, 3)
		if err != nil {
			tc.t.Errorf("FetchObjectByCounter (%s): object type %s,"+
				" got error %v", tc.dbType, objType, err)
		}
		if len(fetch) != 1 {
			tc.t.Errorf("FetchObjectByCounter (%s): object type %s,"+
				" incorrect slice size, expected 1 got %d", tc.dbType,
				objType, len(fetch))
		}
		if n != 2 {
			tc.t.Errorf("FetchObjectByCounter (%s): object type %s,"+
				" incorrect counter value, expected 2 got %d", tc.dbType,
				objType, n)
		}

		// close database
		teardown()
	}
}

// testPubKey tests inserting public key messages, FetchIdentityByAddress,
// RemoveEncryptedPubKey and RemovePublicIdentity
func testPubKey(tc *testContext) {
	teardown := tc.newDb()
	defer teardown()

	// test inserting invalid public key
	invalidPubkeyBytes := []byte{
		0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x47, 0xd8, // 83928 nonce
		0x00, 0x00, 0x00, 0x00, 0x49, 0x5f, 0xab, 0x29, // 64-bit Timestamp
		0x00, 0x00, 0x00, 0x01, // Object Type
		0x02,                   // Version
		0x01,                   // Stream Number
		0x00, 0x00, 0x00, 0x00, // Behavior
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Signing Key
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Encrypt Key
	}
	invalidPubkey := new(wire.MsgObject)
	invalidPubkey.Decode(bytes.NewReader(invalidPubkeyBytes))
	_, err := tc.db.InsertObject(invalidPubkey)
	if err != nil {
		tc.t.Errorf("InsertObject (%s): inserting invalid pubkey, got error %v",
			tc.dbType, err)
	}
	count, _ := tc.db.GetCounter(wire.ObjectTypePubKey)
	if count != 1 {
		tc.t.Errorf("GetCounter (%s): got %d expected %d", tc.dbType, count, 1)
	}

	// test FetchIdentityByAddress for an address that does not exist
	addr, err := bmutil.DecodeAddress("BM-2cV9RshwouuVKWLBoyH5cghj3kMfw5G7BJ")
	if err != nil {
		tc.t.Fatalf("DecodeAddress failed, got error %v", err)
	}
	_, err = tc.db.FetchIdentityByAddress(addr)
	if err == nil {
		tc.t.Errorf("FetchIdentityByAddress (%s): expected error got none",
			tc.dbType)
	}

	// test RemoveEncryptedPubKey for an address that does not exist
	tag, _ := wire.NewShaHash(addr.Tag())
	err = tc.db.RemoveEncryptedPubKey(tag)
	if err == nil {
		tc.t.Errorf("RemoveEncryptedPubKey (%s): expected error got none",
			tc.dbType)
	}

	// test RemovePublicIdentity for an address that does not exist
	err = tc.db.RemovePublicIdentity(addr)
	if err == nil {
		tc.t.Errorf("RemovePublicIdentity (%s): expected error got none",
			tc.dbType)
	}

	// test inserting valid v2 public key
	addrV2, _ := bmutil.DecodeAddress("BM-orNprZ3PNHsLgK5CQMgRoje1aCKgRA4QP")
	data, _ := hex.DecodeString("000000000000000000000000000000000000000102010000000187b541daefffc4b5ad1e61579e30c049709247630305e7962dcdf9ea2d0ef3e10ede4864ea5cfb42bd4ffa8b6f713490f106333b4e2ea8aed7b1ec7a7713958b380c6bac1f9742ef20fde832d0321a0643104ad98a91cf31f8ea0d28aa9886f19369ec065eafd823ae2c661cd586b111f72f18aa0b68db57f553f9b86f182f8f")
	msg := new(wire.MsgObject)
	err = msg.Decode(bytes.NewReader(data))
	if err != nil {
		tc.t.Fatal("failed to decode v2 pubkey, got error", err)
	}

	counter, err := tc.db.InsertObject(msg)
	if err != nil {
		tc.t.Errorf("InsertObject (%s): got error %v", tc.dbType, err)
	}
	if counter != 2 {
		tc.t.Errorf("InsertObject (%s): counter error, expected 2 got %d",
			tc.dbType, counter)
	}

	// test inserting valid v3 public key
	addrV3, _ := bmutil.DecodeAddress("BM-2D7oboD97WDibFcc792gkZjkvb3JQARiQx")
	data, _ = hex.DecodeString("0000000001FB575F000000005581B73A00000001030100000001520A752F43BD36DA5BD2C77FDB7E53C597EB21BDA6BD08A80AC2F4ACC3D885DE19945F02D6D18A655FD831F071B6224E0F145F7C3138BE07DB7C4C9C8BD234DD8333DA6BA201B9893982B28B740AB6252E3A146677A1EDE15F567F15D8E8C83EAD7547AC132D008418330810243A43DBCF2DD39C5283913ED6BD6C1A3B468271FD03E8FD03E8473045022100AB37F26D1709E43FD24852273033D97764F2498E170422EDC6775FADE21F7A9502206FEB2527BBCAF77E7D07BAF6FCD2F4ED49B8B4D1C3FCE7DEB6149D7E9DF3CD95")
	msg = new(wire.MsgObject)
	err = msg.Decode(bytes.NewReader(data))
	if err != nil {
		tc.t.Fatal("failed to decode v3 pubkey, got error", err)
	}

	counter, err = tc.db.InsertObject(msg)
	if err != nil {
		tc.t.Errorf("InsertObject (%s): got error %v", tc.dbType, err)
	}
	if counter != 3 {
		tc.t.Errorf("InsertObject (%s): counter error, expected 3 got %d",
			tc.dbType, counter)
	}

	// test inserting valid v4 public key
	addrV4, _ := bmutil.DecodeAddress("BM-2cTFEueNqmjgR3EqduEZmaZbEW1h9z7M7o")
	data, _ = hex.DecodeString("00000000025A04D60000000055A4EA7C0000000104017F933D64A866DE24C27D647C74068A59DCEE0CABFC1DF887BE7DD30BA3BD9143D513F0B37087891F6A98DD0B55B1A73E02CA002090CE6A050E760F52D18F7F50B1B9139DBCEF861254C195173AA601DE8A72B52E00206FAF91EDD32E213097CD91E4ACBB883CB2F8CC6AAFCC670DDE1FAC52C210469D71B08A162E07C4B8926A50CC0701594AF55D65052C2D9D74CE28BB571D781423C101BDC8DB6CE3FA639BDDE9CE39364307188470AEC410F7EE2BCC008CA6B1F2A37CF0841FC5EDE154C172438061577FBF3BC6BCDAAAB9BBCC90378DE815A99B0B78D81DFC9ABE33F99B4BC2AFAC2101ED7E0E213C00011FF3583B1E2BAADEF4BED2DB17F340258C22D38F8B490040B94E01F76F2118D90D718FFAFFB7D8F2A9F2B3498D45D528F16BCE55B43E63AAF3AED720F0AC06FCEB853661ACE13714069AA47A3D2FD6180AD0458B344E7AF04A26A25490DCEF236EE29CDF2FD96CDF55EB2B0D4DACA1EC21B4049DB6A6C713A2350D6ECE4C77C01DA01BCAAB2F2CBB31")
	msg = new(wire.MsgObject)
	err = msg.Decode(bytes.NewReader(data))
	if err != nil {
		tc.t.Fatal("failed to decode v4 pubkey, got error", err)
	}

	counter, err = tc.db.InsertObject(msg)
	if err != nil {
		tc.t.Errorf("InsertObject (%s): got error %v", tc.dbType, err)
	}
	if counter != 4 {
		tc.t.Errorf("InsertObject (%s): count error, expected 4 got %d",
			tc.dbType, counter)
	}

	// test FetchIdentityByAddress for an address that exists in the database
	// v2 address
	idV2, err := tc.db.FetchIdentityByAddress(addrV2)
	if err != nil {
		tc.t.Errorf("FetchIdentityByAddress (%s): got error %v", tc.dbType,
			err)
	}
	if !reflect.DeepEqual(&idV2.Address, addrV2) {
		tc.t.Errorf("FetchIdentityByAddress (%s): identities not equal",
			tc.dbType)
	}

	// v3 address
	idV3, err := tc.db.FetchIdentityByAddress(addrV3)
	if err != nil {
		tc.t.Errorf("FetchIdentityByAddress (%s): got error %v", tc.dbType,
			err)
	}
	if idV3 == nil {
		panic("Nooooooooooooooooooooooooooooooo")
	}
	if !reflect.DeepEqual(&idV3.Address, addrV3) {
		tc.t.Errorf("FetchIdentityByAddress (%s): identities not equal",
			tc.dbType)
	}

	// v4 address
	idV4, err := tc.db.FetchIdentityByAddress(addrV4)
	if err != nil {
		tc.t.Errorf("FetchIdentityByAddress (%s): got error %v", tc.dbType,
			err)
	}
	if !reflect.DeepEqual(&idV4.Address, addrV4) {
		tc.t.Errorf("FetchIdentityByAddress (%s): identities not equal",
			tc.dbType)
	}

	// Test whether RemoveEncryptedPubKey fails for a decrypted key.
	tag, _ = wire.NewShaHash(idV4.Tag())
	err = tc.db.RemoveEncryptedPubKey(tag)
	if err != database.ErrNonexistentObject {
		tc.t.Errorf("RemoveEncryptedPubKey (%s): expected nonexistent object"+
			" error, got %v", tc.dbType, err)
	}

	// Test RemoveEncryptedPubKey for a tag that exists in the database
	data, _ = hex.DecodeString("0000000000A229F300000000559BAFB0000000010401F17457B60376F21C20F485652A8A3047ECBBAD4E609E3594D74C7A94D55B994BB4385338FF5E76639EA4EB083C01CCE402CA00205BA2AE2C4519376892C8352EE978E91B298071FFC2F9A211B566715C1D8A4EFF002018E8708FACA508F037DB07E05015B3F91BAAAE22F6A5FF24C4F0C9AF3B1119B01AE14110E14ECC4B511D867DDA589F26A257AD07244F1BCA502C2BFF4269AF29F99C2437C555F4CC42FF510607E4787082354D6C4CDD437010EFDC9B7C88783855988578890C5CBB1FBAE692B7B40C6E1B4642299E181BADCB48D9F931701BA5351161C7E136703DDE5D85735F6366184195C68EF0FB401304B068ED10E785B78C503A3D15FE5D302B0D660E611004BC2925D45D4F65F6E9607F5EA5CA64CBF87B753318AC55364D471B589FFD946E85AC8BA3B6FE82E71A34403852C55A4F4CDCECB89F77032AB8BF18D7C68A983CB902456C90367D3494FA040A69830F4A140E251BCD78A7A36E5F674D5B91C553EF2A3DA17D0F1E9A05F154719F39CBEEF1")
	msg = new(wire.MsgObject)
	err = msg.Decode(bytes.NewReader(data))
	if err != nil {
		tc.t.Fatal("failed to decode v4 pubkey, got error", err)
	}
	_, err = tc.db.InsertObject(msg)
	if err != nil {
		tc.t.Errorf("InsertObject (%s): got error %v", tc.dbType, err)
	}
	tag, _ = wire.NewShaHash(msg.Payload()[:32])
	err = tc.db.RemoveEncryptedPubKey(tag)
	if err != nil {
		tc.t.Errorf("RemoveEncryptedPubKey (%s): got error %v", tc.dbType, err)
	}

	// test RemovePublicIdentity for an address that exists in the database
	// v2
	err = tc.db.RemovePublicIdentity(addrV2)
	if err != nil {
		tc.t.Errorf("RemovePublicIdentity (%s): got error %v", tc.dbType, err)
	}
	// v3
	err = tc.db.RemovePublicIdentity(addrV3)
	if err != nil {
		tc.t.Errorf("RemovePublicIdentity (%s): got error %v", tc.dbType, err)
	}
	// decrypted v4
	err = tc.db.RemovePublicIdentity(addrV4)
	if err != nil {
		tc.t.Errorf("RemovePublicIdentity (%s): got error %v", tc.dbType, err)
	}
	// Test RemovePubKey for an address that was removed.
	err = tc.db.RemovePublicIdentity(addrV2)
	if err != database.ErrNonexistentObject {
		tc.t.Errorf("RemovePublicIdentity (%s): expected nonexistent object"+
			" error, got %v", tc.dbType, err)
	}

	// test FetchIdentityByAddress for an address that was removed
	// v2 address
	_, err = tc.db.FetchIdentityByAddress(addrV2)
	if err != database.ErrNonexistentObject {
		tc.t.Errorf("FetchIdentityByAddress (%s): expected nonexistent object"+
			" error, got %v", tc.dbType, err)
	}
	// v3 address
	_, err = tc.db.FetchIdentityByAddress(addrV3)
	if err != database.ErrNonexistentObject {
		tc.t.Errorf("FetchIdentityByAddress (%s): expected nonexistent object"+
			" error, got %v", tc.dbType, err)
	}
	// v4 address
	_, err = tc.db.FetchIdentityByAddress(addrV4)
	if err != database.ErrNonexistentObject {
		tc.t.Errorf("FetchIdentityByAddress (%s): expected nonexistent object"+
			" error, got %v", tc.dbType, err)
	}
}

// tests FetchRandomInvHashes and FilterObjects
func testFilters(tc *testContext) {
	teardown := tc.newDb()
	defer teardown()

	for _, messages := range testObj {
		for _, msg := range messages {
			_, _ = tc.db.InsertObject(msg.MsgObject())
		}
	}

	type randomInvHashesTest struct {
		count         uint64
		expectedCount int
	}

	randomInvHashesTests := []randomInvHashesTest{
		{2, 2},
		{15, 12},
	}

	for i, tst := range randomInvHashesTests {
		hashes, err := tc.db.FetchRandomInvHashes(tst.count)
		if err != nil {
			tc.t.Fatalf("FetchRandomInvHashes (%s): test #%d, got error %v",
				tc.dbType, i, err)
		}
		if len(hashes) > tst.expectedCount {
			tc.t.Errorf("FetchRandomInvHashes (%s): test #%d, got length %d"+
				" expected %d", tc.dbType, i, len(hashes), tst.expectedCount)
		}
	}
}

func testRemoveExpiredObjects(tc *testContext) {
	teardown := tc.newDb()
	defer teardown()

	for _, messages := range testObj {
		for _, msg := range messages {
			_, _ = tc.db.InsertObject(msg.MsgObject())
		}
	}

	tc.db.RemoveExpiredObjects()

	for i, messages := range testObj {
		for j, msg := range messages {
			hash := msg.InventoryHash()

			exists, _ := tc.db.ExistsObject(hash)

			// The object should have been deleted
			if j == 1 {
				if exists {
					tc.t.Errorf("RemoveExpiredObjects (%s): message #%d #%d"+
						" should have been deleted, but was not",
						tc.dbType, i, j)
				}
			} else {
				if !exists {
					tc.t.Errorf("RemoveExpiredObjects (%s): message #%d #%d"+
						" should not have been deleted, but was",
						tc.dbType, i, j)
				}
			}
		}
	}
}

// testInterface tests performs tests for the various interfaces of the database
// package which require state in the database for the given database type.
func testInterface(t *testing.T, dbType string) {
	// Create a test context to pass around.
	context := &testContext{t: t, dbType: dbType}

	testObject(context)
	testPubKey(context)
	testRemoveExpiredObjects(context)
	testCounter(context)
	testFilters(context)
}
