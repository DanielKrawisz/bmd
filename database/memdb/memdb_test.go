// Originally derived from: btcsuite/btcd/database/memdb/memdb_test.go
// Copyright (c) 2013-2015 Conformal Systems LLC.

// Copyright (c) 2015 Monetas.
// Copyright 2016 Daniel Krawisz.
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package memdb_test

import (
	"testing"

	"github.com/DanielKrawisz/bmd/database"
	_ "github.com/DanielKrawisz/bmd/database/memdb"
	"github.com/DanielKrawisz/bmutil/wire"
)

// TestClosed ensures that the correct errors are returend when the public
// functions are called on a closed database.
func TestClosed(t *testing.T) {
	db, err := database.OpenDB("memdb")
	if err != nil {
		t.Fatalf("Failed to open test database %v", err)
	}

	db.Close()

	if err := db.Close(); err != database.ErrDbClosed {
		t.Errorf("Close: unexpected error %v", err)
	}

	if _, err := db.InsertObject(nil); err != database.ErrDbClosed {
		t.Errorf("InsertObject: unexpected error %v", err)
	}

	if _, err = db.ExistsObject(nil); err != database.ErrDbClosed {
		t.Errorf("ExistsObject: unexpected error %v", err)
	}

	if err := db.RemoveObject(nil); err != database.ErrDbClosed {
		t.Errorf("RemoveObject: unexpected error %v", err)
	}

	if _, err := db.FetchObjectByHash(nil); err != database.ErrDbClosed {
		t.Errorf("FetchObjectByHash: unexpected error %v", err)
	}

	if _, err := db.RemoveExpiredObjects(); err != database.ErrDbClosed {
		t.Errorf("RemoveExpiredObjects: unexpected error %v", err)
	}

	_, err = db.FetchObjectByCounter(wire.ObjectType(4), 1)
	if err != database.ErrDbClosed {
		t.Errorf("FetchObjectByCounter: unexpected error %v", err)
	}

	_, _, err = db.FetchObjectsFromCounter(wire.ObjectType(4), 1, 10)
	if err != database.ErrDbClosed {
		t.Errorf("FetchObjectsFromCounter: unexpected error %v", err)
	}

	if _, err := db.GetCounter(wire.ObjectType(4)); err != database.ErrDbClosed {
		t.Errorf("GetCounter: unexpected error %v", err)
	}

	if err := db.RemoveObjectByCounter(wire.ObjectType(4), 3); err !=
		database.ErrDbClosed {
		t.Errorf("RemoveObjectByCounter: unexpected error %v", err)
	}

	if err := db.RemoveEncryptedPubKey(nil); err != database.ErrDbClosed {
		t.Errorf("RemoveEncryptedPubKey: unexpected error %v", err)
	}

	if _, err := db.FetchIdentityByAddress(nil); err != database.ErrDbClosed {
		t.Errorf("FetchIdentityByAddress: unexpected error %v", err)
	}

	if _, err := db.FetchRandomInvHashes(0); err != database.ErrDbClosed {
		t.Errorf("FetchRandomInvHashes: unexpected error %v", err)
	}
}
