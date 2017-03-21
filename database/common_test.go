// Originally derived from: btcsuite/btcd/database/common_test.go
// Copyright (c) 2013-2015 Conformal Systems LLC.

// Copyright (c) 2015 Monetas.
// Copyright 2016 Daniel Krawisz.
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package database_test

import (
	"fmt"
	"io/ioutil"
	"os"

	"github.com/DanielKrawisz/bmd/database"
	_ "github.com/DanielKrawisz/bmd/database/bdb"
	_ "github.com/DanielKrawisz/bmd/database/memdb"
)

// createDB creates a new db instance and returns a teardown function the caller
// should invoke when done testing to clean up. The close flag indicates
// whether or not the teardown function should sync and close the database
// during teardown.
func createDB(dbType string) (*database.Db, func(), error) {
	// Handle memory database specially since it doesn't need the disk
	// specific handling.
	if dbType == "memdb" {
		db, err := database.OpenDB(dbType)
		if err != nil {
			return nil, nil, fmt.Errorf("error creating db: %v", err)
		}

		// Setup a teardown function for cleaning up. This function is
		// returned to the caller to be invoked when it is done testing.
		teardown := func() {
			db.Close()
		}

		return db, teardown, nil
	}

	// Create temporary file for test database.
	f, err := ioutil.TempFile("", "bmd_db")
	if err != nil {
		return nil, nil, err
	}

	// Create a new database.
	db, err := database.OpenDB(dbType, f.Name())
	if err != nil {
		return nil, nil, fmt.Errorf("error creating db: %v", err)
	}

	// Setup a teardown function for cleaning up. This function is
	// returned to the caller to be invoked when it is done testing.
	teardown := func() {
		os.Remove(f.Name())
	}

	return db, teardown, nil
}
