// Originally derived from: btcsuite/btcd/database/db_test.go
// Copyright (c) 2013-2015 Conformal Systems LLC.

// Copyright (c) 2015 Monetas.
// Copyright 2016 Daniel Krawisz.
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package database_test

import (
	"fmt"
	"testing"

	"github.com/DanielKrawisz/bmd/database"
)

var (
	// ignoreDbTypes are types which should be ignored when running tests
	// that iterate all supported DB types. This allows some tests to add
	// bogus drivers for testing purposes while still allowing other tests
	// to easily iterate all supported drivers.
	ignoreDbTypes = map[string]bool{"createopenfail": true}
)

// TestAddDuplicateDriver ensures that adding a duplicate driver does not
// overwrite an existing one.
func TestAddDuplicateDriver(t *testing.T) {
	supportedDBs := database.SupportedDBs()
	if len(supportedDBs) == 0 {
		t.Errorf("TestAddDuplicateDriver: No backends to test")
		return
	}
	dbType := supportedDBs[0]

	// bogusCreateDB is a function which acts as a bogus create and open
	// driver function and intentionally returns a failure that can be
	// detected if the interface allows a duplicate driver to overwrite an
	// existing one.
	bogusCreateDB := func(args ...interface{}) (*database.Db, error) {
		return nil, fmt.Errorf("duplicate driver allowed for database "+
			"type [%v]", dbType)
	}

	// Create a driver that tries to replace an existing one. Set its
	// create and open functions to a function that causes a test failure if
	// they are invoked.
	driver := database.DriverDB{
		DbType: dbType,
		OpenDB: bogusCreateDB,
	}
	database.AddDBDriver(driver)

	// Ensure creating a database of the type that we tried to replace
	// doesn't fail (if it does, it indicates the driver was erroneously
	// replaced).
	_, _, teardown, err := createDB(dbType)
	if err != nil {
		t.Errorf("TestAddDuplicateDriver: %v", err)
		return
	}
	teardown()
}

// TestCreateOpenFail ensures that errors which occur while opening or closing
// a database are handled properly.
func TestCreateOpenFail(t *testing.T) {
	// bogusCreateDB is a function which acts as a bogus create and open
	// driver function that intentionally returns a failure which can be
	// detected.
	dbType := "createopenfail"
	openError := fmt.Errorf("failed to create or open database for "+
		"database type [%v]", dbType)
	bogusCreateDB := func(args ...interface{}) (*database.Db, error) {
		return nil, openError
	}

	// Create and add driver that intentionally fails when created or opened
	// to ensure errors on database open and create are handled properly.
	driver := database.DriverDB{
		DbType: dbType,
		OpenDB: bogusCreateDB,
	}
	database.AddDBDriver(driver)

	// Ensure opening a database with the new type fails with the expected
	// error.
	_, err := database.OpenDB(dbType, "openfailtest")
	if err != openError {
		t.Errorf("TestOpenFail: expected error not received - "+
			"got: %v, want %v", err, openError)
		return
	}
}

// TestOpenUnsupported ensures that attempting to create or open an unsupported
// database type is handled properly.
func TestOpenUnsupported(t *testing.T) {
	// Ensure opening a database with the new type fails with the expected
	// error.
	dbType := "unsupported"
	_, err := database.OpenDB(dbType, "unsupportedopentest")
	if err != database.ErrDbUnknownType {
		t.Errorf("TestCreateOpenUnsupported: expected error not "+
			"received - got: %v, want %v", err, database.ErrDbUnknownType)
		return
	}
}

// TestInterface performs tests for the various interfaces of the database
// package which require state in the database for each supported database
// type (those loaded in common_test.go that is).
func TestInterface(t *testing.T) {
	for _, dbType := range database.SupportedDBs() {
		if _, exists := ignoreDbTypes[dbType]; !exists {
			testInterface(t, dbType)
		}
	}
}
