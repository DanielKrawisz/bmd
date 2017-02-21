// Originally derived from: btcsuite/btcd/database/memdb/driver.go
// Copyright (c) 2013-2015 Conformal Systems LLC.

// Copyright (c) 2015 Monetas.
// Copyright 2016 Daniel Krawisz.
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package bdb

import (
	"errors"
	"fmt"
	"time"

	"github.com/DanielKrawisz/bmd/database"
	"github.com/boltdb/bolt"
	"github.com/btcsuite/btclog"
)

const (
	// latestDbVersion is the most recent version of database.
	latestDbVersion = 0x01
)

var log = btclog.Disabled

func init() {
	driver := database.DriverDB{DbType: "boltdb", OpenDB: OpenDB}
	database.AddDBDriver(driver)
}

// parseArgs parses the arguments from the database package Open/Create methods.
func parseArgs(funcName string, args ...interface{}) (string, error) {
	if len(args) != 1 {
		return "", fmt.Errorf("Invalid arguments to bdb.%s -- "+
			"expected database path string", funcName)
	}
	dbPath, ok := args[0].(string)
	if !ok {
		return "", fmt.Errorf("First argument to bdb.%s is invalid -- "+
			"expected database path string", funcName)
	}
	return dbPath, nil
}

// OpenDB opens a database, initializing it if necessary.
func OpenDB(args ...interface{}) (database.Db, error) {
	dbPath, err := parseArgs("OpenDB", args...)
	if err != nil {
		return nil, err
	}

	log = database.GetLog()

	// Open the database, creating the required structure, if necessary.
	db, err := bolt.Open(dbPath, 0644, &bolt.Options{Timeout: time.Second})
	if err != nil {
		return nil, err
	}

	bdb, err := newBoltDB(db)
	if err != nil {
		return nil, err
	}

	return bdb, nil
}

// checkAndUpgrade checks for and upgrades the database version.
func checkAndUpgrade(tx *bolt.Tx) error {
	v := tx.Bucket(miscBucket).Get(versionKey)
	if v[0] != latestDbVersion {
		return errors.New("Unrecognized database version.")
	}
	return nil
}
