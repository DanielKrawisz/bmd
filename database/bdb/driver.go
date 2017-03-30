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

type Now func() time.Time

func init() {
	driver := database.DriverDB{DbType: "boltdb", OpenDB: OpenDB}
	database.AddDBDriver(driver)
}

// parseString parses the arguments from the database package Open/Create methods.
func parseString(funcName string, arg interface{}) (string, error) {
	dbPath, ok := arg.(string)
	if !ok {
		return "", fmt.Errorf("First argument to bdb.%s is invalid -- "+
			"expected string", funcName)
	}
	return dbPath, nil
}

// parseStats parses the arguments from the database package Open/Create methods.
func parseStats(funcName string, arg interface{}) (database.Stats, error) {
	z, ok := arg.(database.Stats)
	if !ok {
		return database.Stats{}, fmt.Errorf("First argument to bdb.%s is invalid -- "+
			"expected file pointer", funcName)
	}
	return z, nil
}

// parseNow parses a function that is used to tell the current time.
func parseNow(argNumber int, funcName string, arg interface{}) (Now, error) {
	z, ok := arg.(Now)
	if !ok {
		return nil, fmt.Errorf("argument %d of to bdb.%s is invalid -- "+
			"expected Now", argNumber, funcName)
	}
	return z, nil
}

// OpenDB opens a database, initializing it if necessary.
func OpenDB(args ...interface{}) (*database.Db, error) {
	var dbpath string
	var err error
	var bdb *database.Db

	if len(args) == 0 {
		return nil, errors.New("Path to database required.")
	}

	if len(args) > 3 {
		return nil, errors.New("Too many arguments for OpenDB.")
	}

	dbpath, err = parseString("OpenDB", args[0])
	if err != nil {
		return nil, err
	}

	log = database.GetLog()
	now := time.Now
	z := database.NewDisabledStatsRecorder()

	// Open the database, creating the required structure, if necessary.
	db, err := bolt.Open(dbpath, 0644, &bolt.Options{Timeout: time.Second})
	if err != nil {
		return nil, err
	}

	if len(args) >= 2 {
		z, err = parseStats("OpenDB", args[1])
		if err != nil {
			return nil, err
		}
	}

	if len(args) >= 3 {
		now, err = parseNow(3, "OpenDB", args[2])
		if err != nil {
			return nil, err
		}
	}

	bdb, err = NewBoltDB(db, z, now)
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
