// Copyright (c) 2015 Monetas.
// Copyright 2016 Daniel Krawisz.
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"encoding/binary"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"time"

	"github.com/DanielKrawisz/bmd/database"
	"github.com/DanielKrawisz/bmutil"
	"github.com/DanielKrawisz/bmutil/hash"
	"github.com/DanielKrawisz/bmutil/pow"
	"github.com/DanielKrawisz/bmutil/wire"
	"github.com/DanielKrawisz/bmutil/wire/obj"
)

var expires = time.Now().Add(5 * time.Minute)

// resetCfg is called to refresh configuration before every test. The returned
// function is supposed to be called at the end of the test; to clear temp
// directories.
func resetCfg(cfg *Config) func() {
	dir, err := ioutil.TempDir("", "bmd")
	if err != nil {
		panic(fmt.Sprint("Failed to create temporary directory:", err))
	}
	cfg.DataDir = dir
	cfg.LogDir = filepath.Join(cfg.DataDir, defaultLogDirname)

	cfg.Validate("test")

	return func() {
		os.RemoveAll(dir)
	}
}

func getMemDb(msgs []obj.Object) *database.Db {
	db, err := database.OpenDB("memdb")
	if err != nil {
		return nil
	}

	for _, msg := range msgs {
		db.InsertObject(msg)
	}

	return db
}

// Some bitmessage objects that we use for testing. Two of each.
var testObj = []obj.Object{
	obj.NewGetPubKey(654, expires, NewAddress(4, 1, &ripehash[0], &shahash[0])).MsgObject(),
	obj.NewGetPubKey(654, expires, NewAddress(4, 1, &ripehash[1], &shahash[1])).MsgObject(),
	obj.NewEncryptedPubKey(543, expires, 1, &shahash[0], []byte{11, 12, 13, 14, 15, 16, 17, 18}).MsgObject(),
	obj.NewEncryptedPubKey(543, expires, 1, &shahash[1], []byte{11, 12, 13, 14, 15, 16, 17, 18}).MsgObject(),
	obj.NewMessage(765, expires, 1,
		[]byte{90, 87, 66, 45, 3, 2, 120, 101, 78, 78, 78, 7, 85, 55, 2, 23}).MsgObject(),
	obj.NewMessage(765, expires, 1,
		[]byte{90, 87, 66, 45, 3, 2, 120, 101, 78, 78, 78, 7, 85, 55}).MsgObject(),
	obj.NewTaggedBroadcast(876, expires, 1, &shahash[0],
		[]byte{42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56}).MsgObject(),
	obj.NewTaggedBroadcast(876, expires, 1, &shahash[1],
		[]byte{42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55}).MsgObject(),
	wire.NewMsgObject(wire.NewObjectHeader(345, expires, wire.ObjectType(4), 1, 1), []byte{77, 82, 53, 48, 96, 1}),
	wire.NewMsgObject(wire.NewObjectHeader(987, expires, wire.ObjectType(4), 1, 1), []byte{1, 2, 3, 4, 5, 0, 6, 7, 8, 9, 100}),
	wire.NewMsgObject(wire.NewObjectHeader(7288, expires, wire.ObjectType(5), 1, 1), []byte{0, 0, 0, 0, 1, 0, 0}),
	wire.NewMsgObject(wire.NewObjectHeader(7288, expires, wire.ObjectType(5), 1, 1), []byte{0, 0, 0, 0, 0, 0, 0, 99, 98, 97}),
}

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

var shahash = []hash.Sha{
	hash.Sha([hash.ShaSize]byte{
		98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113,
		114, 115, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125, 126, 127, 128, 129}),
	hash.Sha([hash.ShaSize]byte{
		100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115,
		116, 117, 118, 119, 120, 121, 122, 123, 124, 125, 126, 127, 128, 129, 130, 131}),
}

var ripehash = []hash.Ripe{
	hash.Ripe([hash.RipeSize]byte{
		78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95, 96, 97}),
	hash.Ripe([hash.RipeSize]byte{
		80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95, 96, 97, 98, 99}),
}

func NewAddress(version, stream uint64, ripe *hash.Ripe, sha *hash.Sha) bmutil.Address {
	var a bmutil.Address
	if version == 4 {
		a, _ = bmutil.NewAddress(4, stream, ripe)
	} else if version < 4 {
		a, _ = bmutil.NewDepricatedAddress(version, stream, ripe)
	}

	return a
}

func init() {
	start := int(0)
	println("Calculating pow for ", len(testObj)-start, " objects. ")

	// Calculate pow for object messages.
	for i := start; i < len(testObj); i++ {
		n := testObj[i].Header().Nonce

		b := wire.Encode(testObj[i])
		section := b[8:]
		hash := hash.Sha512(section)

		target := pow.CalculateTarget(uint64(len(section)),
			uint64(expires.Sub(time.Now()).Seconds()), pow.Default)

		if pow.Check(target, n, hash) {
			println("Object ", i, "'s nonce checks out ok.")
			continue
		}

		nonce := pow.DoSequential(target, hash)
		binary.BigEndian.PutUint64(b, uint64(nonce))
		testObj[i], _ = wire.DecodeMsgObject(b)
		println("Object ", i, " has nonce ", nonce)
	}

	// Load config
	var err error
	cfg = DefaultConfig()
	if err != nil {
		panic(fmt.Sprint("Config failed to load: ", err))
	}
	cfg.MaxPeers = 1
	cfg.DisableDNSSeed = true
	cfg.DebugLevel = "trace"
}
