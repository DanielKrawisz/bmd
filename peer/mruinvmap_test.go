// Copyright (c) 2015 Monetas.
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package peer_test

import (
	"testing"
	"math/rand"

	"github.com/monetas/bmd/peer"
	"github.com/monetas/bmutil/wire"
)

func randomShaHash() *wire.ShaHash {
	b := make([]byte, 32)
	for i := 0; i < 32; i++ {
		b[i] = byte(rand.Intn(256))
	}
	hash, _ := wire.NewShaHash(b)
	return hash
}

func TestNew(t *testing.T) {
	if peer.NewMruInventoryMap(2) == nil {
		t.Error("Should have returned an inv map.")
	}
}

func TestString(t *testing.T) {
	hasha, _ := wire.NewShaHash([]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1})
	hashb, _ := wire.NewShaHash([]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 200})
	a := &wire.InvVect{Hash: *hasha}
	b := &wire.InvVect{Hash: *hashb}

	m := peer.NewMruInventoryMap(2)
	m.Add(a)
	m.Add(b)

	// No good way to actually test that the string comes out right.
	str := m.String()
	//t.Error("String expected:",str)

	if str[:74] != "<2>map[{0000000000000000000000000000000000000000000000000000000000000001}:" &&
		str[87:154] != "{00000000000000000000000000000000000000000000000000000000000000c8}:" {
		t.Error("Incorrect string returned.")
	}
}

// TestMruInvMap tests Exists, Add, and Delete.
func TestMruInvMap(t *testing.T) {
	a := &wire.InvVect{Hash: *randomShaHash()}
	b := &wire.InvVect{Hash: *randomShaHash()}
	c := &wire.InvVect{Hash: *randomShaHash()}

	m := peer.NewMruInventoryMap(2)

	if m.Exists(a) {
		t.Error("Map should be empty.")
	}

	m.Add(a)
	if !m.Exists(a) {
		t.Error("Map should not be empty..")
	}
	m.Add(b)
	m.Add(c)

	// Now the map should be missing a and have both b and c.
	if m.Exists(a) {
		t.Error("Element should have been knocked out.")
	}

	if !m.Exists(b) {
		t.Error("Element should be present.")
	}

	m.Delete(b)
	if m.Exists(b) {
		t.Error("Element was deleted and should not be present.")
	}
	m.Add(c)
	if !m.Exists(c) {
		t.Error("Element should be present.")
	}
}

// TestAdd0 tests an mruinvmap of size zero.
func TestAdd0(t *testing.T) {
	a := &wire.InvVect{Hash: *randomShaHash()}

	m := peer.NewMruInventoryMap(0)
	if m.Exists(a) {
		t.Error("Map should be empty.")
	}

	m.Add(a)
	if m.Exists(a) {
		t.Error("Map should still be empty.")
	}
}

func TestFilter(t *testing.T) {
	a := &wire.InvVect{Hash: *randomShaHash()}
	b := &wire.InvVect{Hash: *randomShaHash()}
	c := &wire.InvVect{Hash: *randomShaHash()}

	m := peer.NewMruInventoryMap(3)
	m.Add(a)

	ret := m.Filter([]*wire.InvVect{a, b, c})

	if len(ret) != 2 {
		t.Errorf("Filtered list has the wrong size. Got %d expected %d.", len(ret), 2)
	}
	if ret[0] != b {
		t.Error("Wrong filtered list returned.")
	}

	if !m.Exists(a) {
		t.Error("Element should be present.")
	}
	if !m.Exists(b) {
		t.Error("Element should be present.")
	}
	if !m.Exists(c) {
		t.Error("Element should be present.")
	}
}
