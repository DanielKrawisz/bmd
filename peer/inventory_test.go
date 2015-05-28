// Copyright (c) 2015 Monetas.
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package peer_test

import (
	"testing"

	"github.com/monetas/bmd/peer"
	"github.com/monetas/bmutil/wire"
)

func TestNewInventory(t *testing.T) {
	if peer.NewInventory() == nil {
		t.Error("Nil inventory returned.")
	}
}

func TestIsAddKnown(t *testing.T) {
	inventory := peer.NewInventory()

	a := &wire.InvVect{Hash: *randomShaHash()}

	if inventory.IsKnown(a) {
		t.Error("Map should be empty.")
	}

	inventory.AddKnown(a)
	if !inventory.IsKnown(a) {
		t.Error("Map should not be empty..")
	}
}

func TestAddDeleteRequest(t *testing.T) {
	inventory := peer.NewInventory()

	a := &wire.InvVect{Hash: *randomShaHash()}

	if inventory.DeleteRequest(a) {
		t.Error("Map should be empty.")
	}

	inventory.AddRequest(a)
	if !inventory.DeleteRequest(a) {
		t.Error("Map should not be empty..")
	}
}

func TestFilterKnown(t *testing.T) {
	inventory := peer.NewInventory()

	a := &wire.InvVect{Hash: *randomShaHash()}
	b := &wire.InvVect{Hash: *randomShaHash()}
	c := &wire.InvVect{Hash: *randomShaHash()}

	inventory.AddKnown(a)

	ret := inventory.FilterKnown([]*wire.InvVect{a, b, c})

	if len(ret) != 2 {
		t.Errorf("Filtered list has the wrong size. Got %d expected %d.", len(ret), 2)
	}
	if ret[0] != b {
		t.Error("Wrong filtered list returned.")
	}

	if !inventory.IsKnown(a) {
		t.Error("Element should be present.")
	}
	if !inventory.IsKnown(b) {
		t.Error("Element should be present.")
	}
	if !inventory.IsKnown(c) {
		t.Error("Element should be present.")
	}
}

func TestFilterRequested(t *testing.T) {
	inventory := peer.NewInventory()

	a := &wire.InvVect{Hash: *randomShaHash()}
	b := &wire.InvVect{Hash: *randomShaHash()}
	c := &wire.InvVect{Hash: *randomShaHash()}

	inventory.AddRequest(a)

	ret := inventory.FilterRequested([]*wire.InvVect{a, b, c})

	if len(ret) != 2 {
		t.Errorf("Filtered list has the wrong size. Got %d expected %d.", len(ret), 2)
	}
	if ret[0] != b {
		t.Error("Wrong filtered list returned.")
	}

	if !inventory.DeleteRequest(a) {
		t.Error("Element should be present.")
	}
	if !inventory.DeleteRequest(b) {
		t.Error("Element should be present.")
	}
	if !inventory.DeleteRequest(c) {
		t.Error("Element should be present.")
	}
}
