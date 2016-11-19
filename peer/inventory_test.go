// Copyright (c) 2015 Monetas.
// Copyright 2016 Daniel Krawisz.
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package peer_test

import (
	"testing"

	"github.com/DanielKrawisz/bmd/peer"
	"github.com/DanielKrawisz/bmutil/wire"
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

func TestRequest(t *testing.T) {
	inventory := peer.NewInventory()

	if inventory.NumRequests() != 0 {
		t.Error("Number of requests should be zero.")
	}

	inventory.AddRequest(3)

	if inventory.NumRequests() != 3 {
		t.Error("Number of requests should be three.")
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
