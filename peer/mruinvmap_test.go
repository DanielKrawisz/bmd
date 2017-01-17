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

func TestNew(t *testing.T) {
	if peer.NewMruInventoryMap(2) == nil {
		t.Error("Should have returned an inv map.")
	}
}

// TestMruInvMap tests Exists, Add, and Delete.
func TestMruInvMap(t *testing.T) {
	a := (*wire.InvVect)(randomShaHash())
	b := (*wire.InvVect)(randomShaHash())
	c := (*wire.InvVect)(randomShaHash())

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
	a := (*wire.InvVect)(randomShaHash())

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
	a := (*wire.InvVect)(randomShaHash())
	b := (*wire.InvVect)(randomShaHash())
	c := (*wire.InvVect)(randomShaHash())

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
