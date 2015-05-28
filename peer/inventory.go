// Copyright (c) 2015 Monetas.
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package peer

import (
	"sync"

	"github.com/monetas/bmutil/wire"
)

// Inventory is the part of a peer that manages object hashes and remembers
// which are known to the peer and which have been requested from it. It is safe
// for concurrent access.
type Inventory struct {
	known     *MruInventoryMap
	requested *MruInventoryMap
	mutex     sync.RWMutex
}

// IsKnown returns whether or not the peer is known to have the passed
// inventory.
func (I *Inventory) IsKnown(invVect *wire.InvVect) bool {
	I.mutex.RLock()
	defer I.mutex.RUnlock()

	if I.known.Exists(invVect) {
		return true
	}
	return false
}

// AddKnown adds the passed inventory to the cache of known inventory for the
// peer.
func (I *Inventory) AddKnown(invVect *wire.InvVect) {
	I.mutex.Lock()
	defer I.mutex.Unlock()

	I.known.Add(invVect)
}

// AddRequest adds a request to the set of requested inventory.
func (I *Inventory) AddRequest(invVect *wire.InvVect) {
	I.mutex.Lock()
	defer I.mutex.Unlock()

	I.requested.Add(invVect)
}

// DeleteRequest removes an entry from the set of requested inventory. It returns
// true if the inventory was really removed.
func (I *Inventory) DeleteRequest(invVect *wire.InvVect) (ok bool) {
	I.mutex.Lock()
	defer I.mutex.Unlock()

	if I.requested.Exists(invVect) {
		I.requested.Delete(invVect)
		return true
	}
	return false
}

// FilterKnown takes a list of InvVects, adds them to the list of known
// inventory, and returns those which were not already in the list. It is used
// to ensure that data is not sent to the peer that it already is known to have.
func (I *Inventory) FilterKnown(inv []*wire.InvVect) []*wire.InvVect {
	I.mutex.Lock()
	defer I.mutex.Unlock()

	return I.known.Filter(inv)
}

// FilterRequested takes a list of InvVects, adds them to the list of requested
// data, and returns those which were not already in the list. It is used to
// ensure that data is not requested twice.
func (I *Inventory) FilterRequested(inv []*wire.InvVect) []*wire.InvVect {
	I.mutex.Lock()
	defer I.mutex.Unlock()

	return I.requested.Filter(inv)
}

// NewInventory returns a new Inventory object.
func NewInventory() *Inventory {
	return &Inventory{
		known:     NewMruInventoryMap(maxKnownInventory),
		requested: NewMruInventoryMap(maxKnownInventory),
	}
}
