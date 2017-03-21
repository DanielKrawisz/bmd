// Copyright (c) 2015 Monetas.
// Copyright 2016 Daniel Krawisz.
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package peer

import (
	"sync"
	"sync/atomic"

	"github.com/DanielKrawisz/bmutil/wire"
)

// Inventory is the part of a peer that manages object hashes and remembers
// which are known to the peer and which have been requested from it. It is safe
// for concurrent access.
type Inventory struct {
	known     *MruInventoryMap
	requested int32
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

// RemoveKnown adds the passed inventory to the cache of known inventory for the
// peer.
func (I *Inventory) RemoveKnown(invVect *wire.InvVect) {
	I.mutex.Lock()
	defer I.mutex.Unlock()

	I.known.Delete(invVect)
}

// AddRequest marks that a certain number of objects have been requested.
func (I *Inventory) AddRequest(i uint32) {
	atomic.AddInt32(&I.requested, int32(i))
}

// DropRequest marks that a certain number of objects have been requested.
func (I *Inventory) DropRequest() {
	atomic.AddInt32(&I.requested, -1)
}

// NumRequests is the number of object download requests that have been made.
func (I *Inventory) NumRequests() uint32 {
	return uint32(atomic.LoadInt32(&I.requested))
}

// FilterKnown takes a list of InvVects, adds them to the list of known
// inventory, and returns those which were not already in the list. It is used
// to ensure that data is not sent to the peer that it already is known to have.
func (I *Inventory) FilterKnown(inv []*wire.InvVect) []*wire.InvVect {
	I.mutex.Lock()
	defer I.mutex.Unlock()

	return I.known.Filter(inv)
}

// NewInventory returns a new Inventory object.
func NewInventory() *Inventory {
	return &Inventory{
		known: NewMruInventoryMap(maxKnownInventory),
	}
}
