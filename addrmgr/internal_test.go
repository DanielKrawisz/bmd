// Originally derived from: btcsuite/btcd/addrmgr/internal_test.go
// Copyright (c) 2013-2015 Conformal Systems LLC.

// Copyright (c) 2015 Monetas.
// Copyright 2016 Daniel Krawisz.
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package addrmgr

import (
	"time"

	"github.com/DanielKrawisz/bmutil/wire"
)

func TstKnownAddressIsBad(ka *KnownAddress) bool {
	return ka.isBad()
}

func TstKnownAddressChance(ka *KnownAddress) float64 {
	return ka.chance()
}

func TstNewKnownAddress(na *wire.NetAddress, attempts int,
	lastattempt, lastsuccess time.Time, tried bool, refs uint32) *KnownAddress {
	return &KnownAddress{na: na, attempts: attempts, lastattempt: lastattempt,
		lastsuccess: lastsuccess, tried: tried, refs: refs}
}

func TstGetReachabilityFrom(localAddr, remoteAddr *wire.NetAddress) int {
	return getReachabilityFrom(localAddr, remoteAddr)
}

func TstGetAddrMax() int {
	return getAddrMax
}

func TstGetAddrPercent() int {
	return getAddrPercent
}

func (a *AddrManager) TstGetTriedBucket(netAddr *wire.NetAddress) int {
	return a.getTriedBucket(netAddr)
}

// AddAddressesSkipChecks adds a bunch of addresses without enforcing
// limits for bucket sizes or following the ordinary rules for assigning
// buckets. Used for testing purposes.
func (a *AddrManager) TstAddAddressesSkipChecks(addrs []*wire.NetAddress, srcAddr *wire.NetAddress) {
	for _, netAddr := range addrs {
		addr := NetAddressKey(netAddr)

		netAddrCopy := *netAddr
		ka := &KnownAddress{na: &netAddrCopy, srcAddr: srcAddr}
		a.addrIndex[addr] = ka
		a.nNew++

		// Put in bucket.
		bucket := a.getNewBucket(netAddr, srcAddr)

		ka.refs++
		a.addrNew[bucket][addr] = ka
	}
}

// TstAddKnownAddress adds a KnownAddress object in a specific bucket for
// testing purposes.
func (a *AddrManager) TstAddKnownAddress(ka *KnownAddress, bucket int) {
	addr := NetAddressKey(ka.na)
	a.addrIndex[addr] = ka
	a.nNew++

	ka.refs++
	a.addrNew[bucket][addr] = ka
}

// GoodNoChecks Sets a new address as good without performing the usual
// checks on it or updating its timestamp and puts it in a specific bucket.
// this function exists purely to set up certain unusual situations for
// testing purposes.
func (a *AddrManager) TstGoodNoChecks(addr *wire.NetAddress, bucket int) {
	ka := a.find(addr)
	if ka == nil {
		return
	}

	if ka.tried {
		return
	}

	// Remove from new buckets.
	addrKey := NetAddressKey(addr)
	oldBucket := -1
	for i := range a.addrNew {
		// we check for existance so we can record the first one
		if _, ok := a.addrNew[i][addrKey]; ok {
			delete(a.addrNew[i], addrKey)
			ka.refs--
			if oldBucket == -1 {
				oldBucket = i
			}
		}
	}
	a.nNew--

	ka.tried = true
	a.addrTried[bucket].PushBack(ka)
	a.nTried++
	return
}

// TstAddAddressNoBucket is used to create an illegal situation in which an
// address has been registered to an address manager but is not put in a new
// bucket. Used to test Good.
func (a *AddrManager) TstAddAddressNoBucket(netAddr *wire.NetAddress, srcAddr *wire.NetAddress) {
	addr := NetAddressKey(netAddr)

	netAddrCopy := *netAddr
	ka := &KnownAddress{na: &netAddrCopy, srcAddr: srcAddr}
	a.addrIndex[addr] = ka
	a.nNew++
}

// TstGetBucketAndTried gets the bucket that an address is in and whether it has
// been tried or not. Used to test Good.
func (a *AddrManager) TstGetBucketAndTried(ka *KnownAddress) (bucket []int, tried bool) {
	bucket = make([]int, newBucketCount)

	x := 0
	tried = ka.tried

	if tried {
		for i, triedBucket := range a.addrTried {
			for e := triedBucket.Front(); e != nil; e = e.Next() {
				if ka == e.Value.(*KnownAddress) {
					bucket[x] = i
					x++
					break
				}
			}
		}
	} else {
		for i, newBucket := range a.addrNew {
			// we check for existance so we can record the first one
			for _, val := range newBucket {
				if val == ka {
					bucket[x] = i
					x++
					break
				}
			}
		}
	}
	bucket = bucket[:x]
	return
}
