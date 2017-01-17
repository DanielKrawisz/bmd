// Originally derived from: btcsuite/btcd/blockmanager.go
// Copyright (c) 2013-2015 the btcsuite developers.

// Copyright (c) 2015 Monetas.
// Copyright 2016 Daniel Krawisz.
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package objmgr

import (
	"container/list"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/DanielKrawisz/bmd/database"
	"github.com/DanielKrawisz/bmd/peer"
	"github.com/DanielKrawisz/bmutil/pow"
	"github.com/DanielKrawisz/bmutil/wire"
	"github.com/DanielKrawisz/bmutil/wire/obj"
)

const (
	// unsentObjectPenaltyTimeout is used to treat object request timeouts
	// differently during the initial download from how they are treated under
	// normal operation. Given that there are tens of thousands of messages in
	// the network at any one time, some messages will expire and be deleted by
	// peers before we can get around to downloading them. Therefore, we do not
	// want to consider an expired object request always to be malicious,
	// especially during the initial download. Otherwise, it is possible for
	// an object that has expired to be requested from peer after peer without
	// being received. unsentObjectPenaltyTimeout specifies the amount of time
	// that an object can be known about without being received before it is
	// assumed to have expired.
	unsentObjectPenaltyTimeout = 10 * time.Minute

	// maxQueueForRequestTimeoutPenalty is the minimum number of requests a peer
	// must have before object request timeouts are treated more leniently.
	maxQueueForRequestTimeoutPenalty = 10
)

// newPeerMsg signifies a newly connected peer to the object manager.
type newPeerMsg struct {
	peer *peer.Peer
}

// objectMsg packages a bitmessage object message and the peer it came from
// together so the object manager has access to that information.
type objectMsg struct {
	object *wire.MsgObject
	peer   *peer.Peer
}

// invMsg packages a bitmessage inv message and the peer it came from together
// so the object manager has access to that information.
type invMsg struct {
	inv  *wire.MsgInv
	peer *peer.Peer
}

// donePeerMsg signifies a newly disconnected peer to the object manager.
type donePeerMsg struct {
	peer *peer.Peer
}

// peerRequest represents the peer from which an object was requested along with
// the timestamp.
type peerRequest struct {
	peer *peer.Peer
	// The time the request was made.
	timestamp time.Time
	// The time that the inv was first heard about.
	knownSince time.Time
}

// readyPeerMsg signals that a peer is ready to download more objects.
type readyPeerMsg peer.Peer

type server interface {
	DisconnectPeer(*peer.Peer)
	NotifyObject(wire.ObjectType)
}

// ObjectManager provides a concurrency safe object manager for handling all
// incoming and outgoing.
type ObjectManager struct {
	requestExpire   time.Duration
	cleanupInterval time.Duration

	server   server
	db       database.Db
	started  int32
	shutdown int32

	// The set of peers that are fully connected and the time that
	// an object was last received by them.
	peers map[*peer.Peer]time.Time

	// The set of peers that are working on downloading messages.
	working map[*peer.Peer]struct{}

	// The set of objects which we do not have and which have not been
	// assigned to peers for download.
	unknown map[wire.InvVect]time.Time

	// The set of objects which have been assigned to peers for download.
	requested map[wire.InvVect]*peerRequest

	relayInvList *list.List
	msgChan      chan interface{}
	wg           sync.WaitGroup
	quit         chan struct{}
}

// handleNewPeer deals with new peers that have signalled they may
// be considered as a sync peer (they have already successfully negotiated). It
// is invoked from the syncHandler goroutine.
func (om *ObjectManager) handleNewPeer(p *peer.Peer) {
	// Ignore if in the process of shutting down.
	if atomic.LoadInt32(&om.shutdown) != 0 {
		return
	}

	// Add the peer
	om.peers[p] = time.Time{}
	log.Debug("Peer ", p.Addr().String(), " added to object manager.")
}

// handleDonePeer deals with peers that have signalled they are done. It is
// invoked from the syncHandler goroutine.
func (om *ObjectManager) handleDonePeer(p *peer.Peer) {
	if _, ok := om.peers[p]; !ok {
		return
	}

	// Remove the peer from the list of candidate peers.
	delete(om.peers, p)
	delete(om.working, p)

	reassignInvs := 0
	// Remove requested objects from the global map so that they will be fetched
	// from elsewhere next time we get an inv.
	for invHash, rqst := range om.requested {
		if rqst.peer == p { // peer matches
			delete(om.requested, invHash)

			om.unknown[invHash] = rqst.knownSince

			reassignInvs++
		}
	}

	log.Debug("Peer ", p.Addr().String(), " removed from object manager; ", reassignInvs, " reassigned invs.")
	if reassignInvs > 0 {
		om.assignRequests()
	}
}

// handleObjectMsg handles object messages from all peers.
func (om *ObjectManager) handleObjectMsg(omsg *objectMsg) {
	hash := obj.InventoryHash(omsg.object)
	invVect := (*wire.InvVect)(hash)

	// Unrequested data means disconnect.
	if rqst, exists := om.requested[*invVect]; !exists || rqst.peer != omsg.peer {
		// An attacker could guess which objects are being requested from peers
		// and send them before the actual peer the object was requested from,
		// thus disconnecting legitimate peers. We want to prevent against such
		// an attack by checking that objects came from peers that we requested
		// from.
		// NOTE: PyBitmessage does not do this, so for now if this actually
		// happens it should be considered more likely to be an indication of a
		// bug in bmd itself rather than a malicious peer.
		log.Error(omsg.peer.Addr().String(),
			" Disconnecting because of unrequested object ", hash.String()[:8], " received.")
		om.server.DisconnectPeer(omsg.peer)
		return
	}

	now := time.Now()
	om.peers[omsg.peer] = time.Now()

	delete(om.requested, *invVect)

	// Check PoW.
	if !omsg.object.CheckPow(pow.DefaultData, time.Now()) {
		return // invalid PoW
	}

	log.Debugf(omsg.peer.PrependAddr(fmt.Sprint("Object ", hash.String()[:8],
		" received; ", omsg.peer.Inventory.NumRequests(), " still assigned; ", len(om.requested), " still queued; ",
		len(om.unknown), " unqueued; last receipt = ", now)))

	om.HandleInsert(omsg.object)
}

// HandleInsert inserts a new object into the database and relays it to the peers.
func (om *ObjectManager) HandleInsert(object *wire.MsgObject) uint64 {
	invVect := (*wire.InvVect)(obj.InventoryHash(object))
	// Insert object into database.
	counter, err := om.db.InsertObject(object)
	if err != nil {
		log.Errorf("failed to insert object: %v", err)
		return 0
	}

	// Notify RPC server
	om.server.NotifyObject(object.Header().ObjectType)

	// Advertise objects to other peers.
	om.relayInvList.PushBack(invVect)

	return counter
}

// HaveInventory returns whether or not the inventory represented by the passed
// inventory vector is known. This includes checking all of the various places
// inventory can be.
func (om *ObjectManager) HaveInventory(invVect *wire.InvVect) (bool, error) {
	return om.db.ExistsObject((*wire.ShaHash)(invVect))
}

// handleInvMsg handles inv messages from all peers.
// We examine the inventory advertised by the remote peer and act accordingly.
func (om *ObjectManager) handleInvMsg(imsg *invMsg) {
	requestList := make([]*wire.InvVect, len(imsg.inv.InvList))

	// Request the advertised inventory if we don't already have it.
	numInvs := 0
	for _, iv := range imsg.inv.InvList {
		haveInv, err := om.HaveInventory(iv)
		if err != nil || haveInv {
			continue
		}

		// If the object is already known about, ignore it.
		if _, ok := om.unknown[*iv]; ok {
			continue
		}

		// If this has already been requested, ignore it.
		if _, ok := om.requested[*iv]; ok {
			continue
		}

		// Add it to the list of invs to be requested.
		requestList[numInvs] = iv
		numInvs++
	}

	// Nothing to request, so we are done.
	if numInvs == 0 {
		return
	}
	log.Trace("Inv received with ", len(requestList), " unknown objects.")

	// If the request can fit, we just request it from the peer that told us
	// about it in the first place.
	if numInvs <= peer.MaxPeerRequests-imsg.peer.Inventory.NumRequests() {

		for _, iv := range requestList[:numInvs] {
			now := time.Now()
			om.requested[*iv] = &peerRequest{
				peer:       imsg.peer,
				timestamp:  now,
				knownSince: now,
			}
		}
		log.Trace("All are assigned to peer ", imsg.peer.Addr().String(),
			"; total assigned is ", len(om.requested))

		imsg.peer.PushGetDataMsg(requestList[:numInvs])
		om.working[imsg.peer] = struct{}{}

		// Send the peer more to download if there is more that it could be doing.
		// This can happen if a peer connects and sends an inv message with only
		// one or two new invs while the initial download is going on, so it
		// needs to be given a lot more to download.
		if len(om.unknown) > 0 {
			om.handleReadyPeer(imsg.peer)
		}
		return
	}

	now := time.Now()
	// Add the new invs to the list of unknown invs.
	for _, iv := range requestList[:numInvs] {
		om.unknown[*iv] = now
	}

	// If the number of unknown objects had been zero before, we have to do
	// something to get the download process started again.
	if len(om.unknown) == numInvs {
		om.assignRequests()
	}
}

// assignRequests takes the list of unknown objects and tries to assign some
// to each peer, up to the maximum allowed.
func (om *ObjectManager) assignRequests() {
	if len(om.peers) == 0 {
		return
	}
	log.Trace("Assigning objects to peers for download; number of requested objects: ", len(om.requested))

	for peer := range om.peers {
		if len(om.unknown) == 0 {
			return
		}

		// Assign some unknown objects to each peer.
		om.handleReadyPeer(peer)
	}
}

func (om *ObjectManager) handleReadyPeer(p *peer.Peer) {
	assigned := 0

	// Detect if no peers are working by the end of this function and call
	// cleanUnknown if so.
	defer func() {
		if assigned != 0 {
			om.working[p] = struct{}{}
			return
		}
		delete(om.working, p)
		if len(om.working) == 0 {
			om.cleanUnknown()
		}
	}()

	// If there are no objects to get, we don't need to request anything.
	if len(om.unknown) == 0 {
		return
	}
	log.Trace("Assigning objects to peer ", p.Addr().String())

	// If the object is already downloading too much, return.
	max := peer.MaxPeerRequests - p.Inventory.NumRequests()
	if max <= 0 {
		return
	}

	requestList := make([]*wire.InvVect, max)

	// Since unknown is a map, the elements come out randomly ordered. Therefore
	// (for now at least) object request handling does not work like a queue.
	// We might ask for new invs earlier than old invs, or with any order at all.
	for iv, knownSince := range om.unknown {
		if assigned >= max {
			break
		}

		// Add an inv in the list of unknown objects to the request list
		// if the peer knows about it.
		if !p.Inventory.IsKnown(&iv) {
			continue
		}

		if _, ok := om.requested[iv]; ok {
			log.Error("Object ", (wire.ShaHash)(iv).String()[:8], " is in both requested objects AND unknown objects. Should not happen!")
			delete(om.unknown, iv)
			continue
		}

		// Add to the list of requested objects and remove from the list of unknown objects.
		newiv := iv
		requestList[assigned] = &newiv
		delete(om.unknown, iv)

		now := time.Now()
		om.requested[iv] = &peerRequest{
			peer:       p,
			timestamp:  now,
			knownSince: knownSince,
		}

		assigned++
	}

	// If there was nothing the peer could give us, return.
	if assigned == 0 {
		return
	}

	log.Trace(assigned, " objects assigned to peer ", p.Addr().String(), ". ", len(om.unknown),
		" unassigned objects remaining and ", len(om.requested), " total assigned.")
	p.PushGetDataMsg(requestList[:assigned])
}

// cleanUnknown is called after all the downloading work is done and it clears
// out any remaining invs that are not known by any peers.
func (om *ObjectManager) cleanUnknown() {
	if len(om.unknown) == 0 {
		return
	}

loop:
	for iv := range om.unknown {
		for peer := range om.peers {
			if peer.Inventory.IsKnown(&iv) {
				peer.PushGetDataMsg([]*wire.InvVect{&iv})
				continue loop
			}
		}

		delete(om.unknown, iv)
	}
}

// clearRequests is used to clear out timed out requests periodically. It's used
// to prevent against a scenario in which a malicious peer advertises an inv
// hash but does not send the object. This would effectively 'censor' the object
// from the peer. To avoid this scenario, we need to record the timestamp of a
// request and set it to timeout within the set duration.
func (om *ObjectManager) clearRequests(d time.Duration) {
	now := time.Now()
	// Collect all peers to be disconnected in one map so that we don't try
	// to disconnect a peer more than once. Otherwise a channel could be locked
	// up if many requests from the same peer timed out at once.
	peerDisconnect := make(map[*peer.Peer]struct{})
	for hash, rqst := range om.requested {
		// if request has expired
		if rqst.timestamp.Add(d).Before(now) {
			peerQueueSize := rqst.peer.Inventory.NumRequests()
			lastReceipt := om.peers[rqst.peer]
			// If the peer has a long queue of requested objects, then don't
			// disconnect it unless it has not received SOME object recently enough,
			// or if the request is expired by a much longer time.
			if peerQueueSize < maxQueueForRequestTimeoutPenalty ||
				rqst.timestamp.Add(d*time.Duration(peerQueueSize)).Before(now) ||
				lastReceipt.Add(d).Before(now) {

				// If more than ten minutes (default) has passed since the object
				// manager has first learned about the object, then the object
				// may have just expired. Therefore, drop the request without
				// penalizing the peer.
				if rqst.knownSince.Add(unsentObjectPenaltyTimeout).Before(rqst.timestamp) {
					delete(om.requested, hash)
					continue
				}

				if _, ok := peerDisconnect[rqst.peer]; !ok {
					log.Debug(rqst.peer.PrependAddr(fmt.Sprint(
						" disconnecting due to expired request for object ", (wire.ShaHash)(hash).String()[:8], "; queue size = ",
						peerQueueSize, "; last receipt =", lastReceipt, "; cond 1 =",
						rqst.timestamp.Add(d*time.Duration(peerQueueSize)).Before(now),
						"; cond 2 = ", lastReceipt.Add(d).Before(now))))

					om.server.DisconnectPeer(rqst.peer) // we're done with this malicious peer

					peerDisconnect[rqst.peer] = struct{}{}
				}
			}
		}
	}
}

// handleRelayInvMsg deals with relaying inventory to peers that are not already
// known to have it. It is invoked from the peerHandler goroutine.
func (om *ObjectManager) handleRelayInvMsg(inv []*wire.InvVect) {
	for peer := range om.peers {
		peer.HandleRelayInvMsg(inv)
	}
}

// objectHandler is the main handler for the object manager. It must be run as a
// goroutine. It processes inv messages in a separate goroutine from the peer
// handlers.
func (om *ObjectManager) objectHandler() {
	clearTick := time.NewTicker(om.requestExpire / 2)
	relayInvTick := time.NewTicker(10 * time.Second)
	cleanupTick := time.NewTicker(om.cleanupInterval)

	for {
		select {
		case <-om.quit:
			relayInvTick.Stop()
			clearTick.Stop()
			om.wg.Done()
			return

		case <-clearTick.C:
			// Under normal operation, we expire requests much more quickly
			// than during the initial download.
			om.clearRequests(om.requestExpire)

		// Relay to the other peers all the new invs collected
		// during the past ten seconds.
		case <-relayInvTick.C:
			if om.relayInvList.Len() == 0 {
				continue
			}
			invs := make([]*wire.InvVect, om.relayInvList.Len())
			i := 0
			for e := om.relayInvList.Front(); e != nil; e = e.Next() {
				invs[i] = e.Value.(*wire.InvVect)
				i++
			}
			om.relayInvList = list.New()
			log.Trace("Relaying list of invs of size ", len(invs))
			om.handleRelayInvMsg(invs)

		// Clean all expired inventory from all peers.
		case <-cleanupTick.C:
			expired, err := om.db.RemoveExpiredObjects()
			log.Trace("Cleanup time: ", len(expired), " objects removed.")
			if len(expired) == 0 || err != nil {
				continue
			}
			for _, ex := range expired {

				inv := (*wire.InvVect)(ex)

				for peer := range om.peers {
					peer.Inventory.RemoveKnown(inv)
				}
			}

		case m := <-om.msgChan:
			switch msg := m.(type) {

			case *readyPeerMsg:
				om.handleReadyPeer((*peer.Peer)(msg))

			case *newPeerMsg:
				om.handleNewPeer(msg.peer)

			case *objectMsg:
				om.handleObjectMsg(msg)

			case *invMsg:
				om.handleInvMsg(msg)

			case *donePeerMsg:
				om.handleDonePeer(msg.peer)
			}
		}
	}
}

// NewPeer informs the object manager of a newly active peer.
func (om *ObjectManager) NewPeer(p *peer.Peer) {
	// Ignore if we are shutting down.
	if atomic.LoadInt32(&om.shutdown) != 0 {
		return
	}

	om.msgChan <- &newPeerMsg{peer: p}
}

// ReadyPeer signals that a peer is ready to download more objects.
func (om *ObjectManager) ReadyPeer(p *peer.Peer) {
	// Ignore if we are shutting down.
	if atomic.LoadInt32(&om.shutdown) != 0 {
		return
	}

	om.msgChan <- (*readyPeerMsg)(p)
}

// QueueObject adds the passed object message and peer to the object handling
// queue.
func (om *ObjectManager) QueueObject(object *wire.MsgObject, p *peer.Peer) {
	// Don't accept more objects if we're shutting down.
	if atomic.LoadInt32(&om.shutdown) != 0 {
		return
	}

	om.msgChan <- &objectMsg{object: object, peer: p}
}

// QueueInv adds the passed inv message and peer to the object handling queue.
func (om *ObjectManager) QueueInv(inv *wire.MsgInv, p *peer.Peer) {
	// Ignore if we are shutting down.
	if atomic.LoadInt32(&om.shutdown) != 0 {
		return
	}

	om.msgChan <- &invMsg{inv: inv, peer: p}
}

// DonePeer informs the object manager that a peer has disconnected.
func (om *ObjectManager) DonePeer(p *peer.Peer) {
	// Ignore if we are shutting down.
	if atomic.LoadInt32(&om.shutdown) != 0 {
		return
	}

	om.msgChan <- &donePeerMsg{peer: p}
}

// Start begins the core object handler which processes object messages.
func (om *ObjectManager) Start() {
	// Already started?
	if atomic.AddInt32(&om.started, 1) != 1 {
		return
	}

	log.Info("Object manager started.")

	om.wg.Add(1)
	go om.objectHandler()
}

// Stop gracefully shuts down the object manager by stopping all asynchronous
// handlers and waiting for them to finish.
func (om *ObjectManager) Stop() error {
	if atomic.AddInt32(&om.shutdown, 1) != 1 {
		return nil
	}

	log.Info("Object manager stopped.")

	close(om.quit)
	om.wg.Wait()
	return nil
}

// NewObjectManager returns a new bitmessage object manager. Use Start to begin
// processing objects and inv messages asynchronously.
func NewObjectManager(s server, db database.Db, requestExpire, cleanupInterval time.Duration) *ObjectManager {
	return &ObjectManager{
		requestExpire:   requestExpire,
		cleanupInterval: cleanupInterval,
		server:          s,
		db:              db,
		requested:       make(map[wire.InvVect]*peerRequest),
		unknown:         make(map[wire.InvVect]time.Time),
		msgChan:         make(chan interface{}),
		quit:            make(chan struct{}),
		peers:           make(map[*peer.Peer]time.Time),
		working:         make(map[*peer.Peer]struct{}),
		relayInvList:    list.New(),
	}
}
