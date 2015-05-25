// Originally derived from: btcsuite/btcd/blockmanager.go
// Copyright (c) 2013-2015 the btcsuite developers.

// Copyright (c) 2013-2014 Monetas.
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/monetas/bmd/database"
	_ "github.com/monetas/bmd/database/memdb"
	"github.com/monetas/bmutil/pow"
	"github.com/monetas/bmutil/wire"
)

const (
	// objectManagerQueueSize specifies the size of object manager msgChan.
	objectManagerQueueSize = 50

	// objectRequestTimeout specifies the duration after which a request for an
	// object should time out and the peer be disconnected from. This is
	// supposed to be a rough estimate, not an exact value. Requests are
	// cleaned after every objectRequestTimeout/2 time.
	objectRequestTimeout = time.Minute * 2
)

// newPeerMsg signifies a newly connected peer to the object manager.
type newPeerMsg struct {
	peer *peer
}

// objectMsg packages a bitmessage object message and the peer it came from
// together so the object manager has access to that information.
type objectMsg struct {
	object wire.Message
	peer   *peer
}

// invMsg packages a bitmessage inv message and the peer it came from together
// so the object manager has access to that information.
type invMsg struct {
	inv  *wire.MsgInv
	peer *peer
}

// donePeerMsg signifies a newly disconnected peer to the object manager.
type donePeerMsg struct {
	peer *peer
}

// peerRequest represents the peer from which an object was requested along with
// the timestamp.
type peerRequest struct {
	peer      *peer
	timestamp time.Time
}

// What objects do we know about but don't have?
// Who has them?
// Which have been requested and of whom?
// objectManager provides a concurrency safe object manager for handling all
// incoming objects.
type objectManager struct {
	server           *server
	started          int32
	shutdown         int32
	requestedObjects map[wire.InvVect]*peerRequest
	msgChan          chan interface{}
	wg               sync.WaitGroup
	quit             chan struct{}
}

// handleNewPeerMsg deals with new peers that have signalled they may
// be considered as a sync peer (they have already successfully negotiated). It
// is invoked from the syncHandler goroutine.
func (om *objectManager) handleNewPeerMsg(peers map[*peer]struct{}, p *peer) {
	// Ignore if in the process of shutting down.
	if atomic.LoadInt32(&om.shutdown) != 0 {
		return
	}

	// Add the peer
	peers[p] = struct{}{}
}

// handleDonePeerMsg deals with peers that have signalled they are done. It is
// invoked from the syncHandler goroutine.
func (om *objectManager) handleDonePeerMsg(peers map[*peer]struct{}, p *peer) {
	// Remove the peer from the list of candidate peers.
	delete(peers, p)

	// Remove requested objects from the global map so that they will be fetched
	// from elsewhere next time we get an inv.
	for invHash, objPeer := range om.requestedObjects {
		if objPeer.peer == p { // peer matches
			delete(om.requestedObjects, invHash)
		}
	}
}

// handleObjectMsg handles object messages from all peers.
func (om *objectManager) handleObjectMsg(omsg *objectMsg) {
	invHash := wire.MessageHash(omsg.object)
	invVect := wire.NewInvVect(invHash)

	// Unrequested data means disconnect.
	if p, exists := om.requestedObjects[*invVect]; !exists || p.peer != omsg.peer {
		// An attacker could guess which objects are being requested from peers
		// and send them before the actual peer the object was requested from,
		// thus disconnecting legitimate peers. We want to prevent against such
		// an attack by checking that objects came from peers that we requested
		// from.
		omsg.peer.Disconnect()
		return
	}

	delete(om.requestedObjects, *invVect)

	// check PoW
	obj := wire.EncodeMessage(omsg.object)
	if pow.Check(obj, pow.DefaultExtraBytes, pow.DefaultNonceTrialsPerByte,
		time.Now()) {
		om.server.db.InsertObject(obj)
	}

}

// haveInventory returns whether or not the inventory represented by the passed
// inventory vector is known. This includes checking all of the various places
// inventory can be.
func (om *objectManager) haveInventory(invVect *wire.InvVect) (bool, error) {
	return om.server.db.ExistsObject(&invVect.Hash)
}

// handleInvMsg handles inv messages from all peers.
// We examine the inventory advertised by the remote peer and act accordingly.
func (om *objectManager) handleInvMsg(imsg *invMsg) {
	requestQueue := make([]*wire.InvVect, len(imsg.inv.InvList))

	// Request the advertised inventory if we don't already have it.
	var i int = 0

	for _, iv := range imsg.inv.InvList {
		// Add inv to known inventory.
		imsg.peer.inventory.AddKnown(iv)

		// Request the inventory if we don't already have it.
		haveInv, err := om.haveInventory(iv)
		if err != nil {
			continue
		}

		if !haveInv {
			// Add it to the request queue.
			requestQueue[i] = iv
			i++
			om.requestedObjects[*iv] = &peerRequest{
				peer:      imsg.peer,
				timestamp: time.Now(),
			}
		}
	}

	if i == 0 {
		return
	}

	// get inventory from specified peer
	imsg.peer.PushGetDataMsg(requestQueue[:i])
}

// clearRequests is used to periodically clear out timed out requests. It's used
// to prevent against a scenario in which a malicious peer advertises an inv
// hash but does not send the object. This would effectively 'censor' the object
// from the peer. To avoid this scenario, we need to record the timestamp of a
// request and set it to timeout within the set duration.
func (om *objectManager) clearRequests() {
	for _, p := range om.requestedObjects {
		// if request has expired
		if p.timestamp.Add(objectRequestTimeout).After(time.Now()) {
			p.peer.Disconnect() // we're done with this malicious peer
			om.DonePeer(p.peer)
		}
	}
}

// objectHandler is the main handler for the object manager. It must be run as a
// goroutine. It processes inv messages in a separate goroutine from the peer
// handlers.
func (om *objectManager) objectHandler() {
	candidatePeers := make(map[*peer]struct{})
	clearTick := time.NewTicker(objectRequestTimeout / 2)

	for {
		select {
		case <-clearTick.C:
			om.clearRequests()

		case m := <-om.msgChan:
			switch msg := m.(type) {
			case *newPeerMsg:
				om.handleNewPeerMsg(candidatePeers, msg.peer)

			case *objectMsg:
				om.handleObjectMsg(msg)

			case *invMsg:
				om.handleInvMsg(msg)

			case *donePeerMsg:
				om.handleDonePeerMsg(candidatePeers, msg.peer)
			}

		case <-om.quit:
			clearTick.Stop()
			om.wg.Done()
			return
		}
	}
}

// NewPeer informs the object manager of a newly active peer.
func (om *objectManager) NewPeer(p *peer) {
	// Ignore if we are shutting down.
	if atomic.LoadInt32(&om.shutdown) != 0 {
		return
	}

	om.msgChan <- &newPeerMsg{peer: p}
}

// QueueObject adds the passed object message and peer to the object handling
// queue.
func (om *objectManager) QueueObject(object wire.Message, p *peer) {
	// Don't accept more objects if we're shutting down.
	if atomic.LoadInt32(&om.shutdown) != 0 {
		return
	}

	om.msgChan <- &objectMsg{object: object, peer: p}
}

// QueueInv adds the passed inv message and peer to the object handling queue.
func (om *objectManager) QueueInv(inv *wire.MsgInv, p *peer) {
	// Ignore if we are shutting down.
	if atomic.LoadInt32(&om.shutdown) != 0 {
		return
	}

	om.msgChan <- &invMsg{inv: inv, peer: p}
}

// DonePeer informs the object manager that a peer has disconnected.
func (om *objectManager) DonePeer(p *peer) {
	// Ignore if we are shutting down.
	if atomic.LoadInt32(&om.shutdown) != 0 {
		return
	}

	om.msgChan <- &donePeerMsg{peer: p}
}

// Start begins the core object handler which processes object messages.
func (om *objectManager) Start() {
	// Already started?
	if atomic.AddInt32(&om.started, 1) != 1 {
		return
	}

	om.wg.Add(1)
	go om.objectHandler()
}

// Stop gracefully shuts down the object manager by stopping all asynchronous
// handlers and waiting for them to finish.
func (om *objectManager) Stop() error {
	if atomic.AddInt32(&om.shutdown, 1) != 1 {
		return nil
	}

	close(om.quit)
	om.wg.Wait()
	return nil
}

// newObjectManager returns a new bitmessage object manager. Use Start to begin
// processing objects and inv messages asynchronously.
func newObjectManager(s *server) *objectManager {
	return &objectManager{
		server:           s,
		requestedObjects: make(map[wire.InvVect]*peerRequest),
		msgChan:          make(chan interface{}, objectManagerQueueSize),
		quit:             make(chan struct{}),
	}
}

// warnMultipeDBs shows a warning if multiple database types are detected.
// This is not a situation most users want.  It is handy for development however
// to support multiple side-by-side databases.
func warnMultipeDBs(dbType string) {
	// This is intentionally not using the known db types which depend
	// on the database types compiled into the binary since we want to
	// detect legacy db types as well.
	dbTypes := []string{"leveldb", "sqlite"}
	duplicateDbPaths := make([]string, 0, len(dbTypes)-1)
	for _, dbt := range dbTypes {
		if dbt == dbType {
			continue
		}

		// Store db path as a duplicate db if it exists.
		/*dbPath := blockDbPath(dbType)
		if fileExists(dbPath) {
			duplicateDbPaths = append(duplicateDbPaths, dbPath)
		}*/
	}

	// Warn if there are extra databases.
	if len(duplicateDbPaths) > 0 {
		// TODO
	}
}

// setupDB loads (or creates when needed) the block database taking into
// account the selected database backend.  It also contains additional logic
// such warning the user if there are multiple databases which consume space on
// the file system and ensuring the regression test database is clean when in
// regression test mode.
func setupDB(dbType, dbPath string) (database.Db, error) {
	// The memdb backend does not have a file path associated with it, so
	// handle it uniquely.  We also don't want to worry about the multiple
	// database type warnings when running with the memory database.
	if dbType == "memdb" {
		db, err := database.CreateDB(dbType)
		if err != nil {
			return nil, err
		}
		return db, nil
	}

	warnMultipeDBs(dbType)

	// The database name is based on the database type.
	//dbPath := blockDbPath(dbType)

	db, err := database.OpenDB(dbType, dbPath)
	if err != nil {
		// Return the error if it's not because the database
		// doesn't exist.
		if err != database.ErrDbDoesNotExist {
			return nil, err
		}

		// Create the db if it does not exist.
		/*err = os.MkdirAll(cfg.DataDir, 0700)
		if err != nil {
			return nil, err
		}*/
		db, err = database.CreateDB(dbType, dbPath)
		if err != nil {
			return nil, err
		}
	}

	return db, nil
}
