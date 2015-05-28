// Originally derived from: btcsuite/btcd/peer.go
// Copyright (c) 2013-2015 Conformal Systems LLC.

// Copyright (c) 2015 Monetas.
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package peer

import (
	"errors"
	"sync"
	"sync/atomic"
	"time"

	"github.com/monetas/bmutil/wire"
)

const (
	// maxProtocolVersion is the max protocol version the peer supports.
	//maxProtocolVersion = 3

	// outputBufferSize is the number of elements the output channels use.
	outputBufferSize = 50

	// invTrickleSize is the maximum amount of inventory to send in a single
	// message when trickling inventory to remote peers.
	maxInvTrickleSize = 1000

	// maxKnownInventory is the maximum number of items to keep in the known
	// inventory cache.
	maxKnownInventory = 1000

	// negotiateTimeoutSeconds is the number of seconds of inactivity before
	// we timeout a peer that hasn't completed the initial version
	// negotiation.
	negotiateTimeoutSeconds = 30

	// idleTimeoutMinutes is the number of minutes of inactivity before
	// we time out a peer. Must be > 5 because that is the time interval
	// at which pongs are sent.
	idleTimeoutMinutes = 6

	// pingTimeoutMinutes is the number of minutes since we last sent a
	// message requiring a reply before we will ping a host.
	pingTimeoutMinutes = 5
)

// Peer is the part of a bitmessage peer that handles the incoming connection
// and manages all other components. This is not yet completed and has not
// been incorporated into the peer that is in use right now.
type Peer struct {
	logic     Logic
	sendQueue SendQueue
	conn      Connection

	started    int32
	starting   int32
	disconnect int32 // only to be used atomically
	resetWg    sync.WaitGroup

	quit chan struct{}
}

// Connected returns whether or not the peer is currently connected.
func (p *Peer) Connected() bool {
	return p.conn.Connected() &&
		atomic.LoadInt32(&p.started) > 0 &&
		atomic.LoadInt32(&p.disconnect) == 0
}

// Disconnect disconnects the peer by closing the connection. It also sets
// a flag so the impending shutdown can be detected.
func (p *Peer) Disconnect() {
	//p.lock.Lock()
	//defer p.lock.Unlock()
	p.resetWg.Wait()

	// Don't stop if we're not running.
	if atomic.LoadInt32(&p.started) == 0 {
		return
	}

	// Already stopping? (shouldn't happen at all anymore.)
	if atomic.AddInt32(&p.disconnect, 1) != 1 {
		return
	}

	if p.conn.Connected() {
		p.conn.Close()
	}
	p.logic.Stop()

	atomic.StoreInt32(&p.started, 0)
	atomic.StoreInt32(&p.disconnect, 0)
}

// Start begins processing input and output messages. It also sends the initial
// version message for outbound connections to start the negotiation process.
func (p *Peer) Start() error {
	if atomic.AddInt32(&p.started, 1) != 1 {
		return nil
	}

	if !p.conn.Connected() {
		err := p.Connect()
		if err != nil {
			atomic.StoreInt32(&p.started, 0)
			return err
		}
	}

	p.sendQueue.Start(p.conn)

	// Start processing input and output.
	go p.inHandler(negotiateTimeoutSeconds, idleTimeoutMinutes)
	return nil
}

// Connect connects the peer object to the remote peer if it is not already
// connected.
func (p *Peer) Connect() error {
	if p.conn.Connected() {
		return nil
	}

	if atomic.LoadInt32(&p.disconnect) != 0 {
		return errors.New("Disconnection in progress.")
	}

	err := p.conn.Connect()
	if err != nil {
		return err
	}

	return nil
}

// inHandler handles all incoming messages for the peer. It must be run as a
// goroutine.
func (p *Peer) inHandler(handshakeTimeoutSeconds, idleTimeoutMinutes uint) {
	// peers must complete the initial version negotiation within a shorter
	// timeframe than a general idle timeout. The timer is then reset below
	// to idleTimeoutMinutes for all future messages.
	idleTimer := time.AfterFunc(time.Duration(handshakeTimeoutSeconds)*time.Second, func() {
		p.Disconnect()
	})

out:
	for atomic.LoadInt32(&p.disconnect) == 0 {
		rmsg, err := p.conn.ReadMessage()
		// Stop the timer now, if we go around again we will reset it.
		idleTimer.Stop()
		if err != nil {
			break out
		}

		// Handle each supported message type.
		markConnected := false
		err = nil
		switch msg := rmsg.(type) {
		case *wire.MsgVersion:
			err = p.logic.HandleVersionMsg(msg)
			markConnected = true

		case *wire.MsgVerAck:
			err = p.logic.HandleVerAckMsg()
			markConnected = true

		case *wire.MsgAddr:
			err = p.logic.HandleAddrMsg(msg)
			markConnected = true

		case *wire.MsgInv:
			err = p.logic.HandleInvMsg(msg)
			markConnected = true

		case *wire.MsgGetData:
			err = p.logic.HandleGetDataMsg(msg)
			//err = p.sendQueue.QueueDataRequest((rmsg.(*wire.MsgGetData)).InvList)
			markConnected = true

		case *wire.MsgGetPubKey, *wire.MsgPubKey, *wire.MsgMsg, *wire.MsgBroadcast, *wire.MsgUnknownObject:
			err = p.logic.HandleObjectMsg(rmsg)
			markConnected = true

		case *wire.MsgPong:
			markConnected = true
		}

		if err != nil {
			break out
		}
		if markConnected == true { // XXX to make it compile
			idleTimer.Reset(time.Duration(idleTimeoutMinutes) * time.Minute)
		}
	}

	idleTimer.Stop()

	// Ensure connection is closed and notify the server that the peer is
	// done.
	p.Disconnect()
}

// NewPeer returns a new Peer object.
func NewPeer(logic Logic, conn Connection, sendQueue SendQueue) *Peer {
	return &Peer{
		logic:     logic,
		sendQueue: sendQueue,
		conn:      conn,
	}
}
