// Originally derived from: btcsuite/btcd/peer.go
// Copyright (c) 2013-2015 Conformal Systems LLC.

// Copyright (c) 2015 Monetas.
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package peer

import (
	"container/list"
	"errors"
	"sync"
	"sync/atomic"
	"time"

	"github.com/monetas/bmd/database"
	"github.com/monetas/bmutil/wire"
)

const (
	// queueSize is the size of data and message queues. TODO arbitrarily set as
	// 20.
	queueSize = 20
)

// SendQueue represents the part of a bitmessage peer that handles data
// that is to be sent to the peer. It takes messages and sends them over
// the outgoing connection, inventory vectors corresponding to objects that
// the peer has requested, and inventory vectors representing objects that
// we have, which will be periodically sent to the peer in a series of inv
// messages.
type SendQueue interface {
	// QueueMessage queues a message to be sent to the peer.
	QueueMessage(wire.Message) error

	// QueueDataRequest
	QueueDataRequest([]*wire.InvVect) error

	// QueueInventory adds the passed inventory to the inventory send queue which
	// might not be sent right away, rather it is trickled to the peer in batches.
	// Inventory that the peer is already known to have is ignored. It is safe for
	// concurrent access.
	QueueInventory([]*wire.InvVect) error

	Start(conn Connection)
	Running() bool
	Stop()
}

// sendQueue is an instance of SendQueue.
type sendQueue struct {
	trickleTime time.Duration

	// Sends messages to the outHandler function.
	msgQueue chan wire.Message
	// Sends messages from the dataRequestHandler to the outHandler function.
	dataQueue chan wire.Message
	// sends new inv data to be queued up and trickled to the other peer eventually.
	outputInvChan chan []*wire.InvVect
	//
	requestQueue chan []*wire.InvVect
	// used to turn off the sendQueue
	quit chan struct{}

	resetWg sync.WaitGroup
	doneWg  sync.WaitGroup

	// An internet connection to another bitmessage node.
	conn Connection
	// The inventory containing the known objects.
	inventory *Inventory
	// The database of objects.
	db database.Db

	// The state of the send queue.
	started int32
	stopped int32
}

// QueueMessage
func (sq *sendQueue) QueueMessage(msg wire.Message) error {
	if !sq.Running() {
		return errors.New("Not running.")
	}

	select {
	case sq.msgQueue <- msg:
		return nil
	default:
		return errors.New("Message queue full.")
	}
}

// QueueDataRequest
func (sq *sendQueue) QueueDataRequest(inv []*wire.InvVect) error {
	if !sq.Running() {
		return errors.New("Not running.")
	}

	select {
	case sq.requestQueue <- inv:
		return nil
	default:
		return errors.New("Data request queue full.")
	}
}

// QueueInventory queues new inventory to be trickled periodically
// to the remote peer
func (sq *sendQueue) QueueInventory(inv []*wire.InvVect) error {
	if !sq.Running() {
		return errors.New("Not running.")
	}

	select {
	case sq.outputInvChan <- inv:
		return nil
	default:
		return errors.New("Inventory queue full.")
	}
}

// Start starts the sendQueue with a new connection.
func (sq *sendQueue) Start(conn Connection) {
	// Wait in case the object is resetting.
	sq.resetWg.Wait()

	// Already starting?
	if atomic.AddInt32(&sq.started, 1) != 1 {
		return
	}

	// When all three go routines are done, the wait group will unlock.
	sq.doneWg.Add(3)
	sq.conn = conn

	// Start the three main go routines.
	go sq.outHandler()
	go sq.queueHandler(time.NewTicker(sq.trickleTime))
	go sq.dataRequestHandler()

	atomic.StoreInt32(&sq.stopped, 0)
}

// Running returns whether the send queue is running.
func (sq *sendQueue) Running() bool {
	return atomic.LoadInt32(&sq.started) > 0 && atomic.LoadInt32(&sq.stopped) == 0
}

// Stop stops the sendQueue.
func (sq *sendQueue) Stop() {
	// Already stopping?
	if atomic.AddInt32(&sq.stopped, 1) != 1 {
		return
	}

	sq.resetWg.Add(1)

	close(sq.quit)

	// Wait for the other goroutines to finish.
	sq.doneWg.Wait()

	// Drain channels to ensure that no other go routine remains locked.
clean1:
	for {
		select {
		case <-sq.requestQueue:
		case <-sq.outputInvChan:
		default:
			break clean1
		}
	}
clean2:
	for {
		select {
		case <-sq.msgQueue:
		case <-sq.dataQueue:
		default:
			break clean2
		}
	}

	atomic.StoreInt32(&sq.started, 0)
	sq.quit = make(chan struct{})
	sq.resetWg.Done()
}

// dataRequestHandler handles getData requests without using up too much
// memory. Must be run as a go routine.
func (sq *sendQueue) dataRequestHandler() {
out:
	for {
		select {
		case <-sq.quit:
			break out
		case invList := <-sq.requestQueue:
			for _, inv := range invList {
				msg := retrieveObject(sq.db, inv)
				if msg != nil {
					sq.dataQueue <- msg
				}
			}
		}
	}

	sq.doneWg.Done()
}

// queueHandler handles the queueing of outgoing data for the peer. This runs
// as a muxer for various sources of input so we can ensure that objectmanager
// and the server goroutine both will not block on us sending a message.
// We then pass the data on to outHandler to be actually written.
func (sq *sendQueue) queueHandler(trickleTicker *time.Ticker) {
	invSendQueue := list.New()
	defer trickleTicker.Stop()

out:
	for {
		select {

		case <-sq.quit:
			break out

		case iv := <-sq.outputInvChan:
			invSendQueue.PushBack(iv)

		case <-trickleTicker.C:
			// Don't send anything if we're disconnecting or there
			// is no queued inventory.
			// version is known if send queue has any entries.
			if !sq.Running() || invSendQueue.Len() == 0 {
				continue
			}

			// Create and send as many inv messages as needed to
			// drain the inventory send queue.
			invMsg := wire.NewMsgInv()
			for e := invSendQueue.Front(); e != nil; e = invSendQueue.Front() {
				ivl := sq.inventory.FilterKnown(invSendQueue.Remove(e).([]*wire.InvVect))

				for _, iv := range ivl {
					invMsg.AddInvVect(iv)
					if len(invMsg.InvList) >= maxInvTrickleSize {
						sq.msgQueue <- invMsg
						invMsg = wire.NewMsgInv()
					}
				}

			}
			if len(invMsg.InvList) > 0 {
				sq.msgQueue <- invMsg
			}
		}
	}

	// Drain any wait channels before we go away so we don't leave something
	// waiting for us.
	for e := invSendQueue.Front(); e != nil; e = invSendQueue.Front() {
		invSendQueue.Remove(e)
	}

	sq.doneWg.Done()
}

// outHandler handles all outgoing messages for the peer. It must be run as a
// goroutine. It uses a buffered channel to serialize output messages while
// allowing the sender to continue running asynchronously.
func (sq *sendQueue) outHandler() {
out:
	for {
		var msg wire.Message

		select {
		case <-sq.quit:
			break out
		// The regular message queue is drained first so that don't clog up the
		// connection with tons of object messages.
		case msg = <-sq.msgQueue:
		case msg = <-sq.dataQueue:
		}

		if msg != nil {
			err := sq.conn.WriteMessage(msg)
			if err != nil {
				sq.doneWg.Done()
				// Run in a separate go routine because otherwise outHandler
				// would never quit.
				go func() {
					sq.Stop()
				}()
				return
			}
		}
	}

	sq.doneWg.Done()
}

// NewSendQueue returns a new sendQueue object.
func NewSendQueue(inventory *Inventory, db database.Db) SendQueue {
	return &sendQueue{
		trickleTime:   time.Second * 10,
		msgQueue:      make(chan wire.Message, queueSize),
		dataQueue:     make(chan wire.Message, queueSize),
		outputInvChan: make(chan []*wire.InvVect, outputBufferSize),
		requestQueue:  make(chan []*wire.InvVect, outputBufferSize),
		quit:          make(chan struct{}),
		inventory:     inventory,
		db:            db,
		stopped:       1,
	}
}

// retrieveObject retrieves an object from the database and decodes it.
// TODO we actually end up decoding the message and then encoding it again when
// it is sent. That is not necessary.
func retrieveObject(db database.Db, inv *wire.InvVect) wire.Message {
	obj, err := db.FetchObjectByHash(&inv.Hash)
	if err != nil {
		return nil
	}

	msg, err := wire.DecodeMsgObject(obj)
	if err != nil {
		return nil
	}

	return msg
}
