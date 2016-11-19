// Originally derived from: btcsuite/btcd/peer.go
// Copyright (c) 2013-2015 Conformal Systems LLC.

// Copyright (c) 2015 Monetas.
// Copyright 2016 Daniel Krawisz.
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package peer

import (
	"container/list"
	"errors"
	"fmt"
	"math/rand"
	"sync"
	"sync/atomic"
	"time"

	"github.com/DanielKrawisz/bmd/database"
	"github.com/DanielKrawisz/bmutil/wire"
	"github.com/DanielKrawisz/bmutil/wire/obj"
)

const (
	// sendQueueSize is the size of data and message queues. The number should be
	// small if possible, and ideally we would use an unbuffered channel eventually.
	sendQueueSize = 5
)

// Send handles everything that is to be sent to the remote peer eventually.
// It takes messages and sends them over
// the outgoing connection, inventory vectors corresponding to objects that
// the peer has requested, and inventory vectors representing objects that
// we have, which will be periodically sent to the peer in a series of inv
// messages.
type Send interface {
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

// send is an instance of Send.
type send struct {
	trickleTime time.Duration

	// Sends messages to the outHandler function.
	msgQueue chan wire.Message
	// Sends messages from the dataRequestHandler to the outHandler function.
	dataQueue chan wire.Message
	// sends new inv data to be queued up and trickled to the other peer eventually.
	outputInvChan chan []*wire.InvVect
	//
	requestQueue chan []*wire.InvVect
	// used to turn off the send
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

// QueueMessage queues up a message to be sent to the remote peer as soon as
// the connection is ready.
func (send *send) QueueMessage(msg wire.Message) error {
	if !send.Running() {
		return errors.New("Not running.")
	}

	send.msgQueue <- msg
	return nil
}

// QueueDataRequest queues a list of invs whose corresponding objects
// are to be sent to the remote peer eventually. send will ensure that
// not too many objects are loaded in memory at a time.
func (send *send) QueueDataRequest(inv []*wire.InvVect) error {
	if !send.Running() {
		return errors.New("Not running.")
	}

	send.requestQueue <- inv
	return nil
}

// QueueInventory queues new inventory to be trickled periodically
// to the remote peer at randomized time intervals.
func (send *send) QueueInventory(inv []*wire.InvVect) error {
	if !send.Running() {
		return errors.New("Not running.")
	}

	send.outputInvChan <- inv
	return nil
}

// Start starts the send with a new connection.
func (send *send) Start(conn Connection) {
	// Wait in case the object is resetting.
	send.resetWg.Wait()

	// Already starting?
	if atomic.AddInt32(&send.started, 1) != 1 {
		return
	}

	// When all three go routines are done, the wait group will unlock.
	send.doneWg.Add(3)
	send.conn = conn

	// Start the three main go routines.
	go send.outHandler()
	go send.queueHandler(time.NewTimer(send.trickleTime))
	go send.dataRequestHandler()

	atomic.StoreInt32(&send.stopped, 0)
}

// Running returns whether the send queue is running.
func (send *send) Running() bool {
	return atomic.LoadInt32(&send.started) > 0 &&
		atomic.LoadInt32(&send.stopped) == 0
}

// Stop stops the send struct.
func (send *send) Stop() {
	// Already stopping?
	if atomic.AddInt32(&send.stopped, 1) != 1 {
		return
	}

	send.resetWg.Add(1)

	close(send.quit)

	// Wait for the other goroutines to finish.
	send.doneWg.Wait()

	// Drain channels to ensure that no other go routine remains locked.
clean1:
	for {
		select {
		case <-send.requestQueue:
		case <-send.outputInvChan:
		default:
			break clean1
		}
	}
clean2:
	for {
		select {
		case <-send.msgQueue:
		case <-send.dataQueue:
		default:
			break clean2
		}
	}

	atomic.StoreInt32(&send.started, 0)
	send.quit = make(chan struct{})
	send.resetWg.Done()
}

// dataRequestHandler handles getData requests without using up too much
// memory. Must be run as a go routine.
func (send *send) dataRequestHandler() {
out:
	for {
		select {
		case <-send.quit:
			break out
		case invList := <-send.requestQueue:
			for _, inv := range invList {
				msg := retrieveObject(send.db, inv)
				if msg != nil {
					send.dataQueue <- msg.MsgObject()
				}
			}
		}
	}

	send.doneWg.Done()
}

// queueHandler handles the queueing of outgoing data for the peer. This runs
// as a muxer for various sources of input so we can ensure that objectmanager
// and the server goroutine both will not block on us sending a message.
// We then pass the data on to outHandler to be actually written.
func (send *send) queueHandler(trickle *time.Timer) {
	defer trickle.Stop()

	randTime := rand.New(rand.NewSource(10))
	invSendQueue := list.New()

out:
	for {
		select {

		case <-send.quit:
			break out

		case iv := <-send.outputInvChan:
			invSendQueue.PushBack(iv)

		case <-trickle.C:
			// Don't send anything if we're disconnecting or there
			// is no queued inventory.
			// version is known if send queue has any entries.
			if !send.Running() || invSendQueue.Len() == 0 {
				continue
			}

			log.Debug(send.PrependAddr("Trickling an inv."))

			// Create and send as many inv messages as needed to
			// drain the inventory send queue.
			invMsg := wire.NewMsgInv()
			for e := invSendQueue.Front(); e != nil; e = invSendQueue.Front() {
				ivl := send.inventory.FilterKnown(invSendQueue.Remove(e).([]*wire.InvVect))

				for _, iv := range ivl {
					invMsg.AddInvVect(iv)
					if len(invMsg.InvList) >= maxInvTrickleSize {
						send.msgQueue <- invMsg
						invMsg = wire.NewMsgInv()
					}
				}

			}
			if len(invMsg.InvList) > 0 {
				send.msgQueue <- invMsg
			}

			// Randomize the number of seconds from 20 to 60 seconds.
			trickle.Reset(time.Second * (20 + time.Duration(randTime.Int63n(40))))
		}
	}

	// Drain any wait channels before we go away so we don't leave something
	// waiting for us.
	for e := invSendQueue.Front(); e != nil; e = invSendQueue.Front() {
		invSendQueue.Remove(e)
	}

	send.doneWg.Done()
}

// outHandler handles all outgoing messages for the peer. It must be run as a
// goroutine. It uses a buffered channel to serialize output messages while
// allowing the sender to continue running asynchronously.
func (send *send) outHandler() {
	defer send.doneWg.Done()

out:
	for {
		var msg wire.Message

		select {
		case <-send.quit:
			break out
		// The regular message queue is drained first so that don't clog up the
		// connection with tons of object messages.
		case msg = <-send.msgQueue:
		case msg = <-send.dataQueue:
		}

		if msg != nil {
			err := send.conn.WriteMessage(msg)
			if err != nil {
				// Run in a separate go routine because otherwise outHandler
				// would never quit.
				go func() {
					send.Stop()
				}()
				return
			}
		}
	}
}

// A helper function for logging that adds the ip address to the start of the
// string to be logged.
func (send *send) PrependAddr(str string) string {
	return fmt.Sprintf("%s : %s", send.conn.RemoteAddr().String(), str)
}

// NewSend returns a new sendQueue object.
func NewSend(inventory *Inventory, db database.Db) Send {
	return &send{
		trickleTime:   time.Second * 10,
		msgQueue:      make(chan wire.Message, sendQueueSize),
		dataQueue:     make(chan wire.Message, sendQueueSize),
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
func retrieveObject(db database.Db, inv *wire.InvVect) obj.Object {
	obj, err := db.FetchObjectByHash(&inv.Hash)
	if err != nil {
		return nil
	}
	return obj
}
