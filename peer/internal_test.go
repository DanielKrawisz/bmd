// Copyright (c) 2015 Monetas.
// Copyright 2016 Daniel Krawisz.
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package peer

import (
	"errors"
	"net"
	"sync/atomic"
	"time"

	"github.com/DanielKrawisz/bmd/database"
	"github.com/DanielKrawisz/bmutil/wire"
	"github.com/DanielKrawisz/bmutil/wire/obj"
	"github.com/DanielKrawisz/maxrate"
)

// TstNewConnection is used to create a new connection with a mock conn instead
// of a real one for testing purposes.
func TstNewConnection(conn net.Conn) Connection {
	return &connection{
		conn:    conn,
		maxDown: maxrate.New(100000000, 20),
		maxUp:   maxrate.New(100000000, 20),
	}
}

// TstNewListneter returns a new listener with a user defined net.Listener, which
// can be a mock object for testing purposes.
func TstNewListener(netListen net.Listener) Listener {
	return &listener{
		netListener: netListen,
	}
}

// SwapDialDial swaps out the dialConnection function to mock it for testing
// purposes. It returns the original function so that it can be swapped back in
// at the end of the test.
func TstSwapDial(f func(string, string) (net.Conn, error)) func(string, string) (net.Conn, error) {
	g := dial
	SetDialer(f)
	return g
}

// SwapDialDial swaps out the listen function to mock it for testing
// purposes. It returns the original function so that it can be swapped back in
// at the end of the test.
func TstSwapListen(f func(string, string) (net.Listener, error)) func(string, string) (net.Listener, error) {
	g := listen
	listen = f
	return g
}

// TstRetrieveObject exposes retrieveObject for testing purposes.
func TstRetrieveObject(db *database.Db, inv *wire.InvVect) (obj.Object, error) {
	obj := retrieveObject(db, inv)
	if obj == nil {
		return nil, errors.New("retrieve object came out nil")
	}
	return obj, nil
}

// tstStart is a special way to start the Send without starting the queue
// handler for testing purposes.
func (sq *send) tstStart(conn Connection) {
	// Wait in case the object is resetting.
	sq.resetWg.Wait()

	// Already starting?
	if atomic.AddInt32(&sq.started, 1) != 1 {
		return
	}

	// When all three go routines are done, the wait group will unlock.
	// Here we only add 2, since we only start 2 go routines.
	sq.doneWg.Add(2)
	sq.conn = conn

	// Start the three main go routines.
	go sq.outHandler()
	go sq.dataRequestHandler()

	atomic.StoreInt32(&sq.stopped, 0)
}

// tstStartWait waits for a message from the given channel in the middle of
// the start function. The purpose is to engineer a situation in which Start
// is called while the send is already started.
func (sq *send) tstStartWait(conn Connection, waitChan chan struct{}, startChan chan struct{}) {
	// Wait in case the object is resetting.
	sq.resetWg.Wait()

	// Already starting?
	if atomic.AddInt32(&sq.started, 1) != 1 {
		return
	}

	// Signal that the function is in the middle of running.
	startChan <- struct{}{}
	// Wait for for a signal to continue.
	<-waitChan

	// When all three go routines are done, the wait group will unlock.
	sq.doneWg.Add(3)
	sq.conn = conn

	// Start the three main go routines.
	go sq.outHandler()
	go sq.queueHandler(time.NewTimer(sq.trickleTime))
	go sq.dataRequestHandler()

	atomic.StoreInt32(&sq.stopped, 0)
}

// tstStopWait is the same as tstStartWait for stopping.
func (sq *send) tstStopWait(waitChan chan struct{}, startChan chan struct{}) {
	// Already stopping?
	if atomic.AddInt32(&sq.stopped, 1) != 1 {
		return
	}

	sq.resetWg.Add(1)

	// Signal that the function is in the middle of running.
	startChan <- struct{}{}
	// Wait for for a signal to continue.
	<-waitChan

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
	atomic.StoreInt32(&sq.stopped, 0)
	sq.quit = make(chan struct{})
	sq.resetWg.Done()
}

// tstStartHandler allows for starting the queue handler with a special
// timer for testing purposes.
func (sq *send) tstStartQueueHandler(trickle *time.Timer) {
	if !sq.Running() {
		return
	}

	sq.doneWg.Add(1)
	go sq.queueHandler(trickle)
}

// TstSendStart runs tstStart on a Send object, assuming it is an instance
// of *send.
func TstSendStart(sq Send, conn Connection) {
	sq.(*send).tstStart(conn)
}

// TstSendStartQueueHandler runs tstStartQueueHandler on a Send object,
// assuming it is an instance of *send.
func TstSendStartQueueHandler(sq Send, trickle *time.Timer) {
	sq.(*send).tstStartQueueHandler(trickle)
}

// TstStartWait runs tstStartWait on a Send object assuming it is
// an instance of *send
func TstSendStartWait(sq Send, conn Connection, waitChan chan struct{}, startChan chan struct{}) {
	sq.(*send).tstStartWait(conn, waitChan, startChan)
}

// TstStopWait runs tstStopWait on a Send object assuming it is an
// instance of *send
func TstSendStopWait(sq Send, waitChan chan struct{}, startChan chan struct{}) {
	sq.(*send).tstStopWait(waitChan, startChan)
}

func (p *Peer) TstDisconnectWait(waitChan chan struct{}, startChan chan struct{}) {
	// Don't stop if we're not running.
	if atomic.LoadInt32(&p.started) == 0 {
		return
	}

	// did we win the race?
	if atomic.AddInt32(&p.disconnect, 1) != 1 {
		return
	}

	p.send.Stop()

	if p.conn.Connected() {
		p.conn.Close()
	}

	// Signal that the function is in the middle of running.
	startChan <- struct{}{}
	// Wait for for a signal to continue.
	<-waitChan

	atomic.StoreInt32(&p.disconnect, 0)

	// Only tell object manager we are gone if we ever told it we existed.
	if p.HandshakeComplete() {
		p.server.ObjectManager().DonePeer(p)
	}

	p.server.DonePeer(p)
}

// TstStart allows us to start the peer with different timout settings so as
// to test the connection timeout.
func (p *Peer) TstStart(negotiateTimeoutSeconds, idleTimeoutMinutes uint) error {

	// Already started?
	if atomic.AddInt32(&p.started, 1) != 1 {
		return nil
	}

	if !p.conn.Connected() {
		err := p.connect()
		if err != nil {
			atomic.StoreInt32(&p.started, 0)
			return err
		}
	}

	p.send.Start(p.conn)

	// Start processing input and output.
	go p.inHandler(negotiateTimeoutSeconds, idleTimeoutMinutes)

	if !p.Inbound {
		p.PushVersionMsg()
	}
	return nil
}
