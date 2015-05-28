// Copyright (c) 2015 Monetas.
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package peer

import (
	"net"
	"sync/atomic"
	"time"

	"github.com/monetas/bmd/database"
	"github.com/monetas/bmutil/wire"
)

// TstNewConnection is used to create a new connection with a mock conn instead
// of a real one for testing purposes.
func TstNewConnection(conn net.Conn) Connection {
	return &connection{
		conn: conn,
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
	dial = f
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
func TstRetrieveObject(db database.Db, inv *wire.InvVect) wire.Message {
	return retrieveObject(db, inv)
}

// tstStart is a special way to start the SendQueue without starting the queue
// handler for testing purposes.
func (sq *sendQueue) tstStart(conn Connection) {
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
// is called while the sendQueue is already started.
func (sq *sendQueue) tstStartWait(conn Connection, waitChan chan struct{}, startChan chan struct{}) {
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
	go sq.queueHandler(time.NewTicker(sq.trickleTime))
	go sq.dataRequestHandler()

	atomic.StoreInt32(&sq.stopped, 0)
}

// tstStopWait is the same as tstStartWait for stopping.
func (sq *sendQueue) tstStopWait(waitChan chan struct{}, startChan chan struct{}) {
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

// tstStartQueueHandler allows for starting the queue handler with a special
// ticker for testing purposes.
func (sq *sendQueue) tstStartQueueHandler(trickleTicker *time.Ticker) {
	if !sq.Running() {
		return
	}

	sq.doneWg.Add(1)
	go sq.queueHandler(trickleTicker)
}

// TstStart runs tstStart on a SendQueue object, assuming it is an instance
// of *sendQueue.
func TstSendQueueStart(sq SendQueue, conn Connection) {
	sq.(*sendQueue).tstStart(conn)
}

// TstStartQueueHandler runs tstStartQueueHandler on a SendQueue object,
// assuming it is an instance of *sendQueue.
func TstSendQueueStartQueueHandler(sq SendQueue, trickleTicker *time.Ticker) {
	sq.(*sendQueue).tstStartQueueHandler(trickleTicker)
}

// TstStartWait runs tstStartWait on a SendQueue object assuming it is
// an instance of *sendQueue
func TstSendQueueStartWait(sq SendQueue, conn Connection, waitChan chan struct{}, startChan chan struct{}) {
	sq.(*sendQueue).tstStartWait(conn, waitChan, startChan)
}

// TstStopWait runs tstStopWait on a SendQueue object assuming it is an
// instance of *sendQueue
func TstSendQueueStopWait(sq SendQueue, waitChan chan struct{}, startChan chan struct{}) {
	sq.(*sendQueue).tstStopWait(waitChan, startChan)
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

	p.sendQueue.Stop()
	close(p.quit)

	if p.conn.Connected() {
		p.conn.Close()
	}
	p.logic.Stop()

	// Signal that the function is in the middle of running.
	startChan <- struct{}{}
	// Wait for for a signal to continue.
	<-waitChan

	atomic.StoreInt32(&p.started, 0)
	atomic.StoreInt32(&p.disconnect, 0)
}

//
func (p *Peer) TstStart(negotiateTimeoutSeconds, idleTimeoutMinutes uint) error {
	p.lock.Lock()
	defer p.lock.Unlock()

	// Already started?
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

	p.quit = make(chan struct{})

	p.sendQueue.Start(p.conn)
	p.logic.Start()

	// Start processing input and output.
	go p.inHandler(negotiateTimeoutSeconds, idleTimeoutMinutes)
	return nil
}
