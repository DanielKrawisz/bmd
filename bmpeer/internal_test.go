// Copyright (c) 2015 Monetas.
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package bmpeer

import (
	"net"
	"sync/atomic"
	"time"
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

// TstStart is a special way to start the SendQueue without starting the queue
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
}

// TstStartQueueHandler allows for starting the queue handler with a special
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
func TstStart(sq SendQueue, conn Connection) {
	sq.(*sendQueue).tstStart(conn)
}

// TstStartQueueHandler runs tstStartQueueHandler on a SendQueue object,
// assuming it is an instance of *sendQueue.
func TstStartQueueHandler(sq SendQueue, trickleTicker *time.Ticker) {
	sq.(*sendQueue).tstStartQueueHandler(trickleTicker)
}