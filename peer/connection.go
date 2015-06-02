// Copyright (c) 2015 Monetas.
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package peer

import (
	"errors"
	"net"
	"sync"
	"time"

	"github.com/DanielKrawisz/maxrate"
	"github.com/monetas/bmutil/wire"
)

// Connection is a bitmessage connection that abstracts the underlying tcp
// connection away. The user of the Connection only uses bitmessage
// wire.Message objects instead of the underlying byte stream.
// This is written as an interface so that it can easily be swapped out for a
// mock object for testing purposes.
type Connection interface {
	WriteMessage(wire.Message) error
	ReadMessage() (wire.Message, error)
	BytesWritten() uint64
	BytesRead() uint64
	LastWrite() time.Time
	LastRead() time.Time
	RemoteAddr() net.Addr
	Connected() bool
	Connect() error
	Close()
}

// connection implements the Connection interface and connects to a
// real outside bitmessage node over the internet.
type connection struct {
	conn          net.Conn
	addr          net.Addr
	sentMtx       sync.Mutex
	bytesSent     uint64
	receivedMtx   sync.Mutex
	bytesReceived uint64
	lastRead      time.Time
	lastWrite     time.Time
	timeConnected time.Time
	idleTimeout   time.Duration
	idleTimer     *time.Timer
	maxUp         *maxrate.MaxRate
	maxDown       *maxrate.MaxRate
}

// WriteMessage sends a bitmessage p2p message along the tcp connection.
func (pc *connection) WriteMessage(msg wire.Message) error {
	// conn will be nill if the connection disconnected.
	if pc.conn == nil {
		return errors.New("No connection established")
	}

	// Write the message to the peer.
	n, err := wire.WriteMessageN(pc.conn, msg, wire.MainNet)

	pc.receivedMtx.Lock()
	pc.bytesSent += uint64(n)
	pc.lastWrite = time.Now()
	pc.receivedMtx.Unlock()

	if err != nil {
		pc.conn = nil
		return err
	}

	pc.maxUp.Transfer(float64(n))

	return nil
}

// ReadMessage reads a bitmessage p2p message from the tcp connection.
func (pc *connection) ReadMessage() (wire.Message, error) {
	// conn will be nill if the connection disconnected.
	if pc.conn == nil {
		return nil, errors.New("No connection established")
	}

	n, msg, _, err := wire.ReadMessageN(pc.conn, wire.MainNet)

	pc.receivedMtx.Lock()
	pc.bytesReceived += uint64(n)
	pc.lastRead = time.Now()
	pc.receivedMtx.Unlock()

	if err != nil {
		pc.conn = nil
		return nil, err
	}

	pc.maxDown.Transfer(float64(n))

	pc.idleTimer.Reset(pc.idleTimeout)

	return msg, nil
}

// BytesWritten returns the total number of bytes written to this connection.
func (pc *connection) BytesWritten() uint64 {
	pc.sentMtx.Lock()
	n := pc.bytesSent
	pc.sentMtx.Unlock()
	return n
}

// BytesRead returns the total number of bytes read by this connection.
func (pc *connection) BytesRead() uint64 {
	pc.receivedMtx.Lock()
	n := pc.bytesReceived
	pc.receivedMtx.Unlock()
	return n
}

// LastWrite returns the last time that a message was written.
func (pc *connection) LastWrite() time.Time {
	t := pc.lastWrite
	return t
}

// LastRead returns the last time that a message was read.
func (pc *connection) LastRead() time.Time {
	t := pc.lastRead
	return t
}

// RemoteAddr returns the address of the remote peer.
func (pc *connection) RemoteAddr() net.Addr {
	if pc.conn == nil {
		return nil
	}
	return pc.conn.RemoteAddr()
}

// Close disconnects the peer and stops running the connection.
func (pc *connection) Close() {
	if pc.conn != nil {
		pc.conn.Close()
		pc.conn = nil
	}

	pc.idleTimer.Stop()
}

// Connected returns whether the connection is connected to a remote peer.
func (pc *connection) Connected() bool {
	return pc.conn != nil
}

var dial = net.Dial

// Connect starts running the connection and connects to the remote peer.
func (pc *connection) Connect() error {
	if pc.Connected() {
		return errors.New("already connected")
	}

	conn, err := dial("tcp", pc.addr.String())
	if err != nil {
		return err
	}

	pc.idleTimer.Reset(pc.idleTimeout)

	pc.timeConnected = time.Now()
	pc.conn = conn
	return nil
}

// NewConnection creates a new *connection.
func NewConnection(addr net.Addr, maxDown, maxUp int64) Connection {
	pc := &connection{
		addr:        addr,
		idleTimeout: time.Minute * pingTimeoutMinutes,
		maxDown:     maxrate.New(float64(maxDown), 1),
		maxUp:       maxrate.New(float64(maxUp), 1),
	}

	pc.idleTimer = time.AfterFunc(pc.idleTimeout, func() {
		pc.WriteMessage(&wire.MsgPong{})
	})

	pc.idleTimer.Stop()

	return pc
}
