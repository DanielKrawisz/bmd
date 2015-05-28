// Copyright (c) 2015 Monetas.
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package peer_test

import (
	"bytes"
	"errors"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/monetas/bmd/peer"
	"github.com/monetas/bmutil/wire"
)

// MockConn implements the net.Conn interface and is used to test the
// connection object without connecting to the real internet.
type MockConn struct {
	sendChan    chan []byte
	receiveChan chan []byte
	done        chan struct{}
	outMessage  []byte // A message ready to be sent back to the real peer.
	outPlace    int    //How much of the outMessage that has been sent.
	localAddr   net.Addr
	remoteAddr  net.Addr
	closed      bool
}

func (mc *MockConn) Close() error {
	mc.closed = true
	close(mc.done)
	return nil
}

// LocalAddr returns the localAddr field of the fake connection and satisfies
// the net.Conn interface.
func (mc *MockConn) LocalAddr() net.Addr {
	return mc.localAddr
}

// RemoteAddr returns the remoteAddr field of the fake connection and satisfies
// the net.Conn interface.
func (mc *MockConn) RemoteAddr() net.Addr {
	return mc.remoteAddr
}

func (mc *MockConn) SetDeadline(t time.Time) error {
	return nil
}

func (mc *MockConn) SetReadDeadline(t time.Time) error {
	return nil
}

func (mc *MockConn) SetWriteDeadline(t time.Time) error {
	return nil
}

// Read allows the real peer to read message from the mock connection.
func (mc *MockConn) Read(b []byte) (int, error) {
	if mc.closed {
		return 0, errors.New("Connection closed.")
	}

	i := 0
	for i < len(b) {
		if mc.outMessage == nil {
			select {
			case <-mc.done:
				return 0, errors.New("Connection closed.")
			case mc.outMessage = <-mc.receiveChan:
			}
			mc.outPlace = 0
		}

		for mc.outPlace < len(mc.outMessage) && i < len(b) {
			b[i] = mc.outMessage[mc.outPlace]
			mc.outPlace++
			i++
		}

		if mc.outPlace == len(mc.outMessage) {
			mc.outMessage = nil
		}
	}

	return i, nil
}

// Write allows the peer to write to the mock connection.
func (mc *MockConn) Write(b []byte) (n int, err error) {
	if mc.closed {
		return 0, errors.New("Connection closed.")
	}

	data := make([]byte, len(b))
	copy(data, b)
	mc.sendChan <- data
	return len(b), nil
}

// MockRead is for the mock peer to read a message that has previously
// been written with Write.
func (mc *MockConn) MockRead() wire.Message {
	if mc.closed {
		return nil
	}

	var header, body []byte
	select {
	case <-mc.done:
		return nil
	case header = <-mc.sendChan:
	}

	select {
	case <-mc.done:
		return nil
	case body = <-mc.sendChan:
	}

	b := make([]byte, len(header)+len(body))

	i := 0
	for j := 0; j < len(header); j++ {
		b[i] = header[j]
		i++
	}
	for j := 0; j < len(body); j++ {
		b[i] = body[j]
		i++
	}

	msg, _, _ := wire.ReadMessage(bytes.NewReader(b), wire.MainNet)
	return msg
}

// MockWrite is for the mock peer to write a message that will be read by
// the real peer.
func (mc *MockConn) MockWrite(msg wire.Message) {
	buf := &bytes.Buffer{}
	wire.WriteMessage(buf, msg, wire.MainNet)
	mc.receiveChan <- buf.Bytes()
}

// NewMockConn creates a new mockConn
func NewMockConn(localAddr, remoteAddr net.Addr, closed bool) *MockConn {
	return &MockConn{
		localAddr:   localAddr,
		remoteAddr:  remoteAddr,
		sendChan:    make(chan []byte),
		receiveChan: make(chan []byte),
		done:        make(chan struct{}),
		closed:      closed,
	}
}

// dialNewMockConn is a function that can be swapped with the dial var for
// testing purposes.
func dialNewMockConn(localAddr net.Addr, fail bool, closed bool) func(service, addr string) (net.Conn, error) {
	return func(service, addr string) (net.Conn, error) {
		if fail {
			return nil, errors.New("Connection failed.")
		}
		host, portstr, _ := net.SplitHostPort(addr)
		port, _ := strconv.ParseInt(portstr, 10, 0)
		return NewMockConn(localAddr, &net.TCPAddr{IP: net.ParseIP(host), Port: int(port)}, closed), nil
	}
}

func TestDial(t *testing.T) {
	remoteAddr := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 8333}
	localAddr := &net.TCPAddr{IP: net.ParseIP("192.168.0.1"), Port: 8333}

	d := peer.TstSwapDial(dialNewMockConn(localAddr, false, false))
	defer peer.TstSwapDial(d)

	conn := peer.NewConnection(remoteAddr)
	if conn == nil {
		t.Errorf("No connection returned.")
	}
	err := conn.Connect()
	if err != nil {
		t.Errorf("Error %s returned.", err)
	}
	err = conn.Connect()
	if err == nil {
		t.Errorf("Expected error for trying to connect twice.")
	}

	peer.TstSwapDial(dialNewMockConn(localAddr, true, false))
	conn = peer.NewConnection(remoteAddr)
	err = conn.Connect()
	if err == nil {
		t.Errorf("Error expected dialing failed connection.")
	}
}

// This tests error cases that are returned for connections which have not
// dialed in to the remote peer yet.
func TestUnconnectedConnection(t *testing.T) {
	remoteAddr := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 8333}
	localAddr := &net.TCPAddr{IP: net.ParseIP("192.168.0.1"), Port: 8333}

	d := peer.TstSwapDial(dialNewMockConn(localAddr, false, false))
	defer peer.TstSwapDial(d)

	conn := peer.NewConnection(remoteAddr)
	if conn.RemoteAddr() != nil {
		t.Error("There should be no remote addr before connecting.")
	}

	msg, err := conn.ReadMessage()
	if err == nil || msg != nil {
		t.Error("It should be impossible to read messages before connection is established.")
	}

	err = conn.WriteMessage(&wire.MsgVerAck{})
	if err == nil {
		t.Error("It should be impossible to write messages before connection is established.")
	}
}

func TestInterruptedConnection(t *testing.T) {
	remoteAddr := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 8333}
	localAddr := &net.TCPAddr{IP: net.ParseIP("192.168.0.1"), Port: 8333}

	d := peer.TstSwapDial(dialNewMockConn(localAddr, false, true))
	defer peer.TstSwapDial(d)

	conn := peer.NewConnection(remoteAddr)
	conn.Connect()
	msg, err := conn.ReadMessage()
	if err == nil || msg != nil {
		t.Error("Connection should be closed.")
	}

	conn = peer.NewConnection(remoteAddr)
	conn.Connect()
	err = conn.WriteMessage(&wire.MsgVerAck{})
	if err == nil {
		t.Error("Connection should be closed.")
	}
}
