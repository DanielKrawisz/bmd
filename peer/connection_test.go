// Copyright (c) 2015 Monetas.
// Copyright 2016 Daniel Krawisz.
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package peer_test

import (
	"bytes"
	"net"
	"testing"

	"github.com/DanielKrawisz/bmd/peer"
	"github.com/DanielKrawisz/bmutil/wire"
	"github.com/DanielKrawisz/mocknet"
)

// MockWrite is for the mock peer to write a message that will be read by
// the real peer.
func MockWrite(mc *mocknet.Conn, msg wire.Message) {
	buf := &bytes.Buffer{}
	wire.WriteMessage(buf, msg, wire.MainNet)
	mc.MockWrite(buf.Bytes())
}

// MockRead is for the mock peer to read a message that has previously
// been written with Write.
func MockRead(mc *mocknet.Conn) wire.Message {
	header := mc.MockRead()
	if header == nil {
		return nil
	}

	body := mc.MockRead()
	if body == nil {
		return nil
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

const (
	maxUpload   = 10000000
	maxDownload = 10000000
)

func TestDial(t *testing.T) {
	remoteAddr := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 8333}
	localAddr := &net.TCPAddr{IP: net.ParseIP("192.168.0.1"), Port: 8333}

	d := peer.TstSwapDial(mocknet.Dialer(localAddr, false, false))
	defer peer.TstSwapDial(d)

	conn := peer.NewConnection(remoteAddr, maxUpload, maxDownload)
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

	peer.TstSwapDial(mocknet.Dialer(localAddr, true, false))
	conn = peer.NewConnection(remoteAddr, maxUpload, maxDownload)
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

	d := peer.TstSwapDial(mocknet.Dialer(localAddr, false, false))
	defer peer.TstSwapDial(d)

	conn := peer.NewConnection(remoteAddr, maxUpload, maxDownload)
	if conn.RemoteAddr() == nil {
		t.Error("The remote adder should not be nil.")
	}

	_, err := conn.ReadMessage()
	if err == nil {
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

	d := peer.TstSwapDial(mocknet.Dialer(localAddr, false, true))
	defer peer.TstSwapDial(d)

	conn := peer.NewConnection(remoteAddr, maxUpload, maxDownload)
	conn.Connect()
	msg, err := conn.ReadMessage()
	if err == nil || msg != nil {
		t.Error("Connection should be closed.")
	}

	conn = peer.NewConnection(remoteAddr, maxUpload, maxDownload)
	conn.Connect()
	err = conn.WriteMessage(&wire.MsgVerAck{})
	if err == nil {
		t.Error("Connection should be closed.")
	}
}
