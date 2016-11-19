// Copyright (c) 2015 Monetas.
// Copyright 2016 Daniel Krawisz.
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package peer_test

import (
	"net"
	"testing"
	"time"

	"github.com/DanielKrawisz/bmd/peer"
	"github.com/DanielKrawisz/bmutil/wire"
	"github.com/DanielKrawisz/mocknet"
)

func TestConnectionAndListener(t *testing.T) {
	remoteAddr := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 8333}
	localAddr := &net.TCPAddr{IP: net.ParseIP("192.168.0.1"), Port: 8333}

	mockListener := mocknet.NewListener(localAddr, false)

	listener := peer.TstNewListener(mockListener)

	if listener.Addr() != localAddr {
		t.Errorf("Wrong local addr returned. Expected %s, got %s.", localAddr, listener.Addr())
	}

	mockConn := mocknet.NewConn(localAddr, remoteAddr, false)

	message1 := wire.NewMsgObject(wire.NewObjectHeader(617, time.Now(), wire.ObjectType(5), 12, 1), []byte{87, 99, 23, 56})
	message2 := wire.NewMsgObject(wire.NewObjectHeader(616, time.Now(), wire.ObjectType(5), 12, 1), []byte{22, 55, 89, 107})

	testStep := make(chan struct{})
	go func() {
		mc, err := listener.Accept()
		if err != nil {
			t.Errorf("Unexpected error returned: %s", err)
		}

		testStep <- struct{}{}

		mc2, err := listener.Accept()
		if err == nil {
			t.Errorf("Error expected.")
		}
		if mc2 != nil {
			t.Errorf("Connection somehow returned?")
		}

		if mc.RemoteAddr() != remoteAddr {
			t.Errorf("Wrong local addr.")
		}

		msg, err := mc.ReadMessage()
		if err != nil {
			t.Fatalf("Error returned reading message.")
		}
		msgObj, _ := msg.(*wire.MsgObject)
		hashtest := msgObj.InventoryHash()

		hashexp := message1.InventoryHash()

		if !hashexp.IsEqual(hashtest) {
			t.Errorf("Wrong mock connection somehow returned?")
		}

		mc.WriteMessage(message2)

		if mc.BytesWritten() != 50 {
			t.Errorf("Wrong value for bytes written. Expected 50, got %d.", mc.BytesWritten())
		}

		if mc.BytesRead() != 50 {
			t.Errorf("Wrong value for bytes read. Expected 50, got %d.", mc.BytesRead())
		}

		now := time.Now().Unix()

		if mc.LastWrite().Unix()>>3 != now>>3 {
			t.Errorf("Wrong time: got %d expected %d", mc.LastWrite().Unix(), now)
		}

		if mc.LastRead().Unix()>>3 != now>>3 {
			t.Errorf("Wrong time: got %d expected %d", mc.LastRead().Unix(), now)
		}

		mc.Close()

		msg, err = mc.ReadMessage()
		if msg != nil && err != nil {
			t.Errorf("Connection should be closed and no message read.")
		}

		testStep <- struct{}{}

	}()

	// Send a mock connection to test Accept()
	mockListener.MockOpenConnection(mockConn)

	<-testStep

	// Close the listener.
	listener.Close()

	// Write a message to the connection.
	MockWrite(mockConn, message1)

	// Write a message to the connection.
	msg := MockRead(mockConn)

	msgObj, _ := msg.(*wire.MsgObject)
	hashtest := msgObj.InventoryHash()

	hashexp := message2.InventoryHash()

	if !hashexp.IsEqual(hashtest) {
		t.Errorf("Wrong message sent.")
	}

	<-testStep
}

func TestListen(t *testing.T) {
	localAddr := &net.TCPAddr{IP: net.ParseIP("192.168.0.1"), Port: 8333}
	builder := mocknet.NewListenerBuilder(localAddr, 1)

	l := peer.TstSwapListen(builder.Listen)
	defer peer.TstSwapListen(l)

	listen, err := peer.Listen("tcp4", "8445")
	if listen == nil {
		t.Errorf("No connection returned.")
	}
	if err != nil {
		t.Errorf("Error %s returned.", err)
	}

	listen, err = peer.Listen("tcp4", "8445")
	if listen != nil {
		t.Errorf("Connection returned when it should have failed.")
	}
	if err == nil {
		t.Errorf("Error expected dialing failed connection.")
	}
}
