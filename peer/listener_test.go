// Copyright (c) 2015 Monetas.
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package peer_test

import (
	"errors"
	"net"
	"testing"
	"time"

	"github.com/monetas/bmd/peer"
	"github.com/monetas/bmutil/wire"
)

// mockListener implements the Listener interface and is used to mock
// a listener to test the server and peers.
type MockListener struct {
	incoming     chan net.Conn
	disconnect   chan struct{}
	localAddr    net.Addr
	disconnected bool
}

// Accept waits for and returns the next connection to the listener.
func (ml *MockListener) Accept() (net.Conn, error) {
	if ml.disconnected {
		return nil, errors.New("Listner disconnected.")
	}
	select {
	case <-ml.disconnect:
		ml.disconnected = true
		return nil, errors.New("Listener disconnected.")
	case m := <-ml.incoming:
		return m, nil
	}
}

// Close closes the listener.
// Any blocked Accept operations will be unblocked and return errors.
func (ml *MockListener) Close() error {
	ml.disconnect <- struct{}{}
	return nil
}

// Addr returns the listener's network address.
func (ml *MockListener) Addr() net.Addr {
	return ml.localAddr
}

// startNewMockListener is a function that can be swapped with the listen var for testing purposes.
func startNewMockListener(localAddr net.Addr, incoming chan net.Conn, disconnect chan struct{}) func(service, addr string) (net.Listener, error) {
	stopped := false

	return func(service, addr string) (net.Listener, error) {
		if stopped {
			return nil, errors.New("Failed.")
		}
		stopped = true // It only works once.
		return &MockListener{
			incoming:   incoming,
			disconnect: disconnect,
			localAddr:  localAddr,
		}, nil
	}
}

func TestConnectionAndListener(t *testing.T) {
	remoteAddr := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 8333}
	localAddr := &net.TCPAddr{IP: net.ParseIP("192.168.0.1"), Port: 8333}

	incoming := make(chan net.Conn)

	listener := peer.TstNewListener(&MockListener{
		incoming:   incoming,
		disconnect: make(chan struct{}),
		localAddr:  localAddr,
	})

	if listener.Addr() != localAddr {
		t.Errorf("Wrong local addr returned. Expected %s, got %s.", localAddr, listener.Addr())
	}

	mockConn := NewMockConn(localAddr, remoteAddr, false)

	message1 := wire.NewMsgUnknownObject(617, time.Now(), wire.ObjectType(5), 12, 1, []byte{87, 99, 23, 56})
	message2 := wire.NewMsgUnknownObject(616, time.Now(), wire.ObjectType(5), 12, 1, []byte{22, 55, 89, 107})

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

		hashtest := wire.MessageHash(msg)
		hashexp := wire.MessageHash(message1)

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

		_, err = mc.ReadMessage()
		if err == nil {
			t.Errorf("Error expected because the connection should be closed.")
		}

		testStep <- struct{}{}

	}()

	// Send a mock connection to test Accept()
	incoming <- mockConn

	<-testStep

	// Close the listener.
	listener.Close()

	// Write a message to the connection.
	mockConn.MockWrite(message1)

	// Write a message to the connection.
	msg := mockConn.MockRead()

	hashtest := wire.MessageHash(msg)
	hashexp := wire.MessageHash(message2)

	if !hashexp.IsEqual(hashtest) {
		t.Errorf("Wrong message sent.")
	}

	<-testStep
}

func TestListen(t *testing.T) {
	localAddr := &net.TCPAddr{IP: net.ParseIP("192.168.0.1"), Port: 8333}

	l := peer.TstSwapListen(startNewMockListener(localAddr, make(chan net.Conn), make(chan struct{})))
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
