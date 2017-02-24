// Copyright (c) 2015 Monetas.
// Copyright 2016 Daniel Krawisz.
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package peer_test

import (
	"errors"
	"math/rand"
	"net"
	"sync"
	"time"

	"github.com/DanielKrawisz/bmutil/hash"
	"github.com/DanielKrawisz/bmutil/wire"
)

// randomShaHash returns a ShaHash with a random string of bytes in it.
func randomShaHash() *hash.Sha {
	b := make([]byte, 32)
	for i := 0; i < 32; i++ {
		b[i] = byte(rand.Intn(256))
	}
	hash, _ := hash.NewSha(b)
	return hash
}

// MockConnection implements the peer.Connection interface and is used to test
// send without connecting to the real internet.
type MockConnection struct {
	closed      bool // Whether the connection has been closed.
	connected   bool // Whether the connection is connected.
	failure     bool // When this is true, sending or receiving messages returns an error.
	connectFail bool // When this is true, the connection cannot connect.
	done        chan struct{}
	failChan    chan struct{}
	reply       chan wire.Message
	send        chan wire.Message
	addr        net.Addr
	mutex       sync.RWMutex
	failmtx     sync.Mutex
}

func (mock *MockConnection) WriteMessage(msg wire.Message) error {
	if mock.closed {
		return errors.New("Connection closed.")
	}

	if mock.failure {
		return errors.New("Mock Connection set to fail.")
	}

	mock.reply <- msg

	return nil
}

// MockRead allows for tests as to whether a message has been sent or not.
// It accepts an extra channel that can be read from if no message has been
// sent. Normally, Read blocks until a message is received.
func (mock *MockConnection) MockRead(reset chan struct{}) wire.Message {
	if mock.closed {
		return nil
	}

	select {
	case <-mock.done:
		return nil
	case message := <-mock.reply:
		return message
	case <-reset:
		return nil
	}
}

func (mock *MockConnection) ReadMessage() (wire.Message, error) {
	mock.mutex.RLock()
	fail := mock.failure
	mock.mutex.RUnlock()

	if fail {
		return nil, errors.New("Mock Connection set to fail.")
	}

	mock.failmtx.Lock()
	defer mock.failmtx.Unlock()

	select {
	case msg := <-mock.send:
		return msg, nil
	case <-mock.failChan:
		return nil, errors.New("Mock Connection set to fail.")
	}
}

func (mock *MockConnection) MockWrite(msg wire.Message) {
	mock.send <- msg

}

func (mock *MockConnection) BytesWritten() uint64 {
	return 0
}

func (mock *MockConnection) BytesRead() uint64 {
	return 0
}

func (mock *MockConnection) LastWrite() time.Time {
	return time.Time{}
}

func (mock *MockConnection) LastRead() time.Time {
	return time.Time{}
}

func (mock *MockConnection) RemoteAddr() net.Addr {
	return mock.addr
}

func (mock *MockConnection) LocalAddr() net.Addr {
	return nil
}

func (mock *MockConnection) Close() {
	if mock.closed {
		return
	}
	mock.closed = true
	mock.mutex.Lock()
	mock.connected = false
	mock.mutex.Unlock()
	close(mock.done)

	// Drain any incoming messages.
close:
	for {
		select {
		case <-mock.reply:
		default:
			break close
		}
	}
}

func (mock *MockConnection) Connected() bool {
	mock.mutex.RLock()
	defer mock.mutex.RUnlock()

	return mock.connected
}

func (mock *MockConnection) Connect() error {
	if mock.connectFail {
		return errors.New("Connection set to fail.")
	}
	mock.mutex.Lock()
	mock.connected = true
	mock.mutex.Unlock()
	return nil
}

func (mock *MockConnection) SetFailure(b bool) {
	mock.mutex.Lock()
	mock.failure = b
	mock.mutex.Unlock()

	if b == true {
		// Drain any messages being sent now so that WriteMessage will
		// immediately return an error.
		select {
		case <-mock.done:
		default:
		}

		// Close the failure channel to ensure any messages being read
		// will return an error.
		close(mock.failChan)

	} else {
		mock.failmtx.Lock()
		mock.failChan = make(chan struct{})
		mock.failmtx.Unlock()
	}
}

func NewMockConnection(addr net.Addr, connected bool, fails bool) *MockConnection {
	return &MockConnection{
		done:        make(chan struct{}),
		reply:       make(chan wire.Message),
		send:        make(chan wire.Message),
		failChan:    make(chan struct{}),
		connected:   connected,
		connectFail: fails,
		addr:        addr,
	}
}
