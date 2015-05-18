// Copyright (c) 2015 Monetas.
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package bmpeer_test

import (
	"bytes"
	"errors"
	"math/rand"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/monetas/bmd/bmpeer"
	"github.com/monetas/bmutil"
	"github.com/monetas/bmutil/identity"
	"github.com/monetas/bmutil/wire"
)

// MockConnection implements the Connection interface and is used to test
// sendQueue without connecting to the real internet.
type MockConnection struct {
	closed  bool
	failure bool // When this is true, sending messages returns an error.
	done    chan struct{}
	reply   chan wire.Message
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
	return nil, errors.New("This mock connection does not send messages.")
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
	return nil
}

func (mock *MockConnection) LocalAddr() net.Addr {
	return nil
}

func (mock *MockConnection) Close() error {
	mock.closed = true
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

	return nil
}

func (mock *MockConnection) SetFailure(b bool) {
	mock.failure = b

	if b == true {
		// Drain any messages being sent now so that WriteMessage will
		// immediately return an error.
		select {
		case <-mock.done:
		default:
		}
	}
}

func NewMockConnection() *MockConnection {
	return &MockConnection{
		done:  make(chan struct{}),
		reply: make(chan wire.Message),
	}
}

// MockDb is a very simple database that does not implement most of the functionality
// which is normally required.
type MockDb struct {
	get map[wire.ShaHash][]byte
	mtx sync.Mutex
}

func (db *MockDb) Close() error {
	return nil
}

func (db *MockDb) ExistsObject(hash *wire.ShaHash) (bool, error) {
	_, ok := db.get[*hash]
	return ok, nil
}

func (db *MockDb) FetchObjectByHash(hash *wire.ShaHash) ([]byte, error) {
	db.mtx.Lock()
	z, ok := db.get[*hash]
	db.mtx.Unlock()
	if !ok {
		return nil, errors.New("hash not found")
	}
	return z, nil
}

func (db *MockDb) FetchObjectByCounter(wire.ObjectType, uint64) ([]byte, error) {
	return nil, nil
}

func (db *MockDb) FetchObjectsFromCounter(objType wire.ObjectType, counter uint64,
	count uint64) ([][]byte, uint64, error) {
	return nil, 0, nil
}

func (db *MockDb) FetchIdentityByAddress(*bmutil.Address) (*identity.Public, error) {
	return nil, nil
}

func (db *MockDb) FilterObjects(func(hash *wire.ShaHash,
	obj []byte) bool) (map[wire.ShaHash][]byte, error) {
	return nil, nil
}

func (db *MockDb) FetchRandomInvHashes(count uint64,
	filter func(*wire.ShaHash, []byte) bool) ([]wire.ShaHash, error) {
	return nil, nil
}

func (db *MockDb) GetCounter(wire.ObjectType) (uint64, error) {
	return 0, nil
}

func (db *MockDb) InsertObject(b []byte) (uint64, error) {
	hash, _ := wire.NewShaHash(bmutil.CalcInventoryHash(b))
	db.get[*hash] = b
	return 0, nil
}

func (db *MockDb) RemoveObject(*wire.ShaHash) error {
	return nil
}

func (db *MockDb) RemoveObjectByCounter(wire.ObjectType, uint64) error {
	return nil
}

func (db *MockDb) RemoveExpiredObjects() error {
	return nil
}

func (db *MockDb) RemovePubKey(*wire.ShaHash) error {
	return nil
}

func (db *MockDb) RollbackClose() (err error) {
	err = nil
	return
}

func (db *MockDb) Sync() (err error) {
	err = nil
	return
}

func (db *MockDb) Lock() {
	db.mtx.Lock()
}

func (db *MockDb) Unlock() {
	db.mtx.Unlock()
}

func NewMockDb() *MockDb {
	return &MockDb{
		get: make(map[wire.ShaHash][]byte),
	}
}

func TestStartStop(t *testing.T) {
	conn := NewMockConnection()
	db := NewMockDb()

	queue := bmpeer.NewSendQueue(bmpeer.NewInventory(db))

	if queue.Running() {
		t.Errorf("queue should not be running yet. ")
	}
	queue.Stop()
	if queue.Running() {
		t.Errorf("queue should still not be running. ")
	}

	queue.Start(conn)
	if queue.Running() {
		t.Errorf("queue should be running. ")
	}
	queue.Stop()
	if queue.Running() {
		t.Errorf("queue should not be running anymore. ")
	}

	// TODO For full coverage, should try to start and stop the queue at the
	// same time, but I don't know know to create this situation.
}

func TestSendMessage(t *testing.T) {
	conn := NewMockConnection()
	db := NewMockDb()
	var err error

	queue := bmpeer.NewSendQueue(bmpeer.NewInventory(db))

	message := &wire.MsgVerAck{}

	// Try sending a message to a sendQueue that is not running yet.
	// This should return an error.
	err = queue.QueueMessage(message)
	if err == nil {
		t.Errorf("No error returned when queue is not running.")
	}

	// Now try to send the message after the queue is started.
	queue.Start(conn)
	err = queue.QueueMessage(message)
	if err != nil {
		t.Errorf("Error returned: %s", err)
	}

	sentMsg := conn.MockRead(nil)
	if sentMsg != message {
		t.Errorf("Different message received somehow.")
	}

	// Now test that the sendQueue shuts down if the connection fails.
	conn.SetFailure(true)
	message = &wire.MsgVerAck{}
	err = queue.QueueMessage(message)
	if err != nil {
		t.Errorf("Error returned at inappropriate time: %s", err)
	}

	// Give the queue some time to shut down completely.
	time.Sleep(time.Millisecond * 50)

	if queue.Running() {
		t.Errorf("queue should not be running after this. ")
	}
	conn.SetFailure(false)

	queue.Start(conn)

	// Engineer a situation in which the message channel gets filled up
	// and must be cleaned out.
	i := 0
	for {
		err = queue.QueueMessage(&wire.MsgVerAck{})
		if i == 20 {
			break
		}
		if err != nil {
			t.Error("Should not have got an error yet.")
		}
		i++
	}
	if err == nil {
		t.Error("Should have got a queue full error.")
	}

	reset := make(chan struct{})
	go func() {
		for {
			if conn.MockRead(reset) == nil {
				break
			}
		}
	}()

	queue.Stop()
	time.Sleep(time.Millisecond * 50)
	//Start the queue again to make sure it shuts down properly before the test ends.
	close(reset)
}

func TestRequestData(t *testing.T) {
	conn := NewMockConnection()
	db := NewMockDb()
	var err error

	queue := bmpeer.NewSendQueue(bmpeer.NewInventory(db))

	message := wire.NewMsgUnknownObject(345, time.Now(), wire.ObjectType(4), 1, 1, []byte{77, 82, 53, 48, 96, 1})

	data := wire.EncodeMessage(message)
	db.InsertObject(data)
	hashes := []*wire.InvVect{&wire.InvVect{Hash: *wire.MessageHash(message)}}

	// The queue isn't running yet, so this should return an error.
	err = queue.QueueDataRequest(hashes)
	if err == nil {
		t.Errorf("No error returned when queue is not running.")
	}

	queue.Start(conn)

	err = queue.QueueDataRequest(hashes)
	if err != nil {
		t.Errorf("Error returned: %s", err)
	}

	sentData := wire.EncodeMessage(conn.MockRead(nil))

	if !bytes.Equal(data, sentData) {
		t.Errorf("Different message received somehow. ")
	}

	// Try to send something that isn't in the database at all and something
	// that isn't a valid message. These don't return errors, but they are here
	// for code coverage. In order to ensure that the queue behaves correctly,
	// we send a regular message after and receive it.
	badData := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 0}
	badHash, _ := wire.NewShaHash(bmutil.CalcInventoryHash(badData))
	badHashes := []*wire.InvVect{&wire.InvVect{Hash: *badHash}}
	queue.QueueDataRequest(badHashes)

	queue.QueueDataRequest(hashes)
	// Force the sendQueue to manage all queued requests.
	sentData = wire.EncodeMessage(conn.MockRead(nil))
	if !bytes.Equal(data, sentData) {
		t.Errorf("Wrong message returned.")
	}

	db.InsertObject(badData)
	queue.QueueDataRequest(badHashes)

	queue.QueueDataRequest(hashes)
	sentData = wire.EncodeMessage(conn.MockRead(nil))
	if !bytes.Equal(data, sentData) {
		t.Errorf("Wrong message returned.")
	}

	// Engineer a situation in which the data request channel gets filled up
	// and must be cleaned out.
	db.Lock()

	i := 0
	for {
		objMsg := wire.NewMsgUnknownObject(666, time.Now(), wire.ObjectType(4), 1, 1, []byte{0, 0, 0, byte(i)})

		data := wire.EncodeMessage(objMsg)
		db.InsertObject(data)
		hashes := []*wire.InvVect{&wire.InvVect{Hash: *wire.MessageHash(objMsg)}}

		err = queue.QueueDataRequest(hashes)
		if i == 50 {
			break
		}
		if err != nil {
			t.Errorf("Should not have got an error yet on hash %d", i)
		}
		i++
	}
	if err == nil {
		t.Error("Should have got a queue full error.")
	}

	time.Sleep(time.Millisecond * 50)
	db.Unlock()

	reset := make(chan struct{})
	go func() {
		for {
			if conn.MockRead(reset) == nil {
				break
			}
		}
	}()
	queue.Stop()

	//Start the queue again to make sure it shuts down properly before the test ends.
	queue.Start(conn)
	close(reset)

	// Engineer a situation in which the data channel gets filled up
	// and must be cleaned out.
	i = 0
	for {
		objMsg := wire.NewMsgUnknownObject(555, time.Now(), wire.ObjectType(4), 1, 1, []byte{0, 0, 0, byte(i)})

		data := wire.EncodeMessage(objMsg)
		db.InsertObject(data)
		hashes := []*wire.InvVect{&wire.InvVect{Hash: *wire.MessageHash(objMsg)}}

		err = queue.QueueDataRequest(hashes)
		// Don't need to fill up the channel this time because there is
		// no error condition to recreate.
		if i == 10 {
			break
		}
		i++
	}

	queue.Stop()

	reset = make(chan struct{})
	go func() {
		for {
			if conn.MockRead(reset) == nil {
				break
			}
		}
	}()

	//Start the queue again to make sure it shuts down properly before the test ends.
	queue.Start(conn)
	close(reset)
	queue.Stop()
}

func randomShaHash() *wire.ShaHash {
	b := make([]byte, 32)
	for i := 0; i < 32; i++ {
		b[i] = byte(rand.Intn(256))
	}
	hash, _ := wire.NewShaHash(b)
	return hash
}

func TestQueueInv(t *testing.T) {
	tickerChan := make(chan time.Time)

	ticker := time.NewTicker(time.Hour)
	ticker.C = tickerChan // Make the ticker into something I control.

	conn := NewMockConnection()
	db := NewMockDb()

	var err error
	queue := bmpeer.NewSendQueue(bmpeer.NewInventory(db))

	// The queue isn't running yet, so this should return an error.
	err = queue.QueueInventory([]*wire.InvVect{&wire.InvVect{Hash: *randomShaHash()}})
	if err == nil {
		t.Errorf("No error returned when queue is not running.")
	}

	// MockRead blocks if there is no message, so we run it in a special
	// go routine here to detect whether it received anything.
	reset := make(chan struct{})
	go func() {
		if conn.MockRead(reset) != nil {
			t.Error("message returned when there should have been none.")
		}
	}()

	// Send a tick without any invs having been sent.
	bmpeer.TstStart(queue, conn)
	bmpeer.TstStartQueueHandler(queue, ticker)
	// Time for the
	time.Sleep(time.Millisecond * 50)
	tickerChan <- time.Now()

	queue.Stop()
	bmpeer.TstStart(queue, conn)
	close(reset)
	bmpeer.TstStartQueueHandler(queue, ticker)

	// Send an inv and try to get an inv message.
	inv := &wire.InvVect{Hash: *randomShaHash()}
	queue.QueueInventory([]*wire.InvVect{inv})
	// Pause a teensy bit to ensure that the peer handler gets the message
	// and queues it up and that there will be something to read when
	// we call MockRead.
	time.Sleep(time.Millisecond * 50)
	tickerChan <- time.Now()
	msg := conn.MockRead(nil)

	switch msg.(type) {
	case *wire.MsgInv:
		invList := msg.(*wire.MsgInv).InvList
		if !(len(invList) == 1 && invList[0] == inv) {
			t.Error("Wrong inv received?")
		}
	default:
		t.Error("Wrong message type received:", msg)
	}

	queue.Stop()
	bmpeer.TstStart(queue, conn)

	// Fill up the channel.
	i := 0
	for {
		invTrickleSize := 1
		invList := make([]*wire.InvVect, invTrickleSize)
		for j := 0; j < invTrickleSize; j++ {
			invList[j] = &wire.InvVect{Hash: *randomShaHash()}
		}
		err = queue.QueueInventory(invList)
		if i == 50 {
			break
		}
		if err != nil {
			t.Error("Should not have got an error yet on round ", i)
		}
		i++
	}
	if err == nil {
		t.Error("Should have got a queue full error.")
	}

	bmpeer.TstStartQueueHandler(queue, ticker)
	queue.Stop()

	bmpeer.TstStart(queue, conn)
	bmpeer.TstStartQueueHandler(queue, ticker)

	for i = 0; i < 6; i++ {
		invTrickleSize := 1200
		invList := make([]*wire.InvVect, invTrickleSize)
		for j := 0; j < invTrickleSize; j++ {
			invList[j] = &wire.InvVect{Hash: *randomShaHash()}
		}
		err = queue.QueueInventory(invList)
	}
	// Give the queue handler some time to run.
	time.Sleep(time.Millisecond * 50)

	// Now drain the SendQueue of all messages.
	reset = make(chan struct{})
	go func() {
		for conn.MockRead(reset) != nil {
		}
	}()

	tickerChan <- time.Now()
	time.Sleep(time.Millisecond * 50)

	queue.Stop()
	close(reset)
	bmpeer.TstStart(queue, conn)
	queue.Stop()
}
