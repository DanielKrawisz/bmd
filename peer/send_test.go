// Copyright (c) 2015 Monetas.
// Copyright 2016 Daniel Krawisz.
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package peer_test

import (
	"bytes"
	"net"
	"testing"
	"time"

	"github.com/DanielKrawisz/bmd/database"
	_ "github.com/DanielKrawisz/bmd/database/memdb"
	"github.com/DanielKrawisz/bmd/peer"
	"github.com/DanielKrawisz/bmutil"
	"github.com/DanielKrawisz/bmutil/wire"
)

var mockAddr net.Addr = &net.TCPAddr{IP: net.ParseIP("192.168.0.1"), Port: 8333}

func TestSendStartStop(t *testing.T) {
	conn := NewMockConnection(mockAddr, true, false)
	db, _ := database.OpenDB("memdb")

	queue := peer.NewSend(peer.NewInventory(), db)

	if queue.Running() {
		t.Errorf("queue should not be running yet. ")
	}
	queue.Stop()
	if queue.Running() {
		t.Errorf("queue should still not be running. ")
	}

	queue.Start(conn)
	if !queue.Running() {
		t.Errorf("queue should be running. ")
	}
	queue.Stop()
	if queue.Running() {
		t.Errorf("queue should not be running anymore. ")
	}

	// Test the case in which Start and Stop end prematurely because they
	// are being called by another go routine.
	waitChan := make(chan struct{})
	startChan := make(chan struct{})
	stopChan := make(chan struct{})
	go func() {
		peer.TstSendStartWait(queue, conn, waitChan, startChan)
		stopChan <- struct{}{}
	}()
	// Make sure the queue is definitely in the middle of starting.
	<-startChan
	queue.Start(conn)
	waitChan <- struct{}{}
	<-stopChan
	if !queue.Running() {
		t.Errorf("queue should be running after being started twice. ")
	}

	go func() {
		peer.TstSendStopWait(queue, waitChan, startChan)
		stopChan <- struct{}{}
	}()
	// Make sure the queue is in the process of stopping already.
	<-startChan
	queue.Stop()
	waitChan <- struct{}{}
	<-stopChan
	if queue.Running() {
		t.Errorf("queue should not be running. ")
	}
}

func TestSendMessage(t *testing.T) {
	conn := NewMockConnection(mockAddr, true, false)
	db, _ := database.OpenDB("memdb")
	var err error

	queue := peer.NewSend(peer.NewInventory(), db)

	message := &wire.MsgVerAck{}

	// Try sending a message to a send that is not running yet.
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

	// Now test that the send shuts down if the connection fails.
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

	queue.Start(conn)

	queue.Stop()
	time.Sleep(time.Millisecond * 50)
}

func TestRequestData(t *testing.T) {
	conn := NewMockConnection(mockAddr, true, false)
	db, _ := database.OpenDB("memdb")

	var err error

	queue := peer.NewSend(peer.NewInventory(), db)
	message := wire.NewMsgObject(wire.NewObjectHeader(345, time.Now(), wire.ObjectType(4), 1, 1), []byte{77, 82, 53, 48, 96, 1})

	db.InsertObject(message)
	hashes := []*wire.InvVect{&wire.InvVect{Hash: *message.InventoryHash()}}

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

	sentData := conn.MockRead(nil)

	if !bytes.Equal(wire.EncodeMessage(message), wire.EncodeMessage(sentData)) {
		t.Errorf("Different message received somehow. ")
	}

	// Try to send something that isn't in the database at all and something
	// that isn't a valid message. These don't return errors, but they are here
	// for code coverage. In order to ensure that the queue behaves correctly,
	// we send a regular message after and receive it.
	badData := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 0}
	badHash, _ := wire.NewShaHash(bmutil.Sha512(badData)[:32])
	badHashes := []*wire.InvVect{&wire.InvVect{Hash: *badHash}}
	queue.QueueDataRequest(badHashes)

	queue.QueueDataRequest(hashes)
	// Force the send to manage all queued requests.
	sentData = conn.MockRead(nil)
	if !bytes.Equal(wire.EncodeMessage(message), wire.EncodeMessage(sentData)) {
		t.Errorf("Wrong message returned.")
	}

	queue.QueueDataRequest(badHashes)

	queue.QueueDataRequest(hashes)
	sentData = conn.MockRead(nil)
	if !bytes.Equal(wire.EncodeMessage(message), wire.EncodeMessage(sentData)) {
		t.Errorf("Wrong message returned.")
	}

	queue.Stop()

	//Start the queue again to make sure it shuts down properly before the test ends.
	queue.Start(conn)

	queue.Stop()
}

func TestQueueInv(t *testing.T) {
	timerChan := make(chan time.Time)

	timer := time.NewTimer(time.Hour)
	timer.C = timerChan // Make the ticker into something I control.

	conn := NewMockConnection(mockAddr, true, false)
	db, _ := database.OpenDB("memdb")

	var err error
	queue := peer.NewSend(peer.NewInventory(), db)

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

	// Give the other thread some time to confirm that no messages are in the channel.
	time.Sleep(50 * time.Millisecond)
	reset <- struct{}{}

	// Send a tick without any invs having been sent.
	peer.TstSendStart(queue, conn)
	peer.TstSendStartQueueHandler(queue, timer)
	// Time for the send queue to get started.
	time.Sleep(time.Millisecond * 50)
	timerChan <- time.Now()

	queue.Stop()
	peer.TstSendStart(queue, conn)
	close(reset)
	peer.TstSendStartQueueHandler(queue, timer)

	// Send an inv and try to get an inv message.
	inv := &wire.InvVect{Hash: *randomShaHash()}
	queue.QueueInventory([]*wire.InvVect{inv})
	// Pause a teensy bit to ensure that the peer handler gets the message
	// and queues it up and that there will be something to read when
	// we call MockRead.
	time.Sleep(time.Millisecond * 50)
	timerChan <- time.Now()
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

	peer.TstSendStart(queue, conn)
	peer.TstSendStartQueueHandler(queue, timer)

	for i := 0; i < 6; i++ {
		invTrickleSize := 1200
		invList := make([]*wire.InvVect, invTrickleSize)
		for j := 0; j < invTrickleSize; j++ {
			invList[j] = &wire.InvVect{Hash: *randomShaHash()}
		}
		err = queue.QueueInventory(invList)
	}
	// Give the queue handler some time to run.
	time.Sleep(time.Millisecond * 50)

	// Now drain the Send of all messages.
	reset = make(chan struct{})
	go func() {
		for conn.MockRead(reset) != nil {
		}
	}()

	timerChan <- time.Now()
	time.Sleep(time.Millisecond * 50)

	queue.Stop()
	close(reset)

	// Finally, test the line that drains invSendQueue if the program disconnects.
	peer.TstSendStart(queue, conn)
	peer.TstSendStartQueueHandler(queue, timer)

	for i := 0; i < 6; i++ {
		invTrickleSize := 1200
		invList := make([]*wire.InvVect, invTrickleSize)
		for j := 0; j < invTrickleSize; j++ {
			invList[j] = &wire.InvVect{Hash: *randomShaHash()}
		}
		err = queue.QueueInventory(invList)
	}
	// Give the queue handler some time to run.
	time.Sleep(time.Millisecond * 50)
	queue.Stop()

	// Start and stop again to make sure the test doesn't end before the queue
	// has shut down the last time.
	peer.TstSendStart(queue, conn)
	queue.Stop()
}

func TestRetrieveObject(t *testing.T) {
	db, _ := database.OpenDB("memdb")

	// An object that is not in the database.
	notThere := &wire.InvVect{Hash: *randomShaHash()}

	// A valid object that will be in the database.
	goodData := wire.NewMsgObject(
		wire.NewObjectHeader(345, time.Now(), wire.ObjectType(4), 1, 1),
		[]byte{77, 82, 53, 48, 96, 1})
	goodInv := &wire.InvVect{Hash: *goodData.InventoryHash()}
	db.InsertObject(goodData)

	// Retrieve objects that are not in the database.
	obj, err := peer.TstRetrieveObject(db, notThere)
	if err == nil {
		t.Error("Object returned that should not have been in the database: ", obj)
	}

	// Retrieve good objects from the database.
	if _, err := peer.TstRetrieveObject(db, goodInv); err != nil {
		t.Error("No object returned.")
	}
}
