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

type MessageType uint32

const (
	MessageTypeNone    MessageType = iota
	MessageTypeVersion MessageType = iota
	MessageTypeVerAck  MessageType = iota
	MessageTypeAddr    MessageType = iota
	MessageTypeInv     MessageType = iota
	MessageTypeGetData MessageType = iota
	MessageTypeObject  MessageType = iota
)

// MockLogic is both an instance of Logic. Used for testing
// the peer object.
type MockLogic struct {
	probe        *PeerTestProbe
	MessageHeard chan MessageType
	FailChan     chan struct{}
	Failure      bool
	inbound      bool
}

func (L *MockLogic) SetFailure(b bool) {
	L.Failure = b
	if b {
		close(L.FailChan)
	} else {
		L.FailChan = make(chan struct{})
	}
}

func (L *MockLogic) Listen() MessageType {
	return <-L.MessageHeard
}

func (L *MockLogic) State() peer.PeerState {
	return peer.PeerState(0)
}

func (L *MockLogic) ProtocolVersion() uint32 {
	return 0
}

func (L *MockLogic) Report(mt MessageType) bool {
	select {
	case <-L.FailChan:
		return true
	case L.MessageHeard <- mt:
		return false
	}
}

func (L *MockLogic) HandleVersionMsg(*wire.MsgVersion) error {
	if L.Failure || L.Report(MessageTypeVersion) {
		return errors.New("Logic is set to return errors.")
	}
	return nil
}

func (L *MockLogic) HandleVerAckMsg() error {
	if L.Failure || L.Report(MessageTypeVerAck) {
		return errors.New("Logic is set to return errors.")
	}
	return nil
}

func (L *MockLogic) HandleAddrMsg(*wire.MsgAddr) error {
	if L.Failure || L.Report(MessageTypeAddr) {
		return errors.New("Logic is set to return errors.")
	}
	return nil
}

func (L *MockLogic) HandleInvMsg(*wire.MsgInv) error {
	if L.Failure || L.Report(MessageTypeInv) {
		return errors.New("Logic is set to return errors.")
	}
	return nil
}

func (L *MockLogic) HandleGetDataMsg(*wire.MsgGetData) error {
	if L.Failure || L.Report(MessageTypeGetData) {
		return errors.New("Logic is set to return errors.")
	}
	return nil
}

func (L *MockLogic) HandleObjectMsg(wire.Message) error {
	if L.Failure || L.Report(MessageTypeObject) {
		return errors.New("Logic is set to return errors.")
	}
	return nil
}

func (L *MockLogic) Start() {}

func (L *MockLogic) Stop() {}

func (L *MockLogic) PushVersionMsg() {}

func (L *MockLogic) PushVerAckMsg() {}

func (L *MockLogic) PushAddrMsg(addresses []*wire.NetAddress) error {
	return nil
}

func (L *MockLogic) PushInvMsg(invVect []*wire.InvVect) {}

func (L *MockLogic) PushGetDataMsg(invVect []*wire.InvVect) {}

func (L *MockLogic) PushObjectMsg(sha *wire.ShaHash) {}

// NewMockLogic returns an instance of MockLogic
func NewMockLogic(inbound bool) *MockLogic {
	return &MockLogic{
		MessageHeard: make(chan MessageType),
		FailChan:     make(chan struct{}),
		inbound:      inbound,
	}
}

type MockSendQueue struct {
	MessageHeard chan MessageType
	probe        *PeerTestProbe
}

func (L *MockSendQueue) QueueMessage(wire.Message) error {
	return nil
}

func (L *MockSendQueue) QueueDataRequest([]*wire.InvVect) error {
	L.MessageHeard <- MessageTypeGetData
	return nil
}

func (L *MockSendQueue) QueueInventory([]*wire.InvVect) error {
	return nil
}

func (L *MockSendQueue) Start(conn peer.Connection) {}

func (L *MockSendQueue) Running() bool {
	return true
}
func (L *MockSendQueue) Stop() {}

type PeerTestProbe struct {
	Logic        *MockLogic
	SendQueue    *MockSendQueue
	MessageHeard chan MessageType
	FailChan     chan struct{}
}

func (L *PeerTestProbe) Report(mt MessageType) bool {
	select {
	case <-L.FailChan:
		return true
	case L.MessageHeard <- mt:
		return false
	}
}

func NewPeerTestProbe(inbound bool) *PeerTestProbe {
	messageHeard := make(chan MessageType)
	failChan := make(chan struct{})

	ptp := &PeerTestProbe{
		SendQueue: &MockSendQueue{
			MessageHeard: messageHeard,
		},
		Logic: &MockLogic{
			MessageHeard: messageHeard,
			FailChan:     failChan,
			inbound:      inbound,
		},
		MessageHeard: messageHeard,
		FailChan:     failChan,
	}
	ptp.SendQueue.probe = ptp
	ptp.Logic.probe = ptp

	return ptp
}

func TestPeerStartStop(t *testing.T) {
	conn := NewMockConnection(true, false)
	probe := NewPeerTestProbe(false)
	logic := probe.Logic
	sendQueue := probe.SendQueue
	Peer := peer.NewPeer(logic, conn, sendQueue)

	Peer.Disconnect()
	if Peer.Connected() {
		t.Error("peer should not be running after being stopped before being started. ")
	}

	Peer.Start()
	if !Peer.Connected() {
		t.Error("peer should be running after being started. ")
	}
	Peer.Start()
	if !Peer.Connected() {
		t.Error("peer should still be running after being started twice in a row. ")
	}

	Peer.Disconnect()
	if Peer.Connected() {
		t.Error("peer should not be running after being stopped. ")
	}
	Peer.Disconnect()
	if Peer.Connected() {
		t.Error("peer should not be running after being stopped twice in a row. ")
	}
}

func TestConnect(t *testing.T) {
	conn := NewMockConnection(false, true)
	probe := NewPeerTestProbe(false)
	logic := probe.Logic
	sendQueue := probe.SendQueue
	Peer := peer.NewPeer(logic, conn, sendQueue)

	err := Peer.Start()
	if err == nil {
		t.Error("Should have failed to connect.")
	}

	conn = NewMockConnection(true, false)
	Peer = peer.NewPeer(logic, conn, sendQueue)
	err = Peer.Connect()
	if err != nil {
		t.Errorf("Connect returned error: %s", err)
	}

	conn = NewMockConnection(false, false)
	Peer = peer.NewPeer(logic, conn, sendQueue)
	err = Peer.Connect()
	if err != nil {
		t.Errorf("Connect returned error: %s", err)
	}

	conn = NewMockConnection(true, false)
	Peer = peer.NewPeer(logic, conn, sendQueue)

	waitChan := make(chan struct{})
	startChan := make(chan struct{})
	stopChan := make(chan struct{})
	Peer.Start()

	go func() {
		Peer.TstDisconnectWait(waitChan, startChan)
		stopChan <- struct{}{}
	}()
	// Make sure the queue is in the process of stopping already.
	<-startChan
	err = Peer.Connect()
	waitChan <- struct{}{}
	<-stopChan
	if err == nil {
		t.Error("peer should have returned an error for trying to connect in the middle of a disconnect. ")
	}
}

// TestPeer tests that every kind of message is routed correctly.
func TestPeer(t *testing.T) {
	conn := NewMockConnection(true, false)
	probe := NewPeerTestProbe(true)
	logic := probe.Logic
	sendQueue := probe.SendQueue
	Peer := peer.NewPeer(logic, conn, sendQueue)

	Peer.Start()

	var addrin, addrout *wire.NetAddress = wire.NewNetAddressIPPort(net.IPv4(5, 45, 99, 75), 8444, 1, 0),
		wire.NewNetAddressIPPort(net.IPv4(5, 45, 99, 75), 8444, 1, 0)

	conn.MockWrite(wire.NewMsgVersion(addrin, addrout, 67, []uint32{1}))
	messageType := logic.Listen()
	if messageType != MessageTypeVersion {
		t.Error("Version message expected; got ", messageType)
	}

	conn.MockWrite(&wire.MsgVerAck{})
	messageType = logic.Listen()
	if messageType != MessageTypeVerAck {
		t.Error("VerAck message expected; got ", messageType)
	}

	conn.MockWrite(wire.NewMsgAddr())
	messageType = logic.Listen()
	if messageType != MessageTypeAddr {
		t.Error("Addr message expected; got ", messageType)
	}

	conn.MockWrite(wire.NewMsgInv())
	messageType = logic.Listen()
	if messageType != MessageTypeInv {
		t.Error("Inv message expected; got ", messageType)
	}

	conn.MockWrite(wire.NewMsgGetData())
	messageType = logic.Listen()
	if messageType != MessageTypeGetData {
		t.Error("GetData message expected; got ", messageType)
	}

	expires := time.Now().Add(10 * time.Minute)
	obj := wire.NewMsgUnknownObject(345, expires, wire.ObjectType(4), 1, 1, []byte{77, 82, 53, 48, 96, 1})
	conn.MockWrite(obj)
	messageType = logic.Listen()
	if messageType != MessageTypeObject {
		t.Error("Object message expected; got ", messageType)
	}

	Peer.Disconnect()
}

// TestPeerError tests error paths in the peer's inHandler function.
func TestPeerError(t *testing.T) {
	conn := NewMockConnection(true, false)
	probe := NewPeerTestProbe(true)
	logic := probe.Logic
	sendQueue := probe.SendQueue
	Peer := peer.NewPeer(logic, conn, sendQueue)

	Peer.Start()
	conn.SetFailure(true)
	time.Sleep(time.Millisecond * 50)

	if Peer.Connected() {
		t.Error("Peer should have disconnected.")
	}
	conn.SetFailure(false)

	Peer = peer.NewPeer(logic, conn, sendQueue)
	Peer.Start()

	logic.SetFailure(true)
	conn.MockWrite(&wire.MsgVerAck{})
}

func TestTimeout(t *testing.T) {
	conn := NewMockConnection(true, false)
	probe := NewPeerTestProbe(true)
	logic := probe.Logic
	sendQueue := probe.SendQueue
	Peer := peer.NewPeer(logic, conn, sendQueue)

	Peer.TstStart(1, 1)
	if !Peer.Connected() {
		t.Fatal("Peer should have connected here.")
	}
	time.Sleep(2 * time.Second)
	if Peer.Connected() {
		t.Error("Peer should have disconnected.")
	}
}
