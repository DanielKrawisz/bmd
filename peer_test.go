// Copyright (c) 2015 Monetas.
// Copyright 2016 Daniel Krawisz.
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"fmt"
	"math/rand"
	"net"
	"testing"
	"time"

	_ "github.com/DanielKrawisz/bmd/database/memdb"
	"github.com/DanielKrawisz/bmd/peer"
	"github.com/DanielKrawisz/bmd/objmgr/stats"
	"github.com/DanielKrawisz/bmutil/wire"
	"github.com/DanielKrawisz/bmutil/wire/obj"
)

// TestOutboundPeerHandshake tests the initial handshake for an outbound peer, ie,
// the real peer initiates the connection.
// Test cases:
//  * Respond to a version message with a verack and then with a version.
//  * Respond to a version message with a version and then a verack.
//  * Error case: respond to a version with something other than verack/version.
//  * Send two veracks. (not necessarily an error.)
func TestOutboundPeerHandshake(t *testing.T) {
	// A channel for the mock peer to communicate with the test.
	report := make(chan TestReport)
	//testDone := make(chan struct{})

	streams := []uint32{1}
	nonce, _ := wire.RandomUint64()
	var addrin, addrout *wire.NetAddress = wire.NewNetAddressIPPort(net.IPv4(5, 45, 99, 75), 8444, 1, 0),
		wire.NewNetAddressIPPort(net.IPv4(5, 45, 99, 75), 8444, 1, 0)
	msgAddr := wire.NewMsgAddr()
	msgAddr.AddAddress(wire.NewNetAddressIPPort(net.IPv4(5, 45, 99, 75), 8444, 1, 0))

	invVect := make([]*wire.InvVect, 10)
	for i := 0; i < 10; i++ {
		invVect[i] = (*wire.InvVect)(randomShaHash())
	}
	msgInv := &wire.MsgInv{InvList: invVect}
	msgGetData := &wire.MsgGetData{InvList: invVect}

	responses := []*PeerAction{
		// Two possible ways of ordering the responses that are both valid.
		&PeerAction{
			Messages: []wire.Message{&wire.MsgVerAck{}, wire.NewMsgVersion(addrin, addrout, nonce, streams)},
		},
		&PeerAction{
			Messages: []wire.Message{wire.NewMsgVersion(addrin, addrout, nonce, streams), &wire.MsgVerAck{}},
		},
		// Extra VerAcks are also ok.
		&PeerAction{
			Messages: []wire.Message{&wire.MsgVerAck{}, wire.NewMsgVersion(addrin, addrout, nonce, streams), &wire.MsgVerAck{}},
		},
		&PeerAction{
			Messages: []wire.Message{&wire.MsgVerAck{}, &wire.MsgVerAck{}, wire.NewMsgVersion(addrin, addrout, nonce, streams)},
		},
		// Send a message that is not allowed at this time. Should result in a disconnect.
		&PeerAction{
			Messages:            []wire.Message{msgAddr},
			InteractionComplete: true,
			DisconnectExpected:  true,
		},
		&PeerAction{
			Messages:            []wire.Message{msgInv},
			InteractionComplete: true,
			DisconnectExpected:  true,
		},
		&PeerAction{
			Messages:            []wire.Message{msgGetData},
			InteractionComplete: true,
			DisconnectExpected:  true,
		},
		&PeerAction{
			Messages:            []wire.Message{testObj[0]},
			InteractionComplete: true,
			DisconnectExpected:  true,
		},
	}

	localAddr := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 8333}
	remoteAddr := &net.TCPAddr{IP: net.ParseIP("192.168.0.1"), Port: 8333}

	// A peer that establishes a handshake for outgoing peers.
	handshakePeerBuilder := func(action *PeerAction) func(net.Addr, int64, int64) peer.Connection {
		return func(addr net.Addr, maxDown, maxUp int64) peer.Connection {
			return NewMockPeer(localAddr, remoteAddr, report,
				NewOutboundHandshakePeerTester(action, msgAddr))
		}
	}

	permament := []string{"5.45.99.75:8444"}

	for testCase, response := range responses {
		defer resetCfg(cfg)()

		NewConn = handshakePeerBuilder(response)

		// Create server and start it.
		listeners := []string{net.JoinHostPort("", "8445")}
		serv, err := newServer(listeners, getMemDb([]obj.Object{}),
			MockListen([]*MockListener{
				NewMockListener(localAddr, make(chan peer.Connection), make(chan struct{}, 1))}),
			permament, stats.Stats{})
		if err != nil {
			t.Fatalf("Server failed to start: %s", err)
		}
		serv.Start()

		msg := <-report
		if msg.Err != nil {
			t.Errorf("error case %d: %s", testCase, msg)
		}
		serv.Stop()

		serv.WaitForShutdown()
	}

	NewConn = peer.NewConnection
}

// Test cases:
//  * Send a version message and get a verack and version message in return.
//  * Error cases: open with a verack and some other kind of message.
//  * Error case: respond to a verack with something other than verack/version.
//  * Error case: send two versions.
//  * Error case: send a version message with a version < 3.
//  * Send a version message with a version higher than three. The peer should not disconnect.
func TestInboundPeerHandshake(t *testing.T) {
	// A channel for the mock peer to communicate with the test.
	report := make(chan TestReport)
	// A channel to make the fake incomming connection.
	incoming := make(chan peer.Connection)

	streams := []uint32{1}
	nonce, _ := wire.RandomUint64()
	var addrin, addrout *wire.NetAddress = wire.NewNetAddressIPPort(net.IPv4(5, 45, 99, 75), 8444, 1, 0),
		wire.NewNetAddressIPPort(net.IPv4(5, 45, 99, 75), 8444, 1, 0)

	localAddr := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 8333}
	remoteAddr := &net.TCPAddr{IP: net.ParseIP("192.168.0.1"), Port: 8333}

	msgAddr := wire.NewMsgAddr()
	msgAddr.AddAddress(wire.NewNetAddressIPPort(net.IPv4(5, 45, 99, 75), 8444, 1, 0))

	addrAction := &PeerAction{
		Messages:            []wire.Message{msgAddr},
		InteractionComplete: true,
		DisconnectExpected:  false,
	}

	incorrectVersion := wire.NewMsgVersion(addrin, addrout, nonce, streams)
	incorrectVersion.ProtocolVersion = int32(2)

	futureVersion := wire.NewMsgVersion(addrin, addrout, nonce, streams)
	futureVersion.ProtocolVersion = int32(4)

	// The four test cases are all in this list.
	openingMsg := []*PeerAction{
		&PeerAction{
			Messages: []wire.Message{wire.NewMsgVersion(addrin, addrout, nonce, streams)},
		},
		&PeerAction{
			Messages:            []wire.Message{&wire.MsgVerAck{}},
			InteractionComplete: true,
			DisconnectExpected:  true,
		},
		&PeerAction{
			Messages:            []wire.Message{msgAddr},
			InteractionComplete: true,
			DisconnectExpected:  true,
		},
		&PeerAction{
			Messages:            []wire.Message{wire.NewMsgVersion(addrin, addrout, nonce, streams), wire.NewMsgVersion(addrin, addrout, nonce, streams)},
			InteractionComplete: true,
			DisconnectExpected:  true,
		},
		&PeerAction{
			Messages:            []wire.Message{incorrectVersion},
			InteractionComplete: true,
			DisconnectExpected:  true,
		},
		&PeerAction{
			Messages:            []wire.Message{futureVersion},
			InteractionComplete: true,
			DisconnectExpected:  false,
		},
	}

	for testCase, open := range openingMsg {
		defer resetCfg(cfg)()

		// Create server and start it.
		listeners := []string{net.JoinHostPort("", "8445")}
		var err error
		serv, err := newServer(listeners, getMemDb([]obj.Object{}),
			MockListen([]*MockListener{
				NewMockListener(localAddr, incoming, make(chan struct{}))}),
				nil, stats.Stats{})
		if err != nil {
			t.Fatalf("Server failed to start: %s", err)
		}
		serv.Start()

		// Test handshake.
		incoming <- NewMockPeer(localAddr, remoteAddr, report,
			NewInboundHandshakePeerTester(open, addrAction))

		msg := <-report
		if msg.Err != nil {
			t.Errorf("error case %d: %s", testCase, msg)
		}
		serv.Stop()

		serv.WaitForShutdown()
	}
}

// Test cases
//  * after a successful handshake, get an addr and receive one.
//  * error case: send an addr message that is too big.
//  * Give the peer no addresses to send.
func TestProcessAddr(t *testing.T) {
	// Process a handshake. This should be an incoming peer.
	// Send an addr and receive an addr.
	// Ignore inv messages.

	// A channel for the mock peer to communicate with the test.
	report := make(chan TestReport)
	// A channel to make the fake incomming connection.
	incoming := make(chan peer.Connection)

	srcAddr := &wire.NetAddress{
		Timestamp: time.Now(),
		Services:  wire.SFNodeNetwork,
		IP:        net.ParseIP("173.144.173.111"),
		Port:      8333,
	}

	// Some parameters for the test sequence.
	streams := []uint32{1}
	nonce, _ := wire.RandomUint64()
	var addrin, addrout *wire.NetAddress = wire.NewNetAddressIPPort(net.IPv4(5, 45, 99, 75), 8444, 1, 0),
		wire.NewNetAddressIPPort(net.IPv4(5, 45, 99, 75), 8444, 1, 0)

	localAddr := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 8333}
	remoteAddr := &net.TCPAddr{IP: net.ParseIP("192.168.0.1"), Port: 8333}

	// Some addr messages to use for testing.
	addrMsg := wire.NewMsgAddr()
	addrMsg.AddAddress(wire.NewNetAddressIPPort(net.IPv4(5, 45, 99, 75), 8444, 1, 0))
	// Maximum number of addresses allowed in an addr message is 1000, so we add 1001.
	addrMsgTooLong := wire.NewMsgAddr()
	for i := 0; i <= 1001; i++ {
		addrMsgTooLong.AddAddress(&wire.NetAddress{
			Timestamp: time.Now(),
			Services:  wire.SFNodeNetwork,
			IP: net.IPv4(
				byte(rand.Intn(256)),
				byte(rand.Intn(256)),
				byte(rand.Intn(256)),
				byte(rand.Intn(256))),
			Port: 8333,
		})
	}

	AddrTests := []struct {
		AddrAction *PeerAction // Action for the mock peer to take upon handshake completion.
		NumAddrs   int         // Number of addresses to put in the address manager.
	}{
		{
			&PeerAction{
				Messages: []wire.Message{addrMsg},
			},
			25,
		},
		{
			&PeerAction{
				Messages:            []wire.Message{addrMsgTooLong},
				InteractionComplete: true,
				DisconnectExpected:  true,
			},
			25,
		},
		{
			&PeerAction{InteractionComplete: true},
			0,
		},
	}

	for testCase, addrTest := range AddrTests {
		defer resetCfg(cfg)()
		// Add some addresses to the address manager.
		addrs := make([]*wire.NetAddress, addrTest.NumAddrs)

		// Create server and start it.
		listeners := []string{net.JoinHostPort("", "8445")}
		serv, err := newServer(listeners, getMemDb([]obj.Object{}),
			MockListen([]*MockListener{
				NewMockListener(localAddr, incoming, make(chan struct{}))}),
				nil, stats.Stats{})
		if err != nil {
			t.Fatal("Server failed to start.")
		}
		serv.Start()

		for i := 0; i < addrTest.NumAddrs; i++ {
			s := fmt.Sprintf("%d.173.147.%d:8333", i/64+60, i%64+60)
			addrs[i], _ = serv.addrManager.DeserializeNetAddress(s)
		}

		serv.addrManager.AddAddresses(addrs, srcAddr)

		mockConn := NewMockPeer(localAddr, remoteAddr, report,
			NewInboundHandshakePeerTester(
				&PeerAction{Messages: []wire.Message{wire.NewMsgVersion(addrin, addrout, nonce, streams)}},
				addrTest.AddrAction))

		incoming <- mockConn

		msg := <-report
		if msg.Err != nil {
			t.Errorf("error case %d: %s", testCase, msg)
		}
		serv.Stop()

		serv.WaitForShutdown()
	}
}

// Test cases
//  * assume handshake already successful. Get an inv and receive one. request an object
//    from the peer and receive a request for something that the mock peer has. Send
//    and receive responses for the requests. Several cases of this scenario:
//     * The peer already has everything that the mock peer has (no inv expected).
//     * The peer has some of what the mock peer has, but not everything.
//     * The peer needs to send more than one getData request.
//  * error case: send an inv message that is too big (peer should disconnect).
//  * error case: send a request for an object that the peer does not have (peer should not disconnect).
//  * error case: return an object that was not requested (peer should disconnect).
func TestProcessInvAndObjectExchange(t *testing.T) {
	// Send an inv and receive an inv.
	// Process a request for an object.
	// Send a request and receive an object.
	// Ignore addr messages.

	tooLongInvVect := make([]*wire.InvVect, wire.MaxInvPerMsg+1)
	for i := 0; i < wire.MaxInvPerMsg+1; i++ {
		tooLongInvVect[i] = (*wire.InvVect)(randomShaHash())
	}
	TooLongInv := &wire.MsgInv{InvList: tooLongInvVect}

	tests := []struct {
		peerDB []obj.Object // The messages already in the peer's db.
		mockDB []obj.Object // The messages that are already in the
		// Action for the mock peer to take upon receiving an inv. If this is
		// nil, then an appropriate action is constructed.
		invAction *PeerAction
	}{
		{ // Nobody has any inv in this test case!
			[]obj.Object{},
			[]obj.Object{},
			&PeerAction{
				Messages:            []wire.Message{&wire.MsgVerAck{}},
				InteractionComplete: true},
		},
		{ // Send empty inv and should be disconnected.
			[]obj.Object{},
			[]obj.Object{},
			&PeerAction{
				Messages:            []wire.Message{&wire.MsgVerAck{}, wire.NewMsgInv()},
				InteractionComplete: true,
				DisconnectExpected:  true},
		},
		{ // Only the real peer should request data.
			[]obj.Object{},
			[]obj.Object{testObj[0], testObj[2], testObj[4], testObj[6], testObj[8]},
			nil,
		},
		{ // Neither peer should request data.
			[]obj.Object{testObj[0], testObj[2], testObj[4], testObj[6], testObj[8]},
			[]obj.Object{testObj[0], testObj[2], testObj[4], testObj[6], testObj[8]},
			nil,
		},
		{ // Only the mock peer should request data.
			[]obj.Object{testObj[0], testObj[2], testObj[4], testObj[6], testObj[8]},
			[]obj.Object{},
			nil,
		},
		{ // The peers have no data in common, so they should both ask for everything of the other.
			[]obj.Object{testObj[1], testObj[3], testObj[5], testObj[7], testObj[9]},
			[]obj.Object{testObj[0], testObj[2], testObj[4], testObj[6], testObj[8]},
			nil,
		},
		{ // The peers have some data in common.
			[]obj.Object{testObj[0], testObj[3], testObj[5], testObj[7], testObj[9]},
			[]obj.Object{testObj[0], testObj[2], testObj[4], testObj[6], testObj[8]},
			nil,
		},
		{
			[]obj.Object{},
			[]obj.Object{},
			&PeerAction{
				Messages:            []wire.Message{&wire.MsgVerAck{}, TooLongInv},
				DisconnectExpected:  true,
				InteractionComplete: true},
		},
	}

	// A channel for the mock peer to communicate with the test.
	report := make(chan TestReport)
	// A channel to make the fake incomming connection.
	incoming := make(chan peer.Connection)

	// Some parameters for the test sequence.
	localAddr := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 8333}
	remoteAddr := &net.TCPAddr{IP: net.ParseIP("192.168.0.1"), Port: 8333}

	addrout, _ := wire.NewNetAddress(remoteAddr, 1, 0)

	for testCase, test := range tests {
		defer resetCfg(cfg)()

		t.Log("Test case", testCase)
		// Define the objects that will go in the database.
		// Create server and start it.
		listeners := []string{net.JoinHostPort("", "8445")}
		db := getMemDb(test.peerDB)
		serv, err := newServer(listeners, db,
			MockListen([]*MockListener{
				NewMockListener(localAddr, incoming, make(chan struct{}))}),
				nil, stats.Stats{})
		if err != nil {
			t.Fatal("Server failed to start.")
		}

		serv.Start()

		mockConn := NewMockPeer(localAddr, remoteAddr, report,
			NewDataExchangePeerTester(test.mockDB, test.peerDB, test.invAction))
		mockSend := NewMockSend(mockConn)
		inventory := peer.NewInventory()
		serv.handleAddPeerMsg(peer.NewPeerHandshakeComplete(
			serv, mockConn, inventory, mockSend, addrout), 0)

		var msg TestReport
		msg = <-report
		if msg.Err != nil {
			t.Errorf("error case %d: %s", testCase, msg)
		}
		serv.Stop()

		serv.WaitForShutdown()
		// Check if the data sent is actually in the peer's database.
		if msg.DataSent != nil {
			for _, hash := range msg.DataSent {
				if ok, _ := db.ExistsObject(hash); !ok {
					t.Error("test case ", testCase, ": Object", *hash, "not found in database.")
				}
			}
		}
	}
}
