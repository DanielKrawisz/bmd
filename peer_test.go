// Copyright (c) 2015 Monetas.
// Copyright 2016 Daniel Krawisz.
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"encoding/binary"
	"fmt"
	"io/ioutil"
	"math/rand"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/DanielKrawisz/bmd/database"
	_ "github.com/DanielKrawisz/bmd/database/memdb"
	"github.com/DanielKrawisz/bmd/peer"
	"github.com/DanielKrawisz/bmutil"
	"github.com/DanielKrawisz/bmutil/pow"
	"github.com/DanielKrawisz/bmutil/wire"
	"github.com/DanielKrawisz/bmutil/wire/obj"
)

// resetCfg is called to refresh configuration before every test. The returned
// function is supposed to be called at the end of the test; to clear temp
// directories.
func resetCfg(cfg *Config) func() {
	dir, err := ioutil.TempDir("", "bmd")
	if err != nil {
		panic(fmt.Sprint("Failed to create temporary directory:", err))
	}
	cfg.DataDir = dir
	cfg.LogDir = filepath.Join(cfg.DataDir, defaultLogDirname)

	return func() {
		os.RemoveAll(dir)
	}
}

func getMemDb(msgs []obj.Object) database.Db {
	db, err := database.OpenDB("memdb")
	if err != nil {
		return nil
	}

	for _, msg := range msgs {
		db.InsertObject(msg)
	}

	return db
}

var expires = time.Now().Add(5 * time.Minute)

// A set of pub keys to create fake objects for testing the database.
var pubkey = []wire.PubKey{
	wire.PubKey([wire.PubKeySize]byte{
		23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38,
		39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54,
		55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70,
		71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86}),
	wire.PubKey([wire.PubKeySize]byte{
		87, 88, 89, 90, 91, 92, 93, 94, 95, 96, 97, 98, 99, 100, 101, 102,
		103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116, 117, 118,
		119, 120, 121, 122, 123, 124, 125, 126, 127, 128, 129, 130, 131, 132, 133, 134,
		135, 136, 137, 138, 139, 140, 141, 142, 143, 144, 145, 146, 147, 148, 149, 150}),
	wire.PubKey([wire.PubKeySize]byte{
		54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69,
		70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85,
		86, 87, 88, 89, 90, 91, 92, 93, 94, 95, 96, 97, 98, 99, 100, 101,
		102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116, 117}),
	wire.PubKey([wire.PubKeySize]byte{
		118, 119, 120, 121, 122, 123, 124, 125, 126, 127, 128, 129, 130, 131, 132, 133,
		134, 135, 136, 137, 138, 139, 140, 141, 142, 143, 144, 145, 146, 147, 148, 149,
		150, 151, 152, 153, 154, 155, 156, 157, 158, 159, 160, 161, 162, 163, 164, 165,
		166, 167, 168, 169, 170, 171, 172, 173, 174, 175, 176, 177, 178, 179, 180, 181}),
}

var shahash = []wire.ShaHash{
	wire.ShaHash([wire.HashSize]byte{
		98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113,
		114, 115, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125, 126, 127, 128, 129}),
	wire.ShaHash([wire.HashSize]byte{
		100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115,
		116, 117, 118, 119, 120, 121, 122, 123, 124, 125, 126, 127, 128, 129, 130, 131}),
}

var ripehash = []wire.RipeHash{
	wire.RipeHash([wire.RipeHashSize]byte{
		78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95, 96, 97}),
	wire.RipeHash([wire.RipeHashSize]byte{
		80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95, 96, 97, 98, 99}),
}

// Some bitmessage objects that we use for testing. Two of each.
var testObj = []obj.Object{
	obj.NewGetPubKey(654, expires, 4, 1, &ripehash[0], &shahash[0]).MsgObject(),
	obj.NewGetPubKey(654, expires, 4, 1, &ripehash[1], &shahash[1]).MsgObject(),
	obj.NewEncryptedPubKey(543, expires, 1, &shahash[0], []byte{11, 12, 13, 14, 15, 16, 17, 18}).MsgObject(),
	obj.NewEncryptedPubKey(543, expires, 1, &shahash[1], []byte{11, 12, 13, 14, 15, 16, 17, 18}).MsgObject(),
	obj.NewMessage(765, expires, 1,
		[]byte{90, 87, 66, 45, 3, 2, 120, 101, 78, 78, 78, 7, 85, 55, 2, 23}).MsgObject(),
	obj.NewMessage(765, expires, 1,
		[]byte{90, 87, 66, 45, 3, 2, 120, 101, 78, 78, 78, 7, 85, 55}).MsgObject(),
	obj.NewTaggedBroadcast(876, expires, 1, &shahash[0],
		[]byte{42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56}).MsgObject(),
	obj.NewTaggedBroadcast(876, expires, 1, &shahash[1],
		[]byte{42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55}).MsgObject(),
	wire.NewMsgObject(wire.NewObjectHeader(345, expires, wire.ObjectType(4), 1, 1), []byte{77, 82, 53, 48, 96, 1}),
	wire.NewMsgObject(wire.NewObjectHeader(987, expires, wire.ObjectType(4), 1, 1), []byte{1, 2, 3, 4, 5, 0, 6, 7, 8, 9, 100}),
	wire.NewMsgObject(wire.NewObjectHeader(7288, expires, wire.ObjectType(5), 1, 1), []byte{0, 0, 0, 0, 1, 0, 0}),
	wire.NewMsgObject(wire.NewObjectHeader(7288, expires, wire.ObjectType(5), 1, 1), []byte{0, 0, 0, 0, 0, 0, 0, 99, 98, 97}),
}

func init() {
	// Calculate pow for object messages.
	for i := 0; i < len(testObj); i++ {
		b := wire.Encode(testObj[i])
		section := b[8:]
		hash := bmutil.Sha512(section)
		nonce := pow.DoSequential(pow.CalculateTarget(uint64(len(section)),
			uint64(expires.Sub(time.Now()).Seconds()), pow.DefaultData), hash)
		binary.BigEndian.PutUint64(b, uint64(nonce))
		testObj[i], _ = wire.DecodeMsgObject(b)
	}

	// Load config
	var err error
	cfg, _, err = loadConfig()
	if err != nil {
		panic(fmt.Sprint("Config failed to load: ", err))
	}
	cfg.MaxPeers = 1
	cfg.DisableDNSSeed = true
	cfg.DebugLevel = "trace"
}

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
		invVect[i] = &wire.InvVect{Hash: *randomShaHash()}
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
			permament)
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
				NewMockListener(localAddr, incoming, make(chan struct{}))}), nil)
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
				NewMockListener(localAddr, incoming, make(chan struct{}))}), nil)
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
		tooLongInvVect[i] = &wire.InvVect{Hash: *randomShaHash()}
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
				NewMockListener(localAddr, incoming, make(chan struct{}))}), nil)
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
