// Copyright (c) 2015 Monetas.
// Copyright 2016 Daniel Krawisz.
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"net"
	"testing"

	"github.com/DanielKrawisz/bmd/peer"
	"github.com/DanielKrawisz/bmd/objmgr/stats"
	pb "github.com/DanielKrawisz/bmd/rpcproto"
	"github.com/DanielKrawisz/bmutil/wire"
	"github.com/DanielKrawisz/bmutil/wire/obj"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
)

const (
	rpcLoc = "localhost:8442"

	rpcAdminUser = "admin"
	rpcAdminPass = "admin"

	rpcLimitUser = "limit"
	rpcLimitPass = "limit"
)

func rpcTests(t *testing.T, s *server) {
	// Order of the tests is important. Do not change.
	testRPCAuth(t)

	// Set up a connection to the server.
	conn, err := grpc.Dial(rpcLoc, grpc.WithInsecure(),
		grpc.WithPerRPCCredentials(pb.NewBasicAuthCredentials(rpcAdminUser, rpcAdminPass)))
	if err != nil {
		t.Fatalf("did not connect: %v", err)
	}
	defer conn.Close()
	c := pb.NewBmdClient(conn)

	testRPCSendObject(s, c, t)
	testRPCGetObjects(c, t)
}

// testRPCAuth tests authentication failures for all RPC methods.
func testRPCAuth(t *testing.T) {
	// Try accessing methods with no credentials.
	conn, err := grpc.Dial(rpcLoc, grpc.WithInsecure())
	if err != nil {
		t.Fatalf("did not connect: %v", err)
	}
	c := pb.NewBmdClient(conn)

	testRPCAuthFailure(c, t, codes.Unauthenticated)
	conn.Close()

	// Try accessing methods with invalid credentials.
	conn, err = grpc.Dial(rpcLoc, grpc.WithInsecure(),
		grpc.WithPerRPCCredentials(pb.NewBasicAuthCredentials("blahblah", "blah blah")))
	if err != nil {
		t.Fatalf("did not connect: %v", err)
	}
	c = pb.NewBmdClient(conn)

	testRPCAuthFailure(c, t, codes.PermissionDenied)
	conn.Close()
}

func testRPCAuthFailure(c pb.BmdClient, t *testing.T, expectedCode codes.Code) {
	_, err := c.SendObject(context.Background(), &pb.Object{})
	if grpc.Code(err) != expectedCode {
		t.Errorf("Expected code %d, got unexpected error %v", expectedCode, err)
	}

	_, err = c.GetIdentity(context.Background(), &pb.GetIdentityRequest{})
	if grpc.Code(err) != expectedCode {
		t.Errorf("Expected code %d, got unexpected error %v", expectedCode, err)
	}

	stream, err := c.GetObjects(context.Background(), &pb.GetObjectsRequest{})
	if err != nil {
		t.Error(err)
	}

	_, err = stream.Recv()
	if grpc.Code(err) != expectedCode {
		t.Errorf("Expected code %d, got unexpected error %v", expectedCode, err)
	}
}

// Test SendObject.
func testRPCSendObject(serv *server, c pb.BmdClient, t *testing.T) {
	errorTests := [][]byte{
		[]byte{},                       // empty
		[]byte{0x00, 0x00, 0x00, 0x00}, // invalid object
		[]byte{ // expired
			0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xe0, 0xf3, // Nonce
			0x00, 0x00, 0x00, 0x00, 0x49, 0x5f, 0xab, 0x29, // 64-bit Timestamp
			0x00, 0x00, 0x00, 0x00, // object type
			0x03, // Version
			0x01, // Stream Number
		},
		[]byte{ // invalid stream
			0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xe0, 0xf3, // Nonce
			0x00, 0x00, 0x00, 0xff, 0x49, 0x5f, 0xab, 0x29, // 64-bit Timestamp
			0x00, 0x00, 0x00, 0x00, // object type
			0x03, // Version
			0x05, // Stream Number
		},
		[]byte{ // invalid PoW
			0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xe0, 0xf3, // Nonce
			0x00, 0x00, 0x00, 0xff, 0x49, 0x5f, 0xab, 0x29, // 64-bit Timestamp
			0x00, 0x00, 0x00, 0x00, // object type
			0x03, // Version
			0x01, // Stream Number
		},
	}

	for i, test := range errorTests {
		_, err := c.SendObject(context.Background(), &pb.Object{Contents: test})
		if grpc.Code(err) != codes.InvalidArgument {
			t.Errorf("for case #%d got unexpected error %v", i, err)
		}
	}

	// Insert valid object.
	data := wire.Encode(testObj[0]) // getpubkey
	ret, err := c.SendObject(context.Background(), &pb.Object{Contents: data})
	if err != nil {
		t.Errorf("for valid SendObject got error %v", err)
	} else if 1 != ret.Counter {
		t.Errorf("For counter expected %d got %d", 1, ret.Counter)
	}

	hash := obj.InventoryHash(testObj[0])

	// Check if advertised.
	if ok, err := serv.objectManager.HaveInventory((*wire.InvVect)(hash)); !ok {
		t.Error("server doesn't have new object in inventory, error:", err)
	}

	// Try inserting object again.
	_, err = c.SendObject(context.Background(), &pb.Object{Contents: data})
	if grpc.Code(err) != codes.AlreadyExists {
		t.Errorf("got unexpected error %v", err)
	}
}

func testRPCGetObjects(c pb.BmdClient, t *testing.T) {
	// Receive Getpubkey inserted in previous test.
	stream, err := c.GetObjects(context.Background(), &pb.GetObjectsRequest{
		ObjectType:  pb.ObjectType_GETPUBKEY,
		FromCounter: 1,
	})
	if err != nil {
		t.Fatal(err)
	}

	objMsg, err := stream.Recv()
	if err != nil {
		t.Fatal(err)
	}

	data := wire.Encode(testObj[0]) // getpubkey
	if !bytes.Equal(data, objMsg.Contents) {
		t.Errorf("invalid getpubkey bytes, expected %v got %v", data, objMsg.Contents)
	}

	// Test if objects inserted after subscribing are handled correctly.
	data = wire.Encode(testObj[1]) // getpubkey
	_, err = c.SendObject(context.Background(), &pb.Object{Contents: data})
	if err != nil {
		t.Errorf("for valid SendObject got error %v", err)
	}

	objMsg, err = stream.Recv()
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(data, objMsg.Contents) {
		t.Errorf("invalid getpubkey bytes, expected %v got %v", data, objMsg.Contents)
	}
}

func TestRPCConnection(t *testing.T) {

	// Address for mock listener to pass to server. The server
	// needs at least one listener or it won't start so we mock it.
	remoteAddr := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 8445}

	// Set config.
	cfg.MaxPeers = 0
	cfg.RPCPass = rpcAdminUser
	cfg.RPCUser = rpcAdminPass
	cfg.RPCLimitUser = rpcLimitUser
	cfg.RPCLimitPass = rpcLimitPass
	cfg.EnableRPC = true
	cfg.DisableTLS = true
	cfg.RPCMaxClients = 1
	defer resetCfg(cfg)()

	// Set RPC listener.
	cfg.RPCListeners = []string{net.JoinHostPort("", "8442")}

	// Create a server.
	listeners := []string{net.JoinHostPort("", "8445")}
	serv, err := newServer(listeners, getMemDb([]obj.Object{}),
		MockListen([]*MockListener{
			NewMockListener(remoteAddr, make(chan peer.Connection), make(chan struct{}, 1))}), nil, stats.Stats{})

	if err != nil {
		t.Fatalf("Server creation failed: %s", err)
	}
	serv.Start()

	// Run the actual tests.
	rpcTests(t, serv)

	// Cleanup.
	serv.Stop()
	serv.WaitForShutdown()
}
