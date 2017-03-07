// Copyright (c) 2015 Monetas.
// Copyright 2016 Daniel Krawisz.
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"sync"
	"time"

	"github.com/DanielKrawisz/bmd/database"
	"github.com/DanielKrawisz/bmd/rpc"
	pb "github.com/DanielKrawisz/bmd/rpcproto"
	"github.com/DanielKrawisz/bmutil"
	"github.com/DanielKrawisz/bmutil/pow"
	"github.com/DanielKrawisz/bmutil/wire"
	"github.com/DanielKrawisz/bmutil/wire/obj"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
)

const (
	// rpcCounterObjectsSize is the number of objects that db.FetchObjectsFromCounter
	// will fetch per query to the database. This is used when a client requests
	// subscription to an object type from a specified counter value.
	rpcCounterObjectsSize = 100
)

type rpcServer struct {
	rpc.Server
	server *server

	// Conds for notifying listening clients about pending objects. Key is the
	// string representation of the object type.
	objConds map[string]*sync.Cond
}

// NotifyObject is used to notify the RPC server of any new objects so that it
// can send those onwards to the client.
func (s *rpcServer) NotifyObject(objType wire.ObjectType) {
	s.objConds[objType.String()].Broadcast()
}

// SendObject inserts the object into bmd's database and sends it out to the
// Bitmessage network.
func (s *rpcServer) SendObject(ctx context.Context, in *pb.Object) (*pb.SendObjectReply, error) {
	rpcLog.Trace("SendObject: object received to be sent out into the network.")

	if code := s.RestrictAuth(ctx); code != codes.OK {
		return nil, grpc.Errorf(code, "auth failure")
	}
	if len(in.Contents) == 0 {
		return nil, grpc.Errorf(codes.InvalidArgument, "contents must not be empty")
	}

	objMsg, err := wire.DecodeMsgObject(in.Contents)
	if err != nil {
		return nil, grpc.Errorf(codes.InvalidArgument, "error decoding object: %v",
			err)
	}

	// Check if object is already in database.
	exists, err := s.server.db.ExistsObject(obj.InventoryHash(objMsg))
	if err != nil {
		rpcLog.Errorf("ExistsObject, database error: %v", err)
		return nil, grpc.Errorf(codes.Internal, "database error")
	}
	if exists {
		return nil, grpc.Errorf(codes.AlreadyExists, "object already in database")
	}

	// Check whether the object is valid.
	if time.Now().After(objMsg.Header().Expiration()) { // already expired
		return nil, grpc.Errorf(codes.InvalidArgument, "object already expired")
	}
	if objMsg.Header().StreamNumber != 1 { // TODO improve
		return nil, grpc.Errorf(codes.InvalidArgument, "invalid stream")
	}

	// Check whether the PoW is valid.
	if !objMsg.CheckPow(pow.Default, time.Now()) {
		return nil, grpc.Errorf(codes.InvalidArgument, "invalid proof of work")
	}

	rpcLog.Trace("SendObject: Object will be sent out into the network.")

	// Relay object to object manager which will handle insertion and
	// advertisement.
	counter := s.server.objectManager.HandleInsert(objMsg)
	if counter == 0 {
		return nil, grpc.Errorf(codes.Internal, "failed to insert and advertise object")
	}

	return &pb.SendObjectReply{
		Counter: counter,
	}, nil
}

// GetIdentity returns the stored public key associated with the given
// Bitmessage address.
func (s *rpcServer) GetIdentity(ctx context.Context, in *pb.GetIdentityRequest) (*pb.GetIdentityReply, error) {
	if code := s.RestrictAuth(ctx); code != codes.OK {
		return nil, grpc.Errorf(code, "auth failure")
	}

	address, err := bmutil.DecodeAddress(in.Address)
	if err != nil {
		return nil, grpc.Errorf(codes.InvalidArgument, "address decode failed: %v",
			err)
	}

	pubID, err := s.server.db.FetchIdentityByAddress(address)
	if err == database.ErrNonexistentObject {
		return nil, grpc.Errorf(codes.NotFound, "identity not found")
	} else if err != nil {
		rpcLog.Errorf("FetchIdentityByAddress, database error: %v", err)
		return nil, grpc.Errorf(codes.Internal, "database error")
	}

	data := pubID.Data()
	return &pb.GetIdentityReply{
		NonceTrials:   data.Pow.NonceTrialsPerByte,
		ExtraBytes:    data.Pow.ExtraBytes,
		Behavior:      data.Behavior,
		SigningKey:    data.Verification.Bytes(),
		EncryptionKey: data.Encryption.Bytes(),
	}, nil
}

// GetObjects retrieves objects of a particular type starting from a particular
// counter value from the database and streams them to the client.
func (s *rpcServer) GetObjects(in *pb.GetObjectsRequest, stream pb.Bmd_GetObjectsServer) error {
	ctx := stream.Context()
	if code := s.RestrictAuth(ctx); code != codes.OK {
		return grpc.Errorf(code, "auth failure")
	}

	if in.FromCounter == 0 {
		return grpc.Errorf(codes.InvalidArgument, "from_counter cannot be 0")
	}

	// fromCounter is updated after each iteration of the loop and set to the
	// value of the last element+1.
	fromCounter := in.FromCounter
	objType := wire.ObjectType(in.ObjectType)
	cond := s.objConds[objType.String()]

	for {
		objs, lastCount, err := s.server.db.FetchObjectsFromCounter(objType,
			fromCounter, rpcCounterObjectsSize)
		if err != nil {
			rpcLog.Errorf("FetchObjectsFromCounter, database error: %v", err)
			return grpc.Errorf(codes.Internal, "database error")
		}

		// We ran out of more objects to send to the client, so wait until we have
		// more.
		if len(objs) == 0 {
			cond.L.Lock()
			cond.Wait()
			cond.L.Unlock()
			continue
		}

		// For next iteration.
		fromCounter = lastCount + 1

		// Send objects to client.
		for _, object := range objs {
			out := &pb.Object{
				Contents: wire.Encode(object.Object),
				Counter:  object.Counter,
			}
			err = stream.Send(out)
			if err != nil {
				return grpc.Errorf(codes.DataLoss, "failed to send object: %v", err)
			}
		}
	}
}

// newRPCServer returns a new instance of the Server struct.
func newRPCServer(s *server, rpcCfg *rpc.Config) (*rpcServer, error) {

	rpc, err := rpc.NewRPCServer(rpcCfg)
	if err != nil {
		return nil, err
	}

	rpcServer := &rpcServer{
		Server: *rpc,
		server: s,
		objConds: map[string]*sync.Cond{
			wire.ObjectTypeGetPubKey.String(): sync.NewCond(&sync.Mutex{}),
			wire.ObjectTypePubKey.String():    sync.NewCond(&sync.Mutex{}),
			wire.ObjectTypeMsg.String():       sync.NewCond(&sync.Mutex{}),
			wire.ObjectTypeBroadcast.String(): sync.NewCond(&sync.Mutex{}),
			wire.ObjectType(999).String():     sync.NewCond(&sync.Mutex{}), // Unknown
		},
	}

	pb.RegisterBmdServer(rpc.GRPC(), rpcServer)

	return rpcServer, nil
}
