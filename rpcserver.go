// Originally derived from: btcsuite/btcd/rpcserver.go
// Copyright (c) 2013-2015 The btcsuite developers.

// Copyright (c) 2015 Monetas.
// Copyright 2016 Daniel Krawisz.
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"io/ioutil"
	prand "math/rand"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	pb "github.com/DanielKrawisz/bmd/rpcproto"
	"github.com/DanielKrawisz/bmutil/wire"
	"github.com/btcsuite/btcutil"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
)

const (
	// rpcCounterObjectsSize is the number of objects that db.FetchObjectsFromCounter
	// will fetch per query to the database. This is used when a client requests
	// subscription to an object type from a specified counter value.
	rpcCounterObjectsSize = 100
)

// rpcServer holds the items the rpc server may need to access (config,
// shutdown, main server, etc.)
type rpcServer struct {
	server       *server
	rpcSrv       *grpc.Server
	listeners    []net.Listener
	limitauthsha [sha256.Size]byte
	authsha      [sha256.Size]byte
	mutex        sync.RWMutex
	started      int32
	shutdown     int32
	wg           sync.WaitGroup
	// Conds for notifying listening clients about pending objects. Key is the
	// string representation of the object type.
	objConds map[string]*sync.Cond
	quit     chan int
}

// genCertPair generates a key/cert pair to the paths provided.
func genCertPair(certFile, keyFile string) error {
	rpcLog.Infof("Generating TLS certificates...")

	org := "bmd autogenerated cert"
	validUntil := time.Now().Add(10 * 365 * 24 * time.Hour)
	cert, key, err := btcutil.NewTLSCertPair(org, validUntil, nil)
	if err != nil {
		return err
	}

	// Write cert and key files.
	if err = ioutil.WriteFile(certFile, cert, 0666); err != nil {
		return err
	}
	if err = ioutil.WriteFile(keyFile, key, 0600); err != nil {
		os.Remove(certFile)
		return err
	}

	rpcLog.Infof("Done generating TLS certificates")
	return nil
}

// restrictAuth restricts access of the client, returning an error if the client
// is not already authenticated.
func (s *rpcServer) restrictAuth(ctx context.Context) codes.Code {
	md, ok := metadata.FromContext(ctx)
	if !ok {
		return codes.Unauthenticated
	}
	login, ok := md["authorization"]
	if !ok {
		return codes.Unauthenticated
	}

	authsha := sha256.Sum256([]byte(login[0]))

	// Check for limited auth first as in environments with limited users, those
	// are probably expected to have a higher volume of calls
	limitcmp := subtle.ConstantTimeCompare(authsha[:], s.limitauthsha[:])
	if limitcmp == 1 {
		return codes.OK
	}

	// Check for admin-level auth
	cmp := subtle.ConstantTimeCompare(authsha[:], s.authsha[:])
	if cmp == 1 {
		return codes.OK
	}

	return codes.PermissionDenied
}

// restrictAdmin restricts access of the client, returning an error if the
// client is not already authenticated as an admin.
func (s *rpcServer) restrictAdmin(ctx context.Context) codes.Code {
	md, ok := metadata.FromContext(ctx)
	if !ok {
		return codes.Unauthenticated
	}
	login, ok := md["authorization"]
	if !ok {
		return codes.Unauthenticated
	}

	authsha := sha256.Sum256([]byte(login[0]))
	// Check for admin-level auth
	cmp := subtle.ConstantTimeCompare(authsha[:], s.authsha[:])
	if cmp == 1 {
		return codes.OK
	}

	return codes.PermissionDenied
}

// NotifyObject is used to notify the RPC server of any new objects so that it
// can send those onwards to the client.
func (s *rpcServer) NotifyObject(objType wire.ObjectType) {
	s.objConds[objType.String()].Broadcast()
}

// newRPCServer returns a new instance of the rpcServer struct.
func newRPCServer(listenAddrs []string, s *server) (*rpcServer, error) {

	// Setup TLS if not disabled.
	listenFunc := net.Listen
	var opts []grpc.ServerOption
	if !cfg.DisableTLS {
		if !fileExists(cfg.RPCKey) && !fileExists(cfg.RPCCert) {
			err := genCertPair(cfg.RPCCert, cfg.RPCKey)
			if err != nil {
				return nil, err
			}
		}

		creds, err := credentials.NewServerTLSFromFile(cfg.RPCCert, cfg.RPCKey)
		if err != nil {
			return nil, fmt.Errorf("Failed to generate credentials %v", err)
		}
		opts = []grpc.ServerOption{grpc.Creds(creds)}
	}

	rpc := rpcServer{
		server: s,
		rpcSrv: grpc.NewServer(opts...), // Create the underlying RPC server.
		quit:   make(chan int),
		objConds: map[string]*sync.Cond{
			wire.ObjectTypeGetPubKey.String(): sync.NewCond(&sync.Mutex{}),
			wire.ObjectTypePubKey.String():    sync.NewCond(&sync.Mutex{}),
			wire.ObjectTypeMsg.String():       sync.NewCond(&sync.Mutex{}),
			wire.ObjectTypeBroadcast.String(): sync.NewCond(&sync.Mutex{}),
			wire.ObjectType(999).String():     sync.NewCond(&sync.Mutex{}), // Unknown
		},
	}
	pb.RegisterBmdServer(rpc.rpcSrv, &rpc)

	if cfg.RPCUser != "" && cfg.RPCPass != "" {
		login := base64.StdEncoding.EncodeToString([]byte(cfg.RPCUser + ":" +
			cfg.RPCPass))
		rpc.authsha = sha256.Sum256([]byte("Basic " + login))
	}
	if cfg.RPCLimitUser != "" && cfg.RPCLimitPass != "" {
		login := base64.StdEncoding.EncodeToString([]byte(cfg.RPCLimitUser + ":" +
			cfg.RPCLimitPass))
		rpc.limitauthsha = sha256.Sum256([]byte("Basic " + login))
	}

	ipv4ListenAddrs, ipv6ListenAddrs, err := parseListeners(listenAddrs)
	if err != nil {
		return nil, err
	}
	listeners := make([]net.Listener, 0,
		len(ipv6ListenAddrs)+len(ipv4ListenAddrs))

	for _, addr := range ipv4ListenAddrs {
		listener, err := listenFunc("tcp4", addr)
		if err != nil {
			rpcLog.Warnf("Can't listen on %s: %v", addr, err)
			continue
		}
		listeners = append(listeners, listener)
	}

	for _, addr := range ipv6ListenAddrs {
		listener, err := listenFunc("tcp6", addr)
		if err != nil {
			rpcLog.Warnf("Can't listen on %s: %v", addr, err)
			continue
		}
		listeners = append(listeners, listener)
	}
	if len(listeners) == 0 {
		return nil, errors.New("RPC: No valid listen address")
	}

	rpc.listeners = listeners
	return &rpc, nil
}

// Stop is used by server.go to stop the rpc listener.
func (s *rpcServer) Stop() error {
	if atomic.AddInt32(&s.shutdown, 1) != 1 {
		rpcLog.Infof("RPC server is already in the process of shutting down")
		return nil
	}
	rpcLog.Warnf("RPC server shutting down")

	for _, listener := range s.listeners {
		err := listener.Close()
		if err != nil {
			rpcLog.Errorf("Problem shutting down rpc: %v", err)
			return err
		}
	}

	close(s.quit)
	s.wg.Wait()
	rpcLog.Infof("RPC server shutdown complete")
	return nil
}

// Start is used by server.go to start the rpc listener.
func (s *rpcServer) Start() {
	if atomic.AddInt32(&s.started, 1) != 1 {
		return
	}

	rpcLog.Trace("Starting RPC server")

	// Start listening on the listeners.
	for _, listener := range s.listeners {
		s.wg.Add(1)
		go func(listener net.Listener) {
			rpcLog.Infof("RPC server listening on %s", listener.Addr())
			s.rpcSrv.Serve(listener)
			rpcLog.Tracef("RPC listener done for %s", listener.Addr())
			s.wg.Done()
		}(listener)
	}
}

func init() {
	prand.Seed(time.Now().UnixNano())
}
