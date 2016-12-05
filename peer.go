// Originally derived from: btcsuite/btcd/peer.go
// Copyright (c) 2013-2015 Conformal Systems LLC.

// Copyright (c) 2015 Monetas.
// Copyright 2016 Daniel Krawisz.
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"net"
	"strconv"

	"github.com/DanielKrawisz/bmd/peer"
)

// NewConn is the function used to create new connections.
// Can be swapped out for testing purposes.
// TODO handle this more elegantly eventually.
var NewConn = peer.NewConnection

// NewInboundPeer returns a new inbound bitmessage peer for the provided server and
// connection. Use Start to begin processing incoming and outgoing messages.
func NewInboundPeer(s *server, conn peer.Connection) *peer.Peer {
	inventory := peer.NewInventory()
	sq := peer.NewSend(inventory, s.Db())
	return peer.NewPeer(s, conn, inventory, sq, nil, true, false)
}

// NewOutboundPeer returns a new outbound bitmessage peer for the provided server and
// address and connects to it asynchronously. If the connection is successful
// then the peer will also be started.
func NewOutboundPeer(addr string, s *server, stream uint32, persistent bool) *peer.Peer {
	// Setup p.na with a temporary address that we are connecting to with
	// faked up service flags. We will replace this with the real one after
	// version negotiation is successful. The only failure case here would
	// be if the string was incomplete for connection so can't be split
	// into address and port, and thus this would be invalid anyway. In
	// which case we return nil to be handled by the caller. This must be
	// done before we fork off the goroutine because as soon as this
	// function returns the peer must have a valid netaddress.
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return nil
	}

	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return nil
	}

	na, err := s.addrManager.HostToNetAddress(host, uint16(port), stream, 0)
	if err != nil {
		return nil
	}

	conn := NewConn((*peer.Addr)(na), int64(cfg.MaxDownPerPeer), int64(cfg.MaxUpPerPeer))
	inventory := peer.NewInventory()
	sq := peer.NewSend(inventory, s.db)
	p := peer.NewPeer(s, conn, inventory, sq, na, false, persistent)

	peerLog.Trace("NewOutboundPeer ", addr, " created.")
	return p
}
