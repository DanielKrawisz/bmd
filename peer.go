// Originally derived from: btcsuite/btcd/peer.go
// Copyright (c) 2013-2015 Conformal Systems LLC.

// Copyright (c) 2015 Monetas.
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"errors"
	"fmt"
	prand "math/rand"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/monetas/bmd/addrmgr"
	"github.com/monetas/bmd/peer"
	"github.com/monetas/bmutil/wire"
)

const (
	// maxProtocolVersion is the max protocol version the peer supports.
	maxProtocolVersion = 3
)

var (
	defaultStreamList = []uint32{1}

	// userAgentName is the user agent name and is used to help identify
	// ourselves to other bitmessage peers.
	userAgentName = "bmd"

	// userAgentVersion is the user agent version and is used to help
	// identify ourselves to other bitmessage peers.
	userAgentVersion = fmt.Sprintf("%d.%d.%d", 0, 0, 1)
)

// peer implements peer.Logic and provides for the handling of messages
// from a bitmessage peer. For inbound data-related messages such as
// objects and inventory, the data is passed on to the object
// manager to handle it. Outbound messages are queued via a SendQueue object.
// QueueMessage is intended for all messages. In addition, the
// peer contains several functions which are of the form pushX, that are used
// to push messages to the peer. Internally they use QueueMessage.
type bmpeer struct {
	Persistent        bool
	RetryCount        int64
	server            *server
	peer              *peer.Peer
	bmnet             wire.BitmessageNet
	send              peer.Send
	inventory         *peer.Inventory
	addr              net.Addr
	na                *wire.NetAddress
	inbound           bool
	knownAddresses    map[string]struct{}
	StatsMtx          sync.Mutex // protects all statistics below here.
	versionKnown      bool
	versionSent       bool
	verAckReceived    bool
	handshakeComplete bool
	protocolVersion   uint32
	services          wire.ServiceFlag
	userAgent         string
}

// VersionKnown returns the whether or not the version of a peer is known locally.
// It is safe for concurrent access.
func (p *bmpeer) VersionKnown() bool {
	p.StatsMtx.Lock()
	defer p.StatsMtx.Unlock()

	return p.versionKnown
}

// HandshakeComplete returns the whether or the initial handshake has been
// successfully completed. It is safe for concurrent access.
func (p *bmpeer) HandshakeComplete() bool {
	p.StatsMtx.Lock()
	defer p.StatsMtx.Unlock()

	return p.handshakeComplete
}

// disconnect disconnects the peer.
func (p *bmpeer) disconnect() {
	p.peer.Disconnect()

	// Only tell object manager we are gone if we ever told it we existed.
	if p.HandshakeComplete() {
		p.server.objectManager.DonePeer(p)
	}

	p.server.donePeers <- p
}

// Start starts running the peer.
func (p *bmpeer) Start() {
	p.peer.Start()
	if !p.inbound {
		p.PushVersionMsg()
	}
}

// ProtocolVersion returns the peer protocol version in a manner that is safe
// for concurrent access.
func (p *bmpeer) ProtocolVersion() uint32 {
	p.StatsMtx.Lock()
	defer p.StatsMtx.Unlock()

	return p.protocolVersion
}

// PushVersionMsg sends a version message to the connected peer using the
// current state.
func (p *bmpeer) PushVersionMsg() {
	if p.versionSent {
		return
	}

	theirNa := p.na
	// p.na could be nil if this is an inbound peer but the version message
	// has not yet been processed.
	if theirNa == nil {
		return
	}

	// Version message.
	msg := wire.NewMsgVersion(
		p.server.addrManager.GetBestLocalAddress(p.na), theirNa,
		p.server.nonce, defaultStreamList)
	msg.AddUserAgent(userAgentName, userAgentVersion)

	msg.AddrYou.Services = wire.SFNodeNetwork
	msg.Services = wire.SFNodeNetwork

	// Advertise our max supported protocol version.
	msg.ProtocolVersion = maxProtocolVersion

	p.QueueMessage(msg)

	p.versionSent = true
}

// PushVerAckMsg sends a ver ack to the remote peer.
func (p *bmpeer) PushVerAckMsg() {
	p.QueueMessage(&wire.MsgVerAck{})
}

func max(x, y int) int {
	if x > y {
		return x
	}
	return y
}

// PushGetDataMsg creates a GetData message and sends it to the remote peer.
func (p *bmpeer) PushGetDataMsg(invVect []*wire.InvVect) {
	ivl := p.inventory.FilterRequested(invVect)

	if len(ivl) == 0 {
		return
	}

	x := 0
	for len(ivl)-x > wire.MaxInvPerMsg {
		p.QueueMessage(&wire.MsgInv{InvList: ivl[x : x+wire.MaxInvPerMsg]})
		x += wire.MaxInvPerMsg
	}

	if len(ivl)-x > 0 {
		p.QueueMessage(&wire.MsgGetData{InvList: ivl[x:]})
	}
}

// PushInvMsg creates and sends an Inv message and sends it to the remote peer.
func (p *bmpeer) PushInvMsg(invVect []*wire.InvVect) {
	ivl := p.inventory.FilterKnown(invVect)

	x := 0
	for len(ivl)-x > wire.MaxInvPerMsg {
		p.QueueMessage(&wire.MsgInv{InvList: ivl[x : x+wire.MaxInvPerMsg]})
		x += wire.MaxInvPerMsg
	}

	if len(ivl)-x > 0 {
		p.QueueMessage(&wire.MsgInv{InvList: ivl[x:]})
	}
}

// PushObjectMsg sends an object message for the provided object hash to the
// connected peer.  An error is returned if the object hash is not known.
func (p *bmpeer) PushObjectMsg(sha *wire.ShaHash) {
	obj, err := p.server.db.FetchObjectByHash(sha)
	if err != nil {
		return
	}

	msg, err := wire.DecodeMsgObject(obj)
	if err != nil {
		return
	}
	p.QueueMessage(msg)
}

// pushAddrMsg sends one, or more, addr message(s) to the connected peer using
// the provided addresses.
func (p *bmpeer) PushAddrMsg(addresses []*wire.NetAddress) error {
	// Nothing to send.
	if len(addresses) == 0 {
		return errors.New("Address list is empty.")
	}

	r := prand.New(prand.NewSource(time.Now().UnixNano()))
	numAdded := 0
	msg := wire.NewMsgAddr()
	for _, na := range addresses {
		// Filter addresses the peer already knows about.
		if _, exists := p.knownAddresses[addrmgr.NetAddressKey(na)]; exists {
			continue
		}

		// If the maxAddrs limit has been reached, randomize the list
		// with the remaining addresses.
		if numAdded == wire.MaxAddrPerMsg {
			msg.AddrList[r.Intn(wire.MaxAddrPerMsg)] = na
			continue
		}

		// Add the address to the message.
		err := msg.AddAddress(na)
		if err != nil {
			return errors.New("Address could not be added.")
		}
		numAdded++
	}
	if numAdded > 0 {
		for _, na := range msg.AddrList {
			// Add address to known addresses for this peer.
			p.knownAddresses[addrmgr.NetAddressKey(na)] = struct{}{}
		}

		p.QueueMessage(msg)
		return nil
	}
	return errors.New("No addresses added.")
}

// QueueMessage takes a message and sends it to the remote peer.
func (p *bmpeer) QueueMessage(msg wire.Message) {
	p.send.QueueMessage(msg)
}

// updateAddresses adds the remote address of the peer to the address manager.
func (p *bmpeer) updateAddresses() {
	// A peer might not be advertising the same address that it
	// actually connected from. One example of why this can happen
	// is with NAT. Only add the actual address to the address manager.
	p.server.addrManager.AddAddress(p.na, p.na)
	p.server.addrManager.Good(p.na)
}

// HandleVersionMsg is invoked when a peer receives a version bitmessage message
// and is used to negotiate the protocol version details as well as kick start
// the communications.
func (p *bmpeer) HandleVersionMsg(msg *wire.MsgVersion) error {
	// Detect self connections.
	if msg.Nonce == p.server.nonce {
		return errors.New("Self connection detected.")
	}

	// Updating a bunch of stats.
	p.StatsMtx.Lock()

	// Limit to one version message per peer.
	if p.versionKnown {
		p.StatsMtx.Unlock()

		return errors.New("Only one version message allowed per peer.")
	}
	p.versionKnown = true

	// Set the supported services for the peer to what the remote peer
	// advertised.
	p.services = msg.Services

	// Set the remote peer's user agent.
	p.userAgent = msg.UserAgent

	p.StatsMtx.Unlock()

	// Inbound connections.
	if p.inbound {
		// Set up a NetAddress for the peer to be used with addrManager.
		// We only do this inbound because outbound set this up
		// at connection time and no point recomputing.
		// We only use the first stream number for now because bitmessage has
		// only one stream.
		na, err := wire.NewNetAddress(p.addr, uint32(msg.StreamNumbers[0]), p.services)
		if err != nil {
			return fmt.Errorf("Can't send version message: %s", err)
		}
		p.na = na

		// Send version.
		p.PushVersionMsg()
	}

	// Send verack.
	p.QueueMessage(wire.NewMsgVerAck())

	// Update the address manager.
	p.updateAddresses()

	p.server.addrManager.Connected(p.na)
	p.handleInitialConnection()
	return nil
}

// HandleVerAckMsg disconnects if the VerAck was received at the wrong time
// and otherwise updates the peer's state.
func (p *bmpeer) HandleVerAckMsg() error {
	// If no version message has been sent disconnect.
	if !p.versionSent {
		return errors.New("Version not yet received.")
	}

	p.verAckReceived = true
	p.server.addrManager.Connected(p.na)
	p.handleInitialConnection()
	return nil
}

// HandleInvMsg is invoked when a peer receives an inv bitmessage message and is
// used to examine the inventory being advertised by the remote peer and react
// accordingly. We pass the message down to objectmanager which will call
// QueueMessage with any appropriate responses.
func (p *bmpeer) HandleInvMsg(msg *wire.MsgInv) error {
	if !p.HandshakeComplete() {
		return errors.New("Handshake not complete.")
	}

	// Disconnect if the message is too big.
	if len(msg.InvList) > wire.MaxInvPerMsg {
		return errors.New("Inv too big.")
	}

	// Disconnect if the message is too big.
	if len(msg.InvList) == 0 {
		return errors.New("Empty inv received.")
	}

	p.server.objectManager.QueueInv(msg, p)
	p.server.addrManager.Connected(p.na)
	return nil
}

// HandleGetData is invoked when a peer receives a getdata message and
// is used to deliver object information.
func (p *bmpeer) HandleGetDataMsg(msg *wire.MsgGetData) error {
	if !p.HandshakeComplete() {
		return errors.New("Handshake not complete.")
	}

	err := p.send.QueueDataRequest(msg.InvList)
	if err != nil {
		return err
	}
	p.server.addrManager.Connected(p.na)
	return nil
}

// HandleObjectMsg updates the peer's request list and sends the object to
// the object manager.
func (p *bmpeer) HandleObjectMsg(msg wire.Message) error {
	if !p.HandshakeComplete() {
		return errors.New("Handshake not complete.")
	}

	p.inventory.DeleteRequest(&wire.InvVect{Hash: *wire.MessageHash(msg)})

	p.server.objectManager.QueueObject(msg, p)
	p.server.addrManager.Connected(p.na)

	return nil
}

// HandleAddrMsg is invoked when a peer receives an addr bitmessage message and
// is used to notify the server about advertised addresses.
func (p *bmpeer) HandleAddrMsg(msg *wire.MsgAddr) error {
	if !p.HandshakeComplete() {
		return errors.New("Handshake not complete.")
	}

	// A message that has no addresses is invalid.
	if len(msg.AddrList) == 0 {
		return errors.New("Empty addr message received.")
	}

	for _, na := range msg.AddrList {

		// Set the timestamp to 5 days ago if it's more than 24 hours
		// in the future so this address is one of the first to be
		// removed when space is needed.
		now := time.Now()
		if na.Timestamp.After(now.Add(time.Minute * 10)) {
			na.Timestamp = now.Add(-1 * time.Hour * 24 * 5)
		}

		// Add address to known addresses for this peer.
		p.knownAddresses[addrmgr.NetAddressKey(na)] = struct{}{}
	}

	// Add addresses to server address manager. The address manager handles
	// the details of things such as preventing duplicate addresses, max
	// addresses, and last seen updates.
	p.server.addrManager.AddAddresses(msg.AddrList, p.na)
	p.server.addrManager.Connected(p.na)
	return nil
}

// handleInitialConnection is called once the initial handshake is complete.
func (p *bmpeer) handleInitialConnection() {
	if !(p.VersionKnown() && p.verAckReceived) {
		return
	}
	//The initial handshake is complete.

	p.StatsMtx.Lock()
	p.handshakeComplete = true
	p.StatsMtx.Unlock()

	// Signal the object manager that a new peer has been connected.
	p.server.objectManager.NewPeer(p)

	// Send a big addr message.
	p.PushAddrMsg(p.server.addrManager.AddressCache())

	// Send a big inv message.
	hashes, _ := p.server.db.FetchRandomInvHashes(wire.MaxInvPerMsg,
		func(*wire.ShaHash, []byte) bool { return true })
	invVectList := make([]*wire.InvVect, len(hashes))
	for i, hash := range hashes {
		invVectList[i] = &wire.InvVect{Hash: hash}
	}
	p.PushInvMsg(invVectList)
}

// newPeerBase returns a new base bitmessage peer for the provided server and
// inbound flag. This is used by the newInboundPeer and newOutboundPeer
// functions to perform base setup needed by both types of peers.
func newPeerBase(addr net.Addr, s *server, inventory *peer.Inventory,
	send peer.Send, inbound, persistent bool, retries int64) *bmpeer {
	bmp := &bmpeer{
		server:          s,
		protocolVersion: maxProtocolVersion,
		bmnet:           wire.MainNet,
		services:        wire.SFNodeNetwork,
		inventory:       inventory,
		send:            send,
		addr:            addr,
		knownAddresses:  make(map[string]struct{}),
		inbound:         inbound,
		Persistent:      persistent,
		RetryCount:      retries,
	}
	return bmp
}

// newInboundPeer returns a new inbound bitmessage peer for the provided server and
// connection. Use Start to begin processing incoming and outgoing messages.
func newInboundPeer(s *server, conn peer.Connection) *bmpeer {
	inventory := peer.NewInventory()
	sq := peer.NewSend(inventory, s.db)
	bmp := newPeerBase(conn.RemoteAddr(), s, inventory, sq, true, false, 0)

	p := peer.NewPeer(bmp, conn, sq)
	bmp.peer = p
	return bmp
}

// Can be swapped out for testing purposes.
// TODO handle this more elegantly eventually.
var NewConn = peer.NewConnection

// newOutbountPeer returns a new outbound bitmessage peer for the provided server and
// address and connects to it asynchronously. If the connection is successful
// then the peer will also be started.
func newOutboundPeer(addr string, s *server, stream uint32, persistent bool, retryCount int64) *bmpeer {
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

	tcpAddr := &net.TCPAddr{IP: net.ParseIP(host), Port: int(port)}
	conn := NewConn(tcpAddr, int64(cfg.MaxDownPerPeer), int64(cfg.MaxUpPerPeer))
	inventory := peer.NewInventory()
	sq := peer.NewSend(inventory, s.db)
	logic := newPeerBase(tcpAddr, s, inventory, sq, false, persistent, retryCount)

	p := peer.NewPeer(logic, conn, sq)

	logic.addr = tcpAddr
	logic.na = na
	logic.peer = p

	go func() {
		// Wait for some time if this is a retry, and wait longer if we have
		// tried multiple times.
		if retryCount > 0 {
			scaledInterval := connectionRetryInterval.Nanoseconds() * retryCount / 2
			scaledDuration := time.Duration(scaledInterval)
			time.Sleep(scaledDuration)
		}

		logic.Start()

		s.addrManager.Attempt(na)
	}()
	return logic
}
