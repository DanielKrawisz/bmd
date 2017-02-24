// Copyright (c) 2015 Monetas.
// Copyright 2016 Daniel Krawisz.
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package peer

import (
	"errors"
	"fmt"
	prand "math/rand"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/DanielKrawisz/bmd/addrmgr"
	"github.com/DanielKrawisz/bmd/database"
	"github.com/DanielKrawisz/bmutil/hash"
	"github.com/DanielKrawisz/bmutil/wire"
)

const (
	// maxProtocolVersion is the max protocol version the peer supports.
	maxProtocolVersion = 3

	// outputBufferSize is the number of elements the output channels use.
	outputBufferSize = 50

	// invTrickleSize is the maximum amount of inventory to send in a single
	// message when trickling inventory to remote peers.
	maxInvTrickleSize = 1000

	// maxKnownInventory is the maximum number of items to keep in the known
	// inventory cache.
	// Originally this was set at 1000, but until there is more intelligent
	// behavior from the object manager, this must be set at MaxInvPerMsg.
	maxKnownInventory = wire.MaxInvPerMsg

	// negotiateTimeoutSeconds is the number of seconds of inactivity before
	// we timeout a peer that hasn't completed the initial version
	// negotiation.
	negotiateTimeoutSeconds = 30

	// idleTimeoutMinutes is the number of minutes of inactivity before
	// we time out a peer. Must be > 5 because that is the time interval
	// at which pongs are sent.
	idleTimeoutMinutes = 6

	// pingTimeoutMinutes is the number of minutes since we last sent a
	// message requiring a reply before we will ping a host.
	pingTimeoutMinutes = 5

	// MaxPeerRequests is the maximum number of outstanding object requests a
	// may have at any given time.
	MaxPeerRequests = 120
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

type server interface {
	Nonce() uint64
	AddrManager() *addrmgr.AddrManager
	ObjectManager() ObjectManager
	Db() database.Db
	DonePeer(*Peer)
}

// ObjectManager represents the object manager. It is returned by the server
// when the ObjectManager function is called.
type ObjectManager interface {
	NewPeer(*Peer)
	DonePeer(*Peer)
	ReadyPeer(*Peer)
	QueueInv(inv *wire.MsgInv, p *Peer)
	QueueObject(inv *wire.MsgObject, p *Peer)
}

// Peer provides for the handling of messages from a bitmessage peer.
// For inbound data-related messages such as objects and inventory, the data is
// passed on to the object manager to handle it. Outbound messages are queued
// via a Send object. In addition, the peer contains several functions which
// are of the form pushX, that are used to push messages to the peer. Internally
// they use QueueMessage.
type Peer struct {
	Persistent bool
	Inbound    bool

	Inventory *Inventory
	server    server
	send      Send
	conn      Connection

	// Some variables only to be used atomically which tell the state of the
	// peer.
	started    int32 // whether the peer has started.
	disconnect int32 // Whether a disconnect is scheduled.

	// Whether the peer has received its first inv. This is when it signals
	// to the object manager that it is ready to start downloading.
	invReceived bool

	// signalReady determines when the peer tells the object manager that it
	// is ready to request more objects from the remote peer. It does this
	// when the number of requested objects falls to this amount.
	signalReady int

	// The set of addresses known to this peer.
	knownAddresses map[string]struct{}

	StatsMtx          sync.RWMutex // protects all statistics below here.
	na                *wire.NetAddress
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
func (p *Peer) VersionKnown() bool {
	p.StatsMtx.RLock()
	defer p.StatsMtx.RUnlock()

	return p.versionKnown
}

// HandshakeComplete returns the whether or the initial handshake has been
// successfully completed. It is safe for concurrent access.
func (p *Peer) HandshakeComplete() bool {
	p.StatsMtx.RLock()
	defer p.StatsMtx.RUnlock()

	return p.handshakeComplete
}

// PrependAddr is a helper function for logging that adds the ip address to
// the start of the string to be logged.
func (p *Peer) PrependAddr(str string) string {
	return fmt.Sprintf("%s : %s", p.Addr().String(), str)
}

// Addr returns the address of the remote peer in the form of a net.Addr
func (p *Peer) Addr() net.Addr {
	return p.conn.RemoteAddr()
}

// NetAddress returns the net address of the remote peer. It may be nil.
func (p *Peer) NetAddress() *wire.NetAddress {
	p.StatsMtx.RLock()
	defer p.StatsMtx.RUnlock()

	return p.na
}

// Connected returns whether or not the peer is currently connected.
func (p *Peer) Connected() bool {
	return p.conn.Connected() &&
		atomic.LoadInt32(&p.started) > 0 &&
		atomic.LoadInt32(&p.disconnect) == 0
}

// Disconnect disconnects the peer by closing the connection and signals to
// the server and object manager that the peer is done. It also sets
// a flag so the impending shutdown can be detected.
func (p *Peer) Disconnect() {
	log.Info(p.PrependAddr("Disconnecting."))
	// Already stopping?
	if atomic.AddInt32(&p.disconnect, 1) != 1 {
		return
	}

	// Don't stop if we're not running.
	if atomic.LoadInt32(&p.started) == 0 {
		return
	}

	if p.conn.Connected() {
		p.conn.Close()
	}
	p.send.Stop()

	atomic.StoreInt32(&p.started, 0)

	// Only tell object manager we are gone if we ever told it we existed.
	if p.HandshakeComplete() {
		p.server.ObjectManager().DonePeer(p)
	}

	p.server.DonePeer(p)
	log.Info(p.PrependAddr("Disconnected."))
	atomic.StoreInt32(&p.disconnect, 0)
}

// Start starts running the peer.
func (p *Peer) Start() error {
	if atomic.AddInt32(&p.started, 1) != 1 {
		return nil
	}
	log.Info(p.PrependAddr("Starting."))

	if !p.conn.Connected() {
		err := p.connect()
		if err != nil {
			atomic.StoreInt32(&p.started, 0)
			return err
		}
	}

	p.send.Start(p.conn)

	// Start processing input and output.
	go p.inHandler(negotiateTimeoutSeconds, idleTimeoutMinutes)

	if !p.Inbound {
		p.PushVersionMsg()
	}
	log.Info(p.PrependAddr("Started."))
	return nil
}

// connect connects the peer object to the remote peer if it is not already
// connected.
func (p *Peer) connect() error {
	if p.conn.Connected() {
		return nil
	}

	if atomic.LoadInt32(&p.disconnect) != 0 {
		return errors.New("Disconnection in progress.")
	}

	err := p.conn.Connect()
	if err != nil {
		return err
	}

	return nil
}

// ProtocolVersion returns the peer protocol version in a manner that is safe
// for concurrent access.
func (p *Peer) ProtocolVersion() uint32 {
	p.StatsMtx.RLock()
	defer p.StatsMtx.RUnlock()

	return p.protocolVersion
}

// PushVersionMsg sends a version message to the connected peer using the
// current state.
func (p *Peer) PushVersionMsg() {
	if p.versionSent {
		log.Error(p.PrependAddr("For some reason we are trying to send a version message a second time."))
		return
	}

	theirNa := p.NetAddress()
	// p.Na could be nil if this is an inbound peer but the version message
	// has not yet been processed.
	if theirNa == nil {
		return
	}

	// Version message.
	msg := wire.NewMsgVersion(
		p.server.AddrManager().GetBestLocalAddress(theirNa), theirNa,
		p.server.Nonce(), defaultStreamList)
	msg.AddUserAgent(userAgentName, userAgentVersion)

	msg.AddrYou.Services = wire.SFNodeNetwork
	msg.Services = wire.SFNodeNetwork

	// Advertise our max supported protocol version.
	msg.ProtocolVersion = maxProtocolVersion

	p.QueueMessage(msg)

	p.StatsMtx.Lock()
	p.versionSent = true
	p.StatsMtx.Unlock()

	log.Debug(p.PrependAddr("Version message sent."))
}

// PushVerAckMsg sends a ver ack to the remote peer.
func (p *Peer) PushVerAckMsg() {
	p.QueueMessage(&wire.MsgVerAck{})
	log.Debug(p.PrependAddr("Ver ack message sent."))
}

// PushGetDataMsg creates a GetData message and sends it to the remote peer.
func (p *Peer) PushGetDataMsg(ivl []*wire.InvVect) {
	if len(ivl) == 0 {
		return
	}

	p.Inventory.AddRequest(len(ivl))
	if p.Inventory.NumRequests() > MaxPeerRequests/2 {
		p.signalReady = p.Inventory.NumRequests() / 2
	} else {
		p.signalReady = 0
	}
	log.Debug(p.PrependAddr(fmt.Sprint(len(ivl),
		" requests assigned for a total of ", p.Inventory.NumRequests(),
		"; signal ready at ", p.signalReady)))

	x := 0
	for len(ivl)-x > wire.MaxInvPerMsg {
		p.QueueMessage(&wire.MsgInv{InvList: ivl[x : x+wire.MaxInvPerMsg]})
		log.Debug(p.PrependAddr(fmt.Sprint("get data message sent with ", wire.MaxInvPerMsg, " hashes.")))
		x += wire.MaxInvPerMsg
	}

	if len(ivl)-x > 0 {
		p.QueueMessage(&wire.MsgGetData{InvList: ivl[x:]})
		log.Debug(p.PrependAddr(fmt.Sprint("Get data message sent with ", len(ivl)-x, " hashes.")))
	}
}

// PushInvMsg creates and sends an Inv message and sends it to the remote peer.
func (p *Peer) PushInvMsg(invVect []*wire.InvVect) {
	ivl := p.Inventory.FilterKnown(invVect)

	x := 0
	for len(ivl)-x > wire.MaxInvPerMsg {
		p.QueueMessage(&wire.MsgInv{InvList: ivl[x : x+wire.MaxInvPerMsg]})
		log.Debug(p.PrependAddr(fmt.Sprint("Inv message sent with ", wire.MaxInvPerMsg, " hashes.")))
		x += wire.MaxInvPerMsg
	}

	if len(ivl)-x > 0 {
		p.QueueMessage(&wire.MsgInv{InvList: ivl[x:]})
		log.Debug(p.PrependAddr(fmt.Sprint("Inv message sent with ", len(ivl)-x, " hashes.")))
	}
}

// PushObjectMsg sends an object message for the provided object hash to the
// connected peer.  An error is returned if the object hash is not known.
func (p *Peer) PushObjectMsg(sha *hash.Sha) {
	obj, err := p.server.Db().FetchObjectByHash(sha)
	if err != nil {
		return
	}

	p.QueueMessage(obj)
}

// PushAddrMsg sends one, or more, addr message(s) to the connected peer using
// the provided addresses.
func (p *Peer) PushAddrMsg(addresses []*wire.NetAddress) error {
	// Nothing to send.
	if len(addresses) == 0 {
		return errors.New("Address list is empty.")
	}

	r := prand.New(prand.NewSource(time.Now().UnixNano()))
	numAdded := 0
	msg := wire.NewMsgAddr()
	for _, Na := range addresses {
		if Na == nil {
			continue
		}

		// Filter addresses the peer already knows about.
		if _, exists := p.knownAddresses[addrmgr.NetAddressKey(Na)]; exists {
			continue
		}

		// If the maxAddrs limit has been reached, randomize the list
		// with the remaining addresses.
		if numAdded == wire.MaxAddrPerMsg {
			msg.AddrList[r.Intn(wire.MaxAddrPerMsg)] = Na
			continue
		}

		// Add the address to the message.
		err := msg.AddAddress(Na)
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
		log.Debug(p.PrependAddr(fmt.Sprint("Addr message sent with ", numAdded, " addresses.")))
		return nil
	}
	return errors.New("No addresses added.")
}

// QueueMessage takes a message and sends it to the remote peer.
func (p *Peer) QueueMessage(msg wire.Message) {
	p.send.QueueMessage(msg)
}

// updateAddresses adds the remote address of the peer to the address manager.
func (p *Peer) updateAddresses() {
	// A peer might not be advertising the same address that it
	// actually connected from. One example of why this can happen
	// is with NAT. Only add the actual address to the address manager.
	na := p.NetAddress()
	addrMgr := p.server.AddrManager()
	addrMgr.AddAddress(na, na)
	addrMgr.Good(na)
}

// HandleVersionMsg is invoked when a peer receives a version bitmessage message
// and is used to negotiate the protocol version details as well as kick start
// the communications.
func (p *Peer) HandleVersionMsg(msg *wire.MsgVersion) error {
	// Detect self connections.
	if msg.Nonce == p.server.Nonce() {
		return errors.New("Self connection detected.")
	}

	// Updating a bunch of stats.
	p.StatsMtx.Lock()

	// Limit to one version message per peer.
	if p.versionKnown {
		p.StatsMtx.Unlock()

		return errors.New("Only one version message allowed per peer.")
	}

	log.Debug(p.PrependAddr("Version msg received."))
	p.versionKnown = true

	// Set the supported services for the peer to what the remote peer
	// advertised.
	p.services = msg.Services

	// Set the remote peer's user agent.
	p.userAgent = msg.UserAgent

	p.StatsMtx.Unlock()

	// Inbound connections.
	if p.Inbound {
		// Set up a NetAddress for the peer to be used with addrManager.
		// We only do this inbound because outbound set this up
		// at connection time and no point recomputing.
		// We only use the first stream number for now because bitmessage has
		// only one stream.

		addr := p.Addr().String()
		host, portStr, err := net.SplitHostPort(addr)
		if err != nil {
			return err
		}

		port, err := strconv.ParseUint(portStr, 10, 16)
		if err != nil {
			return err
		}

		na, err := p.server.AddrManager().HostToNetAddress(host, uint16(port), msg.StreamNumbers[0], p.services)
		if err != nil {
			return fmt.Errorf("Can't send version message: %s", err)
		}

		p.StatsMtx.Lock()
		p.na = na
		p.StatsMtx.Unlock()

		// Send version.
		p.PushVersionMsg()
	}

	// Send verack.
	p.QueueMessage(wire.NewMsgVerAck())

	// Update the address manager.
	p.updateAddresses()

	p.server.AddrManager().Connected(p.NetAddress())
	p.handleInitialConnection()
	return nil
}

// HandleVerAckMsg disconnects if the VerAck was received at the wrong time
// and otherwise updates the peer's state.
func (p *Peer) HandleVerAckMsg() error {
	p.StatsMtx.RLock()
	versionSent := p.versionSent
	p.StatsMtx.RUnlock()
	// If no version message has been sent disconnect.
	if !versionSent {
		log.Error(p.PrependAddr("Ver ack msg received before version sent."))
		return errors.New("Version not yet received.")
	}
	log.Debug(p.PrependAddr("Ver ack msg received."))

	p.verAckReceived = true
	p.server.AddrManager().Connected(p.NetAddress())
	p.handleInitialConnection()
	return nil
}

// HandleInvMsg is invoked when a peer receives an inv bitmessage message and is
// used to examine the inventory being advertised by the remote peer and react
// accordingly. We pass the message down to objectmanager which will call
// QueueMessage with any appropriate responses.
func (p *Peer) HandleInvMsg(msg *wire.MsgInv) error {
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

	log.Debug(p.PrependAddr(fmt.Sprint("Inv received with ", len(msg.InvList), " hashes.")))

	// If this is the first inv we've received,
	// signal the object manager that a new peer has connected.
	if !p.invReceived {
		// Signal the object manager that a new peer has been connected.
		p.server.ObjectManager().NewPeer(p)
		p.invReceived = true
	}

	// Add to known inventory.
	for _, iv := range msg.InvList {
		// Add inv to known inventory.
		p.Inventory.AddKnown(iv)
	}

	p.server.ObjectManager().QueueInv(msg, p)
	p.server.AddrManager().Connected(p.NetAddress())
	return nil
}

// HandleGetDataMsg is invoked when a peer receives a getdata message and
// is used to deliver object information.
func (p *Peer) HandleGetDataMsg(msg *wire.MsgGetData) error {
	if !p.HandshakeComplete() {
		return errors.New("Handshake not complete.")
	}
	log.Debug(p.PrependAddr(fmt.Sprint("GetData request received for ", len(msg.InvList), " objects.")))

	err := p.send.QueueDataRequest(msg.InvList)
	if err != nil {
		return err
	}
	p.server.AddrManager().Connected(p.NetAddress())
	return nil
}

// HandleObjectMsg updates the peer's request list and sends the object to
// the object manager.
func (p *Peer) HandleObjectMsg(msg *wire.MsgObject) error {
	if !p.HandshakeComplete() {
		return errors.New("Handshake not complete.")
	}

	p.Inventory.AddRequest(-1)

	p.server.ObjectManager().QueueObject(msg, p)

	// signal object manager that we are ready to download more.
	if p.signalReady == p.Inventory.NumRequests() || p.Inventory.NumRequests() == 0 {
		p.server.ObjectManager().ReadyPeer(p)
	}
	p.server.AddrManager().Connected(p.NetAddress())

	return nil
}

// HandleAddrMsg is invoked when a peer receives an addr bitmessage message and
// is used to notify the server about advertised addresses.
func (p *Peer) HandleAddrMsg(msg *wire.MsgAddr) error {
	if !p.HandshakeComplete() {
		return errors.New("Handshake not complete.")
	}

	// A message that has no addresses is invalid.
	if len(msg.AddrList) == 0 {
		return errors.New("Empty addr message received.")
	}

	for _, Na := range msg.AddrList {

		// Set the timestamp to 5 days ago if it's more than 24 hours
		// in the future so this address is one of the first to be
		// removed when space is needed.
		now := time.Now()
		if Na.Timestamp.After(now.Add(time.Minute * 10)) {
			Na.Timestamp = now.Add(-1 * time.Hour * 24 * 5)
		}

		// Add address to known addresses for this peer.
		p.knownAddresses[addrmgr.NetAddressKey(Na)] = struct{}{}
	}

	log.Debug(p.PrependAddr(fmt.Sprint("addr message with ",
		len(msg.AddrList), " addrs. Peer has ", len(p.knownAddresses), " addrs.")))

	// Add addresses to server address manager. The address manager handles
	// the details of things such as preventing duplicate addresses, max
	// addresses, and last seen updates.
	na := p.NetAddress()
	p.server.AddrManager().AddAddresses(msg.AddrList, na)
	p.server.AddrManager().Connected(na)
	return nil
}

// HandleRelayInvMsg takes an inv list and queues it to be sent to the remote
// peer eventually.
func (p *Peer) HandleRelayInvMsg(inv []*wire.InvVect) error {
	ivl := p.Inventory.FilterKnown(inv)

	if len(ivl) == 0 {
		return nil
	}

	// Queue the inventory to be relayed with the next batch.
	// It will be ignored if the peer is already known to
	// have the inventory.
	p.send.QueueInventory(ivl)
	return nil
}

// handleInitialConnection is called once the initial handshake is complete.
func (p *Peer) handleInitialConnection() {
	if !(p.VersionKnown() && p.verAckReceived) {
		return
	}
	// The initial handshake is complete.

	p.StatsMtx.Lock()
	p.handshakeComplete = true
	p.StatsMtx.Unlock()

	// Send a big addr message.
	p.PushAddrMsg(p.server.AddrManager().AddressCache())

	// Send a big inv message.
	hashes, err := p.server.Db().FetchRandomInvHashes(wire.MaxInvPerMsg)
	if err != nil {
		log.Errorf("FetchRandomInvHashes failed: %v", err)
		return
	}
	p.PushInvMsg(hashes)
	log.Debug(p.PrependAddr("Handshake complete."))
}

// inHandler handles all incoming messages for the peer. It must be run as a
// goroutine.
func (p *Peer) inHandler(handshakeTimeoutSeconds, idleTimeoutMinutes uint) {
	// peers must complete the initial version negotiation within a shorter
	// timeframe than a general idle timeout. The timer is then reset below
	// to idleTimeoutMinutes for all future messages.
	idleTimer := time.AfterFunc(time.Duration(handshakeTimeoutSeconds)*time.Second, func() {
		log.Error(p.PrependAddr("Disconnecting due to idle time out."))
		p.Disconnect()
	})

out:
	for atomic.LoadInt32(&p.disconnect) == 0 {
		rmsg, err := p.conn.ReadMessage()
		// Stop the timer now, if we go around again we will reset it.
		idleTimer.Stop()
		if err != nil && err != errNoConnection {
			log.Debugf(p.PrependAddr("Invalid message received: "), err)
			// Ignore messages we don't understand.
			continue
		}
		if rmsg == nil {
			break out
		}

		// Handle each supported message type.
		err = nil
		switch msg := rmsg.(type) {
		case *wire.MsgVersion:
			err = p.HandleVersionMsg(msg)

		case *wire.MsgVerAck:
			err = p.HandleVerAckMsg()

		case *wire.MsgAddr:
			err = p.HandleAddrMsg(msg)

		case *wire.MsgInv:
			err = p.HandleInvMsg(msg)

		case *wire.MsgGetData:
			err = p.HandleGetDataMsg(msg)

		case *wire.MsgObject:
			err = p.HandleObjectMsg(msg)

		case *wire.MsgPong:

		default:
			log.Warn(p.PrependAddr("Invalid message processed. This should not happen."))
			break out
		}

		if err != nil {
			log.Error(p.PrependAddr("Error handling message: "), err)
			break out
		}

		idleTimer.Reset(time.Duration(idleTimeoutMinutes) * time.Minute)
	}

	idleTimer.Stop()

	// Ensure connection is closed and notify the server that the peer is
	// done.
	p.Disconnect()
}

// NewPeer returns a new base bitmessage peer for the provided server and
// inbound flag. This is used by the newInboundPeer and newOutboundPeer
// functions to perform base setup needed by both types of peers.
func NewPeer(s server, conn Connection, inventory *Inventory, send Send,
	na *wire.NetAddress, inbound, persistent bool) *Peer {
	p := &Peer{
		server:          s,
		conn:            conn,
		protocolVersion: maxProtocolVersion,
		services:        wire.SFNodeNetwork,
		Inventory:       inventory,
		send:            send,
		knownAddresses:  make(map[string]struct{}),
		Persistent:      persistent,
		Inbound:         inbound,
		na:              na,
	}

	return p
}

// NewPeerHandshakeComplete creates a new peer object that has already nearly
// completed its initial handshake. It just needs to be sent a ver ack.
// This function exists mainly for testing purposes.
func NewPeerHandshakeComplete(s server, conn Connection, inventory *Inventory, send Send,
	na *wire.NetAddress) *Peer {
	p := &Peer{
		server:          s,
		conn:            conn,
		protocolVersion: maxProtocolVersion,
		services:        wire.SFNodeNetwork,
		Inbound:         true,
		Inventory:       inventory,
		send:            send,
		versionSent:     true,
		versionKnown:    true,
		userAgent:       wire.DefaultUserAgent,
		na:              na,
	}

	return p
}
