// Originally derived from: btcsuite/btcd/server.go
// Copyright (c) 2013-2015 Conformal Systems LLC.

// Copyright (c) 2015 Monetas.
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"net"
	"os/user"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/monetas/bmd/addrmgr"
	"github.com/monetas/bmd/peer"
	"github.com/monetas/bmd/database"
	"github.com/monetas/bmutil/wire"
)

const (
	// supportedServices describes which services are supported by the
	// server.
	supportedServices = wire.SFNodeNetwork

	// connectionRetryInterval is the amount of time to wait in between
	// retries when connecting to persistent peers.
	connectionRetryInterval = time.Second * 10

	// defaultMaxOutbound is the default number of max outbound peers.
	defaultMaxOutbound = 8

	// MaxPeers is the maximum number of peers that can be connected at a time.
	MaxPeers = 1000
	// BanDuration is the number of nanoseconds that a peer is banned.
	// This is about 15 minutes.
	BanDuration = 1000000
	// DefaultPort is the default port for listening for incoming connections.
	DefaultPort = 8444

	// DataDir specifies the path where bmd should store its data. $HOME would
	// be replaced with the home directory of the user that runs bmd.
	DataDir = "$HOME/.bmd"
)

// relayMsg packages an inventory vector along with the newly discovered
// inventory so the relay has access to that information.
type relayMsg struct {
	invVect *wire.InvVect
	data    interface{}
}

// The peerState is used by the server to keep track of what the peers it is
// connected to are up to.
type peerState struct {
	peers            map[*bmpeer]struct{}
	outboundPeers    map[*bmpeer]struct{}
	persistentPeers  map[*bmpeer]struct{}
	banned           map[string]time.Time
	outboundGroups   map[string]int
	maxOutboundPeers int
}

// Count returns the total number of peers.
func (p *peerState) Count() int {
	return len(p.peers) + len(p.outboundPeers) + len(p.persistentPeers)
}

// OutboundCount returns the number of outbound peers.
func (p *peerState) OutboundCount() int {
	return len(p.outboundPeers) + len(p.persistentPeers)
}

// NeedMoreOutbound returns whether more outbound peers are needed.
func (p *peerState) NeedMoreOutbound() bool {
	return p.OutboundCount() < p.maxOutboundPeers &&
		p.Count() < MaxPeers
}

// forAllOutboundPeers is a helper function that runs closure on all outbound
// peers known to peerState
func (p *peerState) forAllOutboundPeers(closure func(p *bmpeer)) {
	for e := range p.outboundPeers {
		closure(e)
	}
	for e := range p.persistentPeers {
		closure(e)
	}
}

// forAllPeers is a helper function that runs closure on all peers known to
// peerState.
func (p *peerState) forAllPeers(closure func(p *bmpeer)) {
	for e := range p.peers {
		closure(e)
	}
	p.forAllOutboundPeers(closure)
}

func newPeerState(maxOutbound int) *peerState {
	return &peerState{
		peers:            make(map[*bmpeer]struct{}),
		persistentPeers:  make(map[*bmpeer]struct{}),
		outboundPeers:    make(map[*bmpeer]struct{}),
		banned:           make(map[string]time.Time),
		maxOutboundPeers: maxOutbound,
		outboundGroups:   make(map[string]int),
	}
}

// DefaultPeer represents a peer that the server connects to by default.
type DefaultPeer struct {
	addr      string
	stream    uint32
	permanent bool
}

// The list of default peers.
var defaultPeers = []*DefaultPeer{
	&DefaultPeer{"5.45.99.75:8444", 1, true},
	&DefaultPeer{"75.167.159.54:8444", 1, true},
	&DefaultPeer{"95.165.168.168:8444", 1, true},
	&DefaultPeer{"85.180.139.241:8444", 1, true},
	&DefaultPeer{"158.222.211.81:8080", 1, true},
	&DefaultPeer{"178.62.12.187:8448", 1, true},
	&DefaultPeer{"24.188.198.204:8111", 1, true},
	&DefaultPeer{"109.147.204.113:1195", 1, true},
	&DefaultPeer{"178.11.46.221:8444", 1, true},
}

// server provides a bitmssage server for handling communications to and from
// bitcoin peers.
type server struct {
	nonce         uint64
	listeners     []peer.Listener
	started       int32 // atomic
	shutdown      int32 // atomic
	shutdownSched int32 // atomic
	addrManager   *addrmgr.AddrManager
	objectManager *ObjectManager
	state         *peerState
	newPeers      chan *bmpeer
	donePeers     chan *bmpeer
	banPeers      chan *bmpeer
	wakeup        chan struct{}
	query         chan interface{}
	relayInv      chan relayMsg
	wg            sync.WaitGroup
	quit          chan struct{}
	db            database.Db
}

// randomUint16Number returns a random uint16 in a specified input range. Note
// that the range is in zeroth ordering; if you pass it 1800, you will get
// values from 0 to 1800.
func randomUint16Number(max uint16) uint16 {
	// In order to avoid modulo bias and ensure every possible outcome in
	// [0, max) has equal probability, the random number must be sampled
	// from a random source that has a range limited to a multiple of the
	// modulus.
	var randomNumber uint16
	var limitRange = (math.MaxUint16 / max) * max
	for {
		binary.Read(rand.Reader, binary.LittleEndian, &randomNumber)
		if randomNumber < limitRange {
			return (randomNumber % max)
		}
	}
}

// handleAddPeerMsg deals with adding new peers. It is invoked from the
// peerHandler goroutine.
func (s *server) handleAddPeerMsg(p *bmpeer) bool {
	if p == nil {
		return false
	}

	// Ignore new peers if we're shutting down.
	if atomic.LoadInt32(&s.shutdown) != 0 {
		p.disconnect()
		return false
	}

	// Disconnect banned peers.
	host, _, err := net.SplitHostPort(p.addr.String())
	if err != nil {
		p.disconnect()
		return false
	}
	if banEnd, ok := s.state.banned[host]; ok {
		if time.Now().Before(banEnd) {
			p.disconnect()
			return false
		}

		delete(s.state.banned, host)
	}

	// TODO: Check for max peers from a single IP.

	// Limit max number of total peers.
	if s.state.Count() >= MaxPeers {
		p.disconnect()
		// TODO(oga) how to handle permanent peers here?
		// they should be rescheduled.
		return false
	}

	// Add the new peer and start it.
	if p.inbound {
		s.state.peers[p] = struct{}{}
		p.Start()
	} else {
		s.state.outboundGroups[addrmgr.GroupKey(p.na)]++
		if p.Persistent {
			s.state.persistentPeers[p] = struct{}{}
		} else {
			s.state.outboundPeers[p] = struct{}{}
		}
	}

	return true
}

// handleDonePeerMsg deals with peers that have signalled they are done. It is
// invoked from the peerHandler goroutine.
func (s *server) handleDonePeerMsg(p *bmpeer) {
	var list map[*bmpeer]struct{}
	if p.Persistent {
		list = s.state.persistentPeers
	} else if p.inbound {
		list = s.state.peers
	} else {
		list = s.state.outboundPeers
	}
	for e := range list {
		if e == p {
			// Issue an asynchronous reconnect if the peer was a
			// persistent outbound connection.
			if !p.inbound && p.Persistent && atomic.LoadInt32(&s.shutdown) == 0 {
				// TODO eventually we shouldn't work with addresses represented as strings at all.
				e = newOutboundPeer(p.addr.String(), s, p.na.Stream, true, p.RetryCount+1)
				return
			}
			if !p.inbound {
				s.state.outboundGroups[addrmgr.GroupKey(p.na)]--
			}
			delete(list, e)
			return
		}
	}
}

// handleBanPeerMsg deals with banning peers. It is invoked from the
// peerHandler goroutine.
func (s *server) handleBanPeerMsg(p *bmpeer) {
	host, _, err := net.SplitHostPort(p.addr.String())
	if err != nil {
		return
	}
	s.state.banned[host] = time.Now().Add(BanDuration)
}

// handleRelayInvMsg deals with relaying inventory to peers that are not already
// known to have it. It is invoked from the peerHandler goroutine.
// TODO
/*func (s *server) handleRelayInvMsg(msg relayMsg) {
	s.state.forAllPeers(func(p *peer) {
		if !p.Connected() {
			return
		}

		// Queue the inventory to be relayed with the next batch.
		// It will be ignored if the peer is already known to
		// have the inventory.
		p.sendQueue.QueueInventory(msg.invVect)
	})
}*/

type getConnCountMsg struct {
	reply chan int32
}

type addNodeMsg struct {
	addr      string
	stream    uint32
	permanent bool
	reply     chan error
}

type delNodeMsg struct {
	addr  string
	reply chan error
}

type getAddedNodesMsg struct {
	reply chan []*bmpeer
}

// AddNewPeer adds an ip address to the peer handler and adds permanent connections
// to the set of persistant peers.
// This function exists to add initial peers to the address manager before the
// peerHandler go routine has entered its main loop.
func (s *server) AddNewPeer(addr string, stream uint32, permanent bool) error {
	// XXX(oga) duplicate oneshots?
	if permanent {
		for p := range s.state.persistentPeers {
			if p.addr.String() == addr {
				return errors.New("peer already connected")
			}
		}
	}
	// TODO(oga) if too many, nuke a non-perm peer.
	if !s.handleAddPeerMsg(newOutboundPeer(addr, s, stream, permanent, 0)) {
		return errors.New("failed to add peer")
	}

	return nil
}

// handleQuery is the central handler for all queries and commands from other
// goroutines related to the peer state.
func (s *server) handleQuery(querymsg interface{}) {
	switch msg := querymsg.(type) {
	case getConnCountMsg:
		nconnected := int32(0)
		s.state.forAllPeers(func(p *bmpeer) {
			// TODO
			//if p.Connected() {
			nconnected++
			//}
		})
		msg.reply <- nconnected

	case addNodeMsg:
		msg.reply <- s.AddNewPeer(msg.addr, msg.stream, msg.permanent)

	case delNodeMsg:
		found := false
		for p := range s.state.persistentPeers {
			if p.addr.String() == msg.addr {
				// Keep group counts ok since we remove from
				// the list now.
				s.state.outboundGroups[addrmgr.GroupKey(p.na)]--
				// This is ok because we are not continuing
				// to iterate so won't corrupt the loop.
				delete(s.state.persistentPeers, p)
				p.disconnect()
				found = true
				break
			}
		}

		if found {
			msg.reply <- nil
		} else {
			msg.reply <- errors.New("peer not found")
		}

	// Request a list of the persistent (added) peers.
	case getAddedNodesMsg:
		// Respond with a slice of the relavent peers.
		peers := make([]*bmpeer, 0, len(s.state.persistentPeers))
		for p := range s.state.persistentPeers {
			peers = append(peers, p)
		}
		msg.reply <- peers
	}
}

// listenHandler is the main listener which accepts incoming connections for the
// server. It must be run as a goroutine.
func (s *server) listenHandler(listener peer.Listener) {
	for atomic.LoadInt32(&s.shutdown) == 0 {
		conn, err := listener.Accept()
		if err != nil {
			continue
		}
		s.newPeers <- newInboundPeer(s, conn)
	}
	s.wg.Done()
}

// // seedFromDNS uses DNS seeding to populate the address manager with peers.
// func (s *server) seedFromDNS() {
// 	addresses := make([]*wire.NetAddress, 10)
// 	i := 0
// 	ip := net.ParseIP("23.239.9.147")
// 	addresses[i] = new(wire.NetAddress)
// 	addresses[i].SetAddress(ip, 8444)
// 	i++
// 	ip = net.ParseIP("98.218.125.214")
// 	addresses[i] = new(wire.NetAddress)
// 	addresses[i].SetAddress(ip, 8444)
// 	i++
// 	ip = net.ParseIP("192.121.170.162")
// 	addresses[i] = new(wire.NetAddress)
// 	addresses[i].SetAddress(ip, 8444)
// 	i++
// 	ip = net.ParseIP("108.61.72.12")
// 	addresses[i] = new(wire.NetAddress)
// 	addresses[i].SetAddress(ip, 28444)
// 	i++
// 	ip = net.ParseIP("158.222.211.81")
// 	addresses[i] = new(wire.NetAddress)
// 	addresses[i].SetAddress(ip, 8080)
// 	i++
// 	ip = net.ParseIP("79.163.240.110")
// 	addresses[i] = new(wire.NetAddress)
// 	addresses[i].SetAddress(ip, 8446)
// 	i++
// 	ip = net.ParseIP("178.62.154.250")
// 	addresses[i] = new(wire.NetAddress)
// 	addresses[i].SetAddress(ip, 8444)
// 	i++
// 	ip = net.ParseIP("178.62.155.6")
// 	addresses[i] = new(wire.NetAddress)
// 	addresses[i].SetAddress(ip, 8444)
// 	i++
// 	ip = net.ParseIP("178.62.155.8")
// 	addresses[i] = new(wire.NetAddress)
// 	addresses[i].SetAddress(ip, 8444)
// 	i++
// 	ip = net.ParseIP("68.42.42.120")
// 	addresses[i] = new(wire.NetAddress)
// 	addresses[i].SetAddress(ip, 8444)
// 	s.addrManager.AddAddresses(addresses, addresses[0])
// }

// peerHandler is used to handle peer operations such as adding and removing
// peers to and from the server, banning peers, and broadcasting messages to
// peers. It must be run in a goroutine.
func (s *server) peerHandler() {
	// Start the address manager, needed by peers.
	// This is done here since their lifecycle is closely tied
	// to this handler and rather than adding more channels to sychronize
	// things, it's easier and slightly faster to simply start and stop
	// them in this handler.
	s.addrManager.Start()
	s.objectManager.Start()

	if MaxPeers < s.state.maxOutboundPeers {
		s.state.maxOutboundPeers = MaxPeers
	}

	// Add peers discovered through DNS to the address manager.
	// s.seedFromDNS()

	// if nothing else happens, wake us up soon.
	time.AfterFunc(10*time.Second, func() { s.wakeup <- struct{}{} })

	for {
		select {
		// New peers connected to the server.
		case p := <-s.newPeers:
			s.handleAddPeerMsg(p)

		// Disconnected peers.
		case p := <-s.donePeers:
			s.handleDonePeerMsg(p)

		// Peer to ban.
		case p := <-s.banPeers:
			s.handleBanPeerMsg(p)

		// Used by timers below to wake us back up.
		case <-s.wakeup:
			// left intentionally blank

		case qmsg := <-s.query:
			s.handleQuery(qmsg)

		// Shutdown the peer handler.
		case <-s.quit:
			// Shutdown peers.
			s.state.forAllPeers(func(p *bmpeer) {
				p.disconnect()
			})
			s.addrManager.Stop()
			s.objectManager.Stop()
			s.wg.Done()
			return
		}

		// Only try connect to more peers if we actually need more.
		if !s.state.NeedMoreOutbound() ||
			atomic.LoadInt32(&s.shutdown) != 0 {
			continue
		}
		tries := 0
		for s.state.NeedMoreOutbound() &&
			atomic.LoadInt32(&s.shutdown) == 0 {

			nPeers := s.state.OutboundCount()
			if nPeers > MaxPeers {
				nPeers = MaxPeers
			}
			addr := s.addrManager.GetAddress("any")
			if addr == nil {
				break
			}
			key := addrmgr.GroupKey(addr.NetAddress())
			// Address will not be invalid, local or unroutable
			// because addrmanager rejects those on addition.
			// Just check that we don't already have an address
			// in the same group so that we are not connecting
			// to the same network segment at the expense of
			// others.
			if s.state.outboundGroups[key] != 0 {
				break
			}

			tries++
			// After 100 bad tries exit the loop and we'll try again
			// later.
			if tries > 100 {
				break
			}

			// XXX if we have limited that address skip

			// only allow recent nodes (10mins) after we failed 30
			// times
			if time.Now().After(addr.LastAttempt().Add(10*time.Minute)) &&
				tries < 30 {
				continue
			}

			addrStr := addrmgr.NetAddressKey(addr.NetAddress())

			tries = 0
			// any failure will be due to banned peers etc. we have
			// already checked that we have room for more peers.
			if s.handleAddPeerMsg(
				// Stream number 1 is hard-coded in here. Will have to handle
				// this more gracefully when we support streams.
				newOutboundPeer(addrStr, s, 1, false, 0)) {
			}
		}

		// We need more peers, wake up in ten seconds and try again.
		if s.state.NeedMoreOutbound() {
			time.AfterFunc(10*time.Second, func() {
				s.wakeup <- struct{}{}
			})
		}
	}
}

// BanPeer bans a peer that has already been connected to the server by ip.
func (s *server) BanPeer(p *bmpeer) {
	s.banPeers <- p
}

// ConnectedCount returns the number of currently connected peers.
func (s *server) ConnectedCount() int32 {
	replyChan := make(chan int32)

	s.query <- getConnCountMsg{reply: replyChan}

	return <-replyChan
}

// AddedNodeInfo returns an array of structures
// describing the persistent (added) nodes.
func (s *server) AddedNodeInfo() []*bmpeer {
	replyChan := make(chan []*bmpeer)
	s.query <- getAddedNodesMsg{reply: replyChan}
	return <-replyChan
}

// AddAddr adds `addr' as a new outbound peer. If permanent is true then the
// peer will be persistent and reconnect if the connection is lost.
// It is an error to call this with an already existing peer.
func (s *server) AddAddr(addr string, stream uint32, permanent bool) error {
	replyChan := make(chan error)

	s.query <- addNodeMsg{addr: addr, stream: stream, permanent: permanent, reply: replyChan}

	return <-replyChan
}

// RemoveAddr removes `addr' from the list of persistent peers if present.
// An error will be returned if the peer was not found.
func (s *server) RemoveAddr(addr string) error {
	replyChan := make(chan error)

	s.query <- delNodeMsg{addr: addr, reply: replyChan}

	return <-replyChan
}

// Start begins accepting connections from peers.
func (s *server) Start() {
	s.start(defaultPeers)
}

// start is the real start function. It takes parameters that can be exposed
// for testing purposes.
func (s *server) start(startPeers []*DefaultPeer) {
	// Already started?
	if atomic.AddInt32(&s.started, 1) != 1 {
		return
	}

	// Start all the listeners. There will not be any if listening is
	// disabled.
	for _, listener := range s.listeners {
		s.wg.Add(1)
		go s.listenHandler(listener)
	}

	// Start the peer handler which in turn starts the address manager and object manager.
	s.wg.Add(1)
	go s.peerHandler()

	for _, dp := range startPeers {
		s.AddNewPeer(dp.addr, dp.stream, dp.permanent)
	}
}

// Stop gracefully shuts down the server by stopping and disconnecting all
// peers and the main listener.
func (s *server) Stop() error {
	// Make sure this only happens once.
	if atomic.AddInt32(&s.shutdown, 1) != 1 {
		return nil
	}

	// Stop all the listeners. There will not be any listeners if
	// listening is disabled.
	for _, listener := range s.listeners {
		err := listener.Close()
		if err != nil {
			return err
		}
	}

	// Signal the remaining goroutines to quit.
	close(s.quit)
	return nil
}

// WaitForShutdown blocks until the main listener and peer handlers are stopped.
func (s *server) WaitForShutdown() {
	s.wg.Wait()
}

// parseListeners splits the list of listen addresses passed in addrs into
// IPv4 and IPv6 slices and returns them. This allows easy creation of the
// listeners on the correct interface "tcp4" and "tcp6". It also properly
// detects addresses which apply to "all interfaces" and adds the address to
// both slices.
func parseListeners(addrs []string) ([]string, []string, bool, error) {
	ipv4ListenAddrs := make([]string, 0, len(addrs)*2)
	ipv6ListenAddrs := make([]string, 0, len(addrs)*2)
	haveWildcard := false

	for _, addr := range addrs {
		host, _, err := net.SplitHostPort(addr)
		if err != nil {
			// Shouldn't happen due to already being normalized.
			return nil, nil, false, err
		}

		// Empty host or host of * on plan9 is both IPv4 and IPv6.
		if host == "" || (host == "*" && runtime.GOOS == "plan9") {
			ipv4ListenAddrs = append(ipv4ListenAddrs, addr)
			ipv6ListenAddrs = append(ipv6ListenAddrs, addr)
			haveWildcard = true
			continue
		}

		// Parse the IP.
		ip := net.ParseIP(host)
		if ip == nil {
			return nil, nil, false, fmt.Errorf("'%s' is not a "+
				"valid IP address", host)
		}

		// To4 returns nil when the IP is not an IPv4 address, so use
		// this determine the address type.
		if ip.To4() == nil {
			ipv6ListenAddrs = append(ipv6ListenAddrs, addr)
		} else {
			ipv4ListenAddrs = append(ipv4ListenAddrs, addr)
		}
	}
	return ipv4ListenAddrs, ipv6ListenAddrs, haveWildcard, nil
}

// NewServer returns a new server.
func NewServer(listenAddrs []string, db database.Db) (*server, error) {
	return newServer(listenAddrs, db, peer.Listen)
}

// newServer returns a new bmd Server configured to listen on addr for the
// bitmessage network. Use start to begin accepting connections from peers.
func newServer(listenAddrs []string, db database.Db,
	listen func(string, string) (peer.Listener, error)) (*server, error) {

	nonce, err := wire.RandomUint64()
	if err != nil {
		return nil, err
	}

	// get data directory
	user, err := user.Current()
	if err != nil {
		return nil, fmt.Errorf("failed to get current user: %v", err)
	}
	dataDir := strings.Replace(DataDir, "$HOME", user.HomeDir, 1)

	amgr := addrmgr.New(dataDir, net.LookupIP)

	var listeners []peer.Listener
	ipv4Addrs, ipv6Addrs, wildcard, err := parseListeners(listenAddrs)
	if err != nil {
		return nil, err
	}
	listeners = make([]peer.Listener, 0, len(ipv4Addrs)+len(ipv6Addrs))
	discover := true

	// TODO(oga) nonstandard port...
	if wildcard {
		port := DefaultPort
		addrs, _ := net.InterfaceAddrs()
		for _, a := range addrs {
			ip, _, err := net.ParseCIDR(a.String())
			if err != nil {
				continue
			}
			// Stream number 1 is hard-coded in here. When we support streams,
			// this will need to be handled properly.
			na := wire.NewNetAddressIPPort(ip,
				uint16(port), 1, wire.SFNodeNetwork)
			if discover {
				err = amgr.AddLocalAddress(na, addrmgr.InterfacePrio)
			}
		}
	}

	for _, addr := range ipv4Addrs {
		listener, err := listen("tcp4", addr)
		if err != nil {
			continue
		}
		listeners = append(listeners, listener)

		if discover {
			if na, err := amgr.DeserializeNetAddress(addr); err == nil {
				err = amgr.AddLocalAddress(na, addrmgr.BoundPrio)
				if err != nil {
				}
			}
		}
	}

	for _, addr := range ipv6Addrs {
		listener, err := listen("tcp6", addr)
		if err != nil {
			continue
		}
		listeners = append(listeners, listener)
		if discover {
			if na, err := amgr.DeserializeNetAddress(addr); err == nil {
				err = amgr.AddLocalAddress(na, addrmgr.BoundPrio)
			}
		}
	}

	if len(listeners) == 0 {
		return nil, errors.New("no valid listen address")
	}

	s := server{
		nonce:       nonce,
		listeners:   listeners,
		addrManager: amgr,
		state:       newPeerState(defaultMaxOutbound),
		newPeers:    make(chan *bmpeer, MaxPeers),
		donePeers:   make(chan *bmpeer, MaxPeers),
		banPeers:    make(chan *bmpeer, MaxPeers),
		wakeup:      make(chan struct{}),
		query:       make(chan interface{}),
		relayInv:    make(chan relayMsg, MaxPeers),
		quit:        make(chan struct{}),
		db:          db,
	}
	s.objectManager = newObjectManager(&s)

	return &s, nil
}
