// Originally derived from: btcsuite/btcd/server.go
// Copyright (c) 2013-2015 Conformal Systems LLC.

// Copyright (c) 2015 Monetas.
// Copyright 2016 Daniel Krawisz.
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	mrand "math/rand"
	"net"
	"runtime"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/DanielKrawisz/bmd/addrmgr"
	"github.com/DanielKrawisz/bmd/database"
	"github.com/DanielKrawisz/bmd/objmgr"
	"github.com/DanielKrawisz/bmd/peer"
	"github.com/DanielKrawisz/bmutil/wire"
)

const (
	// These constants are used by the DNS seed code to pick a random last seen
	// time.
	secondsIn3Days int32 = 24 * 60 * 60 * 3
	secondsIn4Days int32 = 24 * 60 * 60 * 4
)

const (
	// supportedServices describes which services are supported by the
	// server.
	supportedServices = wire.SFNodeNetwork

	// connectionRetryInterval is the amount of time to wait in between
	// retries when connecting to persistent peers.
	connectionRetryInterval = time.Second * 10

	// maxReconnectionAttempts is the maximum number of reconnection attempts
	// allowed before a persistant peer is dropped.
	maxReconnectionAttempts = 5
)

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

type reconnectionAttempts uint32

// The peerState is used by the server to keep track of what the peers it is
// connected to are up to.
type peerState struct {
	peers            map[*peer.Peer]struct{}
	outboundPeers    map[*peer.Peer]struct{}
	persistentPeers  map[*peer.Peer]reconnectionAttempts
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
		p.Count() < cfg.MaxPeers
}

// forAllOutboundPeers is a helper function that runs closure on all outbound
// peers known to peerState
func (p *peerState) forAllOutboundPeers(closure func(p *peer.Peer)) {
	for e := range p.outboundPeers {
		closure(e)
	}
	for e := range p.persistentPeers {
		closure(e)
	}
}

// forAllPeers is a helper function that runs closure on all peers known to
// peerState.
func (p *peerState) forAllPeers(closure func(p *peer.Peer)) {
	for e := range p.peers {
		closure(e)
	}
	p.forAllOutboundPeers(closure)
}

func newPeerState(maxOutbound int) *peerState {
	return &peerState{
		peers:            make(map[*peer.Peer]struct{}),
		persistentPeers:  make(map[*peer.Peer]reconnectionAttempts),
		outboundPeers:    make(map[*peer.Peer]struct{}),
		banned:           make(map[string]time.Time),
		outboundGroups:   make(map[string]int),
		maxOutboundPeers: maxOutbound,
	}
}

// server provides a bitmssage server for handling communications to and from
// bitmessage peers. It satisfies the peer.server and objmgr.server interfaces.
type server struct {
	nonce         uint64
	listeners     []peer.Listener
	permanent     []string
	started       int32 // atomic
	shutdown      int32 // atomic
	shutdownSched int32 // atomic
	addrManager   *addrmgr.AddrManager
	objectManager *objmgr.ObjectManager
	state         *peerState
	newPeers      chan *peer.Peer
	donePeers     chan *peer.Peer
	banPeers      chan *peer.Peer
	disconPeers   chan *peer.Peer
	wakeup        chan struct{}
	wg            sync.WaitGroup
	quit          chan struct{}
	db            database.Db
	rpcServer     *rpcServer
	nat           NAT
}

// Nonce returns the server's nonce. Part of the peer.server interface.
func (s *server) Nonce() uint64 {
	return s.nonce
}

// AddrManager returns a pointer to the address manager. Part of the peer.server interface.
func (s *server) AddrManager() *addrmgr.AddrManager {
	return s.addrManager
}

// ObjectManager returns an interface representing the object manager.
// Part of the peer.server interface.
func (s *server) ObjectManager() peer.ObjectManager {
	return s.objectManager
}

// Db returns the database. Part of the peer.server interface.
func (s *server) Db() database.Db {
	return s.db
}

// DonePeer tells the server that a peer has disconnected and can be removed.
// Part of the peer.server interface.
func (s *server) DonePeer(p *peer.Peer) {
	s.donePeers <- p
}

// DisconnectPeer tells the server to disconnect a fully-connected peer.
// Part of the objmgr.server interface.
func (s *server) DisconnectPeer(p *peer.Peer) {
	s.disconPeers <- p
}

// NotifyObject notifies the rpc server of a new object. Part of the
// objmgr.server interface.
func (s *server) NotifyObject(counter wire.ObjectType) {
	if !cfg.DisableRPC {
		s.rpcServer.NotifyObject(counter)
	}
}

// handleAddPeerMsg deals with adding new peers. It is invoked from the
// peerHandler goroutine.
func (s *server) handleAddPeerMsg(p *peer.Peer, retries reconnectionAttempts) bool {
	peerLog.Trace(p.PrependAddr("handleAddPeerMsg: About to add peer."))
	if p == nil {
		return false
	}

	// Drop if the number of reconnection attempts is too high.
	if retries > maxReconnectionAttempts {
		p.Disconnect()
		return false
	}

	// Ignore new peers if we're shutting down.
	if atomic.LoadInt32(&s.shutdown) != 0 {
		p.Disconnect()
		return false
	}

	// Ignore banned peers.
	host, _, err := net.SplitHostPort(p.Addr().String())
	if err != nil {
		p.Disconnect()
		return false
	}
	if banEnd, ok := s.state.banned[host]; ok {
		if time.Now().Before(banEnd) {
			p.Disconnect()
			return false
		}

		delete(s.state.banned, host)
	}

	// TODO: Check for max peers from a single IP.

	// Limit max number of total peers.
	if s.state.Count() >= cfg.MaxPeers {
		peerLog.Trace(p.PrependAddr("handleAddPeerMsg: Disconnecting because of too many peers."))
		p.Disconnect()
		// TODO(oga) how to handle permanent peers here?
		// they should be rescheduled.
		return false
	}
	peerLog.Infof(p.PrependAddr("Added to server."))

	// Add the new peer to the appropriate peer bin and start running it.
	na := p.NetAddress()
	if p.Inbound {
		s.state.peers[p] = struct{}{}
	} else {
		s.state.outboundGroups[addrmgr.GroupKey(na)]++
		if p.Persistent {
			s.state.persistentPeers[p] = retries
		} else {
			s.state.outboundPeers[p] = struct{}{}
		}
	}

	if !p.Connected() {
		// Attempt to connect with the new peer if it is not already connected.
		go func() {
			// Wait for some time if this is a retry, and wait longer if we have
			// tried multiple times.
			if retries > 0 {
				scaledInterval := connectionRetryInterval.Nanoseconds() * int64(retries) / 2
				scaledDuration := time.Duration(scaledInterval)
				time.Sleep(scaledDuration)
			}

			peerLog.Trace("NewOutboundPeer: About to start peer ", p.Addr(), ".")

			if err := p.Start(); err != nil {
				peerLog.Tracef("Failed to start peer %s: %v", p.Addr(), err)
				s.DonePeer(p)
			}
			peerLog.Trace("NewOutboundPeer: ", p.Addr(), " started.")

			if na != nil {
				s.addrManager.Attempt(na)
			}
		}()
	}

	return true
}

// handleDonePeerMsg deals with peers that have signalled they are done. It is
// invoked from the peerHandler goroutine.
func (s *server) handleDonePeerMsg(p *peer.Peer) {
	serverLog.Trace("handleDonePeerMsg for ", p.Addr())
	na := p.NetAddress()
	if p.Persistent {
		list := s.state.persistentPeers
		retries := list[p] + 1
		delete(list, p)
		s.state.outboundGroups[addrmgr.GroupKey(na)]--
		peerLog.Info(p.PrependAddr("Removed from server. "), len(list), " persistent peers remain.")

		if !p.Inbound && atomic.LoadInt32(&s.shutdown) == 0 {
			// TODO eventually we shouldn't work with addresses represented as strings at all.
			s.handleAddPeerMsg(NewOutboundPeer(p.Addr().String(), s, na.Stream, true), retries)
		}

	} else if p.Inbound {
		delete(s.state.peers, p)
		peerLog.Info(p.PrependAddr("Removed from server. "),
			len(s.state.peers), " inbound peers remain.")
	} else {
		delete(s.state.outboundPeers, p)
		s.state.outboundGroups[addrmgr.GroupKey(na)]--
		peerLog.Info(p.PrependAddr("Removed from server. "),
			len(s.state.outboundPeers), " outbound peers remain.")
	}
}

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
	reply chan []*peer.Peer
}

// AddNewPeer adds an ip address to the peer handler and adds permanent connections
// to the set of persistant peers.
func (s *server) AddNewPeer(addr string, stream uint32, permanent bool) error {
	serverLog.Debug("Creating peer at ", addr, ", stream: ", stream)

	// XXX(oga) duplicate oneshots?
	if permanent {
		for p := range s.state.persistentPeers {
			if p.Addr().String() == addr {
				return errors.New("peer already connected")
			}
		}
	}
	// TODO(oga) if too many, nuke a non-perm peer.
	if !s.handleAddPeerMsg(NewOutboundPeer(addr, s, stream, permanent), 0) {
		return errors.New("failed to add peer")
	}

	return nil
}

// listenHandler is the main listener which accepts incoming connections for the
// server. It must be run as a goroutine.
func (s *server) listenHandler(listener peer.Listener) {
	serverLog.Infof("Server listening on %s", listener.Addr())
	for atomic.LoadInt32(&s.shutdown) == 0 {
		conn, err := listener.Accept()
		if err != nil {
			continue
		}
		s.newPeers <- NewInboundPeer(s, conn)
	}
	s.wg.Done()
}

// seedFromDNS uses DNS seeding to populate the address manager with peers.
func (s *server) seedFromDNS() {
	// Nothing to do if DNS seeding is disabled.
	if cfg.DisableDNSSeed {
		return
	}

	for _, seeder := range cfg.dnsSeeds {
		go func(seeder string) {
			randSource := mrand.New(mrand.NewSource(time.Now().UnixNano()))
			host, port, _ := net.SplitHostPort(seeder)

			seedpeers, err := dnsDiscover(host)
			if err != nil {
				serverLog.Warnf("DNS discovery failed on seed %s: %v", seeder, err)
				return
			}
			numPeers := len(seedpeers)

			serverLog.Infof("%d addresses found from DNS seed %s", numPeers, host)

			if numPeers == 0 {
				return
			}
			addresses := make([]*wire.NetAddress, len(seedpeers))
			// if this errors then we have *real* problems
			intPort, _ := strconv.Atoi(port)
			for i, peer := range seedpeers {
				addresses[i] = new(wire.NetAddress)
				addresses[i].SetAddress(peer, uint16(intPort))
				// bitcoind seeds with addresses from
				// a time randomly selected between 3
				// and 7 days ago.
				addresses[i].Timestamp = time.Now().Add(-1 *
					time.Second * time.Duration(secondsIn3Days+
					randSource.Int31n(secondsIn4Days)))
			}

			// Bitcoind uses a lookup of the dns seeder here. This
			// is rather strange since the values looked up by the
			// DNS seed lookups will vary quite a lot.
			// to replicate this behaviour we put all addresses as
			// having come from the first one.
			s.addrManager.AddAddresses(addresses, addresses[0])
		}(seeder)
	}
}

// peerHandler is used to handle peer operations such as adding and removing
// peers to and from the server, banning peers, and broadcasting messages to
// peers. It must be run in a goroutine.
func (s *server) peerHandler(persistentPeers []string) {
	serverLog.Info("Peer handler started.")
	// Start the address manager, needed by peers.
	// This is done here since their lifecycle is closely tied
	// to this handler and rather than adding more channels to sychronize
	// things, it's easier and slightly faster to simply start and stop
	// them in this handler.
	s.addrManager.Start()
	s.objectManager.Start()

	if cfg.MaxPeers < s.state.maxOutboundPeers {
		s.state.maxOutboundPeers = cfg.MaxPeers
	}

	// Add peers discovered through DNS to the address manager.
	s.seedFromDNS()

	// Add persistent peers. Run in a separate goroutine so as to avoid
	// clogging up the channel.
	go func(persistentPeers []string) {
		if persistentPeers != nil {
			for _, addr := range persistentPeers {
				s.AddNewPeer(addr, 1, true)
			}
		}
	}(persistentPeers)

	// if nothing else happens, wake us up soon.
	time.AfterFunc(10*time.Second, func() { s.wakeup <- struct{}{} })

	for {
		select {
		// Shutdown the peer handler.
		case <-s.quit:
			// Shutdown peers.
			s.state.forAllPeers(func(p *peer.Peer) {
				p.Disconnect()
			})
			s.addrManager.Stop()
			s.objectManager.Stop()
			s.wg.Done()
			return

		// New peers connected to the server.
		case p := <-s.newPeers:
			s.handleAddPeerMsg(p, 0)

		// Disconnected peers.
		case p := <-s.donePeers:
			s.handleDonePeerMsg(p)

		// Disconnect a peer. There is an inherent problem with disconnecting
		// a peer because it might have to send messages to be read by the go
		// routine that called the disconnect in the first place. Under some
		// circumstances, even with a buffered channel, this can cause it to lock.
		// It would be good if we came up with a way of disconnecting a peer
		// that we could guarantee was safe but I think that's a larger project.
		case p := <-s.disconPeers:
			p.Disconnect()

		// Used by timers below to wake us back up.
		case <-s.wakeup:
			// left intentionally blank
		}

		// Only try connect to more peers if we actually need more.
		if !s.state.NeedMoreOutbound() || len(cfg.ConnectPeers) > 0 ||
			atomic.LoadInt32(&s.shutdown) != 0 {
			continue
		}
		tries := 0
		for s.state.NeedMoreOutbound() &&
			atomic.LoadInt32(&s.shutdown) == 0 {
			serverLog.Info("Adding new peers.")

			nPeers := s.state.OutboundCount()
			if nPeers > cfg.MaxPeers {
				nPeers = cfg.MaxPeers
			}
			addr := s.addrManager.GetAddress("any")
			if addr == nil {
				break
			}

			na := addr.NetAddress()
			key := addrmgr.GroupKey(na)
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
			if time.Now().Before(addr.LastAttempt().Add(10*time.Minute)) &&
				tries < 30 {
				serverLog.Debug("Continuing because last attempt is too soon. ")
				continue
			}

			addrStr := addrmgr.NetAddressKey(addr.NetAddress())
			serverLog.Info("need more peers; attempting to connect to ", addrStr)

			tries = 0
			// any failure will be due to banned peers etc. we have
			// already checked that we have room for more peers.
			s.handleAddPeerMsg(
				// Stream number 1 is hard-coded in here. Will have to handle
				// this more gracefully when we support streams.
				NewOutboundPeer(addrStr, s, 1, false), 0)
		}

		// We need more peers, wake up in ten seconds and try again.
		if s.state.NeedMoreOutbound() {
			serverLog.Error("Unable to connect to new peers. Retrying in 10 seconds.")
			time.AfterFunc(10*time.Second, func() {
				s.wakeup <- struct{}{}
			})
		}
	}
}

// BanPeer bans a peer that has already been connected to the server by ip.
func (s *server) BanPeer(p *peer.Peer) {
	s.banPeers <- p
}

// Start begins accepting connections from peers.
func (s *server) Start() {
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

	// Start the peer handler which in turn starts the address manager and
	// object manager.
	s.wg.Add(1)
	go s.peerHandler(s.permanent)

	if s.nat != nil {
		s.wg.Add(1)
		go s.upnpUpdateThread()
	}

	// Start RPC server.
	if !cfg.DisableRPC {
		s.wg.Add(1)
		s.rpcServer.Start()
	}
}

// Stop gracefully shuts down the server by stopping and disconnecting all
// peers and the main listener.
func (s *server) Stop() error {
	// Make sure this only happens once.
	if atomic.AddInt32(&s.shutdown, 1) != 1 {
		return nil
	}

	// Signal the remaining goroutines to quit.
	close(s.quit)

	// Stop all the listeners. There will not be any listeners if
	// listening is disabled.
	for _, listener := range s.listeners {
		err := listener.Close()
		if err != nil {
			return err
		}
	}

	// Stop RPC server.
	if !cfg.DisableRPC {
		err := s.rpcServer.Stop()
		s.wg.Done()
		if err != nil {
			return err
		}
	}

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
func parseListeners(addrs []string) ([]string, []string, error) {
	ipv4ListenAddrs := make([]string, 0, len(addrs)*2)
	ipv6ListenAddrs := make([]string, 0, len(addrs)*2)

	for _, addr := range addrs {
		host, _, err := net.SplitHostPort(addr)
		if err != nil {
			// Shouldn't happen due to already being normalized.
			return nil, nil, err
		}

		// Empty host or host of * on plan9 is both IPv4 and IPv6.
		if host == "" || (host == "*" && runtime.GOOS == "plan9") {
			ipv4ListenAddrs = append(ipv4ListenAddrs, addr)
			ipv6ListenAddrs = append(ipv6ListenAddrs, addr)
			continue
		}

		// Parse the IP.
		ip := net.ParseIP(host)
		if ip == nil {
			return nil, nil, fmt.Errorf("'%s' is not a "+
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
	return ipv4ListenAddrs, ipv6ListenAddrs, nil
}

// upnpUpdateThread renews the port mapping lease from the router after every
// 15 minutes. Must be run as a go routine.
func (s *server) upnpUpdateThread() {
	// Go off immediately to prevent code duplication, thereafter we renew
	// lease every 15 minutes.
	timer := time.NewTimer(0 * time.Second)
	first := true
out:
	for {
		select {
		case <-timer.C:
			// TODO(oga) pick external port  more cleverly
			// TODO(oga) know which ports we are listening to on an external net.
			// TODO(oga) if specific listen port doesn't work then ask for wildcard
			// listen port?
			// XXX this assumes timeout is in seconds.
			listenPort, err := s.nat.AddPortMapping("tcp", defaultPort,
				defaultPort, "bmd listen port", 20*60)
			if err != nil {
				serverLog.Warnf("can't add UPnP port mapping: %v", err)
			}
			if first && err == nil {
				// TODO(oga): look this up periodically to see if upnp domain changed
				// and so did ip.
				externalip, err := s.nat.GetExternalAddress()
				if err != nil {
					serverLog.Warnf("UPnP can't get external address: %v", err)
					continue out
				}
				na := wire.NewNetAddressIPPort(externalip, uint16(listenPort),
					1, wire.SFNodeNetwork)
				err = s.addrManager.AddLocalAddress(na, addrmgr.UpnpPrio)
				if err != nil {
					// XXX DeletePortMapping?
				}
				serverLog.Warnf("Successfully bound via UPnP to %s", addrmgr.NetAddressKey(na))
				first = false
			}
			timer.Reset(time.Minute * 15)
		case <-s.quit:
			break out
		}
	}

	timer.Stop()

	err := s.nat.DeletePortMapping("tcp", defaultPort, defaultPort)
	if err != nil {
		serverLog.Warnf("unable to remove UPnP port mapping: %v", err)
	} else {
		serverLog.Debugf("succesfully disestablished UPnP port mapping")
	}

	s.wg.Done()
}

// newDefaultServer returns a new server with the default listener and
// initial nodes.
func newDefaultServer(listenAddrs []string, db database.Db) (*server, error) {
	// Set up persistent peers.
	var persistentPeers []string
	if cfg.ConnectPeers != nil && len(cfg.ConnectPeers) > 0 {
		persistentPeers = cfg.ConnectPeers
	} else {
		persistentPeers = cfg.AddPeers
	}

	return newServer(listenAddrs, db, peer.Listen, persistentPeers)
}

// newServer returns a new bmd Server configured to listen on addr for the
// bitmessage network. Use start to begin accepting connections from peers.
func newServer(listenAddrs []string, db database.Db,
	listen func(string, string) (peer.Listener, error), persistentPeers []string) (*server, error) {

	nonce, err := wire.RandomUint64()
	if err != nil {
		return nil, err
	}

	amgr := addrmgr.New(cfg.DataDir, bmdLookup)

	if persistentPeers != nil {
		for _, node := range persistentPeers {
			amgr.AddAddressByIP(node)
		}
	}

	var listeners []peer.Listener
	var nat NAT
	if !cfg.DisableListen {
		ipv4Addrs, ipv6Addrs, err := parseListeners(listenAddrs)
		if err != nil {
			return nil, err
		}
		listeners = make([]peer.Listener, 0, len(ipv4Addrs)+len(ipv6Addrs))
		discover := true

		if len(cfg.ExternalIPs) != 0 {
			discover = false

			for _, sip := range cfg.ExternalIPs {
				eport := uint16(defaultPort)
				host, portstr, err := net.SplitHostPort(sip)
				if err != nil {
					// no port, use default.
					host = sip
				} else {
					port, err := strconv.ParseUint(portstr, 10, 16)
					if err != nil {
						serverLog.Warnf("Can not parse port from %s for "+
							"externalip: %v", sip, err)
						continue
					}
					eport = uint16(port)
				}
				// Stream 1 is hardcoded here.
				na, err := amgr.HostToNetAddress(host, eport, 1, wire.SFNodeNetwork)
				if err != nil {
					serverLog.Warnf("Not adding %s as externalip: %v", sip, err)
					continue
				}

				err = amgr.AddLocalAddress(na, addrmgr.ManualPrio)
				if err != nil {
					addrmgrLog.Warnf("Skipping specified external IP: %v", err)
				}
			}
		} else if discover && cfg.Upnp {
			nat, err = Discover()
			if err != nil {
				serverLog.Warnf("Can't discover upnp: %v", err)
			}
			// nil nat here is fine, just means no upnp on network.
		}

		for _, addr := range ipv4Addrs {

			// Handle wildcards
			host, portStr, err := net.SplitHostPort(addr)
			port, _ := strconv.Atoi(portStr)

			// Empty host or host of * on plan9 is both IPv4 and IPv6.
			if host == "" || (host == "*" && runtime.GOOS == "plan9") {
				addrs, _ := net.InterfaceAddrs()
				for _, a := range addrs {
					ip, _, err := net.ParseCIDR(a.String())
					if err != nil {
						continue
					}
					// Stream number 1 is hard-coded in here. When we support
					// streams, this will need to be handled properly.
					na := wire.NewNetAddressIPPort(ip,
						uint16(port), 1, wire.SFNodeNetwork)
					if discover {
						err = amgr.AddLocalAddress(na, addrmgr.InterfacePrio)
						if err != nil {
							addrmgrLog.Debugf("Skipping local address: %v", err)
						}
					}
				}
			}

			listener, err := listen("tcp4", addr)
			if err != nil {
				continue
			}
			listeners = append(listeners, listener)

			if discover {
				if na, err := amgr.DeserializeNetAddress(addr); err == nil {
					err = amgr.AddLocalAddress(na, addrmgr.BoundPrio)
					if err != nil {
						addrmgrLog.Debugf("Skipping bound address: %v", err)
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
					if err != nil {
						addrmgrLog.Debugf("Skipping bound address: %v", err)
					}
				}
			}
		}

		if len(listeners) == 0 {
			return nil, errors.New("no valid listen address")
		}
	}

	s := server{
		nonce:       nonce,
		listeners:   listeners,
		permanent:   persistentPeers,
		addrManager: amgr,
		state:       newPeerState(cfg.MaxOutbound),
		newPeers:    make(chan *peer.Peer, cfg.MaxPeers),
		donePeers:   make(chan *peer.Peer, cfg.MaxPeers),
		banPeers:    make(chan *peer.Peer, cfg.MaxPeers),
		disconPeers: make(chan *peer.Peer, cfg.MaxPeers),
		wakeup:      make(chan struct{}),
		quit:        make(chan struct{}),
		db:          db,
		nat:         nat,
	}
	s.objectManager = objmgr.NewObjectManager(&s, s.db, cfg.RequestExpire, cfg.CleanupInterval)

	if !cfg.DisableRPC {
		s.rpcServer, err = newRPCServer(cfg.RPCListeners, &s)
		if err != nil {
			return nil, err
		}
	}

	return &s, nil
}
