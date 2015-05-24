package bmpeer

import (
	"net"
	"github.com/monetas/bmutil/wire"
)

// PeerState is a number defining the state of an interaction with a remote
// peer.
type PeerState uint32

// A bitmessage peer can be in one of three states.
//  - PeerStateNew: no version message has been sent or received. A peer in
//    this state should send a version message.
//  - PeerStateVersionKnown: a version message has been received and both a
//    version and ver ack have been sent.
//  - PeerStateHandshakeComplete: the peer has completed its handshake and
//    is exchanging data.
const (
	PeerStateNew               PeerState = iota
	PeerStateVersionKnown      PeerState = iota
	PeerStateHandshakeComplete PeerState = iota
)

// Logic is an interface that represents the behavior of a peer object
// excluding the parts that must be continually running.
type Logic interface {
	State() PeerState
	ProtocolVersion() uint32
	Addr() net.Addr
	NetAddress() *wire.NetAddress
	Inbound() bool

	HandleVersionMsg(*wire.MsgVersion) error
	HandleVerAckMsg() error
	HandleAddrMsg(*wire.MsgAddr) error
	HandleInvMsg(*wire.MsgInv) error
	HandleGetDataMsg(*wire.MsgGetData) error
	HandleObjectMsg(wire.Message) error

	PushVersionMsg()
	PushVerAckMsg()
	PushAddrMsg(addresses []*wire.NetAddress) error
	PushInvMsg(invVect []*wire.InvVect)
	PushGetDataMsg(invVect []*wire.InvVect)
	PushObjectMsg(sha *wire.ShaHash)
}
