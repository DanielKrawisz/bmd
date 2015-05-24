// Copyright (c) 2015 Monetas.
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package bmpeer

import (
	"net"
)

// Listener represents an open port listening for bitmessage connections.
// It is given as an interface so that mock peer listeners can easily swapped
// for the genuine ones.
type Listener interface {
	Accept() (Connection, error)
	Close() error
	Addr() net.Addr
}

// listener implements the Listener interface. It listens on the given net.Listener
// and creates new bitmessage connections as new peers dial in.
type listener struct {
	netListener net.Listener
}

// Accept blocks until a new connection dials in. It returns a Connection object,
// which means that only bitmessage messages pass along it.
func (pl *listener) Accept() (Connection, error) {
	conn, err := pl.netListener.Accept()
	if err != nil {
		return nil, err
	}
	return &connection{
		conn: conn,
		addr: conn.RemoteAddr(),
	}, nil
}

// Close closes the listener.
func (pl *listener) Close() error {
	return pl.netListener.Close()
}

// Addr returns the listener's network address.
func (pl *listener) Addr() net.Addr {
	return pl.netListener.Addr()
}

// A value that can be swapped out to create mock listeners.
var listen = net.Listen

// Listen creates a listener object. The value of listen can
// be swapped out with a mock connection dialer for testing purposes.
func Listen(service, addr string) (Listener, error) {
	netListener, err := listen(service, addr)
	if err != nil {
		return nil, err
	}
	return &listener{
		netListener: netListener,
	}, nil
}
