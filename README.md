# bmd 

[![Build Status](https://travis-ci.org/monetas/bmd.svg)]
(https://travis-ci.org/monetas/bmd)

bmd is collection of Bitmessage tools inspired by [btcsuite]
(https://github.com/btcsuite).

bmd extensively shares code and design philosophy with btcd.

## Components

### bmd

bmd is the network daemon (the equivalent of btcd) which connects to the P2P
network, relays and stores messages, and contains no private keys or
user-specific metadata.

### bmclient

bmclient is the user daemon (the equivalent of btcwallet) which stores a user's
private keys, messages, and metadata. bmclient obtains incoming messages from,
and routes outgoing messages through, a trusted instance of bmd.

Users interact with bmclient via standard mail clients rather than a dedicated
GUI.

bmclient includes functionality similar to [bmwrapper]
(https://github.com/Arceliar/bmwrapper) except that it uses the IMAP protocol
rather than POP3.

## TODO

Bug: bmd does not synch with the network properly out-of-the box. It requires
a new set of default addresses. 

In the communication from bmd to bmagent, the whole of the objects should not be
sent. Only enough should be sent for bmagent to determine whether the message
can be decrypted. Then it should request the remainder. 

Allow connections to multiple instances of bmagent.