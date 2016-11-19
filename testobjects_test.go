package main

import (
	"errors"
	"math/rand"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/DanielKrawisz/bmd/peer"
	"github.com/DanielKrawisz/bmutil/wire"
	"github.com/DanielKrawisz/bmutil/wire/obj"
)

// randomShaHash returns a ShaHash with a random string of bytes in it.
func randomShaHash() *wire.ShaHash {
	b := make([]byte, 32)
	for i := 0; i < 32; i++ {
		b[i] = byte(rand.Intn(256))
	}
	hash, _ := wire.NewShaHash(b)
	return hash
}

// MockListener implements the peer.Listener interface
type MockListener struct {
	incoming     chan peer.Connection
	disconnect   chan struct{}
	localAddr    net.Addr
	disconnected bool
}

func (ml *MockListener) Accept() (peer.Connection, error) {
	if ml.disconnected {
		return nil, errors.New("Listner disconnected.")
	}
	select {
	case <-ml.disconnect:
		return nil, errors.New("Listener disconnected.")
	case m := <-ml.incoming:
		return m, nil
	}
}

func (ml *MockListener) Close() error {
	ml.disconnect <- struct{}{}
	return nil
}

// Addr returns the listener's network address.
func (ml *MockListener) Addr() net.Addr {
	return ml.localAddr
}

func NewMockListener(localAddr net.Addr, incoming chan peer.Connection, disconnect chan struct{}) *MockListener {
	return &MockListener{
		incoming:   incoming,
		disconnect: disconnect,
		localAddr:  localAddr,
	}
}

// MockListen returns a mock listener
func MockListen(listeners []*MockListener) func(string, string) (peer.Listener, error) {
	i := 0

	return func(service, addr string) (peer.Listener, error) {
		i++
		if i > len(listeners) {
			return nil, errors.New("No mock listeners remaining.")
		}

		return listeners[i-1], nil
	}
}

// The report that the MockConnection sends when its interaction is complete.
// If the error is nil, then the test has completed successfully.
// The report also includes any object messages that were sent to the peer.
type TestReport struct {
	Err      error
	DataSent []*wire.ShaHash
}

// MockPeer implements the peer.Connection interface and
// is a mock peer to be used for testing purposes.
type MockPeer struct {
	// After a message is processed, the replies are sent here.
	reply chan []wire.Message

	// A channel used to report invalid states to the test.
	report chan TestReport

	// A structure that manages the sequence of steps that the test should go through.
	// This is the part that is customized for each test.
	peerTest PeerTest

	// A list of hashes of objects that have been sent to the real peer.
	objectData []*wire.ShaHash

	// A queue of messages to be received by the real peer.
	msgQueue []wire.Message

	// The current place in the queue.
	queuePlace int

	// The test ends when the timer runs out. Until the interaction is complete,
	// the timer is reset with every message received. Some time is required after
	// the mock peer is done interacting with the real one to see if the real peer
	// disconnects or not.
	timer *time.Timer

	// when interactionComplete is set, the mock peer no longer processes incoming
	// messages or resets the timer. It is just waiting to see whether the real peer
	// disconnects.
	interactionComplete bool

	// Whether the peer is expected to disconnect.
	disconnectExpected bool

	localAddr  net.Addr
	remoteAddr net.Addr

	// Whether the report has already been submitted.
	reported int32

	// A mutex for data that might be accessed by different threads.
	mutex sync.RWMutex
}

func (mock *MockPeer) ReadMessage() (wire.Message, error) {
	// If the queue is empty, get a new message from the channel.
	for mock.msgQueue == nil || mock.queuePlace >= len(mock.msgQueue) {
		mock.msgQueue = <-mock.reply
		mock.queuePlace = 0
	}

	toSend := mock.msgQueue[mock.queuePlace]

	mock.queuePlace++

	if mock.queuePlace >= len(mock.msgQueue) {
		mock.msgQueue = nil
	}

	switch t := toSend.(type) {
	case *wire.MsgObject:
		mock.mutex.Lock()
		mock.objectData = append(mock.objectData, t.InventoryHash())
		mock.mutex.Unlock()
	}

	return toSend, nil
}

// WriteMessage figures out how to respond to a message once it is decyphered.
func (mock *MockPeer) WriteMessage(rmsg wire.Message) error {
	// We can keep receiving messages after the interaction is done; we just
	// ignore them.	 We are waiting to see whether the peer disconnects.
	mock.mutex.RLock()
	ic := mock.interactionComplete
	mock.mutex.RUnlock()
	if ic {
		return nil
	}

	mock.mutex.Lock()
	mock.timer.Reset(time.Second)
	mock.mutex.Unlock()
	mock.handleAction(mock.handleMessage(rmsg))
	return nil
}

func (mock *MockPeer) RequestData(invVect []*wire.InvVect) error {
	// We can keep receiving messages after the interaction is done; we just ignore them.
	// We are waiting to see whether the peer disconnects.
	mock.mutex.RLock()
	ic := mock.interactionComplete
	mock.mutex.RUnlock()
	if ic {
		return nil
	}

	mock.mutex.Lock()
	mock.timer.Reset(time.Second)
	mock.mutex.Unlock()
	mock.handleAction(mock.peerTest.OnSendData(invVect))
	return nil
}

func (mock *MockPeer) BytesWritten() uint64 {
	return 0
}

func (mock *MockPeer) BytesRead() uint64 {
	return 0
}

func (mock *MockPeer) LastWrite() time.Time {
	return time.Time{}
}

func (mock *MockPeer) LastRead() time.Time {
	return time.Time{}
}

// LocalAddr returns the localAddr field of the fake connection and satisfies
// the net.Conn interface.
func (mock *MockPeer) LocalAddr() net.Addr {
	return mock.localAddr
}

// RemoteAddr returns the remoteAddr field of the fake connection and satisfies
// the net.Conn interface.
func (mock *MockPeer) RemoteAddr() net.Addr {
	return mock.remoteAddr
}

func (mock *MockPeer) Close() {
	mock.ConnectionClosed()
}

func (mock *MockPeer) Connected() bool {
	return true
}

func (mock *MockPeer) Connect() error {
	return errors.New("Already connected.")
}

func (mock *MockPeer) handleMessage(msg wire.Message) *PeerAction {
	switch msg.(type) {
	case *wire.MsgVersion:
		return mock.peerTest.OnMsgVersion(msg.(*wire.MsgVersion))
	case *wire.MsgVerAck:
		return mock.peerTest.OnMsgVerAck(msg.(*wire.MsgVerAck))
	case *wire.MsgAddr:
		return mock.peerTest.OnMsgAddr(msg.(*wire.MsgAddr))
	case *wire.MsgInv:
		return mock.peerTest.OnMsgInv(msg.(*wire.MsgInv))
	case *wire.MsgGetData:
		return mock.peerTest.OnMsgGetData(msg.(*wire.MsgGetData))
	default:
		return nil
	}
}

func (mock *MockPeer) handleAction(action *PeerAction) {
	// A nil response means to do nothing.
	if action == nil {
		return
	}

	// If an error is returned, immediately end the interaction.
	if action.Err != nil {
		mock.Done(action.Err)
		return
	}

	mock.mutex.Lock()
	mock.interactionComplete = mock.interactionComplete || action.InteractionComplete

	mock.disconnectExpected = mock.disconnectExpected || action.DisconnectExpected
	mock.mutex.Unlock()

	if action.Messages != nil {

		mock.reply <- action.Messages
	}
}

// ConnectionClosed is called when the real peer closes the connection to the mock peer.
func (mock *MockPeer) ConnectionClosed() {
	mock.mutex.RLock()
	ic := mock.interactionComplete
	mock.mutex.RUnlock()
	if !ic &&
		(!mock.disconnectExpected ||
			(mock.msgQueue != nil && mock.queuePlace < len(mock.msgQueue))) {
		mock.Done(errors.New("Connection closed prematurely."))
	}
	mock.Done(nil)
}

// Done stops the server and ends the test.
func (mock *MockPeer) Done(err error) {
	if atomic.AddInt32(&mock.reported, 1) > 1 {
		// The report has already been submitted.
		return
	}
	mock.mutex.Lock()
	mock.timer.Stop()
	mock.interactionComplete = true
	mock.report <- TestReport{err, mock.objectData}
	mock.mutex.Unlock()
}

// Start loads the mock peer's initial action if there is one.
func (mock *MockPeer) BeginTest() {
	action := mock.peerTest.OnStart()

	if action == nil {
		return
	}

	mock.mutex.Lock()
	mock.interactionComplete = mock.interactionComplete || action.InteractionComplete

	mock.disconnectExpected = mock.disconnectExpected || action.DisconnectExpected
	mock.mutex.Unlock()

	if action.Messages == nil {
		return
	}

	if mock.msgQueue == nil {
		mock.msgQueue = action.Messages
		mock.queuePlace = 0
	}
}

func NewMockPeer(localAddr, remoteAddr net.Addr, report chan TestReport, peerTest PeerTest) *MockPeer {
	mock := &MockPeer{
		localAddr:           localAddr,
		remoteAddr:          remoteAddr,
		report:              report,
		peerTest:            peerTest,
		interactionComplete: false,
		disconnectExpected:  false,
		reply:               make(chan []wire.Message),
		objectData:          make([]*wire.ShaHash, 0),
	}

	mock.mutex.Lock()
	mock.timer = time.AfterFunc(time.Millisecond*100, func() {
		mock.mutex.RLock()
		ic := mock.interactionComplete
		mock.mutex.RUnlock()
		if !ic {
			if mock.disconnectExpected {
				mock.Done(errors.New("Peer stopped interacting when it was expected to disconnect."))
			} else {
				mock.Done(errors.New("Peer stopped interacting (without disconnecting) before the interaction was complete."))
			}
		} else {
			mock.Done(nil)
		}
	})
	mock.mutex.Unlock()

	mock.BeginTest()

	return mock
}

type MockSend struct {
	conn         *MockPeer
	msgQueue     chan wire.Message
	requestQueue chan []*wire.InvVect
	quit         chan struct{}
}

func (msq *MockSend) QueueMessage(msg wire.Message) error {
	msq.msgQueue <- msg
	return nil
}

func (msq *MockSend) QueueDataRequest(inv []*wire.InvVect) error {
	msq.requestQueue <- inv
	return nil
}

func (msq *MockSend) QueueInventory([]*wire.InvVect) error {
	return nil
}

// Start ignores its input here because we need a MockConnection, which has some
// extra functions that the regular Connection does not have.
func (msq *MockSend) Start(conn peer.Connection) {
	go msq.handler()
}

func (msq *MockSend) Running() bool {
	return true
}

func (msq *MockSend) Stop() {
	close(msq.quit)
}

// Must be run as a go routine.
func (msq *MockSend) handler() {
out:
	for {
		select {
		case <-msq.quit:
			break out
		case inv := <-msq.requestQueue:
			msq.conn.RequestData(inv)
		case msg := <-msq.msgQueue:
			msq.conn.WriteMessage(msg)
		}
	}
}

func NewMockSend(mockConn *MockPeer) *MockSend {
	return &MockSend{
		conn:         mockConn,
		msgQueue:     make(chan wire.Message, 1),
		requestQueue: make(chan []*wire.InvVect, 1),
		quit:         make(chan struct{}),
	}
}

// PeerAction represents a an action to be taken by the mock peer and information
// about the expected response from the real peer.
type PeerAction struct {
	// A series of messages to send to the real peer.
	Messages []wire.Message

	// If an error is set, the interaction ends immediately.
	Err error

	// Whether the interaction is complete.
	InteractionComplete bool

	// For negative tests, we expect the peer to disconnect after the interaction is
	// complete. If disconnectExpected is set, the test fails if the real peer fails
	// to disconnect after half a second.
	DisconnectExpected bool
}

// PeerTest is a type that defines the high-level behavior of a peer.
type PeerTest interface {
	OnStart() *PeerAction
	OnMsgVersion(p *wire.MsgVersion) *PeerAction
	OnMsgVerAck(p *wire.MsgVerAck) *PeerAction
	OnMsgAddr(p *wire.MsgAddr) *PeerAction
	OnMsgInv(p *wire.MsgInv) *PeerAction
	OnMsgGetData(p *wire.MsgGetData) *PeerAction
	OnSendData(invVect []*wire.InvVect) *PeerAction
}

// OutboundHandshakePeerTester is an implementation of PeerTest that is for
// testing the handshake with an outbound peer.
type OutboundHandshakePeerTester struct {
	versionReceived   bool
	handshakeComplete bool
	response          *PeerAction
	msgAddr           wire.Message
	mutex             sync.RWMutex
}

func (peer *OutboundHandshakePeerTester) OnStart() *PeerAction {
	return nil
}

func (peer *OutboundHandshakePeerTester) VersionReceived() bool {
	peer.mutex.RLock()
	defer peer.mutex.RUnlock()

	return peer.versionReceived
}

func (peer *OutboundHandshakePeerTester) HandshakeComplete() bool {
	peer.mutex.RLock()
	defer peer.mutex.RUnlock()

	return peer.handshakeComplete
}

func (peer *OutboundHandshakePeerTester) OnMsgVersion(version *wire.MsgVersion) *PeerAction {
	if peer.VersionReceived() {
		return &PeerAction{Err: errors.New("Two version messages received")}
	}
	peer.versionReceived = true
	return peer.response
}

func (peer *OutboundHandshakePeerTester) OnMsgVerAck(p *wire.MsgVerAck) *PeerAction {
	if !peer.VersionReceived() {
		return &PeerAction{Err: errors.New("Expecting version message first.")}
	}
	peer.mutex.Lock()
	peer.handshakeComplete = true
	peer.mutex.Unlock()
	return &PeerAction{
		Messages:            []wire.Message{peer.msgAddr},
		InteractionComplete: true,
		DisconnectExpected:  false,
	}
}

func (peer *OutboundHandshakePeerTester) OnMsgAddr(p *wire.MsgAddr) *PeerAction {
	if peer.HandshakeComplete() {
		return nil
	}
	return &PeerAction{Err: errors.New("Not allowed before handshake is complete.")}
}

func (peer *OutboundHandshakePeerTester) OnMsgInv(p *wire.MsgInv) *PeerAction {
	if peer.HandshakeComplete() {
		return nil
	}
	return &PeerAction{Err: errors.New("Not allowed before handshake is complete.")}
}

func (peer *OutboundHandshakePeerTester) OnMsgGetData(p *wire.MsgGetData) *PeerAction {
	if peer.HandshakeComplete() {
		return nil
	}
	return &PeerAction{Err: errors.New("Not allowed before handshake is complete.")}
}

func (peer *OutboundHandshakePeerTester) OnSendData(invVect []*wire.InvVect) *PeerAction {
	if peer.HandshakeComplete() {
		return nil
	}
	return &PeerAction{Err: errors.New("Object message not allowed before handshake is complete.")}
}

func NewOutboundHandshakePeerTester(action *PeerAction, msgAddr wire.Message) *OutboundHandshakePeerTester {
	return &OutboundHandshakePeerTester{
		versionReceived:   false,
		handshakeComplete: false,
		response:          action,
		msgAddr:           msgAddr,
	}
}

// InboundHandsakePeerTester implements the PeerTest interface and is used to test
// handshakes with inbound peers and the exchange of the addr messages.
type InboundHandshakePeerTester struct {
	verackReceived    bool
	versionReceived   bool
	handshakeComplete bool
	openMsg           *PeerAction
	addrAction        *PeerAction
}

func (peer *InboundHandshakePeerTester) OnStart() *PeerAction {
	return peer.openMsg
}

func (peer *InboundHandshakePeerTester) OnMsgVersion(version *wire.MsgVersion) *PeerAction {
	if peer.versionReceived {
		return &PeerAction{Err: errors.New("Two versions received?")}
	}
	peer.versionReceived = true
	if peer.verackReceived {
		// Handshake completed successfully
		peer.handshakeComplete = true

		// Sending an addr message to make sure the peer doesn't disconnect.
		return peer.addrAction
	}
	return &PeerAction{[]wire.Message{&wire.MsgVerAck{}}, nil, false, false}
}

func (peer *InboundHandshakePeerTester) OnMsgVerAck(p *wire.MsgVerAck) *PeerAction {
	if peer.verackReceived {
		return &PeerAction{Err: errors.New("Two veracks received?")}
	}
	peer.verackReceived = true
	if peer.versionReceived {
		// Handshake completed successfully
		peer.handshakeComplete = true

		//Sending an addr message to make sure the peer doesn't disconnect.
		return peer.addrAction
	}
	// Return nothing and await a version message.
	return &PeerAction{nil, nil, false, false}
}

func (peer *InboundHandshakePeerTester) OnMsgAddr(p *wire.MsgAddr) *PeerAction {
	if peer.handshakeComplete {
		return &PeerAction{nil, nil, true, false}
	}
	return &PeerAction{Err: errors.New("Not allowed before handshake is complete.")}
}

func (peer *InboundHandshakePeerTester) OnMsgInv(p *wire.MsgInv) *PeerAction {
	if peer.handshakeComplete {
		return nil
	}
	return &PeerAction{Err: errors.New("Not allowed before handshake is complete.")}
}

func (peer *InboundHandshakePeerTester) OnMsgGetData(p *wire.MsgGetData) *PeerAction {
	if peer.handshakeComplete {
		return nil
	}
	return &PeerAction{Err: errors.New("Not allowed before handshake is complete.")}
}

func (peer *InboundHandshakePeerTester) OnSendData(invVect []*wire.InvVect) *PeerAction {
	if peer.handshakeComplete {
		return nil
	}
	return &PeerAction{Err: errors.New("Object message not allowed before handshake is complete.")}
}

func NewInboundHandshakePeerTester(openingMsg *PeerAction, addrAction *PeerAction) *InboundHandshakePeerTester {
	return &InboundHandshakePeerTester{
		verackReceived:    false,
		versionReceived:   false,
		handshakeComplete: false,
		openMsg:           openingMsg,
		addrAction:        addrAction,
	}
}

// DataExchangePeerTester implements the PeerTest interface and tests the exchange
// of inv messages and data.
type DataExchangePeerTester struct {
	dataSent      bool
	dataReceived  bool
	invReceived   bool
	invAction     *PeerAction
	inventory     map[wire.InvVect]obj.Object // The initial inventory of the mock peer.
	peerInventory map[wire.InvVect]struct{}   // The initial inventory of the real peer.
	requested     map[wire.InvVect]struct{}   // The messages that were requested.
}

func (peer *DataExchangePeerTester) OnStart() *PeerAction {
	return peer.invAction
}

func (peer *DataExchangePeerTester) OnMsgVersion(version *wire.MsgVersion) *PeerAction {
	return &PeerAction{Err: errors.New("This test should begin with handshake already done.")}
}

func (peer *DataExchangePeerTester) OnMsgVerAck(p *wire.MsgVerAck) *PeerAction {
	return &PeerAction{Err: errors.New("This test should begin with handshake already done.")}
}

func (peer *DataExchangePeerTester) OnMsgAddr(p *wire.MsgAddr) *PeerAction {
	return nil
}

func (peer *DataExchangePeerTester) OnMsgInv(inv *wire.MsgInv) *PeerAction {
	if peer.invReceived {
		return &PeerAction{Err: errors.New("Inv message allready received.")}
	}

	peer.invReceived = true

	if len(inv.InvList) == 0 {
		return &PeerAction{Err: errors.New("Empty inv message received.")}
	}

	if len(inv.InvList) > wire.MaxInvPerMsg {
		return &PeerAction{Err: errors.New("Excessively long inv message received.")}
	}

	// Return a get data message that requests the entries in inv which are not already known.
	i := 0
	var ok bool
	duplicate := make(map[wire.InvVect]struct{})
	newInvList := make([]*wire.InvVect, len(inv.InvList))
	for _, iv := range inv.InvList {
		if _, ok = peer.inventory[*iv]; !ok {
			if _, ok = duplicate[*iv]; ok {
				return &PeerAction{Err: errors.New("Inv with duplicates received.")}
			}
			duplicate[*iv] = struct{}{}
			newInvList[i] = iv
			peer.requested[*iv] = struct{}{}
			i++
		}
	}

	if i == 0 {
		return nil
	}

	return &PeerAction{
		Messages: []wire.Message{&wire.MsgGetData{InvList: newInvList[:i]}},
	}
}

func (peer *DataExchangePeerTester) OnMsgGetData(getData *wire.MsgGetData) *PeerAction {

	if len(getData.InvList) == 0 {
		return &PeerAction{Err: errors.New("Empty GetData message received.")}
	}

	if len(getData.InvList) > wire.MaxInvPerMsg {
		return &PeerAction{Err: errors.New("Excessively long GetData message received.")}
	}

	// The getdata message should include no duplicates and should include nothing
	// that the peer already knows, and nothing that the mock peer doesn't know.
	i := 0
	duplicate := make(map[wire.InvVect]struct{})
	messages := make([]wire.Message, len(getData.InvList))
	for _, iv := range getData.InvList {
		msg, ok := peer.inventory[*iv]
		if !ok {
			return &PeerAction{Err: errors.New("GetData asked for something we don't know.")}
		}

		if _, ok = duplicate[*iv]; ok {
			return &PeerAction{Err: errors.New("GetData with duplicates received.")}
		}

		duplicate[*iv] = struct{}{}
		messages[i] = msg
		peer.peerInventory[*iv] = struct{}{}
		i++
	}

	peer.dataSent = true

	if peer.dataReceived {
		return &PeerAction{messages[:i], nil, true, false}
	}
	return &PeerAction{messages[:i], nil, false, false}
}

func (peer *DataExchangePeerTester) OnSendData(invVect []*wire.InvVect) *PeerAction {
	if !peer.invReceived {
		return &PeerAction{Err: errors.New("Object message not allowed before exchange of invs.")}
	}

	// The objects must have been requested.
	for _, iv := range invVect {
		if _, ok := peer.requested[*iv]; !ok {
			return &PeerAction{Err: errors.New("Object message not allowed before handshake is complete.")}
		}
		delete(peer.requested, *iv)
	}

	if len(peer.requested) == 0 {
		peer.dataReceived = true
	}

	if peer.dataReceived && peer.dataSent {
		return &PeerAction{nil, nil, true, false}
	}
	return &PeerAction{nil, nil, false, false}
}

func NewDataExchangePeerTester(inventory []obj.Object, peerInventory []obj.Object, invAction *PeerAction) *DataExchangePeerTester {
	// Catalog the initial inventories of the mock peer and real peer.
	in := make(map[wire.InvVect]obj.Object)
	pin := make(map[wire.InvVect]struct{})
	invMsg := wire.NewMsgInv()

	// Construct the real peer's inventory.
	for _, message := range inventory {
		inv := wire.InvVect{Hash: *message.InventoryHash()}
		invMsg.AddInvVect(&inv)
		in[inv] = message
	}

	// Construct the mock peer's inventory.
	for _, message := range peerInventory {
		inv := wire.InvVect{Hash: *message.InventoryHash()}
		pin[inv] = struct{}{}
	}

	dataSent := true
	dataReceived := true

	// Does the real peer have any inventory that the mock peer does not have?
	for inv := range in {
		if _, ok := pin[inv]; !ok {
			dataSent = false
			break
		}
	}

	// Does the mock peer have any inventory that the real peer does not?
	for inv := range pin {
		if _, ok := in[inv]; !ok {
			dataReceived = false
			break
		}
	}

	var inva *PeerAction
	if invAction == nil {
		if len(invMsg.InvList) == 0 {
			inva = &PeerAction{
				Messages:            []wire.Message{&wire.MsgVerAck{}},
				InteractionComplete: dataSent && dataReceived,
			}
		} else {
			inva = &PeerAction{
				Messages:            []wire.Message{&wire.MsgVerAck{}, invMsg},
				InteractionComplete: dataSent && dataReceived,
			}
		}
	} else {
		inva = invAction
	}

	return &DataExchangePeerTester{
		dataSent:      dataSent,
		dataReceived:  dataReceived,
		inventory:     in,
		peerInventory: pin,
		invAction:     inva,
		requested:     make(map[wire.InvVect]struct{}),
	}
}
