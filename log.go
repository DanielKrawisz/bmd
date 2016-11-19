// Originally derived from: btcsuite/btcd/log.go
// Copyright (c) 2013-2015 The btcsuite developers

// Copyright (c) 2015 Monetas.
// Copyright 2016 Daniel Krawisz.
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/DanielKrawisz/bmd/addrmgr"
	"github.com/DanielKrawisz/bmd/database"
	"github.com/DanielKrawisz/bmd/objmgr"
	"github.com/DanielKrawisz/bmd/peer"
	"github.com/DanielKrawisz/bmutil/wire"
	"github.com/btcsuite/btclog"
	"github.com/btcsuite/seelog"
)

const (
	// maxRejectReasonLen is the maximum length of a sanitized reject reason
	// that will be logged.
	maxRejectReasonLen = 250
)

// Loggers per subsytem. Note that backendLog is a seelog logger that all of
// the subsystem loggers route their messages to. When adding new subsystems,
// add a reference here, to the subsystemLoggers map, and the useLogger
// function.
var (
	backendLog = seelog.Disabled
	addrmgrLog = btclog.Disabled
	bmdLog     = btclog.Disabled
	peerLog    = btclog.Disabled
	rpcLog     = btclog.Disabled
	serverLog  = btclog.Disabled
	dbLog      = btclog.Disabled
	objmgrLog  = btclog.Disabled
)

// subsystemLoggers maps each subsystem identifier to its associated logger.
var subsystemLoggers = map[string]btclog.Logger{
	"ADDRMGR": addrmgrLog,
	"BMD":     bmdLog,
	"PEER":    peerLog,
	"RPC":     rpcLog,
	"SERVER":  serverLog,
	"DB":      dbLog,
	"OBJMGR":  objmgrLog,
}

// logClosure is used to provide a closure over expensive logging operations
// so don't have to be performed when the logging level doesn't warrant it.
type logClosure func() string

// String invokes the underlying function and returns the result.
func (c logClosure) String() string {
	return c()
}

// newLogClosure returns a new closure over a function that returns a string
// which itself provides a Stringer interface so that it can be used with the
// logging system.
func newLogClosure(c func() string) logClosure {
	return logClosure(c)
}

// useLogger updates the logger references for subsystemID to logger.  Invalid
// subsystems are ignored.
func useLogger(subsystemID string, logger btclog.Logger) {
	if _, ok := subsystemLoggers[subsystemID]; !ok {
		return
	}
	subsystemLoggers[subsystemID] = logger

	switch subsystemID {

	case "ADDRMGR":
		addrmgrLog = logger
		addrmgr.UseLogger(logger)

	case "BMD":
		bmdLog = logger

	case "PEER":
		peerLog = logger
		peer.UseLogger(logger)

	case "RPC":
		rpcLog = logger

	case "SERVER":
		serverLog = logger

	case "DB":
		dbLog = logger
		database.UseLogger(logger)

	case "OBJMGR":
		objmgrLog = logger
		objmgr.UseLogger(logger)
	}
}

// initSeelogLogger initializes a new seelog logger that is used as the backend
// for all logging subsytems.
func initSeelogLogger(logFile string) {
	config := `
	<seelog type="adaptive" mininterval="2000000" maxinterval="100000000"
		critmsgcount="500" minlevel="trace">
		<outputs formatid="all">
			<console />
			<rollingfile type="size" filename="%s" maxsize="10485760" maxrolls="3" />
		</outputs>
		<formats>
			<format id="all" format="%%Time %%Date [%%LEV] %%Msg%%n" />
		</formats>
	</seelog>`
	config = fmt.Sprintf(config, logFile)

	logger, err := seelog.LoggerFromConfigAsString(config)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to create logger: %v", err)
		os.Exit(1)
	}

	backendLog = logger
}

// setLogLevel sets the logging level for provided subsystem. Invalid
// subsystems are ignored. Uninitialized subsystems are dynamically created as
// needed.
func setLogLevel(subsystemID string, logLevel string) {
	// Ignore invalid subsystems.
	logger, ok := subsystemLoggers[subsystemID]
	if !ok {
		return
	}

	// Default to info if the log level is invalid.
	level, ok := btclog.LogLevelFromString(logLevel)
	if !ok {
		level = btclog.InfoLvl
	}

	// Create new logger for the subsystem if needed.
	if logger == btclog.Disabled {
		logger = btclog.NewSubsystemLogger(backendLog, subsystemID+": ")
		useLogger(subsystemID, logger)
	}
	logger.SetLevel(level)
}

// setLogLevels sets the log level for all subsystem loggers to the passed
// level. It also dynamically creates the subsystem loggers as needed, so it
// can be used to initialize the logging system.
func setLogLevels(logLevel string) {
	// Configure all sub-systems with the new logging level.  Dynamically
	// create loggers as needed.
	for subsystemID := range subsystemLoggers {
		setLogLevel(subsystemID, logLevel)
	}
}

// directionString is a helper function that returns a string that represents
// the direction of a connection (inbound or outbound).
func directionString(inbound bool) string {
	if inbound {
		return "inbound"
	}
	return "outbound"
}

// invSummary returns an inventory message as a human-readable string.
func invSummary(invList []*wire.InvVect) string {
	// No inventory.
	invLen := len(invList)
	if invLen == 0 {
		return "empty"
	}

	// One inventory item.
	if invLen == 1 {
		return fmt.Sprintf("hash %s", invList[0].Hash)
	}

	// More than one inv item.
	return fmt.Sprintf("size %d", invLen)
}

// sanitizeString strips any characters which are even remotely dangerous, such
// as html control characters, from the passed string.  It also limits it to
// the passed maximum size, which can be 0 for unlimited.  When the string is
// limited, it will also add "..." to the string to indicate it was truncated.
func sanitizeString(str string, maxLength uint) string {
	const safeChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXY" +
		"Z01234567890 .,;_/:?@"

	// Strip any characters not in the safeChars string removed.
	str = strings.Map(func(r rune) rune {
		if strings.IndexRune(safeChars, r) >= 0 {
			return r
		}
		return -1
	}, str)

	// Limit the string to the max allowed length.
	if maxLength > 0 && uint(len(str)) > maxLength {
		str = str[:maxLength]
		str = str + "..."
	}
	return str
}

// messageSummary returns a human-readable string which summarizes a message.
// Not all messages have or need a summary.  This is used for debug logging.
func messageSummary(msg wire.Message) string {
	switch msg := msg.(type) {
	case *wire.MsgVersion:
		return fmt.Sprintf("agent %s, streams %v",
			msg.UserAgent, msg.StreamNumbers)

	case *wire.MsgVerAck:
		// No summary.

	case *wire.MsgAddr:
		return fmt.Sprintf("%d addr", len(msg.AddrList))

	case *wire.MsgPong:
		// No summary - perhaps add nonce.

	case *wire.MsgInv:
		return invSummary(msg.InvList)

	case *wire.MsgGetData:
		return invSummary(msg.InvList)

	case *wire.MsgObject:
		// TODO
	}

	// No summary for other messages.
	return ""
}
