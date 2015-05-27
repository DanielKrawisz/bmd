// Originally derived from: btcsuite/btcd/btcd.go
// Copyright (c) 2013-2015 Conformal Systems LLC.

// Copyright (c) 2015 Monetas.
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"net"
	"net/http"
	_ "net/http/pprof"
	"os"
	"runtime"
	"runtime/pprof"
)

var (
	cfg             *config
	shutdownChannel = make(chan struct{})
)

// bmdMain is the real main function for bmd. It is necessary to work around
// the fact that deferred functions do not run when os.Exit() is called. The
func bmdMain() error {

	// load configuration
	tcfg, _, err := loadConfig()
	if err != nil {
		return err
	}
	cfg = tcfg
	defer backendLog.Flush()

	// Show version at startup.
	bmdLog.Infof("Version %s", version())

	// Enable http profiling server if requested.
	if cfg.Profile != "" {
		go func() {
			listenAddr := net.JoinHostPort("", cfg.Profile)
			bmdLog.Infof("Profile server listening on %s", listenAddr)
			profileRedirect := http.RedirectHandler("/debug/pprof",
				http.StatusSeeOther)
			http.Handle("/", profileRedirect)
			bmdLog.Errorf("%v", http.ListenAndServe(listenAddr, nil))
		}()
	}

	// Write cpu profile if requested.
	if cfg.CPUProfile != "" {
		f, err := os.Create(cfg.CPUProfile)
		if err != nil {
			bmdLog.Errorf("Unable to create cpu profile: %v", err)
			return err
		}
		pprof.StartCPUProfile(f)
		defer f.Close()
		defer pprof.StopCPUProfile()
	}

	// Load object database.
	db, err := setupDB(cfg.DbType, objectDbPath(cfg.DbType))
	if err != nil {
		dbLog.Errorf("Failed to initialize database: %v", err)
		return err
	}
	defer db.Close()

	// Ensure the database is sync'd and closed on Ctrl+C.
	addInterruptHandler(func() {
		bmdLog.Infof("Gracefully shutting down the database...")
		db.RollbackClose()
	})

	// Create server and start it.
	server, err := NewServer(cfg.Listeners, db)
	if err != nil {
		serverLog.Errorf("Failed to start server on %v: %v", cfg.Listeners,
			err)
		return err
	}
	server.Start()

	addInterruptHandler(func() {
		bmdLog.Infof("Gracefully shutting down the server...")
		server.Stop()
		server.WaitForShutdown()
	})

	// Monitor for graceful server shutdown and signal the main goroutine
	// when done. This is done in a separate goroutine rather than waiting
	// directly so the main goroutine can be signaled for shutdown by either
	// a graceful shutdown or from the main interrupt handler. This is
	// necessary since the main goroutine must be kept running long enough
	// for the interrupt handler goroutine to finish.
	go func() {
		server.WaitForShutdown()
		serverLog.Infof("Server shutdown complete")
		shutdownChannel <- struct{}{}
	}()

	// Wait for shutdown signal from either a graceful server stop or from
	// the interrupt handler.
	<-shutdownChannel
	bmdLog.Info("Shutdown complete")
	return nil
}

func main() {
	// Use all processor cores.
	runtime.GOMAXPROCS(runtime.NumCPU())

	// Work around defer not working after os.Exit()
	if err := bmdMain(); err != nil {
		os.Exit(1)
	}
}
