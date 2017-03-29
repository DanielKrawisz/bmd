// Originally derived from: btcsuite/btcd/btcd.go
// Copyright (c) 2013-2015 Conformal Systems LLC.

// Copyright (c) 2015 Monetas.
// Copyright 2016 Daniel Krawisz.
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"net"
	"net/http"
	_ "net/http/pprof"
	"os"
	"path/filepath"
	"runtime"
	"runtime/pprof"

	"github.com/DanielKrawisz/bmd/database"
	_ "github.com/DanielKrawisz/bmd/database/memdb"
	"github.com/DanielKrawisz/bmd/peer"
	"github.com/DanielKrawisz/bmd/objmgr/stats"
)

const (
	// objectDbNamePrefix is the prefix for the object database name. The
	// database type is appended to this value to form the full object database
	// name.
	objectDbNamePrefix = "objects"
)

var (
	cfg             *Config
	shutdownChannel = make(chan struct{})
)

// bmdMain is the real main function for bmd. It is necessary to work around
// the fact that deferred functions do not run when os.Exit() is called.
func bmdMain() error {

	// Load configuration.
	tcfg, _, err := loadConfig()
	if err != nil {
		return err
	}
	cfg = tcfg
	defer backendLog.Flush()

	// Ensure that the correct dialer is used.
	peer.SetDialer(bmdDial)

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
	
	var mgrStats stats.Stats
	var dbStats database.Stats
	if cfg.UpToDateTimer || cfg.ObjectStats {
		// Open the stats file.
		performanceMonitor, err := os.OpenFile(filepath.Join(cfg.DataDir, "performance.txt"), os.O_RDWR|os.O_APPEND|os.O_CREATE, 0660)
		if err != nil {
			bmdLog.Errorf("Unable to load performance monitor file: %v", err)
			return err
		}
	
		if cfg.UpToDateTimer {
			mgrStats = stats.NewFileStatsRecorder(performanceMonitor)
		}
		
		if cfg.ObjectStats {
			dbStats = database.NewFileStatsRecorder(performanceMonitor)
		}
	}

	// Load object database.
	db, err := setupDB(cfg.DbType, cfg.objectDbPath(), dbStats)
	if err != nil {
		dbLog.Errorf("Failed to initialize database: %v", err)
		return err
	}
	defer db.Close()

	// Create server and start it.
	server, err := newDefaultServer(cfg.Listeners, db, mgrStats)
	if err != nil {
		serverLog.Errorf("Failed to start server on %v: %v", cfg.Listeners,
			err)
		return err
	}
	server.Start()

	addInterruptHandler(func() {
		bmdLog.Infof("Gracefully shutting down the server...")
		server.Stop()
	})

	// Monitor for graceful server shutdown and signal the main goroutine
	// when done. This is done in a separate goroutine rather than waiting
	// directly so the main goroutine can be signaled for shutdown by either
	// a graceful shutdown or from the main interrupt handler. This is
	// necessary since the main goroutine must be kept running long enough
	// for the interrupt handler goroutine to finish.
	go func() {
		server.WaitForShutdown()
		serverLog.Info("Server shutdown complete")
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

// setupDB loads (or creates when needed) the object database taking into
// account the selected database backend.
func setupDB(dbType, dbPath string, dbStats database.Stats) (*database.Db, error) {
	// The memdb backend does not have a file path associated with it, so
	// handle it uniquely.
	if dbType == "memdb" {
		return database.OpenDB(dbType)
	}
	var err error
	var db *database.Db
	db, err = database.OpenDB(dbType, dbPath, dbStats)
	if err != nil {
		return nil, err
	}

	// Remove all expired objects.
	_, err = db.RemoveExpiredObjects()
	if err != nil {
		return nil, err
	}

	return db, nil
}
