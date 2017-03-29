package stats

import (
	"fmt"
	"os"
	"time"
)

// UpToDateTimer is used to measure how long it takes bmd to be up-to-date
// with the network.
type UpToDateTimer struct {
	finished bool
	finish   func()
}

func (utd UpToDateTimer) Finish() {
	if utd.finished {
		return
	}
	
	utd.finished = true
	
	if utd.finish != nil {
		utd.finish()
	}
}

// Stats is a type that records various stats for objects which are inserted
// into the database.
type Stats struct {
	file *os.File
}

// StartUpToDateTimer records an observation of an object.
func (s Stats) StartUpToDateTimer() UpToDateTimer {
	if s.file == nil {
		return UpToDateTimer{}
	}
	
	begin := time.Now()
	
	return UpToDateTimer{
		finish: func() {
			s.file.WriteString(
				fmt.Sprintf("Fully up to date with Bitmessage network after %s.",
				time.Now().Sub(begin).String()))
		},
	}
}

// NewFileStatsRecorder creates a new Stats object.
func NewFileStatsRecorder(f *os.File) Stats {
	return Stats{
		file: f,
	}
}

func NewDisabledStatsRecorder() Stats {
	return Stats{}
}
