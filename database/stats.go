package database

import (
	"fmt"
	"os"
	"time"

	"github.com/DanielKrawisz/bmutil/hash"
)

// Stats is a type that records stats for objects which are inserted
// into the database.
type Stats struct {
	recordObject func(h *hash.Sha, bytes uint64, t time.Time)
}

// RecordObject records an observation of an object.
func (s Stats) RecordObject(h *hash.Sha, bytes uint64, t time.Time) {
	if s.recordObject != nil {
		s.recordObject(h, bytes, t)
	}
}

// NewStatsRecorder creates a new Stats object.
func NewStatsRecorder(f *os.File) Stats {
	return Stats{
		recordObject: func(h *hash.Sha, bytes uint64, t time.Time) {
			f.WriteString(h.String())
			f.WriteString("\n")
			f.WriteString(fmt.Sprintf("%d", bytes))
			f.WriteString("\n")
			f.WriteString(t.String())
			f.WriteString("\n")
		},
	}
}
