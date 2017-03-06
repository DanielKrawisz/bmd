package database

import (
	"fmt"
	"time"
	"os"
	
	"github.com/DanielKrawisz/bmutil/hash"
)

type Stats interface {
	RecordObject(h *hash.Sha, bytes uint64, t time.Time)
}

type fileStats os.File

func NewStatsRecorder(f *os.File) Stats {
	return (*fileStats)(f)
}

func (fs *fileStats) RecordObject(h *hash.Sha, bytes uint64, t time.Time) {
	(*os.File)(fs).WriteString(h.String())
	(*os.File)(fs).WriteString("\n")
	(*os.File)(fs).WriteString(fmt.Sprintf("%d", bytes))
	(*os.File)(fs).WriteString("\n")
	(*os.File)(fs).WriteString(t.String())
	(*os.File)(fs).WriteString("\n")
}
