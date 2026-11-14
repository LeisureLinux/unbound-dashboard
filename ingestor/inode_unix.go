//go:build !windows

package ingestor

import (
	"os"
	"syscall"
)

func fileInode(fi os.FileInfo) uint64 {
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		return st.Ino
	}
	return 0
}
