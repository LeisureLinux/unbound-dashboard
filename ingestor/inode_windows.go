//go:build windows

package ingestor

import "os"

func fileInode(fi os.FileInfo) uint64 {
	_ = fi
	return 0
}
