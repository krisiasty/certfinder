//go:build linux

package scanner

import (
	"os"
	"syscall"
)

func platformFilesystemID(info os.FileInfo) (uint64, bool) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return stat.Dev, true
}
