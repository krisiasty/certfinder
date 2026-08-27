//go:build darwin

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
	if stat.Dev < 0 {
		return 0, false
	}
	return uint64(stat.Dev), true
}
