//go:build !linux && !darwin

package scanner

import "os"

func platformFilesystemID(os.FileInfo) (uint64, bool) {
	return 0, false
}
