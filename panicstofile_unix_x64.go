// Log the panic under unix to the log file

//go:build unix && !arm && !arm64
// +build unix,!arm,!arm64

package sequence

import (
	"os"
	"syscall"
)

// redirectStderr to the file passed in
func RedirectStderr(f *os.File) error {
	err := syscall.Dup2(int(f.Fd()), int(os.Stderr.Fd()))
	if err != nil {
		return err
	}
	return nil
}
