// Log the panic under unix to the log file

//+build unix

package sequence

import (
	"os"
	"syscall"
)

// redirectStderr to the file passed in
func RedirectStderr(f *os.File) error {
	err := syscall.Dup3(int(f.Fd()), int(os.Stderr.Fd()),0)
	if err != nil {
		return err
	}
	return nil
}
