//go:build unix

package config

import (
	"errors"
	"syscall"
)

// openFlags refuses a symlink as the final path element and never blocks on a FIFO or device.
const openFlags = syscall.O_RDONLY | syscall.O_NOFOLLOW | syscall.O_NONBLOCK

func isSymlinkErr(err error) bool { return errors.Is(err, syscall.ELOOP) }
