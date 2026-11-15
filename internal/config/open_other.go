//go:build !unix

package config

import "os"

const openFlags = os.O_RDONLY

func isSymlinkErr(error) bool { return false }
