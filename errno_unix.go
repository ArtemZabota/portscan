//go:build aix || android || darwin || dragonfly || freebsd || illumos || ios || linux || netbsd || openbsd || solaris

package portscan

import (
	"errors"
	"syscall"
)

func isRefused(err error) bool { return errors.Is(err, syscall.ECONNREFUSED) }

func isUnreachable(err error) bool {
	return errors.Is(err, syscall.EHOSTUNREACH) || errors.Is(err, syscall.EHOSTDOWN) ||
		errors.Is(err, syscall.ENETUNREACH) || errors.Is(err, syscall.ENETDOWN)
}

func isConnectTimeout(err error) bool { return errors.Is(err, syscall.ETIMEDOUT) }
