package portscan

import (
	"errors"
	"syscall"
)

// Go's syscall.ECONNREFUSED and friends are synthetic POSIX values on Windows.
// Winsock returns different numeric codes; use the native WSA codes as well.
const (
	wsaNetDown     syscall.Errno = 10050
	wsaNetUnreach  syscall.Errno = 10051
	wsaTimedOut    syscall.Errno = 10060
	wsaRefused     syscall.Errno = 10061
	wsaHostDown    syscall.Errno = 10064
	wsaHostUnreach syscall.Errno = 10065
)

func isRefused(err error) bool {
	return errors.Is(err, wsaRefused) || errors.Is(err, syscall.ECONNREFUSED)
}

func isUnreachable(err error) bool {
	return errors.Is(err, wsaHostUnreach) || errors.Is(err, wsaHostDown) || errors.Is(err, wsaNetUnreach) || errors.Is(err, wsaNetDown) ||
		errors.Is(err, syscall.EHOSTUNREACH) || errors.Is(err, syscall.EHOSTDOWN) || errors.Is(err, syscall.ENETUNREACH) || errors.Is(err, syscall.ENETDOWN)
}

func isConnectTimeout(err error) bool {
	return errors.Is(err, wsaTimedOut) || errors.Is(err, syscall.ETIMEDOUT)
}
