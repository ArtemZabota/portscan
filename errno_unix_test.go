//go:build aix || android || darwin || dragonfly || freebsd || illumos || ios || linux || netbsd || openbsd || solaris

package portscan

import (
	"net"
	"os"
	"syscall"
	"testing"
)

func TestUnixErrorCodes(t *testing.T) {
	for _, tt := range []struct {
		code syscall.Errno
		want State
	}{
		{syscall.ECONNREFUSED, Closed}, {syscall.ETIMEDOUT, Timeout},
		{syscall.EHOSTUNREACH, Unreachable}, {syscall.ENETUNREACH, Unreachable},
		{syscall.EHOSTDOWN, Unreachable},
		{syscall.ENETDOWN, Unreachable}, {syscall.EACCES, Error},
	} {
		err := &net.OpError{Op: "dial", Net: "tcp", Err: &os.SyscallError{Syscall: "connect", Err: tt.code}}
		if got := classify(err); got != tt.want {
			t.Errorf("code %d = %s, want %s", tt.code, got, tt.want)
		}
	}
}
