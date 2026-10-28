package portscan

import (
	"net"
	"os"
	"syscall"
	"testing"
)

func TestWindowsErrorCodes(t *testing.T) {
	for _, tt := range []struct {
		code syscall.Errno
		want State
	}{
		{10061, Closed}, {10060, Timeout}, {10050, Unreachable},
		{10051, Unreachable}, {10065, Unreachable}, {10013, Error},
		{10064, Unreachable}, {syscall.EHOSTDOWN, Unreachable},
		{syscall.ECONNREFUSED, Closed}, {syscall.ETIMEDOUT, Timeout},
		{syscall.EHOSTUNREACH, Unreachable}, {syscall.ENETUNREACH, Unreachable},
		{syscall.ENETDOWN, Unreachable},
	} {
		err := &net.OpError{Op: "dial", Net: "tcp", Err: &os.SyscallError{Syscall: "connectex", Err: tt.code}}
		if got := classify(err); got != tt.want {
			t.Errorf("code %d = %s, want %s", tt.code, got, tt.want)
		}
	}
}
