package portscan

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"testing"
)

type timeoutError struct{}

func (timeoutError) Error() string   { return "arbitrary text" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return false }

func TestClassifyPortableErrors(t *testing.T) {
	tests := []struct {
		err  error
		want State
	}{
		{nil, Open},
		{context.Canceled, Canceled},
		{context.DeadlineExceeded, Timeout},
		{timeoutError{}, Timeout},
		{errors.Join(errors.New("another error"), timeoutError{}), Timeout},
		{&net.DNSError{IsNotFound: true}, Unreachable},
		{&net.DNSError{IsTimeout: true}, Timeout},
		{&net.DNSError{IsTemporary: true, Err: "temporary resolver failure"}, Error},
		{errors.New("connection refused"), Error},
		{errors.New("i/o timeout"), Error},
		{errors.New("network is unreachable"), Error},
	}
	for _, tt := range tests {
		if got := classify(tt.err); got != tt.want {
			t.Errorf("classify(%v) = %s, want %s", tt.err, got, tt.want)
		}
		if tt.err != nil {
			wrapped := &net.OpError{Op: "dial", Net: "tcp", Err: &os.SyscallError{Syscall: "connect", Err: fmt.Errorf("wrapped: %w", tt.err)}}
			if got := classify(wrapped); got != tt.want {
				t.Errorf("classify(wrapped %v) = %s, want %s", tt.err, got, tt.want)
			}
		}
	}
}
