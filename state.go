package portscan

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"time"
)

// State is the outcome of a TCP connection attempt or a DNS resolution failure.
type State string

const (
	Open        State = "open"
	Closed      State = "closed"
	Timeout     State = "timeout"
	Unreachable State = "unreachable"
	Canceled    State = "canceled"
	Error       State = "error"
)

// Result identifies one target/address/port. IP is invalid for DNS failures.
// Host retains the first supplied spelling of a duplicate target.
// Duration measures dialing (including Close), or resolution on DNS failure;
// it excludes time waiting for a worker, concurrency slot, or result consumer.
// IP uses immutable netip.Addr so results can safely be shared between goroutines.
type Result struct {
	Host     string
	IP       netip.Addr
	Port     uint16
	State    State
	Duration time.Duration
	Err      error
}

func classify(err error) State {
	if err == nil {
		return Open
	}
	if errors.Is(err, context.Canceled) {
		return Canceled
	}
	if errors.Is(err, context.DeadlineExceeded) || isConnectTimeout(err) {
		return Timeout
	}
	if isRefused(err) {
		return Closed
	}
	if isUnreachable(err) {
		return Unreachable
	}
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
		return Unreachable
	}
	if isNetworkTimeout(err) {
		return Timeout
	}
	return Error
}

func isNetworkTimeout(err error) bool {
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return true
	}
	// Some wrappers (including net.OpError) implement Timeout but do not look
	// through every possible intermediary. A false result must not hide an
	// underlying timeout. Also retain errors.Join's multiple causes.
	switch wrapped := err.(type) {
	case interface{ Unwrap() error }:
		return isNetworkTimeout(wrapped.Unwrap())
	case interface{ Unwrap() []error }:
		for _, cause := range wrapped.Unwrap() {
			if isNetworkTimeout(cause) {
				return true
			}
		}
	}
	return false
}
