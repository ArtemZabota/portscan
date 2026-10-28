package portscan

import (
	"context"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"
)

func TestCanceledScanWaitingForSharedSlot(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s := newScanner(t, WithConcurrency(1), WithConnectTimeout(time.Hour))
		var calls atomic.Int32
		s.dial = func(ctx context.Context, _, _ string) (net.Conn, error) {
			calls.Add(1)
			<-ctx.Done()
			return nil, ctx.Err()
		}
		firstCtx, cancelFirst := context.WithCancel(context.Background())
		defer cancelFirst()
		first := startScan(t, s, firstCtx, []string{"127.0.0.1"}, Ports(80))
		synctest.Wait()
		secondCtx, cancelSecond := context.WithCancel(context.Background())
		defer cancelSecond()
		second := startScan(t, s, secondCtx, []string{"::1"}, Ports(80))
		synctest.Wait()
		cancelSecond()
		synctest.Wait()
		if got := closedResults(t, second); len(got) != 0 || calls.Load() != 1 {
			t.Fatalf("canceled queued scan dialed: calls=%d results=%v", calls.Load(), got)
		}
		cancelFirst()
		synctest.Wait()
		closedResults(t, first)
		if len(s.slots) != 0 {
			t.Fatal("a shared slot leaked")
		}
	})
}

func TestDNSUsesSharedConcurrencyLimit(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s := newScanner(t, WithConcurrency(1), WithResolveTimeout(time.Hour))
		var lookupCalls, dialCalls atomic.Int32
		s.lookup = func(ctx context.Context, _, _ string) ([]netip.Addr, error) {
			lookupCalls.Add(1)
			<-ctx.Done()
			return nil, ctx.Err()
		}
		s.dial = func(context.Context, string, string) (net.Conn, error) {
			dialCalls.Add(1)
			return &stubConn{}, nil
		}
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		dns := startScan(t, s, ctx, []string{"example.test"}, Ports(80))
		synctest.Wait()
		ip := startScan(t, s, context.Background(), []string{"127.0.0.1"}, Ports(80))
		synctest.Wait()
		if lookupCalls.Load() != 1 || dialCalls.Load() != 0 {
			t.Fatalf("DNS did not hold shared slot: DNS=%d TCP=%d", lookupCalls.Load(), dialCalls.Load())
		}
		cancel()
		if got := collect(ip); len(got) != 1 || got[0].State != Open {
			t.Fatalf("slot not released after DNS cancellation: %v", got)
		}
		synctest.Wait()
		closedResults(t, dns)
	})
}

func TestSlowConsumerEventuallyGetsEveryResult(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s := newScanner(t, WithConcurrency(2))
		s.dial = func(context.Context, string, string) (net.Conn, error) { return &stubConn{}, nil }
		results := startScan(t, s, context.Background(), []string{"127.0.0.1"}, Range(1, 100))
		seen := make(map[uint16]bool)
		for result := range results {
			if seen[result.Port] || result.State != Open {
				t.Fatalf("duplicate or invalid result: %+v", result)
			}
			seen[result.Port] = true
			time.Sleep(time.Millisecond) // Virtual time; no wall-clock delay.
		}
		if len(seen) != 100 {
			t.Fatalf("slow reader lost results: received %d", len(seen))
		}
	})
}
