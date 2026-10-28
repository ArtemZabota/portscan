package portscan

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"
)

type stubConn struct {
	net.Conn
	closed   *atomic.Int32
	closeErr error
}

func (c *stubConn) Close() error {
	if c.closed != nil {
		c.closed.Add(1)
	}
	return c.closeErr
}

func newScanner(t *testing.T, options ...Option) *Scanner {
	t.Helper()
	s, err := New(options...)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func startScan(t *testing.T, s *Scanner, ctx context.Context, hosts []string, ports PortSet) <-chan Result {
	t.Helper()
	results, err := s.Scan(ctx, hosts, ports)
	if err != nil {
		t.Fatal(err)
	}
	return results
}

func collect(results <-chan Result) []Result {
	var got []Result
	for result := range results {
		got = append(got, result)
	}
	return got
}

// This assertion cannot unblock a stuck producer: it does not wait on reads.
func closedResults(t *testing.T, results <-chan Result) []Result {
	t.Helper()
	var got []Result
	for {
		select {
		case result, ok := <-results:
			if !ok {
				return got
			}
			got = append(got, result)
		default:
			t.Fatal("results channel was not closed after cancellation")
			return nil
		}
	}
}

func TestConfigurationValidation(t *testing.T) {
	for _, option := range []Option{
		nil, WithConcurrency(0), WithConcurrency(-1),
		WithConnectTimeout(0), WithConnectTimeout(-1), WithResolveTimeout(0), WithResolveTimeout(-1),
	} {
		s, err := New(option)
		var validation *ValidationError
		if s != nil || !errors.As(err, &validation) {
			t.Errorf("expected nil scanner and validation error; got %v, %v", s, err)
		}
	}
}

func TestScanValidationBeforeNetwork(t *testing.T) {
	s := newScanner(t)
	var calls atomic.Int32
	s.dial = func(context.Context, string, string) (net.Conn, error) {
		calls.Add(1)
		return &stubConn{}, nil
	}
	s.lookup = func(context.Context, string, string) ([]netip.Addr, error) {
		calls.Add(1)
		return nil, errors.New("unexpected lookup")
	}
	for _, tt := range []struct {
		s     *Scanner
		ctx   context.Context
		hosts []string
		ports PortSet
	}{
		{s, nil, []string{"127.0.0.1"}, Ports(80)},
		{nil, context.Background(), []string{"127.0.0.1"}, Ports(80)},
		{&Scanner{}, context.Background(), []string{"127.0.0.1"}, Ports(80)},
		{s, context.Background(), nil, Ports(80)},
		{s, context.Background(), []string{"example.test", ""}, Ports(80)},
		{s, context.Background(), []string{"example.test"}, Range(2, 1)},
	} {
		results, err := tt.s.Scan(tt.ctx, tt.hosts, tt.ports)
		var validation *ValidationError
		if results != nil || !errors.As(err, &validation) || validation.Error() == "" {
			t.Errorf("expected validation error and nil channel, got %v, %v", results, err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if results, err := s.Scan(ctx, []string{"127.0.0.1"}, Ports(80)); results != nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("already canceled scan = %v, %v", results, err)
	}
	if calls.Load() != 0 {
		t.Fatalf("validation caused %d network calls", calls.Load())
	}
}

func TestDNSAddressesAndInputOwnership(t *testing.T) {
	s := newScanner(t, WithConcurrency(3))
	var lookupCalls atomic.Int32
	s.lookup = func(_ context.Context, network, host string) ([]netip.Addr, error) {
		lookupCalls.Add(1)
		if network != "ip" || host != "Example.test" {
			t.Errorf("unexpected lookup: %s %s", network, host)
		}
		return []netip.Addr{
			netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("::ffff:192.0.2.1"),
			netip.MustParseAddr("2001:db8::1"), {},
		}, nil
	}
	var closed atomic.Int32
	var mu sync.Mutex
	addresses := make(map[string]int)
	s.dial = func(_ context.Context, network, address string) (net.Conn, error) {
		if network != "tcp" {
			t.Errorf("network = %s", network)
		}
		mu.Lock()
		addresses[address]++
		mu.Unlock()
		return &stubConn{closed: &closed}, nil
	}
	hosts := []string{"Example.test", "example.test", "192.0.2.1"}
	results := startScan(t, s, context.Background(), hosts, Ports(80, 443, 80))
	hosts[0] = "changed.test"
	got := collect(results)
	if len(got) != 6 || lookupCalls.Load() != 1 || closed.Load() != 6 {
		t.Fatalf("results=%d lookups=%d closes=%d", len(got), lookupCalls.Load(), closed.Load())
	}
	for _, result := range got {
		if result.State != Open || result.Err != nil || !result.IP.IsValid() || result.Host == "changed.test" {
			t.Errorf("unexpected result: %+v", result)
		}
	}
	want := map[string]int{"192.0.2.1:80": 2, "192.0.2.1:443": 2, "[2001:db8::1]:80": 1, "[2001:db8::1]:443": 1}
	if !reflect.DeepEqual(addresses, want) {
		t.Fatalf("dialed %v, want %v", addresses, want)
	}
}

func TestDNSFailureDoesNotAbortOtherHosts(t *testing.T) {
	for _, tt := range []struct {
		name string
		err  error
		want State
	}{
		{"missing", &net.DNSError{IsNotFound: true, Name: "missing.test"}, Unreachable},
		{"temporary", &net.DNSError{IsTemporary: true}, Error},
		{"empty answer", nil, Unreachable},
	} {
		t.Run(tt.name, func(t *testing.T) {
			s := newScanner(t)
			s.lookup = func(context.Context, string, string) ([]netip.Addr, error) { return nil, tt.err }
			s.dial = func(context.Context, string, string) (net.Conn, error) { return &stubConn{}, nil }
			got := collect(startScan(t, s, context.Background(), []string{"missing.test", "127.0.0.1"}, Ports(80, 443)))
			if len(got) != 4 {
				t.Fatalf("got %d results, want 4", len(got))
			}
			for _, result := range got {
				if result.Host == "missing.test" {
					if result.State != tt.want || result.IP.IsValid() || result.Err == nil {
						t.Errorf("DNS failure: %+v", result)
					}
					if tt.err != nil && !errors.Is(result.Err, tt.err) {
						t.Errorf("DNS error lost its cause: %v", result.Err)
					}
				} else if result.State != Open {
					t.Errorf("other host was affected: %+v", result)
				}
			}
		})
	}
}

func TestConcurrencySharedAcrossScans(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s := newScanner(t, WithConcurrency(3))
		gate := make(chan struct{})
		var active, peak, closes atomic.Int32
		s.dial = func(context.Context, string, string) (net.Conn, error) {
			n := active.Add(1)
			for old := peak.Load(); n > old; old = peak.Load() {
				if peak.CompareAndSwap(old, n) {
					break
				}
			}
			<-gate
			active.Add(-1)
			return &stubConn{closed: &closes}, nil
		}
		first := startScan(t, s, context.Background(), []string{"127.0.0.1"}, Range(1, 20))
		second := startScan(t, s, context.Background(), []string{"::1"}, Range(1, 20))
		synctest.Wait()
		if active.Load() != 3 {
			t.Fatalf("active connections = %d, want 3", active.Load())
		}
		close(gate)
		if len(collect(first)) != 20 || len(collect(second)) != 20 || peak.Load() > 3 || closes.Load() != 40 {
			t.Fatalf("lost results or exceeded concurrency: peak=%d closes=%d", peak.Load(), closes.Load())
		}
	})
}

func TestCancelWithoutConsumerAndReuse(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s := newScanner(t, WithConcurrency(2))
		var calls, closes atomic.Int32
		s.dial = func(context.Context, string, string) (net.Conn, error) {
			calls.Add(1)
			return &stubConn{closed: &closes}, nil
		}
		ctx, cancel := context.WithCancel(context.Background())
		results := startScan(t, s, ctx, []string{"127.0.0.1", "::1"}, Range(1, 65535))
		synctest.Wait()
		if calls.Load() != 4 { // Two buffered results + two workers awaiting send.
			t.Fatalf("backpressure did not bound work: %d dials", calls.Load())
		}
		cancel()
		synctest.Wait()
		closedResults(t, results)
		if calls.Load() != 4 || closes.Load() != 4 {
			t.Fatalf("cancellation scheduled work or leaked connections: dials=%d closes=%d", calls.Load(), closes.Load())
		}
		if got := collect(startScan(t, s, context.Background(), []string{"127.0.0.1"}, Ports(80))); len(got) != 1 {
			t.Fatalf("scanner was not reusable: %v", got)
		}
	})
}

func TestCancelInflightConnections(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s := newScanner(t, WithConcurrency(3), WithConnectTimeout(time.Hour))
		var calls atomic.Int32
		s.dial = func(ctx context.Context, _, _ string) (net.Conn, error) {
			calls.Add(1)
			<-ctx.Done()
			return nil, ctx.Err()
		}
		ctx, cancel := context.WithCancel(context.Background())
		results := startScan(t, s, ctx, []string{"127.0.0.1"}, Range(1, 65535))
		synctest.Wait()
		cancel()
		synctest.Wait()
		got := closedResults(t, results)
		if calls.Load() != 3 || len(got) != 3 {
			t.Fatalf("dials=%d canceled results=%d", calls.Load(), len(got))
		}
		for _, result := range got {
			if result.State != Canceled || !errors.Is(result.Err, context.Canceled) {
				t.Errorf("expected canceled, got %+v", result)
			}
		}
	})
}

func TestConnectAndParentTimeouts(t *testing.T) {
	for _, parentTimeout := range []bool{false, true} {
		t.Run(map[bool]string{false: "connect timeout", true: "parent deadline"}[parentTimeout], func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				s := newScanner(t, WithConcurrency(1), WithConnectTimeout(time.Second))
				s.dial = func(ctx context.Context, _, _ string) (net.Conn, error) {
					<-ctx.Done()
					return nil, ctx.Err()
				}
				ctx := context.Background()
				want, duration := Timeout, time.Second
				if parentTimeout {
					var cancel context.CancelFunc
					ctx, cancel = context.WithTimeout(ctx, 100*time.Millisecond)
					defer cancel()
					want, duration = Canceled, 100*time.Millisecond
				}
				got := collect(startScan(t, s, ctx, []string{"127.0.0.1"}, Ports(80)))
				if len(got) != 1 || got[0].State != want || got[0].Duration != duration || !errors.Is(got[0].Err, context.DeadlineExceeded) {
					t.Fatalf("timeout result = %+v; want state=%s duration=%v", got, want, duration)
				}
			})
		})
	}
}

func TestResolveTimeoutAndCancellation(t *testing.T) {
	for _, shouldCancel := range []bool{false, true} {
		t.Run(map[bool]string{false: "resolve timeout", true: "cancel lookup"}[shouldCancel], func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				s := newScanner(t, WithConcurrency(1), WithResolveTimeout(time.Second))
				s.lookup = func(ctx context.Context, _, _ string) ([]netip.Addr, error) {
					<-ctx.Done()
					return nil, ctx.Err()
				}
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				results := startScan(t, s, ctx, []string{"missing.test"}, Ports(80, 443))
				if shouldCancel {
					synctest.Wait()
					cancel()
					synctest.Wait()
					got := closedResults(t, results)
					if len(got) != 1 || got[0].State != Canceled {
						t.Fatalf("canceled DNS results = %+v", got)
					}
				} else {
					got := collect(results)
					if len(got) != 2 {
						t.Fatalf("got %d DNS results", len(got))
					}
					for _, result := range got {
						if result.State != Timeout || result.Duration != time.Second || result.IP.IsValid() {
							t.Errorf("DNS timeout = %+v", result)
						}
					}
				}
			})
		})
	}
}

func TestSlowConsumerDoesNotBlockOtherScan(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s := newScanner(t, WithConcurrency(1))
		s.dial = func(context.Context, string, string) (net.Conn, error) { return &stubConn{}, nil }
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		abandoned := startScan(t, s, ctx, []string{"127.0.0.1"}, Range(1, 65535))
		synctest.Wait()
		if got := collect(startScan(t, s, context.Background(), []string{"::1"}, Ports(80))); len(got) != 1 || got[0].State != Open {
			t.Fatalf("slow consumer held a shared slot: %+v", got)
		}
		cancel()
		synctest.Wait()
		closedResults(t, abandoned)
	})
}

func TestCloseErrorKeepsOpenState(t *testing.T) {
	s := newScanner(t, WithConcurrency(1))
	closeErr := errors.New("close failed")
	var closed atomic.Int32
	s.dial = func(context.Context, string, string) (net.Conn, error) {
		return &stubConn{closed: &closed, closeErr: closeErr}, nil
	}
	got := collect(startScan(t, s, context.Background(), []string{"127.0.0.1"}, Ports(80)))
	if len(got) != 1 || got[0].State != Open || !errors.Is(got[0].Err, closeErr) || closed.Load() != 1 {
		t.Fatalf("close error = %+v, closes=%d", got, closed.Load())
	}
}

func TestLoopbackOpenAndConnectionClosed(t *testing.T) {
	for _, network := range []string{"tcp4", "tcp6"} {
		t.Run(network, func(t *testing.T) {
			address := "127.0.0.1:0"
			if network == "tcp6" {
				address = "[::1]:0"
			}
			listener, err := net.Listen(network, address)
			if err != nil {
				if network == "tcp6" {
					t.Skipf("IPv6 loopback unavailable: %v", err)
				}
				t.Fatal(err)
			}
			defer listener.Close()
			if network == "tcp6" {
				// Some Windows hosts allow binding ::1 but block outgoing IPv6.
				// Probe with the standard library before testing the scanner, so
				// a scanner regression cannot be mistaken for missing capability.
				probe, err := net.DialTimeout(network, listener.Addr().String(), time.Second)
				if err != nil {
					t.Skipf("IPv6 loopback connect unavailable: %v", err)
				}
				accepted, err := listener.Accept()
				probe.Close()
				if err != nil {
					t.Fatal(err)
				}
				accepted.Close()
			}
			serverDone := make(chan error, 1)
			go func() {
				conn, err := listener.Accept()
				if err != nil {
					serverDone <- err
					return
				}
				defer conn.Close()
				if err := conn.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
					serverDone <- err
					return
				}
				_, err = conn.Read(make([]byte, 1))
				serverDone <- err
			}()
			addr := listener.Addr().(*net.TCPAddr)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			s := newScanner(t, WithConnectTimeout(2*time.Second))
			got := collect(startScan(t, s, ctx, []string{addr.IP.String()}, Ports(addr.Port)))
			if len(got) != 1 || got[0].State != Open || got[0].Err != nil || got[0].Duration < 0 {
				t.Fatalf("loopback result = %+v", got)
			}
			select {
			case err := <-serverDone:
				if !errors.Is(err, io.EOF) {
					t.Fatalf("connection not cleanly closed: %v", err)
				}
			case <-ctx.Done():
				t.Fatal("server did not observe connection closure")
			}
		})
	}
}

func TestLoopbackClosed(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	s := newScanner(t, WithConnectTimeout(2*time.Second))
	got := collect(startScan(t, s, ctx, []string{"127.0.0.1"}, Ports(port)))
	if len(got) != 1 || got[0].State != Closed || got[0].Err == nil {
		t.Fatalf("refused loopback result = %+v", got)
	}
}
