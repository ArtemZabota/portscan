package portscan

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"time"
)

type config struct {
	concurrency    int
	connectTimeout time.Duration
	resolveTimeout time.Duration
}

// Option configures a Scanner created with New.
type Option func(*config) error

// WithConcurrency limits simultaneous DNS lookups and TCP connects across all
// Scan calls on the same Scanner. The default is 64. n must be positive.
func WithConcurrency(n int) Option {
	return func(c *config) error {
		if n < 1 {
			return &ValidationError{"concurrency", "must be positive"}
		}
		c.concurrency = n
		return nil
	}
}

// WithConnectTimeout sets the timeout of each TCP attempt, excluding queue time.
// The default is 500ms. d must be positive.
func WithConnectTimeout(d time.Duration) Option {
	return func(c *config) error {
		if d <= 0 {
			return &ValidationError{"connect timeout", "must be positive"}
		}
		c.connectTimeout = d
		return nil
	}
}

// WithResolveTimeout sets a separate timeout per DNS name. The default is 5s.
// d must be positive.
func WithResolveTimeout(d time.Duration) Option {
	return func(c *config) error {
		if d <= 0 {
			return &ValidationError{"resolve timeout", "must be positive"}
		}
		c.resolveTimeout = d
		return nil
	}
}

// Scanner is safe for concurrent reuse. Create it with New; the zero value is
// not usable. Scanner owns no persistent workers and does not require Close.
type Scanner struct {
	config config
	slots  chan struct{}
	dial   func(context.Context, string, string) (net.Conn, error)
	lookup func(context.Context, string, string) ([]netip.Addr, error)
}

// New validates options and returns a reusable Scanner using the standard
// library's TCP dialer and resolver. It performs no network operations.
func New(options ...Option) (*Scanner, error) {
	c := config{concurrency: 64, connectTimeout: 500 * time.Millisecond, resolveTimeout: 5 * time.Second}
	for _, option := range options {
		if option == nil {
			return nil, &ValidationError{"option", "must not be nil"}
		}
		if err := option(&c); err != nil {
			return nil, err
		}
	}
	dialer := &net.Dialer{KeepAlive: -1}
	resolver := &net.Resolver{}
	return &Scanner{
		config: c,
		slots:  make(chan struct{}, c.concurrency),
		dial:   dialer.DialContext,
		lookup: resolver.LookupNetIP,
	}, nil
}

// Scan validates and copies inputs synchronously, then streams results.
// Every unique (target, resolved IP, port) produces one result on normal
// completion. Failed DNS produces one result per port with an invalid IP.
// Validation errors return a nil channel. Runtime errors appear in Result.Err.
//
// Read until the channel closes or cancel ctx. Cancellation stops scheduling
// and interrupts DNS and TCP operations, even if nobody reads the channel.
// Results may be dropped on cancellation; unstarted jobs have no result.
// Check ctx.Err() after draining to detect an interrupted scan.
func (s *Scanner) Scan(ctx context.Context, hosts []string, ports PortSet) (<-chan Result, error) {
	if ctx == nil {
		return nil, &ValidationError{"context", "must not be nil"}
	}
	if s == nil || s.slots == nil {
		return nil, &ValidationError{"scanner", "must be created with New"}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	targets, err := normalizeTargets(ctx, hosts)
	if err != nil {
		return nil, err
	}
	portList, err := ports.normalize(ctx)
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	results := make(chan Result, s.config.concurrency)
	go s.run(ctx, targets, portList, results)
	return results, nil
}

type job struct {
	host string
	ip   netip.Addr
	port uint16
}

func (s *Scanner) run(ctx context.Context, targets []target, ports []uint16, results chan<- Result) {
	defer close(results)
	jobs := make(chan job) // Lazy production: no targets × IPs × ports allocation.
	var workers sync.WaitGroup
	for i := 0; i < s.config.concurrency; i++ {
		workers.Go(func() {
			for {
				if ctx.Err() != nil {
					return
				}
				select {
				case <-ctx.Done():
					return
				case next, ok := <-jobs:
					if !ok || !s.acquire(ctx) {
						return
					}
					result := s.connect(ctx, next)
					s.release()
					if !sendResult(ctx, results, result) {
						return
					}
				}
			}
		})
	}
	s.produce(ctx, targets, ports, jobs, results)
	close(jobs)
	workers.Wait()
}

func (s *Scanner) produce(ctx context.Context, targets []target, ports []uint16, jobs chan<- job, results chan<- Result) {
	for _, target := range targets {
		if ctx.Err() != nil {
			return
		}
		ips := []netip.Addr{target.ip}
		if !target.ip.IsValid() {
			if !s.acquire(ctx) {
				return
			}
			started := time.Now()
			lookupCtx, cancel := context.WithTimeout(ctx, s.config.resolveTimeout)
			resolved, err := s.lookup(lookupCtx, "ip", target.host)
			cancel()
			s.release()
			duration := time.Since(started)
			if err == nil {
				ips = uniqueIPs(resolved)
				if len(ips) == 0 {
					err = &net.DNSError{Name: target.host, Err: "no usable addresses", IsNotFound: true}
				}
			}
			if err != nil {
				for _, port := range ports {
					result := Result{Host: target.host, Port: port, State: operationState(ctx, err), Duration: duration, Err: fmt.Errorf("resolve %s: %w", target.host, err)}
					if !sendResult(ctx, results, result) || ctx.Err() != nil {
						return
					}
				}
				continue
			}
		}
		for _, ip := range ips {
			for _, port := range ports {
				if ctx.Err() != nil {
					return
				}
				select {
				case <-ctx.Done():
					return
				case jobs <- job{target.host, ip, port}:
				}
			}
		}
	}
}

func uniqueIPs(addresses []netip.Addr) []netip.Addr {
	seen := make(map[netip.Addr]bool, len(addresses))
	ips := make([]netip.Addr, 0, len(addresses))
	for _, ip := range addresses {
		ip = ip.Unmap()
		if ip.IsValid() && ip.Zone() == "" && !seen[ip] {
			seen[ip] = true
			ips = append(ips, ip)
		}
	}
	return ips
}

func (s *Scanner) connect(ctx context.Context, j job) Result {
	started := time.Now()
	connectCtx, cancel := context.WithTimeout(ctx, s.config.connectTimeout)
	defer cancel()
	address := net.JoinHostPort(j.ip.String(), strconv.Itoa(int(j.port)))
	conn, err := s.dial(connectCtx, "tcp", address)
	state := operationState(ctx, err)
	if conn != nil {
		// Success remains open if Close itself fails: the handshake succeeded.
		if closeErr := conn.Close(); err == nil && closeErr != nil {
			err = fmt.Errorf("close %s: %w", address, closeErr)
		}
	}
	return Result{Host: j.host, IP: j.ip, Port: j.port, State: state, Duration: time.Since(started), Err: err}
}

func operationState(ctx context.Context, err error) State {
	// A parent deadline is scan cancellation; a per-operation deadline is timeout.
	// A completed handshake stays open even if cancellation races with its return.
	if err != nil && ctx.Err() != nil {
		return Canceled
	}
	return classify(err)
}

func (s *Scanner) acquire(ctx context.Context) bool {
	if ctx.Err() != nil {
		return false
	}
	select {
	case <-ctx.Done():
		return false
	case s.slots <- struct{}{}:
		if ctx.Err() != nil {
			s.release()
			return false
		}
		return true
	}
}

func (s *Scanner) release() { <-s.slots }

func sendResult(ctx context.Context, results chan<- Result, result Result) bool {
	// First try a nonblocking send so cancellation results reach an available
	// consumer/buffer, without ever requiring that consumer for shutdown.
	select {
	case results <- result:
		return true
	default:
	}
	select {
	case results <- result:
		return true
	case <-ctx.Done():
		return false
	}
}
