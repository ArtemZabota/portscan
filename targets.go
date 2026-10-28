package portscan

import (
	"context"
	"fmt"
	"net/netip"
	"strings"
)

type target struct {
	host string
	ip   netip.Addr
}

func normalizeTargets(ctx context.Context, hosts []string) ([]target, error) {
	if len(hosts) == 0 {
		return nil, &ValidationError{"hosts", "at least one host is required"}
	}
	seen := make(map[string]bool, len(hosts))
	targets := make([]target, 0, len(hosts))
	for i, host := range hosts {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		ip, err := netip.ParseAddr(host)
		key := strings.ToLower(host)
		if err == nil && ip.Zone() == "" {
			ip = ip.Unmap()
			key = ip.String()
		} else if !validDNSName(host) {
			return nil, &ValidationError{fmt.Sprintf("hosts[%d]", i), fmt.Sprintf("invalid host %q; require an IP literal or an ASCII DNS name without a port", host)}
		}
		if !seen[key] {
			seen[key] = true
			targets = append(targets, target{host: host, ip: ip})
		}
	}
	return targets, nil
}

func validDNSName(name string) bool {
	name = strings.TrimSuffix(name, ".")
	if len(name) == 0 || len(name) > 253 {
		return false
	}
	// Reject malformed dotted numeric addresses instead of treating them as DNS.
	onlyDigitsAndDots := true
	for _, c := range name {
		if c != '.' && (c < '0' || c > '9') {
			onlyDigitsAndDots = false
		}
	}
	if onlyDigitsAndDots && strings.Contains(name, ".") {
		return false
	}
	for _, label := range strings.Split(name, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}
