package portscan

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"
)

func TestTargetNormalization(t *testing.T) {
	hosts := []string{
		"127.0.0.1", "::ffff:127.0.0.1", "127.0.0.1",
		"2001:db8::1", "2001:0db8:0:0:0:0:0:1",
		"Example.COM", "example.com", "example.com.", "localhost", "xn--e1afmkfd.xn--p1ai",
	}
	got, err := normalizeTargets(context.Background(), hosts)
	if err != nil || len(got) != 6 {
		t.Fatalf("targets = %v, %v", got, err)
	}
	if got[0].ip != netip.MustParseAddr("127.0.0.1") || got[2].host != "Example.COM" {
		t.Fatalf("unexpected canonicalization: %v", got)
	}
	// Preserve absolute versus relative DNS names: search suffixes can differ.
	if got[3].host != "example.com." {
		t.Fatalf("absolute DNS name lost: %v", got)
	}
}

func TestInvalidTargets(t *testing.T) {
	for _, host := range []string{
		"", " ", " localhost", "localhost ", "256.1.1.1", "127.1", "1.2.3.4.5",
		"2001:::1", "[::1]", "[::1]:80", "127.0.0.1:80", "https://example.com",
		"10.0.0.0/24", "fe80::1%eth0", ".", "a..b", "-a.test", "a-.test",
		"a_b.test", "пример.рф", strings.Repeat("a", 64) + ".test",
		strings.Repeat("a.", 127) + "a",
	} {
		t.Run(host, func(t *testing.T) {
			_, err := normalizeTargets(context.Background(), []string{"127.0.0.1", host})
			var validation *ValidationError
			if !errors.As(err, &validation) || validation.Field != "hosts[1]" {
				t.Fatalf("expected target validation error, got %v", err)
			}
		})
	}
	if _, err := normalizeTargets(context.Background(), nil); err == nil {
		t.Fatal("accepted empty target list")
	}
}
