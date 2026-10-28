package portscan

import (
	"context"
	"fmt"
)

// ValidationError describes invalid configuration or scan input. It can be
// inspected using errors.As. No network operations start if validation fails.
type ValidationError struct {
	Field  string
	Reason string
}

func (e *ValidationError) Error() string {
	return "portscan: " + e.Field + ": " + e.Reason
}

type portRange struct{ first, last int }

// PortSet is an immutable port specification. Its zero value is empty.
// Constructors defer validation until Scan so specifications can be composed
// inline. Repeated ports are checked only once.
type PortSet struct{ ranges []portRange }

// Ports specifies individual TCP ports. Valid values are 1 through 65535.
func Ports(ports ...int) PortSet {
	ranges := make([]portRange, len(ports))
	for i, port := range ports {
		ranges[i] = portRange{port, port}
	}
	return PortSet{ranges: ranges}
}

// Range specifies an inclusive range. Scan rejects reversed or invalid ranges.
func Range(first, last int) PortSet {
	return PortSet{ranges: []portRange{{first, last}}}
}

// Union combines specifications without modifying them.
func Union(sets ...PortSet) PortSet {
	var ranges []portRange
	for _, set := range sets {
		ranges = append(ranges, set.ranges...)
	}
	return PortSet{ranges: ranges}
}

func (p PortSet) normalize(ctx context.Context) ([]uint16, error) {
	// A fixed-size bitmap avoids allocating memory proportional to overlapping
	// ranges or to the targets × addresses × ports product.
	var seen [1024]uint64
	for _, r := range p.ranges {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if r.first < 1 || r.last > 65535 || r.first > r.last {
			return nil, &ValidationError{"ports", fmt.Sprintf("invalid range %d..%d; require 1 <= first <= last <= 65535", r.first, r.last)}
		}
		for port := r.first; port <= r.last; port++ {
			seen[port/64] |= uint64(1) << uint(port%64)
		}
	}
	var ports []uint16
	for port := 1; port <= 65535; port++ {
		if seen[port/64]&(uint64(1)<<uint(port%64)) != 0 {
			ports = append(ports, uint16(port))
		}
	}
	if len(ports) == 0 {
		return nil, &ValidationError{"ports", "at least one port is required"}
	}
	return ports, nil
}
