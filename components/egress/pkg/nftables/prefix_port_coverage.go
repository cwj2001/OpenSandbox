// Copyright 2026 The OpenSandbox Authors
// SPDX-License-Identifier: Apache-2.0

package nftables

import (
	"net/netip"
	"slices"

	"github.com/alibaba/opensandbox/egress/pkg/policy"
)

// Static keeps only. Explicit denies take effect before these keeps; a DNS
// lease is neither static coverage nor a reason to omit a late withdrawal.
// IPv4 and IPv6 (including mapped IPv6) are separate trees even at /0.
type prefixPortCoverage map[netip.Prefix]hostSpans

func compilePrefixPortCoverage(old []policy.EgressRule, plain []netip.Prefix, scoped []policy.PortScopedRule) prefixPortCoverage {
	// Scope the work to families, networks and ports the old broad allows
	// could withdraw. In particular, one narrow DELETE should not sort the
	// long port lists of thousands of unrelated replacement rules.
	type query struct {
		scopes []netip.Prefix
		hostSpans
	}
	queries := [2]query{}
	for _, r := range old {
		if r.Action != policy.ActionAllow || len(r.Ports)+len(r.PortRanges) == 0 {
			continue
		}
		p := tcpPrefix(r.Target)
		if !p.IsValid() || p.IsSingleIP() {
			continue
		}
		i := 0
		if p.Addr().Is6() {
			i = 1
		}
		q := &queries[i]
		if len(q.scopes) == 0 || q.scopes[len(q.scopes)-1] != p {
			q.scopes = append(q.scopes, p)
		}
		q.add(tcpRuleSpans(r.Ports, r.PortRanges))
	}
	c := make(prefixPortCoverage)
	var levels [129][]netip.Prefix
	add := func(p netip.Prefix, ports tcpSpans) {
		g, seen := c[p]
		if !seen && p.Bits() > 0 {
			levels[p.Bits()] = append(levels[p.Bits()], p)
		}
		g.add(ports)
		c[p] = g
	}
	for _, q := range queries {
		if len(q.scopes) == 0 {
			continue
		}
		window := q.normalized()
		scopes := disjointScopes(q.scopes)
		for _, p := range plain {
			if overlapsScope(scopes, p) {
				add(p, allTCP)
			}
		}
		for _, r := range scoped {
			var p netip.Prefix
			if r.Target != "" {
				p = tcpPrefix(r.Target)
				if !overlapsScope(scopes, p) {
					continue
				}
			} else {
				p = netip.PrefixFrom(scopes[0].Addr(), 0).Masked()
			}
			if keep := coveredPorts(window, r); len(keep) != 0 {
				add(p, keep)
			}
		}
	}
	// A port absent from the parent's own allows covers the parent only
	// if it covers both children. Visit each sibling pair once, bottom-up;
	// do not allocate ancestor chains for isolated IPv6 hosts.
	for depth := len(levels) - 1; depth > 0; depth-- {
		for _, left := range levels[depth] {
			parent := parentScope(left)
			if parent.Addr() != left.Addr() {
				continue
			}
			_, right := splitPrefix(parent)
			if _, ok := c[right]; ok {
				if common := c.ports(left).intersect(c.ports(right)); len(common) != 0 {
					add(parent, common)
				}
			}
		}
	}
	return c
}

// Sort by starting address, widest first on a tie. Removing nested scopes
// leaves disjoint intervals, so only two neighbors can witness an overlap.
func disjointScopes(ps []netip.Prefix) []netip.Prefix {
	slices.SortFunc(ps, netip.Prefix.Compare)
	out := ps[:0]
	for _, p := range ps {
		if len(out) == 0 || !out[len(out)-1].Contains(p.Addr()) {
			out = append(out, p)
		}
	}
	return out
}

func overlapsScope(scopes []netip.Prefix, p netip.Prefix) bool {
	i, _ := slices.BinarySearchFunc(scopes, p.Addr(), func(s netip.Prefix, a netip.Addr) int {
		return s.Addr().Compare(a)
	})
	return i > 0 && scopes[i-1].Overlaps(p) || i < len(scopes) && scopes[i].Overlaps(p)
}

func coveredPorts(window tcpSpans, r policy.PortScopedRule) tcpSpans {
	if len(window) == 1 && window[0].Lo == window[0].Hi {
		if containsRawPort(r.Ports, r.Ranges, window[0].Lo) {
			return window
		}
		return nil
	}
	var points tcpSpans
	for _, port := range r.Ports {
		if window.contains(port) {
			points = append(points, policy.PortRange{Lo: port, Hi: port})
		}
	}
	for _, span := range r.Ranges {
		points = append(points, window.intersect(tcpSpans{span})...)
	}
	return mergeTCP(points)
}

func (c prefixPortCoverage) ports(p netip.Prefix) tcpSpans {
	g := c[p]
	if g.merge {
		g.normalized()
		c[p] = g
	}
	return g.spans
}

func (c prefixPortCoverage) covers(p netip.Prefix, wanted tcpSpans) bool {
	for len(wanted) != 0 && p.IsValid() {
		wanted = wanted.subtract(c.ports(p))
		p = parentScope(p)
	}
	return len(wanted) == 0
}
