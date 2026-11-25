// Copyright 2026 The OpenSandbox Authors
// SPDX-License-Identifier: Apache-2.0

package nftables

import (
	"fmt"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/alibaba/opensandbox/egress/pkg/policy"
)

func TestWithdrawnPortPrefixCoverage(t *testing.T) {
	for _, cidr := range []string{"198.18.0.0/29", "2001:db8::/125", "::ffff:198.18.0.0/125", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:fff8/125"} {
		p := netip.MustParsePrefix(cidr)
		var hosts [8]netip.Addr
		hosts[0] = p.Addr()
		for i := 1; i < len(hosts); i++ {
			hosts[i] = hosts[i-1].Next()
		}
		old := mustPolicy(t, fmt.Sprintf(`{"egress":[{"action":"allow","target":"%s","ports":[443,8443]}]}`, p))
		for _, mode := range []string{"hole", "split-cover", "default-allow"} {
			t.Run(cidr+"/"+mode, func(t *testing.T) {
				bits, right := p.Bits()+2, 6
				if mode == "split-cover" {
					bits, right = p.Bits()+1, 4
				}
				rules := fmt.Sprintf(`{"egress":[{"action":"allow","target":"%s","ports":[443]},{"action":"allow","target":"%s","ports":[443]},{"action":"allow","target":"%s","ports":[8443]}]}`, netip.PrefixFrom(hosts[0], bits), netip.PrefixFrom(hosts[right], bits), p)
				if mode == "default-allow" {
					rules = fmt.Sprintf(`{"defaultAction":"allow","egress":[{"action":"deny","target":"%s","ports":[443]}]}`, hosts[3])
				}
				next := mustPolicy(t, rules)
				m, _ := recordingManager()
				_, err := m.ApplyStaticComputingEstablishedDrops(t.Context(), old, next)
				require.NoError(t, err)
				for stage := range 2 {
					for i, addr := range hosts {
						cut := mode == "hole" && i >= 2 && i < 6 || mode == "default-allow" && i == 3
						require.Equal(t, cut, m.lastDrops.MatchesFlow(addr, 443), "stage %d %s", stage, addr)
						require.False(t, m.lastDrops.MatchesFlow(addr, 8443), "sibling port remains permitted")
						require.False(t, m.lastDrops.MatchesFlow(addr, 9000), "outside the removed allow")
						if addr.Is4In6() {
							require.False(t, m.lastDrops.MatchesFlow(addr.Unmap(), 443))
						}
					}
					if stage == 0 {
						require.NoError(t, m.ApplyStatic(t.Context(), next))
					}
				}
			})
		}
	}
}

func TestPrefixCoverageCombinesOnlySharedPorts(t *testing.T) {
	// A global port, an IPv6-only /0 port, and a port assembled from
	// one half plus two quarters cover the old window. The unilateral
	// port is not promoted, and neither family inherits the other's /0.
	next := mustPolicy(t, `{"egress":[
		{"action":"allow","ports":[53]},
		{"action":"allow","target":"::/0","ports":[65535]},
		{"action":"allow","target":"0.0.0.0/0","ports":[80]},
		{"action":"allow","target":"2001:db8::/125","ports":[443]},
		{"action":"allow","target":"2001:db8::/126","ports":[8443,9000]},
		{"action":"allow","target":"2001:db8::4/127","ports":[8443]},
		{"action":"allow","target":"2001:db8::6/127","ports":[8443]}]}`)
	old := mustPolicy(t, `{"egress":[{"action":"allow","target":"2001:db8::/125","ports":[53,443,8443,65535]}]}`)
	require.True(t, ComputeEstablishedDrops(old, next, nil).Empty(), "no redundant late rule on a complete cover")
	old = mustPolicy(t, `{"egress":[{"action":"allow","target":"2001:db8::/125","ports":[80,9000]}]}`)
	d := ComputeEstablishedDrops(old, next, nil)
	left, right := netip.MustParseAddr("2001:db8::2"), netip.MustParseAddr("2001:db8::5")
	require.True(t, d.MatchesFlow(left, 80))
	require.True(t, d.MatchesFlow(right, 80))
	require.False(t, d.MatchesFlow(left, 9000))
	require.True(t, d.MatchesFlow(right, 9000))
}

func BenchmarkScopedPrefixCoverage(b *testing.B) {
	var oldRules []policy.EgressRule
	for port := 10000; port < 10032; port++ {
		oldRules = append(oldRules, policy.EgressRule{Action: policy.ActionAllow, Target: "198.18.0.0/23", Ports: []int{port}})
	}
	old := benchmarkPortPolicy(b, policy.ActionDeny, oldRules)
	for _, gap := range []int{0, 256, 510, 511, -1} {
		b.Run(fmt.Sprintf("gap=%d", gap), func(b *testing.B) {
			var keeps []policy.EgressRule
			for i := range 512 {
				if i != gap {
					ip := netip.AddrFrom4([4]byte{198, 18, byte(i >> 8), byte(i)})
					keeps = append(keeps, policy.EgressRule{Action: policy.ActionAllow, Target: ip.String()})
				}
			}
			next := benchmarkPortPolicy(b, policy.ActionDeny, keeps)
			d := ComputeEstablishedDrops(old, next, nil)
			for i := range 512 {
				ip := netip.AddrFrom4([4]byte{198, 18, byte(i >> 8), byte(i)})
				for port := 10000; port < 10032; port++ {
					require.Equal(b, gap == i, d.MatchesFlow(ip, port))
				}
			}
			b.ReportAllocs()
			for b.Loop() {
				ComputeEstablishedDrops(old, next, nil)
			}
		})
	}
}

// The enclosing prefix spans both old scopes and every replacement rule,
// but none of those rules covers either withdrawal. Their port lists should
// not need sorting to decide what happens to the two subnets.
func BenchmarkScopedPrefixCoverageDisjoint(b *testing.B) {
	ports := make([]int, 128)
	for i := range ports {
		ports[i] = 2048 + (37*i)%len(ports)
	}
	old := benchmarkPortPolicy(b, policy.ActionDeny, []policy.EgressRule{
		{Action: policy.ActionAllow, Target: "10.0.0.0/24", Ports: ports},
		{Action: policy.ActionAllow, Target: "240.0.0.0/24", Ports: ports},
	})
	keeps := make([]policy.EgressRule, 1024)
	for i := range keeps {
		ip := netip.AddrFrom4([4]byte{203, byte(i >> 8), byte(i), 0})
		keeps[i] = policy.EgressRule{Action: policy.ActionAllow, Target: netip.PrefixFrom(ip, 24).String(), Ports: ports}
	}
	next := benchmarkPortPolicy(b, policy.ActionDeny, keeps)
	d := ComputeEstablishedDrops(old, next, nil)
	for _, port := range ports {
		require.True(b, d.MatchesFlow(netip.MustParseAddr("10.0.0.1"), port))
		require.True(b, d.MatchesFlow(netip.MustParseAddr("240.0.0.1"), port))
		require.False(b, d.MatchesFlow(netip.MustParseAddr("203.0.0.1"), port))
	}
	b.ReportAllocs()
	for b.Loop() {
		ComputeEstablishedDrops(old, next, nil)
	}
}
