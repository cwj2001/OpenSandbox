// Copyright 2026 The OpenSandbox Authors
// SPDX-License-Identifier: Apache-2.0

package nftables

import (
	"fmt"
	"net/netip"
	"slices"
	"testing"

	"github.com/alibaba/opensandbox/egress/pkg/policy"
	"github.com/stretchr/testify/require"
)

func TestAlwaysDroppedExcludesAllReturnHoles(t *testing.T) {
	floor := tcpSpans{{Lo: 1, Hi: 20}, {Lo: 40, Hi: 50}, {Lo: 65530, Hi: 65535}}
	plan := broadTCP{rules: map[netip.Prefix]portDelta{
		{}:                                     {block: floor},
		netip.MustParsePrefix("192.0.2.0/24"):  {spare: tcpSpans{{Lo: 1, Hi: 2}, {Lo: 10, Hi: 12}}},
		netip.MustParsePrefix("192.0.2.1/32"):  {spare: tcpSpans{{Lo: 10, Hi: 15}, {Lo: 40, Hi: 42}}},
		netip.MustParsePrefix("2001:db8::/32"): {spare: tcpSpans{{Lo: 16, Hi: 41}, {Lo: 65535, Hi: 65535}}},
	}}
	original := make(map[netip.Prefix]portDelta)
	for p, r := range plan.rules {
		original[p] = portDelta{block: slices.Clone(r.block), spare: slices.Clone(r.spare)}
	}
	require.Equal(t, tcpSpans{{Lo: 3, Hi: 9}, {Lo: 43, Hi: 50}, {Lo: 65530, Hi: 65534}}, plan.alwaysDropped())
	require.Equal(t, original, plan.rules, "rendering cannot mutate either phase of a published plan")
}

func TestAlwaysDroppedStopsAtFullCoverageAcrossFamilies(t *testing.T) {
	plan := broadTCP{rules: map[netip.Prefix]portDelta{
		{}:                                       {block: tcpSpans{{Lo: 1, Hi: 20}, {Lo: 40, Hi: 50}}},
		netip.MustParsePrefix("192.0.2.1/32"):    {spare: tcpSpans{{Lo: 1, Hi: 10}, {Lo: 40, Hi: 44}}},
		netip.MustParsePrefix("2001:db8::1/128"): {spare: tcpSpans{{Lo: 11, Hi: 30}, {Lo: 45, Hi: 60}}},
	}}
	require.Empty(t, plan.alwaysDropped(), "neither spare covers the original floor on its own")
}

func BenchmarkAlwaysDropped(b *testing.B) {
	dense, even := make(tcpSpans, 4096), make(tcpSpans, 4096)
	var interleaved tcpSpans
	for i := range dense {
		dense[i] = policy.PortRange{Lo: 2*i + 1, Hi: 2*i + 1}
		even[i] = policy.PortRange{Lo: 2*i + 2, Hi: 2*i + 2}
		if i%2 == 0 {
			interleaved = append(interleaved, dense[i])
		}
	}
	distinct := make([]tcpSpans, 1024)
	for i := range distinct {
		distinct[i] = even[i : i+1]
	}
	copies := func(s tcpSpans) []tcpSpans { return []tcpSpans{slices.Clone(s), slices.Clone(s)} }
	nearTotal := tcpSpans{{Lo: 1, Hi: 65534}}
	for _, tc := range []struct {
		name   string
		hosts  int
		floor  tcpSpans
		spares []tcpSpans
	}{
		{"distinct", 512, allTCP, distinct[:512]},
		{"distinct", 1024, allTCP, distinct},
		{"repeated/full", 8192, dense, copies(dense)},
		{"repeated/partial", 8192, dense, copies(dense[:len(dense)-1])},
		{"repeated/interleaved", 8192, dense, copies(interleaved)},
		{"no-holes", 1024, allTCP, []tcpSpans{nil}},
		{"mixed", 8192, allTCP, []tcpSpans{nearTotal, nearTotal, even, dense}},
	} {
		b.Run(fmt.Sprintf("%s/%d", tc.name, tc.hosts), func(b *testing.B) {
			plan := broadTCP{rules: map[netip.Prefix]portDelta{{}: {block: tc.floor}}}
			for i := range tc.hosts {
				a := netip.AddrFrom4([4]byte{198, 18, byte(i >> 8), byte(i)})
				plan.rules[netip.PrefixFrom(a, 32)] = portDelta{spare: tc.spares[i%len(tc.spares)]}
			}
			b.ReportAllocs()
			for b.Loop() {
				plan.alwaysDropped()
			}
		})
	}
}
