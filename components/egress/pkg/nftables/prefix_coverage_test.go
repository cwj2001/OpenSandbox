// Copyright 2026 The OpenSandbox Authors
// SPDX-License-Identifier: Apache-2.0

package nftables

import (
	"fmt"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestWithdrawnPrefixNeedsCompleteCoverage(t *testing.T) {
	for _, cidr := range []string{"198.18.0.0/29", "2001:db8::/125", "::ffff:198.18.0.0/125"} {
		t.Run(cidr, func(t *testing.T) {
			p := netip.MustParsePrefix(cidr)
			first := p.Addr()
			at := func(i int) netip.Addr {
				a := first
				for range i {
					a = a.Next()
				}
				return a
			}
			old := mustPolicy(t, fmt.Sprintf(`{"egress":[{"action":"allow","target":"%s"}]}`, p))
			for _, tc := range []struct {
				name        string
				bits, right int
				cuts        [8]bool
			}{
				{"split-cover", p.Bits() + 1, 4, [8]bool{}},
				{"hole", p.Bits() + 2, 6, [8]bool{false, false, true, true, true, true, false, false}},
			} {
				t.Run(tc.name, func(t *testing.T) {
					newPol := mustPolicy(t, fmt.Sprintf(`{"egress":[{"action":"allow","target":"%s"},{"action":"allow","target":"%s"}]}`, netip.PrefixFrom(first, tc.bits), netip.PrefixFrom(at(tc.right), tc.bits)))
					m, _ := recordingManager()
					_, err := m.ApplyStaticComputingEstablishedDrops(t.Context(), old, newPol)
					require.NoError(t, err)
					for stage := range 2 {
						for i, cut := range tc.cuts {
							require.Equal(t, cut, m.lastDrops.MatchesFlow(at(i), 443), "stage %d, host %d", stage, i)
							require.Equal(t, cut, m.lastDrops.Matches(at(i)), "portless stage %d, host %d", stage, i)
						}
						require.NoError(t, m.ApplyStatic(t.Context(), newPol))
					}
					if first.Is4In6() {
						require.False(t, m.lastDrops.MatchesFlow(at(3).Unmap(), 443), "mapped rules cannot withdraw native IPv4")
					}
				})
			}
		})
	}
}
