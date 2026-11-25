// Copyright 2026 The OpenSandbox Authors
// SPDX-License-Identifier: Apache-2.0

package nftables

import (
	"net/netip"
	"testing"

	"github.com/alibaba/opensandbox/egress/pkg/policy"
	"github.com/stretchr/testify/require"
)

func TestOptIn_WithdrawnSingletonParity(t *testing.T) {
	for _, host := range []string{"192.0.2.7", "2001:db8::7", "::ffff:192.0.2.7"} {
		addr := netip.MustParseAddr(host)
		for _, target := range []string{host, netip.PrefixFrom(addr, addr.BitLen()).String()} {
			t.Run(target+"/ports", func(t *testing.T) {
				old := mustPolicy(t, `{"defaultAction":"allow","egress":[{"action":"allow","target":"`+target+`","ports":[443,8443]}]}`)
				next := mustPolicy(t, `{"defaultAction":"allow","egress":[{"action":"deny","target":"`+netip.PrefixFrom(addr, addr.BitLen()-1).Masked().String()+`","ports":[443]}]}`)
				d := ComputeEstablishedDrops(old, next, nil)
				require.True(t, d.MatchesFlow(addr, 443))
				require.False(t, d.MatchesFlow(addr, 8443), "the default still admits the sibling")
			})
			t.Run(target+"/whole", func(t *testing.T) {
				m, _ := recordingManager()
				ctx := t.Context()
				old := mustPolicy(t, `{"egress":[{"action":"allow","target":"`+target+`"}]}`)
				next := mustPolicy(t, `{"defaultAction":"allow","egress":[{"action":"deny","target":"`+host+`"}]}`)
				_, err := m.ApplyStaticComputingEstablishedDrops(ctx, old, next)
				require.NoError(t, err)
				require.True(t, m.lastDrops.Matches(addr))
				require.NoError(t, m.ApplyStatic(ctx, policy.DefaultDenyPolicy()))
				require.True(t, m.lastDrops.Matches(addr), "removing a redundant deny did not reallow the host")
				require.True(t, m.lastDrops.MatchesFlow(addr, 443))
			})
		}
	}
}
