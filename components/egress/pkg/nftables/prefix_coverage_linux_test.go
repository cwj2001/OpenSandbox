// Copyright 2026 The OpenSandbox Authors
// SPDX-License-Identifier: Apache-2.0

package nftables

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestNftNarrowedCIDRKeepsOnlyCoveredStreams(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	if !isolatedNftTest(t, ctx) {
		return
	}
	startWithdrawalEchoPeer(t, ctx, "443", "8443")
	const scoped = `,"ports":[443,8443]`
	for _, tc := range []struct{ name, scope, replacement string }{
		{"portless", "", `{"egress":[{"action":"allow","target":"198.18.0.0/31"},{"action":"allow","target":"198.18.0.3"},{"action":"allow","target":"198.18.0.0/30","ports":[8443]}]}`},
		{"scoped", scoped, `{"egress":[{"action":"allow","target":"198.18.0.0/31","ports":[443,8443]},{"action":"allow","target":"198.18.0.3","ports":[443,8443]},{"action":"allow","target":"198.18.0.0/30","ports":[8443]}]}`},
		{"covered-with-deny", scoped, `{"egress":[{"action":"allow","target":"198.18.0.0/31","ports":[443,8443]},{"action":"allow","target":"198.18.0.2/31","ports":[443,8443]},{"action":"deny","target":"198.18.0.2","ports":[443]}]}`},
		{"default-allow", scoped, `{"defaultAction":"allow","egress":[{"action":"deny","target":"198.18.0.2","ports":[443]}]}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := NewManagerWithOptions(Options{})
			old := mustPolicy(t, `{"egress":[{"action":"allow","target":"198.18.0.0/30"`+tc.scope+`}]}`)
			next := mustPolicy(t, tc.replacement)
			require.NoError(t, m.ApplyStatic(ctx, old))
			atWithdrawal := openWithdrawalStream(t, "198.18.0.2", "443")
			atReload := openWithdrawalStream(t, "198.18.0.2", "443")
			sibling := openWithdrawalStream(t, "198.18.0.2", "8443")
			kept := openWithdrawalStream(t, "198.18.0.3", "443")
			_, err := m.ApplyStaticComputingEstablishedDrops(ctx, old, next)
			require.NoError(t, err)
			if tc.name == "covered-with-deny" {
				require.Empty(t, m.lastDrops.PortDrops, "both halves are covered; only the explicit deny should withdraw a flow")
			}
			requireWithdrawalDrop(t, ctx, atWithdrawal, 2)
			require.NoError(t, withdrawalEcho(sibling, 2))
			require.NoError(t, withdrawalEcho(kept, 2))
			require.NoError(t, m.ApplyStatic(ctx, next))
			requireWithdrawalDrop(t, ctx, atReload, 3)
			require.NoError(t, withdrawalEcho(sibling, 3))
			require.NoError(t, withdrawalEcho(kept, 3))
		})
	}
}
