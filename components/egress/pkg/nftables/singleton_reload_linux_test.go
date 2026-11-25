// Copyright 2026 The OpenSandbox Authors
// SPDX-License-Identifier: Apache-2.0

package nftables

import (
	"context"
	"testing"
	"time"

	"github.com/alibaba/opensandbox/egress/pkg/policy"
	"github.com/stretchr/testify/require"
)

// All streams predate opt-in. An ordinary reload may release a port but must
// neither reopen one still denied nor cut a sibling that was actually spared.
func TestNftSingletonReloadPortIntersection(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 35*time.Second)
	defer cancel()
	if !isolatedNftTest(t, ctx) {
		return
	}
	const host = "198.18.0.2"
	const wide = `{"action":"allow","target":"198.18.0.0/24"}`
	const deny443 = `{"action":"deny","target":"198.18.0.2","ports":[443]}`
	const denyBoth = `{"action":"deny","target":"198.18.0.2","ports":[443,8443]}`
	startWithdrawalEchoPeer(t, ctx, "443", "8443")
	for _, tc := range []struct{ name, oldAllow, optIn, reload string }{
		{"ports-to-port-under-wide-allow", `{"action":"allow","target":"198.18.0.2/32","ports":[443,8443]}`, `{"egress":[]}`, `{"egress":[` + wide + `,` + deny443 + `]}`},
		{"whole-to-port", `{"action":"allow","target":"198.18.0.2"}`, `{"egress":[]}`, `{"defaultAction":"allow","egress":[` + deny443 + `]}`},
		{"old-keep-is-not-a-withdrawal", `{"action":"allow","target":"198.18.0.2/32"}`, `{"egress":[{"action":"allow","ports":[8443]}]}`, `{"egress":[` + wide + `,` + denyBoth + `]}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := NewManagerWithOptions(Options{})
			old := mustPolicy(t, `{"egress":[`+tc.oldAllow+`]}`)
			require.NoError(t, m.ApplyStatic(ctx, old))
			cut := openWithdrawalStream(t, host, "443")
			stillCut := openWithdrawalStream(t, host, "443")
			reopened := openWithdrawalStream(t, host, "443")
			sibling := openWithdrawalStream(t, host, "8443")
			_, err := m.ApplyStaticComputingEstablishedDrops(ctx, old, mustPolicy(t, tc.optIn))
			require.NoError(t, err)
			require.NoError(t, m.ApplyStatic(ctx, mustPolicy(t, tc.reload)))
			requireWithdrawalDrop(t, ctx, cut, 2)
			require.NoError(t, withdrawalEcho(sibling, 2))
			require.NoError(t, m.ApplyStatic(ctx, policy.DefaultDenyPolicy()))
			requireWithdrawalDrop(t, ctx, stillCut, 3)
			require.NoError(t, withdrawalEcho(sibling, 3))
			require.NoError(t, m.ApplyStatic(ctx, mustPolicy(t, `{"defaultAction":"allow"}`)))
			require.NoError(t, m.ApplyStatic(ctx, policy.DefaultDenyPolicy()))
			require.NoError(t, withdrawalEcho(reopened, 4), "a genuine reallow retires the old cut")
		})
	}
}
