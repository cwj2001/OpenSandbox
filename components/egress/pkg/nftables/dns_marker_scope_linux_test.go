// Copyright 2026 The OpenSandbox Authors
// SPDX-License-Identifier: Apache-2.0

package nftables

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestNftDNSHistoryPreservesOnlyAdmittedPorts(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 35*time.Second)
	defer cancel()
	if !isolatedNftTest(t, ctx) {
		return
	}
	const a, b = "198.18.0.2", "198.18.0.3"
	startWithdrawalEchoPeer(t, ctx, "443", "8443")
	m := NewManagerWithOptions(Options{})
	old := mustPolicy(t, `{"defaultAction":"allow"}`)
	require.NoError(t, m.ApplyStatic(ctx, old))
	allowed := openWithdrawalStream(t, a, "443")
	cutAtGrant := openWithdrawalStream(t, a, "8443")
	cutAtExpiry := openWithdrawalStream(t, a, "8443")
	cutAfterReload := openWithdrawalStream(t, a, "8443")
	portless := openWithdrawalStream(t, b, "443")
	strict := mustPolicy(t, `{"egress":[{"action":"allow","target":"a.example"},{"action":"deny","target":"198.18.0.0/29","ports":[8443]},{"action":"deny","target":"198.18.0.3"}]}`)
	_, err := m.ApplyStaticComputingEstablishedDrops(ctx, old, strict)
	require.NoError(t, err)
	require.NoError(t, m.ApplyStatic(ctx, strict))
	// Drive two actual timed transactions with short deadlines. A's 443 is a
	// late cut, 8443 is early; all of B is early, so DNS cannot spare it.
	grant := func(expiry time.Time) {
		m.mu.Lock()
		defer m.mu.Unlock()
		now := time.Now()
		require.NoError(t, m.addResolvedDeadlinesLocked(ctx, map[netip.Addr]time.Time{netip.MustParseAddr(a): expiry, netip.MustParseAddr(b): expiry}, now))
	}
	grant(time.Now().Add(2 * time.Second))
	expiry := time.Now().Add(5 * time.Second)
	grant(expiry)
	require.NoError(t, withdrawalEcho(allowed, 2))
	requireWithdrawalDrop(t, ctx, cutAtGrant, 2)
	requireWithdrawalDrop(t, ctx, portless, 2)
	select {
	case <-time.After(time.Until(expiry.Add(1100 * time.Millisecond))):
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	require.NoError(t, withdrawalEcho(allowed, 3))
	requireWithdrawalDrop(t, ctx, cutAtExpiry, 3)
	// Remove the explicit deny but keep default deny, without another grant.
	// Both A ports are now late cuts. Only the old admission of 443 survives.
	require.NoError(t, m.ApplyStatic(ctx, mustPolicy(t, `{"egress":[{"action":"allow","target":"a.example"}]}`)))
	require.Empty(t, readKernelLeaseExpiry(t, ctx))
	markers, err := m.run(ctx, "list set inet "+tableName+" "+dnsTCPv4+"\n")
	require.NoError(t, err)
	require.NotContains(t, string(markers), a)
	require.NoError(t, withdrawalEcho(allowed, 4))
	requireWithdrawalDrop(t, ctx, cutAfterReload, 4)
}
