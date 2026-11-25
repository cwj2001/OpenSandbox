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

func TestNftAgedFullDNSHistoryRequiresInstalledRetirement(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 40*time.Second)
	defer cancel()
	if !isolatedNftTest(t, ctx) {
		return
	}
	const host = "198.18.0.2"
	startWithdrawalEchoPeer(t, ctx, "443")
	m := NewManagerWithOptions(Options{})
	old := mustPolicy(t, `{"defaultAction":"allow"}`)
	p := mustPolicy(t, `{"egress":[{"action":"allow","target":"a.example"}]}`)
	require.NoError(t, m.ApplyStatic(ctx, old))
	stream := openWithdrawalStream(t, host, "443")
	_, err := m.ApplyStaticComputingEstablishedDrops(ctx, old, p)
	require.NoError(t, err)
	pool := withdrawalDNSPool(maxDNSExceptions)
	for i := range pool {
		pool[i].Addr = netip.AddrFrom4([4]byte{198, 19, byte(i >> 8), byte(i)})
	}
	require.NoError(t, m.AddResolvedIPs(ctx, pool))
	aged := m.lastDropsAt.Add(establishedCarryTTL() + time.Second)
	m.now = func() time.Time { return aged }
	answer := []ResolvedIP{{Addr: netip.MustParseAddr(host), TTL: time.Minute}}
	require.ErrorIs(t, m.AddResolvedDomain(ctx, "a.example", answer), errTCPHistoryCapacity)
	leases := readKernelLeaseExpiry(t, ctx)
	require.Len(t, leases, maxDNSExceptions)
	require.NotContains(t, leases, host)
	requireWithdrawalDrop(t, ctx, stream, 2)
	require.NoError(t, m.ApplyStatic(ctx, p))
	require.NoError(t, m.AddResolvedDomain(ctx, "a.example", answer))
	require.Contains(t, readKernelLeaseExpiry(t, ctx), host)
	openWithdrawalStream(t, host, "443")
}
