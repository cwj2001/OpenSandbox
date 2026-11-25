// Copyright 2026 The OpenSandbox Authors
// SPDX-License-Identifier: Apache-2.0

package nftables

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestNftDNSAdmissionAcrossExpiryAndExplicitDeny(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	if !isolatedNftTest(t, ctx) {
		return
	}
	const host = "198.18.0.2"
	startWithdrawalEchoPeer(t, ctx, "443", "8443")
	m := NewManagerWithOptions(Options{})
	old := mustPolicy(t, `{"defaultAction":"allow"}`)
	live := mustPolicy(t, `{"egress":[{"action":"allow","target":"*.example"}]}`)
	require.NoError(t, m.ApplyStatic(ctx, old))
	_, err := m.ApplyStaticComputingEstablishedDrops(ctx, old, live)
	require.NoError(t, err)
	require.NoError(t, m.ApplyStatic(ctx, live))
	ips := []ResolvedIP{{Addr: netip.MustParseAddr(host), TTL: 0}}
	grant := func(name string) { t.Helper(); require.NoError(t, m.AddResolvedDomain(ctx, name, ips)) }
	noDial := func(port string) {
		t.Helper()
		c, err := net.DialTimeout("tcp4", net.JoinHostPort(host, port), 350*time.Millisecond)
		if c != nil {
			_ = c.Close()
		}
		var ne net.Error
		require.True(t, errors.Is(err, syscall.EPERM) || (errors.As(err, &ne) && ne.Timeout()), "expected a filtered new dial to %s, got %v", port, err)
	}
	// Exercise the same grant transaction with a short absolute deadline,
	// rather than spending the public DNS TTL minimum on each kernel CI run.
	const ttl = 5 * time.Second
	now := time.Now()
	m.mu.Lock()
	err = m.addResolvedDeadlinesLocked(ctx, map[netip.Addr]time.Time{ips[0].Addr: now.Add(ttl)}, now)
	m.mu.Unlock()
	require.NoError(t, err)
	afterExpiry := time.NewTimer(ttl + 250*time.Millisecond)
	defer afterExpiry.Stop()
	require.Contains(t, readKernelLeaseExpiry(t, ctx), host)
	old443 := openWithdrawalStream(t, host, "443")
	afterRenewal := openWithdrawalStream(t, host, "443")
	sibling := openWithdrawalStream(t, host, "8443")
	// There is no refresh worker. Check actual admission after the installed
	// timeout, not when the kernel garbage collector removes the expired row.
	select {
	case <-afterExpiry.C:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	noDial("8443")
	require.NoError(t, withdrawalEcho(sibling, 2), "expiry is not a fresh established-flow withdrawal")
	require.NoError(t, m.ApplyStatic(ctx, live))
	require.NotContains(t, readKernelLeaseExpiry(t, ctx), host)
	require.NoError(t, withdrawalEcho(sibling, 3))
	noDial("8443")

	grant("a.example")
	grant("b.example")
	const deny443 = `{"action":"deny","target":"198.18.0.2","ports":[443]}`
	tight := mustPolicy(t, `{"egress":[{"action":"allow","target":"*.example"},`+deny443+`]}`)
	require.NoError(t, m.ApplyStatic(ctx, tight))
	noDial("443")
	require.NoError(t, withdrawalEcho(old443, 4), "plain replacement must not initiate teardown")
	keepB := mustPolicy(t, `{"egress":[{"action":"allow","target":"b.example"},`+deny443+`]}`)
	_, err = m.ApplyStaticComputingEstablishedDrops(ctx, tight, keepB)
	require.NoError(t, err)
	requireWithdrawalDrop(t, ctx, old443, 5)
	require.NoError(t, withdrawalEcho(sibling, 5))
	require.Error(t, m.AddResolvedDomain(ctx, "a.example", ips))
	grant("b.example")
	noDial("443")
	requireWithdrawalDrop(t, ctx, afterRenewal, 6)
	require.NoError(t, withdrawalEcho(sibling, 6))
	openWithdrawalStream(t, host, "8443")
	require.NoError(t, m.ApplyStatic(ctx, live))
	openWithdrawalStream(t, host, "443")
}

func TestNftUncertainDNSHistoryRequiresKernelEvidence(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	if !isolatedNftTest(t, ctx) {
		return
	}
	for _, tc := range []struct {
		name   string
		landed bool
	}{{"lost-ACK", true}, {"not-installed", false}} {
		t.Run(tc.name, func(t *testing.T) {
			m := NewManagerWithOptions(Options{})
			old := mustPolicy(t, `{"defaultAction":"allow"}`)
			p := mustPolicy(t, `{"egress":[{"action":"allow","target":"a.example"},{"action":"deny","ports":[443]}]}`)
			require.NoError(t, m.ApplyStatic(ctx, old))
			_, err := m.ApplyStaticComputingEstablishedDrops(ctx, old, p)
			require.NoError(t, err)
			require.NoError(t, m.ApplyStatic(ctx, p))
			run := m.run
			m.run = func(ctx context.Context, script string) ([]byte, error) {
				if tc.landed {
					out, err := run(ctx, script)
					require.NoError(t, err, "%s", out)
				}
				return nil, context.DeadlineExceeded // unknown kernel outcome
			}
			ips := []ResolvedIP{{Addr: netip.MustParseAddr("192.0.2.10")}, {Addr: netip.MustParseAddr("2001:db8::10")}}
			require.Error(t, m.AddResolvedDomain(ctx, "a.example", ips))
			require.Empty(t, m.tracker.dynamicIPs)
			require.Empty(t, m.domains)
			require.True(t, m.lastDrops.MatchesFlow(ips[0].Addr, 8443))
			m.run = func(_ context.Context, script string) ([]byte, error) {
				require.True(t, strings.HasPrefix(script, "get element ") || strings.HasPrefix(script, "create element "), "must not submit a new grant or rebuild on unknown state")
				return nil, context.DeadlineExceeded
			}
			require.Error(t, m.ApplyStatic(ctx, p))
			require.Error(t, m.AddResolvedDomain(ctx, "a.example", ips))
			m.run = run
			require.NoError(t, m.ApplyStatic(ctx, p))
			for _, ip := range ips {
				require.True(t, m.lastDrops.MatchesFlow(ip.Addr, 443))
				require.Equal(t, !tc.landed, m.lastDrops.MatchesFlow(ip.Addr, 8443))
			}
			require.Empty(t, readKernelLeaseExpiry(t, ctx), "history cannot publish an unacknowledged DNS lease")
			require.Empty(t, m.domains)
		})
	}
}
