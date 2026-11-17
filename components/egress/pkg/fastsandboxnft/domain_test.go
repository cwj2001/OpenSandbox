// Copyright 2026 The OpenSandbox Authors
// SPDX-License-Identifier: Apache-2.0

package fastsandboxnft

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"testing"
	"time"

	"github.com/alibaba/opensandbox/egress/pkg/nftables"
	"github.com/alibaba/opensandbox/egress/pkg/policy"
	"github.com/alibaba/opensandbox/egress/pkg/subject"
	"github.com/stretchr/testify/require"
)

func domainPolicy(t *testing.T, text string) *policy.NetworkPolicy {
	t.Helper()
	pol, err := policy.ParsePolicy(text)
	require.NoError(t, err)
	return pol
}

func TestDomainResolutionGenerationInvalidatesIdenticalRebindAndReset(t *testing.T) {
	ctx := context.Background()
	a := NewApplier((&fakeRunner{}).Run)
	s := subject.FromSandboxUID("domain-generation")
	att := testSlot("domain-generation", "10.0.0.5")
	pol := domainPolicy(t, `{"defaultAction":"deny","egress":[{"action":"allow","target":"api.example","ports":[443]}]}`)
	addr := netip.MustParseAddr("192.0.2.1")
	var previous uint64
	for i := range 3 {
		require.NoError(t, a.ApplyDenyFirst(ctx, s, att))
		snapshot, generation, ok := a.ResolutionPolicy(s, att.IP)
		require.False(t, ok, "deny-first must not expose a DNS admission policy")
		require.Nil(t, snapshot)
		require.ErrorIs(t, a.AddResolvedDomain(ctx, s, previous, "api.example", []nftables.ResolvedIP{{Addr: addr}}), ErrLeaseRejected)
		require.NotContains(t, a.states, s, "deny-first must ignore DNS callbacks")
		require.NoError(t, a.ApplyPolicy(ctx, s, pol))
		snapshot, generation, ok = a.ResolutionPolicy(s, netip.MustParseAddr("::ffff:10.0.0.5"))
		require.True(t, ok)
		require.Same(t, pol, snapshot)
		require.Greater(t, generation, previous)
		snapshot, wrongGeneration, matched := a.ResolutionPolicy(s, netip.MustParseAddr("10.0.0.99"))
		require.False(t, matched, "an old source binding must not receive the installed policy")
		require.Nil(t, snapshot)
		require.Zero(t, wrongGeneration)
		require.ErrorIs(t, a.AddResolvedDomain(ctx, s, previous, "api.example", []nftables.ResolvedIP{{Addr: addr}}), ErrLeaseRejected)
		require.Empty(t, a.states[s].allowTCP, "a late callback must not authorize the replacement")
		require.NoError(t, a.AddResolvedDomain(ctx, s, generation, "api.example", []nftables.ResolvedIP{{Addr: addr}}))
		require.Contains(t, a.states[s].allowTCP, nftables.TCPEndpoint{Addr: addr, Port: 443})
		previous = generation
		if i == 1 {
			require.NoError(t, a.ApplyReset(ctx))
		}
	}
	require.NoError(t, a.Remove(ctx, s))
	snapshot, removedGeneration, ok := a.ResolutionPolicy(s, att.IP)
	require.False(t, ok)
	require.Nil(t, snapshot)
	require.Zero(t, removedGeneration)
	require.NoError(t, a.ApplyDenyFirst(ctx, s, att))
	require.NoError(t, a.ApplyPolicy(ctx, s, pol))
	_, generation, _ := a.ResolutionPolicy(s, att.IP)
	require.Greater(t, generation, previous)
}

func TestDomainPolicyNarrowingPreservesAbsoluteDeadlinesAndFailureState(t *testing.T) {
	ctx := context.Background()
	runner := &fakeRunner{}
	a := NewApplier(runner.Run)
	now := time.Unix(1700000000, 0)
	a.now = func() time.Time { return now }
	s := subject.FromSandboxUID("domain-narrow")
	require.NoError(t, a.ApplyDenyFirst(ctx, s, testSlot("domain-narrow", "10.0.0.5")))
	broad := domainPolicy(t, `{"defaultAction":"deny","egress":[{"action":"allow","target":"api.example"}]}`)
	narrow := domainPolicy(t, `{"defaultAction":"deny","egress":[{"action":"allow","target":"api.example","ports":[443,8443]},{"action":"deny","target":"api.example","ports":[8443]}]}`)
	require.NoError(t, a.ApplyPolicy(ctx, s, broad))
	_, generation, _ := a.ResolutionPolicy(s, netip.MustParseAddr("10.0.0.5"))
	addr := netip.MustParseAddr("192.0.2.1")
	require.NoError(t, a.AddResolvedDomain(ctx, s, generation, "API.EXAMPLE.", []nftables.ResolvedIP{{Addr: addr, TTL: time.Minute}}))
	deadline := now.Add(2 * time.Minute)
	now = now.Add(20 * time.Second)
	runner.fail = func(string) error { return errors.New("rejected") }
	require.Error(t, a.ApplyPolicy(ctx, s, narrow))
	require.Same(t, broad, a.subjects[s].pol)
	require.Equal(t, deadline, a.states[s].dyn[addr])
	runner.fail = nil
	require.NoError(t, a.ApplyPolicy(ctx, s, narrow))
	require.NotContains(t, a.states[s].dyn, addr)
	require.Equal(t, deadline, a.states[s].allowTCP[nftables.TCPEndpoint{Addr: addr, Port: 443}])
	require.Equal(t, deadline, a.states[s].denyTCP[nftables.TCPEndpoint{Addr: addr, Port: 8443}])
	snapshot, current, ok := a.ResolutionPolicy(s, netip.MustParseAddr("10.0.0.5"))
	require.True(t, ok)
	require.Same(t, narrow, snapshot)
	require.Equal(t, generation, current, "policy replacement is not a new incarnation")
}

func TestDomainRefreshUsesOriginalPortAndCommitsOnlySuccessfulWrites(t *testing.T) {
	ctx := context.Background()
	runner := &fakeRunner{}
	a := NewApplier(runner.Run)
	now := time.Unix(1700000000, 0)
	a.now = func() time.Time { return now }
	s := subject.FromSandboxUID("domain-refresh")
	require.NoError(t, a.ApplyDenyFirst(ctx, s, testSlot("domain-refresh", "10.0.0.5")))
	require.NoError(t, a.ApplyPolicy(ctx, s, domainPolicy(t, `{"defaultAction":"deny","egress":[{"action":"allow","target":"api.example","ports":[443,8443]}]}`)))
	_, generation, _ := a.ResolutionPolicy(s, netip.MustParseAddr("10.0.0.5"))
	addr := netip.MustParseAddr("192.0.2.1")
	require.NoError(t, a.AddResolvedDomain(ctx, s, generation, "api.example", []nftables.ResolvedIP{{Addr: addr}}))
	originalDeadline := now.Add(time.Minute)
	a.conntrack = func(context.Context) ([]conntrackEntry, error) {
		return parseConntrackTCPEntries([]byte("ipv4 2 tcp 6 431999 ESTABLISHED src=10.0.0.5 dst=192.0.2.1 sport=51234 dport=443 src=192.0.2.1 dst=10.0.0.5 sport=443 dport=8443")), nil
	}
	now = now.Add(30 * time.Second)
	runner.fail = func(string) error { return errors.New("rejected") }
	a.refreshTick(ctx)
	require.Equal(t, originalDeadline, a.states[s].allowTCP[nftables.TCPEndpoint{Addr: addr, Port: 443}])
	require.Empty(t, a.states[s].prevTCP)
	runner.fail = nil
	a.refreshTick(ctx)
	require.Equal(t, now.Add(360*time.Second), a.states[s].allowTCP[nftables.TCPEndpoint{Addr: addr, Port: 443}])
	require.Equal(t, originalDeadline, a.states[s].allowTCP[nftables.TCPEndpoint{Addr: addr, Port: 8443}])
	now = now.Add(time.Minute)
	a.refreshTick(ctx)
	require.NotContains(t, a.states[s].allowTCP, nftables.TCPEndpoint{Addr: addr, Port: 8443})
	a.conntrack = func(context.Context) ([]conntrackEntry, error) { return nil, nil }
	now = now.Add(time.Second)
	a.refreshTick(ctx)
	finalDeadline := now.Add(360 * time.Second)
	require.Equal(t, finalDeadline, a.states[s].allowTCP[nftables.TCPEndpoint{Addr: addr, Port: 443}])
	now = now.Add(time.Second)
	a.refreshTick(ctx)
	require.Equal(t, finalDeadline, a.states[s].allowTCP[nftables.TCPEndpoint{Addr: addr, Port: 443}], "idle ticks must not reset grace")
}

func TestDomainAlwaysReloadReclassifiesObservedLeasesAtomically(t *testing.T) {
	ctx := context.Background()
	runner := &fakeRunner{}
	a := NewApplier(runner.Run)
	now := time.Unix(1700000000, 0)
	a.now = func() time.Time { return now }
	s := subject.FromSandboxUID("domain-reload")
	att := testSlot("domain-reload", "10.0.0.5")
	require.NoError(t, a.ApplyDenyFirst(ctx, s, att))
	broad := domainPolicy(t, `{"egress":[{"action":"allow","target":"a.example"},{"action":"allow","target":"b.example"}]}`)
	narrow := domainPolicy(t, `{"egress":[{"action":"allow","target":"a.example","ports":[443]},{"action":"allow","target":"b.example","ports":[443]},{"action":"deny","target":"a.example","ports":[8443]}]}`)
	require.NoError(t, a.ApplyPolicy(ctx, s, broad))
	_, generation, ok := a.ResolutionPolicy(s, att.IP)
	require.True(t, ok)
	addr := netip.MustParseAddr("192.0.2.1")
	require.NoError(t, a.AddResolvedDomain(ctx, s, generation, "a.example", []nftables.ResolvedIP{{Addr: addr}}))
	require.NoError(t, a.AddResolvedDomain(ctx, s, generation, "b.example", []nftables.ResolvedIP{{Addr: addr, TTL: time.Minute}}))
	deadline := now.Add(2 * time.Minute)
	now = now.Add(20 * time.Second)
	floor := []policy.PortRange{{Lo: 25, Hi: 25}}
	runner.fail = func(string) error { return errors.New("rejected") }
	require.Error(t, a.ApplyAlwaysRulesReload(ctx, floor, map[subject.Subject]*policy.NetworkPolicy{s: narrow}))
	require.Same(t, broad, a.subjects[s].pol)
	require.Equal(t, deadline, a.states[s].dyn[addr])
	require.Empty(t, a.opts.PortFloorDenyRanges)
	runner.fail = nil
	require.NoError(t, a.ApplyAlwaysRulesReload(ctx, floor, map[subject.Subject]*policy.NetworkPolicy{s: narrow}))
	require.NotContains(t, a.states[s].dyn, addr)
	require.Equal(t, deadline, a.states[s].allowTCP[nftables.TCPEndpoint{Addr: addr, Port: 443}])
	require.Equal(t, now.Add(40*time.Second), a.states[s].denyTCP[nftables.TCPEndpoint{Addr: addr, Port: 8443}])
	require.Equal(t, floor, a.opts.PortFloorDenyRanges)
	require.Contains(t, runner.last(), "192.0.2.1 . 443 timeout 100s")
	require.Contains(t, runner.last(), "192.0.2.1 . 8443 timeout 40s")
}

func TestDomainDeltaRetainsSharedSourcesWithoutRewritingUnchangedLeases(t *testing.T) {
	ctx := context.Background()
	runner := &fakeRunner{}
	a := NewApplier(runner.Run)
	now := time.Unix(1700000000, 0)
	a.now = func() time.Time { return now }
	s := subject.FromSandboxUID("domain-delta")
	att := testSlot("domain-delta", "10.0.0.5")
	require.NoError(t, a.ApplyDenyFirst(ctx, s, att))
	pol := domainPolicy(t, `{"defaultAction":"deny","egress":[{"action":"allow","target":"a.example","ports":[443]},{"action":"allow","target":"b.example","ports":[443]},{"action":"allow","target":"unrelated.example","ports":[8443]}]}`)
	require.NoError(t, a.ApplyPolicy(ctx, s, pol))
	_, generation, _ := a.ResolutionPolicy(s, att.IP)
	addr := netip.MustParseAddr("192.0.2.1")
	other := netip.MustParseAddr("2001:db8::2")
	require.NoError(t, a.AddResolvedDomain(ctx, s, generation, "a.example", []nftables.ResolvedIP{{Addr: addr, TTL: time.Minute}}))
	require.NoError(t, a.AddResolvedDomain(ctx, s, generation, "unrelated.example", []nftables.ResolvedIP{{Addr: other}}))
	deadline := a.states[s].allowTCP[nftables.TCPEndpoint{Addr: addr, Port: 443}]
	count := runner.count()
	// A shorter independent contribution must be accepted even when it
	// produces no kernel changes.
	require.NoError(t, a.AddResolvedDomain(ctx, s, generation, "b.example", []nftables.ResolvedIP{{Addr: addr}}))
	require.Equal(t, count, runner.count())
	require.Equal(t, deadline, a.states[s].allowTCP[nftables.TCPEndpoint{Addr: addr, Port: 443}])
	require.Contains(t, a.states[s].domains["b.example"], addr)
	now = now.Add(10 * time.Second)
	require.NoError(t, a.AddResolvedDomain(ctx, s, generation, "a.example", []nftables.ResolvedIP{{Addr: addr, TTL: 2 * time.Minute}}))
	require.Equal(t, count+1, runner.count())
	require.Contains(t, runner.last(), "192.0.2.1 . 443 timeout 180s")
	require.NotContains(t, runner.last(), other.String())
	require.NotContains(t, runner.last(), "flush set")
	// Revoking the longer source uses the shorter source's original clock.
	require.NoError(t, a.ApplyPolicy(ctx, s, domainPolicy(t, `{"defaultAction":"deny","egress":[{"action":"allow","target":"b.example","ports":[443]}]}`)))
	require.Equal(t, time.Unix(1700000000, 0).Add(time.Minute), a.states[s].allowTCP[nftables.TCPEndpoint{Addr: addr, Port: 443}])
}

func TestDomainDeltaFailureReconcilesEvenWhenRetryWouldBeNoop(t *testing.T) {
	ctx := context.Background()
	runner := &fakeRunner{}
	a := NewApplier(runner.Run)
	now := time.Unix(1700000000, 0)
	a.now = func() time.Time { return now }
	s := subject.FromSandboxUID("domain-uncertain")
	att := testSlot("domain-uncertain", "10.0.0.5")
	require.NoError(t, a.ApplyDenyFirst(ctx, s, att))
	require.NoError(t, a.ApplyPolicy(ctx, s, domainPolicy(t, `{"defaultAction":"deny","egress":[{"action":"allow","target":"api.example","ports":[443]}]}`)))
	_, generation, _ := a.ResolutionPolicy(s, att.IP)
	addr := netip.MustParseAddr("192.0.2.1")
	ghost := netip.MustParseAddr("2001:db8::2")
	require.NoError(t, a.AddResolvedDomain(ctx, s, generation, "api.example", []nftables.ResolvedIP{{Addr: addr, TTL: time.Minute}}))
	previous := a.states[s]
	runner.fail = func(string) error { return errors.New("reply lost after commit") }
	require.Error(t, a.AddResolvedDomain(ctx, s, generation, "api.example", []nftables.ResolvedIP{{Addr: ghost}}))
	require.Same(t, previous, a.states[s])
	require.NotContains(t, a.states[s].domains["api.example"], ghost)
	require.True(t, a.dirtyLeases[s])
	runner.fail = nil
	now = now.Add(5 * time.Second)
	// This shorter answer would otherwise be a no-op.
	require.NoError(t, a.AddResolvedDomain(ctx, s, generation, "api.example", []nftables.ResolvedIP{{Addr: addr, TTL: -time.Minute}}))
	require.Contains(t, runner.last(), "flush set")
	require.Contains(t, runner.last(), "192.0.2.1 . 443 timeout 115s")
	require.NotContains(t, runner.last(), ghost.String())
	require.False(t, a.dirtyLeases[s])
	count := runner.count()
	require.NoError(t, a.AddResolvedDomain(ctx, s, generation, "api.example", []nftables.ResolvedIP{{Addr: addr, TTL: -time.Minute}}))
	require.Equal(t, count, runner.count())
}

func TestDomainDeltaRefreshBatchesSubjectsAndRemovesExpiredEndpointsOnce(t *testing.T) {
	ctx := context.Background()
	runner := &fakeRunner{}
	a := NewApplier(runner.Run)
	now := time.Unix(1700000000, 0)
	a.now = func() time.Time { return now }
	addr := netip.MustParseAddr("192.0.2.1")
	var entries []conntrackEntry
	var subjects []subject.Subject
	for _, source := range []string{"10.0.0.5", "10.0.0.6"} {
		s := subject.FromSandboxUID(source)
		subjects = append(subjects, s)
		att := testSlot(source, source)
		require.NoError(t, a.ApplyDenyFirst(ctx, s, att))
		require.NoError(t, a.ApplyPolicy(ctx, s, domainPolicy(t, `{"defaultAction":"deny","egress":[{"action":"allow","target":"api.example","ports":[443,8443]}]}`)))
		_, generation, _ := a.ResolutionPolicy(s, att.IP)
		require.NoError(t, a.AddResolvedDomain(ctx, s, generation, "api.example", []nftables.ResolvedIP{{Addr: addr}}))
		entries = append(entries, conntrackEntry{src: att.IP, dst: addr, port: 443, state: "ESTABLISHED"})
	}
	a.conntrack = func(context.Context) ([]conntrackEntry, error) { return entries, nil }
	now = now.Add(10 * time.Second)
	count := runner.count()
	a.refreshTick(ctx)
	require.Equal(t, count+1, runner.count(), "one transaction across both subjects")
	require.NotContains(t, runner.last(), "flush set")
	require.NotContains(t, runner.last(), " . 8443")
	for _, s := range subjects {
		require.Contains(t, runner.last(), tcpSetName(s, "v4", true))
		require.Equal(t, now.Add(360*time.Second), a.states[s].allowTCP[nftables.TCPEndpoint{Addr: addr, Port: 443}])
	}
	now = now.Add(time.Second)
	runner.fail = func(string) error { return errors.New("unknown batch outcome") }
	a.refreshTick(ctx)
	for _, s := range subjects {
		require.True(t, a.dirtyLeases[s])
		require.Equal(t, now.Add(359*time.Second), a.states[s].allowTCP[nftables.TCPEndpoint{Addr: addr, Port: 443}], "failed batch must not publish leases")
	}
	runner.fail = nil
	count = runner.count()
	a.refreshTick(ctx)
	require.Equal(t, count+1, runner.count(), "dirty subjects also recover in one transaction")
	for _, s := range subjects {
		require.Contains(t, runner.last(), "flush set inet "+TableName+" "+tcpSetName(s, "v4", true))
		require.False(t, a.dirtyLeases[s])
	}
	now = now.Add(time.Minute)
	a.refreshTick(ctx)
	require.Contains(t, runner.last(), "delete element")
	require.Contains(t, runner.last(), " . 8443")
	for _, s := range subjects {
		require.NotContains(t, a.states[s].allowTCP, nftables.TCPEndpoint{Addr: addr, Port: 8443})
	}
	count = runner.count()
	a.refreshTick(ctx)
	require.Equal(t, count, runner.count(), "same clock/activity is a true no-op; removed keys stay removed")
}

func TestDomainDeltaFencesUnknownStaticOutcomeUntilLifecycleRecovery(t *testing.T) {
	for _, operation := range []string{"policy", "reload", "remove", "reset", "rebind"} {
		t.Run(operation, func(t *testing.T) {
			ctx := context.Background()
			runner := &fakeRunner{}
			a := NewApplier(runner.Run)
			now := time.Unix(1700000000, 0)
			a.now = func() time.Time { return now }
			s := subject.FromSandboxUID("static-fence")
			other := subject.FromSandboxUID("static-other")
			att := testSlot("static-fence", "10.0.0.5")
			pol := domainPolicy(t, `{"defaultAction":"deny","egress":[{"action":"allow","target":"api.example","ports":[443]}]}`)
			require.NoError(t, a.ApplyDenyFirst(ctx, s, att))
			require.NoError(t, a.ApplyPolicy(ctx, s, pol))
			require.NoError(t, a.ApplyDenyFirst(ctx, other, testSlot("static-other", "10.0.0.6")))
			_, generation, _ := a.ResolutionPolicy(s, att.IP)
			addr := netip.MustParseAddr("192.0.2.1")
			answer := []nftables.ResolvedIP{{Addr: addr}}
			require.NoError(t, a.AddResolvedDomain(ctx, s, generation, "api.example", answer))
			previous := a.states[s]
			a.conntrack = func(context.Context) ([]conntrackEntry, error) {
				return []conntrackEntry{{src: att.IP, dst: addr, port: 443, state: "ESTABLISHED"}}, nil
			}
			attempt := func() error {
				switch operation {
				case "policy":
					return a.ApplyPolicy(ctx, s, pol)
				case "reload":
					return a.ApplyAlwaysRulesReload(ctx, nil, map[subject.Subject]*policy.NetworkPolicy{s: pol})
				case "remove":
					return a.Remove(ctx, other)
				case "reset":
					return a.ApplyReset(ctx)
				default:
					return a.ApplyDenyFirst(ctx, s, att)
				}
			}
			runner.fail = func(string) error {
				return &nftables.ApplyError{Effect: nftables.ApplyUnchanged, Err: errors.New("not executed")}
			}
			require.Error(t, attempt())
			require.False(t, a.staticUncertain[s], "trusted no-execution failure preserves knowledge")
			require.NoError(t, a.AddResolvedDomain(ctx, s, generation, "api.example", answer), "unchanged answer needs no nft execution")
			runner.fail = func(string) error { return errors.New("response lost after execution") }
			require.Error(t, attempt())
			require.True(t, a.staticUncertain[s])
			_, _, admitted := a.ResolutionPolicy(s, att.IP)
			require.False(t, admitted)
			runner.fail = nil
			count := runner.count()
			require.ErrorIs(t, a.AddResolvedDomain(ctx, s, generation, "api.example", answer), ErrLeaseRejected)
			now = now.Add(time.Second)
			a.refreshTick(ctx)
			require.Equal(t, count, runner.count(), "DNS/refresh cannot repair or overwrite uncertain static rules")
			require.Equal(t, previous.allowTCP, a.states[s].allowTCP)
			require.Empty(t, a.states[s].prevTCP)
			require.NoError(t, a.ApplyPolicy(ctx, s, pol))
			require.False(t, a.staticUncertain[s])
			_, _, admitted = a.ResolutionPolicy(s, att.IP)
			require.True(t, admitted)
			require.NoError(t, a.AddResolvedDomain(ctx, s, generation, "api.example", answer))
			a.refreshTick(ctx)
			require.Equal(t, now.Add(360*time.Second), a.states[s].allowTCP[nftables.TCPEndpoint{Addr: addr, Port: 443}])
		})
	}
}

func TestDomainAnswerCapsStageBeforeEffectsAndRetainActivity(t *testing.T) {
	ctx := context.Background()
	runner := &fakeRunner{}
	a := NewApplier(runner.Run)
	now := time.Unix(1700000000, 0)
	a.now = func() time.Time { return now }
	a.conntrack = func(context.Context) ([]conntrackEntry, error) { return nil, nil }
	s := subject.FromSandboxUID("bounded")
	att := testSlot("bounded", "10.0.0.5")
	require.NoError(t, a.ApplyDenyFirst(ctx, s, att))
	require.NoError(t, a.ApplyPolicy(ctx, s, domainPolicy(t, `{"egress":[{"action":"allow","target":"*.example","ports":[443]}]}`)))
	_, generation, _ := a.ResolutionPolicy(s, att.IP)
	addr := netip.MustParseAddr("192.0.2.1")
	answer := []nftables.ResolvedIP{{Addr: addr}}
	for i := range maxResolvedDomains {
		require.NoError(t, a.AddResolvedDomain(ctx, s, generation, fmt.Sprintf("d%d.example", i), answer))
	}
	previous, calls := a.states[s], runner.count()
	require.ErrorContains(t, a.AddResolvedDomain(ctx, s, generation, "overflow.example", answer), "domain lease capacity")
	require.Same(t, previous, a.states[s])
	require.Equal(t, calls, runner.count())
	require.False(t, a.dirtyLeases[s])
	// Expired DNS sources with live endpoint grace remain capacity owners.
	for _, addresses := range previous.domains {
		lease := addresses[addr]
		lease.tcp = map[uint16]time.Time{443: now.Add(5 * time.Minute)}
		addresses[addr] = lease
	}
	now = now.Add(2 * time.Minute)
	require.ErrorContains(t, a.AddResolvedDomain(ctx, s, generation, "overflow.example", answer), "domain lease capacity")
	require.Same(t, previous, a.states[s])
	require.Equal(t, calls, runner.count())
	now = now.Add(4 * time.Minute)
	runner.fail = func(string) error { return errors.New("not acknowledged") }
	a.refreshTick(ctx)
	require.Same(t, previous, a.states[s], "failed activity writes cannot retire source identities")
	require.ErrorContains(t, a.AddResolvedDomain(ctx, s, generation, "overflow.example", answer), "domain lease capacity")
	require.Len(t, a.states[s].domains, maxResolvedDomains)
	runner.fail = nil
	a.refreshTick(ctx)
	require.NoError(t, a.AddResolvedDomain(ctx, s, generation, "overflow.example", answer))
	require.Len(t, a.states[s].domains, 1, "successful activity planning retires expired inactive sources")
	require.Contains(t, a.states[s].domains, "overflow.example")

	require.NoError(t, a.ApplyDenyFirst(ctx, s, att))
	require.NoError(t, a.ApplyPolicy(ctx, s, domainPolicy(t, `{"egress":[{"action":"allow","target":"*.example","ports":[443]}]}`)))
	_, generation, _ = a.ResolutionPolicy(s, att.IP)
	addresses := make([]nftables.ResolvedIP, 0, maxDomainAddresses+1)
	for i := range maxDomainAddresses + 1 {
		addresses = append(addresses, nftables.ResolvedIP{Addr: netip.AddrFrom4([4]byte{192, 0, 2, byte(i + 1)}), TTL: time.Minute})
	}
	previous, calls = a.states[s], runner.count()
	require.ErrorContains(t, a.AddResolvedDomain(ctx, s, generation, "bounded.example", addresses), "address lease capacity")
	require.Same(t, previous, a.states[s])
	require.Empty(t, a.states[s].domains)
	require.Equal(t, calls, runner.count(), "oversized answers must not partially install")
	require.NoError(t, a.AddResolvedDomain(ctx, s, generation, "bounded.example", addresses[:maxDomainAddresses]))
	deadline := now.Add(2 * time.Minute)
	now = now.Add(10 * time.Second)
	require.NoError(t, a.AddResolvedDomain(ctx, s, generation, "bounded.example", []nftables.ResolvedIP{{Addr: addresses[0].Addr, TTL: -time.Minute}}))
	require.Equal(t, deadline, a.states[s].domains["bounded.example"][addresses[0].Addr].expires, "a shorter observation cannot truncate a source lease")
	previous, calls = a.states[s], runner.count()
	require.ErrorContains(t, a.AddResolvedDomain(ctx, s, generation, "bounded.example", addresses[maxDomainAddresses:]), "address lease capacity")
	require.Same(t, previous, a.states[s])
	require.Equal(t, calls, runner.count())
	now = now.Add(2 * time.Minute)
	a.refreshTick(ctx)
	require.NoError(t, a.AddResolvedDomain(ctx, s, generation, "bounded.example", addresses[maxDomainAddresses:]))
	require.Len(t, a.states[s].domains["bounded.example"], 1, "expired inactive provenance can be reclaimed")
}

func TestDomainDNSRecoveryPreservesActivityIdentityUntilRefresh(t *testing.T) {
	for _, scoped := range []bool{false, true} {
		for _, activity := range []string{"active", "ending", "never_observed", "revoked"} {
			t.Run(fmt.Sprintf("scoped_%t/%s", scoped, activity), func(t *testing.T) {
				ctx := context.Background()
				runner := &fakeRunner{}
				a := NewApplier(runner.Run)
				now := time.Unix(1700000000, 0)
				a.now = func() time.Time { return now }
				s := subject.FromSandboxUID("dns-recovery")
				att := testSlot("dns-recovery", "10.0.0.5")
				require.NoError(t, a.ApplyDenyFirst(ctx, s, att))
				ports := ""
				if scoped {
					ports = `,"ports":[443,8443]`
				}
				pol := domainPolicy(t, fmt.Sprintf(`{"egress":[{"action":"allow","target":"a.example"%s},{"action":"allow","target":"b.example"%s}]}`, ports, ports))
				require.NoError(t, a.ApplyPolicy(ctx, s, pol))
				_, generation, _ := a.ResolutionPolicy(s, att.IP)
				addr := netip.MustParseAddr("192.0.2.1")
				endpoint := nftables.TCPEndpoint{Addr: addr, Port: 443}
				require.NoError(t, a.AddResolvedDomain(ctx, s, generation, "a.example", []nftables.ResolvedIP{{Addr: addr}}))
				entries := []conntrackEntry{{src: att.IP, dst: addr, port: 443, state: "ESTABLISHED"}}
				a.conntrack = func(context.Context) ([]conntrackEntry, error) { return entries, nil }
				if activity == "ending" {
					now = now.Add(time.Second)
					a.refreshTick(ctx)
				}
				previous := a.states[s]
				runner.fail = func(string) error { return errors.New("refresh unavailable") }
				now = now.Add(30 * time.Second)
				a.refreshTick(ctx)
				require.Same(t, previous, a.states[s], "failed planning must not publish activity or deadlines")
				now = now.Add(10 * time.Minute)
				a.refreshTick(ctx)
				require.Same(t, previous, a.states[s])
				runner.fail = nil
				other := netip.MustParseAddr("192.0.2.2")
				require.NoError(t, a.AddResolvedDomain(ctx, s, generation, "b.example", []nftables.ResolvedIP{{Addr: other}}))
				require.NotContains(t, runner.last(), addr.String(), "DNS recovery cannot install expired identity as a grant")
				require.Contains(t, a.states[s].domains["a.example"], addr, "source facts must survive until a successful activity plan")
				require.NotContains(t, a.states[s].dyn, addr, "retained identity is not an installed IP grant")
				require.NotContains(t, a.states[s].allowTCP, endpoint, "retained identity is not an installed TCP grant")
				candidate := endpoint
				if !scoped {
					candidate.Port = 0
				}
				require.Contains(t, a.states[s].renewalEndpoints, candidate)
				if activity == "revoked" {
					require.NoError(t, a.ApplyPolicy(ctx, s, policy.DefaultDenyPolicy()))
					require.Empty(t, a.states[s].renewalEndpoints, "static policy replacement retires old candidates")
					a.refreshTick(ctx)
					require.NotContains(t, a.states[s].dyn, addr)
					require.NotContains(t, a.states[s].allowTCP, endpoint, "active conntrack cannot override current policy")
					return
				}
				if activity != "active" {
					entries = nil
				}
				if activity != "never_observed" {
					reconciled := a.states[s]
					runner.fail = func(string) error { return errors.New("activity retry unavailable") }
					a.refreshTick(ctx)
					require.Same(t, reconciled, a.states[s], "failed retries must preserve renewal identity and previous activity")
					runner.fail = nil
				}
				a.refreshTick(ctx)
				require.Empty(t, a.states[s].renewalEndpoints)
				if activity == "never_observed" {
					require.NotContains(t, a.states[s].dyn, addr)
					require.NotContains(t, a.states[s].allowTCP, endpoint, "expired identity without active or previous activity cannot grant")
					return
				}
				deadline := now.Add(360 * time.Second)
				if scoped {
					require.Equal(t, deadline, a.states[s].allowTCP[endpoint])
					require.NotContains(t, a.states[s].allowTCP, nftables.TCPEndpoint{Addr: addr, Port: 8443})
				} else {
					require.Equal(t, deadline, a.states[s].dyn[addr])
				}
				entries = nil
				now = now.Add(time.Second)
				a.refreshTick(ctx)
				final := a.states[s].clone()
				now = now.Add(time.Second)
				a.refreshTick(ctx)
				require.Equal(t, final.dyn, a.states[s].dyn, "idle ticks must not repeatedly extend final grace")
				require.Equal(t, final.allowTCP, a.states[s].allowTCP)
				now = now.Add(361 * time.Second)
				a.refreshTick(ctx)
				entries = []conntrackEntry{{src: att.IP, dst: addr, port: 443, state: "ESTABLISHED"}}
				a.refreshTick(ctx)
				require.NotContains(t, a.states[s].dyn, addr)
				require.NotContains(t, a.states[s].allowTCP, endpoint, "a successfully retired identity cannot be resurrected")
			})
		}
	}
}
