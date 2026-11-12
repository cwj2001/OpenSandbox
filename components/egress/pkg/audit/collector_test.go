// Copyright 2026 The OpenSandbox Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package audit

import (
	"net/netip"
	"testing"
	"time"

	"github.com/alibaba/opensandbox/egress/pkg/policy"
	"github.com/stretchr/testify/require"
)

// eventRecorder is a synchronous emitter; refuse simulates a full queue.
type eventRecorder struct {
	events []Event
	refuse bool
}

func (r *eventRecorder) TryEmit(e Event) bool {
	if r.refuse {
		return false
	}
	r.events = append(r.events, e)
	return true
}

type staticView struct {
	p        *policy.NetworkPolicy
	platform int
}

func (v staticView) EffectivePolicy() (*policy.NetworkPolicy, int) { return v.p, v.platform }

type fakeClock struct{ t time.Time }

func (c *fakeClock) now() time.Time { return c.t }

func newTestCollector(t *testing.T, view PolicyView) (*Collector, *eventRecorder, *fakeClock) {
	t.Helper()
	sink := &eventRecorder{}
	clock := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	return newCollector(sink, view, clock.now), sink, clock
}

func platformView(t *testing.T) staticView {
	t.Helper()
	user, err := policy.ParsePolicy(`{"defaultAction":"deny","egress":[
		{"action":"allow","target":"pypi.org"},
		{"action":"allow","target":"203.0.113.0/24"},
		{"action":"deny","ports":[25]}]}`)
	require.NoError(t, err)
	alwaysDeny, err := policy.ParseValidatedEgressRule(policy.ActionDeny, "10.96.0.0/12")
	require.NoError(t, err)
	return staticView{p: policy.MergeAlwaysOverlay(user, []policy.EgressRule{alwaysDeny}, nil), platform: 1}
}

func TestCollectorDNSThenConnectionCarriesDomain(t *testing.T) {
	c, sink, clock := newTestCollector(t, nil)
	at := clock.t
	c.RecordDNS(DNSRecord{
		Domain: "pypi.org", Decision: DecisionAllow, Reason: ReasonPolicy,
		QueryType: "A", ResponseCode: "NOERROR",
		Answers: []netip.Addr{netip.MustParseAddr("151.101.0.223")}, TTL: time.Minute,
	})
	c.handleNFLog(NFLogPrefix(DecisionAllow, ReasonDNSLease), ipv4Packet(protoTCP, "192.0.2.2", "151.101.0.223", 40000, 443))
	c.handleNFLog(NFLogPrefix(DecisionDeny, ReasonDefault), ipv4Packet(protoTCP, "192.0.2.2", "198.51.100.7", 40001, 443))

	require.Len(t, sink.events, 3)
	require.Equal(t, Event{
		Layer: LayerDNS, Decision: DecisionAllow, Reason: ReasonPolicy, ObservedAt: at, Domain: "pypi.org",
		QueryType: "A", ResponseCode: "NOERROR", ResolvedIPs: []string{"151.101.0.223"},
	}, sink.events[0])
	require.Equal(t, Event{
		Layer: LayerL4, Decision: DecisionAllow, Reason: ReasonDNSLease, ObservedAt: at, Domain: "pypi.org", DNSSeen: true,
		Protocol: "tcp", DestinationIP: netip.MustParseAddr("151.101.0.223"), DestinationPort: 443,
	}, sink.events[1])
	require.Equal(t, Event{
		Layer: LayerL4, Decision: DecisionDeny, Reason: ReasonDefault, ObservedAt: at,
		Protocol: "tcp", DestinationIP: netip.MustParseAddr("198.51.100.7"), DestinationPort: 443,
	}, sink.events[2], "a literal-IP dial carries no domain and dns_seen=false")
}

func TestCollectorDeniedDNSDoesNotAttributeAddresses(t *testing.T) {
	c, sink, _ := newTestCollector(t, nil)
	c.RecordDNS(DNSRecord{Domain: "evil.example", Decision: DecisionDeny, Reason: ReasonPolicy, ResponseCode: "NXDOMAIN"})
	c.handleNFLog(NFLogPrefix(DecisionDeny, ReasonDefault), ipv4Packet(protoUDP, "192.0.2.2", "198.51.100.7", 5000, 9999))
	require.Len(t, sink.events, 2)
	require.False(t, sink.events[1].DNSSeen)
	require.Empty(t, sink.events[1].Domain)
}

func TestCollectorDeduplicatesRetransmits(t *testing.T) {
	c, sink, clock := newTestCollector(t, nil)
	syn := ipv4Packet(protoTCP, "192.0.2.2", "198.51.100.7", 40000, 443)
	prefix := NFLogPrefix(DecisionDeny, ReasonDefault)

	c.handleNFLog(prefix, syn)
	clock.t = clock.t.Add(time.Second)
	c.handleNFLog(prefix, syn)
	require.Len(t, sink.events, 1, "SYN retransmit of the same attempt")
	require.Equal(t, uint64(1), c.Stats().Deduplicated, "a folded copy is still accounted for")

	c.handleNFLog(prefix, ipv4Packet(protoTCP, "192.0.2.2", "198.51.100.7", 40002, 443))
	require.Len(t, sink.events, 2, "a new source port is a new attempt")

	clock.t = clock.t.Add(flowDedupWindow)
	c.handleNFLog(prefix, syn)
	require.Len(t, sink.events, 3, "the window expires")
}

func TestCollectorDedupIsBounded(t *testing.T) {
	c, sink, _ := newTestCollector(t, nil)
	prefix := NFLogPrefix(DecisionAllow, ReasonDefault)
	for i := 0; i < maxTrackedFlows+10; i++ {
		c.handleNFLog(prefix, ipv4Packet(protoUDP, "192.0.2.2", "198.51.100.7", uint16(i%65536), uint16(1+i/65536)))
	}
	require.LessOrEqual(t, len(c.flows), maxTrackedFlows)
	stats := c.snapshot()
	require.Equal(t, uint64(maxTrackedFlows+10), stats.Detailed+stats.Aggregated, "every distinct flow is counted")
	require.Len(t, sink.events, int(stats.Detailed))
}

func TestCollectorIgnoresForeignAndUndecodablePackets(t *testing.T) {
	c, sink, _ := newTestCollector(t, nil)
	c.handleNFLog("someone-else", ipv4Packet(protoTCP, "192.0.2.2", "198.51.100.7", 1, 2))
	c.handleNFLog(NFLogPrefix(DecisionDeny, ReasonDefault), []byte{0x45, 0})
	require.Empty(t, sink.events)
}

func TestCollectorAttributesRules(t *testing.T) {
	c, sink, _ := newTestCollector(t, platformView(t))
	c.handleNFLog(NFLogPrefix(DecisionDeny, ReasonIPRule), ipv4Packet(protoTCP, "192.0.2.2", "10.96.0.10", 1, 5432))
	c.handleNFLog(NFLogPrefix(DecisionAllow, ReasonIPRule), ipv4Packet(protoTCP, "192.0.2.2", "203.0.113.5", 2, 443))
	c.handleNFLog(NFLogPrefix(DecisionDeny, ReasonPortRule), ipv4Packet(protoTCP, "192.0.2.2", "198.51.100.7", 3, 25))
	c.handleNFLog(NFLogPrefix(DecisionDeny, ReasonDefault), ipv4Packet(protoTCP, "192.0.2.2", "198.51.100.7", 4, 80))

	require.Len(t, sink.events, 4)
	require.Equal(t, "10.96.0.0/12", sink.events[0].Rule)
	require.Equal(t, "platform", sink.events[0].RuleSource)
	require.Equal(t, "203.0.113.0/24", sink.events[1].Rule)
	require.Equal(t, "user", sink.events[1].RuleSource)
	require.Equal(t, "ports 25", sink.events[2].Rule)
	require.Equal(t, "user", sink.events[2].RuleSource)
	require.Empty(t, sink.events[3].Rule, "default verdicts name no rule")
}

func TestCollectorAttributionToleratesPolicyDrift(t *testing.T) {
	// The verdict came from a rule the current policy no longer has.
	c, sink, _ := newTestCollector(t, staticView{p: policy.DefaultDenyPolicy()})
	c.handleNFLog(NFLogPrefix(DecisionAllow, ReasonIPRule), ipv4Packet(protoTCP, "192.0.2.2", "203.0.113.5", 2, 443))
	require.Len(t, sink.events, 1)
	require.Empty(t, sink.events[0].Rule)
}

func TestDescribeRule(t *testing.T) {
	require.Equal(t, "10.0.0.0/8", describeRule(policy.EgressRule{Target: "10.0.0.0/8"}))
	require.Equal(t, "ports 25,465", describeRule(policy.EgressRule{Ports: []int{25, 465}}))
	require.Equal(t, "198.51.100.7 ports 443", describeRule(policy.EgressRule{Target: "198.51.100.7", Ports: []int{443}}))
	require.Equal(t, "reachable.ports.cap", describeRule(policy.EgressRule{PortRanges: []policy.PortRange{{Lo: 1, Hi: 79}}}))
}

func TestDNSAnswersCappedInEvent(t *testing.T) {
	c, sink, _ := newTestCollector(t, nil)
	var answers []netip.Addr
	for i := 0; i < maxEventAnswerIPs+5; i++ {
		answers = append(answers, netip.AddrFrom4([4]byte{198, 51, 100, byte(i)}))
	}
	c.RecordDNS(DNSRecord{Domain: "many.example", Decision: DecisionAllow, Reason: ReasonPolicy, Answers: answers, TTL: time.Minute})
	require.Len(t, sink.events[0].ResolvedIPs, maxEventAnswerIPs)
	_, seen := c.domains.lookup(answers[len(answers)-1])
	require.True(t, seen, "attribution keeps every answer even when the event is capped")
}

func TestDomainCacheExpiryAndCapacity(t *testing.T) {
	clock := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	cache := newDomainCache(clock.now)
	addr := netip.MustParseAddr("198.51.100.7")
	cache.observe("a.example", []netip.Addr{addr}, time.Second)
	domain, ok := cache.lookup(netip.MustParseAddr("::ffff:198.51.100.7"))
	require.True(t, ok)
	require.Equal(t, "a.example", domain)

	cache.observe("b.example", []netip.Addr{addr}, time.Second)
	domain, _ = cache.lookup(addr)
	require.Equal(t, "b.example", domain, "latest answer wins")

	clock.t = clock.t.Add(domainRetention)
	_, ok = cache.lookup(addr)
	require.False(t, ok)

	evictions := 0
	for i := 0; i < 4*maxDomainEntries; i++ {
		if len(cache.entries) == maxDomainEntries {
			evictions++
		}
		cache.observe("bulk.example", []netip.Addr{netip.AddrFrom4([4]byte{10, byte(i >> 16), byte(i >> 8), byte(i)})}, time.Minute)
		require.LessOrEqual(t, len(cache.entries), maxDomainEntries)
	}
	// Churn with nothing expired: each full scan frees an eighth, so scans
	// stay rare instead of running on every insert.
	require.LessOrEqual(t, evictions, 3*8+1)
	n := 4*maxDomainEntries - 1
	last := netip.AddrFrom4([4]byte{10, byte(n >> 16), byte(n >> 8), byte(n)})
	domain, ok = cache.lookup(last)
	require.True(t, ok, "the newest answer is always kept")
	require.Equal(t, "bulk.example", domain)
}

func TestDomainCacheEvictsExpiredFirst(t *testing.T) {
	clock := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	cache := newDomainCache(clock.now)
	for i := 0; i < maxDomainEntries; i++ {
		cache.observe("old.example", []netip.Addr{netip.AddrFrom4([4]byte{10, 1, byte(i >> 8), byte(i)})}, time.Minute)
	}
	clock.t = clock.t.Add(domainRetention)
	fresh := netip.MustParseAddr("192.0.2.1")
	cache.observe("new.example", []netip.Addr{fresh}, time.Minute)
	require.Len(t, cache.entries, 1, "every expired entry goes before any live one")
}
