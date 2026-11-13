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
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/alibaba/opensandbox/egress/pkg/policy"
	"github.com/stretchr/testify/require"
)

func TestDNSOnlyDoesNotMaintainConnectionCache(t *testing.T) {
	out := &eventRecorder{}
	c := newCollector(out, nil, time.Now)
	c.RecordDNS(DNSRecord{Domain: "a.example", Decision: DecisionAllow,
		Answers: []netip.Addr{netip.MustParseAddr("192.0.2.1")}})
	require.Empty(t, c.domains.entries)
	require.Equal(t, []string{"192.0.2.1"}, out.events[0].ResolvedIPs)
}

func TestAggregatedDNSRetainsAllConnectionAttribution(t *testing.T) {
	c, out, _ := newTestCollector(t, nil)
	c.budget = tokenBucket{rate: 1} // no detailed admission
	var answers []netip.Addr
	for i := range maxEventAnswerIPs + 5 {
		answers = append(answers, netip.AddrFrom4([4]byte{198, 51, 100, byte(i)}))
	}
	c.RecordDNS(DNSRecord{Domain: "many.example", Decision: DecisionAllow,
		Reason: ReasonPolicy, Answers: answers})
	require.Empty(t, out.events)
	domain, seen := c.domains.lookup(answers[len(answers)-1])
	require.True(t, seen)
	require.Equal(t, "many.example", domain)
	c.tick()
	require.Len(t, out.events, 1)
	require.Empty(t, out.events[0].ResolvedIPs)
	require.Equal(t, "many.example", out.events[0].Domain)
	require.Equal(t, uint64(1), out.events[0].Count)
	require.Equal(t, uint64(1), c.Stats().Aggregated)
}

type unexpectedPolicyRead struct{}

func (unexpectedPolicyRead) EffectivePolicy() (*policy.NetworkPolicy, int) {
	panic("verdict without rule attribution must not lock/read policy")
}

func TestUnattributedVerdictsDoNotReadPolicy(t *testing.T) {
	c, _, _ := newTestCollector(t, unexpectedPolicyRead{})
	for _, reason := range []string{ReasonDefault, ReasonDoH, ReasonDoT, ReasonDNSLease, ReasonPortRule} {
		e := Event{Layer: LayerL4, Reason: reason, Protocol: "udp",
			DestinationIP: netip.MustParseAddr("192.0.2.1")}
		require.NotPanics(t, func() { c.attributeRule(&e) })
	}
}

func TestCloseJoinsL4BeforeFinalStats(t *testing.T) {
	out := &eventRecorder{}
	c := newCollector(out, nil, time.Now)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	c.l4Cancel, c.l4Done = cancel, done
	go func() {
		defer close(done)
		<-ctx.Done()
		// Simulate an in-flight datagram finishing after cancellation.
		c.handleNFLog(NFLogPrefix(DecisionDeny, ReasonDefault),
			ipv4Packet(protoUDP, "192.0.2.2", "198.51.100.7", 5000, 9999))
		c.l4Backlog.Store(true)
	}()
	c.Close(time.Second)
	require.Len(t, out.events, 2)
	require.Equal(t, LayerL4, out.events[0].Layer)
	last := out.events[1]
	require.Equal(t, ReasonStopped, last.Reason)
	require.Equal(t, uint64(1), last.Stats.Detailed)
	require.Contains(t, last.Detail, "unread copies")
}

func TestCloseDoesNotClaimFinalStatsForUnfinishedReader(t *testing.T) {
	out := &eventRecorder{}
	c := newCollector(out, nil, time.Now)
	done := make(chan struct{})
	defer close(done)
	cancelled := false
	c.l4Cancel = func() { cancelled = true }
	c.l4Done = done
	start := time.Now()
	c.Close(20 * time.Millisecond)
	require.True(t, cancelled)
	require.Less(t, time.Since(start), time.Second)
	require.Empty(t, out.events, "unfinished reader cannot publish stopped/final totals")
}
