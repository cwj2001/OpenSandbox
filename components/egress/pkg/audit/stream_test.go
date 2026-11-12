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

	"github.com/stretchr/testify/require"
)

// counted sums the queries/connections an event stands for.
func counted(events []Event, layer string) uint64 {
	var n uint64
	for _, e := range events {
		if e.Layer != layer {
			continue
		}
		if e.Count > 0 {
			n += e.Count
		} else {
			n++
		}
	}
	return n
}

func lastOf(events []Event, reason string) *Event {
	for i := len(events) - 1; i >= 0; i-- {
		if events[i].Layer == LayerAudit && events[i].Reason == reason {
			return &events[i]
		}
	}
	return nil
}

// Over the detailed budget, connections are aggregated, never dropped: the
// stream accounts for every one of them.
func TestOverBudgetConnectionsAreAggregatedNotLost(t *testing.T) {
	c, sink, clock := newTestCollector(t, platformView(t))
	dsts := []string{"203.0.113.5", "203.0.113.6", "198.51.100.7"}
	const total = 5000
	for i := 0; i < total; i++ {
		c.handleNFLog(NFLogPrefix(DecisionAllow, ReasonIPRule),
			ipv4Packet(protoTCP, "192.0.2.2", dsts[i%len(dsts)], uint16(1024+i), 443))
	}
	stats := c.snapshot()
	require.Equal(t, uint64(detailedBurst), stats.Detailed)
	require.Equal(t, uint64(total-detailedBurst), stats.Aggregated)

	clock.t = clock.t.Add(flushInterval)
	c.tick()
	var aggregates []Event
	for _, e := range sink.events {
		if e.Count > 0 {
			aggregates = append(aggregates, e)
		}
	}
	require.Len(t, aggregates, len(dsts), "one aggregate per destination")
	for _, e := range aggregates {
		require.False(t, e.WindowStart.IsZero())
		if netip.MustParsePrefix("203.0.113.0/24").Contains(e.DestinationIP) {
			require.Equal(t, "203.0.113.0/24", e.Rule, "aggregates are attributed too")
		} else {
			require.Empty(t, e.Rule)
		}
	}
	require.Equal(t, uint64(total), counted(sink.events, LayerL4))
}

func TestBudgetRefills(t *testing.T) {
	c, sink, clock := newTestCollector(t, nil)
	for i := 0; i < detailedBurst+10; i++ {
		c.RecordDNS(DNSRecord{Domain: "a.example", Decision: DecisionDeny, Reason: ReasonPolicy})
	}
	require.Len(t, sink.events, detailedBurst)
	clock.t = clock.t.Add(time.Second)
	for i := 0; i < detailedPerSecond+10; i++ {
		c.RecordDNS(DNSRecord{Domain: "a.example", Decision: DecisionDeny, Reason: ReasonPolicy})
	}
	require.Len(t, sink.events, detailedBurst+detailedPerSecond)
}

// A full queue folds events into aggregates, and aggregates the queue cannot
// take yet wait for the next flush.
func TestRefusedEventsWaitForRoom(t *testing.T) {
	c, sink, clock := newTestCollector(t, nil)
	sink.refuse = true
	c.RecordDNS(DNSRecord{Domain: "a.example", Decision: DecisionAllow, Reason: ReasonPolicy})
	c.RecordDNS(DNSRecord{Domain: "a.example", Decision: DecisionAllow, Reason: ReasonPolicy})
	c.Started([]string{LayerDNS}, "")
	clock.t = clock.t.Add(flushInterval)
	c.tick()
	require.Empty(t, sink.events)

	sink.refuse = false
	clock.t = clock.t.Add(flushInterval)
	c.tick()
	require.NotNil(t, lastOf(sink.events, ReasonStarted), "lifecycle events are retried")
	require.Equal(t, uint64(2), counted(sink.events, LayerDNS))
}

func TestAggregateOverflowKeepsCounts(t *testing.T) {
	c, sink, clock := newTestCollector(t, nil)
	sink.refuse = true
	const total = maxAggregateKeys + 500
	for i := 0; i < total; i++ {
		c.handleNFLog(NFLogPrefix(DecisionDeny, ReasonDefault),
			ipv4Packet(protoUDP, "192.0.2.2", netip.AddrFrom4([4]byte{198, 18, byte(i >> 8), byte(i)}).String(), 5000, 53))
	}
	sink.refuse = false
	clock.t = clock.t.Add(flushInterval)
	c.tick()
	require.Equal(t, uint64(total), counted(sink.events, LayerL4))
	var coarse *Event
	for i := range sink.events {
		if !sink.events[i].DestinationIP.IsValid() {
			coarse = &sink.events[i]
		}
	}
	require.NotNil(t, coarse, "keys past the window bound fold into one coarse aggregate")
	require.Equal(t, uint64(500), coarse.Count)
	require.NotContains(t, eventFieldKeys(*coarse), "dst_ip")
}

func eventFieldKeys(e Event) []string {
	var keys []string
	for _, f := range e.fields() {
		keys = append(keys, f.Key)
	}
	return keys
}

func TestSequenceGapsAreExactAndReportedOnce(t *testing.T) {
	c, sink, clock := newTestCollector(t, nil)
	start := clock.t
	for _, seq := range []uint32{0, 1, 5, 6} { // 2, 3, 4 lost
		c.observeSeq(seq)
	}
	c.handleNFLog(NFLogPrefix(DecisionDeny, ReasonDefault), []byte{0x45})
	clock.t = clock.t.Add(flushInterval)
	c.tick()
	gap := lastOf(sink.events, ReasonGap)
	require.NotNil(t, gap)
	require.Equal(t, Stats{LostKernel: 3, LostUndecodable: 1}, *gap.Stats)
	require.Equal(t, start, gap.WindowStart)
	require.Equal(t, clock.t, gap.WindowEnd)

	clock.t = clock.t.Add(flushInterval)
	c.tick()
	require.Same(t, gap, lastOf(sink.events, ReasonGap), "no new loss, no new gap event")
}

func TestSequenceGapAcrossWraparound(t *testing.T) {
	c, _, _ := newTestCollector(t, nil)
	c.nextSeq = 0xfffffffe
	c.observeSeq(0xfffffffe)
	c.observeSeq(0)
	require.Equal(t, uint64(1), c.snapshot().LostKernel, "0xffffffff was lost")
}

func TestFirstCopiesLostBeforeTheFirstReadAreCounted(t *testing.T) {
	c, _, _ := newTestCollector(t, nil)
	c.observeSeq(4)
	require.Equal(t, uint64(4), c.snapshot().LostKernel)
}

func TestGapReportRetriedUntilWritten(t *testing.T) {
	c, sink, clock := newTestCollector(t, nil)
	c.observeSeq(2)
	sink.refuse = true
	clock.t = clock.t.Add(flushInterval)
	c.tick()
	sink.refuse = false
	c.observeSeq(5)
	clock.t = clock.t.Add(flushInterval)
	c.tick()
	gap := lastOf(sink.events, ReasonGap)
	require.NotNil(t, gap)
	require.Equal(t, uint64(4), gap.Stats.LostKernel, "the refused report is folded into the next")
}

func TestHeartbeatCarriesCumulativeStats(t *testing.T) {
	c, sink, clock := newTestCollector(t, nil)
	c.RecordDNS(DNSRecord{Domain: "a.example", Decision: DecisionAllow, Reason: ReasonPolicy})
	clock.t = clock.t.Add(heartbeatInterval - time.Second)
	c.tick()
	require.Nil(t, lastOf(sink.events, ReasonHeartbeat))
	clock.t = clock.t.Add(time.Second)
	c.tick()
	hb := lastOf(sink.events, ReasonHeartbeat)
	require.NotNil(t, hb)
	require.Equal(t, Stats{Detailed: 1}, *hb.Stats)
}

func TestCloseFlushesAndReportsFinalStats(t *testing.T) {
	c, sink, _ := newTestCollector(t, nil)
	for i := 0; i < detailedBurst+7; i++ {
		c.RecordDNS(DNSRecord{Domain: "a.example", Decision: DecisionAllow, Reason: ReasonPolicy})
	}
	c.observeSeq(3)
	c.Close(time.Second)
	c.Close(time.Second) // idempotent

	stopped := lastOf(sink.events, ReasonStopped)
	require.NotNil(t, stopped)
	require.Equal(t, Stats{Detailed: detailedBurst, Aggregated: 7, LostKernel: 3}, *stopped.Stats)
	require.Equal(t, uint64(detailedBurst+7), counted(sink.events, LayerDNS), "aggregates are flushed before stopped")
	require.NotNil(t, lastOf(sink.events, ReasonGap))
	require.Equal(t, ReasonStopped, sink.events[len(sink.events)-1].Reason, "stopped is the last event")
}

func TestOverrunWithoutLaterCopyIsDeclared(t *testing.T) {
	c, sink, _ := newTestCollector(t, nil)
	c.observeSeq(0)
	c.markOverrun()
	c.Close(time.Second)
	stopped := lastOf(sink.events, ReasonStopped)
	require.NotNil(t, stopped)
	require.Contains(t, stopped.Detail, "overrun after the last delivered copy")

	c2, sink2, _ := newTestCollector(t, nil)
	c2.markOverrun()
	c2.observeSeq(3) // the next copy counts the loss
	c2.Close(time.Second)
	stopped = lastOf(sink2.events, ReasonStopped)
	require.Empty(t, stopped.Detail)
	require.Equal(t, uint64(3), stopped.Stats.LostKernel)
}
