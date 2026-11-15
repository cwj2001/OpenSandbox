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
	"fmt"
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
func TestOverBudgetDNSAreAggregatedNotLost(t *testing.T) {
	c, sink, clock := newTestCollector(t)
	dsts := []string{"a.example", "b.example", "c.example"}
	const total = 5000
	for i := 0; i < total; i++ {
		c.RecordDNS(DNSRecord{Domain: dsts[i%len(dsts)], Decision: DecisionAllow, Reason: ReasonPolicy})
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

	}
	require.Equal(t, uint64(total), counted(sink.events, LayerDNS))
}

func TestBudgetRefills(t *testing.T) {
	c, sink, clock := newTestCollector(t)
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
	c, sink, clock := newTestCollector(t)
	sink.refuse = true
	c.RecordDNS(DNSRecord{Domain: "a.example", Decision: DecisionAllow, Reason: ReasonPolicy})
	c.RecordDNS(DNSRecord{Domain: "a.example", Decision: DecisionAllow, Reason: ReasonPolicy})
	c.Started()
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
	c, sink, clock := newTestCollector(t)
	sink.refuse = true
	const total = maxAggregateKeys + 500
	for i := 0; i < total; i++ {
		c.RecordDNS(DNSRecord{Domain: fmt.Sprintf("host%d.example", i), Decision: DecisionDeny, Reason: ReasonPolicy})
	}
	sink.refuse = false
	clock.t = clock.t.Add(flushInterval)
	c.tick()
	require.Equal(t, uint64(total), counted(sink.events, LayerDNS))
	var coarse *Event
	for i := range sink.events {
		if sink.events[i].Domain == "" {
			coarse = &sink.events[i]
		}
	}
	require.NotNil(t, coarse, "keys past the window bound fold into one coarse aggregate")
	require.Equal(t, uint64(500), coarse.Count)
	require.NotContains(t, logSinkRecord(t, *coarse), "domain")
}

func TestHeartbeatCarriesCumulativeStats(t *testing.T) {
	c, sink, clock := newTestCollector(t)
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
	c, sink, _ := newTestCollector(t)
	for i := 0; i < detailedBurst+7; i++ {
		c.RecordDNS(DNSRecord{Domain: "a.example", Decision: DecisionAllow, Reason: ReasonPolicy})
	}
	finishTestCollector(c, time.Second)
	finishTestCollector(c, time.Second) // idempotent

	stopped := lastOf(sink.events, ReasonStopped)
	require.NotNil(t, stopped)
	require.Equal(t, Stats{Detailed: detailedBurst, Aggregated: 7}, *stopped.Stats)
	require.Equal(t, uint64(detailedBurst+7), counted(sink.events, LayerDNS), "aggregates are flushed before stopped")
	require.Equal(t, ReasonStopped, sink.events[len(sink.events)-1].Reason, "stopped is the last event")
}
