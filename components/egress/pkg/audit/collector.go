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
	"sync"
	"sync/atomic"
	"time"

	"github.com/alibaba/opensandbox/egress/pkg/telemetry"
	"github.com/alibaba/opensandbox/internal/safego"
)

const maxEventAnswerIPs = 32

const (
	// Individual events are budgeted; over budget, events are aggregated
	// rather than dropped, so every query is still counted.
	detailedPerSecond = 1000
	detailedBurst     = 2000

	flushInterval     = time.Second
	heartbeatInterval = time.Minute
)

type emitter interface {
	TryEmit(Event) bool
}

type Collector struct {
	out    emitter
	sink   *AsyncSink
	now    func() time.Time
	budget tokenBucket
	agg    *aggregator

	detailed   atomic.Uint64
	aggregated atomic.Uint64
	// Guarded by mu: the flush goroutine, lifecycle calls and Close.
	mu            sync.Mutex
	pending       []Event
	lastHeartbeat time.Time

	stop      chan context.Context
	done      chan struct{}
	closeOnce sync.Once
}

// NewCollector claims the audit lane and starts its flush loop. Close drains
// only that lane; ordinary diagnostics retain their independent lifetime.
func NewCollector(sink *AsyncSink) *Collector {
	c := newCollector(sink, time.Now)
	c.sink = sink
	c.done = make(chan struct{})
	safego.Go(c.run)
	return c
}

func newCollector(out emitter, now func() time.Time) *Collector {
	start := now()
	return &Collector{
		out:           out,
		now:           now,
		budget:        tokenBucket{rate: detailedPerSecond, burst: detailedBurst},
		agg:           newAggregator(),
		lastHeartbeat: start,
		stop:          make(chan context.Context, 1),
	}
}

func (c *Collector) run() {
	defer close(c.done)
	ticker := time.NewTicker(flushInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			c.tick()
		case ctx := <-c.stop:
			c.finish(ctx, func(e Event) bool { return c.sink.emitBefore(e, ctx) })
			return
		}
	}
}

// tick writes aggregates and sends the heartbeat. Events
// the queue refuses stay pending (aggregates are merged back) for the next
// tick.
func (c *Collector) tick() {
	now := c.now()
	c.mu.Lock()
	defer c.mu.Unlock()
	c.flushLocked(c.out.TryEmit)
	if now.Sub(c.lastHeartbeat) >= heartbeatInterval {
		if c.out.TryEmit(Event{Layer: LayerAudit, Reason: ReasonHeartbeat, ObservedAt: now, Stats: c.snapshot()}) {
			c.lastHeartbeat = now
		}
	}
}

func (c *Collector) flushLocked(emit func(Event) bool) bool {
	accepted := true
	kept := c.pending[:0]
	for _, e := range c.pending {
		if !emit(e) {
			accepted = false
			kept = append(kept, e)
		}
	}
	c.pending = kept

	for k, v := range c.agg.drain() {
		e := k.event(v)
		if !emit(e) {
			accepted = false
			c.agg.merge(k, *v)
		}
	}

	return accepted
}

// Started records DNS coverage.
func (c *Collector) Started() {
	c.lifecycle(Event{Layer: LayerAudit, Reason: ReasonStarted, ObservedAt: c.now(), Coverage: []string{LayerDNS}})
}

func (c *Collector) lifecycle(e Event) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.out.TryEmit(e) {
		c.pending = append(c.pending, e)
	}
}

// Close writes pending aggregates and a stopped event
// with the final Stats. One deadline covers producers and
// the writer. An unfinished worker or refused output leaves stopped absent.
func (c *Collector) Close(timeout time.Duration) {
	c.closeOnce.Do(func() {
		deadline := time.Now().Add(timeout)
		ctx, cancel := context.WithDeadline(context.Background(), deadline)
		defer cancel()
		c.stop <- ctx
		select {
		case <-c.done:
		case <-ctx.Done():
		}
		c.sink.CloseAudit(deadline)
	})
}

func (c *Collector) finish(ctx context.Context, output func(Event) bool) {
	emit := func(e Event) bool {
		if !beforeDeadline(ctx) {
			return false
		}
		return output(e)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if !beforeDeadline(ctx) {
		return
	}
	now := c.now()
	if c.flushLocked(emit) {
		emit(Event{Layer: LayerAudit, Reason: ReasonStopped, ObservedAt: now, Stats: c.snapshot()})
	}
}

// Stats returns the running totals.
func (c *Collector) Stats() Stats {
	return *c.snapshot()
}

func (c *Collector) snapshot() *Stats {
	return &Stats{
		Detailed:   c.detailed.Load(),
		Aggregated: c.aggregated.Load(),
	}
}

// emit writes e on its own while the budget and the queue allow, and folds it
// into the current aggregate window otherwise.
func (c *Collector) emit(e Event, answers []netip.Addr) {
	if c.budget.allow(e.ObservedAt) {
		// Aggregates omit answers. Do not format them on the DNS reply path
		// unless this event has been admitted for detailed output.
		if n := min(len(answers), maxEventAnswerIPs); n > 0 {
			e.ResolvedIPs = make([]string, n)
			for i, addr := range answers[:n] {
				e.ResolvedIPs[i] = addr.String()
			}
		}
		if c.out.TryEmit(e) {
			c.detailed.Add(1)
			return
		}
	}
	c.agg.add(e)
	c.aggregated.Add(1)
	telemetry.RecordAuditAggregated()
}

// DNSRecord is one decided DNS query, as reported by the DNS proxy.
type DNSRecord struct {
	Domain       string
	Decision     string
	Reason       string
	QueryType    string
	ResponseCode string
	// Answers are the A/AAAA addresses returned to the client.
	Answers []netip.Addr
}

func (c *Collector) RecordDNS(r DNSRecord) {
	e := Event{
		Layer:        LayerDNS,
		Decision:     r.Decision,
		Reason:       r.Reason,
		ObservedAt:   c.now(),
		Domain:       r.Domain,
		QueryType:    r.QueryType,
		ResponseCode: r.ResponseCode,
	}
	c.emit(e, r.Answers)
}

// tokenBucket budgets individual events. Callers pass event times, which can
// arrive slightly out of order across goroutines; time never runs backwards.
type tokenBucket struct {
	mu          sync.Mutex
	rate, burst float64
	tokens      float64
	last        time.Time
}

func (b *tokenBucket) allow(now time.Time) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.last.IsZero() {
		b.tokens, b.last = b.burst, now
	}
	if now.After(b.last) {
		b.tokens = min(b.burst, b.tokens+now.Sub(b.last).Seconds()*b.rate)
		b.last = now
	}
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}
