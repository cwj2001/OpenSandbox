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
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/alibaba/opensandbox/egress/pkg/policy"
	"github.com/alibaba/opensandbox/egress/pkg/telemetry"
	"github.com/alibaba/opensandbox/internal/safego"
)

const (
	// flowDedupWindow folds TCP SYN retransmits and the repeated packets of a
	// denied UDP flow (each is conntrack-new, so each is logged) into one event.
	flowDedupWindow = 30 * time.Second
	maxTrackedFlows = 16384

	// Individual events are budgeted; over budget, events are aggregated
	// rather than dropped, so every query and connection is still counted.
	detailedPerSecond = 1000
	detailedBurst     = 2000

	flushInterval     = time.Second
	heartbeatInterval = time.Minute
)

// PolicyView exposes the effective sidecar policy for rule attribution.
type PolicyView interface {
	// EffectivePolicy returns the merged policy and how many of its leading
	// rules come from the platform overlay (always-deny, then always-allow).
	EffectivePolicy() (*policy.NetworkPolicy, int)
}

type emitter interface {
	TryEmit(Event) bool
}

// Collector turns DNS decisions and NFLOG verdict copies into audit events.
//
// Accounting invariant: every query and L4 copy it observes ends up in
// exactly one of Stats.Detailed, Aggregated, Deduplicated or
// LostUndecodable, and every L4 copy the kernel failed to deliver in
// Stats.LostKernel; losses are reported in-stream by gap events. Only a crash, or a writer slower than the shutdown deadline, loses
// events without a record — downstream sees that as a Seq gap or a missing
// stopped event for the BootID.
type Collector struct {
	out     emitter
	sink    *AsyncSink // nil when a test supplies a synchronous emitter
	policy  PolicyView
	domains *domainCache
	now     func() time.Time
	budget  tokenBucket
	agg     *aggregator

	detailed        atomic.Uint64
	aggregated      atomic.Uint64
	deduplicated    atomic.Uint64
	lostKernel      atomic.Uint64
	lostUndecodable atomic.Uint64
	// overrunPending is set by a receive-buffer overrun and cleared by the
	// next delivered copy, whose sequence number counts the loss.
	overrunPending atomic.Bool
	l4Backlog      atomic.Bool
	l4Active       atomic.Bool

	// Set by StartL4 before producers start; Close joins the reader before
	// publishing final totals. Neither startup nor Close may run concurrently.
	l4Cancel context.CancelFunc
	l4Done   <-chan struct{}

	// NFLOG reader goroutine only.
	flows   map[flow]time.Time
	nextSeq uint32

	// Guarded by mu: the flush goroutine, lifecycle calls and Close.
	mu            sync.Mutex
	pending       []Event
	reported      Stats
	reportedAt    time.Time
	lastHeartbeat time.Time

	stop      chan struct{}
	done      chan struct{}
	closeOnce sync.Once
}

// NewCollector writes events to inner through an AsyncSink and starts the
// flush loop. Call Close to flush on shutdown.
func NewCollector(inner Sink, view PolicyView) *Collector {
	sink := NewAsyncSink(inner, DefaultQueueSize)
	c := newCollector(sink, view, time.Now)
	c.sink = sink
	c.done = make(chan struct{})
	safego.Go(c.run)
	return c
}

func newCollector(out emitter, view PolicyView, now func() time.Time) *Collector {
	start := now()
	return &Collector{
		out:           out,
		policy:        view,
		domains:       newDomainCache(now),
		now:           now,
		budget:        tokenBucket{rate: detailedPerSecond, burst: detailedBurst},
		agg:           newAggregator(),
		flows:         make(map[flow]time.Time),
		reportedAt:    start,
		lastHeartbeat: start,
		stop:          make(chan struct{}),
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
		case <-c.stop:
			return
		}
	}
}

// tick writes aggregates, reports new losses and sends the heartbeat. Events
// the queue refuses stay pending (aggregates are merged back) for the next
// tick.
func (c *Collector) tick() {
	now := c.now()
	c.mu.Lock()
	defer c.mu.Unlock()
	c.flushLocked(now, c.out.TryEmit)
	if now.Sub(c.lastHeartbeat) >= heartbeatInterval {
		if c.out.TryEmit(Event{Layer: LayerAudit, Reason: ReasonHeartbeat, ObservedAt: now, Stats: c.snapshot(), Detail: c.uncountedLoss()}) {
			c.lastHeartbeat = now
		}
	}
}

func (c *Collector) flushLocked(now time.Time, emit func(Event) bool) {
	kept := c.pending[:0]
	for _, e := range c.pending {
		if !emit(e) {
			kept = append(kept, e)
		}
	}
	c.pending = kept

	for k, v := range c.agg.drain() {
		e := k.event(v)
		c.attributeRule(&e)
		if !emit(e) {
			c.agg.merge(k, *v)
		}
	}

	cur := c.snapshot()
	delta := Stats{
		LostKernel:      cur.LostKernel - c.reported.LostKernel,
		LostUndecodable: cur.LostUndecodable - c.reported.LostUndecodable,
	}
	if delta.LostKernel == 0 && delta.LostUndecodable == 0 {
		c.reportedAt = now
		return
	}
	gap := Event{Layer: LayerAudit, Reason: ReasonGap, ObservedAt: now, WindowStart: c.reportedAt, WindowEnd: now, Stats: &delta}
	if emit(gap) {
		c.reported, c.reportedAt = *cur, now
	}
}

// Started records the audit coverage; detail explains a layer that is
// missing.
func (c *Collector) Started(coverage []string, detail string) {
	c.lifecycle(Event{Layer: LayerAudit, Reason: ReasonStarted, ObservedAt: c.now(), Coverage: coverage, Detail: detail})
}

// Degraded records that a layer stopped while running.
func (c *Collector) Degraded(coverage []string, detail string) {
	c.lifecycle(Event{Layer: LayerAudit, Reason: ReasonDegraded, ObservedAt: c.now(), Coverage: coverage, Detail: detail})
}

func (c *Collector) lifecycle(e Event) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.out.TryEmit(e) {
		c.pending = append(c.pending, e)
	}
}

// Close writes pending aggregates, the last gap report and a stopped event
// with the final Stats, waiting at most timeout for a slow writer.
func (c *Collector) Close(timeout time.Duration) {
	c.closeOnce.Do(func() {
		deadline := time.Now().Add(timeout)
		if c.l4Cancel != nil {
			c.l4Cancel()
		}
		close(c.stop)
		if c.done != nil {
			<-c.done
		}
		if c.l4Done != nil {
			timer := time.NewTimer(time.Until(deadline))
			defer timer.Stop()
			select {
			case <-c.l4Done:
			case <-timer.C:
				// Do not claim final totals while a producer can still write.
				// A missing stopped event declares the incomplete shutdown.
				if c.sink != nil {
					c.sink.Close(deadline)
				}
				return
			}
		}
		emit := c.out.TryEmit
		if c.sink != nil {
			emit = func(e Event) bool { return c.sink.emitBefore(e, deadline) }
		}
		now := c.now()
		c.mu.Lock()
		c.flushLocked(now, emit)
		emit(Event{Layer: LayerAudit, Reason: ReasonStopped, ObservedAt: now, Stats: c.snapshot(), Detail: c.uncountedLoss()})
		c.mu.Unlock()
		if c.sink != nil {
			c.sink.Close(deadline)
		}
	})
}

// Stats returns the running totals.
func (c *Collector) Stats() Stats {
	return *c.snapshot()
}

func (c *Collector) snapshot() *Stats {
	return &Stats{
		Detailed:        c.detailed.Load(),
		Aggregated:      c.aggregated.Load(),
		Deduplicated:    c.deduplicated.Load(),
		LostKernel:      c.lostKernel.Load(),
		LostUndecodable: c.lostUndecodable.Load(),
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
		c.attributeRule(&e)
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
	// Answers are the A/AAAA addresses returned to the client; TTL is their
	// smallest TTL.
	Answers []netip.Addr
	TTL     time.Duration
}

// RecordDNS emits the DNS event and, while L4 collection is active, remembers
// the answered addresses for attribution of the connections that follow.
func (c *Collector) RecordDNS(r DNSRecord) {
	if r.Decision == DecisionAllow && c.l4Active.Load() {
		c.domains.observe(r.Domain, r.Answers, r.TTL)
	}
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

// uncountedLoss explains an overrun no later copy has counted yet: the
// kernel numbers copies, but loss after the last delivered one only shows
// once the next one arrives.
func (c *Collector) uncountedLoss() string {
	if c.l4Backlog.Load() {
		return "nflog stopped with unread copies: final totals exclude the remaining receive backlog and any trailing loss"
	}
	if c.overrunPending.Load() {
		return "nflog overrun after the last delivered copy: lost_kernel excludes it until the next connection"
	}
	return ""
}

func (c *Collector) markOverrun() {
	c.overrunPending.Store(true)
}

// observeSeq accounts for copies the kernel numbered but could not deliver
// (receive-buffer overruns). Sequence numbers start at 0 per NFLOG instance
// and increase by one per copy, so any jump is an exact loss count.
func (c *Collector) observeSeq(seq uint32) {
	// Unsigned wraparound keeps the arithmetic right across 2^32; a "gap"
	// in the upper half would be a reordering, which netlink does not do.
	if gap := seq - c.nextSeq; gap != 0 && gap < 1<<31 {
		c.lostKernel.Add(uint64(gap))
		telemetry.RecordAuditLost(telemetry.AuditLostKernel, int64(gap))
	}
	c.nextSeq = seq + 1
	c.overrunPending.Store(false)
}

// handleNFLog processes one packet copied by an audit rule. Packets that do
// not carry an audit prefix belong to some other NFLOG user and are ignored.
func (c *Collector) handleNFLog(prefix string, payload []byte) {
	decision, reason, ok := parseNFLogPrefix(prefix)
	if !ok {
		return
	}
	f, ok := decodeFlow(payload)
	if !ok {
		c.lostUndecodable.Add(1)
		telemetry.RecordAuditLost(telemetry.AuditLostUndecodable, 1)
		return
	}
	now := c.now()
	if c.duplicate(f, now) {
		c.deduplicated.Add(1)
		return
	}
	e := Event{
		Layer:           LayerL4,
		Decision:        decision,
		Reason:          reason,
		ObservedAt:      now,
		Protocol:        f.protocol(),
		DestinationIP:   f.dst,
		DestinationPort: f.dport,
	}
	e.Domain, e.DNSSeen = c.domains.lookup(f.dst)
	c.emit(e, nil)
}

func (c *Collector) duplicate(f flow, now time.Time) bool {
	if until, ok := c.flows[f]; ok && now.Before(until) {
		return true
	}
	if len(c.flows) >= maxTrackedFlows {
		for k, until := range c.flows {
			if !now.Before(until) {
				delete(c.flows, k)
			}
		}
		// Still full: forgetting every window only risks a repeated event.
		if len(c.flows) >= maxTrackedFlows {
			clear(c.flows)
		}
	}
	c.flows[f] = now.Add(flowDedupWindow)
	return false
}

// attributeRule names the policy rule behind an ip_rule or port_rule verdict.
// It reads the policy at event time, so a policy changed between the verdict
// and this lookup can leave the rule empty or name the newer rule.
func (c *Collector) attributeRule(e *Event) {
	if c.policy == nil || e.Layer != LayerL4 || !e.DestinationIP.IsValid() {
		return
	}
	if e.Reason != ReasonIPRule && (e.Reason != ReasonPortRule || e.Protocol != "tcp") {
		return
	}
	p, platformRules := c.policy.EffectivePolicy()
	action := policy.ActionAllow
	if e.Decision == DecisionDeny {
		action = policy.ActionDeny
	}
	var idx int
	var ok bool
	switch e.Reason {
	case ReasonIPRule:
		idx, ok = p.MatchIPRule(action, e.DestinationIP)
	case ReasonPortRule:
		if e.Protocol == "tcp" {
			idx, ok = p.MatchPortRule(action, e.DestinationIP, int(e.DestinationPort))
		}
	}
	if !ok {
		return
	}
	e.Rule = describeRule(p.Egress[idx])
	e.RuleSource = "user"
	if idx < platformRules {
		e.RuleSource = "platform"
	}
}

func describeRule(r policy.EgressRule) string {
	// PortRanges is set only by the platform reachable-ports floor, whose
	// complement would be an unreadable port list.
	if len(r.PortRanges) > 0 {
		return "reachable.ports.cap"
	}
	if len(r.Ports) == 0 {
		return r.Target
	}
	ports := make([]string, len(r.Ports))
	for i, p := range r.Ports {
		ports[i] = strconv.Itoa(p)
	}
	if r.Target == "" {
		return "ports " + strings.Join(ports, ",")
	}
	return r.Target + " ports " + strings.Join(ports, ",")
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
