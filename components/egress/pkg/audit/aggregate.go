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
	"sync"
	"time"
)

// maxAggregateKeys bounds one window. Past it, new keys fold into a coarser
// per-(layer, decision, reason) key: detail degrades, the count never does.
const maxAggregateKeys = 1024

type aggregateKey struct {
	layer, decision, reason string
	domain, protocol        string
	dst                     netip.Addr
	port                    uint16
	dnsSeen                 bool
}

type aggregateValue struct {
	count       uint64
	first, last time.Time
}

type aggregator struct {
	mu      sync.Mutex
	entries map[aggregateKey]*aggregateValue
}

func newAggregator() *aggregator {
	return &aggregator{entries: make(map[aggregateKey]*aggregateValue)}
}

func keyOf(e Event) aggregateKey {
	return aggregateKey{
		layer: e.Layer, decision: e.Decision, reason: e.Reason,
		domain: e.Domain, protocol: e.Protocol,
		dst: e.DestinationIP, port: e.DestinationPort, dnsSeen: e.DNSSeen,
	}
}

func (a *aggregator) add(e Event) {
	a.merge(keyOf(e), aggregateValue{count: 1, first: e.ObservedAt, last: e.ObservedAt})
}

func (a *aggregator) merge(k aggregateKey, v aggregateValue) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if _, ok := a.entries[k]; !ok && len(a.entries) >= maxAggregateKeys {
		k = aggregateKey{layer: k.layer, decision: k.decision, reason: k.reason}
	}
	cur, ok := a.entries[k]
	if !ok {
		vv := v
		a.entries[k] = &vv
		return
	}
	cur.count += v.count
	if v.first.Before(cur.first) {
		cur.first = v.first
	}
	if v.last.After(cur.last) {
		cur.last = v.last
	}
}

// drain hands over the current window and starts a new one.
func (a *aggregator) drain() map[aggregateKey]*aggregateValue {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := a.entries
	a.entries = make(map[aggregateKey]*aggregateValue)
	return out
}

func (k aggregateKey) event(v *aggregateValue) Event {
	return Event{
		Layer: k.layer, Decision: k.decision, Reason: k.reason,
		Domain: k.domain, Protocol: k.protocol,
		DestinationIP: k.dst, DestinationPort: k.port, DNSSeen: k.dnsSeen,
		ObservedAt: v.first, Count: v.count, WindowStart: v.first, WindowEnd: v.last,
	}
}
