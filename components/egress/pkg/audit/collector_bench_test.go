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
)

type discardEmitter struct{}

func (discardEmitter) TryEmit(Event) bool { return true }

// Exercise the synchronous DNS hook after detail admission is exhausted. The
// aggregate still retains the domain/count, but does not need answer strings.
func BenchmarkRecordDNSAggregated(b *testing.B) {
	benchmarkRecordDNSAggregated(b, false)
}

func BenchmarkRecordDNSAggregatedConnectionAudit(b *testing.B) {
	benchmarkRecordDNSAggregated(b, true)
}

func benchmarkRecordDNSAggregated(b *testing.B, l4 bool) {
	now := time.Now()
	c := newCollector(discardEmitter{}, nil, func() time.Time { return now })
	c.l4Active.Store(l4)
	c.budget = tokenBucket{rate: 1}
	r := DNSRecord{Domain: "many.example", Decision: DecisionAllow, Reason: ReasonPolicy, TTL: time.Minute}
	for i := 0; i < maxEventAnswerIPs; i++ {
		r.Answers = append(r.Answers, netip.AddrFrom4([4]byte{198, 51, 100, byte(i)}))
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c.RecordDNS(r)
	}
}
