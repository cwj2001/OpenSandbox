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
	"io"
	"testing"
	"time"
)

// BenchmarkLogSink measures JSON encoding and per-event allocations, not
// downstream writer IO, queue admission, or end-to-end sidecar overhead.
func BenchmarkLogSink(b *testing.B) {
	at := time.Date(2026, 1, 2, 3, 4, 5, 123456789, time.UTC)
	cases := []struct {
		name  string
		event Event
	}{
		{"DNSAllow", Event{
			Layer: LayerDNS, Decision: DecisionAllow, Reason: ReasonPolicy,
			BootID: "synthetic-boot", Seq: 9007199254740993, ObservedAt: at,
			Domain: "allowed.example", QueryType: "A", ResponseCode: "NOERROR",
			ResolvedIPs: []string{"192.0.2.1", "2001:db8::1"},
		}},
	}
	for _, tc := range cases {
		b.Run(tc.name, func(b *testing.B) {
			sink := newJSONLogSink(io.Discard)
			sink.Emit(tc.event)
			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				sink.Emit(tc.event)
			}
		})
	}
}
