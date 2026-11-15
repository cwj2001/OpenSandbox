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

type fakeClock struct{ t time.Time }

func (c *fakeClock) now() time.Time { return c.t }

func newTestCollector(t *testing.T) (*Collector, *eventRecorder, *fakeClock) {
	t.Helper()
	sink := &eventRecorder{}
	clock := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	c := newCollector(sink, clock.now)
	return c, sink, clock
}

func TestDNSAnswersCappedInEvent(t *testing.T) {
	c, sink, _ := newTestCollector(t)
	var answers []netip.Addr
	for i := 0; i < maxEventAnswerIPs+5; i++ {
		answers = append(answers, netip.AddrFrom4([4]byte{198, 51, 100, byte(i)}))
	}
	c.RecordDNS(DNSRecord{Domain: "many.example", Decision: DecisionAllow, Reason: ReasonPolicy, Answers: answers})
	require.Len(t, sink.events[0].ResolvedIPs, maxEventAnswerIPs)
	require.Equal(t, answers[0].String(), sink.events[0].ResolvedIPs[0])
	require.Equal(t, answers[maxEventAnswerIPs-1].String(), sink.events[0].ResolvedIPs[maxEventAnswerIPs-1])
}

func finishTestCollector(c *Collector, timeout time.Duration) {
	c.closeOnce.Do(func() {
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		c.finish(ctx, c.out.TryEmit)
	})
}
