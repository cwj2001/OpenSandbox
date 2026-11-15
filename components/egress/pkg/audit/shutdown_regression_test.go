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
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

type selectiveRecorder struct {
	mu     sync.Mutex
	refuse func(Event) bool
	events []Event
}

func (r *selectiveRecorder) TryEmit(e Event) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.refuse(e) {
		return false
	}
	r.events = append(r.events, e)
	return true
}

func (r *selectiveRecorder) snapshot() []Event {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]Event(nil), r.events...)
}

func TestCloseRefusedFinalOutputNeverClaimsStopped(t *testing.T) {
	for _, kind := range []string{"aggregate", "lifecycle"} {
		t.Run(kind, func(t *testing.T) {
			out := &selectiveRecorder{refuse: func(e Event) bool {
				return kind == "aggregate" && e.Count > 0 || kind == "lifecycle" && e.Reason == ReasonStarted
			}}
			c := newCollector(out, time.Now)
			switch kind {
			case "aggregate":
				c.agg.add(Event{Layer: LayerDNS, Decision: DecisionAllow, Reason: ReasonPolicy, ObservedAt: time.Now()})
			case "lifecycle":
				c.Started()
			}
			finishTestCollector(c, time.Second)
			require.Nil(t, lastOf(out.snapshot(), ReasonStopped), "refused final output must leave shutdown incomplete")
		})
	}
}

func TestAsyncSinkExpiredDeadlineCannotQueueStopped(t *testing.T) {
	// An isolated empty queue is always writable, even though the deadline is expired.
	s := &AsyncSink{queue: make(chan Event, 64)}
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	for range 64 {
		require.False(t, s.emitBefore(Event{Layer: LayerAudit, Reason: ReasonStopped}, ctx))
	}
	require.Empty(t, s.queue)
}

// When Err is checked before admission, hold that mutex and return the value
// captured before cancellation. Under admission, Err instead reads cancellation
// after the gate opens. This distinguishes the stale precheck without sleeps.
type admissionCheckContext struct {
	context.Context
	admission *sync.Mutex
	checked   chan error
	resume    chan struct{}
}

func (c admissionCheckContext) Err() error {
	if c.admission.TryLock() {
		err := c.Context.Err()
		c.checked <- err
		<-c.resume
		c.admission.Unlock()
		return err
	}
	c.checked <- c.Context.Err()
	<-c.resume
	return c.Context.Err()
}

func TestAsyncSinkCancellationDuringAdmissionCannotQueueStopped(t *testing.T) {
	s := &AsyncSink{queue: make(chan Event, 1)}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	checked, resume := make(chan error), make(chan struct{})
	result := make(chan bool, 1)
	go func() {
		result <- s.emitBefore(Event{Layer: LayerAudit, Reason: ReasonStopped},
			admissionCheckContext{ctx, &s.mu, checked, resume})
	}()
	select {
	case err := <-checked:
		require.NoError(t, err, "the context must be live at the initial check")
	case <-time.After(time.Second):
		t.Fatal("emitter did not reach the admission gate")
	}
	cancel() // The admission mutex remains held until resume is released.
	close(resume)
	select {
	case accepted := <-result:
		require.False(t, accepted, "cancellation during admission must reject stopped")
	case <-time.After(time.Second):
		t.Fatal("emitter did not leave the admission gate")
	}
	require.Empty(t, s.queue)
}

// Pause the wait-select setup so cancellation and newly freed room are both
// ready before it continues. No sleep or scheduling assumption is involved.
type gatedDoneContext struct {
	context.Context
	waiting chan struct{}
	proceed chan struct{}
}

func (c gatedDoneContext) Done() <-chan struct{} {
	close(c.waiting)
	<-c.proceed
	return c.Context.Done()
}

func TestAsyncSinkExpiredWaitCannotQueueStopped(t *testing.T) {
	for range 16 {
		ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(time.Second))
		waiting, proceed := make(chan struct{}), make(chan struct{})
		s := &AsyncSink{queue: make(chan Event, 1)}
		s.queue <- Event{Layer: LayerDNS}
		result := make(chan bool, 1)
		go func() {
			result <- s.emitBefore(Event{Layer: LayerAudit, Reason: ReasonStopped}, gatedDoneContext{ctx, waiting, proceed})
		}()
		select {
		case <-waiting:
		case <-time.After(time.Second):
			t.Fatal("emitter did not begin waiting for room")
		}
		cancel()
		<-s.queue
		s.mu.Lock()
		s.notifyChanged()
		s.mu.Unlock()
		close(proceed)
		select {
		case accepted := <-result:
			require.False(t, accepted, "cancellation must win even when the queue became writable")
		case <-time.After(time.Second):
			t.Fatal("emitter ignored cancellation")
		}
		require.Empty(t, s.queue)
	}
}

func TestAsyncSinkClosedRejectsFurtherAdmission(t *testing.T) {
	inner := &blockingSink{release: make(chan struct{})}
	close(inner.release)
	s := NewAsyncSink(inner, 1)
	s.Close(time.Now().Add(time.Second))
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(time.Second))
	defer cancel()
	require.False(t, s.TryEmit(Event{Layer: LayerDNS}))
	require.False(t, s.emitBefore(Event{Layer: LayerAudit, Reason: ReasonStopped}, ctx))
	require.Empty(t, s.queue, "a stopped writer cannot accept more queued output")
	require.Empty(t, inner.snapshot())
}

func TestCollectorCloseWithActuallyFullOutputLeavesStoppedAbsent(t *testing.T) {
	inner := &blockingSink{release: make(chan struct{})}
	output := NewAsyncSink(inner, 1)
	c := NewCollector(output)
	c.Started()
	// Saturation is independent of whether the writer has dequeued started.
	for i := 0; i < 4; i++ {
		c.RecordDNS(DNSRecord{Domain: "queued.example", Decision: DecisionAllow, Reason: ReasonPolicy})
	}
	c.Close(20 * time.Millisecond)
	close(inner.release)
	output.Close(time.Now().Add(time.Second))
	if lastOf(inner.snapshot(), ReasonStopped) != nil {
		t.Fatal("deadline-refused final aggregate claimed stopped")
	}
	if c.aggregated.Load() == 0 {
		t.Fatal("full audit lane lost refusal aggregation")
	}
}
