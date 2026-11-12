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
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// blockingSink stands in for a stalled log pipeline until released.
type blockingSink struct {
	release chan struct{}
	mu      sync.Mutex
	events  []Event
}

func (s *blockingSink) Emit(e Event) {
	<-s.release
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = append(s.events, e)
}

func (s *blockingSink) snapshot() []Event {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Event(nil), s.events...)
}

func TestAsyncSinkTryEmitNeverBlocks(t *testing.T) {
	inner := &blockingSink{release: make(chan struct{})}
	sink := NewAsyncSink(inner, 4)
	accepted := 0
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 100; i++ {
			if sink.TryEmit(Event{Layer: LayerDNS}) {
				accepted++
			}
		}
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("TryEmit blocked behind a stalled writer")
	}
	require.LessOrEqual(t, accepted, 5, "queue capacity plus the event the writer holds")
	close(inner.release)
	sink.Close(time.Now().Add(2 * time.Second))
	require.Len(t, inner.snapshot(), accepted, "everything accepted is written")
}

func TestAsyncSinkStampsContiguousSequence(t *testing.T) {
	inner := &blockingSink{release: make(chan struct{})}
	close(inner.release)
	sink := NewAsyncSink(inner, 64)
	for i := 0; i < 50; i++ {
		require.True(t, sink.TryEmit(Event{Layer: LayerL4}))
	}
	sink.Close(time.Now().Add(2 * time.Second))
	events := inner.snapshot()
	require.Len(t, events, 50)
	require.Len(t, events[0].BootID, 32)
	for i, e := range events {
		require.Equal(t, uint64(i+1), e.Seq)
		require.Equal(t, events[0].BootID, e.BootID)
	}
	require.NotEqual(t, events[0].BootID, NewAsyncSink(inner, 1).bootID, "each sidecar run gets its own boot id")
}

func TestAsyncSinkCloseIsBounded(t *testing.T) {
	inner := &blockingSink{release: make(chan struct{})}
	sink := NewAsyncSink(inner, 8)
	sink.TryEmit(Event{})
	start := time.Now()
	sink.Close(time.Now().Add(100 * time.Millisecond))
	require.Less(t, time.Since(start), time.Second, "a stalled writer must not hang shutdown")
	close(inner.release)
}
