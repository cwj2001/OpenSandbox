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
	"crypto/rand"
	"encoding/hex"
	"sync"
	"time"

	"github.com/alibaba/opensandbox/internal/safego"
)

// DefaultQueueSize bounds the events buffered ahead of a slow writer.
const DefaultQueueSize = 4096

// AsyncSink decouples producers — DNS handlers, which emit before writing
// their reply, and the NFLOG reader — from the writer. TryEmit never blocks;
// the collector folds a refused event into an aggregate instead of losing it.
// The single writer goroutine stamps BootID and a contiguous Seq in output
// order.
type AsyncSink struct {
	inner     Sink
	bootID    string
	queue     chan Event
	stop      chan struct{}
	done      chan struct{}
	closeOnce sync.Once
}

func NewAsyncSink(inner Sink, size int) *AsyncSink {
	s := &AsyncSink{
		inner:  inner,
		bootID: newBootID(),
		queue:  make(chan Event, size),
		stop:   make(chan struct{}),
		done:   make(chan struct{}),
	}
	safego.Go(s.run)
	return s
}

func newBootID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// TryEmit queues e and reports whether there was room.
func (s *AsyncSink) TryEmit(e Event) bool {
	select {
	case s.queue <- e:
		return true
	default:
		return false
	}
}

// emitBefore queues e, waiting until deadline for room. Only shutdown uses
// it, to land the final aggregates and the stopped event.
func (s *AsyncSink) emitBefore(e Event, deadline time.Time) bool {
	timer := time.NewTimer(time.Until(deadline))
	defer timer.Stop()
	select {
	case s.queue <- e:
		return true
	case <-timer.C:
		return false
	}
}

func (s *AsyncSink) run() {
	defer close(s.done)
	var seq uint64
	write := func(e Event) {
		seq++
		e.BootID, e.Seq = s.bootID, seq
		s.inner.Emit(e)
	}
	for {
		select {
		case e := <-s.queue:
			write(e)
		case <-s.stop:
			for {
				select {
				case e := <-s.queue:
					write(e)
				default:
					return
				}
			}
		}
	}
}

// Close writes what is queued, waiting until deadline for a slow writer.
func (s *AsyncSink) Close(deadline time.Time) {
	s.closeOnce.Do(func() { close(s.stop) })
	timer := time.NewTimer(time.Until(deadline))
	defer timer.Stop()
	select {
	case <-s.done:
	case <-timer.C:
	}
}
