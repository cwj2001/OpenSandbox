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
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"sync"
	"time"

	"github.com/alibaba/opensandbox/internal/logger"
	"github.com/alibaba/opensandbox/internal/safego"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

const (
	DefaultQueueSize = 4096
	ordinaryEntries  = 256
	ordinaryBytes    = 1 << 20
	ordinaryTimeout  = 100 * time.Millisecond
)

var errOutputClosed = errors.New("ordinary logger output closed")
var errOutputTimeout = errors.New("ordinary logger output flush timed out")

type ordinaryRecord struct {
	data       []byte
	diagnostic bool
}

// AsyncSink is the sole physical writer. Audit events and already-encoded
// ordinary records have independent bounds and admission lifetimes. Only audit
// events receive BootID/Seq; refused audit admission remains collector-owned.
type AsyncSink struct {
	inner                               Sink
	bootID                              string
	queue                               chan Event
	ordinary                            chan ordinaryRecord
	outputs                             *logger.Outputs
	stop, done, wake                    chan struct{}
	mu                                  sync.Mutex // admission/progress only; never destination I/O
	closed, ordinaryClosed              bool
	bytes                               int
	dropped, handledDrops               uint64
	auditAccepted, auditCompleted       uint64
	ordinaryAccepted, ordinaryCompleted uint64
	changed                             chan struct{} // allocated only while progress/admission has waiters
	result                              error
}

// NewAsyncSink owns inner (including io.Closer) until its actual worker exits,
// even when the caller's audit drain deadline expires.
func NewAsyncSink(inner Sink, size int) *AsyncSink {
	return newAsyncSink(inner, size, nil)
}

// NewOutputSink transfers physical ownership and opens the ordinary lane.
// CloseAudit drains audit only; Close ends both admissions and the worker.
func NewOutputSink(inner Sink, outputs *logger.Outputs, size int) *AsyncSink {
	return newAsyncSink(inner, size, outputs)
}

func newAsyncSink(inner Sink, size int, outputs *logger.Outputs) *AsyncSink {
	s := &AsyncSink{inner: inner, bootID: newBootID(), queue: make(chan Event, max(size, 1)),
		stop: make(chan struct{}), done: make(chan struct{}), wake: make(chan struct{}, 1), outputs: outputs}
	if outputs != nil {
		s.ordinary = make(chan ordinaryRecord, ordinaryEntries)
	}
	safego.Go(s.run)
	return s
}

func newBootID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func (s *AsyncSink) TryEmit(e Event) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.admit(e)
}

// admit runs under mu, including the closed check and channel send.
func (s *AsyncSink) admit(e Event) bool {
	if s.closed {
		return false
	}
	select {
	case s.queue <- e:
		s.auditAccepted++
		return true
	default:
		return false
	}
}

func (s *AsyncSink) emitBefore(e Event, ctx context.Context) bool {
	for {
		s.mu.Lock()
		if !beforeDeadline(ctx) || s.closed {
			s.mu.Unlock()
			return false
		}
		if s.admit(e) {
			s.mu.Unlock()
			return true
		}
		changed := s.progress()
		s.mu.Unlock()
		select {
		case <-changed:
		case <-ctx.Done():
			return false
		}
	}
}

func beforeDeadline(ctx context.Context) bool {
	deadline, ok := ctx.Deadline()
	return ctx.Err() == nil && (!ok || time.Now().Before(deadline))
}

// OrdinaryWriter receives bytes after zap has applied levels/sampling and
// encoded mutable fields. Admission never performs destination I/O.
func (s *AsyncSink) OrdinaryWriter(diagnostic bool) zapcore.WriteSyncer {
	return ordinaryWriter{s, diagnostic}
}

type ordinaryWriter struct {
	owner      *AsyncSink
	diagnostic bool
}

func (w ordinaryWriter) Write(p []byte) (int, error) {
	s := w.owner
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ordinaryClosed {
		return 0, errOutputClosed
	}
	if len(s.ordinary) == cap(s.ordinary) || len(p) > ordinaryBytes-s.bytes {
		s.dropped++
		select {
		case s.wake <- struct{}{}:
		default:
		}
		return len(p), nil
	}
	data := make([]byte, len(p))
	copy(data, p)
	s.bytes += len(data)
	s.ordinaryAccepted++
	s.ordinary <- ordinaryRecord{data: data, diagnostic: w.diagnostic}
	return len(p), nil
}

// Sync snapshots preceding ordinary work, not queue space or future audit
// traffic. Physical backends have no durability Sync; completion is the flush.
func (w ordinaryWriter) Sync() error {
	s := w.owner
	s.mu.Lock()
	target, drops := s.ordinaryAccepted, s.dropped
	s.mu.Unlock()
	return s.wait(time.Now().Add(ordinaryTimeout), &s.ordinaryCompleted, target, drops)
}

// progress and notifyChanged run under mu. One broadcast wakes all current
// waiters without allocating a command or reserving a slot in either lane.
func (s *AsyncSink) progress() <-chan struct{} {
	if s.changed == nil {
		s.changed = make(chan struct{})
	}
	return s.changed
}

func (s *AsyncSink) notifyChanged() {
	if s.changed != nil {
		close(s.changed)
		s.changed = nil
	}
}

func (s *AsyncSink) wait(deadline time.Time, completed *uint64, target, drops uint64) error {
	timer := time.NewTimer(time.Until(deadline))
	defer timer.Stop()
	for {
		s.mu.Lock()
		if *completed >= target && s.handledDrops >= drops {
			err := s.result
			s.mu.Unlock()
			return err
		}
		changed := s.progress()
		s.mu.Unlock()
		select {
		case <-changed:
		case <-timer.C:
			return errOutputTimeout
		}
	}
}

// CloseAudit ends audit admission and waits only for accepted audit work.
// Ordinary diagnostics can continue through telemetry shutdown.
func (s *AsyncSink) CloseAudit(deadline time.Time) {
	s.mu.Lock()
	s.closed = true
	target := s.auditAccepted
	s.notifyChanged()
	s.mu.Unlock()
	_ = s.wait(deadline, &s.auditCompleted, target, 0)
}

// Close ends both lanes, including early setup failure before audit starts.
// A timed-out caller never owns physical Close: the worker drains both lanes.
func (s *AsyncSink) Close(deadline time.Time) error {
	timer := time.NewTimer(time.Until(deadline))
	defer timer.Stop()
	s.mu.Lock()
	s.closed = true
	if !s.ordinaryClosed {
		s.ordinaryClosed = true
		close(s.stop)
	}
	s.notifyChanged()
	s.mu.Unlock()
	select {
	case <-s.done:
		return s.result
	case <-timer.C:
		return errOutputTimeout
	}
}

func (s *AsyncSink) run() {
	defer close(s.done)
	defer func() {
		if s.outputs != nil {
			s.remember(s.outputs.Close())
		} else if closer, ok := s.inner.(io.Closer); ok {
			s.remember(closer.Close())
		}
	}()
	var encoder zapcore.Encoder
	if s.outputs != nil {
		cfg := zap.NewProductionEncoderConfig()
		cfg.EncodeTime = zapcore.ISO8601TimeEncoder
		encoder = zapcore.NewJSONEncoder(cfg)
	}
	stop := s.stop
	var seq, reported uint64
	for {
		if s.outputs != nil {
			s.reportGap(encoder, &reported)
		}
		if stop == nil && len(s.queue) == 0 && len(s.ordinary) == 0 {
			return
		}
		select {
		case e := <-s.queue:
			s.mu.Lock()
			s.notifyChanged()
			s.mu.Unlock()
			seq++
			e.BootID, e.Seq = s.bootID, seq
			s.inner.Emit(e)
			s.mu.Lock()
			s.auditCompleted++
			s.notifyChanged()
			s.mu.Unlock()
		case r := <-s.ordinary:
			s.mu.Lock()
			s.bytes -= len(r.data)
			s.mu.Unlock()
			out := s.outputs.Out
			if r.diagnostic {
				out = s.outputs.Errors
			}
			if err := writeRecord(out, r.data); err != nil {
				s.remember(err)
				if !r.diagnostic {
					s.reportFailure(encoder, err)
				}
				s.mu.Lock()
				s.dropped++
				s.mu.Unlock()
			}
			s.mu.Lock()
			s.ordinaryCompleted++
			s.notifyChanged()
			s.mu.Unlock()
		case <-s.wake:
		case <-stop:
			stop = nil
		}
	}
}

func (s *AsyncSink) reportGap(encoder zapcore.Encoder, reported *uint64) {
	s.mu.Lock()
	total := s.dropped
	s.mu.Unlock()
	if total <= *reported {
		return
	}
	err := s.diagnostic(encoder, s.outputs.Out, zapcore.WarnLevel, "ordinary_log_gap", []zapcore.Field{
		zap.Uint64("dropped", total-*reported), zap.Uint64("dropped_total", total)})
	if err == nil {
		*reported = total
	} else {
		s.reportFailure(encoder, err)
	}
	s.remember(err)
	s.mu.Lock()
	s.handledDrops = total
	s.notifyChanged()
	s.mu.Unlock()
}

func writeRecord(out zapcore.WriteSyncer, p []byte) error {
	n, err := out.Write(p)
	if err == nil && n != len(p) {
		err = io.ErrShortWrite
	}
	return err
}

func (s *AsyncSink) remember(err error) {
	if err == nil {
		return
	}
	s.mu.Lock()
	if s.result == nil {
		s.result = err
	}
	s.mu.Unlock()
}

func (s *AsyncSink) diagnostic(encoder zapcore.Encoder, out zapcore.WriteSyncer, level zapcore.Level, msg string, fields []zapcore.Field) error {
	buf, err := encoder.EncodeEntry(zapcore.Entry{Level: level, Time: time.Now(), LoggerName: "opensandbox.logger", Message: msg}, fields)
	if err != nil {
		return err
	}
	defer buf.Free()
	return writeRecord(out, buf.Bytes())
}

// Direct, nonrecursive reporting remains worker-owned even when error sinks fail.
func (s *AsyncSink) reportFailure(encoder zapcore.Encoder, failure error) {
	s.remember(s.diagnostic(encoder, s.outputs.Errors, zapcore.ErrorLevel, "ordinary_log_output_error", []zapcore.Field{zap.Error(failure)}))
}
