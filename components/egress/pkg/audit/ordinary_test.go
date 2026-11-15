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
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alibaba/opensandbox/internal/logger"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

type gatedLogOutput struct {
	mu      sync.Mutex
	data    bytes.Buffer
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (w *gatedLogOutput) block() {
	w.once.Do(func() { close(w.entered); <-w.release })
}
func (w *gatedLogOutput) Write(p []byte) (int, error) {
	w.block()
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.data.Write(p)
}
func (w *gatedLogOutput) Sync() error {
	return nil
}
func (w *gatedLogOutput) records(t *testing.T) []map[string]any {
	t.Helper()
	w.mu.Lock()
	defer w.mu.Unlock()
	var records []map[string]any
	for _, line := range bytes.Split(bytes.TrimSpace(w.data.Bytes()), []byte("\n")) {
		if len(line) == 0 {
			continue
		}
		var record map[string]any
		if err := json.Unmarshal(line, &record); err != nil {
			t.Fatal(err)
		}
		records = append(records, record)
	}
	return records
}
func isolatedLog(t *testing.T) (logger.Logger, *AsyncSink, *gatedLogOutput) {
	t.Helper()
	out := &gatedLogOutput{entered: make(chan struct{}), release: make(chan struct{})}
	q := outputActor(out, out)
	w := ordinaryWriter{owner: q}
	l := logger.NewWithWriter(logger.Config{Level: "debug"}, w, ordinaryWriter{owner: q, diagnostic: true})
	t.Cleanup(func() {
		select {
		case <-out.release:
		default:
			close(out.release)
		}
		_ = q.Close(time.Now().Add(ordinaryTimeout))
		select {
		case <-q.done:
		case <-time.After(time.Second):
			t.Error("output worker did not exit")
		}
	})
	return l, q, out
}
func awaitLogWriter(t *testing.T, out *gatedLogOutput) {
	t.Helper()
	select {
	case <-out.entered:
	case <-time.After(time.Second):
		t.Fatal("worker did not reach destination")
	}
}
func requireLogSync(t *testing.T, l logger.Logger) {
	t.Helper()
	if err := l.Sync(); err != nil {
		t.Fatal(err)
	}
}

func TestBoundedOutputOverflowReportsGap(t *testing.T) {
	l, q, out := isolatedLog(t)
	l.Warnf("in flight")
	awaitLogWriter(t, out)
	for i := range ordinaryEntries {
		l.Warnf("queued %d", i)
	}
	l.Warnf("lost one")
	l.Errorf("lost two")
	close(out.release)
	requireLogSync(t, l)
	var kept, gaps int
	for _, r := range out.records(t) {
		if r["msg"] == "ordinary_log_gap" {
			gaps++
			if r["dropped"] != float64(2) || r["dropped_total"] != float64(2) || r["level"] != "warn" {
				t.Fatalf("incorrect gap: %v", r)
			}
		} else {
			kept++
		}
	}
	if kept != ordinaryEntries+1 || gaps != 1 {
		t.Fatalf("kept=%d gaps=%d", kept, gaps)
	}
	_, _ = (ordinaryWriter{owner: q}).Write(make([]byte, ordinaryBytes+1))
	requireLogSync(t, l)
	records := out.records(t)
	last := records[len(records)-1]
	if last["msg"] != "ordinary_log_gap" || last["dropped"] != float64(1) || last["dropped_total"] != float64(3) {
		t.Fatalf("cumulative gap=%v", last)
	}
	if err := q.Close(time.Now().Add(ordinaryTimeout)); err != nil {
		t.Fatal(err)
	}
	if n, err := (ordinaryWriter{owner: q}).Write([]byte("after close")); n != 0 || !errors.Is(err, errOutputClosed) {
		t.Fatalf("post-close write accepted: %d %v", n, err)
	}
}

func TestBoundedOutputByteBudgetAndOwnedCopies(t *testing.T) {
	l, q, out := isolatedLog(t)
	l.Warnf("in flight")
	awaitLogWriter(t, out)
	w := ordinaryWriter{owner: q}
	data := []byte(`{"msg":"` + strings.Repeat("x", ordinaryBytes/4-11) + `"}` + "\n")
	if len(data) != ordinaryBytes/4 {
		t.Fatalf("fixture bytes=%d", len(data))
	}
	for range 4 {
		if _, err := w.Write(data); err != nil {
			t.Fatal(err)
		}
	}
	// Neither the queue admission nor oversized rejection may retain the caller's buffer.
	for i := range data {
		data[i] = '!'
	}
	oversize := make([]byte, ordinaryBytes+1)
	if got := testing.AllocsPerRun(10, func() { _, _ = w.Write(oversize) }); got != 0 {
		t.Fatalf("oversized rejection allocated %v", got)
	}
	_, _ = w.Write([]byte("{\"msg\":\"over byte budget\"}\n"))
	close(out.release)
	requireLogSync(t, l)
	var gaps, copied int
	for _, r := range out.records(t) {
		if r["msg"] == "ordinary_log_gap" {
			gaps++
			if r["dropped_total"] != float64(12) {
				t.Fatalf("gap=%v", r)
			}
		} else if r["msg"] != "in flight" {
			copied++
		}
	}
	if copied != 4 || gaps != 1 {
		t.Fatalf("copied=%d gaps=%d", copied, gaps)
	}
}

func TestBoundedOutputOneCopyAndEagerFieldEncoding(t *testing.T) {
	l, q, out := isolatedLog(t)
	l.Warnf("in flight")
	awaitLogWriter(t, out)
	w := ordinaryWriter{owner: q}
	p := []byte("{\"msg\":\"owned\"}\n")
	if got := testing.AllocsPerRun(10, func() { _, _ = w.Write(p) }); got != 1 {
		t.Fatalf("accepted write allocations=%v", got)
	}
	fields := map[string]string{"value": "before"}
	child := l.With(logger.Field{Key: "fields", Value: fields}).Named("child")
	fields["value"] = "after With"
	child.Warnf("encoded %s", "before")
	fields["value"] = "after log"
	mutable := map[string]string{"value": "at call"}
	sugar, _ := logger.AsZapSugared(child)
	sugar.Warnw("structured", "mutable", mutable)
	mutable["value"] = "after call"
	close(out.release)
	requireLogSync(t, l)
	var derived, structured bool
	for _, r := range out.records(t) {
		if r["msg"] == "encoded before" {
			if r["logger"] != "child" || r["fields"].(map[string]any)["value"] != "before" {
				t.Fatalf("mutated fields: %v", r)
			}
			derived = true
		}
		if r["msg"] == "structured" {
			if r["mutable"].(map[string]any)["value"] != "at call" {
				t.Fatalf("mutated call fields: %v", r)
			}
			structured = true
		}
	}
	if !derived || !structured {
		t.Fatal("derived/structured log not written")
	}
}

func TestBoundedConstructorPreservesLevelsFieldsAndSampling(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ordinary.json")
	l, q, err := outputLog(logger.Config{Level: "warn", OutputPaths: []string{path}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = q.Close(time.Now().Add(ordinaryTimeout)) })
	child := l.With(logger.Field{Key: "sandbox_id", Value: "test"}).Named("parent").Named("child")
	child.Infof("filtered")
	// Flush small batches so this measures sampling, not queue overflow.
	for i := range 1000 {
		child.Warnf("same message")
		if i%50 == 49 {
			requireLogSync(t, l)
		}
	}
	requireLogSync(t, l)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if count := bytes.Count(data, []byte("\n")); count < 100 || count >= 1000 {
		t.Fatalf("default sampling count=%d", count)
	}
	for _, line := range bytes.Split(bytes.TrimSpace(data), []byte("\n")) {
		var r map[string]any
		if err := json.Unmarshal(line, &r); err != nil {
			t.Fatal(err)
		}
		if r["level"] != "warn" || r["logger"] != "parent.child" || r["sandbox_id"] != "test" || r["msg"] != "same message" {
			t.Fatalf("record=%v", r)
		}
	}
}

func TestRawAuditLoggerRemainsUnsampled(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.json")
	outputs, err := logger.OpenOutputs(logger.Config{Level: "error", OutputPaths: []string{path}})
	if err != nil {
		t.Fatal(err)
	}
	defer outputs.Close()
	for range 1000 {
		outputs.Audit.Info("same audit message")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if count := bytes.Count(data, []byte("\n")); count != 1000 {
		t.Fatalf("raw audit logger sampled %d of 1000 entries", count)
	}
	for _, line := range bytes.Split(bytes.TrimSpace(data), []byte("\n")) {
		var r map[string]any
		if err := json.Unmarshal(line, &r); err != nil {
			t.Fatal(err)
		}
		if r["level"] != "info" || r["msg"] != "same audit message" {
			t.Fatalf("record=%v", r)
		}
	}
}

func TestBoundedSyncCloseAndFatalHaveBoundedDrains(t *testing.T) {
	t.Run("blocked write", func(t *testing.T) {
		l, q, out := isolatedLog(t)
		l.Warnf("in flight")
		awaitLogWriter(t, out)
		start := time.Now()
		if err := l.Sync(); !errors.Is(err, errOutputTimeout) {
			t.Fatalf("Sync=%v", err)
		}
		if elapsed := time.Since(start); elapsed > 500*time.Millisecond {
			t.Fatalf("Sync waited %v", elapsed)
		}
		start = time.Now()
		if err := q.Close(time.Now().Add(ordinaryTimeout)); !errors.Is(err, errOutputTimeout) {
			t.Fatalf("Close=%v", err)
		}
		if elapsed := time.Since(start); elapsed > 500*time.Millisecond {
			t.Fatalf("Close waited %v", elapsed)
		}
	})
	t.Run("full queue", func(t *testing.T) {
		l, q, out := isolatedLog(t)
		l.Warnf("in flight")
		awaitLogWriter(t, out)
		for i := range ordinaryEntries {
			l.Warnf("queued %d", i)
		}
		if err := l.Sync(); !errors.Is(err, errOutputTimeout) {
			t.Fatalf("full queue Sync=%v", err)
		}
		if err := q.Close(time.Now().Add(ordinaryTimeout)); !errors.Is(err, errOutputTimeout) {
			t.Fatalf("full queue Close=%v", err)
		}
	})
	t.Run("fatal", func(t *testing.T) {
		l, _, out := isolatedLog(t)
		l.Warnf("in flight")
		awaitLogWriter(t, out)
		sugar, _ := logger.AsZapSugared(l)
		fatal := sugar.Desugar().WithOptions(zap.WithFatalHook(zapcore.WriteThenGoexit))
		done := make(chan struct{})
		go func() { defer close(done); fatal.Fatal("fatal entry") }()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatal("fatal drain waited for output")
		}
		close(out.release)
		requireLogSync(t, l)
		found := false
		for _, r := range out.records(t) {
			if r["msg"] == "fatal entry" && r["level"] == "fatal" {
				found = true
			}
		}
		if !found {
			t.Fatal("fatal record not drained")
		}
	})
}

func TestBoundedConcurrentCloseRejectsWrites(t *testing.T) {
	l, q, out := isolatedLog(t)
	l.Warnf("in flight")
	awaitLogWriter(t, out)
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 100 {
				_, _ = (ordinaryWriter{owner: q}).Write([]byte("{\"msg\":\"racing\"}\n"))
			}
		}()
	}
	closed := make(chan struct{})
	go func() { _ = q.Close(time.Now().Add(ordinaryTimeout)); close(closed) }()
	wg.Wait()
	<-closed
	if _, err := (ordinaryWriter{owner: q}).Write(nil); !errors.Is(err, errOutputClosed) {
		t.Fatalf("post-close=%v", err)
	}
	close(out.release)
}

type failedLogOutput struct {
	err   error
	calls atomic.Int32
}

func (w *failedLogOutput) Write(p []byte) (int, error) {
	w.calls.Add(1)
	if w.err != nil {
		return 0, w.err
	}
	return len(p) - 1, nil
}
func (w *failedLogOutput) Sync() error { return nil }

func TestBoundedWorkerReportsActualOutputFailure(t *testing.T) {
	for _, failure := range []error{errors.New("output: no space left on device"), io.ErrShortWrite} {
		t.Run(failure.Error(), func(t *testing.T) {
			out := &failedLogOutput{}
			if failure != io.ErrShortWrite {
				out.err = failure
			}
			errs := &gatedLogOutput{entered: make(chan struct{}), release: make(chan struct{})}
			q := outputActor(out, errs)
			defer q.Close(time.Now().Add(ordinaryTimeout))
			defer func() {
				select {
				case <-errs.release:
				default:
					close(errs.release)
				}
			}()
			l := logger.NewWithWriter(logger.Config{}, ordinaryWriter{owner: q}, ordinaryWriter{owner: q, diagnostic: true})
			l.Warnf("failed ordinary record") // Must return even if the diagnostic blocks.
			awaitLogWriter(t, errs)
			close(errs.release)
			if err := l.Sync(); !errors.Is(err, failure) {
				t.Fatalf("Sync error=%v want %v", err, failure)
			}
			if err := q.Close(time.Now().Add(ordinaryTimeout)); !errors.Is(err, failure) {
				t.Fatalf("Close error=%v", err)
			}
			records := errs.records(t)
			if len(records) == 0 {
				t.Fatal("missing worker failure diagnostic")
			}
			for _, record := range records {
				if record["msg"] != "ordinary_log_output_error" || record["level"] != "error" || record["error"] != failure.Error() {
					t.Fatalf("diagnostic lost actual failure: %v", record)
				}
			}
			q.mu.Lock()
			dropped := q.dropped
			q.mu.Unlock()
			if dropped != 1 {
				t.Fatalf("failed record lost from accounting: %d", dropped)
			}
		})
	}
}

func TestBoundedWorkerDoesNotRecursivelyReportErrorSinkFailure(t *testing.T) {
	out := &failedLogOutput{err: errors.New("ordinary output failed")}
	errs := &failedLogOutput{err: errors.New("error output failed")}
	q := outputActor(out, errs)
	_, err := (ordinaryWriter{owner: q}).Write([]byte("ordinary\n"))
	if err != nil {
		t.Fatal(err)
	}
	_ = q.Close(time.Now().Add(ordinaryTimeout))
	<-q.done
	if got := errs.calls.Load(); got > out.calls.Load() || got == 0 {
		t.Fatalf("recursive diagnostics: output writes=%d error writes=%d", out.calls.Load(), got)
	}
}

func TestAuditPairCanonicalErrorPathsShareRotation(t *testing.T) {
	dir := t.TempDir()
	path, alias := filepath.Join(dir, "shared.log"), filepath.Join(dir, "alias.log")
	if err := os.WriteFile(path, nil, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(path, alias); err != nil {
		t.Fatal(err)
	}
	l, q, err := outputLog(logger.Config{OutputPaths: []string{path}, ErrorOutputPaths: []string{alias, path},
		Rotate: &logger.RotateConfig{MaxSize: 1, MaxBackups: 1}})
	if err != nil {
		t.Fatal(err)
	}
	defer q.Close(time.Now().Add(ordinaryTimeout))
	l.Warnf("ordinary-large %s", strings.Repeat("o", 700<<10))
	requireLogSync(t, l)
	// This is zap's internal error writer, still admitted through the ordinary
	// queue. Its canonical aliases must resolve to the very same rotating file.
	_, err = (ordinaryWriter{owner: q, diagnostic: true}).Write([]byte("diagnostic-large " + strings.Repeat("d", 700<<10) + "\n"))
	if err != nil {
		t.Fatal(err)
	}
	requireLogSync(t, l)
	if !q.TryEmit(Event{Layer: LayerDNS, Domain: "audit-current-marker"}) {
		t.Fatal("audit admission refused")
	}
	q.CloseAudit(time.Now().Add(time.Second))
	l.Warnf("ordinary-current-marker")
	requireLogSync(t, l)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, marker := range []string{"diagnostic-large", "audit-current-marker", "ordinary-current-marker"} {
		if n := bytes.Count(data, []byte(marker)); n != 1 {
			t.Fatalf("marker %q count=%d; stale or duplicate physical destination", marker, n)
		}
	}
}

func outputLog(cfg logger.Config) (logger.Logger, *AsyncSink, error) {
	outputs, err := logger.OpenOutputs(cfg)
	if err != nil {
		return nil, nil, err
	}
	q := NewOutputSink(NewLogSink(outputs.Audit), outputs, DefaultQueueSize)
	return logger.NewWithWriter(cfg, q.OrdinaryWriter(false), q.OrdinaryWriter(true)), q, nil
}

// Both independent capacity domains stay usable while one physical write blocks.
func TestOutputActorIndependentLanesAndAuditSequence(t *testing.T) {
	l, q, out := isolatedLog(t)
	l.Warnf("in flight")
	awaitLogWriter(t, out)
	for i := range ordinaryEntries {
		l.Warnf("queued ordinary %d", i)
	}
	l.Warnf("ordinary overflow")
	for i := range DefaultQueueSize {
		if !q.TryEmit(Event{Layer: LayerDNS, Domain: fmt.Sprint(i)}) {
			t.Fatalf("audit capacity consumed by ordinary record %d", i)
		}
	}
	if q.TryEmit(Event{Layer: LayerDNS}) {
		t.Fatal("audit event bound exceeded")
	}
	q.mu.Lock()
	if q.bytes > ordinaryBytes || q.dropped != 1 {
		t.Errorf("ordinary bytes=%d drops=%d", q.bytes, q.dropped)
	}
	q.mu.Unlock()
	close(out.release)
	q.CloseAudit(time.Now().Add(2 * time.Second))
	if err := q.Close(time.Now().Add(ordinaryTimeout)); err != nil {
		t.Fatal(err)
	}
	var seq uint64
	for _, r := range out.records(t) {
		if r["opensandbox.event"] == nil {
			if r["seq"] != nil || r["boot_id"] != nil {
				t.Fatalf("ordinary audit metadata: %v", r)
			}
			continue
		}
		seq++
		if r["seq"] != float64(seq) {
			t.Fatalf("audit sequence=%v want %d", r["seq"], seq)
		}
	}
	if seq != DefaultQueueSize {
		t.Fatalf("accepted audit records lost: %d", seq)
	}
}

func TestOutputActorAuditOnlySequenceAndCloseLifetimes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "both.json")
	l, q, err := outputLog(logger.Config{OutputPaths: []string{path}})
	if err != nil {
		t.Fatal(err)
	}
	c := NewCollector(q)
	c.Started()
	for i := range 100 {
		l.Warnf("ordinary %d", i)
		c.RecordDNS(DNSRecord{Domain: "a.example", Decision: DecisionAllow, Reason: ReasonPolicy})
	}
	c.Close(time.Second)
	c.Close(time.Second)
	l.Warnf("after audit shutdown")
	if err := l.Sync(); err != nil {
		t.Fatal(err)
	}
	if err := q.Close(time.Now().Add(ordinaryTimeout)); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var seq uint64
	var boot string
	var ordinary int
	for _, line := range bytes.Split(bytes.TrimSpace(data), []byte("\n")) {
		var r map[string]any
		if err := json.Unmarshal(line, &r); err != nil {
			t.Fatal(err)
		}
		if r["opensandbox.event"] == nil {
			ordinary++
			if r["seq"] != nil || r["boot_id"] != nil {
				t.Fatalf("ordinary audit metadata: %v", r)
			}
			continue
		}
		seq++
		if got := uint64(r["seq"].(float64)); got != seq {
			t.Fatalf("seq=%d want %d", got, seq)
		}
		if boot == "" {
			boot = r["boot_id"].(string)
		}
		if r["boot_id"] != boot {
			t.Fatal("audit boot identity changed")
		}
		if r["reason"] == ReasonStopped {
			if r["detailed"] != float64(100) || r["aggregated"] != float64(0) {
				t.Fatalf("ordinary traffic entered audit stats: %v", r)
			}
		}
	}
	if ordinary != 101 || seq != 102 {
		t.Fatalf("ordinary=%d audit=%d", ordinary, seq)
	}
}

func TestOutputActorEarlyCloseDoesNotLeak(t *testing.T) {
	_, q, err := outputLog(logger.Config{OutputPaths: []string{filepath.Join(t.TempDir(), "unused.json")}})
	if err != nil {
		t.Fatal(err)
	}
	if err := q.Close(time.Now().Add(ordinaryTimeout)); err != nil {
		t.Fatal(err)
	}
	select {
	case <-q.done:
	case <-time.After(time.Second):
		t.Fatal("unused audit lane kept worker alive")
	}
}

func outputActor(out, errs zapcore.WriteSyncer) *AsyncSink {
	raw := zap.New(zapcore.NewCore(zapcore.NewJSONEncoder(zap.NewProductionEncoderConfig()), out, zapcore.InfoLevel), zap.ErrorOutput(errs))
	outputs := &logger.Outputs{Out: out, Errors: errs, Audit: raw}
	return NewOutputSink(NewLogSink(raw), outputs, DefaultQueueSize)
}

func TestOrdinaryBarrierDoesNotDrainFutureAuditTraffic(t *testing.T) {
	l, q, out := isolatedLog(t)
	l.Warnf("preceding ordinary")
	awaitLogWriter(t, out)
	stop, stopped := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(stopped)
		for {
			select {
			case <-stop:
				return
			default:
			}
			q.TryEmit(Event{Layer: LayerDNS, Domain: "ongoing.example"})
		}
	}()
	defer func() { close(stop); <-stopped; q.CloseAudit(time.Now().Add(2 * time.Second)) }()
	close(out.release)
	for range 10 {
		l.Warnf("ordinary FIFO")
		if err := l.Sync(); err != nil {
			t.Fatalf("ordinary barrier waited for future audit traffic: %v", err)
		}
	}
}
