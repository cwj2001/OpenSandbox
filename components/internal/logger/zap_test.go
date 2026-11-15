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

package logger

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
)

func countLines(t *testing.T) int {
	t.Helper()
	path := filepath.Join(t.TempDir(), "out.log")
	l, err := New(Config{Level: "info", OutputPaths: []string{path}})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 1000; i++ {
		l.Infof("same message")
	}
	_ = l.Sync()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return bytes.Count(data, []byte("\n"))
}

func TestDefaultSampling(t *testing.T) {
	// Default: the first 100 per second, then every 100th — a burst of 1000
	// identical messages within one second keeps 109.
	if got := countLines(t); got >= 1000 || got < 100 {
		t.Fatalf("default sampling kept %d of 1000 entries", got)
	}
}

// Legacy constructors retain synchronous writes and configured multiplicity;
// canonical destination deduplication is limited to the output-owner interface.
func TestLegacyOutputMultiplicityAndExtraCore(t *testing.T) {
	for _, extra := range []bool{false, true} {
		path := filepath.Join(t.TempDir(), "duplicates.log")
		cfg := Config{Level: "warn", OutputPaths: []string{path, path}}
		observed, logs := observer.New(zapcore.DebugLevel)
		var l Logger
		var err error
		if extra {
			l, err = NewWithExtraCores(cfg, observed)
		} else {
			l, err = New(cfg)
		}
		if err != nil {
			t.Fatal(err)
		}
		l.Infof("filtered")
		l.Warnf("synchronous duplicate")
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if count := bytes.Count(data, []byte("synchronous duplicate")); count != 2 {
			t.Fatalf("legacy multiplicity=%d", count)
		}
		if bytes.Contains(data, []byte("filtered")) {
			t.Fatal("ordinary configured level changed")
		}
		if extra && logs.Len() != 2 {
			t.Fatalf("extra core entries=%d", logs.Len())
		}
	}
}

func TestLegacyConfiguredErrorOutput(t *testing.T) {
	if _, err := os.Stat("/dev/full"); err != nil {
		t.Skip("requires a kernel output that fails writes")
	}
	path := filepath.Join(t.TempDir(), "errors.log")
	l, err := New(Config{OutputPaths: []string{"/dev/full"}, ErrorOutputPaths: []string{path}})
	if err != nil {
		t.Fatal(err)
	}
	l.Warnf("failed ordinary output")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(data, []byte("/dev/full")) {
		t.Fatalf("configured error destination lost output failure: %s", data)
	}
}
