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
)

func countLines(t *testing.T, disableSampling bool) int {
	t.Helper()
	path := filepath.Join(t.TempDir(), "out.log")
	l, err := New(Config{Level: "info", OutputPaths: []string{path}, DisableSampling: disableSampling})
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

func TestSamplingDefaultAndDisabled(t *testing.T) {
	// Default: the first 100 per second, then every 100th — a burst of 1000
	// identical messages within one second keeps 109.
	if got := countLines(t, false); got >= 1000 || got < 100 {
		t.Fatalf("default sampling kept %d of 1000 entries", got)
	}
	if got := countLines(t, true); got != 1000 {
		t.Fatalf("DisableSampling kept %d of 1000 entries", got)
	}
}
