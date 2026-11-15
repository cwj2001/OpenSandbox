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

package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/alibaba/opensandbox/egress/pkg/audit"
	"github.com/alibaba/opensandbox/egress/pkg/constants"
	slogger "github.com/alibaba/opensandbox/internal/logger"
	"github.com/stretchr/testify/require"
)

// Kernel FIFO backpressure holds the one worker inside ordinary Write while
// audit remains queued. Neither timed-out caller may close its descriptor.
func TestAuditLoggerFilesCloseOnlyAfterBothLanesDrain(t *testing.T) {
	path := filepath.Join(t.TempDir(), "blocked.log")
	require.NoError(t, syscall.Mkfifo(path, 0600))
	reader, err := os.OpenFile(path, os.O_RDWR, 0600)
	require.NoError(t, err)
	require.NoError(t, reader.SetReadDeadline(time.Now().Add(5*time.Second)))
	defer reader.Close()
	ordinary, stream, err := newOutputLogger(slogger.Config{OutputPaths: []string{path}})
	require.NoError(t, err)
	defer stream.Close(time.Now().Add(100 * time.Millisecond))
	ordinary.Warnf("ordinary %s", strings.Repeat("o", 700<<10))
	input := bufio.NewReaderSize(reader, 4096)
	_, err = input.ReadByte()
	require.NoError(t, err)
	fds, err := os.ReadDir("/proc/self/fd")
	require.NoError(t, err)
	var physicalFD string
	for _, fd := range fds {
		if fd.Name() == strconv.FormatUint(uint64(reader.Fd()), 10) {
			continue
		}
		link := filepath.Join("/proc/self/fd", fd.Name())
		if target, _ := os.Readlink(link); target == path {
			physicalFD = link
		}
	}
	require.NotEmpty(t, physicalFD)
	collector := audit.NewCollector(stream)
	collector.RecordDNS(audit.DNSRecord{Domain: strings.Repeat("a", 700<<10), Decision: audit.DecisionAllow, Reason: audit.ReasonPolicy})
	require.Error(t, stream.Close(time.Now().Add(100*time.Millisecond)))
	collector.Close(0)
	_, err = os.Stat(physicalFD)
	require.NoError(t, err, "expired callers must not close the active descriptor")
	_, err = input.ReadString('\n')
	require.NoError(t, err)
	_, err = os.Stat(physicalFD)
	require.NoError(t, err, "queued audit work must retain the physical descriptor")
	_, err = input.ReadString('\n')
	require.NoError(t, err)
	stream.CloseAudit(time.Now().Add(time.Second))
	require.NoError(t, stream.Close(time.Now().Add(100*time.Millisecond)))
	_, err = os.Stat(physicalFD)
	require.True(t, os.IsNotExist(err), "actual writer exit closes the descriptor: %v", err)
}

// The mill is asynchronous; wait on its filesystem deletion events, not sleeps.
func TestSharedAuditRotationRetainsConfiguredBackups(t *testing.T) {
	dir := t.TempDir()
	directory, err := os.Open(dir)
	require.NoError(t, err)
	defer directory.Close()
	deletions := make(chan os.Signal, 1)
	signal.Notify(deletions, syscall.SIGIO)
	defer signal.Stop(deletions)
	// dnotify avoids consuming the host user's finite inotify watch budget.
	const dnDelete, dnMultishot = 0x00000008, 0x80000000 // Linux UAPI fcntl.h.
	_, _, errno := syscall.Syscall(syscall.SYS_FCNTL, directory.Fd(), syscall.F_SETOWN, uintptr(os.Getpid()))
	require.Zero(t, errno)
	_, _, errno = syscall.Syscall(syscall.SYS_FCNTL, directory.Fd(), syscall.F_NOTIFY, dnDelete|dnMultishot)
	require.Zero(t, errno)
	var old []string
	for _, age := range []time.Duration{time.Hour, 2 * time.Hour} {
		path := filepath.Join(dir, "shared-"+time.Now().Add(-age).UTC().Format("2006-01-02T15-04-05.000")+".log")
		require.NoError(t, os.WriteFile(path, []byte("old backup\n"), 0600))
		old = append(old, path)
	}
	path := filepath.Join(dir, "shared.log")
	ordinary, pair, err := newOutputLogger(slogger.Config{OutputPaths: []string{path}, Rotate: &slogger.RotateConfig{MaxSize: 1, MaxBackups: 1}})
	require.NoError(t, err)
	defer pair.Close(time.Now().Add(100 * time.Millisecond))
	ordinary.Warnf("ordinary-large %s", strings.Repeat("o", 700<<10))
	require.NoError(t, ordinary.Sync())
	stream := pair
	require.True(t, stream.TryEmit(audit.Event{Layer: audit.LayerDNS, Domain: strings.Repeat("a", 700<<10)}))
	stream.CloseAudit(time.Now().Add(time.Second))
	ordinary.Warnf("current-marker")
	require.NoError(t, ordinary.Sync())
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Contains(t, string(data), "current-marker")
	timer := time.NewTimer(2 * time.Second)
	defer timer.Stop()
	for {
		remaining := false
		for _, path := range old {
			_, err := os.Stat(path)
			remaining = remaining || !os.IsNotExist(err)
		}
		if !remaining {
			break
		}
		select {
		case <-deletions:
		case <-timer.C:
			t.Fatal("rotation retention did not remove old backups")
		}
	}
	backups, err := filepath.Glob(filepath.Join(dir, "shared-*.log"))
	require.NoError(t, err)
	require.Len(t, backups, 1, "one shared rotation timeline must honor MaxBackups")
	backup, err := os.ReadFile(backups[0])
	require.NoError(t, err)
	require.Contains(t, string(backup), "ordinary-large")
	require.NotContains(t, string(backup), "current-marker", "no writer may retain the rotated descriptor")
}

func TestOrdinaryOutputFailureReportsToSeparateErrorDestination(t *testing.T) {
	path := filepath.Join(t.TempDir(), "errors.json")
	ordinary, pair, err := newOutputLogger(slogger.Config{OutputPaths: []string{"/dev/full"}, ErrorOutputPaths: []string{"/dev/full", path}})
	require.NoError(t, err)
	defer pair.Close(time.Now().Add(100 * time.Millisecond))
	ordinary.Warnf("cannot persist")
	require.ErrorIs(t, ordinary.Sync(), syscall.ENOSPC)
	require.ErrorIs(t, pair.Close(time.Now().Add(100*time.Millisecond)), syscall.ENOSPC)
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Contains(t, string(data), `"msg":"ordinary_log_output_error"`)
	require.Contains(t, string(data), syscall.ENOSPC.Error())
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		var record map[string]any
		require.NoError(t, json.Unmarshal([]byte(line), &record))
		require.Equal(t, "ordinary_log_output_error", record["msg"], "only structured worker diagnostics reach the healthy error destination")
		require.Contains(t, record["error"], syscall.ENOSPC.Error())
	}
}

func TestOrdinaryOutputFailureReportsToHealthySharedErrorDestination(t *testing.T) {
	path := filepath.Join(t.TempDir(), "shared-errors.json")
	ordinary, pair, err := newOutputLogger(slogger.Config{
		OutputPaths: []string{"/dev/full", path}, ErrorOutputPaths: []string{path},
	})
	require.NoError(t, err)
	defer pair.Close(time.Now().Add(100 * time.Millisecond))
	ordinary.Warnf("one destination failed")
	require.ErrorIs(t, pair.Close(time.Now().Add(100*time.Millisecond)), syscall.ENOSPC)
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Contains(t, string(data), `"msg":"ordinary_log_output_error"`)
	require.Contains(t, string(data), syscall.ENOSPC.Error())
}

func TestPairedAuditPipeOutputAliases(t *testing.T) {
	testPairedAuditOutputAliases(t, false)
}

func TestPairedAuditUnlinkedRegularOutputAliases(t *testing.T) {
	testPairedAuditOutputAliases(t, true)
}

func testPairedAuditOutputAliases(t *testing.T, unlinkedRegular bool) {
	const child = "OPENSANDBOX_TEST_AUDIT_PIPE_ROUTE"
	if route := os.Getenv(child); route != "" {
		stdout, err := os.Stdout.Stat()
		require.NoError(t, err)
		if unlinkedRegular {
			require.True(t, stdout.Mode().IsRegular(), "child stdout must remain an open regular file")
		} else {
			require.NotZero(t, stdout.Mode()&os.ModeNamedPipe, "child stdout must be an actual pipe")
		}
		countDescriptors := func() int {
			entries, err := os.ReadDir("/proc/self/fd")
			require.NoError(t, err)
			count := 0
			for _, entry := range entries {
				info, err := os.Stat(filepath.Join("/proc/self/fd", entry.Name()))
				if err == nil && os.SameFile(stdout, info) {
					count++
				}
			}
			return count
		}
		before := countDescriptors()
		base, pair, err := newSidecarLoggers(audit.LevelDNS)
		require.NoError(t, err, "valid kernel stream route %s must initialize", route)
		require.NotNil(t, pair)
		require.Equal(t, before+1, countDescriptors(), "all configured stream aliases must share one owned descriptor")
		base.Named("ordinary.pipe").Warnf("ordinary-pipe-marker")
		stream := pair
		require.True(t, stream.TryEmit(audit.Event{Layer: audit.LayerDNS, Domain: "pipe.example"}))
		stream.CloseAudit(time.Now().Add(time.Second))
		require.NoError(t, pair.Close(time.Now().Add(100*time.Millisecond)))
		require.Equal(t, before, countDescriptors(), "both drained lanes must release the owned stream descriptor")
		if unlinkedRegular {
			_, _, err := newOutputLogger(slogger.Config{OutputPaths: []string{
				route, filepath.Join(t.TempDir(), "missing-parent", "invalid.log"),
			}})
			require.ErrorIs(t, err, os.ErrNotExist, "ordinary path errors must still fail startup")
			require.Equal(t, before, countDescriptors(), "failed initialization must close an already-proven opaque descriptor")
		}
		return
	}
	testName := t.Name()
	for _, route := range []string{"/proc/self/fd/1", "/dev/stdout"} {
		t.Run(route, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^"+testName+"$")
			other := "/dev/stdout"
			if route == other {
				other = "/proc/self/fd/1"
			}
			cmd.Env = append(os.Environ(), child+"="+route,
				"OPENSANDBOX_LOG_OUTPUT="+route+",stdout,"+other, constants.EnvEgressLogLevel+"=warn")
			var output []byte
			if unlinkedRegular {
				// Keep the test binary's final PASS line from overwriting JSON
				// written through the logger's independently opened append fd.
				file, err := os.OpenFile(filepath.Join(t.TempDir(), "unlinked-stdout"), os.O_CREATE|os.O_RDWR|os.O_APPEND, 0600)
				require.NoError(t, err)
				defer file.Close()
				require.NoError(t, os.Remove(file.Name()))
				_, err = os.Stat(file.Name())
				require.True(t, os.IsNotExist(err), "stdout file must already be unlinked before exec")
				var diagnostics bytes.Buffer
				cmd.Stdout, cmd.Stderr = file, &diagnostics
				runErr := cmd.Run()
				_, err = file.Seek(0, io.SeekStart)
				require.NoError(t, err)
				output, err = io.ReadAll(file)
				require.NoError(t, err)
				require.NoError(t, runErr, "%s\n%s", output, diagnostics.String())
			} else {
				var err error
				output, err = cmd.CombinedOutput()
				require.NoError(t, err, "%s", output)
			}
			var ordinary, audited int
			for _, line := range strings.Split(string(output), "\n") {
				if !strings.HasPrefix(line, "{") {
					continue
				}
				var record map[string]any
				require.NoError(t, json.Unmarshal([]byte(line), &record))
				if record["msg"] == "ordinary-pipe-marker" {
					ordinary++
					require.Equal(t, "ordinary.pipe", record["logger"])
				}
				if record["opensandbox.event"] == "egress.audit.dns" {
					audited++
					require.Equal(t, "pipe.example", record["domain"])
					require.Equal(t, "info", record["level"])
				}
			}
			require.Equal(t, 1, ordinary, "aliases must not duplicate ordinary JSON")
			require.Equal(t, 1, audited, "aliases must not duplicate audit JSON")
		})
	}
}
