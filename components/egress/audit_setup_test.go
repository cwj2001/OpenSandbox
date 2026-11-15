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
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/alibaba/opensandbox/egress/pkg/audit"
	"github.com/alibaba/opensandbox/egress/pkg/constants"
	"github.com/alibaba/opensandbox/egress/pkg/dnsproxy"
	"github.com/alibaba/opensandbox/egress/pkg/policy"
	slogger "github.com/alibaba/opensandbox/internal/logger"
)

func TestResolveAuditLevel(t *testing.T) {
	cases := []struct {
		name, audit, profile, revision string
		want                           audit.Level
	}{
		{name: "unset", want: audit.LevelOff},
		{name: "dns", audit: "dns", want: audit.LevelDNS},
		{name: "conn", audit: "conn", profile: constants.ProfileSidecar, want: audit.LevelOff},
		// Audit never fails startup: bad or unsupported settings turn it off.
		{name: "unknown level", audit: "l7", want: audit.LevelOff},
		{name: "fast-sandbox", audit: "dns", profile: constants.ProfileFastSandbox, want: audit.LevelOff},
		{name: "revision runtime", audit: "dns", revision: "true", want: audit.LevelOff},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			level, warning := resolveAuditLevel(tc.profile, tc.audit, tc.revision == "true")
			require.Equal(t, tc.want, level)
			require.Equal(t, tc.want == audit.LevelOff && tc.audit != "" && tc.audit != "off", warning != "")
		})
	}
}

func newAuditTestProxy(t *testing.T) *dnsproxy.Proxy {
	t.Helper()
	t.Setenv(constants.EnvDNSUpstream, "127.0.0.1:53")
	proxy, err := dnsproxy.New(policy.DefaultDenyPolicy(), "", nil, nil)
	require.NoError(t, err)
	return proxy
}

// Exercise the two real consumers, not two artificial writes to one sink.
func TestOrdinaryAndAuditShareRotatingDestination(t *testing.T) {
	path := filepath.Join(t.TempDir(), "shared.log")
	cfg := slogger.Config{OutputPaths: []string{path}, Rotate: &slogger.RotateConfig{MaxSize: 1, MaxBackups: 1}}
	ordinary, pair, err := newOutputLogger(cfg)
	require.NoError(t, err)
	defer pair.Close(time.Now().Add(100 * time.Millisecond))
	ordinary.Warnf("ordinary-large %s", strings.Repeat("o", 700<<10))
	require.NoError(t, ordinary.Sync())
	stream := pair
	require.True(t, stream.TryEmit(audit.Event{Layer: audit.LayerDNS, Domain: strings.Repeat("a", 700<<10)}))
	stream.CloseAudit(time.Now().Add(time.Second))
	ordinary.Warnf("ordinary-current-marker")
	require.NoError(t, ordinary.Sync())
	current, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Contains(t, string(current), "ordinary-current-marker", "ordinary must not keep writing a rotated/orphaned descriptor")
}

func TestOffAndUnsupportedAuditKeepSynchronousOrdinaryLogger(t *testing.T) {
	for _, tc := range []struct {
		raw, profile string
		revision     bool
	}{
		{raw: "off"},
		{raw: "dns", profile: constants.ProfileFastSandbox},
		{raw: "conn", revision: true},
		{raw: "invalid"},
	} {
		t.Run(tc.raw+tc.profile+fmt.Sprint(tc.revision), func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "ordinary.log")
			output, err := os.Create(path)
			require.NoError(t, err)
			defer output.Close()
			t.Setenv("OPENSANDBOX_LOG_OUTPUT", "stdout")
			t.Setenv(constants.EnvEgressLogLevel, "warn")
			level, warning := resolveAuditLevel(tc.profile, tc.raw, tc.revision)
			require.Equal(t, audit.LevelOff, level)
			oldStdout := os.Stdout
			os.Stdout = output
			base, pair, err := newSidecarLoggers(level)
			os.Stdout = oldStdout
			require.NoError(t, err)
			require.Nil(t, pair, "off/unsupported must not construct or start a bounded worker")
			base.Infof("filtered")
			base.With(slogger.Field{Key: "sandbox_id", Value: "test"}).Named("test").Warnf("configured %s", warning)
			// No Sync or drain: legacy off-mode writes remain synchronous.
			data, err := os.ReadFile(path)
			require.NoError(t, err)
			require.Contains(t, string(data), `"sandbox_id":"test"`)
			require.Contains(t, string(data), `"logger":"test"`)
			require.NotContains(t, string(data), "filtered")
		})
	}
}

func TestPairedAuditRemainsInfoUnsampledAndMetadataBearing(t *testing.T) {
	const child = "OPENSANDBOX_TEST_AUDIT_METADATA_CHILD"
	if os.Getenv(child) != "1" {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestPairedAuditRemainsInfoUnsampledAndMetadataBearing$")
		cmd.Env = append(os.Environ(), child+"=1", constants.EnvSandboxID+"=audit-sandbox")
		output, err := cmd.CombinedOutput()
		require.NoError(t, err, "%s", output)
		return
	}
	// Shared telemetry metadata is intentionally snapshotted once per process.
	path := filepath.Join(t.TempDir(), "shared.log")
	ordinary, pair, err := newOutputLogger(slogger.Config{Level: "error", OutputPaths: []string{path}})
	require.NoError(t, err)
	defer pair.Close(time.Now().Add(100 * time.Millisecond))
	stream := pair
	for range 250 {
		require.True(t, stream.TryEmit(audit.Event{Layer: audit.LayerDNS, Domain: "same.example"}))
	}
	stream.CloseAudit(time.Now().Add(time.Second))
	ordinary.Infof("ordinary-filtered")
	require.NoError(t, ordinary.Sync())
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, 250, strings.Count(string(data), `"opensandbox.event":"egress.audit.dns"`))
	require.Equal(t, 250, strings.Count(string(data), `"level":"info"`))
	require.Equal(t, 250, strings.Count(string(data), `"sandbox_id":"audit-sandbox"`))
	require.Equal(t, 250, strings.Count(string(data), `"logger":"opensandbox.egress.audit"`))
	require.NotContains(t, string(data), "ordinary-filtered")
}

func TestStartAuditDNSLifecycle(t *testing.T) {
	for _, level := range []audit.Level{audit.LevelOff, audit.LevelDNS} {
		t.Run(level.String(), func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "audit.log")
			_, output, err := newOutputLogger(slogger.Config{OutputPaths: []string{path}})
			require.NoError(t, err)
			stop := startAudit(level, newAuditTestProxy(t), output)
			stop()
			require.NoError(t, output.Close(time.Now().Add(time.Second)))
			data, err := os.ReadFile(path)
			require.NoError(t, err)
			if level == audit.LevelOff {
				require.Empty(t, data)
				return
			}
			require.Contains(t, string(data), `"reason":"started"`)
			require.Contains(t, string(data), `"coverage":["dns"]`)
			require.Contains(t, string(data), `"reason":"stopped"`)
			require.Contains(t, string(data), `"detailed":0,"aggregated":0`)
			require.NotContains(t, string(data), "deduplicated")
		})
	}
}

func TestNormalizedEmptyLogOutputsPreserveLegacyFallback(t *testing.T) {
	const child = "OPENSANDBOX_TEST_EMPTY_OUTPUT_CHILD"
	if os.Getenv(child) != "1" {
		for _, output := range []string{",", " \t, ,\t"} {
			for _, level := range []string{"debug", "error"} {
				t.Run(fmt.Sprintf("%q/%s", output, level), func(t *testing.T) {
					ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
					defer cancel()
					cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestNormalizedEmptyLogOutputsPreserveLegacyFallback$")
					cmd.Env = append(os.Environ(), child+"=1", "OPENSANDBOX_LOG_OUTPUT="+output, constants.EnvEgressLogLevel+"="+level)
					var stdout, stderr bytes.Buffer
					cmd.Stdout, cmd.Stderr = &stdout, &stderr
					require.NoError(t, cmd.Run(), "%s\n%s", stdout.String(), stderr.String())
					require.Empty(t, stderr.String())
					for _, marker := range []string{"empty-output-info-legacy", "empty-output-info-actor", `"domain":"fallback.example"`} {
						require.Equal(t, 1, strings.Count(stdout.String(), marker), "missing or duplicate fallback output: %s", stdout.String())
					}
					require.NotContains(t, stdout.String(), "empty-output-debug")
					require.NotContains(t, stdout.String(), "empty-error-route")
				})
			}
		}
		return
	}
	for _, tc := range []struct {
		level audit.Level
		name  string
	}{{audit.LevelOff, "legacy"}, {audit.LevelDNS, "actor"}} {
		base, actor, err := newSidecarLoggers(tc.level)
		require.NoError(t, err)
		base.Debugf("empty-output-debug-%s", tc.name)
		base.Infof("empty-output-info-%s", tc.name)
		if actor != nil {
			require.True(t, actor.TryEmit(audit.Event{Layer: audit.LayerDNS, Domain: "fallback.example"}))
			actor.CloseAudit(time.Now().Add(time.Second))
			require.NoError(t, base.Sync())
			require.NoError(t, actor.Close(time.Now().Add(100*time.Millisecond)))
		}
	}
	// Legacy normalization leaves default error outputs empty, even while the
	// ordinary stdout fallback is active. Do not silently reroute diagnostics.
	outputs, err := slogger.OpenOutputs(slogger.Config{})
	require.NoError(t, err)
	defer outputs.Close()
	_, err = outputs.Errors.Write([]byte("empty-error-route\n"))
	require.NoError(t, err)
}
