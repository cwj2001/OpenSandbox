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
	"fmt"
	"time"

	"github.com/alibaba/opensandbox/egress/pkg/audit"
	"github.com/alibaba/opensandbox/egress/pkg/constants"
	"github.com/alibaba/opensandbox/egress/pkg/dnsproxy"
	"github.com/alibaba/opensandbox/egress/pkg/log"
	"github.com/alibaba/opensandbox/egress/pkg/telemetry"
	slogger "github.com/alibaba/opensandbox/internal/logger"
	"go.uber.org/zap"
)

const (
	// auditFlushTimeout bounds how long shutdown waits for queued events.
	auditFlushTimeout = 2 * time.Second
)

// resolveAuditLevel is pure: configuration warnings are emitted only after the
// one final ordinary logger has its configured outputs, level and metadata.
func resolveAuditLevel(profile, raw string, revisionRuntime bool) (audit.Level, string) {
	level, err := audit.ParseLevel(raw)
	if err != nil {
		return audit.LevelOff, fmt.Sprintf("invalid %s=%q: %v; egress audit disabled", constants.EnvEgressAudit, raw, err)
	}
	if level == audit.LevelOff {
		return level, ""
	}
	if profile == constants.ProfileFastSandbox {
		return audit.LevelOff, fmt.Sprintf("%s is not supported with the %s profile; egress audit disabled", constants.EnvEgressAudit, constants.ProfileFastSandbox)
	}
	if revisionRuntime {
		return audit.LevelOff, fmt.Sprintf("%s is not supported with %s; egress audit disabled", constants.EnvEgressAudit, constants.EnvExperimentalRevisionRuntime)
	}
	return level, ""
}

// startAudit records DNS decisions without changing enforcement.
func startAudit(level audit.Level, proxy *dnsproxy.Proxy, sink *audit.AsyncSink) func() {
	if level == audit.LevelOff {
		return func() {}
	}
	collector := audit.NewCollector(sink)
	proxy.SetAudit(collector)
	collector.Started()
	log.Infof("egress audit enabled (level=dns)")
	return func() { collector.Close(auditFlushTimeout) }
}

// newLogSink keeps typed audit encoding and physical acquisition separate from
// ordinary admission. Metadata is attached before the sole writer starts.
func newLogSink(outputs *slogger.Outputs) *audit.LogSink {
	base := outputs.Audit
	if extra := telemetry.EgressLogFields(); len(extra) > 0 {
		fields := make([]zap.Field, len(extra))
		for i, field := range extra {
			fields[i] = zap.Any(field.Key, field.Value)
		}
		base = base.With(fields...)
	}
	return audit.NewLogSink(base.Named("opensandbox.egress.audit"))
}

func newOutputLogger(cfg slogger.Config) (slogger.Logger, *audit.AsyncSink, error) {
	outputs, err := slogger.OpenOutputs(cfg)
	if err != nil {
		return nil, nil, err
	}
	sink := audit.NewOutputSink(newLogSink(outputs), outputs, audit.DefaultQueueSize)
	return slogger.NewWithWriter(cfg, sink.OrdinaryWriter(false), sink.OrdinaryWriter(true)), sink, nil
}
