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

// Package audit records DNS decisions without changing enforcement.
package audit

import (
	"fmt"
	"strings"
	"time"

	"go.uber.org/zap"
)

// Level selects which audit events the sidecar emits.
type Level int

const (
	LevelOff Level = iota
	// LevelDNS emits one event per DNS query decision.
	LevelDNS
)

// ParseLevel parses OPENSANDBOX_EGRESS_AUDIT: "", "off" or "dns".
func ParseLevel(raw string) (Level, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "", "off":
		return LevelOff, nil
	case "dns":
		return LevelDNS, nil
	default:
		return LevelOff, fmt.Errorf("unknown audit level %q (want off or dns)", raw)
	}
}

func (l Level) String() string {
	switch l {
	case LevelDNS:
		return "dns"
	default:
		return "off"
	}
}

const (
	LayerDNS = "dns"
	// LayerAudit events describe the audit stream itself: its coverage, and
	// its lifetime.
	LayerAudit = "audit"

	DecisionAllow = "allow"
	DecisionDeny  = "deny"
)

// Reasons are a closed set so downstream queries can group on them.
const (
	// DNS layer.
	ReasonPolicy        = "policy"
	ReasonUnknownSource = "unknown_source"

	// Audit layer.
	ReasonStarted   = "started"
	ReasonHeartbeat = "heartbeat"
	ReasonStopped   = "stopped"
)

// Event is one audit record. Empty fields are omitted from the output.
type Event struct {
	Layer    string
	Decision string
	Reason   string
	// ObservedAt is when the sidecar saw the query; the log
	// timestamp is when the line was written, which can trail it under load.
	ObservedAt time.Time
	// Domain is the queried name.
	Domain string

	// DNS only.
	QueryType    string
	ResponseCode string
	ResolvedIPs  []string

	// Count > 0 marks an aggregated event: Count queries with
	// these fields, first and last seen at WindowStart and WindowEnd, folded
	// together because detailed events were over budget.
	Count       uint64
	WindowStart time.Time
	WindowEnd   time.Time

	// Audit layer only.
	Coverage []string
	// Stats is cumulative on heartbeat/stopped.
	Stats *Stats

	// BootID and Seq are assigned by the writer: Seq is contiguous per BootID
	// in output order, so a gap downstream means lines lost after the sidecar.
	BootID string
	Seq    uint64
}

// Stats accounts for every query the collector observed.
type Stats struct {
	// Detailed queries were written as individual events.
	Detailed uint64
	// Aggregated ones were written inside aggregated events.
	Aggregated uint64
}

// Sink writes audit events. The collector calls it from a single writer
// goroutine (see AsyncSink), so it may block without delaying DNS answers.
type Sink interface {
	Emit(Event)
}

// Event names, one per layer, following the egress.* naming of the other
// egress log events.
const (
	EventDNS    = "egress.audit.dns"
	EventStream = "egress.audit.stream"
)

// Name is the opensandbox.event value for e.
func (e Event) Name() string {
	switch e.Layer {
	case LayerDNS:
		return EventDNS
	default:
		return EventStream
	}
}

// LogSink writes each event as one structured log record named by
// Event.Name. Like Sink, it requires a single writer; its field scratch is
// reused between calls rather than attached to a new logger for every event.
type LogSink struct {
	logger *zap.Logger
	fields [32]zap.Field
}

func NewLogSink(logger *zap.Logger) *LogSink {
	return &LogSink{logger: logger}
}

func (s *LogSink) Emit(e Event) {
	fields := s.fields[:0]
	fields = append(fields,
		zap.String("opensandbox.event", e.Name()),
		zap.String("reason", e.Reason),
	)
	if e.BootID != "" {
		fields = append(fields, zap.String("boot_id", e.BootID), zap.Uint64("seq", e.Seq))
	}
	if !e.ObservedAt.IsZero() {
		fields = append(fields, zap.String("observed_at", e.ObservedAt.UTC().Format(time.RFC3339Nano)))
	}
	if e.Decision != "" {
		fields = append(fields, zap.String("decision", e.Decision))
	}
	if e.Domain != "" {
		fields = append(fields, zap.String("domain", e.Domain))
	}
	if e.QueryType != "" {
		fields = append(fields, zap.String("dns_query_type", e.QueryType))
	}
	if e.ResponseCode != "" {
		fields = append(fields, zap.String("dns_response_code", e.ResponseCode))
	}
	if len(e.ResolvedIPs) > 0 {
		fields = append(fields, zap.Strings("resolved_ips", e.ResolvedIPs))
	}
	if e.Count > 0 {
		fields = append(fields, zap.Uint64("count", e.Count))
	}
	if !e.WindowStart.IsZero() {
		fields = append(fields,
			zap.String("window_start", e.WindowStart.UTC().Format(time.RFC3339Nano)),
			zap.String("window_end", e.WindowEnd.UTC().Format(time.RFC3339Nano)),
		)
	}
	if len(e.Coverage) > 0 {
		fields = append(fields, zap.Strings("coverage", e.Coverage))
	}
	if e.Stats != nil {
		fields = append(fields,
			zap.Uint64("detailed", e.Stats.Detailed),
			zap.Uint64("aggregated", e.Stats.Aggregated),
		)
	}
	s.logger.Info("egress audit", fields...)
	clear(fields)
}
