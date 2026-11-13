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

// Package audit records which destinations a sandbox reached or was denied,
// at the DNS layer and (dns+nft) per new L4 connection. It observes verdicts
// already taken by the DNS proxy and the nftables chain; it never decides one,
// and it decodes only IP/transport headers. The fixed NFLOG packet prefix may
// contain payload bytes, but they are never included in audit events.
package audit

import (
	"fmt"
	"net/netip"
	"strings"
	"time"

	slogger "github.com/alibaba/opensandbox/internal/logger"
)

// Level selects which audit events the sidecar emits.
type Level int

const (
	LevelOff Level = iota
	// LevelDNS emits one event per DNS query decision.
	LevelDNS
	// LevelConn adds one event per new TCP/UDP connection verdict (dns+nft only).
	LevelConn
)

// ParseLevel parses OPENSANDBOX_EGRESS_AUDIT: "", "off", "dns" or "conn".
func ParseLevel(raw string) (Level, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "", "off":
		return LevelOff, nil
	case "dns":
		return LevelDNS, nil
	case "conn":
		return LevelConn, nil
	default:
		return LevelOff, fmt.Errorf("unknown audit level %q (want off, dns or conn)", raw)
	}
}

func (l Level) String() string {
	switch l {
	case LevelDNS:
		return "dns"
	case LevelConn:
		return "conn"
	default:
		return "off"
	}
}

const (
	LayerDNS = "dns"
	LayerL4  = "l4"
	// LayerAudit events describe the audit stream itself: its coverage, and
	// every gap in it.
	LayerAudit = "audit"

	DecisionAllow = "allow"
	DecisionDeny  = "deny"
)

// Reasons are a closed set so downstream queries can group on them.
const (
	// DNS layer.
	ReasonPolicy        = "policy"
	ReasonUnknownSource = "unknown_source"

	// L4 layer: which nftables rule family produced the verdict.
	ReasonDoT      = "dot"
	ReasonDoH      = "doh"
	ReasonPortRule = "port_rule"
	ReasonIPRule   = "ip_rule"
	ReasonDNSLease = "dns_lease"
	ReasonDefault  = "default"

	// Audit layer.
	ReasonStarted   = "started"
	ReasonDegraded  = "degraded"
	ReasonGap       = "gap"
	ReasonHeartbeat = "heartbeat"
	ReasonStopped   = "stopped"
)

var l4Reasons = map[string]bool{
	ReasonDoT: true, ReasonDoH: true, ReasonPortRule: true,
	ReasonIPRule: true, ReasonDNSLease: true, ReasonDefault: true,
}

// NFLogGroup is the NFLOG group the sidecar's audit rules log to. Groups are
// per network namespace, so a fixed value cannot collide across sandboxes.
const NFLogGroup = 7391

const nflogPrefix = "osb-audit:"

// NFLogPrefix is the log prefix carried by an audit rule; the collector
// recovers the verdict from it, since NFLOG does not report the verdict.
func NFLogPrefix(decision, reason string) string {
	d := "a"
	if decision == DecisionDeny {
		d = "d"
	}
	return nflogPrefix + d + ":" + reason
}

func parseNFLogPrefix(prefix string) (decision, reason string, ok bool) {
	rest, found := strings.CutPrefix(prefix, nflogPrefix)
	if !found {
		return "", "", false
	}
	d, reason, found := strings.Cut(rest, ":")
	if !found || !l4Reasons[reason] {
		return "", "", false
	}
	switch d {
	case "a":
		return DecisionAllow, reason, true
	case "d":
		return DecisionDeny, reason, true
	default:
		return "", "", false
	}
}

// Event is one audit record. Empty fields are omitted from the output.
type Event struct {
	Layer    string
	Decision string
	Reason   string
	// ObservedAt is when the sidecar saw the query or connection; the log
	// timestamp is when the line was written, which can trail it under load.
	ObservedAt time.Time
	// Domain is the queried name (DNS) or, for L4, the name this destination
	// was most recently resolved from through the sidecar's DNS proxy.
	Domain string

	// L4 only.
	Protocol        string
	DestinationIP   netip.Addr
	DestinationPort uint16
	// DNSSeen reports whether the destination was resolved through the
	// sidecar's DNS proxy before the connection; false means a literal-IP
	// dial or a name resolved some other way.
	DNSSeen bool
	// Rule and RuleSource name the policy rule behind an ip_rule/port_rule
	// verdict; RuleSource is "platform" (always overlay) or "user".
	Rule       string
	RuleSource string

	// DNS only.
	QueryType    string
	ResponseCode string
	ResolvedIPs  []string

	// Count > 0 marks an aggregated event: Count queries or connections with
	// these fields, first and last seen at WindowStart and WindowEnd, folded
	// together because detailed events were over budget.
	Count       uint64
	WindowStart time.Time
	WindowEnd   time.Time

	// Audit layer only.
	Coverage []string
	Detail   string
	// Stats is cumulative on heartbeat/stopped and covers WindowStart to
	// WindowEnd on gap.
	Stats *Stats

	// BootID and Seq are assigned by the writer: Seq is contiguous per BootID
	// in output order, so a gap downstream means lines lost after the sidecar.
	BootID string
	Seq    uint64
}

// Stats accounts for every query and connection the collector observed.
type Stats struct {
	// Detailed queries and connections were written as individual events.
	Detailed uint64
	// Aggregated ones were written inside aggregated events.
	Aggregated uint64
	// Deduplicated L4 copies repeated the 5-tuple of one already counted
	// within the dedup window — TCP SYN retransmits, repeated packets of a
	// denied UDP flow, or (rarely) a new attempt that reused the 5-tuple.
	Deduplicated uint64
	// LostKernel counts L4 copies the kernel could not deliver (NFLOG
	// sequence gaps); a TCP SYN retransmit is one copy, so this bounds the
	// lost connections from above.
	LostKernel uint64
	// LostUndecodable counts copies whose headers could not be parsed.
	LostUndecodable uint64
}

// Sink writes audit events. The collector calls it from a single writer
// goroutine (see AsyncSink), so it may block without delaying DNS answers or
// the NFLOG reader.
type Sink interface {
	Emit(Event)
}

// Event names, one per layer, following the egress.* naming of the other
// egress log events.
const (
	EventDNS        = "egress.audit.dns"
	EventConnection = "egress.audit.connection"
	EventStream     = "egress.audit.stream"
)

// Name is the opensandbox.event value for e.
func (e Event) Name() string {
	switch e.Layer {
	case LayerDNS:
		return EventDNS
	case LayerL4:
		return EventConnection
	default:
		return EventStream
	}
}

// LogSink writes each event as one structured log record named by
// Event.Name.
type LogSink struct {
	logger slogger.Logger
}

func NewLogSink(logger slogger.Logger) *LogSink {
	return &LogSink{logger: logger}
}

func (s *LogSink) Emit(e Event) {
	s.logger.With(e.fields()...).Infof("egress audit")
}

func (e Event) fields() []slogger.Field {
	fields := []slogger.Field{
		{Key: "opensandbox.event", Value: e.Name()},
		{Key: "reason", Value: e.Reason},
	}
	add := func(key string, value any) {
		fields = append(fields, slogger.Field{Key: key, Value: value})
	}
	if e.BootID != "" {
		add("boot_id", e.BootID)
		add("seq", e.Seq)
	}
	if !e.ObservedAt.IsZero() {
		add("observed_at", e.ObservedAt.UTC().Format(time.RFC3339Nano))
	}
	if e.Decision != "" {
		add("decision", e.Decision)
	}
	if e.Domain != "" {
		add("domain", e.Domain)
	}
	// Connection fields match execd's eBPF connect events (dst_ip, dst_port,
	// proto) so the two can be joined. An aggregate that overflowed its
	// window keeps only decision and reason, so it carries no destination.
	if e.Layer == LayerL4 && e.DestinationIP.IsValid() {
		add("proto", e.Protocol)
		add("dst_ip", e.DestinationIP.String())
		add("dst_port", e.DestinationPort)
		add("dns_seen", e.DNSSeen)
	}
	if e.Rule != "" {
		add("rule", e.Rule)
		add("rule_source", e.RuleSource)
	}
	if e.QueryType != "" {
		add("dns_query_type", e.QueryType)
	}
	if e.ResponseCode != "" {
		add("dns_response_code", e.ResponseCode)
	}
	if len(e.ResolvedIPs) > 0 {
		add("resolved_ips", e.ResolvedIPs)
	}
	if e.Count > 0 {
		add("count", e.Count)
	}
	if !e.WindowStart.IsZero() {
		add("window_start", e.WindowStart.UTC().Format(time.RFC3339Nano))
		add("window_end", e.WindowEnd.UTC().Format(time.RFC3339Nano))
	}
	if len(e.Coverage) > 0 {
		add("coverage", e.Coverage)
	}
	if e.Detail != "" {
		add("detail", e.Detail)
	}
	if e.Stats != nil {
		add("detailed", e.Stats.Detailed)
		add("aggregated", e.Stats.Aggregated)
		add("deduplicated", e.Stats.Deduplicated)
		add("lost_kernel", e.Stats.LostKernel)
		add("lost_undecodable", e.Stats.LostUndecodable)
	}
	return fields
}
