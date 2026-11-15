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
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func TestLogSinkJSONSchema(t *testing.T) {
	at := time.Date(2026, 1, 2, 3, 4, 5, 123456789, time.FixedZone("synthetic-offset", 7*3600))
	common := Event{BootID: "synthetic-boot", Seq: 9007199254740993, ObservedAt: at}
	dns := common
	dns.Layer, dns.Decision, dns.Reason = LayerDNS, DecisionAllow, ReasonPolicy
	dns.Domain, dns.QueryType, dns.ResponseCode = "allowed.example", "A", "NOERROR"
	dns.ResolvedIPs = []string{"192.0.2.1", "2001:db8::1"}
	denied := common
	denied.Layer, denied.Decision, denied.Reason = LayerDNS, DecisionDeny, ReasonPolicy
	denied.Domain, denied.QueryType, denied.ResponseCode = "denied.example", "AAAA", "REFUSED"
	l4 := common
	l4.Layer, l4.Decision, l4.Reason = LayerL4, DecisionDeny, ReasonPortRule
	l4.Protocol, l4.DestinationIP, l4.DestinationPort = "tcp", netip.MustParseAddr("192.0.2.5"), 443
	l4.Rule, l4.RuleSource = "tcp:443", "platform"
	v6 := l4
	v6.Decision, v6.Reason, v6.Protocol = DecisionAllow, ReasonDNSLease, "udp"
	v6.DestinationIP, v6.DestinationPort, v6.DNSSeen = netip.MustParseAddr("2001:db8::5"), 53, true
	v6.Domain, v6.Rule, v6.RuleSource = "allowed.example", "udp:53", "user"
	aggregate := dns
	aggregate.Count, aggregate.WindowStart, aggregate.WindowEnd = 123, at.Add(-time.Second), at
	overflow := common
	overflow.Layer, overflow.Reason, overflow.Decision = LayerL4, ReasonDefault, DecisionDeny
	overflow.Count, overflow.WindowStart, overflow.WindowEnd = 9007199254740993, at.Add(-time.Minute), at
	stats := &Stats{Detailed: 9007199254740993, Aggregated: 27, Deduplicated: 3, LostKernel: 5, LostUndecodable: 7}
	gap := common
	gap.Layer, gap.Reason, gap.Stats = LayerAudit, ReasonGap, stats
	gap.WindowStart, gap.WindowEnd, gap.Detail = at.Add(-time.Minute), at, "synthetic gap"
	heartbeat := common
	heartbeat.Layer, heartbeat.Reason, heartbeat.Stats = LayerAudit, ReasonHeartbeat, stats
	heartbeat.Coverage = []string{LayerDNS, LayerL4}
	stopped := heartbeat
	stopped.Reason, stopped.Stats = ReasonStopped, &Stats{}
	started := common
	started.Layer, started.Reason, started.Coverage = LayerAudit, ReasonStarted, []string{LayerDNS, LayerL4}
	degraded := started
	degraded.Reason, degraded.Detail = ReasonDegraded, "synthetic degraded coverage"
	invalid := l4
	invalid.DestinationIP = netip.Addr{}
	zeroEnd := aggregate
	zeroEnd.WindowEnd = time.Time{}
	all := v6
	all.QueryType, all.ResponseCode, all.ResolvedIPs = "AAAA", "NOERROR", dns.ResolvedIPs
	all.Count, all.WindowStart, all.WindowEnd = 99, at.Add(-time.Second), at
	all.Coverage, all.Detail, all.Stats = started.Coverage, "synthetic maximal event", stats
	ignored := dns
	ignored.DestinationIP, ignored.DestinationPort, ignored.Protocol = l4.DestinationIP, 443, "tcp"
	gated := Event{Seq: 17, RuleSource: "user", WindowEnd: at, ResolvedIPs: []string{}, Coverage: []string{}}
	zeroL4 := Event{Layer: LayerL4, DestinationIP: netip.MustParseAddr("::"), Rule: "synthetic-rule"}

	// Literal JSON contracts also cover cases measured against the immutable
	// pre-optimization logger, without retaining that implementation in tests.
	cases := []struct {
		name       string
		event      Event
		identified bool
		want       string
	}{
		{"DNSAllow", dns, true, `{"opensandbox.event":"egress.audit.dns","reason":"policy","decision":"allow","domain":"allowed.example","dns_query_type":"A","dns_response_code":"NOERROR","resolved_ips":["192.0.2.1","2001:db8::1"]}`},
		{"DNSDeny", denied, true, `{"opensandbox.event":"egress.audit.dns","reason":"policy","decision":"deny","domain":"denied.example","dns_query_type":"AAAA","dns_response_code":"REFUSED"}`},
		{"L4Deny", l4, true, `{"opensandbox.event":"egress.audit.connection","reason":"port_rule","decision":"deny","proto":"tcp","dst_ip":"192.0.2.5","dst_port":443,"dns_seen":false,"rule":"tcp:443","rule_source":"platform"}`},
		{"L4AllowIPv6", v6, true, `{"opensandbox.event":"egress.audit.connection","reason":"dns_lease","decision":"allow","domain":"allowed.example","proto":"udp","dst_ip":"2001:db8::5","dst_port":53,"dns_seen":true,"rule":"udp:53","rule_source":"user"}`},
		{"DNSAggregate", aggregate, true, `{"opensandbox.event":"egress.audit.dns","reason":"policy","decision":"allow","domain":"allowed.example","dns_query_type":"A","dns_response_code":"NOERROR","resolved_ips":["192.0.2.1","2001:db8::1"],"count":123,"window_start":"2026-01-01T20:04:04.123456789Z","window_end":"2026-01-01T20:04:05.123456789Z"}`},
		{"OverflowAggregate", overflow, true, `{"opensandbox.event":"egress.audit.connection","reason":"default","decision":"deny","count":9007199254740993,"window_start":"2026-01-01T20:03:05.123456789Z","window_end":"2026-01-01T20:04:05.123456789Z"}`},
		{"Gap", gap, true, `{"opensandbox.event":"egress.audit.stream","reason":"gap","window_start":"2026-01-01T20:03:05.123456789Z","window_end":"2026-01-01T20:04:05.123456789Z","detail":"synthetic gap","detailed":9007199254740993,"aggregated":27,"deduplicated":3,"lost_kernel":5,"lost_undecodable":7}`},
		{"Heartbeat", heartbeat, true, `{"opensandbox.event":"egress.audit.stream","reason":"heartbeat","coverage":["dns","l4"],"detailed":9007199254740993,"aggregated":27,"deduplicated":3,"lost_kernel":5,"lost_undecodable":7}`},
		{"Stopped", stopped, true, `{"opensandbox.event":"egress.audit.stream","reason":"stopped","coverage":["dns","l4"],"detailed":0,"aggregated":0,"deduplicated":0,"lost_kernel":0,"lost_undecodable":0}`},
		{"Started", started, true, `{"opensandbox.event":"egress.audit.stream","reason":"started","coverage":["dns","l4"]}`},
		{"Degraded", degraded, true, `{"opensandbox.event":"egress.audit.stream","reason":"degraded","coverage":["dns","l4"],"detail":"synthetic degraded coverage"}`},
		{"InvalidDestination", invalid, true, `{"opensandbox.event":"egress.audit.connection","reason":"port_rule","decision":"deny","rule":"tcp:443","rule_source":"platform"}`},
		{"ZeroWindowEnd", zeroEnd, true, `{"opensandbox.event":"egress.audit.dns","reason":"policy","decision":"allow","domain":"allowed.example","dns_query_type":"A","dns_response_code":"NOERROR","resolved_ips":["192.0.2.1","2001:db8::1"],"count":123,"window_start":"2026-01-01T20:04:04.123456789Z","window_end":"0001-01-01T00:00:00Z"}`},
		{"AllFields", all, true, `{"opensandbox.event":"egress.audit.connection","reason":"dns_lease","decision":"allow","domain":"allowed.example","proto":"udp","dst_ip":"2001:db8::5","dst_port":53,"dns_seen":true,"rule":"udp:53","rule_source":"user","dns_query_type":"AAAA","dns_response_code":"NOERROR","resolved_ips":["192.0.2.1","2001:db8::1"],"count":99,"window_start":"2026-01-01T20:04:04.123456789Z","window_end":"2026-01-01T20:04:05.123456789Z","coverage":["dns","l4"],"detail":"synthetic maximal event","detailed":9007199254740993,"aggregated":27,"deduplicated":3,"lost_kernel":5,"lost_undecodable":7}`},
		{"DNSIgnoresL4", ignored, true, `{"opensandbox.event":"egress.audit.dns","reason":"policy","decision":"allow","domain":"allowed.example","dns_query_type":"A","dns_response_code":"NOERROR","resolved_ips":["192.0.2.1","2001:db8::1"]}`},
		{"Empty", Event{}, false, `{"opensandbox.event":"egress.audit.stream","reason":""}`},
		{"UnknownLayer", Event{Layer: "synthetic", Reason: "synthetic"}, false, `{"opensandbox.event":"egress.audit.stream","reason":"synthetic"}`},
		{"DependentOmissions", gated, false, `{"opensandbox.event":"egress.audit.stream","reason":""}`},
		{"ValidZeroDestination", zeroL4, false, `{"opensandbox.event":"egress.audit.connection","reason":"","proto":"","dst_ip":"::","dst_port":0,"dns_seen":false,"rule":"synthetic-rule","rule_source":""}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var want map[string]any
			decoder := json.NewDecoder(bytes.NewBufferString(tc.want))
			decoder.UseNumber()
			require.NoError(t, decoder.Decode(&want))
			if tc.identified {
				want["boot_id"] = "synthetic-boot"
				want["seq"] = json.Number("9007199254740993")
				want["observed_at"] = "2026-01-01T20:04:05.123456789Z"
			}
			require.Equal(t, want, logSinkRecord(t, tc.event))
		})
	}
}

func TestLogSinkScratchReuseDoesNotRetainEvent(t *testing.T) {
	var output bytes.Buffer
	sink := newJSONLogSink(&output)
	answers := []string{"192.0.2.1"}
	coverage := []string{LayerDNS, LayerL4}
	sink.Emit(Event{
		Layer: LayerDNS, Reason: ReasonPolicy, Domain: "first.example",
		ResolvedIPs: answers, Coverage: coverage, Detail: "synthetic detail", Stats: &Stats{Detailed: 7},
	})
	// Output equality alone cannot detect a stale reference held by the
	// reusable scratch. Check this memory-lifetime invariant explicitly.
	for _, field := range sink.fields {
		require.Equal(t, zap.Field{}, field, "scratch must not retain encoded strings or slice interfaces")
	}
	answers[0], coverage[0] = "192.0.2.99", "changed"
	sink.Emit(Event{BootID: "second-boot"})
	sink.Emit(Event{})
	records := logSinkRecords(t, output.Bytes())
	require.Len(t, records, 3)
	require.Equal(t, []any{"192.0.2.1"}, records[0]["resolved_ips"])
	require.Equal(t, []any{"dns", "l4"}, records[0]["coverage"])
	require.Equal(t, "first.example", records[0]["domain"])
	require.Equal(t, map[string]any{
		"opensandbox.event": EventStream, "reason": "", "boot_id": "second-boot", "seq": json.Number("0"),
	}, records[1])
	require.Equal(t, map[string]any{"opensandbox.event": EventStream, "reason": ""}, records[2])
	for _, field := range sink.fields {
		require.Equal(t, zap.Field{}, field)
	}
}
