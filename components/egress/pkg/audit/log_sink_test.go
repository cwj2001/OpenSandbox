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
	aggregate := dns
	aggregate.Count, aggregate.WindowStart, aggregate.WindowEnd = 123, at.Add(-time.Second), at
	overflow := common
	overflow.Layer, overflow.Reason, overflow.Decision = LayerDNS, ReasonPolicy, DecisionDeny
	overflow.Count, overflow.WindowStart, overflow.WindowEnd = 9007199254740993, at.Add(-time.Minute), at
	stats := &Stats{Detailed: 9007199254740993, Aggregated: 27}
	heartbeat := common
	heartbeat.Layer, heartbeat.Reason, heartbeat.Stats = LayerAudit, ReasonHeartbeat, stats
	heartbeat.Coverage = []string{LayerDNS}
	stopped := heartbeat
	stopped.Reason, stopped.Stats = ReasonStopped, &Stats{}
	started := common
	started.Layer, started.Reason, started.Coverage = LayerAudit, ReasonStarted, []string{LayerDNS}
	zeroEnd := aggregate
	zeroEnd.WindowEnd = time.Time{}

	gated := Event{Seq: 17, WindowEnd: at, ResolvedIPs: []string{}, Coverage: []string{}}

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
		{"DNSAggregate", aggregate, true, `{"opensandbox.event":"egress.audit.dns","reason":"policy","decision":"allow","domain":"allowed.example","dns_query_type":"A","dns_response_code":"NOERROR","resolved_ips":["192.0.2.1","2001:db8::1"],"count":123,"window_start":"2026-01-01T20:04:04.123456789Z","window_end":"2026-01-01T20:04:05.123456789Z"}`},
		{"OverflowAggregate", overflow, true, `{"opensandbox.event":"egress.audit.dns","reason":"policy","decision":"deny","count":9007199254740993,"window_start":"2026-01-01T20:03:05.123456789Z","window_end":"2026-01-01T20:04:05.123456789Z"}`},
		{"Heartbeat", heartbeat, true, `{"opensandbox.event":"egress.audit.stream","reason":"heartbeat","coverage":["dns"],"detailed":9007199254740993,"aggregated":27}`},
		{"Stopped", stopped, true, `{"opensandbox.event":"egress.audit.stream","reason":"stopped","coverage":["dns"],"detailed":0,"aggregated":0}`},
		{"Started", started, true, `{"opensandbox.event":"egress.audit.stream","reason":"started","coverage":["dns"]}`},
		{"ZeroWindowEnd", zeroEnd, true, `{"opensandbox.event":"egress.audit.dns","reason":"policy","decision":"allow","domain":"allowed.example","dns_query_type":"A","dns_response_code":"NOERROR","resolved_ips":["192.0.2.1","2001:db8::1"],"count":123,"window_start":"2026-01-01T20:04:04.123456789Z","window_end":"0001-01-01T00:00:00Z"}`},
		{"Empty", Event{}, false, `{"opensandbox.event":"egress.audit.stream","reason":""}`},
		{"UnknownLayer", Event{Layer: "synthetic", Reason: "synthetic"}, false, `{"opensandbox.event":"egress.audit.stream","reason":"synthetic"}`},
		{"DependentOmissions", gated, false, `{"opensandbox.event":"egress.audit.stream","reason":""}`},
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
	coverage := []string{LayerDNS}
	sink.Emit(Event{
		Layer: LayerDNS, Reason: ReasonPolicy, Domain: "first.example",
		ResolvedIPs: answers, Coverage: coverage, Stats: &Stats{Detailed: 7},
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
	require.Equal(t, []any{"dns"}, records[0]["coverage"])
	require.Equal(t, "first.example", records[0]["domain"])
	require.Equal(t, map[string]any{
		"opensandbox.event": EventStream, "reason": "", "boot_id": "second-boot", "seq": json.Number("0"),
	}, records[1])
	require.Equal(t, map[string]any{"opensandbox.event": EventStream, "reason": ""}, records[2])
	for _, field := range sink.fields {
		require.Equal(t, zap.Field{}, field)
	}
}
