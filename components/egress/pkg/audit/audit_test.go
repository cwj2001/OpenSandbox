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
	"net/netip"
	"testing"

	slogger "github.com/alibaba/opensandbox/internal/logger"
	"github.com/stretchr/testify/require"
)

func TestParseLevel(t *testing.T) {
	for raw, want := range map[string]Level{"": LevelOff, "off": LevelOff, " DNS ": LevelDNS, "conn": LevelConn} {
		got, err := ParseLevel(raw)
		require.NoError(t, err, raw)
		require.Equal(t, want, got, raw)
	}
	_, err := ParseLevel("l7")
	require.Error(t, err)
}

func TestNFLogPrefixRoundTrip(t *testing.T) {
	for reason := range l4Reasons {
		for _, decision := range []string{DecisionAllow, DecisionDeny} {
			d, r, ok := parseNFLogPrefix(NFLogPrefix(decision, reason))
			require.True(t, ok)
			require.Equal(t, decision, d)
			require.Equal(t, reason, r)
		}
	}
	for _, foreign := range []string{"", "osb-audit:", "osb-audit:x:default", "osb-audit:d:bogus", "other:d:default", "osb-audit:d"} {
		_, _, ok := parseNFLogPrefix(foreign)
		require.False(t, ok, foreign)
	}
}

// capturingLogger records the fields of every With call; LogSink makes one
// With call per event.
type capturingLogger struct{ records []map[string]any }

func (c *capturingLogger) Debugf(string, ...any) {}
func (c *capturingLogger) Infof(string, ...any)  {}
func (c *capturingLogger) Warnf(string, ...any)  {}
func (c *capturingLogger) Errorf(string, ...any) {}
func (c *capturingLogger) Sync() error           { return nil }
func (c *capturingLogger) Named(string) slogger.Logger {
	return c
}
func (c *capturingLogger) With(fields ...slogger.Field) slogger.Logger {
	record := map[string]any{}
	for _, f := range fields {
		record[f.Key] = f.Value
	}
	c.records = append(c.records, record)
	return c
}

func TestLogSinkFields(t *testing.T) {
	logger := &capturingLogger{}
	sink := NewLogSink(logger)

	sink.Emit(Event{
		Layer: LayerL4, Decision: DecisionDeny, Reason: ReasonIPRule,
		Protocol: "tcp", DestinationIP: netip.MustParseAddr("10.96.0.10"), DestinationPort: 5432,
		Rule: "10.96.0.0/12", RuleSource: "platform",
	})
	sink.Emit(Event{
		Layer: LayerDNS, Decision: DecisionAllow, Reason: ReasonPolicy, Domain: "pypi.org",
		QueryType: "A", ResponseCode: "NOERROR", ResolvedIPs: []string{"151.101.0.223"},
	})

	require.Len(t, logger.records, 2)
	require.Equal(t, map[string]any{
		"opensandbox.event": "egress.audit.connection",
		"decision":          "deny",
		"reason":            "ip_rule",
		"proto":             "tcp",
		"dst_ip":            "10.96.0.10",
		"dst_port":          uint16(5432),
		"dns_seen":          false,
		"rule":              "10.96.0.0/12",
		"rule_source":       "platform",
	}, logger.records[0])
	require.Equal(t, map[string]any{
		"opensandbox.event": "egress.audit.dns",
		"decision":          "allow",
		"reason":            "policy",
		"domain":            "pypi.org",
		"dns_query_type":    "A",
		"dns_response_code": "NOERROR",
		"resolved_ips":      []string{"151.101.0.223"},
	}, logger.records[1])
}

func TestEventNames(t *testing.T) {
	require.Equal(t, "egress.audit.dns", Event{Layer: LayerDNS}.Name())
	require.Equal(t, "egress.audit.connection", Event{Layer: LayerL4}.Name())
	require.Equal(t, "egress.audit.stream", Event{Layer: LayerAudit}.Name())
}
