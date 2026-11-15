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
	"io"
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
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

func newJSONLogSink(output io.Writer) *LogSink {
	config := zap.NewProductionEncoderConfig()
	config.EncodeTime = zapcore.ISO8601TimeEncoder
	logger := zap.New(zapcore.NewCore(zapcore.NewJSONEncoder(config), zapcore.AddSync(output), zapcore.InfoLevel))
	return NewLogSink(logger.With(
		zap.String("sandbox_id", "synthetic-sandbox"),
		zap.String("synthetic.region", "test-region"),
	).Named("opensandbox.egress.audit"))
}

func logSinkRecords(t *testing.T, payload []byte) []map[string]any {
	t.Helper()
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.UseNumber()
	var records []map[string]any
	for {
		var record map[string]any
		err := decoder.Decode(&record)
		if err == io.EOF {
			return records
		}
		require.NoError(t, err)
		timestamp, ok := record["ts"].(string)
		require.True(t, ok, "the outer timestamp remains a production ISO8601 string")
		_, err = time.Parse("2006-01-02T15:04:05.000Z0700", timestamp)
		require.NoError(t, err)
		for key, value := range map[string]string{
			"level": "info", "msg": "egress audit", "logger": "opensandbox.egress.audit",
			"sandbox_id": "synthetic-sandbox", "synthetic.region": "test-region",
		} {
			require.Equal(t, value, record[key], key)
			delete(record, key)
		}
		delete(record, "ts")
		records = append(records, record)
	}
}

func logSinkRecord(t *testing.T, event Event) map[string]any {
	t.Helper()
	var output bytes.Buffer
	newJSONLogSink(&output).Emit(event)
	records := logSinkRecords(t, output.Bytes())
	require.Len(t, records, 1)
	return records[0]
}

func TestLogSinkFields(t *testing.T) {
	var output bytes.Buffer
	sink := newJSONLogSink(&output)
	sink.Emit(Event{
		Layer: LayerL4, Decision: DecisionDeny, Reason: ReasonIPRule,
		Protocol: "tcp", DestinationIP: netip.MustParseAddr("10.96.0.10"), DestinationPort: 5432,
		Rule: "10.96.0.0/12", RuleSource: "platform",
	})
	sink.Emit(Event{
		Layer: LayerDNS, Decision: DecisionAllow, Reason: ReasonPolicy, Domain: "pypi.org",
		QueryType: "A", ResponseCode: "NOERROR", ResolvedIPs: []string{"151.101.0.223"},
	})

	records := logSinkRecords(t, output.Bytes())
	require.Len(t, records, 2)
	require.Equal(t, map[string]any{
		"opensandbox.event": "egress.audit.connection",
		"decision":          "deny",
		"reason":            "ip_rule",
		"proto":             "tcp",
		"dst_ip":            "10.96.0.10",
		"dst_port":          json.Number("5432"),
		"dns_seen":          false,
		"rule":              "10.96.0.0/12",
		"rule_source":       "platform",
	}, records[0])
	require.Equal(t, map[string]any{
		"opensandbox.event": "egress.audit.dns",
		"decision":          "allow",
		"reason":            "policy",
		"domain":            "pypi.org",
		"dns_query_type":    "A",
		"dns_response_code": "NOERROR",
		"resolved_ips":      []any{"151.101.0.223"},
	}, records[1])
}

func TestEventNames(t *testing.T) {
	require.Equal(t, "egress.audit.dns", Event{Layer: LayerDNS}.Name())
	require.Equal(t, "egress.audit.connection", Event{Layer: LayerL4}.Name())
	require.Equal(t, "egress.audit.stream", Event{Layer: LayerAudit}.Name())
}
