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

package nftables

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"testing"

	"github.com/alibaba/opensandbox/egress/pkg/audit"
	"github.com/stretchr/testify/require"
)

const auditTestPolicy = `{"defaultAction":"deny","egress":[
	{"action":"allow","target":"pypi.org"},
	{"action":"allow","target":"1.1.1.1"},
	{"action":"deny","target":"2001:db8::/32"},
	{"action":"deny","ports":[25,465]},
	{"action":"allow","target":"203.0.113.0/24","ports":[443]}]}`

func auditTestOptions(group uint16) Options {
	return Options{
		BlockDoT:         true,
		BlockDoH443:      true,
		DoHBlocklistV4:   []string{"8.8.8.8"},
		MitmRedirectPort: 18081,
		UpstreamProxy:    &UpstreamProxyEndpoint{Port: 3128, UID: 1000, IPs: []netip.Addr{netip.MustParseAddr("192.0.2.9")}},
		AuditLogGroup:    group,
	}
}

func auditLogMarker() string {
	return fmt.Sprintf(" group %d\n", audit.NFLogGroup)
}

func isAuditLog(line string) bool {
	return strings.Contains(line+"\n", auditLogMarker()) && strings.Contains(line, " log prefix ")
}

// Removing the audit log rules must give back exactly the audit-off script:
// audit adds observation only, never a verdict or a reordering.
func TestBuildRulesetAuditOnlyAddsLogRules(t *testing.T) {
	for _, raw := range []string{auditTestPolicy, `{"defaultAction":"allow","egress":[{"action":"deny","target":"10.0.0.0/8"}]}`} {
		p := mustPolicy(t, raw)
		drops := EstablishedDrops{Addrs: []netip.Addr{netip.MustParseAddr("198.51.100.1")}}
		off, err := buildRuleset(p, auditTestOptions(0), drops)
		require.NoError(t, err)
		on, err := buildRuleset(p, auditTestOptions(audit.NFLogGroup), drops)
		require.NoError(t, err)
		require.NotContains(t, off, " log ")

		var kept []string
		for _, line := range strings.SplitAfter(on, "\n") {
			if !isAuditLog(line) {
				kept = append(kept, line)
			}
		}
		require.Equal(t, off, strings.Join(kept, ""))
	}
}

// Every new-connection verdict is preceded by a log rule with the same match
// and the matching decision; infrastructure and established-path rules never
// are.
func TestBuildRulesetAuditLogPrecedesEachVerdict(t *testing.T) {
	script, err := buildRuleset(mustPolicy(t, auditTestPolicy), auditTestOptions(audit.NFLogGroup), EstablishedDrops{})
	require.NoError(t, err)
	lines := strings.Split(strings.TrimSpace(script), "\n")
	rulePrefix := fmt.Sprintf("add rule inet %s %s ", tableName, chainName)

	logs := 0
	for i, line := range lines {
		if !isAuditLog(line) {
			continue
		}
		logs++
		require.Less(t, i+1, len(lines), "log rule must not be last under default deny")
		next := lines[i+1]
		match, _, found := strings.Cut(strings.TrimPrefix(line, rulePrefix), "meta l4proto { tcp, udp } ct state new ")
		require.True(t, found, line)
		verdict := "accept"
		if strings.Contains(line, `"osb-audit:d:`) {
			verdict = "drop"
		}
		require.Equal(t, rulePrefix+match+verdict, next, "log rule must sit directly ahead of its verdict")
	}

	verdicts := 0
	for _, line := range lines {
		if !strings.HasPrefix(line, rulePrefix) || isAuditLog(line) {
			continue
		}
		infra := strings.Contains(line, "meta mark ") || strings.Contains(line, `oifname "lo"`) ||
			strings.Contains(line, "icmpv6") || strings.Contains(line, " 127.0.0.1 ") ||
			strings.Contains(line, " ::1 ") || strings.Contains(line, "meta skuid") ||
			strings.Contains(line, "ct state established,related")
		if !infra {
			verdicts++
		}
	}
	require.Equal(t, verdicts, logs, "every new-connection verdict needs exactly one log rule")

	for _, want := range []string{
		`tcp dport 853 meta l4proto { tcp, udp } ct state new log prefix "osb-audit:d:dot"`,
		`ip daddr @doh_block_v4 tcp dport 443 meta l4proto { tcp, udp } ct state new log prefix "osb-audit:d:doh"`,
		`tcp dport { 25, 465 } meta l4proto { tcp, udp } ct state new log prefix "osb-audit:d:port_rule"`,
		`ip daddr @deny_v4 meta l4proto { tcp, udp } ct state new log prefix "osb-audit:d:ip_rule"`,
		`ip daddr 203.0.113.0/24 tcp dport { 443 } meta l4proto { tcp, udp } ct state new log prefix "osb-audit:a:port_rule"`,
		`ip daddr @dyn_allow_v4 meta l4proto { tcp, udp } ct state new log prefix "osb-audit:a:dns_lease"`,
		`ip daddr @allow_v4 meta l4proto { tcp, udp } ct state new log prefix "osb-audit:a:ip_rule"`,
	} {
		require.Contains(t, script, rulePrefix+want)
	}
	require.Equal(t, rulePrefix+"drop", lines[len(lines)-1])
	require.True(t, strings.HasSuffix(lines[len(lines)-2], `log prefix "osb-audit:d:default" group 7391`), lines[len(lines)-2])
}

// Under default allow the chain policy accepts what falls off the end; the
// tail log rule is the only record of that verdict.
func TestBuildRulesetAuditDefaultAllowTail(t *testing.T) {
	p := mustPolicy(t, `{"defaultAction":"allow","egress":[{"action":"deny","target":"10.0.0.0/8"}]}`)
	script, err := buildRuleset(p, Options{AuditLogGroup: audit.NFLogGroup}, EstablishedDrops{})
	require.NoError(t, err)
	lines := strings.Split(strings.TrimSpace(script), "\n")
	require.Equal(t, fmt.Sprintf(`add rule inet %s %s meta l4proto { tcp, udp } ct state new log prefix "osb-audit:a:default" group 7391`, tableName, chainName),
		lines[len(lines)-1])
	require.Contains(t, script, "policy accept;")
}

func TestBuildRulesetAuditPrefixesRoundTrip(t *testing.T) {
	script, err := buildRuleset(mustPolicy(t, auditTestPolicy), auditTestOptions(audit.NFLogGroup), EstablishedDrops{})
	require.NoError(t, err)
	for _, line := range strings.Split(script, "\n") {
		if !isAuditLog(line) {
			continue
		}
		_, quoted, _ := strings.Cut(line, "log prefix ")
		prefix, _, _ := strings.Cut(strings.TrimPrefix(quoted, `"`), `"`)
		require.LessOrEqual(t, len(prefix), 127, "kernel NFLOG prefix limit")
		require.True(t, strings.HasPrefix(prefix, "osb-audit:"), prefix)
	}
}

func TestProbeAuditLogUsesTheRuleStatementOffPath(t *testing.T) {
	var script string
	err := probeAuditLog(context.Background(), func(_ context.Context, s string) ([]byte, error) {
		script = s
		return nil, nil
	}, audit.NFLogGroup)
	require.NoError(t, err)
	require.Contains(t, script, "add chain inet opensandbox_audit_probe probe\n", "a hookless chain never sees packets")
	require.NotContains(t, script, "hook")
	require.Contains(t, script, auditLogStatement(audit.NFLogGroup, audit.DecisionAllow, audit.ReasonDefault))
	require.True(t, strings.HasSuffix(script, "delete table inet opensandbox_audit_probe\n"))

	err = probeAuditLog(context.Background(), func(context.Context, string) ([]byte, error) {
		return []byte("Error: Could not process rule: No such file or directory"), errors.New("exit status 1")
	}, audit.NFLogGroup)
	require.ErrorContains(t, err, "kernel rejected the audit log rule")
	require.ErrorContains(t, err, "No such file or directory")
}
