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

//go:build linux

package nftables

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/alibaba/opensandbox/egress/pkg/policy"
	"github.com/stretchr/testify/require"
)

// TestNftEstablishedDropKernelRuleOrder loads a tightened policy with
// dropEstablished into a real kernel table and checks rule order in the
// loaded chain, which script-string assertions cannot prove.
func TestNftEstablishedDropKernelRuleOrder(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if !isolatedNftTest(t, ctx) {
		return
	}
	m := NewManagerWithOptions(Options{})
	oldPol := mustPolicy(t, `{"defaultAction":"deny","egress":[
		{"action":"allow","target":"203.0.113.10"},
		{"action":"allow","target":"198.51.100.0/24"},
		{"action":"allow","target":"cdn.example.com"}]}`)
	newPol := mustPolicy(t, `{"defaultAction":"deny","egress":[
		{"action":"deny","target":"198.51.100.7"},
		{"action":"allow","target":"198.51.100.0/24"},
		{"action":"allow","target":"cdn.example.com"}]}`)
	require.NoError(t, m.ApplyStatic(ctx, oldPol))
	require.NoError(t, m.AddResolvedDomain(ctx, "cdn.example.com", []ResolvedIP{{Addr: netip.MustParseAddr("192.0.2.20"), TTL: time.Minute}}))

	_, err := m.ApplyStaticComputingEstablishedDrops(ctx, oldPol, newPol)
	require.NoError(t, err)
	// The shared-CDN case: an allowed domain re-resolves to the denied IP.
	require.NoError(t, m.AddResolvedDomain(ctx, "cdn.example.com", []ResolvedIP{{Addr: netip.MustParseAddr("198.51.100.7"), TTL: time.Minute}}))

	out, err := exec.CommandContext(ctx, "nft", "list", "chain", "inet", tableName, chainName).CombinedOutput()
	require.NoError(t, err, "%s", out)
	var rules []string
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "table ") || strings.HasPrefix(line, "chain ") ||
			strings.HasPrefix(line, "type ") || line == "}" {
			continue
		}
		rules = append(rules, line)
	}
	index := func(rule string) int {
		t.Helper()
		for i, r := range rules {
			if r == rule {
				return i
			}
		}
		require.Failf(t, "rule not loaded", "%q not in kernel chain:\n%s", rule, out)
		return -1
	}

	denyDrop := index("ip daddr 198.51.100.7 ct state established,related drop")
	removedDrop := index("ip daddr 203.0.113.10 ct state established,related drop")
	dynAccept := index("ip daddr @dyn_allow_v4 ct state established,related accept")
	staticAccept := index("ip daddr @allow_v4 ct state established,related accept")
	blanket := index("ct state established,related accept")

	require.Less(t, index("meta mark 0x00000001 accept"), denyDrop, "infra accepts stay ahead of teardown")
	require.Less(t, denyDrop, dynAccept, "explicit deny must precede DNS-learned established accept")
	require.Less(t, denyDrop, staticAccept)
	require.Less(t, dynAccept, removedDrop, "DNS-learned accept must be able to unpin a removed-allow drop")
	require.Less(t, staticAccept, removedDrop)
	require.Less(t, removedDrop, blanket, "teardown must precede the blanket established accept")
}

// Plain reload must neither lift an existing TCP block nor add a new one.
// Check both streams immediately after DNS installation, without a reload.
func TestNftFirstDNSGrantAfterPlainReload(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	const host = "198.18.0.2"
	if !isolatedNftTest(t, ctx) {
		return
	}
	startWithdrawalEchoPeer(t, ctx, "2443", "28443")
	const domain = `{"action":"allow","target":"cdn.example"}`
	const firstDNS = `{"egress":[` + domain + `,{"action":"allow","ports":[2443]}]}`
	const denyBoth = `{"action":"deny","target":"198.18.0.0/24","ports":[2443,28443]}`
	old := mustPolicy(t, `{"defaultAction":"allow"}`)
	for _, tc := range []struct {
		name, first, reload string
		grantDNS            bool
	}{
		{"explicit-to-implicit", `{"egress":[{"action":"allow","ports":[2443,28443]},{"action":"deny","target":"198.18.0.0/24","ports":[28443]}]}`, `{"defaultAction":"deny"}`, false},
		{"CIDR-allow", firstDNS, `{"egress":[` + domain + `,{"action":"allow","target":"198.18.0.0/24"},` + denyBoth + `]}`, true},
		{"port-only-allow", firstDNS, `{"egress":[` + domain + `,{"action":"allow","ports":[2443,28443]},` + denyBoth + `]}`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := NewManagerWithOptions(Options{})
			require.NoError(t, m.ApplyStatic(ctx, old))
			atOptIn := openWithdrawalStream(t, host, "28443")
			atReload := openWithdrawalStream(t, host, "28443")
			var atGrant net.Conn
			if tc.grantDNS {
				atGrant = openWithdrawalStream(t, host, "28443")
			}
			spared := openWithdrawalStream(t, host, "2443")
			_, err := m.ApplyStaticComputingEstablishedDrops(ctx, old, mustPolicy(t, tc.first))
			require.NoError(t, err)
			requireWithdrawalDrop(t, ctx, atOptIn, 2)
			require.NoError(t, withdrawalEcho(spared, 2))
			require.NoError(t, m.ApplyStatic(ctx, mustPolicy(t, tc.reload)))
			requireWithdrawalDrop(t, ctx, atReload, 3)
			require.NoError(t, withdrawalEcho(spared, 3))
			if !tc.grantDNS {
				return
			}
			require.NotContains(t, readKernelLeaseExpiry(t, ctx), host)
			require.NoError(t, m.AddResolvedDomain(ctx, "cdn.example", []ResolvedIP{{Addr: netip.MustParseAddr(host), TTL: time.Minute}}))
			require.Contains(t, readKernelLeaseExpiry(t, ctx), host)
			requireWithdrawalDrop(t, ctx, atGrant, 4)
			require.NoError(t, withdrawalEcho(spared, 4))
		})
	}
}

// A fragmented platform floor must not make an otherwise loadable replacement
// too large for a single kernel transaction after a pool of DNS grants is revoked.
func TestNftReloadFragmentedHostWithdrawals(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	if !isolatedNftTest(t, ctx) {
		return
	}
	startWithdrawalEchoPeer(t, ctx, "10002", "10003")
	ports := make([]policy.PortRange, 256)
	for i := range ports {
		ports[i] = policy.PortRange{Lo: 3*i + 2, Hi: 3*i + 3}
	}
	floor := policy.NewPortFloorDenyRule(ports)
	withFloor := func(rules string) *policy.NetworkPolicy {
		p := mustPolicy(t, `{"egress":[`+rules+`]}`)
		p.Egress = append(p.Egress, floor)
		return p
	}
	old := withFloor(`{"action":"allow","target":"*.example.com"}`)
	m := NewManagerWithOptions(Options{})
	require.NoError(t, m.ApplyStatic(ctx, old))
	pool := withdrawalDNSPool(1024)
	rules := make([]string, len(pool))
	for i, ip := range pool {
		rules[i] = fmt.Sprintf(`{"action":"allow","target":"%s","ports":[%d]}`, ip.Addr, 10000+i)
	}
	for i := 0; i < len(pool); i += 64 {
		require.NoError(t, m.AddResolvedDomain(ctx, fmt.Sprintf("pool%d.example.com", i/64), pool[i:i+64]))
	}
	require.Len(t, readKernelLeaseExpiry(t, ctx), 1024)
	// All four connections are admitted by DNS before opt-in. A new dial after
	// replacement would only exercise the new-connection rules, not the tuple drop.
	const a, b = "198.18.0.2", "198.18.0.3"
	aOwn, aCross := openWithdrawalStream(t, a, "10002"), openWithdrawalStream(t, a, "10003")
	bOwn, bCross := openWithdrawalStream(t, b, "10003"), openWithdrawalStream(t, b, "10002")
	optIn := withFloor(`{"action":"allow","target":"marker.example.com"}`)
	_, err := m.ApplyStaticComputingEstablishedDrops(ctx, old, optIn)
	require.NoError(t, err)
	require.Empty(t, readKernelLeaseExpiry(t, ctx), "opt-in must retire the seeded pool")
	marker := netip.MustParseAddr("192.0.2.7")
	require.NoError(t, m.AddResolvedDomain(ctx, "marker.example.com", []ResolvedIP{{Addr: marker, TTL: time.Minute}}))
	require.Contains(t, readKernelLeaseExpiry(t, ctx), marker.String())
	require.NoError(t, m.ApplyStatic(ctx, withFloor(strings.Join(rules, ","))))
	require.Empty(t, readKernelLeaseExpiry(t, ctx), "the replacement must retire the marker in the kernel")
	require.NoError(t, withdrawalEcho(aOwn, 2))
	require.NoError(t, withdrawalEcho(bOwn, 3))
	requireWithdrawalDrop(t, ctx, aCross, 4)
	requireWithdrawalDrop(t, ctx, bCross, 5)
}
