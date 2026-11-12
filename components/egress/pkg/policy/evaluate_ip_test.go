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

package policy

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestEvaluateIP_DenyBeatsAllow(t *testing.T) {
	p, err := ParsePolicy(`{"defaultAction":"allow","egress":[{"action":"allow","target":"203.0.113.0/24"},{"action":"deny","target":"203.0.113.10"}]}`)
	require.NoError(t, err)
	require.Equal(t, ActionDeny, p.EvaluateIP(netip.MustParseAddr("203.0.113.10")))
	require.Equal(t, ActionAllow, p.EvaluateIP(netip.MustParseAddr("203.0.113.11")))
	require.Equal(t, ActionAllow, p.EvaluateIP(netip.MustParseAddr("198.51.100.1")))
}

func TestEvaluateIP_DefaultDenyNeedsAllow(t *testing.T) {
	p, err := ParsePolicy(`{"defaultAction":"deny","egress":[{"action":"allow","target":"1.1.1.1"}]}`)
	require.NoError(t, err)
	require.Equal(t, ActionAllow, p.EvaluateIP(netip.MustParseAddr("1.1.1.1")))
	require.Equal(t, ActionDeny, p.EvaluateIP(netip.MustParseAddr("8.8.8.8")))
}

func TestEvaluateIP_IgnoresPortScopedRules(t *testing.T) {
	p, err := ParsePolicy(`{"defaultAction":"deny","egress":[{"action":"allow","target":"1.1.1.1","ports":[443]}]}`)
	require.NoError(t, err)
	require.Equal(t, ActionDeny, p.EvaluateIP(netip.MustParseAddr("1.1.1.1")))
}

func TestMatchIPRule_FirstPortlessRuleOfAction(t *testing.T) {
	p, err := ParsePolicy(`{"defaultAction":"deny","egress":[
		{"action":"allow","target":"203.0.113.10","ports":[443]},
		{"action":"allow","target":"203.0.113.0/24"},
		{"action":"deny","target":"203.0.113.10"},
		{"action":"allow","target":"203.0.113.10"},
		{"action":"allow","target":"example.com"}]}`)
	require.NoError(t, err)
	addr := netip.MustParseAddr("203.0.113.10")

	i, ok := p.MatchIPRule(ActionAllow, addr)
	require.True(t, ok)
	require.Equal(t, 1, i, "port-scoped rule is skipped; first portless allow wins")
	i, ok = p.MatchIPRule(ActionDeny, addr)
	require.True(t, ok)
	require.Equal(t, 2, i)
	_, ok = p.MatchIPRule(ActionAllow, netip.MustParseAddr("198.51.100.1"))
	require.False(t, ok)
	i, ok = p.MatchIPRule(ActionAllow, netip.MustParseAddr("::ffff:203.0.113.10"))
	require.True(t, ok, "v4-mapped addresses match their v4 rule")
	require.Equal(t, 1, i)
}

func TestMatchPortRule_TargetAndPorts(t *testing.T) {
	p, err := ParsePolicy(`{"defaultAction":"deny","egress":[
		{"action":"deny","target":"10.0.0.0/8"},
		{"action":"deny","target":"198.51.100.0/24","ports":[22]},
		{"action":"deny","ports":[25,465]},
		{"action":"allow","target":"198.51.100.7","ports":[443]}]}`)
	require.NoError(t, err)

	i, ok := p.MatchPortRule(ActionDeny, netip.MustParseAddr("198.51.100.9"), 22)
	require.True(t, ok)
	require.Equal(t, 1, i)
	i, ok = p.MatchPortRule(ActionDeny, netip.MustParseAddr("192.0.2.1"), 465)
	require.True(t, ok, "targetless port rule covers every destination")
	require.Equal(t, 2, i)
	_, ok = p.MatchPortRule(ActionDeny, netip.MustParseAddr("192.0.2.1"), 22)
	require.False(t, ok, "port 22 rule is scoped to its CIDR")
	i, ok = p.MatchPortRule(ActionAllow, netip.MustParseAddr("198.51.100.7"), 443)
	require.True(t, ok)
	require.Equal(t, 3, i)
	_, ok = p.MatchPortRule(ActionDeny, netip.MustParseAddr("10.1.2.3"), 80)
	require.False(t, ok, "portless rules are not port rules")
}

func TestMatchPortRule_PortRanges(t *testing.T) {
	p := MergeAlwaysOverlay(DefaultDenyPolicy(), []EgressRule{{
		Action:     ActionDeny,
		targetKind: targetPortOnly,
		PortRanges: []PortRange{{Lo: 1, Hi: 79}, {Lo: 81, Hi: 442}},
	}}, nil)
	i, ok := p.MatchPortRule(ActionDeny, netip.MustParseAddr("192.0.2.1"), 22)
	require.True(t, ok)
	require.Equal(t, 0, i)
	_, ok = p.MatchPortRule(ActionDeny, netip.MustParseAddr("192.0.2.1"), 80)
	require.False(t, ok)
}
