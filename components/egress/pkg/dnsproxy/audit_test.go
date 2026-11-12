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

package dnsproxy

import (
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"

	"github.com/alibaba/opensandbox/egress/pkg/audit"
	"github.com/alibaba/opensandbox/egress/pkg/constants"
	"github.com/alibaba/opensandbox/egress/pkg/policy"
)

type auditRecorder struct {
	mu        sync.Mutex
	events    []audit.Event
	collector *audit.Collector
}

func (r *auditRecorder) Emit(e audit.Event) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, e)
}

// dnsEvents closes the collector, which flushes the stream, and returns its
// DNS events without the per-run stamps.
func (r *auditRecorder) dnsEvents() []audit.Event {
	r.collector.Close(time.Second)
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []audit.Event
	for _, e := range r.events {
		if e.Layer == audit.LayerDNS {
			e.ObservedAt, e.BootID, e.Seq = time.Time{}, "", 0
			out = append(out, e)
		}
	}
	return out
}

func auditedProxy(t *testing.T) (*Proxy, *auditRecorder) {
	t.Helper()
	t.Setenv(constants.EnvNameserverExempt, "127.0.0.1")
	resetNameserverExemptCache(t)

	upstream := startInfraUpstream(t)
	user, err := policy.ParsePolicy(`{"defaultAction":"deny","egress":[{"action":"allow","target":"pypi.org"}]}`)
	require.NoError(t, err)
	alwaysDeny, err := policy.ParseValidatedEgressRule(policy.ActionDeny, "10.96.0.0/12")
	require.NoError(t, err)
	proxy := &Proxy{
		upstreams:               []string{upstream},
		activeUpstreams:         []string{upstream},
		upstreamExchangeTimeout: time.Second,
		userPolicy:              user,
		alwaysDeny:              []policy.EgressRule{alwaysDeny},
	}
	proxy.refreshEffectivePolicy()
	sink := &auditRecorder{}
	sink.collector = audit.NewCollector(sink, proxy)
	t.Cleanup(func() { sink.collector.Close(time.Second) })
	proxy.SetAudit(sink.collector)
	return proxy, sink
}

func query(t *testing.T, proxy *Proxy, name string, qtype uint16) *dns.Msg {
	t.Helper()
	w := &fakeRespWriter{remote: addrFromIP("10.0.0.9")}
	q := new(dns.Msg)
	q.SetQuestion(name, qtype)
	proxy.serveDNS(w, q)
	require.Len(t, w.msgs, 1)
	return w.msgs[0]
}

func TestAuditRecordsAllowAndDeny(t *testing.T) {
	proxy, sink := auditedProxy(t)

	query(t, proxy, "PyPI.org.", dns.TypeA)
	query(t, proxy, "evil.example.", dns.TypeAAAA)

	require.Equal(t, []audit.Event{
		{
			Layer: audit.LayerDNS, Decision: audit.DecisionAllow, Reason: audit.ReasonPolicy, Domain: "pypi.org",
			QueryType: "A", ResponseCode: "NOERROR", ResolvedIPs: []string{"10.9.8.7"},
		},
		{
			Layer: audit.LayerDNS, Decision: audit.DecisionDeny, Reason: audit.ReasonPolicy, Domain: "evil.example",
			QueryType: "AAAA", ResponseCode: "NXDOMAIN",
		},
	}, sink.dnsEvents())
}

func TestAuditUnknownSourceIsDeny(t *testing.T) {
	proxy, sink := auditedProxy(t)
	proxy.SetQueryPolicySelector(func(netip.Addr) (*QueryPolicy, string) { return nil, "no subject" })
	query(t, proxy, "pypi.org.", dns.TypeA)
	events := sink.dnsEvents()
	require.Len(t, events, 1)
	require.Equal(t, audit.DecisionDeny, events[0].Decision)
	require.Equal(t, audit.ReasonUnknownSource, events[0].Reason)
}

func TestAuditUpstreamFailureIsAllowedServfail(t *testing.T) {
	proxy, sink := auditedProxy(t)
	proxy.upstreams = []string{"127.0.0.1:1"}
	proxy.activeUpstreams = []string{"127.0.0.1:1"}
	proxy.upstreamExchangeTimeout = 200 * time.Millisecond
	query(t, proxy, "pypi.org.", dns.TypeA)
	events := sink.dnsEvents()
	require.Len(t, events, 1)
	require.Equal(t, audit.DecisionAllow, events[0].Decision, "policy allowed it; the upstream failed")
	require.Equal(t, "SERVFAIL", events[0].ResponseCode)
	require.Empty(t, events[0].ResolvedIPs)
}

func TestAuditSkipsInfraDomainsButNotLogSkip(t *testing.T) {
	proxy, sink := auditedProxy(t)
	proxy.SetInfraDomain("proxy.example.com", nil)
	proxy.SetLogSkip([]string{"pypi.org"})

	query(t, proxy, "proxy.example.com.", dns.TypeA)
	query(t, proxy, "pypi.org.", dns.TypeA)

	events := sink.dnsEvents()
	require.Len(t, events, 1, "infra names are not sandbox activity")
	require.Equal(t, "pypi.org", events[0].Domain, "log_skip.always only quiets egress.outbound")
}

func TestAuditOffByDefault(t *testing.T) {
	proxy, _ := auditedProxy(t)
	proxy.audit = nil
	require.NotPanics(t, func() { query(t, proxy, "pypi.org.", dns.TypeA) })
}

func TestEffectivePolicyCountsOverlay(t *testing.T) {
	proxy, _ := auditedProxy(t)
	p, platform := proxy.EffectivePolicy()
	require.Equal(t, 1, platform)
	require.Equal(t, "10.96.0.0/12", p.Egress[0].Target)
	require.Equal(t, "pypi.org", p.Egress[1].Target)
}
