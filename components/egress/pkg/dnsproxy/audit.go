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
	"strconv"

	"github.com/miekg/dns"

	"github.com/alibaba/opensandbox/egress/pkg/audit"
	"github.com/alibaba/opensandbox/egress/pkg/policy"
	"github.com/alibaba/opensandbox/egress/pkg/telemetry"
)

// SetAudit wires the optional audit collector. Register before Start.
func (p *Proxy) SetAudit(c *audit.Collector) {
	p.audit = c
}

// EffectivePolicy returns the merged sidecar policy and how many of its
// leading rules come from the always overlay (always-deny, then always-allow).
func (p *Proxy) EffectivePolicy() (*policy.NetworkPolicy, int) {
	p.policyMu.RLock()
	defer p.policyMu.RUnlock()
	return p.effectivePolicy, len(p.alwaysDeny) + len(p.alwaysAllow)
}

// recordAudit reports a decided query. Unlike the egress.outbound line it
// ignores log_skip.always, and it covers denials. Infrastructure names
// resolve outside the sandbox policy and are not sandbox activity.
func (p *Proxy) recordAudit(r, resp *dns.Msg, stage string) {
	if p.audit == nil || stage == telemetry.DNSReplyStageMalformed || len(r.Question) == 0 {
		return
	}
	q := r.Question[0]
	host := normalizeDNSHost(q.Name)
	if p.infraCallback(host) != nil {
		return
	}
	rec := audit.DNSRecord{
		Domain:       host,
		Decision:     audit.DecisionAllow,
		Reason:       audit.ReasonPolicy,
		QueryType:    dns.Type(q.Qtype).String(),
		ResponseCode: rcodeString(resp.Rcode),
	}
	switch stage {
	case telemetry.DNSReplyStageDeny:
		rec.Decision = audit.DecisionDeny
	case telemetry.DNSReplyStageUnknownSource:
		rec.Decision = audit.DecisionDeny
		rec.Reason = audit.ReasonUnknownSource
	case telemetry.DNSReplyStageAnswer:
		for i, ip := range extractResolvedIPs(resp) {
			rec.Answers = append(rec.Answers, ip.Addr)
			if i == 0 || ip.TTL < rec.TTL {
				rec.TTL = ip.TTL
			}
		}
	}
	p.audit.RecordDNS(rec)
}

func rcodeString(rcode int) string {
	if s, ok := dns.RcodeToString[rcode]; ok {
		return s
	}
	return "RCODE" + strconv.Itoa(rcode)
}

var _ audit.PolicyView = (*Proxy)(nil)
