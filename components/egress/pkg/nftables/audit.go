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
	"fmt"
	"strings"

	"github.com/alibaba/opensandbox/egress/pkg/audit"
)

// The audit rules carry no rate limit on purpose: a kernel limiter would drop
// copies silently. Every conntrack-new packet is copied; the sidecar counts
// delivery losses exactly (NFLOG sequence numbers) and aggregates what is
// over its event budget.
const auditProbeTable = "opensandbox_audit_probe"

// writeVerdict emits one new-connection verdict rule. With audit enabled it
// is preceded by a log rule with the same match: that rule has no verdict, so
// evaluation falls through to the verdict rule unchanged, and the NFLOG copy
// carries the decision and reason in its prefix (NFLOG does not report the
// verdict). Only conntrack-new TCP/UDP packets are copied, one per attempt.
func writeVerdict(b *strings.Builder, opts Options, match, verdict, reason string) {
	if match != "" {
		match += " "
	}
	if opts.AuditLogGroup > 0 {
		decision := audit.DecisionAllow
		if verdict == "drop" {
			decision = audit.DecisionDeny
		}
		writeAuditLog(b, opts, match, decision, reason)
	}
	fmt.Fprintf(b, "add rule inet %s %s %s%s\n", tableName, chainName, match, verdict)
}

func writeAuditLog(b *strings.Builder, opts Options, match, decision, reason string) {
	fmt.Fprintf(b, "add rule inet %s %s %s%s\n", tableName, chainName, match, auditLogStatement(opts.AuditLogGroup, decision, reason))
}

func auditLogStatement(group uint16, decision, reason string) string {
	return fmt.Sprintf("meta l4proto { tcp, udp } ct state new log prefix %q group %d",
		audit.NFLogPrefix(decision, reason), group)
}

// ProbeAuditLog checks that the kernel accepts the audit log statement
// (nft_log, conntrack). Rules are validated when added, so one
// transaction adds a hookless chain holding the statement and deletes it
// again: nothing reaches the data path. Run it before enabling audit rules: a
// statement the kernel rejects would fail every static apply and, since
// enforcement is fail-closed, take the sidecar down.
func ProbeAuditLog(ctx context.Context, group uint16) error {
	return probeAuditLog(ctx, defaultRunner, group)
}

func probeAuditLog(ctx context.Context, run runner, group uint16) error {
	var b strings.Builder
	// add+delete makes the transaction succeed even if a previous probe left
	// the table behind.
	fmt.Fprintf(&b, "add table inet %s\n", auditProbeTable)
	fmt.Fprintf(&b, "delete table inet %s\n", auditProbeTable)
	fmt.Fprintf(&b, "add table inet %s\n", auditProbeTable)
	fmt.Fprintf(&b, "add chain inet %s probe\n", auditProbeTable)
	fmt.Fprintf(&b, "add rule inet %s probe %s\n", auditProbeTable, auditLogStatement(group, audit.DecisionAllow, audit.ReasonDefault))
	fmt.Fprintf(&b, "delete table inet %s\n", auditProbeTable)
	if out, err := run(ctx, b.String()); err != nil {
		return fmt.Errorf("kernel rejected the audit log rule: %w (%s)", err, strings.TrimSpace(string(out)))
	}
	return nil
}
