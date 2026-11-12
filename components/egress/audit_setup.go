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

package main

import (
	"context"
	"os"
	"time"

	"github.com/alibaba/opensandbox/egress/pkg/audit"
	"github.com/alibaba/opensandbox/egress/pkg/constants"
	"github.com/alibaba/opensandbox/egress/pkg/dnsproxy"
	"github.com/alibaba/opensandbox/egress/pkg/log"
	"github.com/alibaba/opensandbox/egress/pkg/nftables"
	"github.com/alibaba/opensandbox/egress/pkg/telemetry"
	slogger "github.com/alibaba/opensandbox/internal/logger"
)

const (
	auditProbeTimeout = 5 * time.Second
	// auditFlushTimeout bounds how long shutdown waits for queued events.
	auditFlushTimeout = 2 * time.Second
)

// resolveAuditLevel runs before profile dispatch. Audit is observability and
// never takes the sidecar down: an invalid or unsupported setting is logged
// and audit stays off, like an invalid OPENSANDBOX_EGRESS_MODE.
func resolveAuditLevel(profile string) audit.Level {
	raw := os.Getenv(constants.EnvEgressAudit)
	level, err := audit.ParseLevel(raw)
	if err != nil {
		log.Warnf("invalid %s=%q: %v; egress audit disabled", constants.EnvEgressAudit, raw, err)
		return audit.LevelOff
	}
	if level == audit.LevelOff {
		return level
	}
	if profile == constants.ProfileFastSandbox {
		log.Warnf("%s is not supported with the %s profile; egress audit disabled", constants.EnvEgressAudit, constants.ProfileFastSandbox)
		return audit.LevelOff
	}
	if constants.IsTruthy(os.Getenv(constants.EnvExperimentalRevisionRuntime)) {
		log.Warnf("%s is not supported with %s; egress audit disabled", constants.EnvEgressAudit, constants.EnvExperimentalRevisionRuntime)
		return audit.LevelOff
	}
	return level
}

// startAudit wires the audit collector into the DNS proxy and, at conn level
// under dns+nft, binds the NFLOG listener before any nft rule exists. It
// returns the NFLOG group for the nft audit rules (0 when L4 audit is not
// running) and a stop function that flushes the stream. Every L4 failure
// degrades to DNS-only audit, recorded in the stream's started event; none
// changes enforcement or startup.
func startAudit(ctx context.Context, level audit.Level, mode string, proxy *dnsproxy.Proxy) (uint16, func()) {
	if level == audit.LevelOff {
		return 0, func() {}
	}
	collector := audit.NewCollector(newLogSink(), proxy)
	proxy.SetAudit(collector)
	stop := func() { collector.Close(auditFlushTimeout) }
	dnsOnly := func(detail string) (uint16, func()) {
		collector.Started([]string{audit.LayerDNS}, detail)
		return 0, stop
	}
	if level != audit.LevelConn {
		log.Infof("egress audit enabled (level=dns)")
		return dnsOnly("")
	}
	if !constants.ModeUsesNft(mode) {
		log.Warnf("egress audit: %s=conn needs dns+nft enforcement (mode=%s); auditing DNS only", constants.EnvEgressAudit, mode)
		return dnsOnly("l4 unavailable: enforcement mode " + mode + " has no nftables")
	}
	probeCtx, cancelProbe := context.WithTimeout(ctx, auditProbeTimeout)
	err := nftables.ProbeAuditLog(probeCtx, audit.NFLogGroup)
	cancelProbe()
	if err != nil {
		log.Warnf("egress audit: L4 collection unavailable, auditing DNS only (enforcement unaffected): %v", err)
		return dnsOnly("l4 unavailable: " + err.Error())
	}
	// The reader outlives the signal context: DNS and nft keep enforcing
	// through the shutdown drain, so their audit must keep running too.
	l4Ctx, cancelL4 := context.WithCancel(context.WithoutCancel(ctx))
	if err := collector.StartL4(l4Ctx); err != nil {
		cancelL4()
		log.Warnf("egress audit: L4 collection unavailable, auditing DNS only (enforcement unaffected): %v", err)
		return dnsOnly("l4 unavailable: " + err.Error())
	}
	collector.Started([]string{audit.LayerDNS, audit.LayerL4}, "")
	log.Infof("egress audit enabled (level=conn, NFLOG group %d)", audit.NFLogGroup)
	return audit.NFLogGroup, func() {
		cancelL4()
		collector.Close(auditFlushTimeout)
	}
}

// newLogSink logs audit events at info on their own logger, so lowering
// OPENSANDBOX_EGRESS_LOG_LEVEL never silences the audit trail.
func newLogSink() audit.Sink {
	base := slogger.MustNew(slogger.Config{Level: "info"})
	if extra := telemetry.EgressLogFields(); len(extra) > 0 {
		base = base.With(extra...)
	}
	return audit.NewLogSink(base.Named("opensandbox.egress.audit"))
}
