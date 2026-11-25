// Copyright 2026 The OpenSandbox Authors
// SPDX-License-Identifier: Apache-2.0

package nftables

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
)

const (
	dnsTCPv4 = "dns_established_v4"
	dnsTCPv6 = "dns_established_v6"
)

func dnsTCPSet(a netip.Addr) string {
	if a.Is4() {
		return dnsTCPv4
	}
	return dnsTCPv6
}

func writeDNSHistoryElements(b *strings.Builder, keeps map[netip.Addr]tcpSpans) {
	if len(keeps) == 0 {
		return
	}
	var v4, v6 []string
	for a := range keeps {
		if a.Is4() {
			v4 = append(v4, a.String())
		} else {
			v6 = append(v6, a.String())
		}
	}
	slices.Sort(v4)
	slices.Sort(v6)
	writeElements(b, dnsTCPv4, v4)
	writeElements(b, dnsTCPv6, v6)
}

// A live DNS lease is address-wide, so it admits ALL late ports for this
// generation, never a subset of them. The address-only marker is evaluated
// after early drops and only on established TCP. On plain replacement the
// sets start empty: carried (possibly partial) history is rendered per port.
func writeDNSHistory(b *strings.Builder, drops EstablishedDrops) {
	if drops.tcp == nil || len(drops.tcp.late.rules) == 0 {
		return
	}
	for _, s := range []struct{ family, name, typ string }{{"ip", dnsTCPv4, "ipv4_addr"}, {"ip6", dnsTCPv6, "ipv6_addr"}} {
		fmt.Fprintf(b, "add set inet %s %s { type %s; size %d; }\n", tableName, s.name, s.typ, maxDNSExceptions)
		fmt.Fprintf(b, "add rule inet %s %s %s daddr @%s tcp dport 1-65535 ct state established,related accept\n", tableName, chainName, s.family, s.name)
	}
	if !drops.carried {
		// On opt-in all exceptions come from live leases, after explicit denies.
		// A carried plan has already rendered its historical port intersections.
		writeDNSHistoryElements(b, drops.dnsKeeps)
	}
}

func (m *Manager) commitDNSHistory(keeps map[netip.Addr]tcpSpans) {
	if m.lastDrops.dnsKeeps == nil {
		m.lastDrops.dnsKeeps = keeps
		return
	}
	for a, keep := range keeps {
		m.lastDrops.dnsKeeps[a] = keep
	}
}

// One freshly added marker witnesses the whole atomic batch, even after its
// DNS TTL. No later marker write or plain carry may pass an unresolved batch.
// A positive recovery confirms *history only*: never recreate a timed lease.
func (m *Manager) reconcileDNSHistoryLocked(ctx context.Context) error {
	for a := range m.pendingDNSHistory {
		if m.staticStateUncertain {
			return fmt.Errorf("cannot recover DNS history across an uncertain table replacement: %w", errStaticStateUncertain)
		}
		elem := fmt.Sprintf("element inet %s %s { %s }\n", tableName, dnsTCPSet(a), a)
		if _, err := m.run(ctx, "get "+elem); err == nil {
			m.commitDNSHistory(m.pendingDNSHistory)
		} else if _, absentErr := m.run(ctx, "create "+elem+"delete "+elem); absentErr != nil {
			// Exclusive create and delete in ONE batch proves absence without
			// changing membership. A failed get alone proves nothing.
			return fmt.Errorf("unconfirmed DNS history: %w", errors.Join(err, absentErr))
		}
		m.pendingDNSHistory = nil
		break
	}
	return nil
}
