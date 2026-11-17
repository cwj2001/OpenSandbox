// Copyright 2026 The OpenSandbox Authors
// SPDX-License-Identifier: Apache-2.0

package fastsandboxnft

import (
	"context"
	"fmt"
	"maps"
	"net/netip"
	"strings"
	"time"

	"github.com/alibaba/opensandbox/egress/pkg/nftables"
	"github.com/alibaba/opensandbox/egress/pkg/policy"
	"github.com/alibaba/opensandbox/egress/pkg/subject"
	"github.com/alibaba/opensandbox/egress/pkg/telemetry"
)

const (
	maxResolvedDomains = 128
	maxDomainAddresses = 64
)

// domainLease retains the DNS clock separately from endpoint-specific TCP grace.
// Renewing one port must never keep a sibling port authorized.
type domainLease struct {
	expires time.Time
	tcp     map[uint16]time.Time
}

// ResolutionPolicy snapshots DNS admission policy and incarnation together.
// A stale source binding cannot obtain a replacement attachment's policy.
func (a *Applier) ResolutionPolicy(s subject.Subject, sourceIP netip.Addr) (*policy.NetworkPolicy, uint64, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	inst, ok := a.subjects[s]
	if !ok || inst.pol == nil || a.staticUncertain[s] || inst.att.IP.Unmap() != sourceIP.Unmap() {
		return nil, 0, false
	}
	return inst.pol, inst.generation, true
}

// AddResolvedDomain classifies an answer against the currently installed policy.
// Stale DNS callbacks are harmless: they cannot authorize another incarnation.
func (a *Applier) AddResolvedDomain(ctx context.Context, s subject.Subject, expectedGeneration uint64, domain string, ips []nftables.ResolvedIP) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	inst, ok := a.subjects[s]
	if !ok {
		return ErrUnknownSubject
	}
	if inst.generation != expectedGeneration || inst.pol == nil || a.staticUncertain[s] {
		return ErrLeaseRejected
	}
	domain = strings.ToLower(strings.TrimSuffix(domain, "."))
	permissions := inst.pol.DomainPermissions(domain)
	if domain == "" || !permissions.Allowed {
		return ErrLeaseRejected
	}
	if len(ips) == 0 {
		return nil
	}
	now := a.now()
	st := a.states[s]
	if st == nil {
		st = &refreshState{}
	}
	// Stage only this answer's source and address projections. Copying every
	// domain and TCP endpoint makes a one-name DNS refresh scale with the
	// entire subject's cache.
	addresses := maps.Clone(st.domains[domain])
	if addresses == nil {
		addresses = make(map[netip.Addr]domainLease)
	}
	affected := make(map[netip.Addr]struct{}, min(len(ips), maxDomainAddresses))
	for addr, lease := range addresses {
		if !lease.live(now) && !st.hasRenewalIdentity(permissions, addr) {
			delete(addresses, addr)
			affected[addr] = struct{}{}
		}
	}
	var retired string
	if st.domains[domain] == nil && len(st.domains) >= maxResolvedDomains {
		for name, leases := range st.domains {
			live := false
			permissions := inst.pol.DomainPermissions(name)
			for addr, lease := range leases {
				live = live || lease.live(now) || st.hasRenewalIdentity(permissions, addr)
			}
			if !live && (retired == "" || name < retired) {
				retired = name
			}
		}
		if retired == "" {
			return fmt.Errorf("domain lease capacity reached (%d)", maxResolvedDomains)
		}
		for addr := range st.domains[retired] {
			affected[addr] = struct{}{}
		}
	}
	for _, ip := range ips {
		addr := ip.Addr.Unmap()
		if !addr.IsValid() {
			continue
		}
		if _, exists := addresses[addr]; !exists && len(addresses) >= maxDomainAddresses {
			return fmt.Errorf("address lease capacity reached for domain %q (%d)", domain, maxDomainAddresses)
		}
		affected[addr] = struct{}{}
		lease := addresses[addr]
		// Overlapping answers contribute their maximum surviving timeout.
		lease.expires = maxTime(lease.expires, now.Add(nftables.ClampTTL(ip.TTL)))
		addresses[addr] = lease
	}
	next := *st
	next.domains = maps.Clone(st.domains)
	if next.domains == nil {
		next.domains = make(map[string]map[netip.Addr]domainLease)
	}
	delete(next.domains, retired)
	next.domains[domain] = addresses
	before := st.addressProjection(affected)
	after := next.projectAddresses(inst.pol, affected, now)
	var b strings.Builder
	if a.dirtyLeases[s] {
		next.retainRenewalEndpoints(st, now)
	} else {
		next.retainRenewalEndpoints(before, now)
	}
	if a.dirtyLeases[s] {
		// An error may have been returned after nft committed. Flush all sets
		// before trusting a delta, including additions absent from our mirror.
		next = *next.clone()
		next.classify(inst.pol, now)
		writeDynamicFlush(&b, s)
		writeRemainingLeasesFragment(&b, s, &next, now)
	} else {
		writeLeaseChanges(&b, s, before, after, now)
	}
	if b.Len() > 0 {
		if _, err := a.run(ctx, b.String()); err != nil {
			a.markLeasesDirty(s)
			telemetry.RecordNftablesUpdateFailed(telemetry.NftOpDynamicAdd)
			return err
		}
		telemetry.RecordNftablesUpdate()
	}
	if !a.dirtyLeases[s] {
		mergeAddressProjection(&next, affected, after)
	}
	delete(a.dirtyLeases, s)
	a.states[s] = &next
	return nil
}

// DNS reconciliation may remove expired elements, but only activity planning
// can retire their source identity. These candidates never carry a new deadline.
func (st *refreshState) retainRenewalEndpoints(before *refreshState, now time.Time) {
	cloned := false
	remember := func(endpoint nftables.TCPEndpoint) {
		if _, exists := st.renewalEndpoints[endpoint]; exists {
			return
		}
		if !cloned {
			st.renewalEndpoints = maps.Clone(st.renewalEndpoints)
			if st.renewalEndpoints == nil {
				st.renewalEndpoints = make(map[nftables.TCPEndpoint]struct{})
			}
			cloned = true
		}
		st.renewalEndpoints[endpoint] = struct{}{}
	}
	for addr, deadline := range before.dyn {
		if !deadline.After(now) {
			remember(nftables.TCPEndpoint{Addr: addr})
		}
	}
	for endpoint, deadline := range before.allowTCP {
		if !deadline.After(now) {
			remember(endpoint)
		}
	}
}

func (st *refreshState) hasRenewalIdentity(permissions policy.DomainPermissions, addr netip.Addr) bool {
	if !permissions.Allowed {
		return false
	}
	if permissions.Unrestricted {
		_, installed := st.dyn[addr]
		_, retained := st.renewalEndpoints[nftables.TCPEndpoint{Addr: addr}]
		return installed || retained
	}
	for _, port := range permissions.AllowPorts {
		endpoint := nftables.TCPEndpoint{Addr: addr, Port: uint16(port)}
		if _, installed := st.allowTCP[endpoint]; installed {
			return true
		}
		if _, retained := st.renewalEndpoints[endpoint]; retained {
			return true
		}
	}
	return false
}

func (lease domainLease) live(now time.Time) bool {
	if lease.expires.After(now) {
		return true
	}
	for _, expiry := range lease.tcp {
		if expiry.After(now) {
			return true
		}
	}
	return false
}

func maxTime(a, b time.Time) time.Time {
	if b.After(a) {
		return b
	}
	return a
}

// addressProjection selects the installed keys touched by an answer; deadlines
// remain absolute, including expired keys whose kernel removal must be safe.
func (st *refreshState) addressProjection(addresses map[netip.Addr]struct{}) *refreshState {
	out := &refreshState{
		dyn:      make(map[netip.Addr]time.Time),
		allowTCP: make(map[nftables.TCPEndpoint]time.Time),
		denyTCP:  make(map[nftables.TCPEndpoint]time.Time),
	}
	for addr := range addresses {
		if expiry, ok := st.dyn[addr]; ok {
			out.dyn[addr] = expiry
		}
	}
	for endpoint, expiry := range st.allowTCP {
		if _, ok := addresses[endpoint.Addr]; ok {
			out.allowTCP[endpoint] = expiry
		}
	}
	for endpoint, expiry := range st.denyTCP {
		if _, ok := addresses[endpoint.Addr]; ok {
			out.denyTCP[endpoint] = expiry
		}
	}
	return out
}

// projectAddresses retains every contributing source for shared addresses, but
// never copies or reclassifies unrelated cached endpoints.
func (st *refreshState) projectAddresses(pol *policy.NetworkPolicy, addresses map[netip.Addr]struct{}, now time.Time) *refreshState {
	out := &refreshState{domains: make(map[string]map[netip.Addr]domainLease)}
	for domain, leases := range st.domains {
		for addr := range addresses {
			lease, ok := leases[addr]
			if !ok {
				continue
			}
			if out.domains[domain] == nil {
				out.domains[domain] = make(map[netip.Addr]domainLease)
			}
			lease.tcp = maps.Clone(lease.tcp)
			out.domains[domain][addr] = lease
		}
	}
	out.classify(pol, now)
	return out
}

// Publish only after a successful transaction (or a synchronized true no-op).
func mergeAddressProjection(st *refreshState, addresses map[netip.Addr]struct{}, after *refreshState) {
	if st.dyn == nil {
		st.dyn = make(map[netip.Addr]time.Time)
	}
	if st.allowTCP == nil {
		st.allowTCP = make(map[nftables.TCPEndpoint]time.Time)
	}
	if st.denyTCP == nil {
		st.denyTCP = make(map[nftables.TCPEndpoint]time.Time)
	}
	for addr := range addresses {
		delete(st.dyn, addr)
	}
	for endpoint := range st.allowTCP {
		if _, ok := addresses[endpoint.Addr]; ok {
			delete(st.allowTCP, endpoint)
		}
	}
	for endpoint := range st.denyTCP {
		if _, ok := addresses[endpoint.Addr]; ok {
			delete(st.denyTCP, endpoint)
		}
	}
	maps.Copy(st.dyn, after.dyn)
	maps.Copy(st.allowTCP, after.allowTCP)
	maps.Copy(st.denyTCP, after.denyTCP)
}

// writeLeaseChanges leaves unchanged deadlines untouched. Helpers tolerate an
// element already expiring in the kernel between planning and the transaction.
func writeLeaseChanges(b *strings.Builder, s subject.Subject, before, after *refreshState, now time.Time) {
	nftables.WriteTimedIPChanges(b, TableName, dynSetName(s, "v4"), dynSetName(s, "v6"), before.dyn, after.dyn, now)
	nftables.WriteTimedPortChanges(b, TableName, tcpSetName(s, "v4", true), tcpSetName(s, "v6", true), before.allowTCP, after.allowTCP, now)
	nftables.WriteTimedPortChanges(b, TableName, tcpSetName(s, "v4", false), tcpSetName(s, "v6", false), before.denyTCP, after.denyTCP, now)
}

func (a *Applier) markLeasesDirty(s subject.Subject) {
	if a.dirtyLeases == nil {
		a.dirtyLeases = make(map[subject.Subject]bool)
	}
	a.dirtyLeases[s] = true
}

// A trusted no-execution failure preserves knowledge; every other error may
// have replaced policy or cleared sets. Only lifecycle success clears this.
func (a *Applier) markStaticUncertain(err error, subjects ...subject.Subject) {
	if nftables.ApplyEffectOf(err) == nftables.ApplyUnchanged {
		return
	}
	if a.staticUncertain == nil {
		a.staticUncertain = make(map[subject.Subject]bool)
	}
	if len(subjects) == 0 {
		for s := range a.subjects {
			a.staticUncertain[s] = true
		}
		return
	}
	for _, s := range subjects {
		a.staticUncertain[s] = true
	}
}

func (st *refreshState) clone() *refreshState {
	if st == nil {
		return &refreshState{}
	}
	next := *st
	next.dyn = maps.Clone(st.dyn)
	next.prev = maps.Clone(st.prev)
	next.pending = maps.Clone(st.pending)
	next.allowTCP = maps.Clone(st.allowTCP)
	next.denyTCP = maps.Clone(st.denyTCP)
	next.prevTCP = maps.Clone(st.prevTCP)
	next.renewalEndpoints = maps.Clone(st.renewalEndpoints)
	next.domains = make(map[string]map[netip.Addr]domainLease, len(st.domains))
	for domain, addresses := range st.domains {
		copyAddresses := make(map[netip.Addr]domainLease, len(addresses))
		for addr, lease := range addresses {
			lease.tcp = maps.Clone(lease.tcp)
			copyAddresses[addr] = lease
		}
		next.domains[domain] = copyAddresses
	}
	return &next
}

// classify never clamps a TTL or restarts a clock. Every set element is the
// maximum surviving contribution for that exact address or TCP endpoint.
func (st *refreshState) classify(pol *policy.NetworkPolicy, now time.Time) {
	st.dyn = make(map[netip.Addr]time.Time)
	st.allowTCP = make(map[nftables.TCPEndpoint]time.Time)
	st.denyTCP = make(map[nftables.TCPEndpoint]time.Time)
	for domain, addresses := range st.domains {
		permissions := pol.DomainPermissions(domain)
		for addr, lease := range addresses {
			latest := lease.expires
			for port, expiry := range lease.tcp {
				if !expiry.After(now) {
					delete(lease.tcp, port)
					continue
				}
				latest = maxTime(latest, expiry)
			}
			if !latest.After(now) {
				if !st.hasRenewalIdentity(permissions, addr) {
					delete(addresses, addr)
				}
				continue
			}
			// Denies follow every known address, even if DNS admission was
			// revoked; another admitted name may share that address.
			for _, port := range permissions.DenyPorts {
				endpoint := nftables.TCPEndpoint{Addr: addr, Port: uint16(port)}
				st.denyTCP[endpoint] = maxTime(st.denyTCP[endpoint], latest)
			}
			if !permissions.Allowed {
				continue
			}
			if permissions.Unrestricted {
				st.dyn[addr] = maxTime(st.dyn[addr], latest)
				continue
			}
			for _, port := range permissions.AllowPorts {
				expiry := maxTime(lease.expires, lease.tcp[uint16(port)])
				if expiry.After(now) {
					endpoint := nftables.TCPEndpoint{Addr: addr, Port: uint16(port)}
					st.allowTCP[endpoint] = maxTime(st.allowTCP[endpoint], expiry)
				}
			}
		}
		if len(addresses) == 0 {
			delete(st.domains, domain)
		}
	}
	// A policy narrowing also revokes old IP-only activity/mirror work.
	// Otherwise a pending broad redelivery could resurrect a scoped grant.
	for addr := range st.prev {
		_, retained := st.renewalEndpoints[nftables.TCPEndpoint{Addr: addr}]
		if _, allowed := st.dyn[addr]; !allowed && !retained {
			delete(st.prev, addr)
		}
	}
	for addr := range st.pending {
		if _, allowed := st.dyn[addr]; !allowed {
			delete(st.pending, addr)
		}
	}
	for endpoint := range st.prevTCP {
		_, retained := st.renewalEndpoints[endpoint]
		if _, allowed := st.allowTCP[endpoint]; (!allowed && !retained) || st.denyTCP[endpoint].After(now) {
			delete(st.prevTCP, endpoint)
		}
	}
}

func bucketActiveTCP(entries []conntrackEntry, sources map[netip.Addr]subject.Subject) map[subject.Subject]map[nftables.TCPEndpoint]struct{} {
	out := make(map[subject.Subject]map[nftables.TCPEndpoint]struct{})
	for _, entry := range entries {
		s, known := sources[entry.src.Unmap()]
		if !known || entry.port == 0 || !activeConntrackTCPState(entry.state) {
			continue
		}
		if out[s] == nil {
			out[s] = make(map[nftables.TCPEndpoint]struct{})
		}
		out[s][nftables.TCPEndpoint{Addr: entry.dst.Unmap(), Port: entry.port}] = struct{}{}
	}
	return out
}

func (st *refreshState) renewDomains(pol *policy.NetworkPolicy, broad []nftables.ResolvedIP, active map[nftables.TCPEndpoint]struct{}, now time.Time) {
	expiry := now.Add(time.Duration(dynSetTimeoutS) * time.Second)
	current := make(map[nftables.TCPEndpoint]struct{})
	refresh := make(map[nftables.TCPEndpoint]struct{})
	for endpoint := range active {
		_, retained := st.renewalEndpoints[endpoint]
		if _, known := st.allowTCP[endpoint]; !known && !retained {
			continue
		}
		if denyUntil := st.denyTCP[endpoint]; denyUntil.After(now) {
			continue
		}
		current[endpoint] = struct{}{}
		refresh[endpoint] = struct{}{}
	}
	for endpoint := range st.prevTCP {
		_, retained := st.renewalEndpoints[endpoint]
		if _, known := st.allowTCP[endpoint]; (known || retained) && !st.denyTCP[endpoint].After(now) {
			refresh[endpoint] = struct{}{}
		}
	}
	for domain, addresses := range st.domains {
		permissions := pol.DomainPermissions(domain)
		if !permissions.Allowed {
			continue
		}
		for addr, lease := range addresses {
			if permissions.Unrestricted {
				for _, ip := range broad {
					if addr == ip.Addr {
						lease.expires = expiry
					}
				}
			} else {
				for _, port := range permissions.AllowPorts {
					endpoint := nftables.TCPEndpoint{Addr: addr, Port: uint16(port)}
					if _, renew := refresh[endpoint]; !renew {
						continue
					}
					if lease.tcp == nil {
						lease.tcp = make(map[uint16]time.Time)
					}
					lease.tcp[uint16(port)] = expiry
				}
			}
			addresses[addr] = lease
		}
	}
	st.prevTCP = current
}
