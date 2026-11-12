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
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"os/exec"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/alibaba/opensandbox/egress/pkg/audit"
	"github.com/alibaba/opensandbox/egress/pkg/policy"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

type lockedSink struct {
	mu     sync.Mutex
	events []audit.Event
}

func (s *lockedSink) Emit(e audit.Event) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = append(s.events, e)
}

func (s *lockedSink) snapshot() []audit.Event {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]audit.Event(nil), s.events...)
}

type policyView struct{ p *policy.NetworkPolicy }

func (v policyView) EffectivePolicy() (*policy.NetworkPolicy, int) { return v.p, 0 }

// TestNftAuditKernelVerdictsAndEvents loads the audited ruleset into a real
// kernel, dials through it and checks two things: every verdict is what the
// policy says (an accepted packet is seen leaving the dummy link, a dropped
// one never is), and every attempt yields exactly one audit event with the
// right decision, reason and destination — including a literal-IP dial that
// never touched DNS.
func TestNftAuditKernelVerdictsAndEvents(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	if !isolatedNftTest(t, ctx) {
		return
	}
	setupAuditLink(t, ctx)

	pol := mustPolicy(t, `{"defaultAction":"deny","egress":[
		{"action":"deny","target":"198.51.100.66"},
		{"action":"allow","target":"198.51.100.0/24"},
		{"action":"deny","ports":[25]},
		{"action":"allow","target":"2001:db8:1::/64"},
		{"action":"deny","target":"2001:db8:1::9"},
		{"action":"allow","target":"cdn.example"}]}`)
	sink := &lockedSink{}
	collector := audit.NewCollector(sink, policyView{p: pol})
	// The listener binds before the rules exist, as in the sidecar.
	require.NoError(t, collector.StartL4(ctx))

	m := NewManagerWithOptions(Options{BlockDoT: true, AuditLogGroup: audit.NFLogGroup})
	require.NoError(t, m.ApplyStatic(ctx, pol))
	lease := netip.MustParseAddr("192.0.2.77")
	collector.RecordDNS(audit.DNSRecord{Domain: "cdn.example", Decision: audit.DecisionAllow, Reason: audit.ReasonPolicy,
		Answers: []netip.Addr{lease}, TTL: time.Minute})
	require.NoError(t, m.AddResolvedDomain(ctx, "cdn.example", []ResolvedIP{{Addr: lease, TTL: time.Minute}}))

	type attempt struct {
		network, addr    string
		denied           bool
		reason, rule     string
		domain           string
		dnsSeen          bool
		expectedProtocol string
	}
	attempts := []attempt{
		{network: "tcp", addr: "198.51.100.7:443", reason: audit.ReasonIPRule, rule: "198.51.100.0/24"},
		{network: "tcp", addr: "198.51.100.66:443", denied: true, reason: audit.ReasonIPRule, rule: "198.51.100.66"},
		{network: "tcp", addr: "198.51.100.7:25", denied: true, reason: audit.ReasonPortRule, rule: "ports 25"},
		{network: "tcp", addr: "203.0.113.9:443", denied: true, reason: audit.ReasonDefault},
		{network: "tcp", addr: "198.51.100.7:853", denied: true, reason: audit.ReasonDoT},
		{network: "tcp", addr: "192.0.2.77:443", reason: audit.ReasonDNSLease, domain: "cdn.example", dnsSeen: true},
		{network: "udp", addr: "203.0.113.9:9999", denied: true, reason: audit.ReasonDefault},
		{network: "udp", addr: "198.51.100.7:9999", reason: audit.ReasonIPRule, rule: "198.51.100.0/24"},
		{network: "tcp", addr: "[2001:db8:1::9]:443", denied: true, reason: audit.ReasonIPRule, rule: "2001:db8:1::9"},
		{network: "tcp", addr: "[2001:db8:2::9]:443", denied: true, reason: audit.ReasonDefault},
		{network: "udp", addr: "[2001:db8:1::7]:9999", reason: audit.ReasonIPRule, rule: "2001:db8:1::/64"},
	}
	stopSniff := sniffTransmitted(t, "audit0")
	for _, a := range attempts {
		dialOnce(a.network, a.addr)
	}
	time.Sleep(200 * time.Millisecond)
	transmitted := stopSniff()
	for _, a := range attempts {
		key := a.network + " " + a.addr
		require.Equal(t, !a.denied, transmitted[key], "%s: accepted=%v by policy, left the link=%v", key, !a.denied, transmitted[key])
	}

	var events []audit.Event
	require.Eventually(t, func() bool {
		events = sink.snapshot()
		return len(events) >= len(attempts)+1 // plus the DNS event
	}, 5*time.Second, 50*time.Millisecond, "audit events: %+v", sink.snapshot())
	time.Sleep(300 * time.Millisecond) // a late duplicate would surface within one NFLOG flush
	collector.Close(time.Second)
	events = sink.snapshot()

	var l4 []audit.Event
	var stopped *audit.Event
	for i, e := range events {
		require.NotEmpty(t, e.BootID)
		require.Equal(t, uint64(i+1), e.Seq, "the stream is contiguous")
		switch e.Layer {
		case audit.LayerL4:
			require.False(t, e.ObservedAt.IsZero())
			e.ObservedAt, e.BootID, e.Seq = time.Time{}, "", 0
			l4 = append(l4, e)
		case audit.LayerAudit:
			if e.Reason == audit.ReasonStopped {
				stopped = &events[i]
			}
		}
	}
	require.NotNil(t, stopped)
	require.Equal(t, audit.Stats{Detailed: uint64(len(attempts)) + 1}, *stopped.Stats, "no loss, nothing aggregated")
	require.Len(t, l4, len(attempts), "exactly one event per attempt: %+v", l4)
	for i, a := range attempts {
		ap := netip.MustParseAddrPort(a.addr)
		want := audit.Event{
			Layer: audit.LayerL4, Decision: audit.DecisionAllow, Reason: a.reason,
			Protocol: a.network, DestinationIP: ap.Addr(), DestinationPort: ap.Port(),
			Domain: a.domain, DNSSeen: a.dnsSeen, Rule: a.rule,
		}
		if a.denied {
			want.Decision = audit.DecisionDeny
		}
		if a.rule != "" {
			want.RuleSource = "user"
		}
		require.Equal(t, want, l4[i], "attempt %d (%s %s)", i, a.network, a.addr)
	}
}

// TestNftAuditKernelAccountsForEveryConnection floods the audited chain with
// far more new flows than the detailed-event budget and checks the stream's
// conservation law against the kernel: every flow is either an individual
// event, inside an aggregate, or counted lost by the NFLOG sequence check —
// never silently missing.
func TestNftAuditKernelAccountsForEveryConnection(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	if !isolatedNftTest(t, ctx) {
		return
	}
	setupAuditLink(t, ctx)
	pol := mustPolicy(t, `{"defaultAction":"deny","egress":[{"action":"allow","target":"198.51.100.0/24"}]}`)
	sink := &lockedSink{}
	collector := audit.NewCollector(sink, policyView{p: pol})
	require.NoError(t, collector.StartL4(ctx))
	m := NewManagerWithOptions(Options{BlockDoT: true, AuditLogGroup: audit.NFLogGroup})
	require.NoError(t, m.ApplyStatic(ctx, pol))

	// Every send is a new 5-tuple (distinct destination port), so each is one
	// conntrack-new packet and one NFLOG copy; denied and allowed alternate.
	const flows = 20000
	start := time.Now()
	for i := 0; i < flows; i++ {
		dst := "198.51.100.7"
		if i%2 == 1 {
			dst = "203.0.113.9"
		}
		conn, err := net.Dial("udp", net.JoinHostPort(dst, strconv.Itoa(10000+i)))
		require.NoError(t, err)
		_, _ = conn.Write([]byte("x"))
		conn.Close()
	}
	t.Logf("sent %d flows in %v", flows, time.Since(start))

	accounted := func(s audit.Stats) uint64 {
		return s.Detailed + s.Aggregated + s.Deduplicated + s.LostKernel + s.LostUndecodable
	}
	require.Eventually(t, func() bool { return accounted(collector.Stats()) == flows }, 30*time.Second, 50*time.Millisecond,
		"every flow must be accounted for: %+v", collector.Stats())
	collector.Close(5 * time.Second)

	stats := collector.Stats()
	t.Logf("stats: %+v", stats)
	require.Positive(t, stats.Aggregated, "the flood must exceed the detailed budget")
	require.Zero(t, stats.Deduplicated, "every flow is a distinct 5-tuple")
	require.Equal(t, uint64(flows), accounted(stats))
	var inStream uint64
	for _, e := range sink.snapshot() {
		if e.Layer == audit.LayerL4 {
			inStream += max(e.Count, 1)
		}
	}
	require.Equal(t, stats.Detailed+stats.Aggregated, inStream, "the stream carries every accounted flow")
}

func setupAuditLink(t *testing.T, ctx context.Context) {
	t.Helper()
	for _, args := range [][]string{
		{"link", "set", "lo", "up"},
		{"link", "add", "audit0", "type", "dummy"},
		{"addr", "add", "192.0.2.2/24", "dev", "audit0"},
		{"link", "set", "audit0", "up"},
		{"route", "add", "default", "dev", "audit0"},
		{"-6", "addr", "add", "2001:db8::2/64", "dev", "audit0", "nodad"},
		{"-6", "route", "add", "default", "dev", "audit0"},
	} {
		out, err := exec.CommandContext(ctx, "ip", args...).CombinedOutput()
		require.NoError(t, err, "ip %v: %s", args, out)
	}
}

// dialOnce makes one connection attempt; the outcome is judged on the wire.
// A TCP SYN dropped in OUTPUT does not fail connect (the kernel retransmits),
// so the dial error cannot tell a drop from an accept on a dead link.
func dialOnce(network, addr string) {
	conn, err := net.DialTimeout(network, addr, 200*time.Millisecond)
	if err != nil {
		return
	}
	defer conn.Close()
	if network == "udp" {
		_, _ = fmt.Fprint(conn, "audit")
	}
}

// sniffTransmitted records the "proto ip:port" of every TCP/UDP packet
// transmitted on ifname until the returned stop function is called. IPv6
// extension headers are not expected on this test link.
func sniffTransmitted(t *testing.T, ifname string) func() map[string]bool {
	t.Helper()
	ifi, err := net.InterfaceByName(ifname)
	require.NoError(t, err)
	ethAll := int(htons(unix.ETH_P_ALL))
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, ethAll)
	require.NoError(t, err)
	require.NoError(t, unix.Bind(fd, &unix.SockaddrLinklayer{Protocol: htons(unix.ETH_P_ALL), Ifindex: ifi.Index}))
	tv := unix.NsecToTimeval((50 * time.Millisecond).Nanoseconds())
	require.NoError(t, unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv))

	var mu sync.Mutex
	seen := map[string]bool{}
	done := make(chan struct{})
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		buf := make([]byte, 2048)
		for {
			select {
			case <-done:
				return
			default:
			}
			n, _, err := unix.Recvfrom(fd, buf, 0)
			if err != nil || n < 1 {
				continue
			}
			var addr netip.Addr
			var next byte
			var off int
			switch buf[0] >> 4 {
			case 4:
				if n < 20 {
					continue
				}
				addr, next, off = netip.AddrFrom4([4]byte(buf[16:20])), buf[9], int(buf[0]&0x0f)*4
			case 6:
				if n < 40 {
					continue
				}
				addr, next, off = netip.AddrFrom16([16]byte(buf[24:40])), buf[6], 40
			default:
				continue
			}
			proto := map[byte]string{6: "tcp", 17: "udp"}[next]
			if proto == "" || n < off+4 {
				continue
			}
			dst := netip.AddrPortFrom(addr, binary.BigEndian.Uint16(buf[off+2:off+4]))
			mu.Lock()
			seen[proto+" "+dst.String()] = true
			mu.Unlock()
		}
	}()
	return func() map[string]bool {
		close(done)
		<-stopped
		unix.Close(fd)
		mu.Lock()
		defer mu.Unlock()
		return seen
	}
}

func htons(v uint16) uint16 {
	return v<<8 | v>>8
}

func TestNftAuditProbeKernel(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if !isolatedNftTest(t, ctx) {
		return
	}
	require.NoError(t, ProbeAuditLog(ctx, audit.NFLogGroup))
	out, err := exec.CommandContext(ctx, "nft", "list", "tables").CombinedOutput()
	require.NoError(t, err, "%s", out)
	require.NotContains(t, string(out), auditProbeTable, "the probe leaves nothing behind")
	// A leftover table from a crashed probe does not fail the next one.
	out, err = exec.CommandContext(ctx, "nft", "add", "table", "inet", auditProbeTable).CombinedOutput()
	require.NoError(t, err, "%s", out)
	require.NoError(t, ProbeAuditLog(ctx, audit.NFLogGroup))
}
