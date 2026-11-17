// Copyright 2026 The OpenSandbox Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package fastsandboxnft

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/alibaba/opensandbox/egress/pkg/nftables"
	"github.com/alibaba/opensandbox/egress/pkg/policy"
	"github.com/alibaba/opensandbox/egress/pkg/subject"
	"github.com/stretchr/testify/require"
)

func isolatedDomainKernel(t *testing.T) bool {
	t.Helper()
	switch os.Getenv("OPENSANDBOX_NFT_TEST") {
	case "1":
		parent, err := os.Readlink("/proc/self/ns/net")
		require.NoError(t, err)
		cmd := exec.Command("unshare", "--net", os.Args[0], "-test.run=^"+t.Name()+"$", "-test.v")
		cmd.Env = append(os.Environ(), "OPENSANDBOX_NFT_TEST=netns", "FAST_NFT_PARENT_NS="+parent)
		output, err := cmd.CombinedOutput()
		require.NoError(t, err, "%s", output)
		t.Logf("%s", output)
		return false
	case "netns":
		parent := os.Getenv("FAST_NFT_PARENT_NS")
		require.NotEmpty(t, parent, "start with OPENSANDBOX_NFT_TEST=1")
		current, err := os.Readlink("/proc/self/ns/net")
		require.NoError(t, err)
		require.NotEqual(t, parent, current)
		return true
	default:
		t.Skip("set OPENSANDBOX_NFT_TEST=1 with nft and private network namespace permissions")
		return false
	}
}

func kernelDomainElement(t *testing.T, s subject.Subject, set, element string, present bool) string {
	t.Helper()
	output, err := exec.Command("nft", "get", "element", "inet", TableName, set, "{", element, "}").CombinedOutput()
	if present {
		require.NoError(t, err, "subject %s element %s: %s", s, element, output)
	} else {
		require.Error(t, err, "subject %s must not authorize %s: %s", s, element, output)
	}
	return string(output)
}

func TestDomainKernelLifecyclePreservesSharedTTLAndIsolation(t *testing.T) {
	if !isolatedDomainKernel(t) {
		return
	}
	ctx := context.Background()
	a := NewApplier(nil)
	now := time.Now()
	a.now = func() time.Time { return now }
	s := subject.FromSandboxUID("domain-kernel")
	other := subject.FromSandboxUID("domain-other")
	require.NoError(t, a.ApplyDenyFirst(ctx, s, testSlot("kernel", "10.0.0.5")))
	require.NoError(t, a.ApplyDenyFirst(ctx, other, testSlot("other", "10.0.0.6")))
	broad := domainPolicy(t, `{"defaultAction":"deny","egress":[{"action":"allow","target":"a.example"},{"action":"allow","target":"b.example"}]}`)
	narrow := domainPolicy(t, `{"defaultAction":"deny","egress":[{"action":"allow","target":"a.example","ports":[443]},{"action":"allow","target":"b.example","ports":[443]},{"action":"deny","target":"a.example","ports":[8443]}]}`)
	require.NoError(t, a.ApplyPolicy(ctx, s, broad))
	_, generation, _ := a.ResolutionPolicy(s, netip.MustParseAddr("10.0.0.5"))
	addresses := []netip.Addr{netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("2001:db8::1")}
	for _, addr := range addresses {
		require.NoError(t, a.AddResolvedDomain(ctx, s, generation, "a.example", []nftables.ResolvedIP{{Addr: addr}}))
		require.NoError(t, a.AddResolvedDomain(ctx, s, generation, "b.example", []nftables.ResolvedIP{{Addr: addr, TTL: 40 * time.Second}}))
	}
	now = now.Add(20 * time.Second)
	require.NoError(t, a.ApplyAlwaysRulesReload(ctx, nil, map[subject.Subject]*policy.NetworkPolicy{s: narrow, other: broad}))
	check := func() {
		for _, addr := range addresses {
			family := "v6"
			if addr.Is4() {
				family = "v4"
			}
			kernelDomainElement(t, s, dynSetName(s, family), addr.String(), false)
			text := kernelDomainElement(t, s, tcpSetName(s, family, true), addr.String()+" . 443", true)
			match := regexp.MustCompile(`expires ([0-9a-z.]+)`).FindStringSubmatch(text)
			require.Len(t, match, 2, "%s", text)
			left, err := time.ParseDuration(match[1])
			require.NoError(t, err)
			require.Greater(t, left, 75*time.Second)
			require.LessOrEqual(t, left, 80*time.Second, "shared endpoint uses max remaining contribution, not a new DNS timeout")
			kernelDomainElement(t, s, tcpSetName(s, family, false), addr.String()+" . 8443", true)
			kernelDomainElement(t, other, tcpSetName(other, family, true), addr.String()+" . 443", false)
		}
	}
	check()
	require.NoError(t, a.Remove(ctx, other))
	// The other subject no longer has sets; check the survivor directly.
	for _, addr := range addresses {
		family := "v6"
		if addr.Is4() {
			family = "v4"
		}
		kernelDomainElement(t, s, tcpSetName(s, family, true), addr.String()+" . 443", true)
	}
	now = now.Add(50 * time.Second)
	removeB := domainPolicy(t, `{"defaultAction":"deny","egress":[{"action":"allow","target":"a.example","ports":[443]}]}`)
	require.NoError(t, a.ApplyPolicy(ctx, s, removeB))
	for _, addr := range addresses {
		family := "v6"
		if addr.Is4() {
			family = "v4"
		}
		kernelDomainElement(t, s, tcpSetName(s, family, true), addr.String()+" . 443", false)
	}
	require.NoError(t, a.ApplyDenyFirst(ctx, s, testSlot("kernel", "10.0.0.5")))
	require.NoError(t, a.ApplyPolicy(ctx, s, narrow))
	require.ErrorIs(t, a.AddResolvedDomain(ctx, s, generation, "a.example", []nftables.ResolvedIP{{Addr: addresses[0]}}), ErrLeaseRejected)
	kernelDomainElement(t, s, tcpSetName(s, "v4", true), addresses[0].String()+" . 443", false)
	// Model a lost exec response AFTER the kernel commits. Recovery must
	// remove the untracked address even when the next DNS update is unrelated.
	_, generation, _ = a.ResolutionPolicy(s, netip.MustParseAddr("10.0.0.5"))
	ghost := netip.MustParseAddr("192.0.2.99")
	run := a.run
	a.run = func(ctx context.Context, script string) ([]byte, error) {
		out, err := run(ctx, script)
		if err == nil {
			err = errors.New("lost response after commit")
		}
		return out, err
	}
	require.Error(t, a.AddResolvedDomain(ctx, s, generation, "a.example", []nftables.ResolvedIP{{Addr: ghost}}))
	kernelDomainElement(t, s, tcpSetName(s, "v4", true), ghost.String()+" . 443", true)
	require.NotContains(t, a.states[s].allowTCP, nftables.TCPEndpoint{Addr: ghost, Port: 443})
	a.run = run
	require.NoError(t, a.AddResolvedDomain(ctx, s, generation, "b.example", []nftables.ResolvedIP{{Addr: addresses[0]}}))
	kernelDomainElement(t, s, tcpSetName(s, "v4", true), ghost.String()+" . 443", false)
	kernelDomainElement(t, s, tcpSetName(s, "v4", true), addresses[0].String()+" . 443", true)
	require.False(t, a.dirtyLeases[s])
	// An uncertain STATIC replacement is different: DNS must not restore
	// the old policy. Only a subsequent normal lifecycle apply can do so.
	a.run = func(ctx context.Context, script string) ([]byte, error) {
		out, err := run(ctx, script)
		if err == nil {
			err = errors.New("lost static response after commit")
		}
		return out, err
	}
	replacement := domainPolicy(t, `{"defaultAction":"deny","egress":[{"action":"allow","target":"b.example","ports":[8443]}]}`)
	require.Error(t, a.ApplyPolicy(ctx, s, replacement))
	require.Equal(t, narrow, a.subjects[s].pol)
	kernelDomainElement(t, s, tcpSetName(s, "v4", true), addresses[0].String()+" . 443", false)
	kernelDomainElement(t, s, tcpSetName(s, "v4", true), addresses[0].String()+" . 8443", true)
	a.run = run
	require.ErrorIs(t, a.AddResolvedDomain(ctx, s, generation, "b.example", []nftables.ResolvedIP{{Addr: addresses[0]}}), ErrLeaseRejected)
	a.conntrack = func(context.Context) ([]conntrackEntry, error) {
		return []conntrackEntry{{src: netip.MustParseAddr("10.0.0.5"), dst: addresses[0], port: 443, state: "ESTABLISHED"}}, nil
	}
	a.refreshTick(ctx)
	kernelDomainElement(t, s, tcpSetName(s, "v4", true), addresses[0].String()+" . 443", false)
	kernelDomainElement(t, s, tcpSetName(s, "v4", true), addresses[0].String()+" . 8443", true)
	require.NoError(t, a.ApplyPolicy(ctx, s, narrow))
	kernelDomainElement(t, s, tcpSetName(s, "v4", true), addresses[0].String()+" . 443", true)
	kernelDomainElement(t, s, tcpSetName(s, "v4", true), addresses[0].String()+" . 8443", false)
	require.False(t, a.staticUncertain[s])
}

// TestDomainPacketHelper runs only in subprocess namespaces created by the packet test.
func TestDomainPacketHelper(t *testing.T) {
	switch os.Getenv("FAST_NFT_HELPER") {
	case "holder":
		fmt.Println("ready")
		time.Sleep(time.Hour)
	case "server":
		for _, port := range []string{"443", "8443"} {
			listener, err := net.Listen("tcp4", "0.0.0.0:"+port)
			require.NoError(t, err)
			defer listener.Close()
			go echoDomainConnections(listener)
		}
		fmt.Println("ready")
		time.Sleep(time.Hour)
	case "client", "kept-client":
		conn, err := net.DialTimeout("tcp4", os.Getenv("FAST_NFT_DEST"), 500*time.Millisecond)
		if os.Getenv("FAST_NFT_EXPECT") == "deny" {
			if conn != nil {
				conn.Close()
			}
			require.Error(t, err, "denied endpoint completed a TCP handshake")
			return
		}
		require.NoError(t, err)
		defer conn.Close()
		exchange := func() {
			require.NoError(t, conn.SetDeadline(time.Now().Add(time.Second)))
			_, err = conn.Write([]byte("port-proof"))
			require.NoError(t, err)
			response := make([]byte, len("port-proof"))
			_, err = io.ReadFull(conn, response)
			require.NoError(t, err)
			require.Equal(t, "port-proof", string(response))
		}
		exchange()
		if os.Getenv("FAST_NFT_HELPER") == "kept-client" {
			fmt.Println("ready")
			require.True(t, bufio.NewScanner(os.Stdin).Scan(), "wait for the policy update before reusing the connection")
			exchange()
		}
	default:
		t.Skip("internal packet fixture")
	}
}

func echoDomainConnections(listener net.Listener) {
	for {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		go func() { defer conn.Close(); _, _ = io.Copy(conn, conn) }()
	}
}

func startDomainHelper(t *testing.T, args []string, mode string) *exec.Cmd {
	t.Helper()
	command := exec.Command(args[0], append(args[1:], os.Args[0], "-test.run=^TestDomainPacketHelper$", "-test.v")...)
	command.Env = append(os.Environ(), "FAST_NFT_HELPER="+mode)
	pipe, err := command.StdoutPipe()
	require.NoError(t, err)
	command.Stderr = os.Stderr
	require.NoError(t, command.Start())
	t.Cleanup(func() { _ = command.Process.Kill(); _ = command.Wait() })
	ready := make(chan bool, 1)
	go func() {
		scanner := bufio.NewScanner(pipe)
		for scanner.Scan() {
			if scanner.Text() == "ready" {
				ready <- true
				return
			}
		}
		ready <- false
	}()
	select {
	case ok := <-ready:
		require.True(t, ok, "helper failed before readiness")
	case <-time.After(5 * time.Second):
		t.Fatal("namespace helper readiness timed out")
	}
	return command
}

func TestDomainKernelForwardAndDNATOriginalPort(t *testing.T) {
	if !isolatedDomainKernel(t) {
		return
	}
	ctx := context.Background()
	run := func(command string, args ...string) {
		output, err := exec.Command(command, args...).CombinedOutput()
		require.NoError(t, err, "%s %v: %s", command, args, output)
	}
	run("ip", "link", "set", "lo", "up")
	run("sysctl", "-w", "net.ipv4.ip_forward=1")
	client := startDomainHelper(t, []string{"unshare", "--net"}, "holder")
	remote := startDomainHelper(t, []string{"unshare", "--net"}, "holder")
	configure := func(pid int, host, peer, hostAddr, peerAddr, gateway string) {
		run("ip", "link", "add", host, "type", "veth", "peer", "name", peer)
		run("ip", "link", "set", peer, "netns", strconv.Itoa(pid))
		run("ip", "addr", "add", hostAddr, "dev", host)
		run("ip", "link", "set", host, "up")
		ns := func(args ...string) {
			run("nsenter", append([]string{"-t", strconv.Itoa(pid), "-n", "--", "ip"}, args...)...)
		}
		ns("link", "set", "lo", "up")
		ns("addr", "add", peerAddr, "dev", peer)
		ns("link", "set", peer, "up")
		ns("route", "add", "default", "via", gateway)
	}
	configure(client.Process.Pid, "fs_client", "fs_c", "10.0.0.1/24", "10.0.0.5/24", "10.0.0.1")
	configure(remote.Process.Pid, "fs_remote", "fs_r", "192.0.2.254/24", "192.0.2.1/24", "192.0.2.254")
	startDomainHelper(t, []string{"nsenter", "-t", strconv.Itoa(remote.Process.Pid), "-n", "--"}, "server")
	listener, err := net.Listen("tcp4", "10.0.0.1:18081")
	require.NoError(t, err)
	defer listener.Close()
	go echoDomainConnections(listener)
	a := NewApplier(nil, Options{MitmRedirectPort: 18081})
	s := subject.FromSandboxUID("packet-domain")
	require.NoError(t, a.ApplyDenyFirst(ctx, s, testSlot("packet", "10.0.0.5")))
	broad := domainPolicy(t, `{"defaultAction":"deny","egress":[{"action":"allow","target":"api.example"}]}`)
	narrow := domainPolicy(t, `{"defaultAction":"deny","egress":[{"action":"allow","target":"api.example","ports":[443]},{"action":"deny","target":"api.example","ports":[8443]}]}`)
	denied := domainPolicy(t, `{"defaultAction":"allow","egress":[{"action":"deny","target":"api.example","ports":[443]}]}`)
	require.NoError(t, a.ApplyPolicy(ctx, s, broad))
	_, generation, _ := a.ResolutionPolicy(s, netip.MustParseAddr("10.0.0.5"))
	require.NoError(t, a.AddResolvedDomain(ctx, s, generation, "api.example", []nftables.ResolvedIP{{Addr: netip.MustParseAddr("192.0.2.1")}}))
	dial := func(port int, allowed bool) {
		expect := "deny"
		if allowed {
			expect = "allow"
		}
		cmd := exec.Command("nsenter", "-t", strconv.Itoa(client.Process.Pid), "-n", "--", os.Args[0], "-test.run=^TestDomainPacketHelper$", "-test.v")
		cmd.Env = append(os.Environ(), "FAST_NFT_HELPER=client", fmt.Sprintf("FAST_NFT_DEST=192.0.2.1:%d", port), "FAST_NFT_EXPECT="+expect)
		output, err := cmd.CombinedOutput()
		require.NoError(t, err, "port %d expected %s: %s", port, expect, output)
	}
	dial(8443, true)
	// Keep a forwarded connection open across the ordinary policy update;
	// established bypass is intentionally independent of new-flow admission.
	kept := exec.Command("nsenter", "-t", strconv.Itoa(client.Process.Pid), "-n", "--", os.Args[0], "-test.run=^TestDomainPacketHelper$", "-test.v")
	kept.Env = append(os.Environ(), "FAST_NFT_HELPER=kept-client", "FAST_NFT_DEST=192.0.2.1:8443", "FAST_NFT_EXPECT=allow")
	resume, err := kept.StdinPipe()
	require.NoError(t, err)
	keptOutput, err := kept.StdoutPipe()
	require.NoError(t, err)
	kept.Stderr = os.Stderr
	require.NoError(t, kept.Start())
	t.Cleanup(func() { _ = kept.Process.Kill(); _ = kept.Wait() })
	ready := make(chan bool, 1)
	go func() {
		scanner := bufio.NewScanner(keptOutput)
		for scanner.Scan() {
			if scanner.Text() == "ready" {
				ready <- true
				return
			}
		}
		ready <- false
	}()
	select {
	case ok := <-ready:
		require.True(t, ok, "kept-open client failed before its first echo")
	case <-time.After(5 * time.Second):
		t.Fatal("kept-open client readiness timed out")
	}
	a.run = func(ctx context.Context, script string) ([]byte, error) {
		return DefaultRunner(ctx, script+"add element inet "+TableName+" missing_set { 192.0.2.99 }\n")
	}
	require.Error(t, a.ApplyPolicy(ctx, s, narrow))
	dial(8443, true) // failed narrowing cannot publish either rules or lease state
	a.run = DefaultRunner
	require.NoError(t, a.ApplyPolicy(ctx, s, narrow))
	_, err = fmt.Fprintln(resume, "policy updated")
	require.NoError(t, err)
	require.NoError(t, resume.Close())
	keptResult, err := io.ReadAll(keptOutput)
	require.NoError(t, err)
	require.NoError(t, kept.Wait(), "existing forwarded flow must survive ordinary scoped deny: %s", keptResult)
	dial(443, true)
	dial(8443, false)
	require.NoError(t, a.ApplyPolicy(ctx, s, denied))
	dial(443, false)
	dial(8443, true)
	require.NoError(t, a.ApplyPolicy(ctx, s, narrow))
	// Both original ports reach exactly the same listener after DNAT. Only
	// conntrack original address+port can distinguish the admitted flow.
	_, err = DefaultRunner(ctx, strings.Join([]string{
		"add table ip domain_packet_nat",
		"add chain ip domain_packet_nat prerouting { type nat hook prerouting priority -100; policy accept; }",
		"add rule ip domain_packet_nat prerouting ip saddr 10.0.0.5 ip daddr 192.0.2.1 tcp dport { 443, 8443 } dnat to 10.0.0.1:18081", ""}, "\n"))
	require.NoError(t, err)
	dial(443, true)
	dial(8443, false)
}

func TestDomainKernelTCPRefreshKeepsSiblingDeadline(t *testing.T) {
	if !isolatedDomainKernel(t) {
		return
	}
	ctx := context.Background()
	a := NewApplier(nil)
	now := time.Now()
	a.now = func() time.Time { return now }
	s := subject.FromSandboxUID("tcp-deadlines")
	require.NoError(t, a.ApplyDenyFirst(ctx, s, testSlot("deadlines", "10.0.0.5")))
	require.NoError(t, a.ApplyPolicy(ctx, s, domainPolicy(t, `{"defaultAction":"deny","egress":[{"action":"allow","target":"api.example","ports":[443,8443]}]}`)))
	_, generation, _ := a.ResolutionPolicy(s, netip.MustParseAddr("10.0.0.5"))
	addr := netip.MustParseAddr("192.0.2.1")
	require.NoError(t, a.AddResolvedDomain(ctx, s, generation, "api.example", []nftables.ResolvedIP{{Addr: addr}}))
	sibling := kernelDomainElement(t, s, tcpSetName(s, "v4", true), addr.String()+" . 8443", true)
	match := regexp.MustCompile(`expires ([0-9a-z.]+)`).FindStringSubmatch(sibling)
	require.Len(t, match, 2, "%s", sibling)
	siblingLeft, err := time.ParseDuration(match[1])
	require.NoError(t, err)
	a.conntrack = func(context.Context) ([]conntrackEntry, error) {
		return parseConntrackTCPEntries([]byte("ipv4 2 tcp 6 431999 ESTABLISHED src=10.0.0.5 dst=192.0.2.1 sport=51234 dport=443 src=192.0.2.1 dst=10.0.0.5 sport=443 dport=8443")), nil
	}
	now = now.Add(20 * time.Second)
	a.refreshTick(ctx)
	for _, tc := range []struct {
		port             int
		minimum, maximum time.Duration
	}{
		{443, 350 * time.Second, 360 * time.Second},
		// Only the injected planning clock advances; unchanged kernel
		// members must retain their existing wall-clock timeout.
		{8443, siblingLeft - 5*time.Second, siblingLeft},
	} {
		text := kernelDomainElement(t, s, tcpSetName(s, "v4", true), fmt.Sprintf("%s . %d", addr, tc.port), true)
		match := regexp.MustCompile(`expires ([0-9a-z.]+)`).FindStringSubmatch(text)
		require.Len(t, match, 2, "%s", text)
		left, err := time.ParseDuration(match[1])
		require.NoError(t, err)
		require.Greater(t, left, tc.minimum)
		require.LessOrEqual(t, left, tc.maximum)
	}
	now = now.Add(time.Minute)
	// Model expiry racing the transaction: deletion must also succeed if
	// the kernel has already removed the old member.
	output, err := exec.Command("nft", "delete", "element", "inet", TableName, tcpSetName(s, "v4", true), "{", addr.String(), ".", "8443", "}").CombinedOutput()
	require.NoError(t, err, "%s", output)
	a.refreshTick(ctx)
	kernelDomainElement(t, s, tcpSetName(s, "v4", true), addr.String()+" . 443", true)
	kernelDomainElement(t, s, tcpSetName(s, "v4", true), addr.String()+" . 8443", false)
	kernelDomainElement(t, s, dynSetName(s, "v4"), addr.String(), false)
}

func TestDomainKernelDNSRecoveryBeforeActivityPlanning(t *testing.T) {
	if !isolatedDomainKernel(t) {
		return
	}
	for _, scoped := range []bool{false, true} {
		t.Run(fmt.Sprintf("scoped_%t", scoped), func(t *testing.T) {
			ctx := context.Background()
			a := NewApplier(nil)
			now := time.Now()
			a.now = func() time.Time { return now }
			s := subject.FromSandboxUID("dns-recovery-kernel")
			att := testSlot("dns-recovery-kernel", "10.0.0.5")
			require.NoError(t, a.ApplyDenyFirst(ctx, s, att))
			ports := ""
			if scoped {
				ports = `,"ports":[443,8443]`
			}
			require.NoError(t, a.ApplyPolicy(ctx, s, domainPolicy(t, fmt.Sprintf(`{"egress":[{"action":"allow","target":"a.example"%s},{"action":"allow","target":"b.example"%s}]}`, ports, ports))))
			_, generation, _ := a.ResolutionPolicy(s, att.IP)
			addr := netip.MustParseAddr("192.0.2.1")
			require.NoError(t, a.AddResolvedDomain(ctx, s, generation, "a.example", []nftables.ResolvedIP{{Addr: addr}}))
			a.conntrack = func(context.Context) ([]conntrackEntry, error) {
				return []conntrackEntry{{src: att.IP, dst: addr, port: 443, state: "ESTABLISHED"}}, nil
			}
			run := a.run
			a.run = func(context.Context, string) ([]byte, error) { return nil, errors.New("refresh unavailable") }
			now = now.Add(30 * time.Second)
			a.refreshTick(ctx)
			now = now.Add(10 * time.Minute)
			a.refreshTick(ctx)
			a.run = run
			require.NoError(t, a.AddResolvedDomain(ctx, s, generation, "b.example", []nftables.ResolvedIP{{Addr: netip.MustParseAddr("192.0.2.2")}}))
			set, element := dynSetName(s, "v4"), addr.String()
			if scoped {
				set, element = tcpSetName(s, "v4", true), addr.String()+" . 443"
			}
			kernelDomainElement(t, s, set, element, false)
			a.refreshTick(ctx)
			kernelDomainElement(t, s, set, element, true)
			if scoped {
				kernelDomainElement(t, s, set, addr.String()+" . 8443", false)
			}
			require.Empty(t, a.states[s].renewalEndpoints)
			a.conntrack = func(context.Context) ([]conntrackEntry, error) { return nil, nil }
			now = now.Add(time.Second)
			a.refreshTick(ctx)
			now = now.Add(361 * time.Second)
			a.refreshTick(ctx)
			kernelDomainElement(t, s, set, element, false)
		})
	}
}
