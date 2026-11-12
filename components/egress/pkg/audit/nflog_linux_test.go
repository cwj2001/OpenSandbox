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

package audit

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

func netlinkMessage(typ uint16, seq uint32, body []byte) []byte {
	msg := make([]byte, unix.NLMSG_HDRLEN, nlAlign(unix.NLMSG_HDRLEN+len(body)))
	binary.NativeEndian.PutUint32(msg[0:4], uint32(unix.NLMSG_HDRLEN+len(body)))
	binary.NativeEndian.PutUint16(msg[4:6], typ)
	binary.NativeEndian.PutUint32(msg[8:12], seq)
	msg = append(msg, body...)
	return append(msg, make([]byte, cap(msg)-len(msg))...)
}

func nflogPacketMessage(seq uint32, prefix string, payload []byte) []byte {
	body := []byte{unix.AF_INET, 0, 0, 0} // nfgenmsg
	body = append(body, nlAttr(1, make([]byte, 4))...)
	body = append(body, nlAttr(nfulaSeq, be32(seq))...)
	body = append(body, nlAttr(nfulaPrefix, append([]byte(prefix), 0))...)
	// NLA_F_NET_BYTEORDER on the payload type must be masked off.
	body = append(body, nlAttr(nfulaPayload|0x4000, payload)...)
	return netlinkMessage(nfulnlMsgPacket, 0, body)
}

func TestForEachNFLogPacketBatch(t *testing.T) {
	first := ipv4Packet(protoTCP, "192.0.2.2", "198.51.100.7", 40000, 443)
	second := ipv4Packet(protoUDP, "192.0.2.2", "198.51.100.8", 5000, 53)
	batch := append(nflogPacketMessage(7, "osb-audit:d:default", first), netlinkMessage(unix.NLMSG_DONE, 0, nil)...)
	batch = append(batch, nflogPacketMessage(8, "osb-audit:a:ip_rule", second)...)

	type seen struct {
		prefix  string
		payload []byte
	}
	var got []seen
	var seqs []uint32
	forEachNFLogPacket(batch, func(seq uint32) { seqs = append(seqs, seq) }, func(prefix string, payload []byte) {
		got = append(got, seen{prefix, append([]byte(nil), payload...)})
	})
	require.Equal(t, []seen{{"osb-audit:d:default", first}, {"osb-audit:a:ip_rule", second}}, got)
	require.Equal(t, []uint32{7, 8}, seqs)
}

func TestForEachNFLogPacketMalformed(t *testing.T) {
	good := nflogPacketMessage(0, "osb-audit:d:default", ipv4Packet(protoTCP, "192.0.2.2", "198.51.100.7", 1, 2))
	for _, b := range [][]byte{
		good[:10], // shorter than a netlink header
		append(append([]byte{}, good...)[:16], 0xff, 0xff, 0xff, 0xff),                      // header length past the buffer
		netlinkMessage(nfulnlMsgPacket, 0, []byte{unix.AF_INET, 0}),                         // shorter than nfgenmsg
		netlinkMessage(nfulnlMsgPacket, 0, []byte{unix.AF_INET, 0, 0, 0, 0xff, 0x00, 9, 0}), // attr length past the body
	} {
		require.NotPanics(t, func() {
			forEachNFLogPacket(b, func(uint32) {}, func(string, []byte) { t.Fatalf("unexpected packet from malformed input %x", b) })
		})
	}
}

func TestNlAttrPadding(t *testing.T) {
	attr := nlAttr(nfulaCfgCmd, []byte{nfulnlCfgCmdBind})
	require.Len(t, attr, 8)
	require.Equal(t, uint16(5), binary.NativeEndian.Uint16(attr[0:2]))
	require.Equal(t, uint16(nfulaCfgCmd), binary.NativeEndian.Uint16(attr[2:4]))
}

type syncEmitter struct {
	mu     sync.Mutex
	events []Event
}

func (s *syncEmitter) TryEmit(e Event) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = append(s.events, e)
	return true
}

// TestNFLogKernelSequenceGapsCountLoss forces real receive-buffer overruns —
// a tiny buffer that is not read while a flood is copied — and checks that
// the NFLOG sequence numbers account for every lost copy exactly.
func TestNFLogKernelSequenceGapsCountLoss(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	switch os.Getenv("OPENSANDBOX_NFT_TEST") {
	case "1":
		command := exec.CommandContext(ctx, "unshare", "--net", os.Args[0], "-test.run=^"+t.Name()+"$", "-test.v")
		command.Env = append(os.Environ(), "OPENSANDBOX_NFT_TEST=netns")
		output, err := command.CombinedOutput()
		require.NoError(t, err, "isolated nflog test failed: %s", output)
		t.Logf("%s", output)
		return
	case "netns":
	default:
		t.Skip("kernel validation not executed: set OPENSANDBOX_NFT_TEST=1 with nft and network namespace permissions")
	}
	run := func(name string, args ...string) {
		out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
		require.NoError(t, err, "%s %v: %s", name, args, out)
	}
	run("ip", "link", "set", "lo", "up")
	run("ip", "link", "add", "audit0", "type", "dummy")
	run("ip", "addr", "add", "192.0.2.2/24", "dev", "audit0")
	run("ip", "link", "set", "audit0", "up")
	run("ip", "route", "add", "default", "dev", "audit0")

	out := &syncEmitter{}
	c := newCollector(out, nil, time.Now)
	sock, err := openNFLog(NFLogGroup, 4096)
	require.NoError(t, err)
	defer unix.Close(sock.fd)
	cmd := exec.CommandContext(ctx, "nft", "-f", "-")
	cmd.Stdin = strings.NewReader(fmt.Sprintf("add table inet seqtest\n"+
		"add chain inet seqtest out { type filter hook output priority 0; policy accept; }\n"+
		"add rule inet seqtest out meta l4proto udp ct state new log prefix %q group %d\n",
		NFLogPrefix(DecisionDeny, ReasonDefault), NFLogGroup))
	nftOut, err := cmd.CombinedOutput()
	require.NoError(t, err, "%s", nftOut)

	send := func(from, to int) {
		for i := from; i < to; i++ {
			conn, err := net.Dial("udp", net.JoinHostPort("198.51.100.7", strconv.Itoa(10000+i)))
			require.NoError(t, err)
			_, _ = conn.Write([]byte("x"))
			conn.Close()
		}
	}
	const flood = 3000
	send(0, flood) // nobody reads: the 4 KiB buffer overflows almost at once

	readFor := func(d time.Duration) {
		readCtx, stop := context.WithTimeout(ctx, d)
		defer stop()
		require.NoError(t, sock.read(readCtx, c.observeSeq, c.markOverrun, c.handleNFLog))
	}
	readFor(time.Second)
	// Copies lost after the last delivered one are counted when the next
	// copy arrives.
	send(flood, flood+1)
	readFor(time.Second)

	stats := c.Stats()
	t.Logf("stats: %+v", stats)
	require.Positive(t, stats.LostKernel, "the flood must overrun the 4 KiB buffer")
	require.Equal(t, uint64(flood+1), stats.Detailed+stats.Aggregated+stats.Deduplicated+stats.LostKernel+stats.LostUndecodable,
		"every copy is either delivered or counted lost")
	require.False(t, c.overrunPending.Load(), "the later copy resolved the overrun")
}
