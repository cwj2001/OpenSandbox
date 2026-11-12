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

package audit

import (
	"encoding/binary"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/require"
)

func ipv4Packet(proto uint8, src, dst string, sport, dport uint16) []byte {
	pkt := make([]byte, 20+8)
	pkt[0] = 0x45
	pkt[9] = proto
	s, d := netip.MustParseAddr(src).As4(), netip.MustParseAddr(dst).As4()
	copy(pkt[12:16], s[:])
	copy(pkt[16:20], d[:])
	binary.BigEndian.PutUint16(pkt[20:22], sport)
	binary.BigEndian.PutUint16(pkt[22:24], dport)
	return pkt
}

func ipv6Packet(next uint8, ext []byte, src, dst string, sport, dport uint16) []byte {
	pkt := make([]byte, 40, 40+len(ext)+8)
	pkt[0] = 0x60
	pkt[6] = next
	s, d := netip.MustParseAddr(src).As16(), netip.MustParseAddr(dst).As16()
	copy(pkt[8:24], s[:])
	copy(pkt[24:40], d[:])
	pkt = append(pkt, ext...)
	ports := make([]byte, 8)
	binary.BigEndian.PutUint16(ports[0:2], sport)
	binary.BigEndian.PutUint16(ports[2:4], dport)
	return append(pkt, ports...)
}

func TestDecodeFlowIPv4(t *testing.T) {
	f, ok := decodeFlow(ipv4Packet(protoTCP, "192.0.2.2", "198.51.100.7", 40000, 443))
	require.True(t, ok)
	require.Equal(t, flow{
		src: netip.MustParseAddr("192.0.2.2"), dst: netip.MustParseAddr("198.51.100.7"),
		sport: 40000, dport: 443, proto: protoTCP,
	}, f)
	require.Equal(t, "tcp", f.protocol())

	f, ok = decodeFlow(ipv4Packet(protoUDP, "192.0.2.2", "198.51.100.7", 5353, 9999))
	require.True(t, ok)
	require.Equal(t, "udp", f.protocol())
	require.Equal(t, uint16(9999), f.dport)
}

func TestDecodeFlowIPv4Rejects(t *testing.T) {
	icmp := ipv4Packet(1, "192.0.2.2", "198.51.100.7", 0, 0)
	_, ok := decodeFlow(icmp)
	require.False(t, ok, "only TCP/UDP carry ports")

	frag := ipv4Packet(protoTCP, "192.0.2.2", "198.51.100.7", 1, 2)
	binary.BigEndian.PutUint16(frag[6:8], 0x0010) // fragment offset 16
	_, ok = decodeFlow(frag)
	require.False(t, ok, "non-first fragments have no transport header")

	badIHL := ipv4Packet(protoTCP, "192.0.2.2", "198.51.100.7", 1, 2)
	badIHL[0] = 0x44
	_, ok = decodeFlow(badIHL)
	require.False(t, ok)

	full := ipv4Packet(protoTCP, "192.0.2.2", "198.51.100.7", 1, 2)
	for n := 0; n < 24; n++ {
		_, ok = decodeFlow(full[:n])
		require.False(t, ok, "truncated to %d bytes", n)
	}
}

func TestDecodeFlowIPv6(t *testing.T) {
	f, ok := decodeFlow(ipv6Packet(protoUDP, nil, "2001:db8::2", "2001:db8::7", 1234, 53))
	require.True(t, ok)
	require.Equal(t, netip.MustParseAddr("2001:db8::7"), f.dst)
	require.Equal(t, uint16(53), f.dport)

	// Hop-by-hop (8 bytes) then a first fragment (offset 0) then TCP.
	ext := []byte{44, 0, 0, 0, 0, 0, 0, 0, protoTCP, 0, 0, 0, 0, 0, 0, 1}
	f, ok = decodeFlow(ipv6Packet(0, ext, "2001:db8::2", "2001:db8::7", 50000, 443))
	require.True(t, ok)
	require.Equal(t, uint8(protoTCP), f.proto)
	require.Equal(t, uint16(443), f.dport)
}

func TestDecodeFlowIPv6Rejects(t *testing.T) {
	laterFragment := []byte{protoTCP, 0, 0x00, 0x08, 0, 0, 0, 1} // offset 1 (8 bytes)
	_, ok := decodeFlow(ipv6Packet(44, laterFragment, "2001:db8::2", "2001:db8::7", 1, 2))
	require.False(t, ok)

	// A chain longer than the bound of destination-options headers.
	var chain []byte
	for i := 0; i <= maxIPv6ExtHeaders; i++ {
		chain = append(chain, 60, 0, 0, 0, 0, 0, 0, 0)
	}
	_, ok = decodeFlow(ipv6Packet(60, chain, "2001:db8::2", "2001:db8::7", 1, 2))
	require.False(t, ok)

	truncated := ipv6Packet(0, []byte{protoTCP, 4}, "2001:db8::2", "2001:db8::7", 1, 2)
	_, ok = decodeFlow(truncated)
	require.False(t, ok, "extension header length points past the copy")
}
