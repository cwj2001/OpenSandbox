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
	"context"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/stretchr/testify/require"
)

func TestCanonicalNFLogPrefixesOwnTheirStorage(t *testing.T) {
	for reason := range l4Reasons {
		for _, decision := range []string{DecisionAllow, DecisionDeny} {
			want := NFLogPrefix(decision, reason)
			wire := append([]byte(want), 0, 0)
			got := canonicalNFLogPrefix(wire)
			require.Equal(t, want, got)
			clear(wire) // receive-buffer reuse cannot mutate emitted strings
			require.Equal(t, want, got)
		}
	}
	for _, invalid := range []string{"", "other-user", "osb-audit:x:default", "osb-audit:d:unknown", "osb-audit:d:default:extra"} {
		require.Empty(t, canonicalNFLogPrefix([]byte(invalid)))
	}
}

func TestReadCancellationDoesNotWaitForBudgetWindow(t *testing.T) {
	pair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	require.NoError(t, err)
	defer unix.Close(pair[0])
	defer unix.Close(pair[1])
	packet := ipv4Packet(protoUDP, "192.0.2.2", "198.51.100.7", 5000, 9999)
	var batch []byte
	for i := range copiesPerWindow + 1 {
		batch = append(batch, nflogPacketMessage(uint32(i), NFLogPrefix(DecisionDeny, ReasonDefault), packet)...)
	}
	require.NoError(t, unix.Sendto(pair[1], batch, 0, nil))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	handled := make(chan struct{})
	returned := make(chan error, 1)
	go func() {
		n := 0
		returned <- (&nflogSocket{fd: pair[0]}).read(ctx, func(uint32) {}, func() {}, func(string, []byte) {
			n++
			if n == copiesPerWindow+1 {
				close(handled)
			}
		})
	}()
	select {
	case <-handled:
	case <-time.After(time.Second):
		t.Fatal("reader did not process the batch")
	}
	cancel()
	select {
	case err := <-returned:
		require.NoError(t, err)
	case <-time.After(time.Second):
		t.Fatal("cancellation ignored while audit budget exhausted")
	}
}

func BenchmarkNFLogBatch(b *testing.B) {
	packet := ipv4Packet(protoUDP, "192.0.2.2", "198.51.100.7", 5000, 9999)
	batch := nflogPacketMessage(0, NFLogPrefix(DecisionDeny, ReasonDefault), packet)
	var seen string
	handle := func(prefix string, _ []byte) { seen = prefix }
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		forEachNFLogPacket(batch, func(uint32) {}, handle)
	}
	if seen == "" {
		b.Fatal("missing packet")
	}
}
