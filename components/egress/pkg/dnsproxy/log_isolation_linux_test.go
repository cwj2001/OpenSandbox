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
	"context"
	"os"
	"syscall"
	"testing"
	"time"

	"github.com/alibaba/opensandbox/egress/pkg/audit"
	"github.com/alibaba/opensandbox/egress/pkg/log"
	"github.com/alibaba/opensandbox/egress/pkg/policy"
	slogger "github.com/alibaba/opensandbox/internal/logger"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

// A full pipe models the shared stdout stalled by the output writer.
// Exercise the actual pre-reply policy warning, not a substitute log call.
func TestDNSDenialDoesNotWaitForOrdinaryLogOutput(t *testing.T) {
	r, w, err := os.Pipe()
	require.NoError(t, err)
	defer r.Close()
	defer w.Close()
	fd := int(w.Fd())
	require.NoError(t, syscall.SetNonblock(fd, true))
	block := make([]byte, 4096)
	for {
		_, err := syscall.Write(fd, block)
		if err == syscall.EAGAIN {
			break
		}
		require.NoError(t, err)
	}
	require.NoError(t, syscall.SetNonblock(fd, false))

	oldStdout, oldLogger := os.Stdout, log.Logger
	os.Stdout = w
	outputs, err := slogger.OpenOutputs(slogger.Config{Level: "warn"})
	os.Stdout = oldStdout
	require.NoError(t, err)
	pair := audit.NewOutputSink(audit.NewLogSink(outputs.Audit), outputs, audit.DefaultQueueSize)
	ordinary := slogger.NewWithWriter(slogger.Config{Level: "warn"}, pair.OrdinaryWriter(false), pair.OrdinaryWriter(true))
	log.WithLogger(context.Background(), ordinary)
	defer func() { log.Logger = oldLogger }()

	pol, err := policy.ParsePolicy(`{"defaultAction":"deny"}`)
	require.NoError(t, err)
	proxy := &Proxy{userPolicy: pol}
	proxy.refreshEffectivePolicy()
	writer := &fakeRespWriter{remote: addrFromIP("10.0.0.9")}
	q := new(dns.Msg)
	q.SetQuestion("denied.example.", dns.TypeA)
	done := make(chan struct{})
	go func() {
		defer close(done)
		proxy.serveDNS(writer, q)
	}()
	defer func() {
		_ = r.Close() // Release any blocked writer, even when the assertion fails.
		_ = pair.Close(time.Now().Add(100 * time.Millisecond))
		<-done
	}()
	select {
	case <-done:
		require.Len(t, writer.msgs, 1)
		require.Equal(t, dns.RcodeNameError, writer.msgs[0].Rcode)
	case <-time.After(time.Second):
		t.Fatal("DNS denial waited for ordinary logger output")
	}
}
