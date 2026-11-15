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
	"net/netip"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAggregatedDNSOmitsAnswerDetail(t *testing.T) {
	c, out, _ := newTestCollector(t)
	c.budget = tokenBucket{rate: 1} // no detailed admission
	var answers []netip.Addr
	for i := range maxEventAnswerIPs + 5 {
		answers = append(answers, netip.AddrFrom4([4]byte{198, 51, 100, byte(i)}))
	}
	c.RecordDNS(DNSRecord{Domain: "many.example", Decision: DecisionAllow,
		Reason: ReasonPolicy, Answers: answers})
	require.Empty(t, out.events)
	c.tick()
	require.Len(t, out.events, 1)
	require.Empty(t, out.events[0].ResolvedIPs)
	require.Equal(t, "many.example", out.events[0].Domain)
	require.Equal(t, uint64(1), out.events[0].Count)
	require.Equal(t, uint64(1), c.Stats().Aggregated)
}
