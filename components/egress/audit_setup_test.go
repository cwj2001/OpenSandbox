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
	"runtime"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/alibaba/opensandbox/egress/pkg/audit"
	"github.com/alibaba/opensandbox/egress/pkg/constants"
	"github.com/alibaba/opensandbox/egress/pkg/dnsproxy"
	"github.com/alibaba/opensandbox/egress/pkg/policy"
)

func TestResolveAuditLevel(t *testing.T) {
	cases := []struct {
		name, audit, profile, revision string
		want                           audit.Level
	}{
		{name: "unset", want: audit.LevelOff},
		{name: "dns", audit: "dns", want: audit.LevelDNS},
		{name: "conn", audit: "conn", profile: constants.ProfileSidecar, want: audit.LevelConn},
		// Audit never fails startup: bad or unsupported settings turn it off.
		{name: "unknown level", audit: "l7", want: audit.LevelOff},
		{name: "fast-sandbox", audit: "conn", profile: constants.ProfileFastSandbox, want: audit.LevelOff},
		{name: "revision runtime", audit: "dns", revision: "true", want: audit.LevelOff},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(constants.EnvEgressAudit, tc.audit)
			t.Setenv(constants.EnvExperimentalRevisionRuntime, tc.revision)
			require.Equal(t, tc.want, resolveAuditLevel(tc.profile))
		})
	}
}

func newAuditTestProxy(t *testing.T) *dnsproxy.Proxy {
	t.Helper()
	t.Setenv(constants.EnvDNSUpstream, "127.0.0.1:53")
	proxy, err := dnsproxy.New(policy.DefaultDenyPolicy(), "", nil, nil)
	require.NoError(t, err)
	return proxy
}

func startAuditGroup(t *testing.T, level audit.Level, mode string) uint16 {
	t.Helper()
	group, stop := startAudit(context.Background(), level, mode, newAuditTestProxy(t))
	stop()
	return group
}

func TestStartAuditGroups(t *testing.T) {
	require.Zero(t, startAuditGroup(t, audit.LevelOff, "dns+nft"))
	require.Zero(t, startAuditGroup(t, audit.LevelDNS, "dns+nft"), "dns level installs no nft log rules")
	require.Zero(t, startAuditGroup(t, audit.LevelConn, "dns"), "conn degrades to DNS without nft")
}

func TestStartAuditDegradesWithoutNFLog(t *testing.T) {
	if runtime.GOOS == "linux" && os.Geteuid() == 0 {
		t.Skip("root can bind NFLOG; the degrade path needs an unprivileged run")
	}
	require.Zero(t, startAuditGroup(t, audit.LevelConn, "dns+nft"),
		"an unprivileged probe or NFLOG bind fails, and no log rules are installed")
}
