// Copyright 2026 The OpenSandbox Authors
// SPDX-License-Identifier: Apache-2.0

package nftables

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestNftNarrowedCIDRKeepsOnlyCoveredStreams(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	if !isolatedNftTest(t, ctx) {
		return
	}
	startWithdrawalEchoPeer(t, ctx, "443")
	m := NewManagerWithOptions(Options{})
	old := mustPolicy(t, `{"egress":[{"action":"allow","target":"198.18.0.0/30"}]}`)
	next := mustPolicy(t, `{"egress":[{"action":"allow","target":"198.18.0.0/31"},{"action":"allow","target":"198.18.0.3"}]}`)
	require.NoError(t, m.ApplyStatic(ctx, old))
	atWithdrawal := openWithdrawalStream(t, "198.18.0.2", "443")
	atReload := openWithdrawalStream(t, "198.18.0.2", "443")
	kept := openWithdrawalStream(t, "198.18.0.3", "443")
	_, err := m.ApplyStaticComputingEstablishedDrops(ctx, old, next)
	require.NoError(t, err)
	requireWithdrawalDrop(t, ctx, atWithdrawal, 2)
	require.NoError(t, withdrawalEcho(kept, 2))
	require.NoError(t, m.ApplyStatic(ctx, next))
	requireWithdrawalDrop(t, ctx, atReload, 3)
	require.NoError(t, withdrawalEcho(kept, 3))
}
