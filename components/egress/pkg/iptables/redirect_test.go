package iptables

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSetupRedirectFallsBackToNftWhenIptablesNftOutputAppendFails(t *testing.T) {
	var iptablesCalls [][]string
	var nftScripts []string
	r := redirectRunner{
		runCommand: func(_ context.Context, args []string) ([]byte, error) {
			iptablesCalls = append(iptablesCalls, append([]string(nil), args...))
			return []byte("iptables v1.8.9 (nf_tables):  RULE_APPEND failed (No such file or directory): rule in chain OUTPUT\n"), errors.New("exit status 4")
		},
		runNft: func(_ context.Context, script string) ([]byte, error) {
			nftScripts = append(nftScripts, script)
			return nil, nil
		},
	}

	err := r.setupRedirect(context.Background(), 15353, []netip.Addr{netip.MustParseAddr("10.179.156.2")})

	require.NoError(t, err)
	require.NotEmpty(t, iptablesCalls)
	require.Len(t, nftScripts, 1)
	require.Contains(t, nftScripts[0], "add table ip opensandbox_dns_redirect")
	require.Contains(t, nftScripts[0], "type nat hook output priority -100; policy accept;")
	require.Contains(t, nftScripts[0], "udp dport 53 ip daddr 10.179.156.2 return")
	require.Contains(t, nftScripts[0], "tcp dport 53 redirect to :15353")
	require.False(t, strings.Contains(nftScripts[0], "hook prerouting"))
}

func TestSetupRedirectRetriesNftFallbackWithoutDeleteWhenTableIsMissing(t *testing.T) {
	var nftScripts []string
	r := redirectRunner{
		runCommand: func(_ context.Context, _ []string) ([]byte, error) {
			return []byte("iptables v1.8.9 (nf_tables):  RULE_APPEND failed (No such file or directory): rule in chain OUTPUT\n"), errors.New("exit status 4")
		},
		runNft: func(_ context.Context, script string) ([]byte, error) {
			nftScripts = append(nftScripts, script)
			if len(nftScripts) == 1 {
				return []byte("Error: Could not process rule: No such file or directory\ndelete table ip opensandbox_dns_redirect"), errors.New("exit status 1")
			}
			return nil, nil
		},
	}

	err := r.setupRedirect(context.Background(), 15353, nil)

	require.NoError(t, err)
	require.Len(t, nftScripts, 2)
	require.Contains(t, nftScripts[0], "delete table ip opensandbox_dns_redirect")
	require.NotContains(t, nftScripts[1], "delete table ip opensandbox_dns_redirect")
	require.Contains(t, nftScripts[1], "add table ip opensandbox_dns_redirect")
}

func TestSetupRedirectReturnsOriginalIptablesErrorWhenFallbackIsNotApplicable(t *testing.T) {
	r := redirectRunner{
		runCommand: func(_ context.Context, _ []string) ([]byte, error) {
			return []byte("permission denied"), errors.New("exit status 4")
		},
		runNft: func(_ context.Context, _ string) ([]byte, error) {
			t.Fatal("nft fallback must not run for unrelated iptables errors")
			return nil, nil
		},
	}

	err := r.setupRedirect(context.Background(), 15353, nil)

	require.Error(t, err)
	require.Contains(t, err.Error(), "permission denied")
}
