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
	"errors"
	"fmt"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	"github.com/alibaba/opensandbox/egress/pkg/log"
	"github.com/alibaba/opensandbox/egress/pkg/telemetry"
	"github.com/alibaba/opensandbox/internal/safego"
)

// nfnetlink_log wire constants (linux/netfilter/nfnetlink_log.h).
const (
	nfnlSubsysULOG   = 4
	nfulnlMsgPacket  = nfnlSubsysULOG<<8 | 0
	nfulnlMsgConfig  = nfnlSubsysULOG<<8 | 1
	nfulaCfgCmd      = 1
	nfulaCfgMode     = 2
	nfulaCfgTimeout  = 3
	nfulaCfgQThresh  = 4
	nfulaCfgFlags    = 6
	nfulnlCfgCmdBind = 1
	nfulnlCopyPacket = 2
	nfulnlCfgFSeq    = 0x0001
	nfulaPayload     = 9
	nfulaPrefix      = 10
	nfulaSeq         = 12
	nlaTypeMask      = 0x3fff // strips NLA_F_NESTED and NLA_F_NET_BYTEORDER
	nfgenMsgLen      = 4
)

const (
	// nflogCopyRange covers an IPv6 header, bounded extension headers and the
	// transport ports; nothing past the ports is ever copied to userspace.
	nflogCopyRange = 128
	// Deliver in small batches: one receive per copy costs the sidecar a
	// syscall per new connection, which under a connection flood competes
	// with the DNS proxy for CPU. A batch is flushed at 64 copies or after
	// 10ms, so observed_at trails the verdict by at most ~10ms (the kernel
	// default flush timeout of 1s would skew it far more).
	nflogQThreshold   = 64
	nflogFlushTimeout = 1 // 1/100 s
	// The buffer only absorbs bursts under the processing cap below; kept
	// small so a backlog cannot delay observed_at by more than about a second.
	nflogRecvBuffer  = 512 << 10
	nflogRecvTimeout = 500_000 // µs; bounds how long the reader ignores ctx
)

// StartL4 binds the audit NFLOG group and processes packet copies until ctx
// is done. Call it before the audit rules are installed so the first
// verdicts are observed. Errors leave verdicts unaffected: the audit rules
// then have no listener and the kernel discards their copies. A reader that
// fails while running is reported in-stream by a degraded event.
func (c *Collector) StartL4(ctx context.Context) error {
	sock, err := openNFLog(NFLogGroup, nflogRecvBuffer)
	if err != nil {
		return err
	}
	telemetry.SetAuditL4Active(true)
	safego.Go(func() {
		defer unix.Close(sock.fd)
		defer telemetry.SetAuditL4Active(false)
		if err := sock.read(ctx, c.observeSeq, c.markOverrun, c.handleNFLog); err != nil {
			log.Warnf("[audit] nflog receive failed; L4 audit stopped: %v", err)
			c.Degraded([]string{LayerDNS}, "nflog receive failed: "+err.Error())
		}
	})
	return nil
}

type nflogSocket struct {
	fd  int
	seq uint32
}

func openNFLog(group uint16, recvBuffer int) (*nflogSocket, error) {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_NETFILTER)
	if err != nil {
		return nil, fmt.Errorf("open nfnetlink socket: %w", err)
	}
	if err := unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("bind nfnetlink socket: %w", err)
	}
	// A larger buffer absorbs connection bursts; overruns are still counted.
	if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUFFORCE, recvBuffer); err != nil {
		_ = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUF, recvBuffer)
	}
	tv := unix.NsecToTimeval(nflogRecvTimeout * 1000)
	if err := unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("set nfnetlink receive timeout: %w", err)
	}
	s := &nflogSocket{fd: fd}
	if err := s.configure(group, nlAttr(nfulaCfgCmd, []byte{nfulnlCfgCmdBind})); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("bind nflog group %d: %w", group, err)
	}
	mode := make([]byte, 6)
	binary.BigEndian.PutUint32(mode, nflogCopyRange)
	mode[4] = nfulnlCopyPacket
	cfg := append(nlAttr(nfulaCfgMode, mode), nlAttr(nfulaCfgQThresh, be32(nflogQThreshold))...)
	cfg = append(cfg, nlAttr(nfulaCfgTimeout, be32(nflogFlushTimeout))...)
	// Per-instance sequence numbers make every receive-buffer overrun an
	// exact, reported loss count instead of a silent one.
	cfg = append(cfg, nlAttr(nfulaCfgFlags, binary.BigEndian.AppendUint16(nil, nfulnlCfgFSeq))...)
	if err := s.configure(group, cfg); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("configure nflog group %d: %w", group, err)
	}
	return s, nil
}

// configure sends one NFULNL_MSG_CONFIG request and waits for its ack.
func (s *nflogSocket) configure(group uint16, attrs []byte) error {
	s.seq++
	msg := make([]byte, unix.NLMSG_HDRLEN+nfgenMsgLen+len(attrs))
	binary.NativeEndian.PutUint32(msg[0:4], uint32(len(msg)))
	binary.NativeEndian.PutUint16(msg[4:6], nfulnlMsgConfig)
	binary.NativeEndian.PutUint16(msg[6:8], unix.NLM_F_REQUEST|unix.NLM_F_ACK)
	binary.NativeEndian.PutUint32(msg[8:12], s.seq)
	msg[16] = unix.AF_UNSPEC
	msg[17] = 0 // NFNETLINK_V0
	binary.BigEndian.PutUint16(msg[18:20], group)
	copy(msg[20:], attrs)
	if err := unix.Sendto(s.fd, msg, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return err
	}
	buf := make([]byte, 8192)
	for {
		n, _, err := unix.Recvfrom(s.fd, buf, 0)
		if err != nil {
			return err
		}
		var ackErr error
		acked := false
		forEachNetlinkMessage(buf[:n], func(typ uint16, seq uint32, data []byte) {
			if acked || typ != unix.NLMSG_ERROR || seq != s.seq || len(data) < 4 {
				return
			}
			acked = true
			if code := int32(binary.NativeEndian.Uint32(data[:4])); code != 0 {
				ackErr = unix.Errno(-code)
			}
		})
		if acked {
			return ackErr
		}
	}
}

// The reader processes at most maxCopiesPerSecond copies, in windows of
// copyWindow. Past a window's share it stops reading until the window ends:
// the socket buffer fills, the kernel drops further copies, and the sequence
// check counts each one as lost_kernel. During a connection flood this caps
// the CPU audit takes from the DNS proxy sharing the sidecar's quota: with a
// 0.25-core sidecar, 2000/s still doubled DNS p99 under a flood, while 500/s
// left it at the unaudited level. Bursts above the rate wait in the socket
// buffer instead of being dropped.
const (
	maxCopiesPerSecond = 500
	copyWindow         = 100 * time.Millisecond
	copiesPerWindow    = maxCopiesPerSecond * int(copyWindow) / int(time.Second)
)

// read returns nil when ctx is done and the error that stopped it otherwise.
func (s *nflogSocket) read(ctx context.Context, observeSeq func(uint32), overrun func(), handle func(prefix string, payload []byte)) error {
	buf := make([]byte, 1<<16)
	windowEnd, copies := time.Now().Add(copyWindow), 0
	for ctx.Err() == nil {
		if now := time.Now(); !now.Before(windowEnd) {
			windowEnd, copies = now.Add(copyWindow), 0
		} else if copies >= copiesPerWindow {
			select {
			case <-ctx.Done():
				return nil
			case <-time.After(time.Until(windowEnd)):
			}
			continue
		}
		n, _, err := unix.Recvfrom(s.fd, buf, 0)
		if err != nil {
			switch {
			case errors.Is(err, unix.EAGAIN), errors.Is(err, unix.EINTR):
			case errors.Is(err, unix.ENOBUFS):
				// The lost copies show up as a sequence gap once the next
				// copy arrives; until then the loss is known but uncounted.
				overrun()
			default:
				return err
			}
			continue
		}
		copies += forEachNFLogPacket(buf[:n], observeSeq, handle)
	}
	return nil
}

// forEachNFLogPacket reports the sequence number of every NFULNL_MSG_PACKET
// in a netlink datagram, then calls handle with its prefix and payload. It
// returns how many packet messages the datagram held.
func forEachNFLogPacket(b []byte, observeSeq func(uint32), handle func(prefix string, payload []byte)) int {
	packets := 0
	forEachNetlinkMessage(b, func(typ uint16, _ uint32, data []byte) {
		if typ != nfulnlMsgPacket || len(data) < nfgenMsgLen {
			return
		}
		var prefix string
		var payload []byte
		forEachAttr(data[nfgenMsgLen:], func(typ uint16, value []byte) {
			switch typ {
			case nfulaPrefix:
				prefix = strings.TrimRight(string(value), "\x00")
			case nfulaPayload:
				payload = value
			case nfulaSeq:
				if len(value) == 4 {
					observeSeq(binary.BigEndian.Uint32(value))
				}
			}
		})
		packets++
		if payload != nil {
			handle(prefix, payload)
		}
	})
	return packets
}

func forEachNetlinkMessage(b []byte, fn func(typ uint16, seq uint32, data []byte)) {
	for len(b) >= unix.NLMSG_HDRLEN {
		size := int(binary.NativeEndian.Uint32(b[0:4]))
		if size < unix.NLMSG_HDRLEN || size > len(b) {
			return
		}
		fn(binary.NativeEndian.Uint16(b[4:6]), binary.NativeEndian.Uint32(b[8:12]), b[unix.NLMSG_HDRLEN:size])
		b = b[min(nlAlign(size), len(b)):]
	}
}

func forEachAttr(b []byte, fn func(typ uint16, value []byte)) {
	for len(b) >= 4 {
		size := int(binary.NativeEndian.Uint16(b[0:2]))
		if size < 4 || size > len(b) {
			return
		}
		fn(binary.NativeEndian.Uint16(b[2:4])&nlaTypeMask, b[4:size])
		b = b[min(nlAlign(size), len(b)):]
	}
}

func nlAttr(typ uint16, value []byte) []byte {
	b := make([]byte, nlAlign(4+len(value)))
	binary.NativeEndian.PutUint16(b[0:2], uint16(4+len(value)))
	binary.NativeEndian.PutUint16(b[2:4], typ)
	copy(b[4:], value)
	return b
}

func be32(v uint32) []byte {
	return binary.BigEndian.AppendUint32(nil, v)
}

func nlAlign(n int) int {
	return (n + 3) &^ 3
}
