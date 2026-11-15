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
	"sync"
	"time"
)

const (
	// domainRetention outlives short DNS TTLs: clients cache answers past
	// their TTL, and the attribution is only an annotation, never a verdict.
	domainRetention   = 30 * time.Minute
	maxDomainEntries  = 8192
	maxEventAnswerIPs = 32
)

type domainEntry struct {
	domain  string
	expires time.Time
}

// domainCache maps addresses answered by the sidecar's DNS proxy back to the
// name that produced them. The latest answer wins when names share an address.
type domainCache struct {
	mu      sync.Mutex
	entries map[netip.Addr]domainEntry
	now     func() time.Time
}

func newDomainCache(now func() time.Time) *domainCache {
	return &domainCache{entries: make(map[netip.Addr]domainEntry), now: now}
}

func (c *domainCache) observe(domain string, addrs []netip.Addr, ttl time.Duration) {
	if len(addrs) == 0 {
		return
	}
	now := c.now()
	expires := now.Add(max(ttl, domainRetention))
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, addr := range addrs {
		addr = addr.Unmap()
		if _, ok := c.entries[addr]; !ok && len(c.entries) >= maxDomainEntries {
			c.evictLocked(now)
		}
		c.entries[addr] = domainEntry{domain: domain, expires: expires}
	}
}

func (c *domainCache) lookup(addr netip.Addr) (string, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.entries[addr.Unmap()]
	if !ok || !c.now().Before(e.expires) {
		return "", false
	}
	return e.domain, true
}

// evictLocked runs at capacity: it drops expired entries and, if that frees
// less than an eighth of the cache, arbitrary live ones up to that eighth.
// Freeing a batch keeps the linear scan to once per maxDomainEntries/8
// inserts even when heavy DNS churn holds the cache full; losing a live entry
// only costs an L4 event its domain annotation.
func (c *domainCache) evictLocked(now time.Time) {
	target := maxDomainEntries - maxDomainEntries/8
	for addr, e := range c.entries {
		if !now.Before(e.expires) {
			delete(c.entries, addr)
		}
	}
	for addr := range c.entries {
		if len(c.entries) <= target {
			return
		}
		delete(c.entries, addr)
	}
}
