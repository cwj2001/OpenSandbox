---
title: Egress
description: Per-sandbox outbound control — FQDN allowlists enforced at the DNS and network layers, transparent credential injection, and fail-closed startup.
---

# Egress

Egress is how a sandbox gets a network policy instead of open internet access. It runs as a sidecar sharing the sandbox's network namespace, so every outbound packet passes it — no application configuration, and no way around it from inside. Policy is declared at create time (`networkPolicy`) or by the platform, and enforced continuously.

![Egress control flow](../../public/images/egress-control-flow.svg)

## Capabilities at a glance

| Capability | What you get |
|---|---|
| FQDN rules | Allow or deny by domain, wildcard (`*.pypi.org`), IP, or CIDR — optionally scoped to TCP destination ports |
| DNS filtering (default) | Denied domains fail resolution; allowed ones resolve normally |
| Network enforcement (`dns+nft`) | Strict default-deny at the packet layer, fed by DNS-resolved addresses with bounded leases |
| Platform overlays | Operator-set `deny.always` / `allow.always` floors that user policy cannot override, plus a TCP port floor (`reachable.ports.cap`) that caps which ports are reachable at all |
| Credential Vault | Secrets stay in the sidecar; credentials are injected into matching outbound requests |
| Transparent TLS interception (L7) | See, control, and authenticate outbound HTTPS — production-usable mechanism, experimental configuration surface |
| Fail-closed startup | If enforcement cannot be installed, the sidecar exits — it never runs as a no-op |
| [Outbound audit](#outbound-audit) | Opt-in per-DNS-query and per-connection allow/deny events, including literal-IP dials |

## How interception works

- **Layer 1 — DNS.** All port-53 traffic is redirected into the sidecar's DNS proxy. Denied domains answer `NXDOMAIN`; allowed domains resolve through to the real upstream, and their resolved addresses are recorded.
- **Layer 2 — Network (`dns+nft` mode).** nftables drops everything not explicitly allowed. Allowed traffic passes by static rule or via DNS-learned address sets: a resolved IP receives a bounded lease (with a grace window for active TCP connections), so "allowed" never silently becomes "allowed forever". UDP and QUIC flows rely on DNS lease timing alone.
- <span id="precedence"></span>**Precedence.** First matching rule wins: platform `deny.always`, then platform `allow.always`, then your policy — the platform's deny always beats your allow. Overlays live inside the sidecar image and hot-reload every minute; a reload publishes only after nftables accepts the corresponding static policy. Parse or apply failures keep the last accepted in-memory rules and stay eligible for retry.
- **Runtime mutation.** Your policy is set per sandbox and can be mutated at runtime (add, replace, remove by target) through the API the SDKs expose.

**Port floor.** Operators can also ship an `reachable.ports.cap` file next to the overlays: a whitelist of TCP ports (one port or `lo-hi` range per line) that are reachable **at all**. The sidecar derives the complement and enforces it as an always-deny ahead of every user rule — so regardless of what a sandbox's `defaultAction` or allow rules say, only the whitelisted ports pass (TCP only; the same fail-closed ordering that makes a deny rule win over any allow). A missing or empty file means no floor. Under transparent MITM, the floor still applies to mitmproxy's own upstream connections, so keep intercepted ports within the whitelist — a non-whitelisted intercepted port fails at the proxy instead of passing silently. The floor never blackholes interception itself: flows redirected into the mitmproxy listener are accepted ahead of the floor because the redirect rewrites their destination port before the policy chain runs (see [Port-scoped rules](#port-scoped-rules)). By default established connections persist after a policy tighten (the nft chain accepts `ct state established,related` before the allow sets). Pass `?dropEstablished=true` on `PATCH`/`DELETE /policy` to drop keep-alive flows to destinations the new policy no longer allows (dns+nft sidecar; see #2329). The teardown rules are carried across later applies until the destination is allowed again or the established-flow conntrack timeout (`nf_conntrack_tcp_timeout_established`) has passed.

### Port-scoped rules

A rule's `target` may be omitted when `ports` is set, so a rule can scope by TCP destination port alone — `{"action": "deny", "ports": [25]}` blocks outbound SMTP regardless of destination. `target` and `ports` can also combine to scope an IP or CIDR rule to specific ports. Ports are enforced at the network layer (`dns+nft` mode) as `tcp dport` matches, and a deny rule — port-scoped or not — always wins over an allow rule.

**DNS limitation for targetless allows.** The DNS proxy only resolves hostnames matched by a domain rule; a targetless `allow` with `ports` is invisible to it. Under `defaultAction: deny`, hostname lookups therefore still fail (`NXDOMAIN`) and such a rule serves clients that dial IPs directly. Hostname access needs explicit domain allow rules — which are not port-scoped — or destinations addressed by stable IP.

Current limits: TCP only (no UDP); at most 256 ports per rule; domain targets cannot combine with `ports` (domain rules are evaluated at the DNS layer, which has no port dimension) and are rejected at validation; `DELETE /policy` removes rules by `target` — port-only rules have none, so `DELETE` with an explicit empty string (`""`) in the target list removes them all, or a full `POST`/`PUT` replaces the policy. The Fast Sandbox profile supports the same TCP port-scoped rules per subject: allowed traffic is marked in prerouting, denied traffic is dropped in the subject's forward chain, and MITM-redirected traffic is checked in the input chain against its conntrack original destination and port. Independently of user rules, operators can cap reachable ports platform-wide with the `reachable.ports.cap` floor (see [Precedence](#precedence)). One boundary to keep in mind in the classic profile: under transparent MITM, intercepted ports are redirected into the sidecar (destination rewritten to the mitmproxy listener port) before the nft policy chain sees them, so the chain accepts that rewritten destination ahead of port-scoped rules and interception works under default-deny policies and port floors — port-scoped rules and the cap then govern mitmproxy's own re-originated connections, keeping the interception port list within the cap.

## Design decisions

| Decision | Rationale |
|---|---|
| Enforcement lives in the data path | The sidecar installs redirect rules in the shared namespace; the workload holds no `NET_ADMIN`, so there is nothing to bypass and no application cooperation required. |
| Two layers, two costs | DNS filtering alone is cheap and universal but only gates names. `dns+nft` adds packet-level default-deny with DNS-learned, leased exceptions. |
| Encrypted DNS is an escape hatch | DoT (853) is always dropped, and blocking DoH over 443 is a one-switch option. |
| Fail-closed over best-effort | If redirect rules cannot be installed, the sidecar exits instead of running as silent pass-through; a supervisor restarts it with backoff and a crash-loop breaker. |
| Portable by fallback, honest about limits | Redirects install via iptables where available and fall back to native nftables (Firecracker-style guest kernels). gVisor does not support the nftables features either path needs, so neither works there — Kata is the supported secure runtime — and transparent mesh sidecars conflict by construction. |

## Transparent TLS interception (L7)

Layers 1 and 2 decide *whether* a connection may happen; the transparent MITM layer adds control and visibility over *what goes through it*. When enabled, outbound HTTP and HTTPS is redirected into a mitmproxy listener inside the sidecar, which recovers the true destination from connection state and terminates TLS on the sandbox's behalf.

**Status: experimental but production-usable.** Interception, credential injection, and CA delivery are complete and run in production settings; the configuration surface — extra ports and diagnostic switches — may still change between releases.

::: warning Internal OSEP-0023 revision runtime
`OPENSANDBOX_EGRESS_EXPERIMENTAL_REVISION_RUNTIME=true` is a development-only gate (default off) for the OSEP-0023 revision protocol. It adds no public configuration surface or supported `interceptionMode`. It selects sidecar live admission or Fast Sandbox subject installation according to the process profile.

The internal Fast Sandbox subject receiver remains installation-only unless both that revision gate and `OPENSANDBOX_EGRESS_EXPERIMENTAL_FSB_TLS_ADMISSION=true` are set. The admission gate alone fails startup. This B3b-1 experiment adds per-subject TLS handshake admission and shared process accounting; **all decrypted HTTP/1.1 and HTTP/2 requests are deliberately terminated before forwarding or credential lookup**, including old connections after suspend, Unload or source-IP reuse. Token-bound request admission and verified tracked-connection teardown are deferred to B3b-2. Do not enable this gate in production before B4 opaque transport teardown is implemented.

The experimental connection limits are `OPENSANDBOX_EGRESS_FSB_TLS_CAPACITY` (per subject, default 32) and `OPENSANDBOX_EGRESS_FSB_PROCESS_TLS_CAPACITY` (process, default 131072), each bounded to 1–1048576 using the existing integer environment parser. Per-subject limits are not reserved allocations. These defaults have not been measured for memory use; B6 must establish release defaults. Exhaustion terminates only new bound handshakes; existing memberships stay charged until disconnect, while opaque traffic consumes no decision-registry slot. Admission uses the dispatch snapshot, never the receiver's installation readback. On non-443 destinations, SNI-bearing TLS is denied even for a matching static selector; ECH and no-SNI retain their earlier opaque exceptions. This intentionally preserves the stricter existing classifier and CR-1 behavior.

The bounded `egress.mitm.tls.connections_total` reasons include `registry_exhausted`. `egress.mitm.tls.registry.occupancy` and `egress.mitm.tls.registry.configured_budget` are histograms of admission/disconnect observations with only `profile=fast-sandbox` and `scope=process|subject` beyond shared process attributes. They contain no subject identity and are not time-weighted occupancy, aggregate subject gauges, or memory measurements. Both gates off, or only the revision gate on, retain the prior launch arguments and child environment.

The Fast Sandbox management transport has a separate `OPENSANDBOX_EGRESS_ACTIONS_API_VERSION` switch (default v1). Its experimental v2 value only selects strict Actions/relay HTTP routes; it does not enable the OSEP-0023 revision runtime or TLS interception. A v2 Fastlet Pool and every egress Handler must use the same version. V2 supports legacy-mode binding and Vault/Policy relay operations for clean-base Firecracker sandboxes; snapshots, template state, pause/resume, and restore are unsupported. Owner metadata fences the Sandbox runtime but is not caller authentication. Because the listener is on Pod-netns loopback, verify management-port isolation for the exact Fastlet Pod composition before enabling v2; this code does not configure or test that isolation.

Strict requests carry an explicit `mode: legacy`. The egress persists the complete owner and `active`/`retiring`/`retired` phase in `<policy-dir>/<uid>.json.owner` using the existing atomic writer. Retirement records are retained without credential material; late SET/Hook/relay operations cannot revive them after restart. This slice rejects same-UID rebind and live `SET null`; use terminal Sandbox Delete and a new UID. A never-registered owner is reported as `absent`, not `retired`; REMOVE first writes its terminal fence. Reopening a directory containing owner records with the v1 switch is rejected. Do not delete these records or roll the whole deployment back to an older binary that does not understand them.


The internal sidecar experiment covers bound HTTPS/443 HTTP/1.1 traffic and experimental HTTP/2 admission and bounded-drain wiring on the fixed-dependency direct/lazy path. Configured chained upstream proxies remain rejected for live HTTP/2. Long-held responses can still cause Go retries to time out; full client migration and Linux acceptance remain follow-up work. Key properties:

- Admission is per connection and per request, from an immutable snapshot installed over an authenticated channel; unknown or mismatched state denies — the mode never falls back to decrypt-all.
- Any uncertain outcome (unconfirmed mutation, session cleanup failure, unexpected child exit) latches a sticky recovery-required state: readiness drops, nft writes quiesce, and an independent quarantine table is installed for the process lifetime. Restarting the sidecar is not a verified recovery — destroy and recreate the sandbox instead.
- Updates are not one atomic visibility boundary: nft rules can affect traffic before receiver acknowledgement, and a committed update is not rolled back if the API response is lost. Retired connections drain within a bounded window (default 30 seconds).

Full contract, including the egress-owned policy-file storage requirements when `OPENSANDBOX_EGRESS_POLICY_FILE` is set: [credential vault guide](/guides/credential-vault#experimental-live-credential-bound-admission-osep-0023), [OSEP-0023](https://github.com/opensandbox-group/OpenSandbox/blob/main/oseps/0023-credential-bound-tls-interception.md), and the [HTTP/2 integration boundary](/architecture/network/osep-0023-h2-integration).
:::

**Trust is delivered, not disabled.** The sidecar exports its CA, and sandbox bootstrap installs it into the system, NSS, and JDK trust stores on a best-effort basis — clients keep certificate verification on (`curl` without `-k`). Chromium-family images should ship the native `certutil` package so the per-user NSS store can be updated.

Bootstrap waits for the exported CA before trusting it, guarding against a stale export left behind by a restarting egress sidecar: a file that was already present when bootstrap started is only trusted after an observed purge or content change, or after remaining unchanged for a full stabilization window. A background rotation watcher keeps running for the sandbox lifetime and reinstalls all trust stores whenever the exported CA content changes — this covers egress sidecar restarts that rotate the CA (the ephemeral mitmproxy confdir regenerates it) without restarting the sandbox container. Env vars (`NODE_EXTRA_CA_CERTS`, `REQUESTS_CA_BUNDLE`, `SSL_CERT_FILE`) reference stable file paths whose content is refreshed in place, so newly started processes pick up the rotated CA without re-exec; long-running processes that cached the old CA in memory (for example JVM `cacerts`) still need a restart. Install passes are retried up to three times per CA generation before giving up until the next rotation. The timing knobs, with defaults, are `MITM_CA_WAIT_TIMEOUT` (300s — how long bootstrap waits for the initial export), `MITM_CA_STABILIZE_WINDOW` (15s — how long a pre-existing export must stay unchanged before it is trusted), `MITM_CA_POLL_INTERVAL` (0.5s — wait-loop poll frequency), and `MITM_CA_WATCH_INTERVAL` (30s — rotation watch frequency).

What it enables:

- **Credential Vault** — injection happens when request headers are read, so it applies regardless of body size, including fully streamed uploads.
- **TLS-level observability** — optional request-level outcome metrics (decrypt / passthrough) for targeted diagnostic windows.

**Extendable at L7.** The bundled system addon always loads first, then any comma-separated mitmproxy addons in `OPENSANDBOX_EGRESS_MITMPROXY_SCRIPT`, in order. Addons are standard mitmproxy scripts with the full L7 hook surface (hostname, method, URI path, headers, bodies), so operators can add hostname/method/header filtering, header injection, or request rewriting as ordinary Python addons — on top of, never ahead of, the built-in behavior.

**Chained upstream proxy.** Set `OPENSANDBOX_EGRESS_UPSTREAM_PROXY` to `http(s)://host[:port]` — optionally with `OPENSANDBOX_EGRESS_UPSTREAM_PROXY_AUTH` (a complete `Proxy-Authorization` value) — to chain all mitmproxy-handled egress through that proxy via `CONNECT`:

- The endpoint accepts only `host[:port]` or a single `/` path, and the host must be a literal IP or dotted domain (a dotless name resolves differently through the pod resolver's search list, so containment sets could miss the dialed address). Credentials, query, fragment, and other paths are rejected.
- Fail-closed: flows that cannot be chained (no SNI, `ignore_hosts`/`tcp_hosts`/`udp_hosts` matches, UDP) are refused rather than sent direct. Chaining requires transparent MITM, plus `dns+nft` outside the fast-sandbox profile; invalid combinations fail startup.
- Under `dns+nft`, the proxy endpoint is reachable only from the mitmproxy process (UID-, IP-, and port-scoped nft rules), never through the sandbox allow sets. Literal proxy IPs are permanently seeded in those sets; DNS-learned ones use bounded TTLs.
- Fast-sandbox profile: the endpoint is dropped profile-wide ahead of per-subject rules, and its hostname is registered as an infrastructure domain. The shared mitmproxy queries the pod resolver and its forward upstreams concurrently and seeds permanent drop sets with the union; startup fails (previous kernel table intact) unless both succeed with a nonempty union.
- Configuration: the server's `[egress.upstream_proxy]` section on Docker and Kubernetes — see [server configuration](https://github.com/opensandbox-group/OpenSandbox/blob/main/server/configuration.md#egress) and [Chained Upstream Proxy Operations](/guides/egress-upstream-proxy). The same section can deliver an extra CA bundle (a Docker host PEM path or a Kubernetes Secret mounted read-only into the egress sidecar only) that mitmproxy trusts in addition to — never instead of — the system roots.

**Scope notes:**

- Ports 80 and 443 are always intercepted; a bounded list of extra ports can be added. Vault binding matching currently fires on 80/443 only — extra ports are decrypted and logged but not credentialed.
- IPv6 destinations are intercepted alongside IPv4 (listeners and redirect rules cover both address families).
- A not-yet-initialized proxy is visible in health: the sidecar answers `503 mitmproxy not ready` rather than passing traffic unexamined.
- An SSE body larger than ~1 MB can be truncated when the origin closes the connection with a TCP RST mid-body — standard TCP semantics, not an interception bug. See [Egress SSE Truncation](/guides/egress-sse-truncation).

## Credentials without secrets in the sandbox

With transparent TLS interception enabled, the sidecar can inject credentials into outbound requests that match a vault binding — bearer tokens, basic auth, API keys, or custom headers. The vault lives in the sidecar's memory only: the sandbox workload sees authenticated traffic but never holds the secret itself. See [Credential Vault](/guides/credential-vault).

## Where it runs

| Deployment | Shape |
|---|---|
| Docker | A separate sidecar container; the sandbox joins the sidecar's network namespace |
| Kubernetes | The sidecar is appended to the sandbox pod and holds the pod's only `NET_ADMIN` |
| Pooled sandboxes | Pre-warmed pods cannot gain a sidecar per request — put required controls in the Pool template (per-request `networkPolicy` + pool references are rejected) |
| Fast Sandbox | A shared egress process per Fastlet pod, one subject per sandbox — see [Fast Sandbox: Networking](/architecture/fast-sandbox/networking) |

## Service Mesh Compatibility

::: warning Not supported with transparent mesh sidecars
Egress is designed to be the only transparent outbound interception layer in the sandbox's network namespace. Deployments that inject a service-mesh sidecar (Istio/Envoy and similar) into the same pod are not currently supported for egress features.
:::

Both layers rewrite outbound traffic in the same namespace, so per-sandbox policy, transparent MITM, and Credential Vault cannot be relied on alongside mesh injection. Prefer excluding sandbox pods from mesh injection, or enforce outbound policy with a CNI-level mechanism. The same constraint applies to gVisor — use Kata, which provides comparable isolation and full egress support (see the [compatibility matrix](/guides/secure-container#compatibility-matrix)).

## Shutdown

On shutdown, the sidecar keeps DNS and network rules working while in-flight deliveries finish (a bounded window), then removes its network rules and flushes telemetry in the legacy path; the experimental containment owner retains ordinary rules instead. Delivery is best effort — forced termination can drop events. Docker gives the sidecar a 9-second stop budget on deletion. A supervisor restarts crashes with exponential backoff, a crash-loop breaker, and stale-redirect cleanup before a fresh start.

## Observability (OpenTelemetry)

When the platform configures an OTLP endpoint, the sidecar exports per-sandbox metrics: denied request counts, DNS query outcomes (denied-by-policy and resolver-failure are deliberately separate counters — alerting on the wrong one inverts the diagnosis), nftables update failures, and process resource usage. Cardinality is bounded: no queried domain or destination ever becomes a label. See [telemetry](/guides/telemetry#egress-sidecar) for the metric list and export configuration.

## Outbound audit

Outbound audit answers "which destinations did this sandbox reach, and which were blocked?" — one structured event per DNS decision and, under `dns+nft`, one per new TCP/UDP connection, allowed or denied, including connections to literal IPs that never touched DNS. It is off by default and is an operator setting: `OPENSANDBOX_EGRESS_AUDIT` is not on the per-request env allowlist, so a sandbox cannot turn it off. Until the server exposes it, set it in a custom egress image (`ENV OPENSANDBOX_EGRESS_AUDIT=conn`), the same way as the [always-rule files](/guides/network-isolation#approach-1-global-enforced-isolation-via-egress-sidecar-deny-always).

| `OPENSANDBOX_EGRESS_AUDIT` | Events |
|---|---|
| `off` (default) | None. The nftables ruleset is byte-for-byte the unaudited one. |
| `dns` | One `egress.audit.dns` event per query the DNS proxy decides. |
| `conn` | DNS events plus one `egress.audit.connection` event per new TCP/UDP connection. Requires `dns+nft`; otherwise it runs at `dns` and says so in the stream. |

Like the other egress logs, the stream is JSON on stdout, one `opensandbox.event` name per kind: `egress.audit.dns`, `egress.audit.connection`, and `egress.audit.stream` for events about the stream itself. Egress produces it; shipping, retention and access control belong to your log pipeline. It is written on its own logger at `info`, so lowering `OPENSANDBOX_EGRESS_LOG_LEVEL` never silences it.

```json
{"ts":"2026-11-12T04:28:20.401Z","sandbox_id":"sbx-abc","opensandbox.event":"egress.audit.stream","reason":"started","boot_id":"9f2c…","seq":1,"observed_at":"2026-11-12T04:28:20.400Z","coverage":["dns","l4"]}
{"ts":"2026-11-12T04:28:20.466Z","sandbox_id":"sbx-abc","opensandbox.event":"egress.audit.dns","reason":"policy","boot_id":"9f2c…","seq":2,"observed_at":"2026-11-12T04:28:20.465Z","decision":"allow","domain":"pypi.org","dns_query_type":"A","dns_response_code":"NOERROR","resolved_ips":["151.101.0.223"]}
{"ts":"2026-11-12T04:28:21.132Z","sandbox_id":"sbx-abc","opensandbox.event":"egress.audit.connection","reason":"dns_lease","boot_id":"9f2c…","seq":3,"observed_at":"2026-11-12T04:28:21.131Z","decision":"allow","domain":"pypi.org","proto":"tcp","dst_ip":"151.101.0.223","dst_port":443,"dns_seen":true}
{"ts":"2026-11-12T04:28:21.140Z","sandbox_id":"sbx-abc","opensandbox.event":"egress.audit.connection","reason":"ip_rule","boot_id":"9f2c…","seq":4,"observed_at":"2026-11-12T04:28:21.139Z","decision":"deny","proto":"tcp","dst_ip":"10.96.0.10","dst_port":5432,"dns_seen":false,"rule":"10.96.0.0/12","rule_source":"platform"}
{"ts":"2026-11-12T04:28:23.001Z","sandbox_id":"sbx-abc","opensandbox.event":"egress.audit.connection","reason":"default","boot_id":"9f2c…","seq":5,"observed_at":"2026-11-12T04:28:22.010Z","decision":"deny","proto":"udp","dst_ip":"203.0.113.9","dst_port":9999,"dns_seen":false,"count":4210,"window_start":"2026-11-12T04:28:22.010Z","window_end":"2026-11-12T04:28:22.998Z"}
```

| Field | Meaning |
|---|---|
| `opensandbox.event` | `egress.audit.dns`, `egress.audit.connection`, or `egress.audit.stream`. A `dns` allow means the name was allowed to resolve, not that a connection followed. |
| `decision` | `allow` or `deny` — the verdict already taken by the DNS proxy or the nftables chain. |
| `reason` | `dns`: `policy` or `unknown_source`. `connection`: the rule family that decided — `dns_lease` (address learned from an allowed DNS answer), `ip_rule` (IP/CIDR rule), `port_rule` (port-scoped rule, including `reachable.ports.cap`), `dot`, `doh`, or `default` (`defaultAction`). `stream`: see [Completeness](#completeness). |
| `observed_at` | When the sidecar saw the query or connection. `ts` is when the line was written and can trail it under load. |
| `rule`, `rule_source` | For `ip_rule`/`port_rule`: the matching rule (`10.96.0.0/12`, `ports 25`, `reachable.ports.cap`) and whether it came from the platform overlay (`platform`) or the sandbox policy (`user`). Read from the policy when the event is emitted, so a policy changed in between can leave it empty. |
| `domain`, `dns_seen` | For connections: the name this address was last answered for by the sidecar's DNS proxy (kept for 30 minutes or the TTL, whichever is longer). `dns_seen: false` marks a literal-IP dial or a name resolved some other way. |
| `proto`, `dst_ip`, `dst_port` | The connection's destination, named as in execd's eBPF `connect` events so the two can be joined per sandbox: egress says what the policy decided, execd which process dialed. |
| `dns_query_type`, `dns_response_code`, `resolved_ips` | For DNS events: the query type, the code returned to the client, and up to 32 answered addresses. |
| `count`, `window_start`, `window_end` | An aggregated event: `count` queries or connections with these fields, first and last seen in the window (see [Completeness](#completeness)). |
| `boot_id`, `seq` | `seq` counts 1, 2, 3, … per `boot_id` (one per sidecar run) in output order. |

**How connection events are produced.** Each new-connection verdict rule in the chain is preceded by a twin rule with the same match and no verdict, which sends an NFLOG copy of up to the first 128 bytes of conntrack-`new` TCP/UDP packets with the decision and reason in its log prefix. That fixed prefix can include payload bytes after shorter headers; the decoder reads only IP addresses, protocol and ports, and no packet payload is included in audit events. Evaluation always falls through to the original verdict rule, so verdicts and their order are unchanged; infrastructure accepts and the established-connection path are never logged, so an established connection costs nothing. The sidecar binds the NFLOG group before the first ruleset is installed. TCP SYN retransmits and repeated packets of a denied UDP flow are folded into one event per connection attempt for 30 seconds.

### Service isolation

Policy enforcement and DNS availability take priority over audit completeness. Audit does not change a verdict or make request handling wait for the log sink. Collection and buffering are bounded: when audit cannot keep up, it must aggregate or declare collection loss rather than apply backpressure to sandbox requests. Within that resource budget, destination-bearing detail is preferred to destination-free totals. This is not a zero-overhead guarantee: NFLOG copies, collection and log output share sidecar CPU and memory, so operators must size and validate audit with their workload and CPU quota. Complete capture at arbitrary traffic rates cannot be guaranteed without risking the service.

### Completeness

An audit trail with silent holes is not one, so the stream accounts for every query and connection the sidecar observes, and reports every gap in-stream:

- **The writer never drops.** Individual events are budgeted at 1000 per second (burst 2000). Over budget — or when the writer falls behind its 4096-event queue — events are folded into per-second aggregates keyed by event, decision, reason, domain and destination, so volume costs per-attempt detail, never a count. A window holds 1024 keys; beyond that, keys fold into one aggregate per event, decision and reason without a destination. Every event is written: the audit logger does not sample.
- **The reader is budgeted, and receive losses are reported.** The kernel rules carry no rate limit (a kernel limiter would drop copies silently); instead the sidecar budgets connection processing at 500 copies per second in 100 ms windows, to limit CPU competition with the DNS proxy. Each received datagram is processed as a unit, so a window can exceed its budget by a batch. Bursts wait in the bounded receive buffer; `observed_at` can lag the verdict by seconds while that backlog drains, and is not a kernel verdict timestamp. Under a sustained flood the buffer fills and the kernel drops further copies. NFLOG per-instance sequence numbers count those losses in `lost_kernel` when a subsequent copy arrives — this preserves a loss count, not the destinations, verdicts or per-destination counts of missing copies. A TCP SYN retransmit is a copy of its own, so `lost_kernel` bounds the lost connections from above. Loss after the last delivered copy remains uncounted until another copy arrives; heartbeat and stopped events report that uncertainty in `detail`.
- **Gaps are events.** `egress.audit.stream` events describe the stream: `started` (with `coverage`, and a `detail` when L4 is unavailable), `degraded` (a layer stopped while running), `gap` (`lost_kernel`/`lost_undecodable` over `window_start`–`window_end`), `heartbeat` (every minute, cumulative `detailed`/`aggregated`/`deduplicated`/`lost_*` totals) and `stopped` (final totals, after the last aggregates are flushed). Per run, `detailed + aggregated + deduplicated + lost_kernel + lost_undecodable` is every query and L4 copy the sidecar observed; `deduplicated` counts copies folded into an earlier event of the same 5-tuple within 30 seconds (retransmits, repeated packets of a denied UDP flow, or a new attempt that happened to reuse the 5-tuple).
- **Shutdown stays bounded.** The 2-second audit shutdown budget includes stopping the NFLOG reader before publishing final totals and flushing the writer. It does not drain an arbitrary kernel backlog: unread copies are declared in the stopped event's `detail`. If the reader cannot stop within the budget, no final `stopped` event is claimed.
- **Downstream can detect the rest.** A crash, or a writer slower than the shutdown budget, loses queued events without a record; so does anything lost after stdout. Both show up as a `seq` gap, a missing `stopped` event for a `boot_id`, or heartbeats that stop: alert on those, on `egress.audit.lost_total`, and on `egress.audit.l4.active = 0` where `conn` is expected.

### Limits

- Audit never takes the sidecar down or changes a verdict. Before installing audit rules the sidecar checks, in a hookless scratch table, that the kernel accepts the log statement (`nft_log`); if that check or the NFLOG bind fails (missing module, no `CAP_NET_ADMIN`), it audits DNS only, records why in the `started` event, and reports `egress.audit.l4.active = 0`.
- Established-flow teardown drops (`dropEstablished`) are not logged.
- With transparent MITM, the workload's own dial to an intercepted port is redirected to the local listener and accepted as infrastructure, so it is not logged; the connection mitmproxy then opens upstream passes the chain and is logged like any other. With a chained upstream proxy that connection is itself an infrastructure accept, so intercepted flows are not logged at L4.
- The DNS proxy's own upstream queries and infrastructure names (such as an upstream-proxy hostname) are not sandbox activity and are not logged. `log_skip.always` quiets only the `egress.outbound` line, never audit events.
- Not supported with the fast-sandbox profile or the experimental revision runtime; there, as with an unknown value, the sidecar logs a warning and runs without audit.

## Experimental strict Vault v2 writes

The strict Fast Sandbox receiver can prepare a legacy-mode v2 Vault only through its separate, versioned management initialization contract. The paired control plane must authorize a new clean-base subject with a one-shot CAS grant; legacy mode or a missing file is not initialization authority. The owner record retains the initialization ID and lineage, while ordinary writes atomically replace only the Vault file. If the initial Vault write confirms that nothing was published, the receiver atomically rolls back the owner contract in the same request; only a confirmed rollback permits retrying the authorized fresh request. Otherwise incomplete initialization remains unavailable, and restart or a lost initialization acknowledgement requires verification, never another fresh grant. A crash between the owner and Vault writes still requires teardown when the Vault file is missing. This receiver change alone does not enable the feature.

The internal state relay carries a lineage/sequence token even for empty or deleted Vaults. Server-side PATCH retains the token from the read used to construct its update, so a delayed update cannot overwrite a deleted-and-recreated Vault whose public revision is again 1. Public responses omit private tokens and credential values. A lost write acknowledgement requires read-back reconciliation; independently repeated public requests have no new idempotency guarantee. Terminal removal retains the retired owner fence. Snapshot/carry, owner migration, automatic fence garbage collection and explicit credential-bound TLS remain outside this slice.

The paired manager first reads the Handler instance ID from the strict status endpoint, then POSTs to `/_fastlet/v2/vault-initialization/{uid}` with the injected owner/UID headers and `{ "handlerInstanceId": "<observed process>", "mode": "legacy", "fresh": true, "contract": { "version": "sandbox.fast.io/vault-writer/v2", "initializationId": "<authorized ID>", "lineage": "<fixed lineage>" } }`. It must consume the transient fresh grant before sending. This path is outside the ordinary relay namespace. Repeated fresh requests are rejected once the contract exists; subsequent calls use `fresh: false`. The structured ACK contains the Handler instance ID, full owner, initialization ID, state and private token; the manager must match all of them, and invalidate its ACK on Handler restart. HTTP 200 alone is insufficient. The stored contract is a receiver-side fence, not a substitute for the control plane's authorization CAS or deployment-level management listener isolation.

Server operations use the internal `/vault-state/{uid}` relay (mapped by strict Fastlet to `/_fastlet/v2/relay/vault-state/{uid}`). GET returns `{version, handlerInstanceId, owner, initializationId, state, token, vault?}`; `token` contains `lineage` and `sequence`. POST/PUT/DELETE send `{expectedState: token, vault: <ordinary create/replace body>}`; DELETE uses an empty body object. Only a 404 from the state endpoint selects legacy fallback; uncertainty never does. Once initialized, the old Vault mutation endpoint refuses writes without a private precondition. Initialization is not available through the public Vault API. Old receivers reject the new initialization path, and old strict readers reject the extended owner record rather than silently downgrade it.

A writer verify/state request from the current registered owner that detects a missing, malformed or unreadable owner record revokes the verified live Vault and makes subsequent active-socket reads unavailable, including conditional reads. Existing Vault bytes are preserved. Restoring the owner record alone does not republish credentials: a successful verify is required. Invalid request identity or initialization contract cannot clear another valid live Vault. This check runs on the management path, not on every data-plane request; it does not retract responses whose snapshots were captured before invalidation.
