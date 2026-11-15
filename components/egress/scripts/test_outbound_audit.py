#!/usr/bin/env python3
# Copyright 2026 The OpenSandbox Authors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Synthetic actual-binary audit exercise; Linux, Python stdlib, no Internet.

Example (build the binary separately):
  sudo python3 components/egress/scripts/test_outbound_audit.py \
    --binary /tmp/egress --artifacts /tmp/audit-results --cpu-quota 0.5

Each mode gets a fresh private network namespace, connected only to synthetic
DNS and TCP/UDP echo servers in the driver's private network namespace. Mounts
are private too; /var is tmpfs so startup cannot touch existing sidecar state.
No host nftables, routes, Docker, or cluster objects are changed. A delegated
cgroup-v2 parent with cpu already enabled is needed for --cpu-quota; this driver
never enables controllers on a shared parent. Services/clients stay outside the
sidecar's own cgroup. Results describe process/cgroup resources, NOT total host
networking overhead. Longer --duration runs are the soak mode. --output-pause
pauses stdout consumption during load; conn must actually block a pipe writer.
Only synthetic audit metadata (never packet payloads) is saved.
"""
from __future__ import annotations


import argparse
import collections
import contextlib
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import shutil
import signal
import socket
import socketserver
import struct
import subprocess
import sys
import threading
import time
import uuid


SCRIPT = Path(__file__).resolve()
DNS_IP, ALLOW_IP, DENY_IP = "192.0.2.1", "192.0.2.2", "192.0.2.3"
ECHO_PORT = 18081
SENTINEL_PORT = ECHO_PORT + 1
SENTINEL = "sentinel.allow.audit.test"
STATS = ("detailed", "aggregated", "deduplicated", "lost_kernel", "lost_undecodable")


def save(path: Path, value: object) -> None:
    """Write machine-readable synthetic metadata."""
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


class AuditStream:
    """Consume emitted JSON lines, validating stream and accounting boundaries."""

    def __init__(self, mode: str) -> None:
        self.mode = mode
        self.records = 0
        self.boot = None
        self.errors = collections.deque(maxlen=20)
        self.started = False
        self.stopped = None
        self.detailed = self.aggregated = 0
        self.loss = collections.Counter()
        self.verdicts = collections.Counter()
        self.sentinel = threading.Event()
        self.dns_sentinel = self.l4_sentinel = False
        self.destinations = collections.Counter()
        self.functional_seen = set()
        self.functional = threading.Event()

    def feed(self, line: str) -> bool:
        """Consume one stdout line; return whether it is audit metadata."""
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            if "egress.audit." in line:
                self.errors.append("malformed audit JSON")
            return False
        if not isinstance(event, dict):
            return False
        name = event.get("opensandbox.event", "")
        if not isinstance(name, str) or not name.startswith("egress.audit."):
            return False
        self.records += 1
        if self.mode == "off":
            self.errors.append("off emitted audit events")
        if self.stopped is not None:
            self.errors.append("record after stopped")
        boot = event.get("boot_id")
        if not isinstance(boot, str) or not boot:
            self.errors.append("missing boot_id")
        if self.boot is None:
            self.boot = boot
        elif boot != self.boot:
            self.errors.append("boot_id changed")
        if type(event.get("seq")) is not int or event["seq"] != self.records:
            self.errors.append("noncontiguous sequence")
        for key in (*STATS, "count"):
            if key in event and (type(event[key]) is not int or event[key] < 0):
                self.errors.append("invalid counter " + key)
                return True
        reason = event.get("reason")
        if self.records == 1 and reason != "started":
            self.errors.append("first record is not started")
        if name == "egress.audit.stream":
            if reason == "started":
                expected = {"dns", "l4"} if self.mode == "conn" else {"dns"}
                coverage = event.get("coverage")
                if (self.started or not isinstance(coverage, list)
                        or any(not isinstance(item, str) for item in coverage)
                        or set(coverage) != expected):
                    self.errors.append("invalid started coverage")
                self.started = True
            elif reason == "degraded":
                self.errors.append("audit coverage degraded")
            elif reason == "gap":
                for key in ("lost_kernel", "lost_undecodable"):
                    self.loss[key] += event.get(key, 0)
            elif reason == "stopped":
                self.stopped = event
        elif name in ("egress.audit.dns", "egress.audit.connection"):
            count = event.get("count", 0)
            if count:
                self.aggregated += count
            else:
                self.detailed += 1
            self.verdicts[name + ":" + str(event.get("decision"))] += count or 1
            if name == "egress.audit.connection":
                key = ("destination_bearing" if event.get("dst_ip") and event.get("dst_port")
                       else "destination_free_aggregated" if count else "destination_free_detailed")
                self.destinations[key] += count or 1
            decision = event.get("decision")
            if name == "egress.audit.dns" and event.get("domain") == f"functional.{decision}.audit.test":
                self.functional_seen.add(("dns", decision))
            if (name == "egress.audit.connection" and event.get("proto") in ("tcp", "udp")
                    and event.get("dst_ip") == (ALLOW_IP if decision == "allow" else DENY_IP)
                    and event.get("dst_port") == ECHO_PORT):
                self.functional_seen.add((event["proto"], decision))
            layers = ("dns", "tcp", "udp") if self.mode == "conn" else ("dns",)
            if all((layer, verdict) in self.functional_seen
                   for layer in layers for verdict in ("allow", "deny")):
                self.functional.set()
            if (name == "egress.audit.dns" and event.get("domain") == SENTINEL
                    and event.get("decision") == "allow"):
                self.dns_sentinel = True
            if (name == "egress.audit.connection" and event.get("proto") == "udp"
                    and event.get("dst_ip") == ALLOW_IP and event.get("dst_port") == SENTINEL_PORT
                    and event.get("decision") == "allow"):
                self.l4_sentinel = True
            if self.dns_sentinel and (self.mode != "conn" or self.l4_sentinel):
                self.sentinel.set()
            if self.mode == "dns" and name == "egress.audit.connection":
                self.errors.append("dns emitted connection event")
        else:
            self.errors.append("unknown audit event " + name)
        return True

    def wait_sentinel(self, timeout: float) -> bool:
        """Wait for emitted DNS and (conn mode) unique-port L4 sentinels."""
        return self.sentinel.wait(timeout)

    def finish(self) -> dict:
        """Reconcile only after stdout EOF and an actually observed sentinel."""
        if self.errors:
            raise ValueError("; ".join(dict.fromkeys(self.errors)))
        if self.mode == "off":
            return {"records": 0}
        if not self.started or self.stopped is None:
            raise ValueError("missing started/stopped event")
        if not self.sentinel.is_set():
            raise ValueError("missing emitted sentinel")
        stats = {key: self.stopped.get(key, 0) for key in STATS}
        if (stats["detailed"], stats["aggregated"]) != (self.detailed, self.aggregated):
            raise ValueError("stream detail/aggregate totals disagree with stopped")
        if any(self.loss[key] != stats[key] for key in ("lost_kernel", "lost_undecodable")):
            raise ValueError("loss totals disagree with gap reports")
        return {"records": self.records, "boot_id": self.boot, "stats": stats,
                "observed_accounted": sum(stats.values()),
                "verdict_counts": dict(self.verdicts),
                "l4_destination_observations": dict(self.destinations),
                "dns_sentinel_emitted": self.dns_sentinel,
                "l4_sentinel_emitted": self.l4_sentinel,
                "uncounted_loss_detail": self.stopped.get("detail", ""),
                "destination_complete": False}


def run(*args: object, **kwargs: object) -> subprocess.CompletedProcess:
    """Run a bounded local command, retaining its precise failure."""
    completed = subprocess.run([str(arg) for arg in args], timeout=30, text=True,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, **kwargs)
    if completed.returncode:
        raise RuntimeError(f"{args[0]} exited {completed.returncode}: {completed.stderr.strip()}")
    return completed


def dns_packet(name: str) -> bytes:
    """Build a synthetic A query with a fixed, checked transaction ID."""
    labels = b"".join(bytes([len(label)]) + label.encode("ascii") for label in name.split("."))
    return struct.pack("!6H", 7391, 0x100, 1, 0, 0, 0) + labels + b"\0\0\1\0\1"


def dns_query(name: str, allowed: bool) -> None:
    """Assert the actual proxy response, including allowed A record content."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(1)
        sock.sendto(dns_packet(name), ("127.0.0.1", 15353))
        answer = sock.recv(4096)
    ident, flags, _, answers, _, _ = struct.unpack("!6H", answer[:12])
    if ident != 7391 or not flags & 0x8000 or flags & 15 != (0 if allowed else 3):
        raise ValueError("unexpected synthetic DNS verdict")
    if allowed and (answers < 1 or not answer.endswith(socket.inet_aton(ALLOW_IP))):
        raise ValueError("allowed DNS did not return synthetic A record")
    if not allowed and answers:
        raise ValueError("denied DNS returned answers")


def echo(ip: str, protocol: str, allowed: bool, port: int = ECHO_PORT) -> None:
    """Assert TCP/UDP echo delivery or non-delivery from a live service."""
    kind = socket.SOCK_STREAM if protocol == "tcp" else socket.SOCK_DGRAM
    delivered = False
    with socket.socket(socket.AF_INET, kind) as sock:
        sock.settimeout(0.4)
        try:
            sock.connect((ip, port))
            sock.sendall(b"synthetic-audit")
            delivered = sock.recv(64) == b"synthetic-audit"
        except (socket.timeout, TimeoutError, ConnectionRefusedError,
                ConnectionResetError, PermissionError):
            pass
    if delivered != allowed:
        raise ValueError(f"{protocol} {ip}: expected allowed={allowed}, got {delivered}")


class DNSLatency:
    """Bound client-side DNS samples while retaining the full completed count/max."""

    def __init__(self, capacity: int = 100000) -> None:
        self.samples = collections.deque(maxlen=capacity)
        self.completed = 0
        self.maximum_ms = None

    def record(self, seconds: float) -> None:
        milliseconds = seconds * 1000
        self.samples.append(milliseconds)
        self.completed += 1
        self.maximum_ms = max(self.maximum_ms or 0, milliseconds)

    def summary(self) -> dict:
        ordered = sorted(self.samples)
        return {
            "completed_queries": self.completed, "retained_samples": len(ordered),
            "truncated": self.completed > len(ordered),
            "p50_ms": ordered[math.ceil(len(ordered) * 0.5) - 1] if ordered else None,
            "p99_ms": ordered[math.ceil(len(ordered) * 0.99) - 1] if ordered else None,
            "max_ms": self.maximum_ms,
            "percentile_scope": "nearest-rank over most recent retained completed queries",
            "max_scope": "all completed queries",
            "measurement_scope": "client userspace monotonic request through validated response; outside sidecar cgroup",
        }


def client(action: str, config: dict) -> dict:
    """Run the real workload inside the sidecar network, outside its cgroup."""
    if action in ("before", "functional"):
        for ip in (ALLOW_IP, DENY_IP):
            for protocol in ("tcp", "udp"):
                echo(ip, protocol, action == "before" or ip == ALLOW_IP)
        if action == "functional":
            dns_query("functional.allow.audit.test", True)
            dns_query("functional.deny.audit.test", False)
        return {"echo_assertions": 4, "dns_assertions": 2 if action == "functional" else 0}
    if action == "sentinel":
        dns_query(SENTINEL, True)
        echo(ALLOW_IP, "udp", True, SENTINEL_PORT)
        return {"dns_assertions": 1, "udp_echo_assertions": 1}
    counters = collections.Counter()
    latency = DNSLatency()
    errors = []
    start = time.monotonic()

    def load(kind: str, rate: float) -> None:
        index = 0
        while rate and time.monotonic() - start < config["duration"]:
            delay = start + index / rate - time.monotonic()
            if delay > 0:
                time.sleep(min(delay, max(0, start + config["duration"] - time.monotonic())))
            if time.monotonic() - start >= config["duration"]:
                break
            try:
                if kind == "probe":
                    for protocol in ("tcp", "udp"):
                        for verdict, ip in (("allow", ALLOW_IP), ("deny", DENY_IP)):
                            echo(ip, protocol, verdict == "allow")
                            counters[f"{protocol}_{verdict}_probes"] += 1
                elif kind == "dns":
                    allowed = index % 2 == 0
                    suffix = "allow" if allowed else "deny"
                    query_started = time.monotonic()
                    dns_query(f"load-{index}.{suffix}.audit.test", allowed)
                    latency.record(time.monotonic() - query_started)
                    counters["dns_allow" if allowed else "dns_deny"] += 1
                else:
                    # Vary destination keys; source ports can repeat. Attempts
                    # are NOT guaranteed unique observed flows or audit copies.
                    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                        try:
                            sock.sendto(b"synthetic-audit", (DENY_IP, 10000 + index % 50000))
                        except PermissionError:
                            # OUTPUT DROP can fail sendto locally with EPERM.
                            counters["denied_udp_local_rejections"] += 1
                    counters["denied_udp_attempts"] += 1
            except (OSError, ValueError) as error:
                errors.append(f"{kind} scheduled_index={index}: {type(error).__name__}: {error}")
                break
            index += 1
            # Never accumulate a catch-up burst when the client falls behind.
            index = max(index, int((time.monotonic() - start) * rate))

    threads = [threading.Thread(target=load, args=("dns", config["dns_rate"])),
               threading.Thread(target=load, args=("udp", config["denied_udp_rate"])),
               threading.Thread(target=load, args=("probe", 1))]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    if errors:
        raise ValueError("client load: " + "; ".join(errors))
    elapsed = time.monotonic() - start
    return {"counts": dict(counters), "elapsed_monotonic_seconds": elapsed,
            "dns_latency": latency.summary(),
            "achieved_rates_per_second": {
                "dns_completed_queries": latency.completed / elapsed,
                "denied_udp_attempts": counters["denied_udp_attempts"] / elapsed},
            "workload": {"dns_queries_per_second": config["dns_rate"],
                         "denied_udp_attempts_per_second": config["denied_udp_rate"],
                         "denied_udp_destination_ports": "10000 + scheduled_index % 50000",
                         "denied_udp_source_ports": "fresh socket, kernel-assigned; reuse possible",
                         "allow_deny_tcp_udp_probe_batches_per_second": 1,
                         "schedule": "monotonic pacing, skip missed slots; no catch-up bursts"}}


class DNSHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        data, sock = self.request
        end = 12
        while end < len(data) and data[end]:
            end += data[end] + 1
        if end + 5 > len(data):
            return
        question = data[12:end + 5]
        qtype = struct.unpack("!H", data[end + 1:end + 3])[0]
        answer = (b"\xc0\x0c\0\1\0\1\0\0\0\x3c\0\4" + socket.inet_aton(ALLOW_IP)
                  if qtype == 1 else b"")
        sock.sendto(data[:2] + struct.pack("!5H", 0x8180, 1, bool(answer), 0, 0)
                    + question + answer, self.client_address)


class UDPHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        data, sock = self.request
        sock.sendto(data, self.client_address)


class TCPHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        self.request.settimeout(1)
        with contextlib.suppress(OSError):
            self.request.sendall(self.request.recv(64))


class TCPServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


class Cgroup:
    """Own exactly one disposable leaf; never change shared controller settings."""

    def __init__(self, parent: str, quota: float | None) -> None:
        self.path = Path(parent) / ("egress-audit-" + uuid.uuid4().hex)
        self.unavailable = None
        try:
            self.path.mkdir()
            if quota is not None:
                cpu_max = self.path / "cpu.max"
                if not cpu_max.exists():
                    raise OSError("cpu controller is not enabled in cgroup parent")
                cpu_max.write_text(f"{max(1, round(quota * 100000))} 100000\n")
        except OSError as error:
            self.close()
            self.path = None
            self.unavailable = str(error)
            if quota is not None:
                raise RuntimeError(f"requested CPU quota unavailable: {error}") from error

    def snapshot(self) -> dict:
        """Read charged cgroup CPU and memory, not total host resources."""
        if self.path is None:
            return {"unavailable": self.unavailable}
        result = {"path": str(self.path)}
        for name in ("cpu.stat", "cpu.max", "memory.current", "memory.peak"):
            file = self.path / name
            if file.exists():
                text = file.read_text().strip()
                if name == "cpu.stat":
                    result[name] = {key: int(value) for key, value in
                                    (line.split() for line in text.splitlines())}
                else:
                    result[name] = int(text) if name.startswith("memory.") else text
        return result

    def close(self) -> None:
        if self.path is not None and self.path.exists():
            self.path.rmdir()


def process_resources(pid: int) -> dict:
    """Sample sidecar user/system CPU and RSS; kernel networking elsewhere excluded."""
    fields = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()
    ticks = os.sysconf("SC_CLK_TCK")
    return {"user_seconds": int(fields[11]) / ticks,
            "system_seconds": int(fields[12]) / ticks,
            "rss_bytes": int(fields[21]) * os.sysconf("SC_PAGE_SIZE")}


def stop(process: subprocess.Popen | None) -> None:
    """Stop only a process created by this run, including on failure."""
    if process is not None and process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=15)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)


def phase(mode: str, config: dict, directory: Path) -> dict:
    """Exercise one fresh sidecar and reconcile its emitted stream."""
    directory.mkdir()
    keeper = binary = None
    group = None
    reader = None
    services = contextlib.ExitStack()
    gate = threading.Event()
    gate.set()
    stream = AuditStream(mode)
    errors = []
    diagnostics = collections.deque(maxlen=20)
    result = {"mode": mode}
    try:
        group = Cgroup(config["cgroup_parent"], config["cpu_quota"])
        keeper = subprocess.Popen(["unshare", "--net", "sleep", "infinity"])
        # Wait until unshare has actually installed the child network namespace.
        deadline = time.monotonic() + 5
        while os.readlink(f"/proc/{keeper.pid}/ns/net") == os.readlink("/proc/self/ns/net"):
            if keeper.poll() is not None or time.monotonic() > deadline:
                raise RuntimeError("child network namespace did not start")
            time.sleep(0.01)
        prefix = ["nsenter", "--target", str(keeper.pid), "--net", "--"]
        run("ip", "link", "add", "audit-up", "type", "veth", "peer", "name", "audit-client")
        run("ip", "link", "set", "audit-client", "netns", keeper.pid)
        for ip in (DNS_IP, ALLOW_IP, DENY_IP):
            run("ip", "addr", "add", ip + "/24", "dev", "audit-up")
        run("ip", "link", "set", "audit-up", "up")
        run(*prefix, "ip", "addr", "add", "192.0.2.10/24", "dev", "audit-client")
        run(*prefix, "ip", "link", "set", "audit-client", "up")
        run(*prefix, "ip", "link", "set", "lo", "up")
        result["routes"] = run(*prefix, "ip", "route", "show", "table", "all").stdout
        for server_type, address, handler in (
                (socketserver.UDPServer, (DNS_IP, 53), DNSHandler),
                (socketserver.UDPServer, (ALLOW_IP, ECHO_PORT), UDPHandler),
                (socketserver.UDPServer, (DENY_IP, ECHO_PORT), UDPHandler),
                (socketserver.UDPServer, (ALLOW_IP, SENTINEL_PORT), UDPHandler),
                (TCPServer, ("0.0.0.0", ECHO_PORT), TCPHandler)):
            server = server_type(address, handler)
            services.callback(server.server_close)
            threading.Thread(target=server.serve_forever, daemon=True).start()
            services.callback(server.shutdown)

        def invoke(action: str) -> dict:
            completed = run(*prefix, sys.executable, SCRIPT, "_client", action,
                            json.dumps(config))
            return json.loads(completed.stdout)

        result["pre_enforcement_services"] = invoke("before")
        policy = {"defaultAction": "deny", "egress": [
            {"action": "allow", "target": ALLOW_IP},
            {"action": "allow", "target": "*.allow.audit.test"}]}
        env = {"PATH": os.environ.get("PATH", os.defpath), "HOME": "/var/egress",
               "OPENSANDBOX_EGRESS_MODE": "dns+nft", "OPENSANDBOX_EGRESS_AUDIT": mode,
               "OPENSANDBOX_EGRESS_RULES": json.dumps(policy),
               "OPENSANDBOX_EGRESS_DNS_UPSTREAM": DNS_IP + ":53",
               "OPENSANDBOX_EGRESS_HTTP_ADDR": "127.0.0.1:18080",
               "OPENSANDBOX_EGRESS_LOG_LEVEL": "warn"}
        result["binary_environment"] = env
        save(directory / "config.json", {"options": config, "environment": env})
        # The tiny exec helper joins the leaf before nsenter/exec, avoiding
        # preexec_fn in a multithreaded process and any unquotaed startup race.
        binary = subprocess.Popen([sys.executable, str(SCRIPT), "_exec",
                                   str(group.path) if group.path else "-",
                                   *prefix, config["binary"]], env=env,
                                  stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

        def consume() -> None:
            try:
                with (directory / "audit.ndjson").open("w") as output:
                    while True:
                        gate.wait()
                        line = binary.stdout.readline()
                        if not line:
                            break
                        text = line.decode("utf-8", errors="replace").strip()
                        if stream.feed(text):
                            output.write(text + "\n")
                        else:
                            diagnostics.append(text)
            except Exception as error:
                errors.append(str(error))

        reader = threading.Thread(target=consume, daemon=True)
        reader.start()
        deadline = time.monotonic() + 15
        # Readiness is tested separately so failed policy assertions are not retried.
        while True:
            probe = subprocess.run([*prefix, sys.executable, "-c",
                                    "import socket; s=socket.create_connection(('127.0.0.1',18080),.2); s.close()"],
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            if probe.returncode == 0:
                break
            if binary.poll() is not None or time.monotonic() > deadline:
                raise RuntimeError("sidecar readiness failed: " + " | ".join(diagnostics))
            time.sleep(0.1)
        result["functional"] = invoke("functional")
        if mode != "off" and not stream.functional.wait(5):
            raise RuntimeError("functional client passed but expected DNS/TCP/UDP audit verdicts were not emitted")
        before = process_resources(binary.pid)
        result["cgroup_before_load"] = group.snapshot()
        load = subprocess.Popen([*prefix, sys.executable, str(SCRIPT), "_client", "load",
                                 json.dumps(config)], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                text=True)
        blocked = False
        peak_rss = before["rss_bytes"]
        load_start = time.monotonic()
        if config["output_pause"]:
            gate.clear()
        try:
            while load.poll() is None:
                elapsed = time.monotonic() - load_start
                if elapsed >= config["output_pause"]:
                    gate.set()
                elif mode == "conn":
                    for file in Path(f"/proc/{binary.pid}/task").glob("*/wchan"):
                        with contextlib.suppress(OSError):
                            blocked |= "pipe_write" in file.read_text()
                peak_rss = max(peak_rss, process_resources(binary.pid)["rss_bytes"])
                if elapsed > config["duration"] + 10:
                    raise RuntimeError("load exceeded duration deadline")
                time.sleep(0.05)
            output, error = load.communicate(timeout=2)
            if load.returncode:
                raise RuntimeError("synthetic client failed: " + error)
            result["load"] = json.loads(output)
        finally:
            gate.set()
            stop(load)
        after = process_resources(binary.pid)
        result["sidecar_process_load"] = {
            "user_seconds": after["user_seconds"] - before["user_seconds"],
            "system_seconds": after["system_seconds"] - before["system_seconds"],
            "sampled_peak_rss_bytes": peak_rss,
            "sampling_interval_seconds": 0.05}
        result["cgroup_after_load"] = group.snapshot()
        if "cpu.stat" in result["cgroup_after_load"]:
            result["cgroup_load_cpu_delta"] = {
                key: value - result["cgroup_before_load"]["cpu.stat"][key]
                for key, value in result["cgroup_after_load"]["cpu.stat"].items()}
        result["stdout_pipe_writer_observed_blocked"] = blocked
        if mode == "conn" and config["output_pause"] and not blocked:
            raise RuntimeError("requested blocked-stdout scenario did not block a pipe writer; increase pause/DNS rate")
        # Later actually emitted L4 copies expose trailing NFLOG sequence loss.
        # Retry with fresh UDP source tuples: the first sentinel can itself be
        # dropped or coarsened while backlog drains. Replies alone are not proof.
        deadline = time.monotonic() + 20
        result["sentinel_client"] = {"attempts": 0, "dns_assertions": 0, "udp_echo_assertions": 0}
        while True:
            attempt = invoke("sentinel")
            result["sentinel_client"]["attempts"] += 1
            for key, value in attempt.items():
                result["sentinel_client"][key] += value
            if mode == "off" or stream.wait_sentinel(0.25):
                break
            if time.monotonic() >= deadline:
                raise RuntimeError("sentinel replies passed but required DNS/L4 audit sentinels were not emitted")
        stop(binary)
        reader.join(timeout=5)
        if reader.is_alive() or errors:
            raise RuntimeError("stdout consumer failed: " + str(errors))
        if binary.returncode != 0:
            raise RuntimeError(f"sidecar exited {binary.returncode}: " + " | ".join(diagnostics))
        result["audit"] = stream.finish()
        result["status"] = "passed"
        return result
    except Exception as error:
        result.update(status="failed", error=str(error), diagnostics=list(diagnostics))
        raise
    finally:
        gate.set()
        stop(binary)
        if reader is not None:
            reader.join(timeout=5)
        stop(keeper)
        services.close()
        # Links live exclusively in our new namespaces, never the host namespace.
        with contextlib.suppress(RuntimeError):
            run("ip", "link", "delete", "audit-up")
        if group is not None:
            group.close()
        save(directory / "result.json", result)


def inside(config: dict) -> dict:
    """Set up isolated mounts and synthetic services; release all owned objects."""
    for kind, original in config["parent_namespaces"].items():
        if os.readlink(f"/proc/self/ns/{kind}") == original:
            raise RuntimeError(f"refusing setup without a new private {kind} namespace")
    run("mount", "--make-rprivate", "/")
    run("mount", "-t", "tmpfs", "-o", "mode=755", "tmpfs", "/var")
    Path("/var/egress/rules").mkdir(parents=True)
    # A synthetic resolver file prevents ambient nameserver allowlist pollution.
    resolver = Path("/var/egress/resolv.conf")
    resolver.write_text("nameserver " + DNS_IP + "\n")
    run("mount", "--bind", resolver, Path("/etc/resolv.conf").resolve())
    run("ip", "link", "set", "lo", "up")
    results = []
    for mode in ("off", "dns", "conn"):
        results.append(phase(mode, config, Path(config["artifacts"]) / mode))
    off, conn = results[0], results[2]
    cpu = lambda result: sum(result["sidecar_process_load"][key]
                             for key in ("user_seconds", "system_seconds"))
    return {"status": "passed", "runs": results,
            "comparison": {"modes": ["off", "conn"],
                           "same_requested_quota_and_rates": True,
                           "sidecar_process_cpu_seconds_delta": cpu(conn) - cpu(off),
                           "scope": "process CPU / optional cgroup charge; not total host overhead",
                           "note": "single sequential samples, achieved counts reported; not a statistical benchmark"}}


def main() -> int:
    """Parse public options and enter new namespaces without changing host state."""
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--binary", required=True, type=Path, help="explicit separately compiled egress executable")
    parser.add_argument("--artifacts", required=True, type=Path, help="new output directory outside repository and /var")
    parser.add_argument("--duration", type=float, default=5, help="load seconds per mode; increase for soak")
    parser.add_argument("--denied-udp-rate", type=float, default=1000, help="requested fresh-socket attempts/sec, varying destination ports (not unique flow count)")
    parser.add_argument("--dns-rate", type=float, default=100, help="requested queries/sec, alternating allow/deny")
    parser.add_argument("--cpu-quota", type=float, help="sidecar CPU cores (e.g. 0.5), REQUIRED if requested; never fallback")
    parser.add_argument("--cgroup-parent", default="/sys/fs/cgroup", help="writable delegated cgroup-v2 parent; no controllers enabled here")
    parser.add_argument("--output-pause", type=float, default=0, help="pause stdout reader seconds during load; conn must demonstrably block")
    args = parser.parse_args()
    for name in ("duration", "denied_udp_rate", "dns_rate", "output_pause", "cpu_quota"):
        value = getattr(args, name)
        if value is not None and (not math.isfinite(value) or value < 0):
            parser.error(name + " must be finite and nonnegative")
    if args.duration <= 0 or args.cpu_quota == 0 or args.output_pause >= args.duration:
        parser.error("duration/quota must be positive and output-pause must be shorter than duration")
    binary, artifacts = args.binary.resolve(), args.artifacts.resolve()
    repo = SCRIPT.parents[3]
    if artifacts.is_relative_to(repo) or artifacts.is_relative_to("/var") or binary.is_relative_to("/var"):
        parser.error("artifacts must be outside repository; binary/artifacts must be outside private /var tmpfs")
    if not binary.is_file() or not os.access(binary, os.X_OK):
        parser.error("--binary must be an existing executable")
    if platform.system() != "Linux":
        parser.error("Linux network/mount namespaces are required")
    tools = ("unshare", "nsenter", "ip", "mount", "nft", "iptables")
    missing = [tool for tool in tools if shutil.which(tool) is None]
    if missing:
        parser.error("missing runtime prerequisites: " + ", ".join(missing))
    artifacts.mkdir(mode=0o700, parents=True, exist_ok=False)
    config = vars(args) | {"binary": str(binary), "artifacts": str(artifacts),
                           "cgroup_parent": str(Path(args.cgroup_parent).resolve()),
                           "parent_namespaces": {kind: os.readlink(f"/proc/self/ns/{kind}")
                                                 for kind in ("net", "mnt")}}
    versions = {}
    for tool in tools:
        flag = "-Version" if tool == "ip" else "--version"
        completed = subprocess.run([tool, flag], capture_output=True, text=True, timeout=5)
        versions[tool] = (completed.stdout + completed.stderr).strip()
    digest = hashlib.sha256()
    with binary.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
    manifest = {"config": config, "binary_sha256": digest.hexdigest(),
                "timestamp_scope": "wall clock manifest; monotonic userspace workload durations; sidecar observed_at timestamps",
                "python": sys.version, "kernel": platform.release(), "tools": versions,
                "started_unix_seconds": time.time(), "argv": sys.argv,
                "resource_scope": "sidecar process/cgroup only; not total host networking overhead"}
    save(artifacts / "manifest.json", manifest)
    result = {"status": "failed"}
    process = None
    try:
        command = ["unshare", "--mount", "--net", "--kill-child=TERM"]
        if os.geteuid() != 0:
            command += ["--user", "--map-root-user"]
        command += ["--", sys.executable, str(SCRIPT), "_inside", str(artifacts / "manifest.json")]
        process = subprocess.Popen(command, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        output, error = process.communicate()
        if process.returncode:
            result["error"] = (error or output).strip()
            result["exit_code"] = process.returncode
            print(result["error"], file=sys.stderr)
            return 1
        result = json.loads(output)
        print(json.dumps(result["comparison"], sort_keys=True))
        return 0
    finally:
        stop(process)
        save(artifacts / "result.json", result)


if __name__ == "__main__":
    def interrupted(signum: int, frame: object) -> None:
        raise KeyboardInterrupt(f"interrupted by signal {signum}")

    if len(sys.argv) < 2 or sys.argv[1] not in ("_client", "_exec"):
        signal.signal(signal.SIGTERM, interrupted)
    if len(sys.argv) > 1 and sys.argv[1] == "_inside":
        print(json.dumps(inside(json.loads(Path(sys.argv[2]).read_text())["config"])))
    elif len(sys.argv) > 1 and sys.argv[1] == "_client":
        print(json.dumps(client(sys.argv[2], json.loads(sys.argv[3]))))
    elif len(sys.argv) > 1 and sys.argv[1] == "_exec":
        if sys.argv[2] != "-":
            (Path(sys.argv[2]) / "cgroup.procs").write_text(str(os.getpid()))
        os.execvp(sys.argv[3], sys.argv[3:])
    else:
        raise SystemExit(main())
