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

"""Consumer regressions; no root/binary/mocks, only a local synthetic UDP sink."""

import json
from pathlib import Path
import socket
import tempfile
import threading
import unittest

from test_outbound_audit import (
    AuditStream, Cgroup, DNSLatency, echo,
)


def event(seq: int, kind: str = "stream", **fields: object) -> str:
    return json.dumps({"opensandbox.event": "egress.audit." + kind,
                       "boot_id": "synthetic-boot", "seq": seq, **fields})


def started() -> str:
    return event(1, reason="started", coverage=["dns"])


class AuditStreamTests(unittest.TestCase):
    def test_reconciles_dns_details_and_aggregates(self) -> None:
        stream = AuditStream("dns")
        for line in [started(), event(2, "dns", domain="sentinel.allow.audit.test",
                                     decision="allow"),
                     event(3, "dns", count=7),
                     event(4, reason="stopped", detailed=1, aggregated=7)]:
            stream.feed(line)
        result = stream.finish()
        self.assertEqual(result["records"], 4)
        self.assertEqual(result["observed_accounted"], 8)
        self.assertEqual(result["destination_complete"], False)

    def test_sentinel_wait_requires_emitted_allowed_dns_not_client_success(self) -> None:
        stream = AuditStream("dns")
        stream.feed(started())
        self.assertFalse(stream.wait_sentinel(0.001))
        stream.feed(event(2, "dns", domain="sentinel.allow.audit.test", decision="deny"))
        self.assertFalse(stream.wait_sentinel(0.001))
        thread = threading.Thread(target=lambda: stream.feed(event(
            3, "dns", domain="sentinel.allow.audit.test", decision="allow")))
        thread.start()
        self.assertTrue(stream.wait_sentinel(1))
        thread.join()

    def test_non_audit_output_does_not_count(self) -> None:
        stream = AuditStream("off")
        stream.feed("OpenSandbox Egress version synthetic")
        stream.feed('{"opensandbox.event":"egress.policy.loaded"}')
        self.assertEqual(stream.finish()["records"], 0)

    def test_off_rejects_even_one_event(self) -> None:
        stream = AuditStream("off")
        stream.feed(started())
        with self.assertRaisesRegex(ValueError, "off"):
            stream.finish()

    def test_rejects_downstream_sequence_gap(self) -> None:
        stream = AuditStream("dns")
        stream.feed(started())
        stream.feed(event(3, reason="stopped"))
        with self.assertRaisesRegex(ValueError, "sequence"):
            stream.finish()

    def test_rejects_boot_change(self) -> None:
        stream = AuditStream("dns")
        stream.feed(started())
        stream.feed(event(2, boot_id="other", reason="stopped"))
        with self.assertRaisesRegex(ValueError, "boot"):
            stream.finish()

    def test_requires_stopped_after_sentinel(self) -> None:
        stream = AuditStream("dns")
        stream.feed(started())
        stream.feed(event(2, "dns", domain="sentinel.allow.audit.test", decision="allow"))
        with self.assertRaisesRegex(ValueError, "stopped"):
            stream.finish()

    def test_rejects_unreconciled_aggregate_totals(self) -> None:
        stream = AuditStream("dns")
        stream.feed(started())
        stream.feed(event(2, "dns", domain="sentinel.allow.audit.test", decision="allow"))
        stream.feed(event(3, reason="stopped", detailed=1, aggregated=1))
        with self.assertRaisesRegex(ValueError, "totals"):
            stream.finish()

    def test_rejects_trailing_records(self) -> None:
        stream = AuditStream("dns")
        stream.feed(started())
        stream.feed(event(2, "dns", domain="sentinel.allow.audit.test", decision="allow"))
        stream.feed(event(3, reason="stopped", detailed=1))
        stream.feed(event(4, "dns"))
        with self.assertRaises(ValueError):
            stream.finish()

    def test_rejects_incorrect_dns_coverage(self) -> None:
        stream = AuditStream("dns")
        stream.feed(event(1, reason="started", coverage=[]))
        with self.assertRaisesRegex(ValueError, "coverage"):
            stream.finish()

    def test_rejects_malformed_audit_json_and_invalid_counts(self) -> None:
        for line in ('{"opensandbox.event":"egress.audit.dns",',
                     event(2, "dns", count=-1)):
            with self.subTest(line=line):
                stream = AuditStream("dns")
                stream.feed(started())
                stream.feed(line)
                with self.assertRaises(ValueError):
                    stream.finish()

    def test_functional_barrier_requires_each_actual_verdict(self) -> None:
        stream = AuditStream("dns")
        stream.feed(started())
        stream.feed(event(2, "dns", domain="functional.allow.audit.test", decision="allow"))
        self.assertFalse(stream.functional.is_set())
        stream.feed(event(3, "dns", domain="functional.deny.audit.test", decision="deny"))
        self.assertTrue(stream.functional.is_set())

    def test_rejects_null_coverage_without_crashing_consumer(self) -> None:
        stream = AuditStream("dns")
        stream.feed(event(1, reason="started", coverage=None))
        with self.assertRaisesRegex(ValueError, "coverage"):
            stream.finish()

    def test_rejects_connection_event_in_dns_stream(self) -> None:
        stream = AuditStream("dns")
        stream.feed(started())
        stream.feed(event(2, "connection", decision="allow"))
        with self.assertRaisesRegex(ValueError, "dns emitted connection event"):
            stream.finish()
        self.assertFalse(stream.wait_sentinel(0))
        self.assertFalse(stream.functional.is_set())

    def test_rejects_unknown_stream_reason(self) -> None:
        stream = AuditStream("dns")
        stream.feed(started())
        stream.feed(event(2, reason="unexpected"))
        with self.assertRaisesRegex(ValueError, "unknown stream reason"):
            stream.finish()

    def test_coarsened_first_sentinel_requires_eventual_emitted_domain(self) -> None:
        stream = AuditStream("dns")
        stream.feed(started())
        stream.feed(event(2, "dns", decision="allow", reason="policy", count=1))
        self.assertFalse(stream.wait_sentinel(0))
        stream.feed(event(3, "dns", domain="sentinel.allow.audit.test",
                          decision="allow", reason="policy"))
        self.assertTrue(stream.wait_sentinel(0))
        stream.feed(event(4, reason="stopped", detailed=1, aggregated=1))
        result = stream.finish()
        self.assertEqual(result["observed_accounted"], 2)
        self.assertTrue(result["dns_sentinel_emitted"])



class DNSLatencyTests(unittest.TestCase):
    def test_nearest_rank_percentiles_and_completed_denominator(self) -> None:
        latency = DNSLatency()
        for seconds in (0.009, 0.001, 0.003, 0.002, 0.005):
            latency.record(seconds)
        result = latency.summary()
        self.assertEqual(result["completed_queries"], 5)
        self.assertEqual(result["retained_samples"], 5)
        self.assertFalse(result["truncated"])
        self.assertEqual((result["p50_ms"], result["p99_ms"], result["max_ms"]), (3, 9, 9))

    def test_truncation_preserves_full_denominator_and_maximum(self) -> None:
        latency = DNSLatency(capacity=3)
        for seconds in (0.1, 0.001, 0.002, 0.003):
            latency.record(seconds)
        result = latency.summary()
        self.assertEqual(result["completed_queries"], 4)
        self.assertEqual(result["retained_samples"], 3)
        self.assertTrue(result["truncated"])
        self.assertEqual((result["p50_ms"], result["p99_ms"], result["max_ms"]), (2, 3, 100))

    def test_no_completed_queries_has_no_fabricated_latency(self) -> None:
        result = DNSLatency().summary()
        self.assertEqual(result["completed_queries"], 0)
        self.assertEqual(result["retained_samples"], 0)
        self.assertIsNone(result["p50_ms"])
        self.assertIsNone(result["p99_ms"])
        self.assertIsNone(result["max_ms"])


class ClientTests(unittest.TestCase):
    def test_udp_timeout_counts_as_denial_but_never_as_allowed_delivery(self) -> None:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sink:
            sink.bind(("127.0.0.1", 0))
            port = sink.getsockname()[1]
            echo("127.0.0.1", "udp", False, port)
            with self.assertRaisesRegex(ValueError, "expected allowed=True"):
                echo("127.0.0.1", "udp", True, port)


class QuotaTests(unittest.TestCase):
    def test_requested_quota_cannot_fall_back_when_cpu_controller_is_missing(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(RuntimeError, "requested CPU quota unavailable"):
                Cgroup(directory, 0.5)
            self.assertEqual(list(Path(directory).iterdir()), [])

    def test_unavailable_unrequested_cgroup_is_explicit(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            group = Cgroup(str(Path(directory) / "missing"), None)
            self.assertIn("unavailable", group.snapshot())
            self.assertIsNone(group.path)
            group.close()


if __name__ == "__main__":
    unittest.main()
