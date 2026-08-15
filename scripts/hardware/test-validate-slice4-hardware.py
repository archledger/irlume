#!/usr/bin/env python3
import copy
import json
import pathlib
import subprocess
import tempfile
import unittest

HERE = pathlib.Path(__file__).resolve().parent
VALIDATOR = HERE / "validate-slice4-hardware.py"
U64_MAX = (1 << 64) - 1


def valid_record():
    return {
        "kind": "irlume.slice4.hardware",
        "schema_version": 1,
        "host": "testhost",
        "commit": "a" * 40,
        "requested_duration_seconds": 60,
        "duration_seconds": 60.5,
        "recovery_exercised": True,
        "recovery_duration_seconds": 1.2,
        "rgb_ir_skew_us": 10,
        "streams": [
            {
                "role": "rgb",
                "frames": 100,
                "observations": 114,
                "discarded_observations": 14,
                "sequence_span_sum": 114,
                "delivered_hz": 100 / 60.5,
                "gap_total": 2,
                "cumulative_drops": 2,
                "discontinuities": 1,
                "epoch_count": 2,
                "timestamp_span_sum_us": 58_800_000,
                "delta_count": 98,
                "delta_sum_us": 58_800_000,
                "delta_min_us": 500_000,
                "delta_max_us": 700_000,
                "clock": "Monotonic",
                "source": "EndOfFrame",
                "stream_epoch": 1,
                "sequence_stream_epoch": 1,
                "timestamp_stream_epoch": 1,
                "first_timestamp_us": 1_000_000,
                "last_timestamp_us": 61_000_000,
            },
            {
                "role": "ir",
                "frames": 90,
                "observations": 91,
                "discarded_observations": 1,
                "sequence_span_sum": 89,
                "delivered_hz": 90 / 60.5,
                "gap_total": 0,
                "cumulative_drops": 0,
                "discontinuities": 1,
                "epoch_count": 2,
                "timestamp_span_sum_us": 59_000_000,
                "delta_count": 88,
                "delta_sum_us": 59_000_000,
                "delta_min_us": 600_000,
                "delta_max_us": 800_000,
                "clock": "Monotonic",
                "source": "StartOfExposure",
                "stream_epoch": 1,
                "sequence_stream_epoch": 1,
                "timestamp_stream_epoch": 1,
                "first_timestamp_us": 1_000_010,
                "last_timestamp_us": 60_999_990,
            },
        ],
    }


class ValidatorTests(unittest.TestCase):
    def run_raw(
        self,
        text,
        expected_host="testhost",
        expected_sha="a" * 40,
        expected_streams="2",
    ):
        with tempfile.TemporaryDirectory() as directory:
            log = pathlib.Path(directory) / "hardware.log"
            log.write_text(text, encoding="utf-8")
            return subprocess.run(
                [
                    "python3",
                    str(VALIDATOR),
                    str(log),
                    expected_host,
                    expected_sha,
                    expected_streams,
                ],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )

    def run_records(self, records, expected_streams="2"):
        text = "".join(json.dumps(record) + "\n" for record in records)
        return self.run_raw(text, expected_streams=expected_streams)

    def run_validator(self, record, expected_streams="2"):
        return self.run_records([record], expected_streams=expected_streams)

    def assert_rejected(self, mutate):
        record = valid_record()
        mutate(record)
        result = self.run_validator(record)
        self.assertNotEqual(result.returncode, 0, result.stdout)

    def test_ambiguous_or_nonstandard_json_is_rejected(self):
        encoded = json.dumps(valid_record())
        duplicate_host = encoded.replace(
            '"host": "testhost"',
            '"host": "wrong", "host": "testhost"',
            1,
        )
        duplicate_role = encoded.replace(
            '"role": "rgb"',
            '"role": "other", "role": "rgb"',
            1,
        )
        malformed = '{"kind":"irlume.slice4.hardware"\n' + encoded + "\n"
        for raw in [duplicate_host, duplicate_role, malformed]:
            with self.subTest(raw=raw[:40]):
                self.assertNotEqual(self.run_raw(raw + "\n").returncode, 0)
        for constant in ["NaN", "Infinity", "-Infinity"]:
            raw = encoded.replace("60.5", constant, 1)
            with self.subTest(constant=constant):
                self.assertNotEqual(self.run_raw(raw + "\n").returncode, 0)

    def test_identity_record_count_and_exact_keys_are_enforced(self):
        self.assertNotEqual(self.run_records([]).returncode, 0)
        record = valid_record()
        self.assertNotEqual(self.run_records([record, record]).returncode, 0)
        self.assert_rejected(lambda item: item.__setitem__("host", "wrong"))
        self.assert_rejected(lambda item: item.__setitem__("commit", "b" * 40))
        self.assert_rejected(lambda item: item.__setitem__("unexpected", 1))
        self.assert_rejected(
            lambda item: item["streams"][0].__setitem__("unexpected", 1)
        )

    def test_duration_recovery_and_stream_shape_are_enforced(self):
        for invalid in [False, None, 1]:
            with self.subTest(field="recovery", invalid=invalid):
                self.assert_rejected(
                    lambda record, invalid=invalid: record.__setitem__(
                        "recovery_exercised", invalid
                    )
                )
        for invalid in [59, 601, True]:
            with self.subTest(field="requested", invalid=invalid):
                self.assert_rejected(
                    lambda record, invalid=invalid: record.__setitem__(
                        "requested_duration_seconds", invalid
                    )
                )
        for invalid in [59.9, 90.6, True, float("inf")]:
            with self.subTest(field="measured", invalid=invalid):
                self.assert_rejected(
                    lambda record, invalid=invalid: record.__setitem__(
                        "duration_seconds", invalid
                    )
                )
        for invalid in [0, -1, True, 31]:
            with self.subTest(field="recovery_duration", invalid=invalid):
                self.assert_rejected(
                    lambda record, invalid=invalid: record.__setitem__(
                        "recovery_duration_seconds", invalid
                    )
                )
        self.assert_rejected(lambda record: record["streams"].reverse())
        self.assert_rejected(lambda record: record["streams"].pop())

    def test_valid_dual_stream_evidence_passes(self):
        result = self.run_validator(valid_record())
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_valid_rgb_only_evidence_passes_only_when_declared(self):
        record = valid_record()
        record["streams"] = record["streams"][:1]
        record["rgb_ir_skew_us"] = None
        result = self.run_validator(record, expected_streams="1")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotEqual(self.run_validator(record).returncode, 0)

    def test_stream_metrics_domains_epochs_and_timestamps_are_enforced(self):
        mutations = [
            lambda stream: stream.__setitem__("frames", 1),
            lambda stream: stream.__setitem__("frames", True),
            lambda stream: stream.__setitem__("delivered_hz", 0),
            lambda stream: stream.__setitem__("delivered_hz", True),
            lambda stream: stream.__setitem__("clock", "Unknown"),
            lambda stream: stream.__setitem__("source", "Unknown"),
            lambda stream: stream.__setitem__("stream_epoch", 2),
            lambda stream: stream.__setitem__("sequence_stream_epoch", 0),
            lambda stream: stream.__setitem__("timestamp_stream_epoch", 0),
            lambda stream: stream.__setitem__("discontinuities", 0),
            lambda stream: stream.__setitem__("delta_min_us", 0),
            lambda stream: stream.__setitem__("delta_max_us", 1),
            lambda stream: stream.__setitem__("first_timestamp_us", 0),
            lambda stream: stream.__setitem__("last_timestamp_us", 1_000_000),
        ]
        for index, mutation in enumerate(mutations):
            with self.subTest(mutation=index):
                self.assert_rejected(
                    lambda record, mutation=mutation: mutation(record["streams"][0])
                )

    def test_cross_field_rate_and_drop_coherence_is_enforced(self):
        self.assert_rejected(
            lambda record: record["streams"][0].__setitem__("delivered_hz", 1e300)
        )
        self.assert_rejected(
            lambda record: record["streams"][0].__setitem__(
                "cumulative_drops", U64_MAX
            )
        )

        def full_sequence_space(record):
            stream = record["streams"][0]
            stream["gap_total"] = U64_MAX
            stream["cumulative_drops"] = U64_MAX

        self.assert_rejected(full_sequence_space)

    def test_near_empty_nominal_run_is_rejected(self):
        def keep_only_three_internally_consistent_rgb_frames(record):
            stream = record["streams"][0]
            stream["frames"] = 3
            stream["observations"] = 17
            stream["sequence_span_sum"] = 17
            stream["delivered_hz"] = 3 / record["duration_seconds"]
            stream["delta_count"] = 1
            stream["delta_min_us"] = stream["timestamp_span_sum_us"]
            stream["delta_max_us"] = stream["timestamp_span_sum_us"]

        self.assert_rejected(keep_only_three_internally_consistent_rgb_frames)

    def test_coordinated_omission_below_the_density_floor_is_rejected(self):
        def omit_and_mirror_delivered_rgb_observations(record):
            stream = record["streams"][0]
            stream["frames"] = 30
            stream["observations"] = stream["frames"] + stream["discarded_observations"]
            stream["sequence_span_sum"] = (
                stream["observations"]
                - stream["epoch_count"]
                + stream["cumulative_drops"]
            )
            stream["delivered_hz"] = stream["frames"] / record["duration_seconds"]
            stream["delta_count"] = stream["frames"] - stream["epoch_count"]
            stream["delta_sum_us"] = stream["timestamp_span_sum_us"]
            stream["delta_min_us"] = 1_000_000
            stream["delta_max_us"] = 3_000_000

        self.assert_rejected(omit_and_mirror_delivered_rgb_observations)

    def test_sequence_observation_accounting_is_exact(self):
        self.assert_rejected(
            lambda record: record["streams"][0].__setitem__("observations", 113)
        )
        self.assert_rejected(
            lambda record: record["streams"][0].__setitem__("sequence_span_sum", 113)
        )

        def omit_rgb_warmup(record):
            stream = record["streams"][0]
            stream["observations"] = stream["frames"]
            stream["discarded_observations"] = 0
            stream["sequence_span_sum"] = (
                stream["observations"]
                - stream["epoch_count"]
                + stream["cumulative_drops"]
            )

        self.assert_rejected(omit_rgb_warmup)

    def test_cross_field_delta_coherence_is_enforced(self):
        mutations = [
            lambda stream: stream.__setitem__("delta_count", 101),
            lambda stream: stream.__setitem__("delta_count", 97),
            lambda stream: stream.__setitem__("delta_sum_us", 1),
            lambda stream: stream.__setitem__("delta_sum_us", 4_000_001),
            lambda stream: stream.__setitem__("delta_sum_us", 3_000_000),
        ]
        for index, mutation in enumerate(mutations):
            with self.subTest(mutation=index):
                self.assert_rejected(
                    lambda record, mutation=mutation: mutation(record["streams"][0])
                )

        def shrink_timestamp_span(record):
            record["streams"][0]["last_timestamp_us"] = 1_000_001
            record["rgb_ir_skew_us"] = 5_999_989

        self.assert_rejected(shrink_timestamp_span)

        def tiny_epoch_spans(record):
            stream = record["streams"][0]
            stream["timestamp_span_sum_us"] = 98
            stream["delta_sum_us"] = 98
            stream["delta_min_us"] = 1
            stream["delta_max_us"] = 1

        self.assert_rejected(tiny_epoch_spans)

    def test_gap_total_must_be_a_bounded_nonnegative_integer(self):
        for invalid in ["2", -1, True, U64_MAX + 1]:
            with self.subTest(invalid=invalid):
                self.assert_rejected(
                    lambda record, invalid=invalid: record["streams"][0].__setitem__(
                        "gap_total", invalid
                    )
                )

    def test_cumulative_drops_must_equal_all_observed_gaps(self):
        for invalid in [-1, True, U64_MAX + 1]:
            with self.subTest(invalid=invalid):
                self.assert_rejected(
                    lambda record, invalid=invalid: record["streams"][0].__setitem__(
                        "cumulative_drops", invalid
                    )
                )
        self.assert_rejected(
            lambda record: record["streams"][0].update(
                {"gap_total": 3, "cumulative_drops": 2}
            )
        )

    def test_schema_and_epoch_fields_are_strict_integers(self):
        self.assert_rejected(lambda record: record.pop("schema_version"))
        for invalid in [True, 0, 2]:
            with self.subTest(field="schema_version", invalid=invalid):
                self.assert_rejected(
                    lambda record, invalid=invalid: record.__setitem__(
                        "schema_version", invalid
                    )
                )
        for field in [
            "stream_epoch",
            "sequence_stream_epoch",
            "timestamp_stream_epoch",
            "discontinuities",
        ]:
            with self.subTest(field=field):
                self.assert_rejected(
                    lambda record, field=field: record["streams"][0].__setitem__(
                        field, True
                    )
                )

    def test_skew_must_equal_the_reported_last_timestamp_difference(self):
        self.assert_rejected(lambda record: record.__setitem__("rgb_ir_skew_us", 10_000))
        self.assert_rejected(lambda record: record.__setitem__("rgb_ir_skew_us", True))


if __name__ == "__main__":
    unittest.main()
