from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Optional
from .timing import stats

@dataclass
class Record:
    benchmark_id: str
    suite: str
    scheme: str
    mode: str
    variant: str
    operation: str
    case: str
    payload_bytes: int
    policy_attributes: int
    stats: dict[str, float]
    extra: dict[str, Any]


class Recorder:
    def __init__(self):
        self.records: list[Record] = []
        self.raw: list[dict[str, Any]] = []

    def add(
        self,
        suite: str,
        scheme: str,
        mode: str,
        variant: str,
        operation: str,
        case: str,
        payload_bytes: int,
        policy_attributes: int,
        samples: list[float],
        extra: Optional[dict[str, Any]] = None,
    ):
        bid = "|".join((suite, scheme, mode, variant, operation, case))
        rec = Record(
            bid, suite, scheme, mode, variant, operation, case,
            payload_bytes, policy_attributes, stats(samples), extra or {}
        )
        self.records.append(rec)
        for i, value in enumerate(samples):
            self.raw.append({
                "benchmark_id": bid,
                "sample_index": i,
                "latency_ms": value,
            })

    def find(self, **filters):
        rows = self.records
        for key, value in filters.items():
            if value is not None:
                rows = [r for r in rows if getattr(r, key) == value]
        return rows

    def raw_for(self, bid):
        return [r["latency_ms"] for r in self.raw if r["benchmark_id"] == bid]


def add(rec, samples, suite, scheme, mode, variant, op, case, payload, attrs, extra=None):
    rec.add(suite, scheme, mode, variant, op, case, payload, attrs, samples, extra)
