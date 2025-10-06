# FILE: tcd/auditor.py
from __future__ import annotations

import dataclasses
import json
import logging
import random
import threading
import time
from typing import Any, Dict, Iterable, List, NamedTuple, Optional, Tuple

from prometheus_client import REGISTRY, CollectorRegistry, Counter, Gauge, Histogram

logger = logging.getLogger(__name__)


class ReceiptRow(NamedTuple):
    head_hex: str
    body_json: str


class ReceiptStore:
    def tail(self, n: int) -> List[ReceiptRow]: ...
    def stats(self) -> Dict[str, Any]: ...


@dataclasses.dataclass
class ChainAuditConfig:
    window: int = 256
    interval_s: float = 15.0
    label_salt_hex: Optional[str] = None
    continue_on_fail: bool = True
    max_bad_bodies: int = 8
    min_sleep_s: float = 0.05
    fail_retry_s: float = 1.0


@dataclasses.dataclass
class ChainAuditReport:
    ok: bool
    checked: int
    gaps: int
    parse_errors: int
    latency_s: float


class _Metrics(NamedTuple):
    chain_ok: Gauge
    chain_fail: Counter
    chain_gap_total: Counter
    chain_gap_window: Gauge
    chain_latency: Histogram
    rcpt_size: Histogram
    store_count: Gauge
    store_size: Gauge
    store_last_ts: Gauge


def build_metrics(registry: Optional[CollectorRegistry] = None) -> _Metrics:
    reg = registry or REGISTRY
    return _Metrics(
        chain_ok=Gauge("tcd_chain_verify_ok", "Recent chain verified OK", registry=reg),
        chain_fail=Counter("tcd_chain_verify_fail_total", "Recent chain verification failures", registry=reg),
        chain_gap_total=Counter("tcd_chain_gap_total", "Prev-pointer gaps detected", registry=reg),
        chain_gap_window=Gauge("tcd_chain_gap_window", "Prev-pointer gaps in last window", registry=reg),
        chain_latency=Histogram(
            "tcd_chain_verify_latency_seconds",
            "Chain verification latency (seconds)",
            buckets=(0.001, 0.002, 0.005, 0.010, 0.020, 0.050, 0.10, 0.20),
            registry=reg,
        ),
        rcpt_size=Histogram("tcd_receipt_size_bytes", "Receipt body size (bytes)", registry=reg),
        store_count=Gauge("tcd_store_count", "Total receipts (store-reported)", registry=reg),
        store_size=Gauge("tcd_store_size_bytes", "Approx store size (bytes)", registry=reg),
        store_last_ts=Gauge("tcd_store_last_ts_seconds", "Timestamp of last receipt (epoch seconds)", registry=reg),
    )


_METRICS = build_metrics()


def _normalize_rows(rows: Iterable[Any]) -> List[ReceiptRow]:
    out: List[ReceiptRow] = []
    for r in rows:
        if isinstance(r, ReceiptRow):
            out.append(r)
            continue
        if isinstance(r, tuple) and len(r) == 2:
            out.append(ReceiptRow(str(r[0]), str(r[1])))
            continue
        if isinstance(r, dict):
            out.append(ReceiptRow(str(r["head_hex"]), str(r["body_json"])))
            continue
        head = getattr(r, "head_hex", None)
        body = getattr(r, "body_json", None)
        if head is None or body is None:
            raise TypeError("Unsupported row type from ReceiptStore.tail()")
        out.append(ReceiptRow(str(head), str(body)))
    return out


def _prev_gap_count(heads: List[str], bodies: List[str]) -> Tuple[int, int]:
    gaps = 0
    bad = 0
    for i in range(len(bodies)):
        try:
            obj = json.loads(bodies[i])
        except Exception:
            bad += 1
            continue
        if i == 0:
            continue
        prev_in_body = obj.get("prev")
        if prev_in_body is not None and prev_in_body != heads[i - 1]:
            gaps += 1
    return gaps, bad


def _verify_chain(heads: List[str], bodies: List[str], label_salt_hex: Optional[str]) -> bool:
    from .verify import verify_chain
    return bool(verify_chain(heads, bodies, label_salt_hex=label_salt_hex))


def audit(store: ReceiptStore, cfg: ChainAuditConfig, *, metrics: _Metrics = _METRICS) -> ChainAuditReport:
    t0 = time.perf_counter()
    try:
        rows_raw = store.tail(int(cfg.window))
    except Exception as e:
        logger.exception("store.tail failed: %s", e)
        dur = time.perf_counter() - t0
        metrics.chain_ok.set(0.0)
        metrics.chain_latency.observe(dur)
        return ChainAuditReport(ok=False, checked=0, gaps=0, parse_errors=0, latency_s=dur)

    rows = _normalize_rows(rows_raw)
    if not rows:
        dur = time.perf_counter() - t0
        metrics.chain_ok.set(1.0)
        metrics.chain_gap_window.set(0)
        try:
            st = store.stats()
        except Exception as e:
            logger.warning("store.stats failed on empty store: %s", e)
            st = {}
        metrics.store_count.set(float(st.get("count", 0.0) or 0.0))
        metrics.store_size.set(float(st.get("size_bytes", 0.0) or 0.0))
        metrics.store_last_ts.set(float(st.get("last_ts", 0.0) or 0.0))
        metrics.chain_latency.observe(dur)
        return ChainAuditReport(ok=True, checked=0, gaps=0, parse_errors=0, latency_s=dur)

    heads = [r.head_hex for r in rows]
    bodies = [r.body_json for r in rows]

    for b in bodies:
        try:
            metrics.rcpt_size.observe(len(b.encode("utf-8")))
        except Exception:
            metrics.rcpt_size.observe(len(b))

    gaps, parse_bad = _prev_gap_count(heads, bodies)

    try:
        ok = _verify_chain(heads, bodies, cfg.label_salt_hex)
    except Exception as e:
        logger.exception("verify_chain raised: %s", e)
        ok = False

    dur = time.perf_counter() - t0

    try:
        st = store.stats()
    except Exception as e:
        logger.warning("store.stats failed: %s", e)
        st = {}

    metrics.store_count.set(float(st.get("count", 0.0) or 0.0))
    metrics.store_size.set(float(st.get("size_bytes", 0.0) or 0.0))
    metrics.store_last_ts.set(float(st.get("last_ts", 0.0) or 0.0))

    metrics.chain_latency.observe(dur)
    metrics.chain_ok.set(1.0 if ok else 0.0)
    metrics.chain_gap_window.set(gaps)
    if gaps > 0:
        metrics.chain_gap_total.inc(gaps)
    if not ok:
        metrics.chain_fail.inc()

    return ChainAuditReport(ok=ok, checked=len(rows), gaps=gaps, parse_errors=parse_bad, latency_s=dur)


class ChainAuditor:
    def __init__(self, store: ReceiptStore, cfg: ChainAuditConfig = ChainAuditConfig(),
                 *, metrics: _Metrics = _METRICS):
        self._store = store
        self._cfg = cfg
        self._metrics = metrics
        self._thread: Optional[threading.Thread] = None
        self._stop = threading.Event()
        self._lock = threading.RLock()

    def start(self) -> None:
        with self._lock:
            if self._thread is not None and self._thread.is_alive():
                return
            self._stop.clear()
            self._thread = threading.Thread(target=self._run_loop, name="tcd-chain-auditor", daemon=True)
            self._thread.start()

    def stop(self, *, join: bool = True, timeout: Optional[float] = 5.0) -> None:
        with self._lock:
            t = self._thread
            if t is None:
                return
            self._stop.set()
        if join:
            t.join(timeout=timeout)
        with self._lock:
            self._thread = None

    def _run_loop(self) -> None:
        while not self._stop.is_set():
            rep = audit(self._store, self._cfg, metrics=self._metrics)
            if not rep.ok and not self._cfg.continue_on_fail:
                base = max(self._cfg.min_sleep_s, float(self._cfg.fail_retry_s))
            else:
                base = max(self._cfg.min_sleep_s, float(self._cfg.interval_s))
            if rep.parse_errors > self._cfg.max_bad_bodies:
                base = max(base, 2.0 * self._cfg.interval_s)
            jitter = base * (0.95 + 0.10 * random.random())
            self._stop.wait(timeout=jitter)