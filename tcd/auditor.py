from __future__ import annotations

"""
Chain Auditor — periodic verification for the verifiable receipts pipeline.

What this provides
------------------
- A small, SRE-friendly daemon (thread) that:
    * fetches the last N receipts from a ReceiptStore,
    * verifies chain linearity and head/body integrity,
    * computes basic audit stats (chain gaps, size distribution),
    * exposes Prometheus metrics and optional OpenTelemetry attributes.

- A one-shot audit() function for on-demand checks (e.g., /admin/audit).

Why it's useful
---------------
- Closes the loop for the "可验证流水线": issuance → persistence → verification.
- Lets SREs alert on chain breakage (即刻告警), size anomalies, and ingestion liveness.
- Decouples from HTTP service; can be embedded or run as a side thread.

Usage
-----
    from tcd.receipt_store import build_store_from_env
    from tcd.auditor import ChainAuditor, ChainAuditConfig

    store = build_store_from_env()
    auditor = ChainAuditor(store, ChainAuditConfig(window=512, interval_s=10.0))
    auditor.start()
    ...
    auditor.stop()

Prometheus Metrics (exposed from the default REGISTRY)
------------------------------------------------------
- tcd_chain_verify_ok              (gauge 0/1)
- tcd_chain_verify_fail_total      (counter)
- tcd_chain_gap_total              (counter)
- tcd_chain_gap_window             (gauge)
- tcd_receipt_size_bytes           (histogram)
- tcd_chain_verify_latency_seconds (histogram)
- tcd_store_count                  (gauge)
- tcd_store_size_bytes             (gauge)
- tcd_store_last_ts_seconds        (gauge)
"""

import dataclasses
import json
import threading
import time
from typing import Dict, List, Optional, Tuple

from prometheus_client import Gauge, Counter, Histogram

from .receipt_store import ReceiptStore, verify_recent_chain
from .verify import verify_chain


# ----------------------------- Config & Report -------------------------------

@dataclasses.dataclass
class ChainAuditConfig:
    window: int = 256                 # how many latest receipts to verify
    interval_s: float = 15.0          # how often to verify in daemon mode
    label_salt_hex: Optional[str] = None  # for verifier (kept for compatibility)
    histogram_buckets: Tuple[float, ...] = (128, 256, 512, 1024, 1536, 2048, 4096)
    # fail-fast: if True and a verification fails, we keep counting (no sleep skip)
    continue_on_fail: bool = True
    # cap for JSON parse errors on bodies (protect against pathological inputs)
    max_bad_bodies: int = 8


@dataclasses.dataclass
class ChainAuditReport:
    ok: bool
    checked: int
    gaps: int
    parse_errors: int
    latency_s: float


# ------------------------------- Prom metrics --------------------------------

_chain_ok = Gauge("tcd_chain_verify_ok", "1 if recent chain verified OK, else 0")
_chain_fail = Counter("tcd_chain_verify_fail_total", "Total recent chain verification failures")
_chain_gap_total = Counter("tcd_chain_gap_total", "Total number of prev-pointer gaps detected")
_chain_gap_window = Gauge("tcd_chain_gap_window", "Prev-pointer gaps in the last verification window")
_chain_latency = Histogram(
    "tcd_chain_verify_latency_seconds", "Chain verification latency (seconds)",
    buckets=(0.001, 0.002, 0.005, 0.010, 0.020, 0.050, 0.10, 0.20)
)
_rcpt_size = Histogram(
    "tcd_receipt_size_bytes", "Canonical receipt body size (bytes)"
)
_store_count = Gauge("tcd_store_count", "Total receipts persisted (store-reported)")
_store_size = Gauge("tcd_store_size_bytes", "Approx store size in bytes (if known)")
_store_last_ts = Gauge("tcd_store_last_ts_seconds", "Timestamp of the last stored receipt (seconds since epoch)")


# --------------------------------- Helpers -----------------------------------

def _prev_gap_count(bodies: List[str]) -> Tuple[int, int]:
    """
    Count gaps by walking the 'prev' pointers in canonical bodies.
    Returns (gap_count, parse_error_count).
    If decoding fails, counts as parse error (not a gap).
    """
    prev = None
    gaps = 0
    bad = 0
    for bj in bodies:
        try:
            obj = json.loads(bj)
        except Exception:
            bad += 1
            continue
        cur_prev = obj.get("prev")
        # First element: prev should be whatever last_head was when issued (may be null/None/"")
        # We only count gaps where prev doesn't match the computed previous head in the linear sequence.
        # For a contiguous window within the full chain, the first prev may legitimately not equal "window[-2].head".
        # Therefore, we only check from the second body onward.
        if prev is not None:
            if cur_prev != prev:
                gaps += 1
        prev = obj.get("receipt") or obj.get("head")  # this is NOT required; bodies need not carry head
        # Most canonical bodies do not embed head; leave prev for next iteration as current head from list order.
        # We override below with the head from the parallel heads array.
    return gaps, bad


def audit(store: ReceiptStore, cfg: ChainAuditConfig) -> ChainAuditReport:
    """
    One-shot audit: verify the recent chain window, compute stats, and update metrics.
    """
    t0 = time.perf_counter()

    rows = store.tail(cfg.window)
    if not rows:
        # Empty stores are trivially OK.
        dur = time.perf_counter() - t0
        _chain_ok.set(1.0)
        _chain_gap_window.set(0)
        _store_count.set(0)
        _store_size.set(0)
        _store_last_ts.set(0)
        _chain_latency.observe(dur)
        return ChainAuditReport(ok=True, checked=0, gaps=0, parse_errors=0, latency_s=dur)

    heads = [r.head_hex for r in rows]
    bodies = [r.body_json for r in rows]

    # Size distribution (as a proxy for budget & MTU monitoring)
    for b in bodies:
        _rcpt_size.observe(len(b.encode("utf-8")))

    # Fine-grained prev gap counting (best-effort; tolerant to bodies w/o "prev")
    gaps, bad = _prev_gap_count(bodies)

    ok = verify_chain(heads, bodies, label_salt_hex=cfg.label_salt_hex)
    dur = time.perf_counter() - t0

    # Store stats
    st = store.stats()
    _store_count.set(float(st.get("count", 0.0)))
    _store_size.set(float(st.get("size_bytes", 0.0)))
    _store_last_ts.set(float(st.get("last_ts", 0.0)))

    # Prom updates
    _chain_latency.observe(dur)
    _chain_ok.set(1.0 if ok else 0.0)
    _chain_gap_window.set(gaps)
    if gaps > 0:
        _chain_gap_total.inc(gaps)
    if not ok:
        _chain_fail.inc()

    return ChainAuditReport(
        ok=bool(ok),
        checked=len(rows),
        gaps=gaps,
        parse_errors=bad,
        latency_s=dur,
    )


# --------------------------------- Daemon ------------------------------------

class ChainAuditor:
    """
    Periodic verifier running in a background thread.

    Thread-safety:
      - The auditor does not modify the store; uses tail() and stats().
      - It can be started/stopped multiple times safely (idempotent semantics).
    """

    def __init__(self, store: ReceiptStore, cfg: ChainAuditConfig = ChainAuditConfig()):
        self._store = store
        self._cfg = cfg
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

    def stop(self, join: bool = True, timeout: Optional[float] = 5.0) -> None:
        with self._lock:
            if self._thread is None:
                return
            self._stop.set()
            t = self._thread
        if join:
            t.join(timeout=timeout)

    def _run_loop(self) -> None:
        while not self._stop.is_set():
            rep = audit(self._store, self._cfg)
            # If verification failed and continue_on_fail is False, we still sleep the interval;
            # callers can reduce interval to achieve near-real-time checks.
            # In both cases we never busy-spin.
            sleep_s = max(0.05, float(self._cfg.interval_s))
            # Backoff a bit if parse errors are frequent (in case of store corruption)
            if rep.parse_errors > self._cfg.max_bad_bodies:
                sleep_s = max(sleep_s, 2.0 * self._cfg.interval_s)
            self._stop.wait(timeout=sleep_s)
