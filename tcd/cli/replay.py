# FILE: tcd/cli/replay.py
from __future__ import annotations

"""
tcd-replay — Traffic replayer for /diagnose with optional receipt verification.
"""

import json
import os
import queue
import random
import string
import sys
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

import click

try:
    import requests
except Exception as _e:  # pragma: no cover
    _requests_import_error = _e
    requests = None  # type: ignore

from ..exporter import TCDPrometheusExporter
from ..otel_exporter import TCDOtelExporter
from ..verify import verify_receipt


# ---------------------- Env toggles ----------------------

def _env_bool(key: str, default: bool) -> bool:
    v = os.environ.get(key)
    if v is None:
        return default
    return v.strip().lower() not in ("0", "false", "")

DEFAULT_ENABLE_OTEL = _env_bool("TCD_REPLAY_OTEL", False)
DEFAULT_ENABLE_PROM = _env_bool("TCD_REPLAY_PROM_HTTP", False)
DEFAULT_PROM_PORT = int(os.environ.get("TCD_REPLAY_PROM_PORT", "8020"))

DEFAULT_URL = os.environ.get("TCD_REPLAY_URL", "http://127.0.0.1:8080/diagnose")
DEFAULT_TIMEOUT_S = float(os.environ.get("TCD_REPLAY_TIMEOUT_S", "3.0"))


# ---------------------- Helpers ----------------------

def _pct(xs: List[float], q: float) -> float:
    if not xs:
        return 0.0
    xs = sorted(xs)
    idx = max(0, min(len(xs) - 1, int(round(q * (len(xs) - 1)))))
    return float(xs[idx])


def _now_ms() -> float:
    return time.perf_counter() * 1000.0


def _rand_key(n: int = 16) -> str:
    return "".join(random.choices(string.ascii_letters + string.digits, k=n))


def _read_jsonl(path_or_stdin: str) -> Iterable[Dict[str, Any]]:
    if path_or_stdin == "-":
        for line in sys.stdin:
            s = line.strip()
            if not s:
                continue
            yield json.loads(s)
        return
    p = Path(path_or_stdin)
    with p.open("r", encoding="utf-8") as fr:
        for line in fr:
            s = line.strip()
            if not s:
                continue
            yield json.loads(s)


def _mk_synthetic(i: int) -> Dict[str, Any]:
    rnd = random.Random(1234 + i)
    L_trace = rnd.randint(8, 32)
    L_spec = rnd.randint(8, 32)
    trace = [float(rnd.random()) for _ in range(L_trace)]
    spectrum = [float(rnd.random()) for _ in range(L_spec)]
    entropy = float(rnd.uniform(0.2, 2.5))
    feats = [float(rnd.random()) for _ in range(rnd.randint(0, 16))]

    return {
        "trace_vector": trace,
        "entropy": entropy,
        "spectrum": spectrum,
        "features": feats,
        "model_id": "m0",
        "gpu_id": "g0",
        "task": "chat",
        "lang": "en",
        "tenant": f"t{(i % 8)}",
        "user": f"u{(i % 64)}",
        "session": f"s{(i % 1024)}",
        "context": {"temperature": 0.7, "top_p": 0.9},
        "tokens_delta": rnd.randint(20, 80),
        "drift_score": rnd.uniform(0.0, 1.0),
    }


@dataclass
class SRE:
    prom_enabled: bool
    prom: TCDPrometheusExporter
    otel: TCDOtelExporter

    def observe_latency(self, s: float):
        if self.prom_enabled:
            self.prom.observe_latency(s)

    def push_trace(self, score: float, attrs: Dict[str, str]):
        self.otel.push_metrics(score, attrs=attrs)


# ---------------------- Worker ----------------------

@dataclass
class WorkItem:
    idx: int
    payload: Dict[str, Any]
    url: str
    timeout_s: float
    verify: bool
    idempotency: bool


@dataclass
class WorkResult:
    ok: bool
    status: int
    latency_ms: float
    verified: Optional[bool]
    err: Optional[str]


def _do_request(item: WorkItem) -> WorkResult:
    if requests is None:  # pragma: no cover
        return WorkResult(False, 0, 0.0, None, f"requests import error: {_requests_import_error!s}")
    t0 = _now_ms()
    headers = {"content-type": "application/json"}
    if item.idempotency:
        headers["Idempotency-Key"] = _rand_key(24)
    try:
        resp = requests.post(item.url, data=json.dumps(item.payload), timeout=item.timeout_s, headers=headers)
        dur = max(0.0, _now_ms() - t0)
        if resp.status_code != 200:
            return WorkResult(False, int(resp.status_code), dur, None, f"http {resp.status_code}")
        obj = resp.json()
        verified_ok: Optional[bool] = None
        if item.verify:
            head = obj.get("receipt") or obj.get("receipt_head") or None
            body = obj.get("receipt_body") or None
            vk = obj.get("verify_key") or None
            sig = obj.get("receipt_sig") or None
            if head and body:
                try:
                    verified_ok = bool(
                        verify_receipt(
                            receipt_head_hex=str(head),
                            receipt_body_json=str(body),
                            verify_key_hex=(str(vk) if isinstance(vk, str) and vk else None),
                            receipt_sig_hex=(str(sig) if isinstance(sig, str) and sig else None),
                            req_obj=None,
                            comp_obj=None,
                            e_obj=None,
                            witness_segments=None,
                            strict=True,
                        )
                    )
                except Exception as e:
                    verified_ok = False
                    return WorkResult(True, 200, dur, verified_ok, f"verify_err:{e}")
        return WorkResult(True, 200, dur, verified_ok, None)
    except requests.Timeout:
        return WorkResult(False, 0, max(0.0, _now_ms() - t0), None, "timeout")
    except Exception as e:
        return WorkResult(False, 0, max(0.0, _now_ms() - t0), None, f"exc:{e!s}")


# ---------------------- CLI ----------------------

@click.command(context_settings={"help_option_names": ["-h", "--help"]})
@click.option("--url", default=DEFAULT_URL, show_default=True, help="POST /diagnose endpoint.")
@click.option("--jsonl", "jsonl_path", default=None, help="JSONL file with DiagnoseRequest lines (or '-' for stdin).")
@click.option("--synthetic", is_flag=True, help="Generate synthetic payloads (ignored when --jsonl is set).")
@click.option("--count", type=int, default=128, show_default=True, help="Total requests (synthetic only).")
@click.option("--concurrency", type=int, default=8, show_default=True, help="Concurrent workers.")
@click.option("--timeout", "timeout_s", type=float, default=DEFAULT_TIMEOUT_S, show_default=True, help="Per-request timeout seconds.")
@click.option("--verify", is_flag=True, help="Verify returned receipts if present.")
@click.option("--idempotency", is_flag=True, help="Send Idempotency-Key header per request.")
@click.option("--seed", type=int, default=2025, show_default=True, help="Random seed (synthetic only).")
@click.option("--otel/--no-otel", default=DEFAULT_ENABLE_OTEL, show_default=True, help="Enable OpenTelemetry spans (batch-level).")
@click.option("--prom-http/--no-prom-http", default=DEFAULT_ENABLE_PROM, show_default=True, help="Expose Prometheus /metrics (short-lived).")
@click.option("--prom-port", type=int, default=DEFAULT_PROM_PORT, show_default=True, help="Prometheus port if enabled.")
@click.option("--json", "json_out", is_flag=True, help="Print JSON summary instead of human text.")
def main(
    url: str,
    jsonl_path: Optional[str],
    synthetic: bool,
    count: int,
    concurrency: int,
    timeout_s: float,
    verify: bool,
    idempotency: bool,
    seed: int,
    otel: bool,
    prom_http: bool,
    prom_port: int,
    json_out: bool,
) -> None:
    if requests is None:  # pragma: no cover
        click.echo(f"[fatal] requests not available: {_requests_import_error!s}", err=True)
        sys.exit(2)

    random.seed(seed)

    prom = TCDPrometheusExporter(port=prom_port, version="0.10.2", config_hash="cli-replay")
    if prom_http:
        prom.ensure_server()
    ot = TCDOtelExporter(endpoint=os.environ.get("TCD_OTEL_ENDPOINT", "http://localhost:4318"))
    if not ot.enabled or not otel:
        class _NoOtel:
            enabled = False
            def push_metrics(self, *_, **__):  # pragma: no cover
                return
        ot = _NoOtel()  # type: ignore

    sre = SRE(prom_enabled=prom_http, prom=prom, otel=ot)

    work_q: "queue.Queue[Optional[WorkItem]]" = queue.Queue()
    results: List[WorkResult] = []
    results_lock = threading.Lock()

    def _enqueue():
        if jsonl_path:
            idx = 0
            for obj in _read_jsonl(jsonl_path):
                if not isinstance(obj, dict):
                    continue
                work_q.put(WorkItem(idx=idx, payload=obj, url=url, timeout_s=timeout_s, verify=verify, idempotency=idempotency))
                idx += 1
        else:
            if not synthetic:
                synthetic_ = True
            else:
                synthetic_ = True
            for i in range(max(0, count)):
                work_q.put(WorkItem(idx=i, payload=_mk_synthetic(i), url=url, timeout_s=timeout_s, verify=verify, idempotency=idempotency))
        for _ in range(concurrency):
            work_q.put(None)

    def _worker(tid: int):
        while True:
            item = work_q.get()
            if item is None:
                break
            res = _do_request(item)
            with results_lock:
                results.append(res)
            sre.observe_latency(res.latency_ms / 1000.0)
        return

    t_batch0 = _now_ms()
    prod = threading.Thread(target=_enqueue, daemon=True)
    prod.start()

    threads = [threading.Thread(target=_worker, args=(i,), daemon=True) for i in range(concurrency)]
    for th in threads:
        th.start()
    for th in threads:
        th.join()

    batch_ms = max(0.0, _now_ms() - t_batch0)

    lat = [r.latency_ms for r in results if r.ok]
    ok_n = sum(1 for r in results if r.ok)
    n = len(results)
    err_429 = sum(1 for r in results if r.status == 429)
    err_5xx = sum(1 for r in results if 500 <= r.status < 600)
    err_other = sum(1 for r in results if (not r.ok) and r.status not in (429,) and r.status < 500)

    ver_yes = sum(1 for r in results if r.verified is True)
    ver_no = sum(1 for r in results if r.verified is False)
    ver_na = sum(1 for r in results if r.verified is None)

    summary = {
        "count": n,
        "ok": ok_n,
        "rate_ok": (ok_n / n) if n else 0.0,
        "latency_ms": {
            "p50": _pct(lat, 0.50),
            "p90": _pct(lat, 0.90),
            "p95": _pct(lat, 0.95),
            "p99": _pct(lat, 0.99),
            "mean": (sum(lat) / len(lat)) if lat else 0.0,
            "batch_wall_ms": batch_ms,
        },
        "errors": {"429": err_429, "5xx": err_5xx, "other": err_other},
        "verify": {"ok": ver_yes, "fail": ver_no, "absent": ver_na},
    }

    sre.push_trace(float(summary["rate_ok"]), attrs={"tool": "tcd-replay", "mode": "batch", "count": str(n)})

    if json_out:
        print(json.dumps(summary, ensure_ascii=False, indent=2))
    else:
        print(
            f"[tcd-replay] n={n} ok={ok_n} ({summary['rate_ok']*100:.1f}%) | "
            f"p50={summary['latency_ms']['p50']:.3f}ms p95={summary['latency_ms']['p95']:.3f}ms p99={summary['latency_ms']['p99']:.3f}ms | "
            f"429={err_429} 5xx={err_5xx} other={err_other} | "
            f"verify ok={ver_yes} fail={ver_no} absent={ver_na}"
        )

    if ver_no > 0 or ok_n == 0:
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        raise
    except Exception as e:  # pragma: no cover
        click.echo(f"Unexpected error: {e}", err=True)
        sys.exit(2)
