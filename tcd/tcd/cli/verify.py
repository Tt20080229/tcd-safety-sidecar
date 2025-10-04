# FILE: tcd/cli/verify.py
from __future__ import annotations

import io
import json
import sys
import time
from pathlib import Path
from typing import List, Optional, Tuple

import click

# Prom/OTel (optional)
try:
    from prometheus_client import Counter, Histogram, start_http_server
    _HAS_PROM = True
except Exception:
    _HAS_PROM = False

from ..otel_exporter import TCDOtelExporter
from ..verify import verify_receipt, verify_chain


# ---------- Metrics (optional) ----------

_cli_verify_hist = None
_cli_verify_ctr = None

def _ensure_metrics(metrics_port: Optional[int]):
    global _cli_verify_hist, _cli_verify_ctr
    if not _HAS_PROM:
        return
    if _cli_verify_hist is None or _cli_verify_ctr is None:
        _cli_verify_hist = Histogram(
            "tcd_cli_verify_latency_seconds", "CLI verify latency",
            buckets=(0.0002, 0.0005, 0.001, 0.002, 0.005, 0.01)
        )
        _cli_verify_ctr = Counter(
            "tcd_cli_verify_total", "CLI verify results", ["kind", "status"]
        )
    if metrics_port and metrics_port > 0:
        try:
            start_http_server(metrics_port)
        except Exception:
            pass


# ---------- Utilities ----------

def _read_text(maybe_path: Optional[str]) -> Optional[str]:
    """Load from path, '-' (stdin), or return literal string."""
    if maybe_path is None:
        return None
    if maybe_path == "-":
        data = sys.stdin.read()
        return data
    p = Path(maybe_path)
    if p.exists() and p.is_file():
        return p.read_text(encoding="utf-8")
    return maybe_path


def _read_json(maybe_path: Optional[str]) -> Optional[object]:
    txt = _read_text(maybe_path)
    if txt is None:
        return None
    try:
        return json.loads(txt)
    except Exception:
        return txt


def _load_witness(maybe_path: Optional[str]) -> Optional[Tuple[List[int], List[int], List[int]]]:
    """
    Accept either:
      - JSON object: {"trace": [...], "spectrum": [...], "feat": [...]}
      - JSON array: [[...trace...], [...spectrum...], [...feat...]]
    """
    if maybe_path is None:
        return None
    obj = _read_json(maybe_path)
    if obj is None:
        return None
    if isinstance(obj, dict):
        try:
            a = [int(x) for x in obj.get("trace", [])]
            b = [int(x) for x in obj.get("spectrum", [])]
            c = [int(x) for x in obj.get("feat", [])]
            return (a, b, c)
        except Exception:
            raise click.BadParameter("witness must contain integer arrays for trace/spectrum/feat")
    if isinstance(obj, list) and len(obj) == 3:
        try:
            a = [int(x) for x in obj[0]]
            b = [int(x) for x in obj[1]]
            c = [int(x) for x in obj[2]]
            return (a, b, c)
        except Exception:
            raise click.BadParameter("witness arrays must be integers")
    raise click.BadParameter("witness must be object {trace,spectrum,feat} or triple array")


def _normalize_heads_bodies(
    heads_src: Optional[str],
    bodies_src: Optional[str],
    jsonl: bool,
) -> Tuple[List[str], List[str]]:
    """
    Load heads and bodies from files or JSONL.
    Supported inputs:
      - heads file: JSON array of hex strings (heads)
      - bodies file: JSON array of canonical JSON strings (bodies)
      - jsonl file (when jsonl=True): each line is an object containing:
            {"receipt": "<head-hex>", "receipt_body": "<canonical-body-json>"}
        or legacy keys { "head": "...", "body": "..." }
    """
    heads: List[str] = []
    bodies: List[str] = []

    if jsonl:
        if not heads_src:
            raise click.BadParameter("When --jsonl is used, --heads must point to a JSONL file")
        txt = _read_text(heads_src) or ""
        for line in io.StringIO(txt):
            s = line.strip()
            if not s:
                continue
            try:
                obj = json.loads(s)
            except Exception:
                raise click.BadParameter("Invalid JSONL line for heads/bodies")
            head = obj.get("receipt") or obj.get("receipt_head") or obj.get("head")
            body = obj.get("receipt_body") or obj.get("body")
            if not (isinstance(head, str) and isinstance(body, str)):
                raise click.BadParameter("JSONL objects must contain 'receipt' and 'receipt_body' fields")
            heads.append(head)
            bodies.append(body)
        if not heads or not bodies or len(heads) != len(bodies):
            raise click.BadParameter("JSONL must contain aligned 'receipt' and 'receipt_body'")
        return heads, bodies

    if heads_src:
        h = _read_json(heads_src)
        if isinstance(h, list):
            heads = [str(x) for x in h]
        elif isinstance(h, str):
            heads = [h]
        else:
            raise click.BadParameter("--heads must be a JSON array or a single hex string")
    if bodies_src:
        b = _read_json(bodies_src)
        if isinstance(b, list):
            bodies = [str(x) for x in b]
        elif isinstance(b, str):
            bodies = [b]
        else:
            raise click.BadParameter("--bodies must be a JSON array or a canonical JSON string")

    if not heads or not bodies or len(heads) != len(bodies):
        raise click.BadParameter("Aligned --heads and --bodies are required in non-JSONL mode")

    return heads, bodies


def _print_result(ok: bool, dur_s: float, json_out: bool) -> int:
    if json_out:
        print(json.dumps({"ok": bool(ok), "latency_ms": dur_s * 1000.0}, ensure_ascii=False))
    else:
        status = "OK" if ok else "FAIL"
        print(f"[{status}] verify in {dur_s*1000.0:.3f} ms")
    return 0 if ok else 1


# ---------- CLI ----------

@click.group(context_settings={"help_option_names": ["-h", "--help"]})
@click.option("--metrics-port", type=int, default=None, help="Expose Prometheus metrics on this port (optional)")
@click.option("--otel", is_flag=True, help="Enable OpenTelemetry export (optional)")
@click.option("--otel-endpoint", default="http://localhost:4318", show_default=True, help="OTLP HTTP endpoint")
@click.pass_context
def cli(ctx: click.Context, metrics_port: Optional[int], otel: bool, otel_endpoint: str):
    """TCD Receipt Verifier — verify single receipts or chains with optional metrics."""
    _ensure_metrics(metrics_port)
    ctx.ensure_object(dict)
    ctx.obj["METRICS_PORT"] = metrics_port
    ctx.obj["OTEL_ENABLED"] = bool(otel)
    ctx.obj["OTEL"] = TCDOtelExporter(endpoint=otel_endpoint) if otel else None


@cli.command("receipt")
@click.option("--head", "head_hex", required=True, help="Receipt head hex (or @file / literal)")
@click.option("--body", "body_src", required=True, help="Receipt body canonical JSON (path, '-', or literal JSON)")
@click.option("--sig", "sig_hex", default=None, help="Optional Ed25519 signature hex")
@click.option("--vk", "verify_key_hex", default=None, help="Optional Ed25519 verify key hex")
@click.option("--req", "req_src", default=None, help="Optional req_obj JSON (path or literal JSON)")
@click.option("--comp", "comp_src", default=None, help="Optional comp_obj JSON")
@click.option("--e", "e_src", default=None, help="Optional e_obj JSON")
@click.option("--witness", "witness_src", default=None, help="Optional witness JSON (object or triple array)")
@click.option("--label-salt-hex", default=None, help="Optional label salt hex used at issue time")
@click.option("--json", "json_out", is_flag=True, help="Print JSON result")
@click.pass_context
def receipt_cmd(
    ctx: click.Context,
    head_hex: str,
    body_src: str,
    sig_hex: Optional[str],
    verify_key_hex: Optional[str],
    req_src: Optional[str],
    comp_src: Optional[str],
    e_src: Optional[str],
    witness_src: Optional[str],
    label_salt_hex: Optional[str],
    json_out: bool,
):
    """
    Verify a single receipt against its canonical body (+ optional signature and witnesses).
    Exit codes: 0=ok, 1=verification failed, 2=bad input.
    """
    try:
        body_json = _read_text(body_src)
        if body_json is None:
            raise click.BadParameter("--body is required")
        req_obj = _read_json(req_src) if req_src else None
        comp_obj = _read_json(comp_src) if comp_src else None
        e_obj = _read_json(e_src) if e_src else None
        witness = _load_witness(witness_src) if witness_src else None
    except click.BadParameter as e:
        click.echo(f"Input error: {e}", err=True)
        sys.exit(2)

    t0 = time.perf_counter()
    ok = verify_receipt(
        receipt_head_hex=head_hex,
        receipt_body_json=body_json,
        verify_key_hex=verify_key_hex,
        receipt_sig_hex=sig_hex,
        req_obj=req_obj if isinstance(req_obj, dict) else None,
        comp_obj=comp_obj if isinstance(comp_obj, dict) else None,
        e_obj=e_obj if isinstance(e_obj, dict) else None,
        witness_segments=witness,
        strict=True,
        label_salt_hex=label_salt_hex,
    )
    dur = time.perf_counter() - t0

    if _HAS_PROM and _cli_verify_hist is not None and _cli_verify_ctr is not None:
        _cli_verify_hist.observe(dur)
        _cli_verify_ctr.labels("receipt", "ok" if ok else "fail").inc()

    ot = ctx.obj.get("OTEL")
    if ctx.obj.get("OTEL_ENABLED") and ot is not None:
        try:
            ot.push_metrics(float(ok), attrs={
                "tcd.cli.kind": "receipt",
                "tcd.cli.status": "ok" if ok else "fail",
                "tcd.cli.latency_ms": dur * 1000.0,
            })
        except Exception:
            pass

    sys.exit(_print_result(bool(ok), dur, json_out))


@cli.command("chain")
@click.option("--heads", "heads_src", required=True, help="File with heads (JSON array) or JSONL when --jsonl")
@click.option("--bodies", "bodies_src", default=None, help="File with bodies (JSON array); omit if --jsonl")
@click.option("--jsonl", is_flag=True, help="Parse --heads as JSONL with {receipt, receipt_body}")
@click.option("--label-salt-hex", default=None, help="Optional label salt hex used at issue time (reserved)")
@click.option("--json", "json_out", is_flag=True, help="Print JSON result")
@click.pass_context
def chain_cmd(
    ctx: click.Context,
    heads_src: str,
    bodies_src: Optional[str],
    jsonl: bool,
    label_salt_hex: Optional[str],
    json_out: bool,
):
    """
    Verify a linear chain of receipts:
      - non-JSONL: --heads <json-array> and --bodies <json-array> of equal length
      - JSONL: --jsonl and --heads <file.jsonl> (each line has receipt & receipt_body)
    Exit codes: 0=ok, 1=verification failed, 2=bad input.
    """
    try:
        heads, bodies = _normalize_heads_bodies(heads_src, bodies_src, jsonl=jsonl)
    except click.BadParameter as e:
        click.echo(f"Input error: {e}", err=True)
        sys.exit(2)

    t0 = time.perf_counter()
    ok = verify_chain(heads, bodies, label_salt_hex=label_salt_hex)
    dur = time.perf_counter() - t0

    if _HAS_PROM and _cli_verify_hist is not None and _cli_verify_ctr is not None:
        _cli_verify_hist.observe(dur)
        _cli_verify_ctr.labels("chain", "ok" if ok else "fail").inc()

    ot = ctx.obj.get("OTEL")
    if ctx.obj.get("OTEL_ENABLED") and ot is not None:
        try:
            ot.push_metrics(float(ok), attrs={
                "tcd.cli.kind": "chain",
                "tcd.cli.status": "ok" if ok else "fail",
                "tcd.cli.latency_ms": dur * 1000.0,
                "tcd.cli.count": len(heads),
            })
        except Exception:
            pass

    sys.exit(_print_result(bool(ok), dur, json_out))


@cli.command("version")
def version_cmd():
    """Print verifier version (matches library semver when released together)."""
    print(json.dumps({"tool": "tcd-verify", "version": "0.10.2"}, ensure_ascii=False))


def main():
    cli(standalone_mode=False)


if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        raise
    except Exception as e:
        click.echo(f"Unexpected error: {e}", err=True)
        sys.exit(2)
