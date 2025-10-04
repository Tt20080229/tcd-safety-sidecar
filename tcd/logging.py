# FILE: tcd/logging.py
from __future__ import annotations

import contextvars
import datetime as _dt
import json
import logging
import os
import sys
import traceback
import types
import uuid
from typing import Any, Dict, Iterable, Optional, Tuple

# Optional OpenTelemetry context
try:
    from opentelemetry import trace as _otel_trace  # type: ignore
    _HAS_OTEL = True
except Exception:  # pragma: no cover
    _HAS_OTEL = False

# -----------------------
# Context management
# -----------------------

_log_ctx: contextvars.ContextVar[Dict[str, Any]] = contextvars.ContextVar(
    "tcd_log_ctx", default={}
)


def bind(**fields: Any) -> None:
    """Merge fields into the current logging context (per-coroutine)."""
    cur = dict(_log_ctx.get())
    for k, v in fields.items():
        if v is None:
            continue
        cur[str(k)] = v
    _log_ctx.set(cur)


def unbind(*keys: str) -> None:
    """Remove fields from the current logging context."""
    cur = dict(_log_ctx.get())
    for k in keys:
        cur.pop(k, None)
    _log_ctx.set(cur)


def reset() -> None:
    """Clear all fields from the current logging context."""
    _log_ctx.set({})


def context() -> Dict[str, Any]:
    """Snapshot the current context."""
    return dict(_log_ctx.get())


# -----------------------
# OpenTelemetry helpers
# -----------------------

def _otel_ids() -> Tuple[Optional[str], Optional[str]]:
    if not _HAS_OTEL:
        return None, None
    try:
        span = _otel_trace.get_current_span()
        ctx = span.get_span_context()
        if not ctx or not ctx.is_valid:
            return None, None
        return (format(ctx.trace_id, "032x"), format(ctx.span_id, "016x"))
    except Exception:  # pragma: no cover
        return None, None


# -----------------------
# JSON formatter
# -----------------------

def _ts_iso() -> str:
    # RFC3339 with milliseconds, UTC Z
    now = _dt.datetime.utcnow().replace(tzinfo=_dt.timezone.utc)
    # Drop microseconds to milliseconds precision
    ms = int(now.microsecond / 1000)
    base = now.replace(microsecond=0).isoformat().replace("+00:00", "Z")
    return f"{base[:-1]}.{ms:03d}Z"


def _compact_json(obj: Dict[str, Any]) -> str:
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":"))


class JSONFormatter(logging.Formatter):
    """
    Minimal-allocation JSON formatter.
    Emits canonical fields for SRE & research workflows.

    Core fields:
      - ts, lvl, msg, logger
      - req_id, trace_id, span_id
      - tenant, model_id, verdict, e_value, a_alloc
    """

    def __init__(self, *, include_stack: bool = True):
        super().__init__()
        self.include_stack = include_stack

    def format(self, record: logging.LogRecord) -> str:  # type: ignore[override]
        ctx = context()
        trace_id, span_id = _otel_ids()

        # Base envelope
        evt: Dict[str, Any] = {
            "ts": _ts_iso(),
            "lvl": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }

        # Context (request + decision)
        # Prefer explicitly bound values; accept record.<attr> as fallback.
        def _pick(*names: str) -> Optional[Any]:
            for n in names:
                if n in ctx:
                    return ctx[n]
                v = getattr(record, n, None)
                if v is not None:
                    return v
            return None

        _merge_optional(
            evt,
            req_id=_pick("req_id"),
            trace_id=trace_id or _pick("trace_id"),
            span_id=span_id or _pick("span_id"),
            tenant=_pick("tenant"),
            model_id=_pick("model_id"),
            verdict=_pick("verdict"),
            e_value=_pick("e_value"),
            a_alloc=_pick("a_alloc"),
            route=_pick("route"),  # optional: routing decision tag
            path=_pick("path"),
            method=_pick("method"),
            status=_pick("status") or _pick("status_code"),
        )

        # Exception info
        if record.exc_info and self.include_stack:
            exc_type, exc_val, exc_tb = record.exc_info
            evt["exc_type"] = getattr(exc_type, "__name__", str(exc_type))
            evt["exc_message"] = str(exc_val)
            evt["stack"] = "".join(traceback.format_exception(exc_type, exc_val, exc_tb))

        return _compact_json(evt)


def _merge_optional(dst: Dict[str, Any], **kvs: Any) -> None:
    for k, v in kvs.items():
        if v is None:
            continue
        # Avoid NaN/Inf leaking into JSON
        if isinstance(v, float):
            if v != v or v == float("inf") or v == float("-inf"):
                continue
        dst[k] = v


# -----------------------
# Uvicorn integration
# -----------------------

def _clear_handlers(logger: logging.Logger) -> None:
    for h in list(logger.handlers):
        logger.removeHandler(h)


def configure_json_logging(
    level: str = "INFO",
    *,
    include_uvicorn: bool = True,
    stream: Any = None,
    include_stack: bool = True,
) -> logging.Logger:
    """
    Configure root+uvicorn loggers for JSON output.

    - Sets root level and installs a single StreamHandler with JSONFormatter.
    - Replaces uvicorn.access / uvicorn.error handlers to avoid duplicate logs.
    - Keeps logger propagation enabled to allow per-module tuning if needed.
    """
    lvl = getattr(logging, (level or "INFO").upper(), logging.INFO)
    stream = stream or sys.stderr

    fmt = JSONFormatter(include_stack=include_stack)
    h = logging.StreamHandler(stream=stream)
    h.setFormatter(fmt)
    h.setLevel(lvl)

    # Root logger
    root = logging.getLogger()
    root.setLevel(lvl)
    _clear_handlers(root)
    root.addHandler(h)

    if include_uvicorn:
        for name in ("uvicorn", "uvicorn.error", "uvicorn.access"):
            lg = logging.getLogger(name)
            lg.setLevel(lvl)
            _clear_handlers(lg)
            lg.addHandler(h)
            lg.propagate = False  # keep it single-emission

    return root


# -----------------------
# Request helpers
# -----------------------

def ensure_request_id(headers: Optional[Dict[str, str]] = None) -> str:
    """
    Get or create a stable request id; bind into context immediately.
    """
    rid = None
    if headers:
        rid = headers.get("x-request-id") or headers.get("X-Request-Id")
    if not rid:
        rid = uuid.uuid4().hex[:16]
    bind(req_id=rid)
    return rid


def bind_request_meta(
    *,
    tenant: Optional[str] = None,
    user: Optional[str] = None,
    session: Optional[str] = None,
    model_id: Optional[str] = None,
    gpu_id: Optional[str] = None,
    task: Optional[str] = None,
    lang: Optional[str] = None,
    path: Optional[str] = None,
    method: Optional[str] = None,
) -> None:
    """
    Attach request-scoped metadata for correlation.
    """
    bind(
        tenant=tenant,
        user=user,
        session=session,
        model_id=model_id,
        gpu_id=gpu_id,
        task=task,
        lang=lang,
        path=path,
        method=method,
    )


def log_decision(
    logger: logging.Logger,
    *,
    verdict: bool,
    score: Optional[float] = None,
    e_value: Optional[float] = None,
    alpha_alloc: Optional[float] = None,
    message: str = "decision",
    extra: Optional[Dict[str, Any]] = None,
    level: int = logging.INFO,
) -> None:
    """
    Emit a single structured decision log line with canonical fields.
    """
    # Bind transient decision fields for this event only
    extra_dict: Dict[str, Any] = {
        "verdict": bool(verdict),
        "e_value": float(e_value) if e_value is not None else None,
        "a_alloc": float(alpha_alloc) if alpha_alloc is not None else None,
        "score": float(score) if score is not None else None,
    }
    if extra:
        for k, v in extra.items():
            if v is not None:
                extra_dict[k] = v
    logger.log(level, message, extra=extra_dict)


# -----------------------
# Convenience: module-level logger
# -----------------------

_logger = None  # type: Optional[logging.Logger]


def get_logger(name: str = "tcd") -> logging.Logger:
    """
    Return a module-level logger configured for JSON output.
    First call initializes the root+uvicorn setup if not configured.
    """
    global _logger
    if _logger is None:
        # Respect env level if provided
        lvl = os.environ.get("TCD_LOG_LEVEL", "INFO")
        _logger = configure_json_logging(level=lvl, include_uvicorn=True)
    return logging.getLogger(name)
