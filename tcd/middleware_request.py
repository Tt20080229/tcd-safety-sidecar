# FILE: tcd/middleware_request.py
from __future__ import annotations

import asyncio
import hmac
import io
import json
import re
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple

from blake3 import blake3
from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp

from .policies import BoundPolicy, PolicyStore
from .ratelimit import RateLimiter


# -------------------------
# Config & utilities
# -------------------------

@dataclass
class RequestAuthConfig:
    enable_bearer: bool = False
    enable_hmac: bool = False
    bearer_token_env: str = "TCD_BEARER_TOKEN"
    hmac_secret_env: str = "TCD_HMAC_SECRET"
    # Signature header: hex(HMAC(method+"\n"+path+"\n"+body))
    signature_header: str = "X-TCD-Signature"
    # Allow skipping auth for selected paths (e.g., /healthz, /metrics)
    auth_skip_paths: Tuple[str, ...] = (r"^/healthz$", r"^/metrics$", r"^/version$")


@dataclass
class RequestLimitConfig:
    max_body_bytes: int = 1_000_000  # 1 MB
    # If Content-Length missing, we read up to this hard cap
    hard_read_cap_bytes: int = 2_000_000
    # Rate limiter: capacity/refill per (tenant,user,session)
    rl_capacity: float = 120.0
    rl_refill_per_s: float = 60.0
    # Token cost divisor for rate estimation; may be overridden by policy
    token_cost_divisor_default: float = 50.0
    # Skip paths for limiter
    rate_skip_paths: Tuple[str, ...] = (r"^/healthz$", r"^/metrics$", r"^/version$")


@dataclass
class IdempotencyConfig:
    enable: bool = True
    header: str = "Idempotency-Key"
    ttl_seconds: float = 15.0 * 60.0
    max_entries: int = 50_000
    skip_paths: Tuple[str, ...] = (r"^/verify$", r"^/metrics$", r"^/healthz$")


@dataclass
class PolicyBindConfig:
    # Header names to derive context; body fields fallback if JSON
    h_tenant: str = "X-Tenant"
    h_user: str = "X-User"
    h_session: str = "X-Session"
    h_model: str = "X-Model-Id"
    h_gpu: str = "X-Gpu-Id"
    h_task: str = "X-Task"
    h_lang: str = "X-Lang"
    # Skip paths for binding (keeps overhead minimal on admin/metrics)
    bind_skip_paths: Tuple[str, ...] = (r"^/metrics$", r"^/healthz$", r"^/version$")


@dataclass
class MetricsConfig:
    # Buckets in seconds
    latency_buckets: Tuple[float, ...] = (0.0005, 0.001, 0.002, 0.005, 0.01, 0.02, 0.05, 0.1, 0.2)
    enable: bool = True
    # Normalize dynamic segments to protect cardinality (UUIDs/IDs)
    path_normalizer: Callable[[str], str] = None  # injected later


def _default_normalizer(path: str) -> str:
    # Replace UUIDs and long numeric IDs to reduce cardinality
    p = re.sub(
        r"[0-9a-fA-F]{8}\b-[0-9a-fA-F]{4}\b-[1-5][0-9a-fA-F]{3}\b-[89abAB][0-9a-fA-F]{3}\b-[0-9a-fA-F]{12}",
        ":uuid",
        path,
    )
    p = re.sub(r"/\d{4,}", "/:id", p)
    return p


# -------------------------
# Idempotency cache (in-memory, TTL, LRU)
# -------------------------

class _IdemCache:
    def __init__(self, ttl: float, max_entries: int):
        from collections import OrderedDict
        import threading

        self._ttl = float(ttl)
        self._max = int(max_entries)
        self._data: "OrderedDict[str, Tuple[float, int, Dict[str, str], bytes]]" = OrderedDict()
        self._g = threading.RLock()

    def _evict(self, now: float) -> None:
        keys = list(self._data.keys())
        for k in keys:
            ts, *_ = self._data.get(k, (0.0, 0, {}, b""))
            if now - ts > self._ttl:
                self._data.pop(k, None)
        while len(self._data) > self._max:
            self._data.popitem(last=False)

    def get(self, key: str) -> Optional[Tuple[int, Dict[str, str], bytes]]:
        now = time.time()
        with self._g:
            self._evict(now)
            v = self._data.get(key)
            if not v:
                return None
            ts, code, headers, body = v
            # LRU touch
            self._data.pop(key, None)
            self._data[key] = (ts, code, headers, body)
            return code, headers, body

    def set(self, key: str, code: int, headers: Dict[str, str], body: bytes) -> None:
        now = time.time()
        with self._g:
            self._evict(now)
            self._data[key] = (now, int(code), dict(headers), bytes(body))


# -------------------------
# Prometheus metrics (lazy)
# -------------------------

class _Metrics:
    def __init__(self, cfg: MetricsConfig):
        self.enabled = bool(cfg.enable)
        if not self.enabled:
            return
        from prometheus_client import Counter, Histogram, Gauge, REGISTRY

        self._Counter = Counter
        self._Histogram = Histogram
        self._Gauge = Gauge
        self._reg = REGISTRY

        # Guard: define once per-process
        self.req_ctr = Counter(
            "tcd_http_requests_total",
            "HTTP requests",
            ["method", "path", "code"],
            registry=self._reg,
        )
        self.req_reject = Counter(
            "tcd_http_reject_total",
            "Rejected requests",
            ["reason", "path"],
            registry=self._reg,
        )
        self.req_bytes = Counter(
            "tcd_http_request_bytes_total",
            "Request bytes",
            ["method", "path"],
            registry=self._reg,
        )
        self.resp_bytes = Counter(
            "tcd_http_response_bytes_total",
            "Response bytes",
            ["method", "path", "code"],
            registry=self._reg,
        )
        self.latency = Histogram(
            "tcd_http_latency_seconds",
            "End-to-end request latency",
            buckets=cfg.latency_buckets,
            registry=self._reg,
        )
        self.idem_ctr = Counter(
            "tcd_http_idempotency_total",
            "Idempotency outcomes",
            ["status", "path"],
            registry=self._reg,
        )
        self.rate_block = Counter(
            "tcd_http_rate_limit_total",
            "Rate-limit blocks",
            ["path"],
            registry=self._reg,
        )
        self.auth_sig = Counter(
            "tcd_http_signature_total",
            "Signature verification",
            ["status", "path"],
            registry=self._reg,
        )


# -------------------------
# Middleware
# -------------------------

@dataclass
class TCDRequestMiddlewareConfig:
    auth: RequestAuthConfig = field(default_factory=RequestAuthConfig)
    limits: RequestLimitConfig = field(default_factory=RequestLimitConfig)
    idempotency: IdempotencyConfig = field(default_factory=IdempotencyConfig)
    policies: PolicyBindConfig = field(default_factory=PolicyBindConfig)
    metrics: MetricsConfig = field(default_factory=MetricsConfig)
    # Path regexes to completely bypass the middleware (early return)
    bypass_paths: Tuple[str, ...] = (r"^/metrics$",)


class TCDRequestMiddleware(BaseHTTPMiddleware):
    """
    Request middleware that provides:
      - Optional HMAC/Bearer auth
      - Body size limits
      - Idempotency-Key caching (safe for POST)
      - Policy binding to request.state.tcd_policy
      - Per-tenant rate limiting via Always-Valid subject keys
      - Basic Prometheus metrics with path normalization
    """

    def __init__(
        self,
        app: ASGIApp,
        *,
        cfg: Optional[TCDRequestMiddlewareConfig] = None,
        policy_store: Optional[PolicyStore] = None,
        rate_limiter: Optional[RateLimiter] = None,
    ):
        super().__init__(app)
        self._cfg = cfg or TCDRequestMiddlewareConfig()
        if self._cfg.metrics.path_normalizer is None:
            self._cfg.metrics.path_normalizer = _default_normalizer
        self._metrics = _Metrics(self._cfg.metrics)
        self._store = policy_store
        self._rl = rate_limiter or RateLimiter(
            capacity=self._cfg.limits.rl_capacity,
            refill_per_s=self._cfg.limits.rl_refill_per_s,
        )
        self._idem = _IdemCache(self._cfg.idempotency.ttl_seconds, self._cfg.idempotency.max_entries)

        # Precompile regexes
        self._skip_auth = [re.compile(p) for p in self._cfg.auth.auth_skip_paths]
        self._skip_rate = [re.compile(p) for p in self._cfg.limits.rate_skip_paths]
        self._skip_bind = [re.compile(p) for p in self._cfg.policies.bind_skip_paths]
        self._bypass = [re.compile(p) for p in self._cfg.bypass_paths]
        self._skip_idem = [re.compile(p) for p in self._cfg.idempotency.skip_paths]

    # ------------- helpers -------------

    def _path_match(self, path: str, pats: Iterable[re.Pattern]) -> bool:
        return any(p.search(path) for p in pats)

    def _auth_ok(self, req: Request, raw_body: bytes, norm_path: str) -> bool:
        # Skip if configured
        if self._path_match(req.url.path, self._skip_auth):
            return True
        if not (self._cfg.auth.enable_bearer or self._cfg.auth.enable_hmac):
            return True

        ok = True
        if self._cfg.auth.enable_bearer:
            want = (os.getenv(self._cfg.auth.bearer_token_env) or "").strip()
            have = (req.headers.get("authorization") or "").strip()
            if want:
                if not have.lower().startswith("bearer "):
                    ok = False
                else:
                    token = have[7:].strip()
                    ok &= hmac.compare_digest(token, want)
            # If want is empty, bearer is effectively disabled

        if self._cfg.auth.enable_hmac:
            secret = os.getenv(self._cfg.auth.hmac_secret_env)
            sig_hex = req.headers.get(self._cfg.auth.signature_header, "")
            if secret:
                msg = f"{req.method}\n{req.url.path}\n".encode("utf-8") + raw_body
                calc = hmac.new(secret.encode("utf-8"), msg, "sha256").hexdigest()
                ok &= hmac.compare_digest(calc, sig_hex)

        if self._metrics.enabled:
            self._metrics.auth_sig.labels("ok" if ok else "fail", norm_path).inc()
        return ok

    async def _read_body_with_limit(self, req: Request) -> bytes:
        # Use Content-Length if present
        cl = req.headers.get("content-length")
        if cl is not None:
            try:
                n = int(cl)
            except Exception:
                n = -1
            if n < 0 or n > self._cfg.limits.max_body_bytes:
                raise _Reject(413, "payload too large")
        # Read body up to hard cap
        body = await req.body()
        if len(body) > self._cfg.limits.max_body_bytes:
            raise _Reject(413, "payload too large")
        return body

    def _extract_ctx(self, req: Request, body_json: Optional[Dict[str, Any]]) -> Dict[str, str]:
        h = req.headers
        ctx = {
            "tenant": h.get(self._cfg.policies.h_tenant) or (body_json or {}).get("tenant") or "*",
            "user": h.get(self._cfg.policies.h_user) or (body_json or {}).get("user") or "*",
            "session": h.get(self._cfg.policies.h_session) or (body_json or {}).get("session") or "*",
            "model_id": h.get(self._cfg.policies.h_model) or (body_json or {}).get("model_id") or "*",
            "gpu_id": h.get(self._cfg.policies.h_gpu) or (body_json or {}).get("gpu_id") or "*",
            "task": h.get(self._cfg.policies.h_task) or (body_json or {}).get("task") or "*",
            "lang": h.get(self._cfg.policies.h_lang) or (body_json or {}).get("lang") or "*",
        }
        return {k: (str(v) if v is not None else "*") for k, v in ctx.items()}

    def _rate_check(self, ctx: Dict[str, str], body_json: Optional[Dict[str, Any]], norm_path: str) -> None:
        if self._path_match(ctx.get("_path", ""), self._skip_rate):
            return
        # cost from tokens_delta if available; else 1
        tokens_delta = 1.0
        if isinstance(body_json, dict) and "tokens_delta" in body_json:
            try:
                tokens_delta = float(body_json["tokens_delta"])
            except Exception:
                tokens_delta = 1.0
        divisor = float(ctx.get("_token_cost_divisor", self._cfg.limits.token_cost_divisor_default))
        cost = max(1.0, tokens_delta / max(1.0, divisor))
        key = (ctx.get("tenant", "*"), ctx.get("user", "*"), ctx.get("session", "*"))
        if not self._rl.consume(key, cost=cost):
            if self._metrics.enabled:
                self._metrics.rate_block.labels(norm_path).inc()
            raise _Reject(429, "rate limited")

    def _hash_body(self, b: bytes) -> str:
        return blake3(b).hexdigest()

    def _idem_key(self, req: Request, norm_path: str, idem_val: str, body_hash: str) -> str:
        base = f"{req.method}:{norm_path}:{idem_val}:{body_hash}"
        return blake3(base.encode("utf-8")).hexdigest()

    # ------------- dispatch -------------

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        path = request.url.path
        if self._path_match(path, self._bypass):
            return await call_next(request)

        t0 = time.perf_counter()
        norm_path = self._cfg.metrics.path_normalizer(path)
        raw_body = b""
        body_json: Optional[Dict[str, Any]] = None
        bound: Optional[BoundPolicy] = None

        try:
            # Body read (once) with limit, then re-attach for downstream
            raw_body = await self._read_body_with_limit(request)
            if raw_body:
                try:
                    body_json = json.loads(raw_body.decode("utf-8"))
                    # Recanonicalize to keep downstream JSON loaders simple
                    raw_body = json.dumps(body_json, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
                except Exception:
                    body_json = None

            # Auth
            if not self._auth_ok(request, raw_body, norm_path):
                raise _Reject(403, "forbidden")

            # Policy bind
            if self._store and not self._path_match(path, self._skip_bind):
                ctx = self._extract_ctx(request, body_json)
                bound = self._store.bind(ctx)
                # Attach derived values for rate limiting
                ctx["_token_cost_divisor"] = str(bound.token_cost_divisor)
                ctx["_path"] = path
                # Expose to route handlers
                request.state.tcd_policy = bound
                request.state.tcd_ctx = ctx

            # Rate limit (per tenant/user/session)
            if bound:
                ctx_local = request.state.tcd_ctx
            else:
                ctx_local = self._extract_ctx(request, body_json)
                ctx_local["_path"] = path
                ctx_local["_token_cost_divisor"] = str(self._cfg.limits.token_cost_divisor_default)
            self._rate_check(ctx_local, body_json, norm_path)

            # Idempotency (optional; safe for POST)
            idem_header = request.headers.get(self._cfg.idempotency.header)
            use_idem = (
                self._cfg.idempotency.enable
                and idem_header
                and not self._path_match(path, self._skip_idem)
                and request.method.upper() in ("POST", "PUT", "PATCH")
            )

            if use_idem:
                key = self._idem_key(request, norm_path, idem_header, self._hash_body(raw_body))
                hit = self._idem.get(key)
                if hit is not None:
                    code, hdrs, body = hit
                    if self._metrics.enabled:
                        self._metrics.idem_ctr.labels("hit", norm_path).inc()
                    # Re-inject X-Request-Id if present
                    headers = {k: v for k, v in hdrs.items() if k.lower() not in ("content-length",)}
                    return Response(content=body, status_code=code, headers=headers, media_type=hdrs.get("content-type"))

            # Rebuild request with original body for downstream
            async def receive_gen():
                yield {"type": "http.request", "body": raw_body, "more_body": False}

            request._receive = _iterable_as_receive(receive_gen())  # type: ignore[attr-defined]

            # Call downstream
            resp = await call_next(request)

            # Capture body to support idempotency store and metrics
            captured, resp2 = await _capture_response(resp)

            # Store idempotent outcome
            if use_idem:
                headers = {k.decode().lower(): v.decode() for k, v in captured.headers}
                self._idem.set(key, captured.status_code, headers, captured.body)
                if self._metrics.enabled:
                    self._metrics.idem_ctr.labels("store", norm_path).inc()

            # Metrics
            if self._metrics.enabled:
                self._metrics.req_bytes.labels(request.method, norm_path).inc(len(raw_body))
                self._metrics.resp_bytes.labels(request.method, norm_path, str(resp2.status_code)).inc(len(captured.body))
                self._metrics.req_ctr.labels(request.method, norm_path, str(resp2.status_code)).inc()
                self._metrics.latency.observe(max(0.0, time.perf_counter() - t0))

            return resp2

        except _Reject as rj:
            if self._metrics.enabled:
                self._metrics.req_reject.labels(rj.reason, norm_path).inc()
                self._metrics.req_ctr.labels(request.method, norm_path, str(rj.code)).inc()
                self._metrics.latency.observe(max(0.0, time.perf_counter() - t0))
            return Response(content=json.dumps({"error": rj.reason}), status_code=rj.code, media_type="application/json")
        except Exception:
            if self._metrics.enabled:
                self._metrics.req_reject.labels("exception", norm_path).inc()
                self._metrics.req_ctr.labels(request.method, norm_path, "500").inc()
                self._metrics.latency.observe(max(0.0, time.perf_counter() - t0))
            return Response(content=json.dumps({"error": "internal"}), status_code=500, media_type="application/json")


# -------------------------
# Internal helpers (ASGI)
# -------------------------

class _Reject(Exception):
    def __init__(self, code: int, reason: str):
        self.code = int(code)
        self.reason = str(reason)
        super().__init__(reason)


def _iterable_as_receive(iterable: Iterable[Dict[str, Any]]) -> Callable[[], Any]:
    iterator = iter(iterable)

    async def receive() -> Dict[str, Any]:
        try:
            return next(iterator)
        except StopIteration:
            await asyncio.sleep(0)  # allow loop switch
            return {"type": "http.request"}

    return receive


@dataclass
class _Captured:
    status_code: int
    headers: List[Tuple[bytes, bytes]]
    body: bytes


async def _capture_response(resp: Response) -> Tuple[_Captured, Response]:
    # Starlette Response has body_iterator for streaming; consume it
    body_chunks: List[bytes] = []
    if hasattr(resp, "body_iterator") and resp.body_iterator is not None:
        async for chunk in resp.body_iterator:
            if isinstance(chunk, (bytes, bytearray)):
                body_chunks.append(bytes(chunk))
            elif isinstance(chunk, memoryview):
                body_chunks.append(chunk.tobytes())
            elif isinstance(chunk, str):
                body_chunks.append(chunk.encode("utf-8"))
            else:
                # Unknown type, coerce to bytes
                body_chunks.append(bytes(chunk))
        body = b"".join(body_chunks)
        headers = list(getattr(resp, "raw_headers", []) or [])
        media_type = getattr(resp, "media_type", None)
        status = resp.status_code
        # Rebuild a new Response with captured body
        new_resp = Response(
            content=body,
            status_code=status,
            headers={k.decode(): v.decode() for k, v in headers},
            media_type=media_type,
        )
        return _Captured(status, headers, body), new_resp

    # Non-streaming responses may already have .body
    body = resp.body if hasattr(resp, "body") else b""
    headers = list(getattr(resp, "raw_headers", []) or [])
    status = resp.status_code
    return _Captured(status, headers, body), resp


# -------------------------
# Wiring helper
# -------------------------

def add_request_middleware(
    app: ASGIApp,
    *,
    config: Optional[TCDRequestMiddlewareConfig] = None,
    policy_store: Optional[PolicyStore] = None,
    rate_limiter: Optional[RateLimiter] = None,
) -> None:
    """
    Install TCDRequestMiddleware with the given configuration.
    """
    app.add_middleware(
        TCDRequestMiddleware,
        cfg=config or TCDRequestMiddlewareConfig(),
        policy_store=policy_store,
        rate_limiter=rate_limiter,
    )
