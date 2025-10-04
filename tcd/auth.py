# FILE: tcd/auth.py
from __future__ import annotations

import json
import os
import time
import hmac
from dataclasses import dataclass
from typing import Callable, Dict, List, Optional, Tuple

from blake3 import blake3
from fastapi import HTTPException
from starlette.requests import Request

try:
    from prometheus_client import Counter
    _HAS_PROM = True
except Exception:
    _HAS_PROM = False


# ---------- Models ----------

@dataclass
class AuthContext:
    mode: str                # "disabled" | "bearer" | "hmac" | "jwt" | "mtls"
    principal: str           # e.g., "svc:gateway" / "tenant:alice"
    scopes: List[str]        # logical scopes/roles
    key_id: Optional[str]    # for hmac/jwt key tracking
    raw: Dict[str, str]      # raw header fields of interest


@dataclass
class AuthResult:
    ok: bool
    ctx: Optional[AuthContext]
    reason: Optional[str] = None


# ---------- Metrics ----------

if _HAS_PROM:
    _AUTH_OK = Counter("tcd_auth_ok_total", "Auth OK", ["mode"])
    _AUTH_FAIL = Counter("tcd_auth_fail_total", "Auth Fail", ["mode", "reason"])
else:
    class _Nop:
        def labels(self, *_, **__): return self
        def inc(self, *_ , **__): pass
    _AUTH_OK = _Nop()
    _AUTH_FAIL = _Nop()


def _inc_ok(mode: str) -> None:
    _AUTH_OK.labels(mode).inc()


def _inc_fail(mode: str, reason: str) -> None:
    _AUTH_FAIL.labels(mode, reason).inc()


# ---------- Helpers ----------

def _b(s: str) -> bytes:
    return s.encode("utf-8")


def _now() -> float:
    return time.time()


def _hmac_blake3(key: bytes, ctx: str, data: bytes) -> str:
    """Domain-separated keyed blake3; returns hex."""
    h = blake3(key=key)
    if ctx:
        ctx_b = ctx.encode("utf-8")
        h.update(len(ctx_b).to_bytes(4, "big") + ctx_b)
    h.update(data)
    return h.hexdigest()


def client_sign_hmac(method: str, path: str, body_bytes: bytes, *, key_hex: str, ts: Optional[int] = None) -> Tuple[str, int]:
    """
    Helper for clients/tests to construct X-TCD-Signature (v1).
    Returns header_value, ts
    """
    ts = int(ts if ts is not None else _now())
    payload = _b(f"{ts}\n{method.upper()}\n{path}\n") + (body_bytes or b"")
    sig_hex = _hmac_blake3(bytes.fromhex(key_hex), "tcd:hmac", payload)
    return f"v1,t={ts},sig={sig_hex}", ts


# ---------- Authenticator ----------

class Authenticator:
    """
    Pluggable authenticator with two production-safe modes:
      - bearer: static token allowlist (comma-separated)
      - hmac:   signed requests with timestamp + raw body (replay-resistant)
    Disabled mode is allowed for local dev/tests.
    """

    def __init__(
        self,
        mode: str = "disabled",
        *,
        bearer_tokens: Optional[List[str]] = None,
        hmac_keys: Optional[Dict[str, str]] = None,   # key_id -> hex
        max_skew_s: int = 300,
        jwt_aud: Optional[str] = None,                # reserved
        jwks_json: Optional[str] = None,              # reserved
        mtls_fp_allow: Optional[List[str]] = None,    # reserved
    ):
        m = (mode or "disabled").lower()
        if m not in ("disabled", "bearer", "hmac", "jwt", "mtls"):
            raise ValueError("auth mode must be one of disabled|bearer|hmac|jwt|mtls")
        self.mode = m
        self.bearer = set([t.strip() for t in (bearer_tokens or []) if t.strip()])
        self.hmac_keys = {str(k): v.lower() for k, v in (hmac_keys or {}).items()}
        self.max_skew_s = int(max(1, max_skew_s))
        self.jwt_aud = jwt_aud
        self.jwks_json = jwks_json
        self.mtls_fp_allow = set([fp.lower() for fp in (mtls_fp_allow or [])])

    # ---- core verify ----

    async def verify(self, request: Request) -> AuthResult:
        """
        Return AuthResult. Never raises; raising is left to the FastAPI dependency wrapper.
        """
        if self.mode == "disabled":
            ctx = AuthContext(mode="disabled", principal="anonymous", scopes=["public"], key_id=None, raw={})
            _inc_ok(self.mode)
            return AuthResult(True, ctx)

        if self.mode == "bearer":
            return await self._verify_bearer(request)

        if self.mode == "hmac":
            return await self._verify_hmac(request)

        if self.mode == "jwt":
            # Reserved: provide a clear error to avoid silent bypass.
            _inc_fail("jwt", "not_implemented")
            return AuthResult(False, None, "jwt mode not implemented in this build")

        if self.mode == "mtls":
            _inc_fail("mtls", "not_implemented")
            return AuthResult(False, None, "mtls mode not implemented in this build")

        _inc_fail(self.mode, "bad_mode")
        return AuthResult(False, None, "bad auth mode")

    # ---- modes ----

    async def _verify_bearer(self, request: Request) -> AuthResult:
        auth = request.headers.get("authorization", "")
        if not auth.lower().startswith("bearer "):
            _inc_fail("bearer", "missing")
            return AuthResult(False, None, "missing bearer")
        token = auth.split(" ", 1)[1].strip()
        if token in self.bearer:
            ctx = AuthContext(mode="bearer", principal="bearer", scopes=["api"], key_id=None, raw={"authorization": "***"})
            _inc_ok("bearer")
            return AuthResult(True, ctx)
        _inc_fail("bearer", "denied")
        return AuthResult(False, None, "invalid bearer")

    async def _verify_hmac(self, request: Request) -> AuthResult:
        """
        Header format:
          X-TCD-Signature: v1,t=<unix_ts>,sig=<hex>
          X-TCD-Key-Id: <kid>           (optional; defaults to "default")
        Payload signed bytes: "<ts>\n<METHOD>\n<PATH>\n" + <raw-body>
        Hash: blake3(key=secret, ctx="tcd:hmac")
        """
        sig_hdr = request.headers.get("x-tcd-signature", "")
        kid = request.headers.get("x-tcd-key-id", "default")
        if not sig_hdr:
            _inc_fail("hmac", "missing")
            return AuthResult(False, None, "missing signature")

        try:
            scheme, rest = sig_hdr.split(",", 1)
            if scheme.strip().lower() != "v1":
                _inc_fail("hmac", "bad_scheme")
                return AuthResult(False, None, "bad signature scheme")
            parts = dict(p.split("=", 1) for p in [x.strip() for x in rest.split(",")] if "=" in x)
            ts = int(parts.get("t", "0"))
            sig = parts.get("sig", "")
        except Exception:
            _inc_fail("hmac", "malformed")
            return AuthResult(False, None, "malformed signature header")

        if kid not in self.hmac_keys:
            _inc_fail("hmac", "unknown_key")
            return AuthResult(False, None, "unknown key")

        # replay window
        now = int(_now())
        if abs(now - ts) > self.max_skew_s:
            _inc_fail("hmac", "skew")
            return AuthResult(False, None, "timestamp out of window")

        # reconstruct payload
        raw = await request.body()
        payload = _b(f"{ts}\n{request.method.upper()}\n{request.url.path}\n") + (raw or b"")
        secret_hex = self.hmac_keys[kid]
        calc = _hmac_blake3(bytes.fromhex(secret_hex), "tcd:hmac", payload)

        if not hmac.compare_digest(calc, sig.lower()):
            _inc_fail("hmac", "mismatch")
            return AuthResult(False, None, "signature mismatch")

        principal = f"hmac:{kid}"
        ctx = AuthContext(mode="hmac", principal=principal, scopes=["api", "signed"], key_id=kid, raw={"x-tcd-signature": "v1,***", "x-tcd-key-id": kid})
        _inc_ok("hmac")
        return AuthResult(True, ctx)


# ---------- Factory & FastAPI dependency ----------

def build_authenticator_from_env() -> Authenticator:
    """
    Environment-driven config:

      TCD_AUTH_MODE            : disabled | bearer | hmac
      TCD_AUTH_BEARER_TOKENS   : comma-separated allowlist (bearer mode)
      TCD_AUTH_HMAC_KEYS_JSON  : {"default":"<hexkey>", "kid2":"<hexkey2>"}
      TCD_AUTH_MAX_SKEW_S      : default 300
    """
    mode = os.environ.get("TCD_AUTH_MODE", "disabled").strip().lower()
    max_skew = int(os.environ.get("TCD_AUTH_MAX_SKEW_S", "300"))

    bearer_tokens: List[str] = []
    if mode == "bearer":
        raw = os.environ.get("TCD_AUTH_BEARER_TOKENS", "")
        bearer_tokens = [t.strip() for t in raw.split(",") if t.strip()]

    hmac_keys: Dict[str, str] = {}
    if mode == "hmac":
        raw = os.environ.get("TCD_AUTH_HMAC_KEYS_JSON", "").strip()
        if not raw:
            raise ValueError("TCD_AUTH_HMAC_KEYS_JSON is required in hmac mode")
        try:
            obj = json.loads(raw)
            if not isinstance(obj, dict) or not obj:
                raise ValueError
            # validate hex
            for k, v in obj.items():
                _ = bytes.fromhex(str(v))
            hmac_keys = {str(k): str(v) for k, v in obj.items()}
        except Exception:
            raise ValueError("TCD_AUTH_HMAC_KEYS_JSON must be a JSON object of {kid: hexkey}")

    return Authenticator(
        mode=mode,
        bearer_tokens=bearer_tokens,
        hmac_keys=hmac_keys,
        max_skew_s=max_skew,
    )


def require_auth(
    authenticator: Authenticator,
    *,
    required_scopes: Optional[List[str]] = None,
) -> Callable[[Request], AuthContext]:
    """
    FastAPI dependency factory.

    Usage:
      auth = build_authenticator_from_env()
      app = FastAPI()
      @app.post("/diagnose")
      async def diagnose(req: DiagnoseRequest, ctx: AuthContext = Depends(require_auth(auth))):
          ...
    """
    required_scopes = list(required_scopes or [])

    async def _dep(request: Request) -> AuthContext:
        res = await authenticator.verify(request)
        if not res.ok or not res.ctx:
            # 401 when missing/invalid credentials; 403 when present but lacks scope (handled below)
            detail = res.reason or "unauthorized"
            raise HTTPException(status_code=401, detail=detail)
        # scope check (basic contains-all policy)
        if required_scopes and not set(required_scopes).issubset(set(res.ctx.scopes)):
            _inc_fail(authenticator.mode, "forbidden")
            raise HTTPException(status_code=403, detail="forbidden")
        return res.ctx

    return _dep
