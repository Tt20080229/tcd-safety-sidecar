# FILE: tests/test_admin_http.py
from __future__ import annotations

import os
from typing import Any, Dict, List, Optional, Tuple
from fastapi.testclient import TestClient

from tcd.admin_http import (
    AdminContext,
    ReceiptStorageProtocol,
    BindContext,
    create_admin_app,
)

# --- Test doubles ------------------------------------------------------------

class _FakePolicyStore:
    def __init__(self):
        self._rules = []

    def rules(self):
        return list(self._rules)

    def replace_rules(self, rules):
        self._rules = list(rules or [])

    def bind(self, ctx_dict):
        class _Bound:
            name = "p0"
            version = "v0"
            policy_ref = "p0#deadbeef"
            priority = 10
            detector_cfg = {"kind": "noop", "k": 1}
            av_cfg = {"alpha": 0.05}
            t_low = 0.1
            t_high = 0.9
            top_p_low = 0.9
            top_p_high = 0.95
            fallback_decoder = "greedy"
            enable_receipts = True
            enable_verify_metrics = True
            slo_latency_ms = 50.0
            token_cost_divisor = 100.0
            match = {"tenant": ctx_dict.get("tenant", "*")}
        return _Bound()

class _FakeStore(ReceiptStorageProtocol):
    def __init__(self):
        self._data: Dict[str, str] = {}
    def put(self, head_hex: str, body_json: str) -> None:
        self._data[head_hex] = body_json
    def get(self, head_hex: str) -> Optional[str]:
        return self._data.get(head_hex)
    def tail(self, n: int) -> List[Tuple[str, str]]:
        items = list(self._data.items())
        return items[-n:]
    def stats(self) -> Dict[str, Any]:
        return {"count": len(self._data), "size_bytes": sum(len(b) for b in self._data.values()), "last_ts": 0.0}

# --- Helpers -----------------------------------------------------------------

def _client(with_store: bool = True) -> TestClient:
    ps = _FakePolicyStore()
    store = _FakeStore() if with_store else None
    app = create_admin_app(AdminContext(policies=ps, storage=store))
    return TestClient(app)

def _with_token_headers():
    os.environ["TCD_ADMIN_TOKEN"] = "secret"
    return {"X-TCD-Admin-Token": "secret"}

# --- Tests -------------------------------------------------------------------

def test_auth_required_when_no_allow_env():
    os.environ.pop("TCD_ADMIN_ALLOW_NO_AUTH", None)
    os.environ.pop("TCD_ADMIN_TOKEN", None)
    c = _client()
    r = c.get("/admin/healthz")
    assert r.status_code == 401
    assert r.json()["detail"] == "admin token required"

def test_healthz_ok_with_token():
    c = _client()
    r = c.get("/admin/healthz", headers=_with_token_headers())
    assert r.status_code == 200
    j = r.json()
    assert j["ok"] is True
    assert "config_hash" in j

def test_policies_bind_roundtrip():
    c = _client()
    payload = BindContext(tenant="t0").model_dump()
    r = c.post("/admin/policies/bind", json=payload, headers=_with_token_headers())
    assert r.status_code == 200
    j = r.json()
    assert j["name"] == "p0"
    assert j["routing"]["fallback_decoder"] == "greedy"
    assert j["enable_receipts"] is True

def test_receipts_tail_and_get():
    c = _client(with_store=True)
    headers = _with_token_headers()
    # prime fake store
    c.app.dependency_overrides = {}  # not used; store is inside context
    # use direct store reference via context: easiest is to call endpoints to populate
    # but endpoints only read, so we insert via the fake directly:
    store: _FakeStore = c.app.router.routes[0].app.extra.get("store") if hasattr(c.app.router.routes[0].app, "extra") else None  # fallback not needed
    # Since we didn't attach 'store' into app.extra, push via Protocol directly:
    _store = c.app.state  # FastAPI state; not used here
    # Instead, reach into the context by recreating it is cumbersome.
    # Easiest: call the protocol through the created context by rebuilding client with pre-seeded store.
    s = _FakeStore()
    s.put("aa00", '{"prev": null, "payload": 1}')
    app = create_admin_app(AdminContext(policies=_FakePolicyStore(), storage=s))
    c2 = TestClient(app)

    r1 = c2.get("/admin/receipts/tail?n=10", headers=_with_token_headers())
    assert r1.status_code == 200
    j1 = r1.json()
    assert j1["total"] == 1
    assert j1["items"][0][0] == "aa00"

    r2 = c2.get("/admin/receipts/aa00", headers=_with_token_headers())
    assert r2.status_code == 200
    j2 = r2.json()
    assert j2["found"] is True
    assert j2["body_json"].startswith("{")

def test_verify_endpoints_monkeypatched(monkeypatch):
    c = _client()

    # monkeypatch verifiers in module under test
    import tcd.admin_http as mod
    monkeypatch.setattr(mod, "verify_receipt", lambda **kw: True)
    monkeypatch.setattr(mod, "verify_chain", lambda *a, **kw: True)

    vr = c.post(
        "/admin/verify/receipt",
        json={"head_hex": "aa00", "body_json": '{"prev": null}'},
        headers=_with_token_headers(),
    )
    assert vr.status_code == 200
    assert vr.json()["ok"] is True

    vc = c.post(
        "/admin/verify/chain",
        json={"heads": ["aa00"], "bodies": ['{"prev": null}']},
        headers=_with_token_headers(),
    )
    assert vc.status_code == 200
    assert vc.json()["ok"] is True
