# FILE: tcd/service_http.py
from __future__ import annotations

import os
import threading
import time
from typing import Dict, List, Optional, Tuple

import numpy as np
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from .config import make_reloadable_settings
from .detector import TCDConfig, TraceCollapseDetector
from .exporter import TCDPrometheusExporter
from .multivariate import MultiVarConfig, MultiVarDetector
from .otel_exporter import TCDOtelExporter
from .ratelimit import RateLimiter
from .risk_av import AlwaysValidConfig, AlwaysValidRiskController
from .routing import StrategyRouter
from .signals import DefaultLLMSignals, SignalProvider
from .telemetry_gpu import GpuSampler
from .utils import sanitize_floats

# receipts
from .attest import Attestor
from .kv import RollingHasher
from .receipt_v2 import build_v2_body
from .verify import verify_receipt, verify_chain

_settings = make_reloadable_settings()


# ---------- Pydantic I/O ----------

class DiagnoseRequest(BaseModel):
    trace_vector: List[float] = Field(default_factory=list)
    entropy: Optional[float] = None
    spectrum: List[float] = Field(default_factory=list)
    features: List[float] = Field(default_factory=list)  # optional multivariate features
    step_id: Optional[int] = None

    model_id: str = "model0"
    gpu_id: str = "gpu0"
    task: str = "chat"
    lang: str = "en"
    tenant: str = "tenant0"
    user: str = "user0"
    session: str = "sess0"

    context: Dict = Field(default_factory=dict)
    tokens_delta: int = 50
    drift_score: float = 0.0


class RiskResponse(BaseModel):
    verdict: bool
    score: float
    threshold: float
    budget_remaining: float
    components: Dict[str, Dict]
    cause: Optional[str] = None
    action: Optional[str] = None
    step: int
    e_value: float
    alpha_alloc: float
    alpha_spent: float

    # optional: inlined receipt triplet
    receipt: Optional[str] = None
    receipt_body: Optional[str] = None
    receipt_sig: Optional[str] = None
    verify_key: Optional[str] = None


class SnapshotState(BaseModel):
    state: Dict


class VerifyRequest(BaseModel):
    # single-receipt verification
    receipt_head_hex: Optional[str] = None
    receipt_body_json: Optional[str] = None
    verify_key_hex: Optional[str] = None
    receipt_sig_hex: Optional[str] = None
    req_obj: Optional[Dict] = None
    comp_obj: Optional[Dict] = None
    e_obj: Optional[Dict] = None
    # witnesses (trace/spectrum/feat)
    witness_segments: Optional[Tuple[List[int], List[int], List[int]]] = None

    # chain verification (mutually exclusive with above)
    heads: Optional[List[str]] = None
    bodies: Optional[List[str]] = None


class VerifyResponse(BaseModel):
    ok: bool


# ---------- Internals ----------

def _quantize_to_u32(xs: List[float], *, scale: float = 1e6, cap: int = 64) -> List[int]:
    """Map floats to non-negative u32 with truncation to avoid content leakage."""
    out: List[int] = []
    for v in xs[: max(0, cap)]:
        try:
            iv = int(abs(float(v)) * float(scale))
        except Exception:
            iv = 0
        out.append(iv & 0xFFFFFFFF)
    return out


def _safe_context_subset(ctx: Dict) -> Dict:
    """Keep only low-cardinality, non-sensitive fields."""
    allow_keys = {"decoder", "temperature", "top_p", "gpu_util", "gpu_temp_c", "p99_latency_ms"}
    return {k: ctx[k] for k in allow_keys if k in ctx}


# ---------- App factory ----------

def create_app() -> FastAPI:
    app = FastAPI(title="tcd-sidecar", version="0.10.2")

    settings = _settings.get()
    prom = TCDPrometheusExporter(
        port=settings.prometheus_port,
        version="0.10.2",
        config_hash=settings.config_hash(),
    )
    if settings.prom_http_enable:
        prom.ensure_server()

    # OTEL: exporter is safe to construct even if OTEL deps are missing
    otel = TCDOtelExporter(endpoint=settings.otel_endpoint) if settings.otel_enable else TCDOtelExporter(endpoint=settings.otel_endpoint)
    signals: SignalProvider = DefaultLLMSignals()
    gpu = GpuSampler(0) if settings.gpu_enable else None

    # rate limiting per tenant/user/session
    rlim = RateLimiter(capacity=60.0, refill_per_s=30.0)

    # state: detectors keyed by (model,gpu,task,lang); AV controllers by (tenant,user,session)
    det_lock = threading.RLock()
    detectors: Dict[Tuple[str, str, str, str], TraceCollapseDetector] = {}

    av_lock = threading.RLock()
    av_by_subject: Dict[Tuple[str, str, str], AlwaysValidRiskController] = {}

    # optional multivariate detector per model
    mv_lock = threading.RLock()
    mv_by_model: Dict[str, MultiVarDetector] = {}

    router = StrategyRouter()

    # optional receipt issuance (off by default)
    receipts_enable = os.environ.get("TCD_RECEIPTS_ENABLE", "0") == "1"
    attestor = Attestor(hash_alg=os.environ.get("TCD_HASH_ALG", "blake3")) if receipts_enable else None

    def _get_detector(key: Tuple[str, str, str, str]) -> TraceCollapseDetector:
        with det_lock:
            if key not in detectors:
                detectors[key] = TraceCollapseDetector(config=TCDConfig())
            return detectors[key]

    def _get_av(subject: Tuple[str, str, str]) -> AlwaysValidRiskController:
        with av_lock:
            if subject not in av_by_subject:
                av_by_subject[subject] = AlwaysValidRiskController(AlwaysValidConfig(alpha_base=settings.alpha))
            return av_by_subject[subject]

    def _get_mv(model_id: str) -> MultiVarDetector:
        with mv_lock:
            if model_id not in mv_by_model:
                mv_by_model[model_id] = MultiVarDetector(MultiVarConfig(estimator="lw", alpha=0.01))
            return mv_by_model[model_id]

    def _conservative_p_from_score(score: float) -> float:
        s = max(0.0, min(1.0, float(score)))
        p = 1.0 - s
        return max(1e-9, min(1.0, p))

    # ---------- Endpoints ----------

    @app.get("/healthz")
    def healthz():
        return {
            "ok": True,
            "config_hash": settings.config_hash(),
            "otel": bool(otel.enabled),
            "prom": True,
            "receipts": bool(receipts_enable),
        }

    @app.get("/version")
    def version():
        return {
            "version": "0.10.2",
            "config_version": settings.config_version,
            "alpha": settings.alpha,
            "slo_latency_ms": settings.slo_latency_ms,
        }

    @app.get("/state/get")
    def state_get(model_id: str = "model0", gpu_id: str = "gpu0", task: str = "chat", lang: str = "en"):
        det = _get_detector((model_id, gpu_id, task, lang))
        return {"detector": det.snapshot_state()}

    @app.post("/state/load")
    def state_load(payload: SnapshotState, model_id: str = "model0", gpu_id: str = "gpu0", task: str = "chat", lang: str = "en"):
        det = _get_detector((model_id, gpu_id, task, lang))
        det.load_state(payload.state)
        return {"ok": True}

    @app.post("/diagnose", response_model=RiskResponse)
    def diagnose(req: DiagnoseRequest):
        t_start = time.perf_counter()

        # rate limiting with token-cost approximation
        key = (req.tenant, req.user, req.session)
        cost = max(1.0, float(req.tokens_delta) / 50.0)
        if not rlim.consume(key, cost=cost):
            prom.throttle(req.tenant, req.user, req.session, reason="rate")
            raise HTTPException(status_code=429, detail="rate limited")

        # optional GPU sampling
        if gpu is not None:
            try:
                req.context.update(gpu.sample())
            except Exception:
                pass

        # sanitize inputs
        trace_vec, _ = sanitize_floats(req.trace_vector, max_len=4096)
        spectrum, _ = sanitize_floats(req.spectrum, max_len=4096)
        features, _ = sanitize_floats(req.features, max_len=2048)

        dkey = (req.model_id, req.gpu_id, req.task, req.lang)
        det = _get_detector(dkey)

        verdict_pack = det.diagnose(trace_vec, req.entropy, spectrum, step_id=req.step_id)

        mv_info = {}
        if features:
            try:
                mv = _get_mv(req.model_id)
                mv_info = mv.decision(np.asarray(features, dtype=float))  # {distance, threshold, trigger}
            except Exception:
                mv_info = {}

        score = float(verdict_pack.get("score", 0.0))
        p_final = _conservative_p_from_score(score)

        subject = (req.tenant, req.user, req.session)
        av = _get_av(subject)
        av_out = av.step(
            policy_key=(req.task, req.lang, req.model_id),
            subject=subject,
            scores={"final": score},
            pvals={"final": p_final},
            drift_weight=float(max(0.0, min(2.0, 1.0 + 0.5 * float(req.drift_score)))),
        )

        decision_fail = bool(verdict_pack.get("verdict", False) or av_out.get("trigger", False))

        route = router.decide(
            decision_fail,
            score,
            base_temp=float(req.context.get("temperature", 0.7)),
            base_top_p=float(req.context.get("top_p", 0.9)),
        )

        # optional inline receipt
        rcpt_head = rcpt_body = rcpt_sig = vk_hex = None
        if attestor is not None:
            try:
                w_trace = _quantize_to_u32(trace_vec)
                w_spec = _quantize_to_u32(spectrum)
                w_feat = _quantize_to_u32(features)

                kvh = RollingHasher(alg=os.environ.get("TCD_HASH_ALG", "blake3"), ctx="tcd:kv")
                kvh.update_ints(w_trace)
                kvh.update_ints(w_spec)
                kvh.update_ints(w_feat)
                kv_digest = kvh.hex()

                meta_v2 = build_v2_body(
                    model_hash=f"unknown:{req.model_id}",
                    tokenizer_hash=f"unknown:{req.model_id}",
                    sampler_cfg={
                        "temperature": route.temperature,
                        "top_p": route.top_p,
                        "decoder": route.decoder,
                        "seed": None,
                    },
                    context_len=len(trace_vec),
                    kv_digest=kv_digest,
                    rng_seed=None,
                    latency_ms=None,
                    throughput_tok_s=None,
                    batch_index=0,
                    batch_size=1,
                    e_snapshot={"e_value": float(av_out.get("e_value", 1.0))},
                )

                req_obj = {
                    "ts": time.time(),
                    "tenant": req.tenant, "user": req.user, "session": req.session,
                    "model_id": req.model_id, "gpu_id": req.gpu_id,
                    "task": req.task, "lang": req.lang,
                    "context": _safe_context_subset(req.context),
                    "tokens_delta": int(req.tokens_delta),
                    "step": int(verdict_pack.get("step", 0)),
                }
                comp_obj = {
                    "score": score,
                    "verdict": bool(verdict_pack.get("verdict", False)),
                    "route": {"temperature": route.temperature, "top_p": route.top_p, "decoder": route.decoder, "tags": route.tags},
                    "components": {
                        "invertibility": {
                            "sev": float(verdict_pack["components"]["invertibility"]["severity"]),
                            "z_low": float(verdict_pack["components"]["invertibility"]["details"].get("trace_z_low", 0.0)),
                        },
                        "entropy_drop": {
                            "sev": float(verdict_pack["components"]["entropy_drop"]["severity"]),
                            "z_low": float(verdict_pack["components"]["entropy_drop"]["details"].get("entropy_z_low", 0.0)),
                        },
                        "sigma_cut": {
                            "sev": float(verdict_pack["components"]["sigma_cut"]["severity"]),
                            "z": float(verdict_pack["components"]["sigma_cut"]["details"].get("spread_z", 0.0)),
                        },
                    },
                }
                e_obj = {
                    "e_value": float(av_out.get("e_value", 1.0)),
                    "alpha_alloc": float(av_out.get("alpha_alloc", 0.0)),
                    "alpha_wealth": float(av_out.get("alpha_wealth", 0.0)),
                    "threshold": float(av_out.get("threshold", 0.0)),
                    "trigger": bool(av_out.get("trigger", False)),
                }

                rcpt = attestor.issue(
                    req_obj=req_obj,
                    comp_obj=comp_obj,
                    e_obj=e_obj,
                    witness_segments=(w_trace, w_spec, w_feat),
                    witness_tags=("trace", "spectrum", "feat"),
                    meta=meta_v2,
                )
                rcpt_head = rcpt.get("receipt")
                rcpt_body = rcpt.get("receipt_body")
                rcpt_sig = rcpt.get("receipt_sig")
                vk_hex = rcpt.get("verify_key")

                if otel.enabled:
                    try:
                        size_bytes = len(rcpt_body.encode("utf-8")) if isinstance(rcpt_body, str) else 0
                        otel.push_metrics(score, attrs={
                            "tcd.receipt.present": True,
                            "tcd.receipt.size_bytes": size_bytes,
                            "tcd.decision.verdict": str(decision_fail),
                            "model_id": req.model_id, "gpu_id": req.gpu_id,
                            "tenant": req.tenant, "user": req.user, "session": req.session,
                        })
                    except Exception:
                        pass
            except Exception:
                if otel.enabled:
                    otel.push_metrics(score, attrs={"tcd.receipt.present": False})

        latency_s = max(0.0, time.perf_counter() - t_start)
        prom.observe_latency(latency_s)
        prom.push(verdict_pack, labels={"model_id": req.model_id, "gpu_id": req.gpu_id})
        prom.push_eprocess(
            model_id=req.model_id,
            gpu_id=req.gpu_id,
            tenant=req.tenant,
            user=req.user,
            session=req.session,
            e_value=float(av_out.get("e_value", 1.0)),
            alpha_alloc=float(av_out.get("alpha_alloc", 0.0)),
            alpha_wealth=float(av_out.get("alpha_wealth", 0.0)),
        )
        prom.update_budget_metrics(
            req.tenant, req.user, req.session,
            remaining=float(av_out.get("alpha_wealth", 0.0)),
            spent=bool(av_out.get("alpha_spent", 0.0) > 0.0),
        )
        if decision_fail:
            prom.record_action(req.model_id, req.gpu_id, action="degrade")
        otel.push_metrics(score, attrs={
            "model_id": req.model_id, "gpu_id": req.gpu_id,
            "tenant": req.tenant, "user": req.user, "session": req.session,
        })

        if (latency_s * 1000.0) > float(settings.slo_latency_ms):
            prom.slo_violation_by_model("diagnose_latency", req.model_id, req.gpu_id)

        return RiskResponse(
            verdict=bool(decision_fail),
            score=score,
            threshold=float(av_out.get("threshold", 0.0)),
            budget_remaining=float(av_out.get("alpha_wealth", 0.0)),
            components=verdict_pack.get("components", {}),
            cause=("detector" if verdict_pack.get("verdict", False) else ("av" if av_out.get("trigger", False) else "")),
            action=("degrade" if decision_fail else "none"),
            step=int(verdict_pack.get("step", 0)),
            e_value=float(av_out.get("e_value", 1.0)),
            alpha_alloc=float(av_out.get("alpha_alloc", 0.0)),
            alpha_spent=float(av_out.get("alpha_spent", 0.0)),
            receipt=rcpt_head,
            receipt_body=rcpt_body,
            receipt_sig=rcpt_sig,
            verify_key=vk_hex,
        )

    @app.post("/verify", response_model=VerifyResponse)
    def verify(req: VerifyRequest):
        t0 = time.perf_counter()
        ok = False
        try:
            if req.heads is not None and req.bodies is not None:
                if not isinstance(req.heads, list) or not isinstance(req.bodies, list) or len(req.heads) != len(req.bodies):
                    raise HTTPException(status_code=400, detail="heads/bodies invalid")
                ok = bool(verify_chain(req.heads, req.bodies))
            else:
                if not req.receipt_head_hex or not req.receipt_body_json:
                    raise HTTPException(status_code=400, detail="missing receipt head/body")
                ws = None
                if req.witness_segments is not None:
                    if (len(req.witness_segments) != 3 or any(not isinstance(seg, list) for seg in req.witness_segments)):
                        raise HTTPException(status_code=400, detail="witness_segments must be triple of int lists")
                    ws = (req.witness_segments[0], req.witness_segments[1], req.witness_segments[2])
                ok = bool(verify_receipt(
                    receipt_head_hex=req.receipt_head_hex,
                    receipt_body_json=req.receipt_body_json,
                    verify_key_hex=req.verify_key_hex,
                    receipt_sig_hex=req.receipt_sig_hex,
                    req_obj=req.req_obj,
                    comp_obj=req.comp_obj,
                    e_obj=req.e_obj,
                    witness_segments=ws,
                    strict=True
                ))
        finally:
            latency = max(0.0, time.perf_counter() - t0)
            prom.observe_latency(latency)
            if not ok:
                prom.slo_violation("verify_fail")
        return VerifyResponse(ok=ok)

    return app
